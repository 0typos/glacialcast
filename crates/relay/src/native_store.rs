//! Durable SQLite-backed storage for opaque native v2 groups and envelopes.
//!
//! A transaction commits each object, its sequence high-water mark, group
//! accounting, and any complete-group eviction atomically. Viewer envelopes
//! share the group's foreign-key lifetime, so they cannot outlive or disappear
//! before their ciphertext group. SQLite's WAL is the checksummed recovery
//! journal; acknowledgements are returned only after a `synchronous=FULL`
//! commit.

use anyhow::{Context, Result};
use glacialcast_protocol::{
    envelope::KeyEnvelope,
    native::{NativeObject, NativeObjectKind, StreamDescriptor},
    wire::SubscriptionStart,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

const DATABASE_FILE: &str = "native-v2.sqlite3";
const SCHEMA_VERSION: i64 = 2;
const MAX_LIST_OBJECTS: usize = 16_384;

/// Non-retention hard limits that bound hostile publisher resource use.
#[derive(Clone, Copy, Debug)]
pub struct NativeStoreLimits {
    /// Maximum descriptors retained globally.
    pub max_streams: u64,
    /// Maximum descriptors owned by one publisher identity.
    pub max_streams_per_publisher: u64,
    /// Maximum encoded objects in one keyframe group.
    pub max_objects_per_group: u64,
    /// Maximum objects plus envelopes in one keyframe group.
    pub max_group_bytes: u64,
    /// Maximum viewer envelopes in one keyframe group.
    pub max_envelopes_per_group: u64,
    /// Maximum retained bytes across the complete relay store.
    pub max_total_bytes: u64,
    /// Maximum retained bytes owned by one publisher identity.
    pub max_publisher_bytes: u64,
}

impl Default for NativeStoreLimits {
    fn default() -> Self {
        Self {
            max_streams: 1_024,
            max_streams_per_publisher: 16,
            max_objects_per_group: 4_096,
            max_group_bytes: 64 * 1024 * 1024,
            max_envelopes_per_group: 128,
            max_total_bytes: 10 * 1024 * 1024 * 1024,
            max_publisher_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Durable payload-opaque native stream store.
#[derive(Clone)]
pub struct NativeStore {
    inner: Arc<NativeStoreInner>,
}

struct NativeStoreInner {
    root: PathBuf,
    connection: Mutex<Connection>,
    retention_bytes: Option<u64>,
    retention_age: Option<Duration>,
    quarantined_v1: Option<PathBuf>,
    limits: NativeStoreLimits,
}

#[derive(Clone, Copy)]
enum GroupItemKind {
    Object,
    Envelope,
}

struct GroupGrowth<'a> {
    publisher_id: &'a [u8; 32],
    stream_id: Uuid,
    epoch_id: Uuid,
    key_group: u64,
    added_bytes: u64,
    item_kind: GroupItemKind,
}

/// Result of committing one native stream object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCommit {
    /// Inclusive stream high-water mark now durable.
    pub committed_through: u64,
    /// Number of complete groups evicted in the same transaction.
    pub evicted_groups: usize,
    /// Whether this call published new bytes rather than matching a retry.
    pub inserted: bool,
}

/// Complete retained range for one stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRetainedBounds {
    /// First retained sequence, always a group boundary.
    pub oldest_sequence: u64,
    /// Last sequence in the newest complete retained group.
    pub newest_sequence: u64,
    /// First retained timestamp in 90 kHz ticks.
    pub oldest_timestamp: u64,
    /// Last retained timestamp in 90 kHz ticks.
    pub newest_timestamp: u64,
}

/// One stream's durable high-water and retention summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeStreamSummary {
    /// Publisher identity fingerprint.
    pub publisher_id: [u8; 32],
    /// Highest sequence ever committed, including evicted objects.
    pub high_water: u64,
    /// Bytes currently retained across objects and envelopes.
    pub retained_bytes: u64,
    /// Complete retained range, if any.
    pub retained: Option<NativeRetainedBounds>,
}

impl NativeStore {
    /// Opens or creates a native v2 store and quarantines a recognized v1 store.
    ///
    /// `retention_bytes` and `retention_age` are independent optional per-stream
    /// limits. When both exist, complete groups are evicted at whichever bound
    /// is reached first. The active incomplete group is never selected as
    /// retained history.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, incompatible schema, SQLite setup, or
    /// a failed atomic v1 quarantine rename.
    pub fn open(
        root: PathBuf,
        retention_bytes: Option<u64>,
        retention_age: Option<Duration>,
    ) -> Result<Self> {
        Self::open_with_limits(
            root,
            retention_bytes,
            retention_age,
            NativeStoreLimits::default(),
        )
    }

    /// Opens a store with explicit hostile-publisher resource limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`], and rejects zero or internally
    /// inconsistent hard limits.
    pub fn open_with_limits(
        root: PathBuf,
        retention_bytes: Option<u64>,
        retention_age: Option<Duration>,
        limits: NativeStoreLimits,
    ) -> Result<Self> {
        if retention_bytes == Some(0) || retention_age == Some(Duration::ZERO) {
            anyhow::bail!("native retention limits must be positive when configured");
        }
        if limits.max_streams == 0
            || limits.max_streams_per_publisher == 0
            || limits.max_streams_per_publisher > limits.max_streams
            || limits.max_objects_per_group == 0
            || limits.max_group_bytes == 0
            || limits.max_envelopes_per_group == 0
            || limits.max_total_bytes == 0
            || limits.max_publisher_bytes == 0
            || limits.max_publisher_bytes > limits.max_total_bytes
        {
            anyhow::bail!("native store hard limits are zero or inconsistent");
        }
        let quarantined_v1 = prepare_native_root(&root)?;
        fs::create_dir_all(&root)
            .with_context(|| format!("creating native store {}", root.display()))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing native store {}", root.display()))?;
        reject_symlink_or_non_directory(&root)?;

        let database_path = root.join(DATABASE_FILE);
        validate_existing_database(&database_path)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("opening native store {}", database_path.display()))?;
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("securing native database {}", database_path.display()))?;
        configure_connection(&connection)?;
        initialize_schema(&connection)?;

        Ok(Self {
            inner: Arc::new(NativeStoreInner {
                root,
                connection: Mutex::new(connection),
                retention_bytes,
                retention_age,
                quarantined_v1,
                limits,
            }),
        })
    }

    /// Returns the path atomically assigned to an incompatible v1 store, if any.
    #[must_use]
    pub fn quarantined_v1_path(&self) -> Option<&Path> {
        self.inner.quarantined_v1.as_deref()
    }

    /// Returns the native store directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Durably publishes a verified stream descriptor.
    ///
    /// Replacing metadata is allowed only for the same publisher identity and
    /// stream ID. A byte-identical retry is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid signatures, publisher substitution, bounds,
    /// lock poisoning, or transaction failure.
    pub fn put_descriptor(&self, descriptor: &StreamDescriptor) -> Result<()> {
        let encoded = descriptor.encode().context("encoding native descriptor")?;
        let stream_id = uuid_bytes(descriptor.body.stream_id);
        let publisher_id = descriptor
            .body
            .publisher
            .id()
            .context("fingerprinting descriptor publisher")?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting descriptor transaction")?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT publisher_id, descriptor FROM streams WHERE stream_id = ?1",
                params![stream_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("reading existing descriptor")?;
        match existing {
            Some((existing_publisher, existing_descriptor)) => {
                if existing_publisher != publisher_id {
                    anyhow::bail!("stream ID is already owned by another publisher");
                }
                if existing_descriptor != encoded {
                    transaction
                        .execute(
                            "UPDATE streams SET descriptor = ?2 WHERE stream_id = ?1",
                            params![stream_id.as_slice(), encoded],
                        )
                        .context("updating native descriptor")?;
                }
            }
            None => {
                let stream_count: i64 = transaction
                    .query_row("SELECT COUNT(*) FROM streams", [], |row| row.get(0))
                    .context("counting native streams")?;
                let publisher_stream_count: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM streams WHERE publisher_id = ?1",
                        params![publisher_id.as_slice()],
                        |row| row.get(0),
                    )
                    .context("counting publisher streams")?;
                if u64::try_from(stream_count).unwrap_or(u64::MAX) >= self.inner.limits.max_streams
                    || u64::try_from(publisher_stream_count).unwrap_or(u64::MAX)
                        >= self.inner.limits.max_streams_per_publisher
                {
                    anyhow::bail!("native stream descriptor limit reached");
                }
                transaction
                    .execute(
                        "INSERT INTO streams(stream_id, publisher_id, descriptor, high_water) \
                         VALUES (?1, ?2, ?3, 0)",
                        params![stream_id.as_slice(), publisher_id.as_slice(), encoded],
                    )
                    .context("inserting native descriptor")?;
            }
        }
        transaction.commit().context("committing native descriptor")
    }

    /// Commits one signed opaque object and applies complete-group retention.
    ///
    /// Sequences are immutable and contiguous. Crossing to a new epoch/group
    /// atomically marks the previous group complete. A retry with byte-identical
    /// canonical content returns the existing acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error for missing descriptors, forgery/corruption, sequence or
    /// group regression, conflicting retries, bounds, or durable commit failure.
    pub fn store_object(&self, object: &NativeObject, received_at_ms: i64) -> Result<NativeCommit> {
        object
            .validate_shape()
            .context("validating native object shape")?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting native object transaction")?;
        let descriptor = descriptor_in_transaction(&transaction, object.header.stream_id)?
            .context("native object stream has no descriptor")?;
        object
            .verify_public(&descriptor.body.publisher)
            .context("verifying native object publisher")?;
        let encoded = object
            .encode(&descriptor.body.publisher)
            .context("encoding native object")?;
        let stream_id = uuid_bytes(object.header.stream_id);
        let sequence = to_sql_u64(object.header.sequence, "object sequence")?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT object FROM objects WHERE stream_id = ?1 AND sequence = ?2",
                params![stream_id.as_slice(), sequence],
                |row| row.get(0),
            )
            .optional()
            .context("checking native object retry")?;
        if let Some(existing) = existing {
            if existing != encoded {
                anyhow::bail!("native sequence already exists with different content");
            }
            transaction
                .commit()
                .context("committing idempotent native object retry")?;
            return Ok(NativeCommit {
                committed_through: object.header.sequence,
                evicted_groups: 0,
                inserted: false,
            });
        }

        let (high_water, active_epoch, active_group): (i64, Option<Vec<u8>>, Option<i64>) =
            transaction
                .query_row(
                    "SELECT high_water, active_epoch, active_group FROM streams WHERE stream_id = ?1",
                    params![stream_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .context("reading native stream high-water mark")?;
        let expected = high_water
            .checked_add(1)
            .context("native sequence space exhausted")?;
        if sequence != expected {
            anyhow::bail!(
                "native sequence {} is out of order; expected {expected}",
                object.header.sequence
            );
        }

        let epoch_id = uuid_bytes(object.header.epoch_id);
        let key_group = to_sql_u64(object.header.key_group, "key group")?;
        let group_changed =
            active_epoch.as_deref() != Some(epoch_id.as_slice()) || active_group != Some(key_group);
        if group_changed {
            if active_epoch.is_some() {
                transaction
                    .execute(
                        "UPDATE groups SET complete = 1 \
                         WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                        params![stream_id.as_slice(), active_epoch, active_group],
                    )
                    .context("completing previous native group")?;
            }
            validate_group_progression(
                active_epoch.as_deref(),
                active_group,
                &epoch_id,
                key_group,
                object,
            )?;
            transaction
                .execute(
                    "INSERT INTO groups(\
                         stream_id, epoch_id, key_group, key_id, first_sequence, last_sequence, \
                         first_timestamp, last_timestamp, received_first_ms, received_last_ms, \
                         retained_bytes, complete\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?6, ?7, ?7, 0, 0)",
                    params![
                        stream_id.as_slice(),
                        epoch_id.as_slice(),
                        key_group,
                        object.header.key_id.as_slice(),
                        sequence,
                        to_sql_u64(object.header.timestamp, "object timestamp")?,
                        received_at_ms,
                    ],
                )
                .context("starting native keyframe group")?;
            transaction
                .execute(
                    "UPDATE streams SET active_epoch = ?2, active_group = ?3 WHERE stream_id = ?1",
                    params![stream_id.as_slice(), epoch_id.as_slice(), key_group],
                )
                .context("setting active native group")?;
        } else {
            let stored_key_id: Vec<u8> = transaction
                .query_row(
                    "SELECT key_id FROM groups \
                     WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                    params![stream_id.as_slice(), epoch_id.as_slice(), key_group],
                    |row| row.get(0),
                )
                .context("reading active group key ID")?;
            if stored_key_id != object.header.key_id {
                anyhow::bail!("native group changed key ID without rotating group");
            }
        }

        let object_bytes =
            u64::try_from(encoded.len()).context("native object length does not fit u64")?;
        self.check_group_growth(
            &transaction,
            GroupGrowth {
                publisher_id: &descriptor.body.publisher.id()?,
                stream_id: object.header.stream_id,
                epoch_id: object.header.epoch_id,
                key_group: object.header.key_group,
                added_bytes: object_bytes,
                item_kind: GroupItemKind::Object,
            },
        )?;

        transaction
            .execute(
                "INSERT INTO objects(stream_id, sequence, epoch_id, key_group, received_at_ms, object) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    stream_id.as_slice(),
                    sequence,
                    epoch_id.as_slice(),
                    key_group,
                    received_at_ms,
                    encoded,
                ],
            )
            .context("inserting native object")?;
        let object_bytes = to_sql_u64(object_bytes, "object byte count")?;
        transaction
            .execute(
                "UPDATE groups SET last_sequence = ?4, last_timestamp = ?5, \
                     received_last_ms = MAX(received_last_ms, ?6), \
                     retained_bytes = retained_bytes + ?7 \
                 WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                params![
                    stream_id.as_slice(),
                    epoch_id.as_slice(),
                    key_group,
                    sequence,
                    to_sql_u64(object.header.timestamp, "object timestamp")?,
                    received_at_ms,
                    object_bytes,
                ],
            )
            .context("updating native group accounting")?;
        transaction
            .execute(
                "UPDATE streams SET high_water = ?2 WHERE stream_id = ?1",
                params![stream_id.as_slice(), sequence],
            )
            .context("updating native high-water mark")?;

        let evicted_groups =
            self.enforce_retention(&transaction, object.header.stream_id, received_at_ms)?;
        transaction.commit().context("committing native object")?;
        Ok(NativeCommit {
            committed_through: object.header.sequence,
            evicted_groups,
            inserted: true,
        })
    }

    /// Commits one viewer envelope under the exact retained group lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error for missing groups, publisher/key mismatch, conflicting
    /// retries, malformed envelopes, or durable transaction failure.
    pub fn store_envelope(&self, envelope: &KeyEnvelope, received_at_ms: i64) -> Result<bool> {
        envelope
            .validate_shape()
            .context("validating key envelope shape")?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting envelope transaction")?;
        let descriptor = descriptor_in_transaction(&transaction, envelope.header.stream_id)?
            .context("key envelope stream has no descriptor")?;
        envelope
            .verify_public(&descriptor.body.publisher)
            .context("verifying key envelope publisher")?;
        let encoded = envelope
            .encode(&descriptor.body.publisher)
            .context("encoding key envelope")?;
        let stream_id = uuid_bytes(envelope.header.stream_id);
        let epoch_id = uuid_bytes(envelope.header.epoch_id);
        let key_group = to_sql_u64(envelope.header.key_group_id, "envelope key group")?;
        let group_key_id: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT key_id FROM groups \
                 WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                params![stream_id.as_slice(), epoch_id.as_slice(), key_group],
                |row| row.get(0),
            )
            .optional()
            .context("reading envelope group")?;
        if group_key_id.as_deref() != Some(envelope.header.key_id.as_slice()) {
            anyhow::bail!("key envelope does not match a retained ciphertext group");
        }

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT envelope FROM envelopes WHERE stream_id = ?1 AND epoch_id = ?2 \
                 AND key_group = ?3 AND recipient_id = ?4",
                params![
                    stream_id.as_slice(),
                    epoch_id.as_slice(),
                    key_group,
                    envelope.header.recipient_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .context("checking envelope retry")?;
        if let Some(existing) = existing {
            if existing != encoded {
                anyhow::bail!("viewer envelope already exists with different content");
            }
            transaction.commit().context("committing envelope retry")?;
            return Ok(false);
        }

        self.check_group_growth(
            &transaction,
            GroupGrowth {
                publisher_id: &descriptor.body.publisher.id()?,
                stream_id: envelope.header.stream_id,
                epoch_id: envelope.header.epoch_id,
                key_group: envelope.header.key_group_id,
                added_bytes: u64::try_from(encoded.len())
                    .context("envelope length does not fit u64")?,
                item_kind: GroupItemKind::Envelope,
            },
        )?;

        transaction
            .execute(
                "INSERT INTO envelopes(\
                     stream_id, epoch_id, key_group, recipient_id, key_id, received_at_ms, envelope\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    stream_id.as_slice(),
                    epoch_id.as_slice(),
                    key_group,
                    envelope.header.recipient_id.as_slice(),
                    envelope.header.key_id.as_slice(),
                    received_at_ms,
                    encoded,
                ],
            )
            .context("inserting viewer envelope")?;
        transaction
            .execute(
                "UPDATE groups SET retained_bytes = retained_bytes + ?4 \
                 WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                params![
                    stream_id.as_slice(),
                    epoch_id.as_slice(),
                    key_group,
                    to_sql_u64(
                        u64::try_from(encoded.len()).context("envelope length does not fit u64")?,
                        "envelope byte count",
                    )?,
                ],
            )
            .context("updating envelope group accounting")?;
        self.enforce_retention(&transaction, envelope.header.stream_id, received_at_ms)?;
        transaction.commit().context("committing viewer envelope")?;
        Ok(true)
    }

    /// Applies age and byte limits to complete groups for every idle stream.
    ///
    /// This is the periodic counterpart to commit-time retention. Active
    /// incomplete groups remain untouched even when a configured bound is
    /// exceeded.
    ///
    /// # Errors
    ///
    /// Returns an error for database corruption, lock poisoning, or transaction
    /// failure. No eviction is published unless the transaction commits.
    pub fn enforce_retention_at(&self, now_ms: i64) -> Result<usize> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting periodic native retention")?;
        let stream_ids = {
            let mut statement = transaction
                .prepare("SELECT stream_id FROM streams ORDER BY stream_id")
                .context("preparing native retention stream list")?;
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .context("listing native retention streams")?;
            let mut stream_ids = Vec::new();
            for row in rows {
                stream_ids.push(decode_uuid(&row?, "retention stream ID")?);
            }
            stream_ids
        };
        let mut removed = 0usize;
        for stream_id in stream_ids {
            removed =
                removed.saturating_add(self.enforce_retention(&transaction, stream_id, now_ms)?);
        }
        transaction
            .commit()
            .context("committing periodic native retention")?;
        Ok(removed)
    }

    /// Returns one verified object by exact stream sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for database, descriptor, parser, or signature failure.
    pub fn get_object(&self, stream_id: Uuid, sequence: u64) -> Result<Option<NativeObject>> {
        let connection = self.connection()?;
        let descriptor = descriptor_in_connection(&connection, stream_id)?;
        let Some(descriptor) = descriptor else {
            return Ok(None);
        };
        let encoded: Option<Vec<u8>> = connection
            .query_row(
                "SELECT object FROM objects WHERE stream_id = ?1 AND sequence = ?2",
                params![
                    uuid_bytes(stream_id).as_slice(),
                    to_sql_u64(sequence, "object sequence")?
                ],
                |row| row.get(0),
            )
            .optional()
            .context("reading native object")?;
        encoded
            .map(|encoded| {
                NativeObject::decode(&encoded, &descriptor.body.publisher)
                    .context("decoding stored native object")
            })
            .transpose()
    }

    /// Lists verified objects after an exclusive sequence in ascending order.
    ///
    /// # Errors
    ///
    /// Returns an error for an excessive limit, database, parser, or signature
    /// failure.
    pub fn list_objects(
        &self,
        stream_id: Uuid,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<NativeObject>> {
        if limit == 0 || limit > MAX_LIST_OBJECTS {
            anyhow::bail!("native object list limit is outside 1..={MAX_LIST_OBJECTS}");
        }
        let connection = self.connection()?;
        let descriptor = descriptor_in_connection(&connection, stream_id)?
            .context("native stream has no descriptor")?;
        let mut statement = connection
            .prepare(
                "SELECT object FROM objects WHERE stream_id = ?1 AND sequence > ?2 \
                 ORDER BY sequence LIMIT ?3",
            )
            .context("preparing native object list")?;
        let rows = statement
            .query_map(
                params![
                    uuid_bytes(stream_id).as_slice(),
                    to_sql_u64(after_sequence, "object sequence")?,
                    i64::try_from(limit).context("object list limit does not fit i64")?,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .context("listing native objects")?;
        let mut objects = Vec::with_capacity(limit);
        for encoded in rows {
            objects.push(
                NativeObject::decode(&encoded?, &descriptor.body.publisher)
                    .context("decoding listed native object")?,
            );
        }
        Ok(objects)
    }

    /// Lists this viewer's envelopes for retained groups, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error for an excessive limit, database, parser, or signature
    /// failure.
    pub fn list_envelopes(
        &self,
        stream_id: Uuid,
        recipient_id: [u8; 32],
        limit: usize,
    ) -> Result<Vec<KeyEnvelope>> {
        if recipient_id == [0; 32] || limit == 0 || limit > MAX_LIST_OBJECTS {
            anyhow::bail!("invalid native envelope list request");
        }
        let connection = self.connection()?;
        let descriptor = descriptor_in_connection(&connection, stream_id)?
            .context("native stream has no descriptor")?;
        let mut statement = connection
            .prepare(
                "SELECT e.envelope FROM envelopes e JOIN groups g USING(stream_id, epoch_id, key_group) \
                 WHERE e.stream_id = ?1 AND e.recipient_id = ?2 \
                 ORDER BY g.first_sequence DESC LIMIT ?3",
            )
            .context("preparing viewer envelope list")?;
        let rows = statement
            .query_map(
                params![
                    uuid_bytes(stream_id).as_slice(),
                    recipient_id.as_slice(),
                    i64::try_from(limit).context("envelope list limit does not fit i64")?,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .context("listing viewer envelopes")?;
        let mut envelopes = Vec::with_capacity(limit);
        for encoded in rows {
            envelopes.push(
                KeyEnvelope::decode(&encoded?, &descriptor.body.publisher)
                    .context("decoding stored viewer envelope")?,
            );
        }
        Ok(envelopes)
    }

    /// Returns one viewer-addressed envelope for an exact retained key group.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, database failure, or a stored
    /// envelope that no longer verifies against the stream publisher.
    pub fn get_envelope(
        &self,
        stream_id: Uuid,
        epoch_id: Uuid,
        key_group: u64,
        recipient_id: [u8; 32],
    ) -> Result<Option<KeyEnvelope>> {
        if stream_id.is_nil() || epoch_id.is_nil() || key_group == 0 || recipient_id == [0; 32] {
            anyhow::bail!("invalid native envelope lookup");
        }
        let connection = self.connection()?;
        let descriptor = descriptor_in_connection(&connection, stream_id)?
            .context("native stream has no descriptor")?;
        let encoded: Option<Vec<u8>> = connection
            .query_row(
                "SELECT envelope FROM envelopes WHERE stream_id = ?1 AND epoch_id = ?2 \
                 AND key_group = ?3 AND recipient_id = ?4",
                params![
                    uuid_bytes(stream_id).as_slice(),
                    uuid_bytes(epoch_id).as_slice(),
                    to_sql_u64(key_group, "envelope key group")?,
                    recipient_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .context("reading exact viewer envelope")?;
        encoded
            .map(|encoded| {
                KeyEnvelope::decode(&encoded, &descriptor.body.publisher)
                    .context("decoding exact viewer envelope")
            })
            .transpose()
    }

    /// Returns a verified stream descriptor, if present.
    ///
    /// # Errors
    ///
    /// Returns an error for database or descriptor validation failure.
    pub fn descriptor(&self, stream_id: Uuid) -> Result<Option<StreamDescriptor>> {
        let connection = self.connection()?;
        descriptor_in_connection(&connection, stream_id)
    }

    /// Returns the highest sequence ever durably committed for a stream.
    ///
    /// # Errors
    ///
    /// Returns an error for database or numeric corruption.
    pub fn high_water(&self, stream_id: Uuid) -> Result<Option<u64>> {
        let connection = self.connection()?;
        let value: Option<i64> = connection
            .query_row(
                "SELECT high_water FROM streams WHERE stream_id = ?1",
                params![uuid_bytes(stream_id).as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context("reading native high-water mark")?;
        value
            .map(|value| from_sql_u64(value, "high-water mark"))
            .transpose()
    }

    /// Marks the active group complete when its publisher session ends.
    ///
    /// This makes the final group eligible for retained-history bounds and
    /// eviction. A reconnect starts a fresh epoch/group at the next sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for database failure or an unknown stream.
    pub fn finalize_stream(&self, stream_id: Uuid) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting stream finalization")?;
        let active: Option<(Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT active_epoch, active_group FROM streams \
                 WHERE stream_id = ?1 AND active_epoch IS NOT NULL AND active_group IS NOT NULL",
                params![uuid_bytes(stream_id).as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("reading active stream group")?;
        if let Some((epoch_id, key_group)) = active {
            transaction
                .execute(
                    "UPDATE groups SET complete = 1 WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                    params![uuid_bytes(stream_id).as_slice(), epoch_id, key_group],
                )
                .context("completing disconnected stream group")?;
            transaction
                .execute(
                    "UPDATE streams SET active_epoch = NULL, active_group = NULL WHERE stream_id = ?1",
                    params![uuid_bytes(stream_id).as_slice()],
                )
                .context("clearing disconnected stream group")?;
        }
        transaction
            .commit()
            .context("committing stream finalization")
    }

    /// Returns complete retained bounds for a stream.
    ///
    /// # Errors
    ///
    /// Returns an error for database or numeric corruption.
    pub fn retained_bounds(&self, stream_id: Uuid) -> Result<Option<NativeRetainedBounds>> {
        let connection = self.connection()?;
        retained_bounds_in_connection(&connection, stream_id)
    }

    /// Resolves a subscription request to a keyframe-group sequence boundary.
    ///
    /// Live starts after the current high-water mark. Explicit sequence/time
    /// starts select the containing or immediately preceding group, falling
    /// back to the oldest complete retained group. If no retained group exists,
    /// the result is the next live sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing stream, database corruption, numeric
    /// overflow, or query failure.
    pub fn subscription_anchor(&self, stream_id: Uuid, start: SubscriptionStart) -> Result<u64> {
        let connection = self.connection()?;
        let high_water: i64 = connection
            .query_row(
                "SELECT high_water FROM streams WHERE stream_id = ?1",
                params![uuid_bytes(stream_id).as_slice()],
                |row| row.get(0),
            )
            .context("subscription stream does not exist")?;
        let next_live = from_sql_u64(high_water, "subscription high-water")?
            .checked_add(1)
            .context("native sequence space exhausted")?;
        if start == SubscriptionStart::Live {
            return Ok(next_live);
        }
        let selected: Option<i64> = match start {
            SubscriptionStart::Live => unreachable!("live returned above"),
            SubscriptionStart::OldestRetained => connection
                .query_row(
                    "SELECT first_sequence FROM groups WHERE stream_id = ?1 AND complete = 1 \
                     ORDER BY first_sequence LIMIT 1",
                    params![uuid_bytes(stream_id).as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .context("finding oldest retained group")?,
            SubscriptionStart::Sequence(sequence) => connection
                .query_row(
                    "SELECT first_sequence FROM groups WHERE stream_id = ?1 AND first_sequence <= ?2 \
                     ORDER BY first_sequence DESC LIMIT 1",
                    params![
                        uuid_bytes(stream_id).as_slice(),
                        to_sql_u64(sequence, "subscription sequence")?
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context("finding sequence subscription group")?,
            SubscriptionStart::Timestamp(timestamp) => connection
                .query_row(
                    "SELECT first_sequence FROM groups WHERE stream_id = ?1 AND first_timestamp <= ?2 \
                     ORDER BY first_timestamp DESC, first_sequence DESC LIMIT 1",
                    params![
                        uuid_bytes(stream_id).as_slice(),
                        to_sql_u64(timestamp, "subscription timestamp")?
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context("finding timestamp subscription group")?,
        };
        match selected {
            Some(sequence) => from_sql_u64(sequence, "subscription anchor"),
            None => Ok(next_live),
        }
    }

    /// Returns summaries for every native stream ordered by stream ID.
    ///
    /// # Errors
    ///
    /// Returns an error for database, identifier, or numeric corruption.
    pub fn summaries(&self) -> Result<Vec<(Uuid, NativeStreamSummary)>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT s.stream_id, s.publisher_id, s.high_water, \
                        COALESCE(SUM(g.retained_bytes), 0) \
                 FROM streams s LEFT JOIN groups g USING(stream_id) \
                 GROUP BY s.stream_id ORDER BY s.stream_id",
            )
            .context("preparing native stream summaries")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .context("reading native stream summaries")?;
        let mut summaries = Vec::new();
        for row in rows {
            let (stream_id, publisher_id, high_water, retained_bytes) = row?;
            let stream_id = decode_uuid(&stream_id, "summary stream ID")?;
            summaries.push((
                stream_id,
                NativeStreamSummary {
                    publisher_id: publisher_id.try_into().map_err(|value: Vec<u8>| {
                        anyhow::anyhow!(
                            "summary publisher ID has length {} instead of 32",
                            value.len()
                        )
                    })?,
                    high_water: from_sql_u64(high_water, "summary high-water")?,
                    retained_bytes: from_sql_u64(retained_bytes, "summary byte count")?,
                    retained: retained_bounds_in_connection(&connection, stream_id)?,
                },
            ));
        }
        Ok(summaries)
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.inner
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("native store mutex poisoned"))
    }

    fn check_group_growth(
        &self,
        transaction: &Transaction<'_>,
        growth: GroupGrowth<'_>,
    ) -> Result<()> {
        let stream_bytes = uuid_bytes(growth.stream_id);
        let epoch_bytes = uuid_bytes(growth.epoch_id);
        let group = params![
            stream_bytes.as_slice(),
            epoch_bytes.as_slice(),
            to_sql_u64(growth.key_group, "resource-limit key group")?,
        ];
        let group_bytes: i64 = transaction
            .query_row(
                "SELECT retained_bytes FROM groups WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                group,
                |row| row.get(0),
            )
            .context("reading group byte usage")?;
        let count_table = match growth.item_kind {
            GroupItemKind::Object => "objects",
            GroupItemKind::Envelope => "envelopes",
        };
        let count_sql = format!(
            "SELECT COUNT(*) FROM {count_table} WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3"
        );
        let item_count: i64 = transaction
            .query_row(
                &count_sql,
                params![
                    uuid_bytes(growth.stream_id).as_slice(),
                    uuid_bytes(growth.epoch_id).as_slice(),
                    to_sql_u64(growth.key_group, "resource-limit key group")?,
                ],
                |row| row.get(0),
            )
            .context("counting group items")?;
        let item_limit = match growth.item_kind {
            GroupItemKind::Object => self.inner.limits.max_objects_per_group,
            GroupItemKind::Envelope => self.inner.limits.max_envelopes_per_group,
        };
        if u64::try_from(item_count).unwrap_or(u64::MAX) >= item_limit
            || from_sql_u64(group_bytes, "group byte usage")?.saturating_add(growth.added_bytes)
                > self.inner.limits.max_group_bytes
        {
            anyhow::bail!("native keyframe group resource limit reached");
        }
        let total_bytes: i64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(retained_bytes), 0) FROM groups",
                [],
                |row| row.get(0),
            )
            .context("summing relay retained bytes")?;
        let publisher_bytes: i64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(g.retained_bytes), 0) FROM groups g JOIN streams s USING(stream_id) WHERE s.publisher_id = ?1",
                params![growth.publisher_id.as_slice()],
                |row| row.get(0),
            )
            .context("summing publisher retained bytes")?;
        if from_sql_u64(total_bytes, "relay retained bytes")?.saturating_add(growth.added_bytes)
            > self.inner.limits.max_total_bytes
            || from_sql_u64(publisher_bytes, "publisher retained bytes")?
                .saturating_add(growth.added_bytes)
                > self.inner.limits.max_publisher_bytes
        {
            anyhow::bail!("native relay or publisher byte quota reached");
        }
        Ok(())
    }

    fn enforce_retention(
        &self,
        transaction: &Transaction<'_>,
        stream_id: Uuid,
        now_ms: i64,
    ) -> Result<usize> {
        let stream_bytes = || -> Result<u64> {
            let bytes: i64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(retained_bytes), 0) FROM groups WHERE stream_id = ?1",
                    params![uuid_bytes(stream_id).as_slice()],
                    |row| row.get(0),
                )
                .context("summing native retained bytes")?;
            from_sql_u64(bytes, "retained byte count")
        };
        let cutoff = self
            .inner
            .retention_age
            .map(|age| now_ms.saturating_sub(i64::try_from(age.as_millis()).unwrap_or(i64::MAX)));
        let mut removed = 0usize;
        loop {
            let bytes_exceeded = match self.inner.retention_bytes {
                Some(limit) => stream_bytes()? > limit,
                None => false,
            };
            let oldest: Option<(Vec<u8>, i64, i64)> = transaction
                .query_row(
                    "SELECT epoch_id, key_group, received_last_ms FROM groups \
                     WHERE stream_id = ?1 AND complete = 1 ORDER BY first_sequence LIMIT 1",
                    params![uuid_bytes(stream_id).as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .context("selecting oldest complete native group")?;
            let Some((epoch_id, key_group, received_last_ms)) = oldest else {
                break;
            };
            let age_exceeded = cutoff.is_some_and(|cutoff| received_last_ms < cutoff);
            if !bytes_exceeded && !age_exceeded {
                break;
            }
            transaction
                .execute(
                    "DELETE FROM groups WHERE stream_id = ?1 AND epoch_id = ?2 AND key_group = ?3",
                    params![uuid_bytes(stream_id).as_slice(), epoch_id, key_group],
                )
                .context("evicting complete native group")?;
            removed = removed.saturating_add(1);
        }
        Ok(removed)
    }
}

fn prepare_native_root(root: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("native store root must be a real directory");
            }
            let native_database = root.join(DATABASE_FILE);
            let recognized_v1 = root.join("streams").exists()
                && !native_database.exists()
                && fs::read_dir(root)
                    .with_context(|| format!("reading possible v1 store {}", root.display()))?
                    .next()
                    .is_some();
            if recognized_v1 {
                let file_name = root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("v1 store root has no UTF-8 file name")?;
                let quarantine = root.with_file_name(format!(
                    "{file_name}.v1-quarantine-{}-{}",
                    glacialcast_protocol::now_ms(),
                    Uuid::new_v4()
                ));
                fs::rename(root, &quarantine).with_context(|| {
                    format!(
                        "atomically quarantining incompatible v1 store {} as {}",
                        root.display(),
                        quarantine.display()
                    )
                })?;
                sync_parent(root)?;
                return Ok(Some(quarantine));
            }
            Ok(None)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspecting native store {}", root.display()))
        }
    }
}

fn reject_symlink_or_non_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting native store {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("native store root is not a real directory");
    }
    Ok(())
}

fn validate_existing_database(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
                anyhow::bail!("native database must be a singly linked regular file");
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                anyhow::bail!("native database is accessible by group or other users");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspecting native database {}", path.display()))
        }
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("synchronizing directory {}", parent.display()))
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .context("setting native database busy timeout")?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;\
             PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = FULL;\
             PRAGMA temp_store = MEMORY;\
             PRAGMA wal_autocheckpoint = 256;",
        )
        .context("configuring native database")?;
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("reading native schema version")?;
    if version != 0 && version != SCHEMA_VERSION {
        anyhow::bail!("unsupported native store schema version {version}");
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;\
             CREATE TABLE IF NOT EXISTS streams(\
                 stream_id BLOB PRIMARY KEY CHECK(length(stream_id) = 16),\
                 publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 32),\
                 descriptor BLOB NOT NULL,\
                 high_water INTEGER NOT NULL CHECK(high_water >= 0),\
                 active_epoch BLOB CHECK(active_epoch IS NULL OR length(active_epoch) = 16),\
                 active_group INTEGER CHECK(active_group IS NULL OR active_group > 0)\
             ) STRICT;\
             CREATE TABLE IF NOT EXISTS groups(\
                 stream_id BLOB NOT NULL,\
                 epoch_id BLOB NOT NULL CHECK(length(epoch_id) = 16),\
                 key_group INTEGER NOT NULL CHECK(key_group > 0),\
                 key_id BLOB NOT NULL CHECK(length(key_id) = 16),\
                 first_sequence INTEGER NOT NULL CHECK(first_sequence > 0),\
                 last_sequence INTEGER NOT NULL CHECK(last_sequence >= first_sequence),\
                 first_timestamp INTEGER NOT NULL CHECK(first_timestamp >= 0),\
                 last_timestamp INTEGER NOT NULL CHECK(last_timestamp >= first_timestamp),\
                 received_first_ms INTEGER NOT NULL,\
                 received_last_ms INTEGER NOT NULL,\
                 retained_bytes INTEGER NOT NULL CHECK(retained_bytes >= 0),\
                 complete INTEGER NOT NULL CHECK(complete IN (0, 1)),\
                 PRIMARY KEY(stream_id, epoch_id, key_group),\
                 FOREIGN KEY(stream_id) REFERENCES streams(stream_id) ON DELETE CASCADE\
             ) STRICT;\
             CREATE TABLE IF NOT EXISTS objects(\
                 stream_id BLOB NOT NULL,\
                 sequence INTEGER NOT NULL CHECK(sequence > 0),\
                 epoch_id BLOB NOT NULL CHECK(length(epoch_id) = 16),\
                 key_group INTEGER NOT NULL CHECK(key_group > 0),\
                 received_at_ms INTEGER NOT NULL,\
                 object BLOB NOT NULL,\
                 PRIMARY KEY(stream_id, sequence),\
                 FOREIGN KEY(stream_id, epoch_id, key_group) \
                     REFERENCES groups(stream_id, epoch_id, key_group) ON DELETE CASCADE\
             ) STRICT;\
             CREATE TABLE IF NOT EXISTS envelopes(\
                 stream_id BLOB NOT NULL,\
                 epoch_id BLOB NOT NULL CHECK(length(epoch_id) = 16),\
                 key_group INTEGER NOT NULL CHECK(key_group > 0),\
                 recipient_id BLOB NOT NULL CHECK(length(recipient_id) = 32),\
                 key_id BLOB NOT NULL CHECK(length(key_id) = 16),\
                 received_at_ms INTEGER NOT NULL,\
                 envelope BLOB NOT NULL,\
                 PRIMARY KEY(stream_id, epoch_id, key_group, recipient_id),\
                 FOREIGN KEY(stream_id, epoch_id, key_group) \
                     REFERENCES groups(stream_id, epoch_id, key_group) ON DELETE CASCADE\
             ) STRICT;\
             CREATE INDEX IF NOT EXISTS objects_group \
                 ON objects(stream_id, epoch_id, key_group);\
             CREATE INDEX IF NOT EXISTS envelopes_recipient \
                 ON envelopes(recipient_id, stream_id);\
             PRAGMA user_version = 2;\
             COMMIT;",
        )
        .context("initializing native store schema")?;
    Ok(())
}

fn validate_group_progression(
    active_epoch: Option<&[u8]>,
    active_group: Option<i64>,
    new_epoch: &[u8; 16],
    new_group: i64,
    object: &NativeObject,
) -> Result<()> {
    if let (Some(active_epoch), Some(active_group)) = (active_epoch, active_group)
        && active_epoch == new_epoch
        && new_group <= active_group
    {
        anyhow::bail!("native key group regressed within one epoch");
    }
    if object.header.kind == NativeObjectKind::Cursor || !object.header.random_access {
        anyhow::bail!("new native group does not begin at a random-access video boundary");
    }
    Ok(())
}

fn descriptor_in_transaction(
    transaction: &Transaction<'_>,
    stream_id: Uuid,
) -> Result<Option<StreamDescriptor>> {
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT descriptor FROM streams WHERE stream_id = ?1",
            params![uuid_bytes(stream_id).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .context("reading native descriptor")?;
    encoded
        .map(|encoded| StreamDescriptor::decode(&encoded).context("decoding native descriptor"))
        .transpose()
}

fn descriptor_in_connection(
    connection: &Connection,
    stream_id: Uuid,
) -> Result<Option<StreamDescriptor>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT descriptor FROM streams WHERE stream_id = ?1",
            params![uuid_bytes(stream_id).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .context("reading native descriptor")?;
    encoded
        .map(|encoded| StreamDescriptor::decode(&encoded).context("decoding native descriptor"))
        .transpose()
}

fn retained_bounds_in_connection(
    connection: &Connection,
    stream_id: Uuid,
) -> Result<Option<NativeRetainedBounds>> {
    let row: Option<(i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT MIN(first_sequence), MAX(last_sequence), \
                    MIN(first_timestamp), MAX(last_timestamp) \
             FROM groups WHERE stream_id = ?1 AND complete = 1 \
             HAVING COUNT(*) > 0",
            params![uuid_bytes(stream_id).as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .context("reading native retained bounds")?;
    row.map(
        |(oldest_sequence, newest_sequence, oldest_timestamp, newest_timestamp)| {
            Ok(NativeRetainedBounds {
                oldest_sequence: from_sql_u64(oldest_sequence, "oldest retained sequence")?,
                newest_sequence: from_sql_u64(newest_sequence, "newest retained sequence")?,
                oldest_timestamp: from_sql_u64(oldest_timestamp, "oldest retained timestamp")?,
                newest_timestamp: from_sql_u64(newest_timestamp, "newest retained timestamp")?,
            })
        },
    )
    .transpose()
}

fn uuid_bytes(value: Uuid) -> [u8; 16] {
    *value.as_bytes()
}

fn decode_uuid(bytes: &[u8], field: &str) -> Result<Uuid> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} has length {} instead of 16", bytes.len()))?;
    Ok(Uuid::from_bytes(bytes))
}

fn to_sql_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds the durable SQLite bound"))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{field} is negative in durable state"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_protocol::{
        envelope::KeyEnvelope,
        identity::IdentitySecret,
        native::{CodecId, GroupEncryptor, NativeObjectKind, NewNativeObject},
    };

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("glacialcast-native-store-{}", Uuid::new_v4()))
    }

    struct Fixture {
        publisher: IdentitySecret,
        viewer: IdentitySecret,
        descriptor: StreamDescriptor,
        stream_id: Uuid,
        epoch_id: Uuid,
        next_sequence: u64,
        next_group: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let publisher = IdentitySecret::generate();
            let viewer = IdentitySecret::generate();
            let stream_id = Uuid::new_v4();
            let epoch_id = Uuid::new_v4();
            let descriptor = StreamDescriptor::new(
                &publisher,
                stream_id,
                "screen".into(),
                "DP-1".into(),
                true,
                1,
            )
            .unwrap();
            Self {
                publisher,
                viewer,
                descriptor,
                stream_id,
                epoch_id,
                next_sequence: 1,
                next_group: 1,
            }
        }

        fn group(&mut self, prior_sequence: u64) -> GroupEncryptor {
            let group = GroupEncryptor::generate(
                &self.publisher.public().unwrap(),
                self.stream_id,
                self.epoch_id,
                self.next_group,
                prior_sequence,
            )
            .unwrap();
            self.next_group += 1;
            group
        }

        fn media(&mut self, group: &mut GroupEncryptor, bytes: usize) -> NativeObject {
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            let mut payload = vec![0u8; bytes.max(4)];
            payload[..4].copy_from_slice(&[0, 0, 1, 0x65]);
            group
                .seal(
                    &self.publisher,
                    NewNativeObject {
                        sequence,
                        timestamp: sequence * 3_000,
                        duration: 3_000,
                        kind: NativeObjectKind::Media,
                        random_access: true,
                        codec: Some(CodecId::H264AnnexB),
                    },
                    &payload,
                )
                .unwrap()
        }
    }

    #[test]
    fn store_recovers_high_water_and_idempotent_objects_after_restart() {
        let root = root();
        let mut fixture = Fixture::new();
        let store = NativeStore::open(
            root.clone(),
            Some(10_000_000),
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();
        let mut group = fixture.group(0);
        let object = fixture.media(&mut group, 100);
        let commit = store.store_object(&object, 1_000).unwrap();
        assert_eq!(commit.committed_through, 1);
        assert!(commit.inserted);
        assert!(!store.store_object(&object, 1_001).unwrap().inserted);
        drop(store);

        let reopened = NativeStore::open(
            root.clone(),
            Some(10_000_000),
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        assert_eq!(reopened.high_water(fixture.stream_id).unwrap(), Some(1));
        assert_eq!(
            reopened.get_object(fixture.stream_id, 1).unwrap(),
            Some(object)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_group_retention_cascades_objects_and_envelopes_atomically() {
        let root = root();
        let mut fixture = Fixture::new();
        let store = NativeStore::open(root.clone(), Some(900), None).unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();

        let mut first_group = fixture.group(0);
        let first = fixture.media(&mut first_group, 400);
        store.store_object(&first, 1_000).unwrap();
        let envelope = KeyEnvelope::seal(
            &fixture.publisher,
            &fixture.viewer.public().unwrap(),
            fixture.stream_id,
            fixture.epoch_id,
            first.header.key_group,
            first.header.key_id,
            &first_group.content_key(),
        )
        .unwrap();
        store.store_envelope(&envelope, 1_001).unwrap();

        let mut second_group = fixture.group(1);
        let second = fixture.media(&mut second_group, 400);
        let commit = store.store_object(&second, 2_000).unwrap();
        assert_eq!(commit.evicted_groups, 1);
        assert!(store.get_object(fixture.stream_id, 1).unwrap().is_none());
        assert!(
            store
                .list_envelopes(
                    fixture.stream_id,
                    fixture.viewer.public().unwrap().id().unwrap(),
                    10,
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.high_water(fixture.stream_id).unwrap(), Some(2));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn envelopes_require_exact_group_key_and_cannot_conflict() {
        let root = root();
        let mut fixture = Fixture::new();
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();
        let mut group = fixture.group(0);
        let object = fixture.media(&mut group, 20);
        store.store_object(&object, 1_000).unwrap();
        let envelope = KeyEnvelope::seal(
            &fixture.publisher,
            &fixture.viewer.public().unwrap(),
            fixture.stream_id,
            fixture.epoch_id,
            object.header.key_group,
            object.header.key_id,
            &group.content_key(),
        )
        .unwrap();
        assert!(store.store_envelope(&envelope, 1_001).unwrap());
        assert!(!store.store_envelope(&envelope, 1_002).unwrap());
        assert_eq!(
            store
                .get_envelope(
                    fixture.stream_id,
                    fixture.epoch_id,
                    object.header.key_group,
                    fixture.viewer.public().unwrap().id().unwrap(),
                )
                .unwrap(),
            Some(envelope.clone())
        );
        assert!(
            store
                .get_envelope(
                    fixture.stream_id,
                    fixture.epoch_id,
                    object.header.key_group,
                    IdentitySecret::generate().public().unwrap().id().unwrap(),
                )
                .unwrap()
                .is_none()
        );
        let mut wrong_group = envelope;
        wrong_group.header.key_group_id += 1;
        assert!(store.store_envelope(&wrong_group, 1_003).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hard_limits_reject_stream_object_envelope_and_byte_exhaustion() {
        let store_root = root();
        let mut fixture = Fixture::new();
        let limits = NativeStoreLimits {
            max_streams: 2,
            max_streams_per_publisher: 1,
            max_objects_per_group: 1,
            max_envelopes_per_group: 1,
            ..NativeStoreLimits::default()
        };
        let store = NativeStore::open_with_limits(store_root.clone(), None, None, limits).unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();
        let same_publisher_stream = StreamDescriptor::new(
            &fixture.publisher,
            Uuid::new_v4(),
            "second".into(),
            "test".into(),
            false,
            1,
        )
        .unwrap();
        assert!(store.put_descriptor(&same_publisher_stream).is_err());

        let other_publisher = IdentitySecret::generate();
        let other_stream = StreamDescriptor::new(
            &other_publisher,
            Uuid::new_v4(),
            "other".into(),
            "test".into(),
            false,
            1,
        )
        .unwrap();
        store.put_descriptor(&other_stream).unwrap();
        let third_publisher = IdentitySecret::generate();
        let third_stream = StreamDescriptor::new(
            &third_publisher,
            Uuid::new_v4(),
            "third".into(),
            "test".into(),
            false,
            1,
        )
        .unwrap();
        assert!(store.put_descriptor(&third_stream).is_err());

        let mut group = fixture.group(0);
        let first = fixture.media(&mut group, 20);
        store.store_object(&first, 1_000).unwrap();
        let second = fixture.media(&mut group, 20);
        assert!(store.store_object(&second, 1_001).is_err());
        assert_eq!(store.high_water(fixture.stream_id).unwrap(), Some(1));

        let first_envelope = KeyEnvelope::seal(
            &fixture.publisher,
            &fixture.viewer.public().unwrap(),
            fixture.stream_id,
            fixture.epoch_id,
            first.header.key_group,
            first.header.key_id,
            &group.content_key(),
        )
        .unwrap();
        store.store_envelope(&first_envelope, 1_002).unwrap();
        let second_viewer = IdentitySecret::generate();
        let second_envelope = KeyEnvelope::seal(
            &fixture.publisher,
            &second_viewer.public().unwrap(),
            fixture.stream_id,
            fixture.epoch_id,
            first.header.key_group,
            first.header.key_id,
            &group.content_key(),
        )
        .unwrap();
        assert!(store.store_envelope(&second_envelope, 1_003).is_err());
        fs::remove_dir_all(store_root).unwrap();

        let byte_root = root();
        let mut byte_fixture = Fixture::new();
        let byte_store = NativeStore::open_with_limits(
            byte_root.clone(),
            None,
            None,
            NativeStoreLimits {
                max_group_bytes: 1,
                max_total_bytes: 1,
                max_publisher_bytes: 1,
                ..NativeStoreLimits::default()
            },
        )
        .unwrap();
        byte_store.put_descriptor(&byte_fixture.descriptor).unwrap();
        let mut byte_group = byte_fixture.group(0);
        let object = byte_fixture.media(&mut byte_group, 20);
        assert!(byte_store.store_object(&object, 1_000).is_err());
        assert_eq!(
            byte_store.high_water(byte_fixture.stream_id).unwrap(),
            Some(0)
        );
        fs::remove_dir_all(byte_root).unwrap();
    }

    #[test]
    fn periodic_age_retention_evicts_only_complete_groups() {
        let root = root();
        let mut fixture = Fixture::new();
        let store = NativeStore::open(root.clone(), None, Some(Duration::from_secs(1))).unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();

        let mut first_group = fixture.group(0);
        let first = fixture.media(&mut first_group, 20);
        store.store_object(&first, 1_000).unwrap();
        assert_eq!(store.enforce_retention_at(10_000).unwrap(), 0);
        assert!(store.get_object(fixture.stream_id, 1).unwrap().is_some());

        let mut second_group = fixture.group(1);
        let second = fixture.media(&mut second_group, 20);
        store.store_object(&second, 1_500).unwrap();
        assert_eq!(store.enforce_retention_at(3_000).unwrap(), 1);
        assert!(store.get_object(fixture.stream_id, 1).unwrap().is_none());
        assert!(store.get_object(fixture.stream_id, 2).unwrap().is_some());
        assert_eq!(store.high_water(fixture.stream_id).unwrap(), Some(2));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disconnect_finalizes_history_and_allows_a_fresh_epoch() {
        let root = root();
        let mut fixture = Fixture::new();
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        store.put_descriptor(&fixture.descriptor).unwrap();
        let mut first_group = fixture.group(0);
        let first = fixture.media(&mut first_group, 20);
        store.store_object(&first, 1_000).unwrap();
        assert!(store.retained_bounds(fixture.stream_id).unwrap().is_none());
        store.finalize_stream(fixture.stream_id).unwrap();
        assert_eq!(
            store
                .retained_bounds(fixture.stream_id)
                .unwrap()
                .unwrap()
                .newest_sequence,
            1
        );

        let next_epoch = Uuid::new_v4();
        let mut next_group = GroupEncryptor::generate(
            &fixture.publisher.public().unwrap(),
            fixture.stream_id,
            next_epoch,
            1,
            1,
        )
        .unwrap();
        let second = next_group
            .seal(
                &fixture.publisher,
                NewNativeObject {
                    sequence: 2,
                    timestamp: 6_000,
                    duration: 3_000,
                    kind: NativeObjectKind::Media,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &[0, 0, 1, 0x65],
            )
            .unwrap();
        store.store_object(&second, 2_000).unwrap();
        assert_eq!(store.high_water(fixture.stream_id).unwrap(), Some(2));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recognized_v1_store_is_renamed_without_deletion() {
        let root = root();
        fs::create_dir_all(root.join("streams/old-stream")).unwrap();
        fs::write(root.join("streams/old-stream/catalog.json"), b"old").unwrap();
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        let quarantine = store.quarantined_v1_path().unwrap().to_path_buf();
        assert!(quarantine.join("streams/old-stream/catalog.json").exists());
        assert!(root.join(DATABASE_FILE).exists());
        drop(store);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(quarantine).unwrap();
    }

    #[test]
    fn database_symlinks_and_public_permissions_fail_closed() {
        use std::os::unix::fs::symlink;

        let root = root();
        fs::create_dir_all(&root).unwrap();
        let target = root.with_extension("target");
        fs::write(&target, b"not sqlite").unwrap();
        symlink(&target, root.join(DATABASE_FILE)).unwrap();
        assert!(NativeStore::open(root.clone(), None, None).is_err());
        fs::remove_file(root.join(DATABASE_FILE)).unwrap();
        fs::write(root.join(DATABASE_FILE), b"not sqlite").unwrap();
        fs::set_permissions(root.join(DATABASE_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NativeStore::open(root.clone(), None, None).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(target).unwrap();
    }
}
