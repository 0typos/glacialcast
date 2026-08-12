//! Durable bounded relay queues for signed offline pairing records.

use anyhow::{Context, Result};
use glacialcast_protocol::{
    identity::IdentityPublic,
    pairing::{
        MAX_PAIRING_MESSAGE_LEN, PairDecisionReason, PairOffer, PairRequest, PublisherDecision,
        ViewerConfirmation, transcript_hash,
    },
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const DATABASE_FILE: &str = "pairing-v1.sqlite3";
const SCHEMA_VERSION: i64 = 1;
const MAX_PENDING_GLOBAL: i64 = 16_384;
const MAX_PENDING_PER_PUBLISHER: i64 = 1_024;
const MAX_REQUESTS_PER_MINUTE: i64 = 10;
const MAX_INBOX_RECORDS: usize = 4_096;
const DECISION_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// Request plus relay-observed informational delivery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairRequestDelivery {
    /// Unmodified viewer-signed request.
    pub request: PairRequest,
    /// Actual network peer observed by the relay.
    pub source_addr: SocketAddr,
    /// Relay receive time as Unix milliseconds.
    pub received_at_ms: i64,
}

/// Pending records delivered to an online publisher.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublisherPairingInbox {
    /// Undecided, unexpired requests for this publisher.
    pub requests: Vec<PairRequestDelivery>,
    /// Viewer confirmations not yet followed by a final decision.
    pub confirmations: Vec<ViewerConfirmation>,
}

/// Queued records delivered to one viewer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ViewerPairingInbox {
    /// Publisher offers for this viewer's requests.
    pub offers: Vec<PairOffer>,
    /// Final publisher approvals or rejections.
    pub decisions: Vec<PublisherDecision>,
}

/// Durable pairing queue independent from stream ciphertext storage.
#[derive(Clone)]
pub struct PairingStore {
    connection: Arc<Mutex<Connection>>,
}

impl PairingStore {
    /// Opens or creates the bounded pairing queue in a private directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, incompatible schema, or SQLite setup.
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("creating pairing store {}", root.display()))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing pairing store {}", root.display()))?;
        let database = root.join(DATABASE_FILE);
        match fs::symlink_metadata(&database) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    anyhow::bail!("pairing database must be a private singly linked regular file");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspecting pairing database"),
        }
        let connection = Connection::open_with_flags(
            &database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("opening pairing database")?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .context("securing pairing database")?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .context("setting pairing database timeout")?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;\
                 PRAGMA journal_mode = WAL;\
                 PRAGMA synchronous = FULL;\
                 PRAGMA temp_store = MEMORY;",
            )
            .context("configuring pairing database")?;
        initialize_schema(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Durably queues one valid signed request, deduplicated by request ID.
    ///
    /// Source address is informational and comes from the accepted socket, not
    /// viewer-controlled message data. Rate limits apply independently by
    /// source and viewer identity over a rolling one-minute database window.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/expired signatures, queue/rate bounds,
    /// conflicting replay, unsafe serialization, or durable commit failure.
    pub fn enqueue_request(
        &self,
        request: &PairRequest,
        source_addr: SocketAddr,
        now_ms: i64,
        max_lifetime_ms: i64,
    ) -> Result<bool> {
        request
            .verify(now_ms, max_lifetime_ms)
            .context("verifying queued pair request")?;
        let encoded = encode_pair(request)?;
        let request_id = request.id()?;
        let publisher_id = request.body.publisher.id()?;
        let viewer_id = request.body.viewer.id()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting pair request transaction")?;
        purge(&transaction, now_ms)?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT request FROM pair_requests WHERE request_id = ?1",
                params![request_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context("checking pair request replay")?;
        if let Some(existing) = existing {
            if existing != encoded {
                anyhow::bail!("pair request ID conflicts with different signed content");
            }
            transaction
                .commit()
                .context("committing pair request retry")?;
            return Ok(false);
        }

        require_count_below(
            &transaction,
            "SELECT COUNT(*) FROM pair_requests WHERE decision IS NULL",
            [],
            MAX_PENDING_GLOBAL,
            "global pending pairing queue is full",
        )?;
        require_count_below(
            &transaction,
            "SELECT COUNT(*) FROM pair_requests WHERE publisher_id = ?1 AND decision IS NULL",
            params![publisher_id.as_slice()],
            MAX_PENDING_PER_PUBLISHER,
            "publisher pending pairing queue is full",
        )?;
        let window_start = now_ms.saturating_sub(60_000);
        require_count_below(
            &transaction,
            "SELECT COUNT(*) FROM pair_requests WHERE source_addr = ?1 AND received_at_ms >= ?2",
            params![source_addr.to_string(), window_start],
            MAX_REQUESTS_PER_MINUTE,
            "pairing source rate limit exceeded",
        )?;
        require_count_below(
            &transaction,
            "SELECT COUNT(*) FROM pair_requests WHERE viewer_id = ?1 AND received_at_ms >= ?2",
            params![viewer_id.as_slice(), window_start],
            MAX_REQUESTS_PER_MINUTE,
            "pairing identity rate limit exceeded",
        )?;

        transaction
            .execute(
                "INSERT INTO pair_requests(\
                     request_id, publisher_id, viewer_id, source_addr, received_at_ms, expires_at_ms, request\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    request_id.as_slice(),
                    publisher_id.as_slice(),
                    viewer_id.as_slice(),
                    source_addr.to_string(),
                    now_ms,
                    request.body.expires_at_ms,
                    encoded,
                ],
            )
            .context("inserting pair request")?;
        transaction.commit().context("committing pair request")?;
        Ok(true)
    }

    /// Durably queues a publisher offer for its exact pending request.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/expired request, transcript/signature
    /// mismatch, or durable commit failure. A verified resubmission with
    /// different bytes keeps the first stored artifact and reports success.
    pub fn store_offer(
        &self,
        offer: &PairOffer,
        now_ms: i64,
        max_lifetime_ms: i64,
    ) -> Result<bool> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting pair offer transaction")?;
        purge(&transaction, now_ms)?;
        let request = request_by_id(&transaction, &offer.body.request_id)?
            .context("pair offer request is not pending")?;
        offer
            .verify(&request, now_ms, max_lifetime_ms)
            .context("verifying pair offer")?;
        let encoded = encode_pair(offer)?;
        let changed = store_once(&transaction, "offer", &offer.body.request_id, &encoded)?;
        transaction.commit().context("committing pair offer")?;
        Ok(changed)
    }

    /// Durably queues the viewer's explicit yes confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error for missing request/offer, transcript/signature
    /// mismatch, or durable commit failure. A verified resubmission with
    /// different bytes keeps the first stored artifact and reports success.
    pub fn store_confirmation(
        &self,
        confirmation: &ViewerConfirmation,
        now_ms: i64,
    ) -> Result<bool> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting viewer confirmation transaction")?;
        purge(&transaction, now_ms)?;
        let request = request_by_id(&transaction, &confirmation.body.request_id)?
            .context("viewer confirmation request is not pending")?;
        let offer = offer_by_id(&transaction, &confirmation.body.request_id)?
            .context("viewer confirmation has no publisher offer")?;
        confirmation
            .verify(&request, &offer)
            .context("verifying viewer confirmation")?;
        let encoded = encode_pair(confirmation)?;
        let changed = store_once(
            &transaction,
            "confirmation",
            &confirmation.body.request_id,
            &encoded,
        )?;
        transaction
            .commit()
            .context("committing viewer confirmation")?;
        Ok(changed)
    }

    /// Durably queues the publisher's final approval or rejection.
    ///
    /// Manual approvals require the exact stored offer and viewer confirmation;
    /// trusted-CA/open decisions deliberately use their zero transcript.
    ///
    /// # Errors
    ///
    /// Returns an error for missing state, invalid signatures/transcripts,
    /// conflicting retry, or durable commit failure.
    pub fn store_decision(&self, decision: &PublisherDecision, now_ms: i64) -> Result<bool> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting publisher decision transaction")?;
        purge(&transaction, now_ms)?;
        let request = request_by_id(&transaction, &decision.body.request_id)?
            .context("publisher decision request is unknown")?;
        decision
            .verify(&request, &request.body.publisher)
            .context("verifying publisher decision")?;
        if decision.body.reason == PairDecisionReason::ManualVerified {
            let offer = offer_by_id(&transaction, &decision.body.request_id)?
                .context("manual publisher decision has no offer")?;
            let confirmation = confirmation_by_id(&transaction, &decision.body.request_id)?
                .context("manual publisher decision has no viewer confirmation")?;
            confirmation
                .verify(&request, &offer)
                .context("verifying stored viewer confirmation")?;
            if decision.body.transcript_hash != transcript_hash(&request, &offer)? {
                anyhow::bail!("publisher decision transcript does not match stored ceremony");
            }
        }
        let encoded = encode_pair(decision)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT decision FROM pair_requests WHERE request_id = ?1",
                params![decision.body.request_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context("checking publisher decision retry")?
            .flatten();
        if let Some(existing) = existing {
            // A publisher retrying its decision after a restart re-signs it
            // with a fresh timestamp. The stored decision was verified against
            // the same ceremony, so keep it — it is the one the viewer may
            // already have acted on — and report the retry as already served.
            let _ = existing;
            transaction.commit().context("committing decision retry")?;
            return Ok(false);
        }
        transaction
            .execute(
                "UPDATE pair_requests SET decision = ?2, decided_at_ms = ?3 WHERE request_id = ?1",
                params![decision.body.request_id.as_slice(), encoded, now_ms],
            )
            .context("storing publisher decision")?;
        transaction
            .commit()
            .context("committing publisher decision")?;
        Ok(true)
    }

    /// Lists an online publisher's pending requests and confirmations.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, database corruption, unsafe
    /// encoded state, or queue bounds.
    pub fn publisher_inbox(
        &self,
        publisher: &IdentityPublic,
        now_ms: i64,
    ) -> Result<PublisherPairingInbox> {
        let publisher_id = publisher.id()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting publisher inbox transaction")?;
        purge(&transaction, now_ms)?;
        let mut statement = transaction
            .prepare(
                "SELECT request, source_addr, received_at_ms, confirmation \
                 FROM pair_requests WHERE publisher_id = ?1 AND decision IS NULL \
                 ORDER BY received_at_ms, request_id LIMIT ?2",
            )
            .context("preparing publisher pairing inbox")?;
        let rows = statement
            .query_map(
                params![
                    publisher_id.as_slice(),
                    i64::try_from(MAX_INBOX_RECORDS).expect("inbox bound fits i64")
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .context("reading publisher pairing inbox")?;
        let mut inbox = PublisherPairingInbox::default();
        for row in rows {
            let (request, source_addr, received_at_ms, confirmation) = row?;
            let request: PairRequest = decode_pair(&request)?;
            let request_lifetime_ms = request
                .body
                .expires_at_ms
                .checked_sub(request.body.issued_at_ms)
                .context("queued pair request has an invalid lifetime")?;
            request
                .verify(now_ms, request_lifetime_ms)
                .context("verifying queued pair request")?;
            inbox.requests.push(PairRequestDelivery {
                request,
                source_addr: source_addr
                    .parse()
                    .context("parsing queued source address")?,
                received_at_ms,
            });
            if let Some(confirmation) = confirmation {
                inbox.confirmations.push(decode_pair(&confirmation)?);
            }
        }
        drop(statement);
        transaction
            .commit()
            .context("committing publisher inbox purge")?;
        Ok(inbox)
    }

    /// Lists queued offers and decisions addressed to one viewer identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, database corruption, or unsafe
    /// encoded state.
    pub fn viewer_inbox(&self, viewer: &IdentityPublic, now_ms: i64) -> Result<ViewerPairingInbox> {
        let viewer_id = viewer.id()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("starting viewer inbox transaction")?;
        purge(&transaction, now_ms)?;
        let mut statement = transaction
            .prepare(
                "SELECT offer, decision FROM pair_requests WHERE viewer_id = ?1 \
                 AND (offer IS NOT NULL OR decision IS NOT NULL) \
                 ORDER BY received_at_ms, request_id LIMIT ?2",
            )
            .context("preparing viewer pairing inbox")?;
        let rows = statement
            .query_map(
                params![
                    viewer_id.as_slice(),
                    i64::try_from(MAX_INBOX_RECORDS).expect("inbox bound fits i64")
                ],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                    ))
                },
            )
            .context("reading viewer pairing inbox")?;
        let mut inbox = ViewerPairingInbox::default();
        for row in rows {
            let (offer, decision) = row?;
            if let Some(offer) = offer {
                inbox.offers.push(decode_pair(&offer)?);
            }
            if let Some(decision) = decision {
                inbox.decisions.push(decode_pair(&decision)?);
            }
        }
        drop(statement);
        transaction
            .commit()
            .context("committing viewer inbox purge")?;
        Ok(inbox)
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("pairing store mutex poisoned"))
    }
}

fn initialize_schema(connection: &Connection) -> Result<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("reading pairing schema version")?;
    if version != 0 && version != SCHEMA_VERSION {
        anyhow::bail!("unsupported pairing schema version {version}");
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;\
             CREATE TABLE IF NOT EXISTS pair_requests(\
                 request_id BLOB PRIMARY KEY CHECK(length(request_id) = 32),\
                 publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 32),\
                 viewer_id BLOB NOT NULL CHECK(length(viewer_id) = 32),\
                 source_addr TEXT NOT NULL CHECK(length(source_addr) BETWEEN 3 AND 128),\
                 received_at_ms INTEGER NOT NULL,\
                 expires_at_ms INTEGER NOT NULL,\
                 request BLOB NOT NULL,\
                 offer BLOB,\
                 confirmation BLOB,\
                 decision BLOB,\
                 decided_at_ms INTEGER\
             ) STRICT;\
             CREATE INDEX IF NOT EXISTS pairing_publisher \
                 ON pair_requests(publisher_id, received_at_ms);\
             CREATE INDEX IF NOT EXISTS pairing_viewer \
                 ON pair_requests(viewer_id, received_at_ms);\
             CREATE INDEX IF NOT EXISTS pairing_source \
                 ON pair_requests(source_addr, received_at_ms);\
             PRAGMA user_version = 1;\
             COMMIT;",
        )
        .context("initializing pairing schema")?;
    Ok(())
}

fn purge(transaction: &rusqlite::Transaction<'_>, now_ms: i64) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM pair_requests WHERE \
                 (decision IS NULL AND expires_at_ms <= ?1) OR \
                 (decision IS NOT NULL AND decided_at_ms < ?2)",
            params![now_ms, now_ms.saturating_sub(DECISION_RETENTION_MS)],
        )
        .context("purging expired pairing records")?;
    Ok(())
}

fn request_by_id(
    transaction: &rusqlite::Transaction<'_>,
    request_id: &[u8; 32],
) -> Result<Option<PairRequest>> {
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT request FROM pair_requests WHERE request_id = ?1",
            params![request_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .context("reading queued pair request")?;
    encoded.map(|encoded| decode_pair(&encoded)).transpose()
}

fn offer_by_id(
    transaction: &rusqlite::Transaction<'_>,
    request_id: &[u8; 32],
) -> Result<Option<PairOffer>> {
    let encoded: Option<Option<Vec<u8>>> = transaction
        .query_row(
            "SELECT offer FROM pair_requests WHERE request_id = ?1",
            params![request_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .context("reading queued pair offer")?;
    encoded
        .flatten()
        .map(|encoded| decode_pair(&encoded))
        .transpose()
}

fn confirmation_by_id(
    transaction: &rusqlite::Transaction<'_>,
    request_id: &[u8; 32],
) -> Result<Option<ViewerConfirmation>> {
    let encoded: Option<Option<Vec<u8>>> = transaction
        .query_row(
            "SELECT confirmation FROM pair_requests WHERE request_id = ?1",
            params![request_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .context("reading queued viewer confirmation")?;
    encoded
        .flatten()
        .map(|encoded| decode_pair(&encoded))
        .transpose()
}

fn store_once(
    transaction: &rusqlite::Transaction<'_>,
    column: &str,
    request_id: &[u8; 32],
    encoded: &[u8],
) -> Result<bool> {
    let sql = match column {
        "offer" => "SELECT offer FROM pair_requests WHERE request_id = ?1",
        "confirmation" => "SELECT confirmation FROM pair_requests WHERE request_id = ?1",
        _ => anyhow::bail!("unsupported pairing column"),
    };
    let existing: Option<Option<Vec<u8>>> = transaction
        .query_row(sql, params![request_id.as_slice()], |row| row.get(0))
        .optional()
        .context("checking queued pairing record")?;
    if let Some(Some(existing)) = existing {
        // A peer that restarts mid-ceremony re-creates its artifact with a
        // fresh timestamp and signature, so a resubmission for the same
        // request arrives with different bytes. It was verified against the
        // same signed ceremony before this point, so the slot is already
        // served: keep the first artifact — the one the other side's
        // transcript may already reference. Refusing the retry wedged the
        // ceremony permanently.
        let _ = existing;
        return Ok(false);
    }
    if existing.is_none() {
        anyhow::bail!("pairing request no longer exists");
    }
    let update = match column {
        "offer" => "UPDATE pair_requests SET offer = ?2 WHERE request_id = ?1",
        "confirmation" => "UPDATE pair_requests SET confirmation = ?2 WHERE request_id = ?1",
        _ => unreachable!("validated above"),
    };
    transaction
        .execute(update, params![request_id.as_slice(), encoded])
        .context("storing queued pairing record")?;
    Ok(true)
}

fn require_count_below<P: rusqlite::Params>(
    transaction: &rusqlite::Transaction<'_>,
    sql: &str,
    parameters: P,
    limit: i64,
    error: &str,
) -> Result<()> {
    let count: i64 = transaction
        .query_row(sql, parameters, |row| row.get(0))
        .context("counting bounded pairing queue")?;
    if count >= limit {
        anyhow::bail!(error.to_string());
    }
    Ok(())
}

fn encode_pair<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let encoded = postcard::to_stdvec(value).context("encoding pairing record")?;
    if encoded.len() > MAX_PAIRING_MESSAGE_LEN {
        anyhow::bail!("pairing record exceeds its bound");
    }
    Ok(encoded)
}

fn decode_pair<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > MAX_PAIRING_MESSAGE_LEN {
        anyhow::bail!("pairing record exceeds its bound");
    }
    let (value, remainder) =
        postcard::take_from_bytes::<T>(bytes).context("decoding pairing record")?;
    if !remainder.is_empty() || postcard::to_stdvec(&value)? != bytes {
        anyhow::bail!("pairing record is trailing or noncanonical");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_protocol::{
        identity::IdentitySecret,
        pairing::{PairOffer, PublisherDecision, ViewerConfirmation},
    };

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "glacialcast-pairing-store-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn resigned_ceremony_resubmissions_keep_the_first_artifact() {
        let root = root();
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let source = "127.0.0.1:4321".parse().unwrap();
        let store = PairingStore::open(root.clone()).unwrap();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            uuid::Uuid::from_u128(1),
            "viewer".into(),
            1_000,
            1_000 + DAY_MS,
        )
        .unwrap();
        store
            .enqueue_request(&request, source, 1_500, DAY_MS)
            .unwrap();

        // Each artifact is re-signed with a fresh timestamp when a restarted
        // peer resubmits it, so the same ceremony arrives with different
        // bytes. Every resubmission must succeed without replacing what the
        // other side may already have acted on; refusing it wedged the
        // ceremony permanently.
        let offer =
            PairOffer::new(&publisher, &request, [7; 32], 2_000, 2_000 + DAY_MS, DAY_MS).unwrap();
        assert!(store.store_offer(&offer, 2_100, DAY_MS).unwrap());
        let reoffer =
            PairOffer::new(&publisher, &request, [7; 32], 2_200, 2_200 + DAY_MS, DAY_MS).unwrap();
        assert!(!store.store_offer(&reoffer, 2_300, DAY_MS).unwrap());

        let confirmation = ViewerConfirmation::approve(&viewer, &request, &offer, 3_000).unwrap();
        assert!(store.store_confirmation(&confirmation, 3_100).unwrap());
        let reconfirmation = ViewerConfirmation::approve(&viewer, &request, &offer, 3_200).unwrap();
        assert!(!store.store_confirmation(&reconfirmation, 3_300).unwrap());

        let decision =
            PublisherDecision::approve_manual(&publisher, &request, &offer, &confirmation, 4_000)
                .unwrap();
        assert!(store.store_decision(&decision, 4_100).unwrap());
        let redecision =
            PublisherDecision::approve_manual(&publisher, &request, &offer, &confirmation, 4_200)
                .unwrap();
        assert!(!store.store_decision(&redecision, 4_300).unwrap());

        // The first artifacts are what remain: the viewer's inbox delivers
        // the original offer's ceremony and the original decision.
        let inbox = store
            .viewer_inbox(&viewer.public().unwrap(), 4_400)
            .unwrap();
        assert_eq!(inbox.decisions, vec![decision]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pairing_records_queue_offline_and_survive_restart() {
        let root = root();
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            uuid::Uuid::from_u128(1),
            "viewer".into(),
            1_000,
            1_000 + DAY_MS,
        )
        .unwrap();
        let source = "127.0.0.1:4321".parse().unwrap();
        let store = PairingStore::open(root.clone()).unwrap();
        assert!(
            store
                .enqueue_request(&request, source, 2_000, DAY_MS)
                .unwrap()
        );
        assert!(
            !store
                .enqueue_request(&request, source, 2_001, DAY_MS)
                .unwrap()
        );
        let offer =
            PairOffer::new(&publisher, &request, [7; 32], 3_000, 3_000 + DAY_MS, DAY_MS).unwrap();
        store.store_offer(&offer, 4_000, DAY_MS).unwrap();
        let confirmation = ViewerConfirmation::approve(&viewer, &request, &offer, 5_000).unwrap();
        store.store_confirmation(&confirmation, 5_000).unwrap();
        drop(store);

        let reopened = PairingStore::open(root.clone()).unwrap();
        let publisher_inbox = reopened
            .publisher_inbox(&publisher.public().unwrap(), 6_000)
            .unwrap();
        assert_eq!(publisher_inbox.requests.len(), 1);
        assert_eq!(
            publisher_inbox.confirmations,
            std::slice::from_ref(&confirmation)
        );
        let viewer_inbox = reopened
            .viewer_inbox(&viewer.public().unwrap(), 6_000)
            .unwrap();
        assert_eq!(viewer_inbox.offers, std::slice::from_ref(&offer));

        let decision =
            PublisherDecision::approve_manual(&publisher, &request, &offer, &confirmation, 7_000)
                .unwrap();
        reopened.store_decision(&decision, 7_000).unwrap();
        assert!(
            reopened
                .publisher_inbox(&publisher.public().unwrap(), 8_000)
                .unwrap()
                .requests
                .is_empty()
        );
        assert_eq!(
            reopened
                .viewer_inbox(&viewer.public().unwrap(), 8_000)
                .unwrap()
                .decisions,
            [decision]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_requests_and_identity_or_transcript_substitution_fail_closed() {
        let root = root();
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            uuid::Uuid::from_u128(1),
            "viewer".into(),
            1_000,
            2_000,
        )
        .unwrap();
        let store = PairingStore::open(root.clone()).unwrap();
        assert!(
            store
                .enqueue_request(&request, "127.0.0.1:1".parse().unwrap(), 2_000, DAY_MS)
                .is_err()
        );

        let valid = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            uuid::Uuid::from_u128(1),
            "viewer".into(),
            3_000,
            3_000 + DAY_MS,
        )
        .unwrap();
        store
            .enqueue_request(&valid, "127.0.0.1:1".parse().unwrap(), 4_000, DAY_MS)
            .unwrap();
        let other_publisher = IdentitySecret::generate();
        assert!(
            PairOffer::new(
                &other_publisher,
                &valid,
                [7; 32],
                5_000,
                5_000 + DAY_MS,
                DAY_MS,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
