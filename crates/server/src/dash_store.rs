use anyhow::{Context, Result};
use glacialcast_dash::{EpochDescriptor, MpdConfig, SegmentTimelineEntry, build_mpd};
use glacialcast_protocol::{DashObject, DashObjectHeader, DashObjectKind};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use uuid::Uuid;

const CATALOG_VERSION: u16 = 2;
const MAX_CATALOG_FILE_LEN: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct DashStore {
    inner: Arc<DashStoreInner>,
}

struct DashStoreInner {
    root: PathBuf,
    retention_bytes: u64,
    retention_age: Duration,
    streams: Mutex<HashMap<Uuid, StreamCatalog>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCatalog {
    version: u16,
    stream_id: Uuid,
    #[serde(default)]
    last_sequence: Option<u64>,
    objects: Vec<StoredDashObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDashObject {
    pub header: DashObjectHeader,
    pub received_at_ms: i64,
    relative_path: PathBuf,
}

#[derive(Debug, Default)]
struct StreamCatalog {
    objects: BTreeMap<u64, StoredDashObject>,
    bytes: u64,
    last_sequence: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DashSummary {
    pub bytes: u64,
    pub last_sequence: Option<u64>,
    pub last_timestamp: Option<u64>,
}

impl DashStore {
    pub fn open(root: PathBuf, retention_bytes: u64, retention_age: Duration) -> Result<Self> {
        std::fs::create_dir_all(root.join("streams"))
            .with_context(|| format!("creating DASH store {}", root.display()))?;
        let store = Self {
            inner: Arc::new(DashStoreInner {
                root,
                retention_bytes,
                retention_age,
                streams: Mutex::new(HashMap::new()),
            }),
        };
        store.load_catalogs()?;
        Ok(store)
    }

    pub fn store(&self, object: DashObject) -> Result<StoredDashObject> {
        object.validate().context("validating DASH object")?;
        let stream_id = object.header.stream_id;
        let mut streams = self.streams()?;
        let catalog = streams.entry(stream_id).or_default();

        if let Some(existing) = catalog.objects.get(&object.header.sequence) {
            if existing.header == object.header {
                return Ok(existing.clone());
            }
            anyhow::bail!(
                "DASH sequence {} was already stored with different metadata",
                object.header.sequence
            );
        }
        let expected_sequence = match catalog.last_sequence {
            Some(sequence) => sequence
                .checked_add(1)
                .context("DASH sequence space exhausted")?,
            None => 1,
        };
        if object.header.sequence != expected_sequence {
            anyhow::bail!(
                "DASH sequence {} is out of order; expected {expected_sequence}",
                object.header.sequence
            );
        }
        validate_media_progression(catalog, &object.header)?;

        let object_dir = self.stream_dir(stream_id).join("objects");
        std::fs::create_dir_all(&object_dir)
            .with_context(|| format!("creating object directory {}", object_dir.display()))?;
        let relative_path = object_relative_path(object.header.sequence);
        let final_path = self.stream_dir(stream_id).join(&relative_path);
        let temp_path = object_dir.join(format!(
            ".{:020}-{}.tmp",
            object.header.sequence,
            Uuid::new_v4()
        ));
        write_durable_file(&temp_path, &object.payload)?;
        if let Err(error) = std::fs::hard_link(&temp_path, &final_path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error).with_context(|| {
                format!(
                    "publishing DASH object {} as {} without replacing an existing file",
                    temp_path.display(),
                    final_path.display()
                )
            });
        }
        std::fs::remove_file(&temp_path)
            .with_context(|| format!("removing temporary object {}", temp_path.display()))?;
        sync_directory(&object_dir)?;

        let stored = StoredDashObject {
            header: object.header,
            received_at_ms: glacialcast_protocol::now_ms(),
            relative_path,
        };
        catalog.bytes = catalog
            .bytes
            .saturating_add(u64::from(stored.header.payload_len));
        catalog
            .objects
            .insert(stored.header.sequence, stored.clone());
        catalog.last_sequence = Some(stored.header.sequence);

        let evicted = self.enforce_retention(catalog, stored.received_at_ms);
        self.persist_catalog(stream_id, catalog)?;
        for path in evicted {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(?err, path = %path.display(), "failed to remove evicted DASH object")
                }
            }
        }
        Ok(stored)
    }

    pub fn list(&self, stream_id: Uuid) -> Result<Vec<StoredDashObject>> {
        Ok(self
            .streams()?
            .get(&stream_id)
            .map(|catalog| catalog.objects.values().cloned().collect())
            .unwrap_or_default())
    }

    pub fn get(&self, stream_id: Uuid, sequence: u64) -> Result<Option<DashObject>> {
        let stored = self
            .streams()?
            .get(&stream_id)
            .and_then(|catalog| catalog.objects.get(&sequence).cloned());
        let Some(stored) = stored else {
            return Ok(None);
        };
        let payload = self.read_stored_payload(stream_id, &stored)?;
        let object = DashObject {
            header: stored.header,
            payload,
        };
        object.validate().context("validating stored DASH object")?;
        Ok(Some(object))
    }

    pub fn initialization(&self, stream_id: Uuid, epoch_id: Uuid) -> Result<Option<Vec<u8>>> {
        self.latest_payload(stream_id, epoch_id, DashObjectKind::Initialization)
    }

    pub fn media_segment(
        &self,
        stream_id: Uuid,
        epoch_id: Uuid,
        segment_number: u64,
    ) -> Result<Option<Vec<u8>>> {
        let sequences = self
            .streams()?
            .get(&stream_id)
            .map(|catalog| {
                let mut chunks = catalog
                    .objects
                    .values()
                    .filter(|object| {
                        object.header.epoch_id == epoch_id
                            && object.header.kind == DashObjectKind::Media
                            && object.header.segment_number == segment_number
                    })
                    .map(|object| (object.header.chunk_index, object.header.sequence))
                    .collect::<Vec<_>>();
                chunks.sort_unstable();
                chunks
            })
            .unwrap_or_default();
        if sequences.is_empty() {
            return Ok(None);
        }
        let mut segment = Vec::new();
        for pair in sequences.windows(2) {
            if pair[0]
                .0
                .checked_add(1)
                .is_none_or(|expected| pair[1].0 != expected)
            {
                anyhow::bail!("DASH media segment has duplicate or missing chunks");
            }
        }
        for (_, sequence) in sequences {
            let object = self
                .get(stream_id, sequence)?
                .ok_or_else(|| anyhow::anyhow!("DASH catalog object disappeared"))?;
            segment.extend_from_slice(&object.payload);
        }
        Ok(Some(segment))
    }

    pub fn manifest(&self, stream_id: Uuid, dynamic: bool) -> Result<Option<String>> {
        let objects = self.list(stream_id)?;
        let descriptor_object = objects
            .iter()
            .rev()
            .find(|object| object.header.kind == DashObjectKind::Epoch);
        let Some(descriptor_object) = descriptor_object else {
            return Ok(None);
        };
        let descriptor_payload = self
            .get(stream_id, descriptor_object.header.sequence)?
            .ok_or_else(|| anyhow::anyhow!("DASH epoch descriptor disappeared"))?
            .payload;
        let descriptor = EpochDescriptor::from_json(&descriptor_payload)
            .context("parsing DASH epoch descriptor")?;

        let mut segments = BTreeMap::<u64, SegmentTimelineEntry>::new();
        for object in objects.iter().filter(|object| {
            object.header.kind == DashObjectKind::Media
                && object.header.epoch_id == descriptor.epoch_id
        }) {
            let entry =
                segments
                    .entry(object.header.segment_number)
                    .or_insert(SegmentTimelineEntry {
                        number: object.header.segment_number,
                        start: object.header.timestamp,
                        duration: 0,
                    });
            entry.start = entry.start.min(object.header.timestamp);
            entry.duration = entry.duration.saturating_add(object.header.duration);
        }
        let segments = segments.into_values().collect::<Vec<_>>();
        Ok(Some(build_mpd(&MpdConfig {
            stream_id,
            epoch_id: descriptor.epoch_id,
            key_id: descriptor.key_id,
            width: descriptor.width,
            height: descriptor.height,
            codec: &descriptor.codec,
            availability_start_time: &descriptor.availability_start_time,
            time_shift_buffer_depth_seconds: self.inner.retention_age.as_secs(),
            segments: &segments,
            dynamic,
        })))
    }

    pub fn last_sequence(&self, stream_id: Uuid) -> Result<Option<u64>> {
        Ok(self
            .streams()?
            .get(&stream_id)
            .and_then(|catalog| catalog.last_sequence))
    }

    pub fn summaries(&self) -> Result<HashMap<Uuid, DashSummary>> {
        Ok(self
            .streams()?
            .iter()
            .map(|(stream_id, catalog)| {
                (
                    *stream_id,
                    DashSummary {
                        bytes: catalog.bytes,
                        last_sequence: catalog.last_sequence,
                        last_timestamp: catalog
                            .objects
                            .values()
                            .filter(|object| object.header.kind == DashObjectKind::Media)
                            .map(|object| object.header.timestamp)
                            .max(),
                    },
                )
            })
            .collect())
    }

    pub fn delete_stream(&self, stream_id: Uuid) -> Result<bool> {
        let removed = self.streams()?.remove(&stream_id).is_some();
        let stream_dir = self.stream_dir(stream_id);
        if stream_dir.exists() {
            std::fs::remove_dir_all(&stream_dir)
                .with_context(|| format!("removing DASH stream {}", stream_dir.display()))?;
            return Ok(true);
        }
        Ok(removed)
    }

    fn latest_payload(
        &self,
        stream_id: Uuid,
        epoch_id: Uuid,
        kind: DashObjectKind,
    ) -> Result<Option<Vec<u8>>> {
        let sequence = self.streams()?.get(&stream_id).and_then(|catalog| {
            catalog
                .objects
                .values()
                .rev()
                .find(|object| object.header.epoch_id == epoch_id && object.header.kind == kind)
                .map(|object| object.header.sequence)
        });
        match sequence {
            Some(sequence) => Ok(self.get(stream_id, sequence)?.map(|object| object.payload)),
            None => Ok(None),
        }
    }

    fn enforce_retention(&self, catalog: &mut StreamCatalog, now_ms: i64) -> Vec<PathBuf> {
        let cutoff_ms = now_ms.saturating_sub(
            i64::try_from(self.inner.retention_age.as_millis()).unwrap_or(i64::MAX),
        );
        let expired = retention_groups(catalog)
            .into_iter()
            .filter(|(_, received_at)| *received_at < cutoff_ms)
            .map(|(group, _)| group)
            .collect::<Vec<_>>();
        let mut removed = Vec::new();
        for group in expired {
            removed.extend(self.remove_group(catalog, group));
        }

        while catalog.bytes > self.inner.retention_bytes {
            let Some((oldest, _)) = oldest_retention_group(catalog) else {
                break;
            };
            removed.extend(self.remove_group(catalog, oldest));
        }
        removed.extend(self.remove_orphaned_epoch_metadata(catalog));
        removed
    }

    fn remove_group(&self, catalog: &mut StreamCatalog, group: (Uuid, u64)) -> Vec<PathBuf> {
        let sequences = catalog
            .objects
            .iter()
            .filter(|(_, object)| {
                object.header.epoch_id == group.0
                    && object.header.segment_number == group.1
                    && matches!(
                        object.header.kind,
                        DashObjectKind::Media | DashObjectKind::Cursor
                    )
            })
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>();
        self.remove_sequences(catalog, sequences)
    }

    fn remove_orphaned_epoch_metadata(&self, catalog: &mut StreamCatalog) -> Vec<PathBuf> {
        let epochs_with_timeline = catalog
            .objects
            .values()
            .filter(|object| {
                matches!(
                    object.header.kind,
                    DashObjectKind::Media | DashObjectKind::Cursor
                )
            })
            .map(|object| object.header.epoch_id)
            .collect::<BTreeSet<_>>();
        let newest_epoch = catalog
            .objects
            .values()
            .rev()
            .find(|object| object.header.kind == DashObjectKind::Epoch)
            .map(|object| object.header.epoch_id);
        let sequences = catalog
            .objects
            .iter()
            .filter(|(_, object)| {
                !epochs_with_timeline.contains(&object.header.epoch_id)
                    && Some(object.header.epoch_id) != newest_epoch
            })
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>();
        self.remove_sequences(catalog, sequences)
    }

    fn remove_sequences(&self, catalog: &mut StreamCatalog, sequences: Vec<u64>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for sequence in sequences {
            if let Some(object) = catalog.objects.remove(&sequence) {
                catalog.bytes = catalog
                    .bytes
                    .saturating_sub(u64::from(object.header.payload_len));
                paths.push(
                    self.stream_dir(object.header.stream_id)
                        .join(object.relative_path),
                );
            }
        }
        paths
    }

    fn load_catalogs(&self) -> Result<()> {
        let streams_dir = self.inner.root.join("streams");
        let mut loaded = HashMap::new();
        for entry in std::fs::read_dir(&streams_dir)
            .with_context(|| format!("reading DASH streams {}", streams_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Ok(stream_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            let catalog_path = entry.path().join("catalog.json");
            if !catalog_path.exists() {
                continue;
            }
            let catalog_metadata = std::fs::symlink_metadata(&catalog_path)
                .with_context(|| format!("reading metadata for {}", catalog_path.display()))?;
            if !catalog_metadata.file_type().is_file()
                || catalog_metadata.len() > MAX_CATALOG_FILE_LEN
            {
                anyhow::bail!(
                    "DASH catalog is not a bounded regular file: {}",
                    catalog_path.display()
                );
            }
            let bytes = std::fs::read(&catalog_path)
                .with_context(|| format!("reading {}", catalog_path.display()))?;
            let persisted: PersistedCatalog = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", catalog_path.display()))?;
            if !matches!(persisted.version, 1 | CATALOG_VERSION) || persisted.stream_id != stream_id
            {
                anyhow::bail!(
                    "unsupported or mismatched DASH catalog {}",
                    catalog_path.display()
                );
            }
            let mut catalog = StreamCatalog {
                last_sequence: persisted.last_sequence,
                ..StreamCatalog::default()
            };
            let mut persisted_objects = persisted.objects;
            persisted_objects.sort_by_key(|stored| stored.header.sequence);
            for stored in persisted_objects {
                if stored.header.stream_id != stream_id
                    || stored.relative_path != object_relative_path(stored.header.sequence)
                {
                    anyhow::bail!(
                        "DASH catalog {} contains an invalid object location",
                        catalog_path.display()
                    );
                }
                validate_media_progression(&catalog, &stored.header)?;
                let payload = self.read_stored_payload(stream_id, &stored)?;
                DashObject {
                    header: stored.header.clone(),
                    payload,
                }
                .validate()
                .with_context(|| {
                    format!(
                        "validating catalog object {}",
                        stored.relative_path.display()
                    )
                })?;
                catalog.bytes = catalog
                    .bytes
                    .saturating_add(u64::from(stored.header.payload_len));
                if catalog
                    .objects
                    .insert(stored.header.sequence, stored)
                    .is_some()
                {
                    anyhow::bail!(
                        "DASH catalog {} contains duplicate sequences",
                        catalog_path.display()
                    );
                }
            }
            let retained_last_sequence = catalog.objects.last_key_value().map(|(seq, _)| *seq);
            if catalog
                .last_sequence
                .is_some_and(|last| retained_last_sequence.is_some_and(|retained| last < retained))
            {
                anyhow::bail!(
                    "DASH catalog {} has a sequence high-water mark below a retained object",
                    catalog_path.display()
                );
            }
            catalog.last_sequence = catalog.last_sequence.or(retained_last_sequence);
            let removed = self.enforce_retention(&mut catalog, glacialcast_protocol::now_ms());
            if !removed.is_empty() {
                self.persist_catalog(stream_id, &catalog)?;
                for path in removed {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => tracing::warn!(
                            ?err,
                            path = %path.display(),
                            "failed to remove expired DASH object while loading catalog"
                        ),
                    }
                }
            }
            loaded.insert(stream_id, catalog);
        }
        *self.streams()? = loaded;
        Ok(())
    }

    fn persist_catalog(&self, stream_id: Uuid, catalog: &StreamCatalog) -> Result<()> {
        let stream_dir = self.stream_dir(stream_id);
        std::fs::create_dir_all(&stream_dir)?;
        let persisted = PersistedCatalog {
            version: CATALOG_VERSION,
            stream_id,
            last_sequence: catalog.last_sequence,
            objects: catalog.objects.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        if bytes.len() as u64 > MAX_CATALOG_FILE_LEN {
            anyhow::bail!("DASH catalog exceeds its size limit");
        }
        let temp_path = stream_dir.join(format!(".catalog-{}.tmp", Uuid::new_v4()));
        write_durable_file(&temp_path, &bytes)?;
        let catalog_path = stream_dir.join("catalog.json");
        std::fs::rename(&temp_path, &catalog_path).with_context(|| {
            format!(
                "publishing DASH catalog {} as {}",
                temp_path.display(),
                catalog_path.display()
            )
        })?;
        sync_directory(&stream_dir)
    }

    fn stream_dir(&self, stream_id: Uuid) -> PathBuf {
        self.inner.root.join("streams").join(stream_id.to_string())
    }

    fn read_stored_payload(&self, stream_id: Uuid, stored: &StoredDashObject) -> Result<Vec<u8>> {
        if stored.header.stream_id != stream_id
            || stored.relative_path != object_relative_path(stored.header.sequence)
        {
            anyhow::bail!("DASH object has an invalid stored location");
        }
        if stored.header.payload_len as usize > stored.header.kind.max_payload_len() {
            anyhow::bail!("stored DASH object exceeds its kind-specific size limit");
        }
        let path = self.stream_dir(stream_id).join(&stored.relative_path);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.len() != u64::from(stored.header.payload_len)
        {
            anyhow::bail!("stored DASH object has an invalid file type or length");
        }
        std::fs::read(&path).with_context(|| {
            format!(
                "reading DASH object {} for stream {stream_id}",
                stored.header.sequence
            )
        })
    }

    fn streams(&self) -> Result<MutexGuard<'_, HashMap<Uuid, StreamCatalog>>> {
        self.inner
            .streams
            .lock()
            .map_err(|_| anyhow::anyhow!("DASH store mutex poisoned"))
    }
}

fn retention_groups(catalog: &StreamCatalog) -> BTreeMap<(Uuid, u64), i64> {
    let mut groups = BTreeMap::new();
    for object in catalog.objects.values().filter(|object| {
        matches!(
            object.header.kind,
            DashObjectKind::Media | DashObjectKind::Cursor
        )
    }) {
        groups
            .entry((object.header.epoch_id, object.header.segment_number))
            .and_modify(|received: &mut i64| *received = (*received).max(object.received_at_ms))
            .or_insert(object.received_at_ms);
    }
    groups
}

fn oldest_retention_group(catalog: &StreamCatalog) -> Option<((Uuid, u64), i64)> {
    retention_groups(catalog)
        .into_iter()
        .min_by_key(|(_, received_at_ms)| *received_at_ms)
}

fn object_relative_path(sequence: u64) -> PathBuf {
    PathBuf::from("objects").join(format!("{sequence:020}.bin"))
}

fn validate_media_progression(catalog: &StreamCatalog, candidate: &DashObjectHeader) -> Result<()> {
    if candidate.kind != DashObjectKind::Media {
        return Ok(());
    }
    let previous = catalog.objects.values().rev().find(|stored| {
        stored.header.kind == DashObjectKind::Media && stored.header.epoch_id == candidate.epoch_id
    });
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous = &previous.header;
    if candidate.segment_number < previous.segment_number
        || candidate.segment_number > previous.segment_number.saturating_add(1)
        || candidate.timestamp < previous.timestamp.saturating_add(previous.duration)
        || (candidate.segment_number == previous.segment_number
            && previous
                .chunk_index
                .checked_add(1)
                .is_none_or(|expected| candidate.chunk_index != expected))
    {
        anyhow::bail!("DASH media chunks are out of order or overlap");
    }
    Ok(())
}

fn write_durable_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_dash::{DASH_FORMAT_VERSION, EpochKeys, MEDIA_TIMESCALE};
    use glacialcast_protocol::{DashObjectKind, NewDashObject};

    fn test_store(retention_bytes: u64) -> (PathBuf, DashStore) {
        let root = std::env::temp_dir().join(format!("glacialcast-dash-{}", Uuid::new_v4()));
        let store =
            DashStore::open(root.clone(), retention_bytes, Duration::from_secs(1800)).unwrap();
        (root, store)
    }

    struct ObjectSpec {
        kind: DashObjectKind,
        sequence: u64,
        segment_number: u64,
        chunk_index: u16,
        random_access: bool,
        payload: Vec<u8>,
    }

    fn object(keys: &EpochKeys, stream_id: Uuid, epoch_id: Uuid, spec: ObjectSpec) -> DashObject {
        let duration = if matches!(spec.kind, DashObjectKind::Media | DashObjectKind::Cursor) {
            MEDIA_TIMESCALE as u64
        } else {
            0
        };
        DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: spec.kind,
                sequence: spec.sequence,
                segment_number: spec.segment_number,
                chunk_index: spec.chunk_index,
                timestamp: spec
                    .segment_number
                    .saturating_sub(1)
                    .saturating_mul(4 * u64::from(MEDIA_TIMESCALE))
                    + u64::from(spec.chunk_index) * u64::from(MEDIA_TIMESCALE),
                duration,
                random_access: spec.random_access,
                mime: match spec.kind {
                    DashObjectKind::Epoch => "application/vnd.glacialcast.epoch+json",
                    DashObjectKind::Initialization => "video/mp4",
                    DashObjectKind::Media => "video/iso.segment",
                    _ => "application/octet-stream",
                },
                payload: spec.payload,
            },
            keys,
        )
        .unwrap()
    }

    #[test]
    fn durable_store_reopens_and_builds_segment() {
        let (root, store) = test_store(1024 * 1024);
        let stream_id = Uuid::from_u128(1);
        let epoch_id = Uuid::from_u128(2);
        let keys = EpochKeys::derive(&[7u8; 32], stream_id, epoch_id).unwrap();
        let descriptor = EpochDescriptor {
            format_version: DASH_FORMAT_VERSION,
            stream_id,
            epoch_id,
            key_id: keys.key_id,
            width: 1280,
            height: 720,
            codec: "avc1.42c01f".to_string(),
            timescale: MEDIA_TIMESCALE,
            segment_frames: 4,
            availability_start_time: "2026-01-01T00:00:00Z".to_string(),
        };
        store
            .store(object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Epoch,
                    sequence: 1,
                    segment_number: 0,
                    chunk_index: 0,
                    random_access: false,
                    payload: descriptor.to_json().unwrap(),
                },
            ))
            .unwrap();
        store
            .store(object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Initialization,
                    sequence: 2,
                    segment_number: 0,
                    chunk_index: 0,
                    random_access: false,
                    payload: b"init".to_vec(),
                },
            ))
            .unwrap();
        for chunk_index in 0..4 {
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Media,
                        sequence: 3 + u64::from(chunk_index),
                        segment_number: 1,
                        chunk_index,
                        random_access: chunk_index == 0,
                        payload: vec![chunk_index as u8; 4],
                    },
                ))
                .unwrap();
        }
        drop(store);

        let reopened =
            DashStore::open(root.clone(), 1024 * 1024, Duration::from_secs(1800)).unwrap();
        assert_eq!(reopened.last_sequence(stream_id).unwrap(), Some(6));
        assert_eq!(
            reopened
                .media_segment(stream_id, epoch_id, 1)
                .unwrap()
                .unwrap(),
            [vec![0; 4], vec![1; 4], vec![2; 4], vec![3; 4]].concat()
        );
        let manifest = reopened.manifest(stream_id, true).unwrap().unwrap();
        assert!(manifest.contains("media=\"epochs/"));
        assert!(manifest.contains("<S t=\"0\" d=\"360000\"/>"));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_retention_evicts_complete_oldest_segment() {
        let (root, store) = test_store(30);
        let stream_id = Uuid::from_u128(11);
        let epoch_id = Uuid::from_u128(12);
        let keys = EpochKeys::derive(&[8u8; 32], stream_id, epoch_id).unwrap();
        for (sequence, segment, chunk_index) in [(1, 1, 0), (2, 1, 1), (3, 2, 0), (4, 2, 1)] {
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Media,
                        sequence,
                        segment_number: segment,
                        chunk_index,
                        random_access: sequence % 2 == 1,
                        payload: vec![sequence as u8; 10],
                    },
                ))
                .unwrap();
        }

        let objects = store.list(stream_id).unwrap();
        assert!(
            objects
                .iter()
                .all(|object| object.header.segment_number == 2)
        );
        assert!(
            store
                .media_segment(stream_id, epoch_id, 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .media_segment(stream_id, epoch_id, 2)
                .unwrap()
                .unwrap()
                .len(),
            20
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sequence_high_water_mark_survives_complete_eviction_and_restart() {
        let (root, store) = test_store(0);
        let stream_id = Uuid::from_u128(31);
        let epoch_id = Uuid::from_u128(32);
        let keys = EpochKeys::derive(&[3u8; 32], stream_id, epoch_id).unwrap();
        let media = |sequence| {
            object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence,
                    segment_number: sequence,
                    chunk_index: 0,
                    random_access: true,
                    payload: vec![sequence as u8],
                },
            )
        };

        store.store(media(1)).unwrap();
        assert!(store.list(stream_id).unwrap().is_empty());
        assert_eq!(store.last_sequence(stream_id).unwrap(), Some(1));
        drop(store);

        let reopened = DashStore::open(root.clone(), 0, Duration::from_secs(1800)).unwrap();
        assert_eq!(reopened.last_sequence(stream_id).unwrap(), Some(1));
        assert!(reopened.store(media(1)).is_err());
        reopened.store(media(2)).unwrap();
        assert_eq!(reopened.last_sequence(stream_id).unwrap(), Some(2));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_retention_uses_arrival_order_instead_of_epoch_uuid_order() {
        let mut catalog = StreamCatalog::default();
        let stream_id = Uuid::from_u128(9);
        let newest_epoch = Uuid::from_u128(1);
        let oldest_epoch = Uuid::from_u128(u128::MAX);
        for (sequence, epoch_id, received_at_ms) in [(1, newest_epoch, 20), (2, oldest_epoch, 10)] {
            let keys = EpochKeys::derive(&[7u8; 32], stream_id, epoch_id).unwrap();
            let object = object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence,
                    segment_number: 1,
                    chunk_index: 0,
                    random_access: true,
                    payload: vec![sequence as u8],
                },
            );
            catalog.objects.insert(
                sequence,
                StoredDashObject {
                    header: object.header,
                    received_at_ms,
                    relative_path: PathBuf::from(format!("{sequence}.bin")),
                },
            );
        }

        assert_eq!(
            oldest_retention_group(&catalog),
            Some(((oldest_epoch, 1), 10))
        );
    }

    #[test]
    fn catalog_reload_enforces_retention_age() {
        let root = std::env::temp_dir().join(format!("glacialcast-dash-{}", Uuid::new_v4()));
        let store = DashStore::open(root.clone(), 1024 * 1024, Duration::from_secs(1)).unwrap();
        let stream_id = Uuid::from_u128(21);
        let epoch_id = Uuid::from_u128(22);
        let keys = EpochKeys::derive(&[7u8; 32], stream_id, epoch_id).unwrap();
        store
            .store(object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence: 1,
                    segment_number: 1,
                    chunk_index: 0,
                    random_access: true,
                    payload: vec![1, 2, 3],
                },
            ))
            .unwrap();
        {
            let mut streams = store.streams().unwrap();
            let catalog = streams.get_mut(&stream_id).unwrap();
            catalog.objects.get_mut(&1).unwrap().received_at_ms = 0;
            store.persist_catalog(stream_id, catalog).unwrap();
        }
        drop(store);

        let reopened = DashStore::open(root.clone(), 1024 * 1024, Duration::from_secs(1)).unwrap();
        assert!(reopened.list(stream_id).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cursor_only_groups_obey_byte_retention() {
        let (root, store) = test_store(15);
        let stream_id = Uuid::from_u128(41);
        let epoch_id = Uuid::from_u128(42);
        let keys = EpochKeys::derive(&[1; 32], stream_id, epoch_id).unwrap();
        for (sequence, segment_number) in [(1, 1), (2, 2)] {
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Cursor,
                        sequence,
                        segment_number,
                        chunk_index: 0,
                        random_access: true,
                        payload: vec![sequence as u8; 10],
                    },
                ))
                .unwrap();
        }

        let retained = store.list(stream_id).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].header.sequence, 2);
        assert_eq!(store.summaries().unwrap()[&stream_id].bytes, 10);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn media_retention_removes_cursor_objects_in_the_same_segment() {
        let (root, store) = test_store(25);
        let stream_id = Uuid::from_u128(43);
        let epoch_id = Uuid::from_u128(44);
        let keys = EpochKeys::derive(&[2; 32], stream_id, epoch_id).unwrap();
        for (kind, sequence, segment_number) in [
            (DashObjectKind::Media, 1, 1),
            (DashObjectKind::Cursor, 2, 1),
            (DashObjectKind::Media, 3, 2),
        ] {
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind,
                        sequence,
                        segment_number,
                        chunk_index: 0,
                        random_access: true,
                        payload: vec![sequence as u8; 10],
                    },
                ))
                .unwrap();
        }

        let retained = store.list(stream_id).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].header.sequence, 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn media_chunks_must_progress_without_duplicates_gaps_or_overlap() {
        let (root, store) = test_store(1024);
        let stream_id = Uuid::from_u128(45);
        let epoch_id = Uuid::from_u128(46);
        let keys = EpochKeys::derive(&[3; 32], stream_id, epoch_id).unwrap();
        let media = |sequence, segment_number, chunk_index| {
            object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence,
                    segment_number,
                    chunk_index,
                    random_access: chunk_index == 0,
                    payload: vec![sequence as u8],
                },
            )
        };

        store.store(media(1, 1, 0)).unwrap();
        assert!(store.store(media(2, 1, 0)).is_err());
        assert!(store.store(media(2, 1, 2)).is_err());
        store.store(media(2, 1, 1)).unwrap();
        assert!(store.store(media(3, 3, 0)).is_err());

        let mut overlapping = media(3, 2, 0);
        overlapping.header.timestamp = MEDIA_TIMESCALE as u64;
        assert!(store.store(overlapping).is_err());
        store.store(media(3, 2, 0)).unwrap();

        assert_eq!(store.list(stream_id).unwrap().len(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storing_is_idempotent_but_never_skips_or_redefines_a_sequence() {
        let (root, store) = test_store(1024);
        let stream_id = Uuid::from_u128(47);
        let epoch_id = Uuid::from_u128(48);
        let keys = EpochKeys::derive(&[4; 32], stream_id, epoch_id).unwrap();
        let media = |sequence, payload| {
            object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence,
                    segment_number: sequence,
                    chunk_index: 0,
                    random_access: true,
                    payload,
                },
            )
        };
        let first = media(1, vec![1]);
        assert_eq!(
            store.store(first.clone()).unwrap().header,
            store.store(first).unwrap().header
        );
        assert!(store.store(media(3, vec![3])).is_err());
        assert!(store.store(media(1, vec![9])).is_err());
        assert_eq!(store.list(stream_id).unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn object_publication_does_not_replace_an_untracked_file() {
        let (root, store) = test_store(1024);
        let stream_id = Uuid::from_u128(49);
        let epoch_id = Uuid::from_u128(50);
        let keys = EpochKeys::derive(&[5; 32], stream_id, epoch_id).unwrap();
        let object_dir = store.stream_dir(stream_id).join("objects");
        std::fs::create_dir_all(&object_dir).unwrap();
        let final_path = store.stream_dir(stream_id).join(object_relative_path(1));
        std::fs::write(&final_path, b"orphan").unwrap();

        let result = store.store(object(
            &keys,
            stream_id,
            epoch_id,
            ObjectSpec {
                kind: DashObjectKind::Media,
                sequence: 1,
                segment_number: 1,
                chunk_index: 0,
                random_access: true,
                payload: vec![1],
            },
        ));
        assert!(result.is_err());
        assert_eq!(std::fs::read(final_path).unwrap(), b"orphan");
        assert_eq!(store.last_sequence(stream_id).unwrap(), None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_reload_rejects_path_traversal_and_stream_mismatch() {
        for mutation in ["path", "stream"] {
            let (root, store) = test_store(1024);
            let stream_id = Uuid::new_v4();
            let epoch_id = Uuid::new_v4();
            let keys = EpochKeys::derive(&[6; 32], stream_id, epoch_id).unwrap();
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Media,
                        sequence: 1,
                        segment_number: 1,
                        chunk_index: 0,
                        random_access: true,
                        payload: vec![1],
                    },
                ))
                .unwrap();
            let catalog_path = store.stream_dir(stream_id).join("catalog.json");
            let mut persisted: PersistedCatalog =
                serde_json::from_slice(&std::fs::read(&catalog_path).unwrap()).unwrap();
            if mutation == "path" {
                persisted.objects[0].relative_path = PathBuf::from("../../outside");
            } else {
                persisted.objects[0].header.stream_id = Uuid::new_v4();
            }
            std::fs::write(&catalog_path, serde_json::to_vec(&persisted).unwrap()).unwrap();
            drop(store);

            assert!(
                DashStore::open(root.clone(), 1024, Duration::from_secs(1800)).is_err(),
                "accepted catalog mutation {mutation}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn catalog_reload_rejects_symlinked_and_corrupt_payloads() {
        use std::os::unix::fs::symlink;

        for mutation in ["symlink", "corrupt"] {
            let (root, store) = test_store(1024);
            let stream_id = Uuid::new_v4();
            let epoch_id = Uuid::new_v4();
            let keys = EpochKeys::derive(&[7; 32], stream_id, epoch_id).unwrap();
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Media,
                        sequence: 1,
                        segment_number: 1,
                        chunk_index: 0,
                        random_access: true,
                        payload: vec![1],
                    },
                ))
                .unwrap();
            let payload_path = store.stream_dir(stream_id).join(object_relative_path(1));
            if mutation == "symlink" {
                let target = root.join("target");
                std::fs::write(&target, [1]).unwrap();
                std::fs::remove_file(&payload_path).unwrap();
                symlink(target, &payload_path).unwrap();
            } else {
                std::fs::write(&payload_path, [2]).unwrap();
            }
            drop(store);

            assert!(
                DashStore::open(root.clone(), 1024, Duration::from_secs(1800)).is_err(),
                "accepted payload mutation {mutation}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn catalog_reload_rejects_oversized_catalog_before_parsing() {
        let root = std::env::temp_dir().join(format!("glacialcast-dash-{}", Uuid::new_v4()));
        let stream_id = Uuid::new_v4();
        let stream_dir = root.join("streams").join(stream_id.to_string());
        std::fs::create_dir_all(&stream_dir).unwrap();
        let file = File::create(stream_dir.join("catalog.json")).unwrap();
        file.set_len(MAX_CATALOG_FILE_LEN + 1).unwrap();
        drop(file);
        assert!(DashStore::open(root.clone(), 1024, Duration::from_secs(1800)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn summaries_and_delete_track_exact_stream_state() {
        let (root, store) = test_store(1024);
        let stream_id = Uuid::from_u128(51);
        let epoch_id = Uuid::from_u128(52);
        let keys = EpochKeys::derive(&[8; 32], stream_id, epoch_id).unwrap();
        store
            .store(object(
                &keys,
                stream_id,
                epoch_id,
                ObjectSpec {
                    kind: DashObjectKind::Media,
                    sequence: 1,
                    segment_number: 1,
                    chunk_index: 0,
                    random_access: true,
                    payload: vec![1, 2, 3],
                },
            ))
            .unwrap();
        assert_eq!(
            store.summaries().unwrap()[&stream_id],
            DashSummary {
                bytes: 3,
                last_sequence: Some(1),
                last_timestamp: Some(0),
            }
        );
        assert!(store.delete_stream(stream_id).unwrap());
        assert!(!store.delete_stream(stream_id).unwrap());
        assert!(store.list(stream_id).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readers_observe_complete_objects_during_concurrent_ingest() {
        let (root, store) = test_store(1024 * 1024);
        let stream_id = Uuid::from_u128(53);
        let epoch_id = Uuid::from_u128(54);
        let keys = EpochKeys::derive(&[9; 32], stream_id, epoch_id).unwrap();
        let reader_store = store.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..100 {
                for stored in reader_store.list(stream_id).unwrap() {
                    let object = reader_store
                        .get(stream_id, stored.header.sequence)
                        .unwrap()
                        .unwrap();
                    assert_eq!(object.header, stored.header);
                }
            }
        });
        for sequence in 1..=10 {
            store
                .store(object(
                    &keys,
                    stream_id,
                    epoch_id,
                    ObjectSpec {
                        kind: DashObjectKind::Media,
                        sequence,
                        segment_number: sequence,
                        chunk_index: 0,
                        random_access: true,
                        payload: vec![sequence as u8; 32],
                    },
                ))
                .unwrap();
        }
        reader.join().unwrap();
        assert_eq!(store.list(stream_id).unwrap().len(), 10);
        std::fs::remove_dir_all(root).unwrap();
    }
}
