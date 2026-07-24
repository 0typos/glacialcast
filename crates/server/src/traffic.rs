//! Bounded ingest traffic accounting for operational diagnostics.
//!
//! The relay records opaque application payload bytes only. Noise, TCP, HTTP,
//! and TLS framing are deliberately excluded, so these counters are stable
//! enough for regression gates while packet captures remain the authority for
//! deployment-specific wire overhead.

use glacialcast_protocol::DashObjectKind;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const WINDOW_SECONDS: u64 = 60;

/// Object and byte counts for one DASH object kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ObjectTraffic {
    /// Number of accepted objects.
    pub objects: u64,
    /// Number of accepted opaque payload bytes.
    pub bytes: u64,
}

impl ObjectTraffic {
    fn record(&mut self, bytes: u64) {
        self.objects = self.objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn merge(&mut self, other: Self) {
        self.objects = self.objects.saturating_add(other.objects);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// Traffic counters partitioned by the stable GlacialCast object kinds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KindTraffic {
    /// Epoch descriptor traffic.
    pub epoch: ObjectTraffic,
    /// MP4 initialization traffic.
    pub initialization: ObjectTraffic,
    /// Encrypted media fragment traffic.
    pub media: ObjectTraffic,
    /// Encrypted cursor batch traffic.
    pub cursor: ObjectTraffic,
    /// Authenticated presentation-index traffic.
    pub index: ObjectTraffic,
    /// Clean epoch-boundary traffic.
    pub end: ObjectTraffic,
}

impl KindTraffic {
    fn record(&mut self, kind: DashObjectKind, bytes: u64) {
        self.kind_mut(kind).record(bytes);
    }

    fn merge(&mut self, other: Self) {
        self.epoch.merge(other.epoch);
        self.initialization.merge(other.initialization);
        self.media.merge(other.media);
        self.cursor.merge(other.cursor);
        self.index.merge(other.index);
        self.end.merge(other.end);
    }

    fn kind_mut(&mut self, kind: DashObjectKind) -> &mut ObjectTraffic {
        match kind {
            DashObjectKind::Epoch => &mut self.epoch,
            DashObjectKind::Initialization => &mut self.initialization,
            DashObjectKind::Media => &mut self.media,
            DashObjectKind::Cursor => &mut self.cursor,
            DashObjectKind::Index => &mut self.index,
            DashObjectKind::End => &mut self.end,
        }
    }

    #[cfg(test)]
    fn aggregate(self) -> ObjectTraffic {
        let mut aggregate = ObjectTraffic::default();
        aggregate.merge(self.epoch);
        aggregate.merge(self.initialization);
        aggregate.merge(self.media);
        aggregate.merge(self.cursor);
        aggregate.merge(self.index);
        aggregate.merge(self.end);
        aggregate
    }
}

/// Rolling and lifetime ingest traffic for one stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamTrafficSnapshot {
    /// Relay-assigned stream identifier.
    pub stream_id: Uuid,
    /// Millisecond Unix time of the most recently accepted object.
    pub last_object_at_ms: i64,
    /// Lifetime application traffic accepted during this relay process.
    pub lifetime: KindTraffic,
    /// Application traffic accepted during the trailing window.
    pub last_minute: KindTraffic,
}

/// Operational ingest traffic snapshot returned to administrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficSnapshot {
    /// Width of the rolling traffic window.
    pub window_seconds: u64,
    /// Lifetime application traffic accepted during this relay process.
    pub lifetime: KindTraffic,
    /// Application traffic accepted during the trailing window.
    pub last_minute: KindTraffic,
    /// Per-stream traffic, sorted by stream identifier for stable output.
    pub streams: Vec<StreamTrafficSnapshot>,
}

#[derive(Debug, Clone, Copy, Default)]
struct StreamTraffic {
    last_object_at_ms: i64,
    counters: KindTraffic,
}

#[derive(Debug)]
struct TrafficBucket {
    second: u64,
    counters: KindTraffic,
    streams: HashMap<Uuid, KindTraffic>,
}

#[derive(Debug, Default)]
struct TrafficState {
    lifetime: KindTraffic,
    streams: HashMap<Uuid, StreamTraffic>,
    buckets: VecDeque<TrafficBucket>,
}

/// Thread-safe, bounded rolling traffic tracker.
#[derive(Clone, Debug, Default)]
pub struct TrafficMetrics {
    state: Arc<Mutex<TrafficState>>,
}

impl TrafficMetrics {
    /// Records one newly accepted object at the current wall-clock time.
    pub fn record(&self, stream_id: Uuid, kind: DashObjectKind, bytes: u64) {
        let now_ms = glacialcast_protocol::now_ms();
        let second = u64::try_from(now_ms.max(0)).unwrap_or_default() / 1000;
        self.record_at(stream_id, kind, bytes, now_ms, second);
    }

    /// Removes lifetime per-stream accounting after an administrator deletes a
    /// stream. Global process totals remain monotonic.
    pub fn forget_stream(&self, stream_id: Uuid) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.streams.remove(&stream_id);
        for bucket in &mut state.buckets {
            bucket.streams.remove(&stream_id);
        }
    }

    /// Returns lifetime and trailing-minute application traffic.
    pub fn snapshot(&self) -> TrafficSnapshot {
        let now_ms = glacialcast_protocol::now_ms();
        let second = u64::try_from(now_ms.max(0)).unwrap_or_default() / 1000;
        self.snapshot_at(second)
    }

    fn record_at(
        &self,
        stream_id: Uuid,
        kind: DashObjectKind,
        bytes: u64,
        now_ms: i64,
        second: u64,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune(&mut state.buckets, second);
        state.lifetime.record(kind, bytes);
        let stream = state.streams.entry(stream_id).or_default();
        stream.last_object_at_ms = stream.last_object_at_ms.max(now_ms);
        stream.counters.record(kind, bytes);
        if state
            .buckets
            .back()
            .is_none_or(|bucket| bucket.second != second)
        {
            state.buckets.push_back(TrafficBucket {
                second,
                counters: KindTraffic::default(),
                streams: HashMap::new(),
            });
        }
        let bucket = state.buckets.back_mut().expect("traffic bucket inserted");
        bucket.counters.record(kind, bytes);
        bucket
            .streams
            .entry(stream_id)
            .or_default()
            .record(kind, bytes);
    }

    fn snapshot_at(&self, second: u64) -> TrafficSnapshot {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune(&mut state.buckets, second);
        let mut last_minute = KindTraffic::default();
        let mut recent_streams = HashMap::<Uuid, KindTraffic>::new();
        for bucket in &state.buckets {
            last_minute.merge(bucket.counters);
            for (stream_id, counters) in &bucket.streams {
                recent_streams
                    .entry(*stream_id)
                    .or_default()
                    .merge(*counters);
            }
        }
        let mut streams = state
            .streams
            .iter()
            .map(|(stream_id, traffic)| StreamTrafficSnapshot {
                stream_id: *stream_id,
                last_object_at_ms: traffic.last_object_at_ms,
                lifetime: traffic.counters,
                last_minute: recent_streams.get(stream_id).copied().unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        streams.sort_by_key(|stream| stream.stream_id);
        TrafficSnapshot {
            window_seconds: WINDOW_SECONDS,
            lifetime: state.lifetime,
            last_minute,
            streams,
        }
    }
}

fn prune(buckets: &mut VecDeque<TrafficBucket>, now_second: u64) {
    let oldest = now_second.saturating_sub(WINDOW_SECONDS.saturating_sub(1));
    while buckets.front().is_some_and(|bucket| bucket.second < oldest) {
        buckets.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_is_partitioned_by_kind_and_stream() {
        let metrics = TrafficMetrics::default();
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        metrics.record_at(first, DashObjectKind::Media, 120, 10_000, 10);
        metrics.record_at(first, DashObjectKind::Cursor, 20, 10_500, 10);
        metrics.record_at(second, DashObjectKind::Initialization, 80, 11_000, 11);

        let snapshot = metrics.snapshot_at(11);
        assert_eq!(snapshot.lifetime.aggregate().objects, 3);
        assert_eq!(snapshot.lifetime.aggregate().bytes, 220);
        assert_eq!(snapshot.last_minute.media.bytes, 120);
        assert_eq!(snapshot.last_minute.cursor.bytes, 20);
        assert_eq!(snapshot.streams.len(), 2);
        assert_eq!(snapshot.streams[0].stream_id, first);
        assert_eq!(snapshot.streams[0].last_object_at_ms, 10_500);
        assert_eq!(snapshot.streams[0].last_minute.aggregate().bytes, 140);
    }

    #[test]
    fn rolling_window_expires_old_buckets_without_changing_lifetime_totals() {
        let metrics = TrafficMetrics::default();
        let stream = Uuid::from_u128(1);
        metrics.record_at(stream, DashObjectKind::Media, 100, 1_000, 1);
        metrics.record_at(stream, DashObjectKind::Media, 40, 60_000, 60);
        assert_eq!(metrics.snapshot_at(60).last_minute.media.bytes, 140);
        let snapshot = metrics.snapshot_at(61);
        assert_eq!(snapshot.last_minute.media.bytes, 40);
        assert_eq!(snapshot.lifetime.media.bytes, 140);
    }

    #[test]
    fn deleting_stream_forgets_stream_rows_but_not_global_totals() {
        let metrics = TrafficMetrics::default();
        let stream = Uuid::from_u128(1);
        metrics.record_at(stream, DashObjectKind::Epoch, 25, 1_000, 1);
        metrics.forget_stream(stream);
        let snapshot = metrics.snapshot_at(1);
        assert!(snapshot.streams.is_empty());
        assert_eq!(snapshot.lifetime.epoch.bytes, 25);
        assert_eq!(snapshot.last_minute.epoch.bytes, 25);
    }
}
