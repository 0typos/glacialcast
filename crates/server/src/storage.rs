use anyhow::{Context, Result};
use glacialcast_protocol::{
    CaptureSource, CursorBitmap, CursorMessage, FrameManifest, FrameMessage, PublicStream,
    StreamMediaKind, VideoChunkManifest, VideoChunkMessage,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
};
use tracing::warn;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    conn: Mutex<Connection>,
    data_dir: PathBuf,
    retention_bytes_per_stream: u64,
    live: Mutex<HashMap<Uuid, LiveStream>>,
    archive_tx: mpsc::Sender<ArchiveCommand>,
}

#[derive(Default)]
struct LiveStream {
    frames: VecDeque<LiveFrame>,
    video_chunks: VecDeque<LiveVideoChunk>,
    cursors: VecDeque<CursorMessage>,
    bytes: u64,
}

#[derive(Clone)]
struct LiveFrame {
    frame: StoredFrame,
    bytes: Arc<Vec<u8>>,
}

#[derive(Clone)]
struct LiveVideoChunk {
    chunk: StoredVideoChunk,
    bytes: Arc<Vec<u8>>,
}

struct LiveSummary {
    bytes: u64,
    last_seq: Option<u64>,
    last_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StoredFramePayload {
    pub frame: StoredFrame,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StoredVideoChunkPayload {
    pub chunk: StoredVideoChunk,
    pub bytes: Vec<u8>,
}

enum ArchiveCommand {
    Frame {
        frame: StoredFrame,
        bytes: Arc<Vec<u8>>,
    },
    VideoChunk {
        chunk: StoredVideoChunk,
        bytes: Arc<Vec<u8>>,
    },
    Cursor(CursorMessage),
    ClearStream {
        stream_id: Uuid,
    },
    DeleteStream {
        stream_id: Uuid,
    },
}

#[derive(Debug, Clone)]
pub struct StoredVideoChunk {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub pts_ms: i64,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub source_width: u32,
    pub source_height: u32,
    pub codec: glacialcast_protocol::VideoCodec,
    pub packetization: glacialcast_protocol::VideoPacketization,
    pub keyframe: bool,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub size_bytes: u64,
    pub path: PathBuf,
}

impl StoredVideoChunk {
    pub fn from_message(chunk: &VideoChunkMessage) -> Self {
        Self {
            stream_id: chunk.stream_id,
            seq: chunk.seq,
            captured_at_ms: chunk.captured_at_ms,
            pts_ms: chunk.pts_ms,
            duration_ms: chunk.duration_ms,
            width: chunk.width,
            height: chunk.height,
            source_width: chunk.source_width,
            source_height: chunk.source_height,
            codec: chunk.codec,
            packetization: chunk.packetization,
            keyframe: chunk.keyframe,
            mime: chunk.mime.clone(),
            key_id: chunk.key_id.clone(),
            nonce: chunk.nonce,
            content_hash: chunk.content_hash,
            size_bytes: chunk.payload.len() as u64,
            path: PathBuf::new(),
        }
    }

    fn manifest(&self) -> VideoChunkManifest {
        VideoChunkManifest {
            stream_id: self.stream_id,
            seq: self.seq,
            captured_at_ms: self.captured_at_ms,
            pts_ms: self.pts_ms,
            duration_ms: self.duration_ms,
            width: self.width,
            height: self.height,
            source_width: self.source_width,
            source_height: self.source_height,
            codec: self.codec,
            packetization: self.packetization,
            keyframe: self.keyframe,
            mime: self.mime.clone(),
            key_id: self.key_id.clone(),
            nonce: self.nonce,
            content_hash: self.content_hash,
            size_bytes: self.size_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredFrame {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub width: u32,
    pub height: u32,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub size_bytes: u64,
    pub path: PathBuf,
}

impl StoredFrame {
    pub fn from_message(frame: &FrameMessage) -> Self {
        Self {
            stream_id: frame.stream_id,
            seq: frame.seq,
            captured_at_ms: frame.captured_at_ms,
            width: frame.width,
            height: frame.height,
            mime: frame.mime.clone(),
            key_id: frame.key_id.clone(),
            nonce: frame.nonce,
            content_hash: frame.content_hash,
            size_bytes: frame.ciphertext.len() as u64,
            path: PathBuf::new(),
        }
    }

    fn manifest(&self) -> FrameManifest {
        FrameManifest {
            stream_id: self.stream_id,
            seq: self.seq,
            captured_at_ms: self.captured_at_ms,
            width: self.width,
            height: self.height,
            mime: self.mime.clone(),
            key_id: self.key_id.clone(),
            nonce: self.nonce,
            content_hash: self.content_hash,
            size_bytes: self.size_bytes,
        }
    }
}

impl Store {
    pub fn open(data_dir: PathBuf, retention_bytes_per_stream: u64) -> Result<Self> {
        std::fs::create_dir_all(data_dir.join("streams"))?;
        let db_path = data_dir.join("glacialcast.sqlite3");
        let conn = Connection::open(db_path)?;
        let archive_tx = start_archive_worker(data_dir.clone());
        let store = Self {
            inner: Arc::new(StoreInner {
                conn: Mutex::new(conn),
                data_dir,
                retention_bytes_per_stream,
                live: Mutex::new(HashMap::new()),
                archive_tx,
            }),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS streams (
                stream_id TEXT PRIMARY KEY,
                client_id TEXT UNIQUE,
                display_name TEXT NOT NULL,
                token_hash TEXT NOT NULL DEFAULT '',
                backend TEXT NOT NULL DEFAULT '',
                source_description TEXT NOT NULL DEFAULT '',
                source_width INTEGER NOT NULL DEFAULT 0,
                source_height INTEGER NOT NULL DEFAULT 0,
                media_kind TEXT NOT NULL DEFAULT 'image',
                frame_encrypted INTEGER NOT NULL DEFAULT 0,
                created_at_ms INTEGER NOT NULL,
                last_seen_at_ms INTEGER,
                active INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS frames (
                stream_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                captured_at_ms INTEGER NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                mime TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                content_hash INTEGER NOT NULL DEFAULT 0,
                size_bytes INTEGER NOT NULL,
                path TEXT NOT NULL,
                PRIMARY KEY (stream_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_frames_stream_time ON frames(stream_id, captured_at_ms);
            CREATE TABLE IF NOT EXISTS video_chunks (
                stream_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                captured_at_ms INTEGER NOT NULL,
                pts_ms INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                source_width INTEGER NOT NULL,
                source_height INTEGER NOT NULL,
                codec TEXT NOT NULL,
                packetization TEXT NOT NULL,
                keyframe INTEGER NOT NULL,
                mime TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                content_hash INTEGER NOT NULL DEFAULT 0,
                size_bytes INTEGER NOT NULL,
                path TEXT NOT NULL,
                PRIMARY KEY (stream_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_video_chunks_stream_time ON video_chunks(stream_id, captured_at_ms);
            CREATE TABLE IF NOT EXISTS cursors (
                stream_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                captured_at_ms INTEGER NOT NULL,
                x REAL NOT NULL,
                y REAL NOT NULL,
                source_width INTEGER NOT NULL,
                source_height INTEGER NOT NULL,
                cursor_bitmap_width INTEGER,
                cursor_bitmap_height INTEGER,
                cursor_hotspot_x INTEGER,
                cursor_hotspot_y INTEGER,
                cursor_png_b64 TEXT,
                PRIMARY KEY (stream_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_cursors_stream_time ON cursors(stream_id, captured_at_ms);
            "#,
        )?;
        drop(conn);
        self.add_column_if_missing("streams", "client_id", "TEXT")?;
        self.add_column_if_missing("streams", "active", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_column_if_missing("streams", "media_kind", "TEXT NOT NULL DEFAULT 'image'")?;
        self.add_column_if_missing("streams", "frame_encrypted", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_column_if_missing("frames", "content_hash", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_column_if_missing("cursors", "cursor_bitmap_width", "INTEGER")?;
        self.add_column_if_missing("cursors", "cursor_bitmap_height", "INTEGER")?;
        self.add_column_if_missing("cursors", "cursor_hotspot_x", "INTEGER")?;
        self.add_column_if_missing("cursors", "cursor_hotspot_y", "INTEGER")?;
        self.add_column_if_missing("cursors", "cursor_png_b64", "TEXT")?;
        self.migrate_frames_schema()?;
        self.backfill_stream_encryption_mode()?;
        self.conn()?.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_streams_client_id ON streams(client_id)",
            [],
        )?;
        self.conn()?.execute(
            "CREATE INDEX IF NOT EXISTS idx_frames_stream_time ON frames(stream_id, captured_at_ms)",
            [],
        )?;
        self.conn()?.execute(
            "CREATE INDEX IF NOT EXISTS idx_video_chunks_stream_time ON video_chunks(stream_id, captured_at_ms)",
            [],
        )?;
        self.conn()?.execute("UPDATE streams SET active = 0", [])?;
        Ok(())
    }

    fn backfill_stream_encryption_mode(&self) -> Result<()> {
        self.conn()?.execute(
            r#"
            UPDATE streams
            SET frame_encrypted = 1
            WHERE EXISTS (
                SELECT 1 FROM frames
                WHERE frames.stream_id = streams.stream_id
                  AND frames.key_id != ''
            )
            "#,
            [],
        )?;
        Ok(())
    }

    fn add_column_if_missing(&self, table: &str, column: &str, definition: &str) -> Result<()> {
        if self.column_exists(table, column)? {
            return Ok(());
        }
        let conn = self.conn()?;
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
        Ok(())
    }

    fn column_exists(&self, table: &str, column: &str) -> Result<bool> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for row in rows {
            if row? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn migrate_frames_schema(&self) -> Result<()> {
        if !self.column_exists("frames", "plaintext_sha256")? {
            return Ok(());
        }

        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS frames_migrated;
            CREATE TABLE frames_migrated (
                stream_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                captured_at_ms INTEGER NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                mime TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                content_hash INTEGER NOT NULL DEFAULT 0,
                size_bytes INTEGER NOT NULL,
                path TEXT NOT NULL,
                PRIMARY KEY (stream_id, seq)
            );
            INSERT OR REPLACE INTO frames_migrated
                (stream_id, seq, captured_at_ms, width, height, mime, key_id,
                 nonce, content_hash, size_bytes, path)
            SELECT stream_id, seq, captured_at_ms, width, height, mime, key_id,
                   nonce, content_hash, size_bytes, path
            FROM frames;
            DROP TABLE frames;
            ALTER TABLE frames_migrated RENAME TO frames;
            "#,
        )?;
        Ok(())
    }

    pub fn ensure_stream_for_client(
        &self,
        client_id: &str,
        display_name: &str,
        source: &CaptureSource,
        media_kind: StreamMediaKind,
        frame_encrypted: bool,
    ) -> Result<Uuid> {
        if let Some(stream_id) = self.stream_id_for_client(client_id)? {
            if self.stream_source_changed(stream_id, source, media_kind, frame_encrypted)? {
                self.clear_stream_data(stream_id)?;
            }
            self.activate_stream(
                stream_id,
                client_id,
                display_name,
                source,
                media_kind,
                frame_encrypted,
            )?;
            return Ok(stream_id);
        }

        let stream_id = Uuid::new_v4();
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO streams
                (stream_id, client_id, display_name, token_hash, backend,
                 source_description, source_width, source_height, media_kind, frame_encrypted, created_at_ms,
                 last_seen_at_ms, active)
            VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 1)
            "#,
            params![
                stream_id.to_string(),
                client_id,
                display_name,
                source.backend,
                source.description,
                source.width,
                source.height,
                media_kind_to_db(media_kind),
                frame_encrypted as i64,
                glacialcast_protocol::now_ms()
            ],
        )?;
        std::fs::create_dir_all(self.stream_dir(stream_id))?;
        Ok(stream_id)
    }

    fn stream_id_for_client(&self, client_id: &str) -> Result<Option<Uuid>> {
        let conn = self.conn()?;
        let stream_id = conn
            .query_row(
                "SELECT stream_id FROM streams WHERE client_id = ?1",
                params![client_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        stream_id
            .map(|stream_id| Uuid::parse_str(&stream_id).context("invalid stream_id in database"))
            .transpose()
    }

    fn stream_source_changed(
        &self,
        stream_id: Uuid,
        source: &CaptureSource,
        media_kind: StreamMediaKind,
        frame_encrypted: bool,
    ) -> Result<bool> {
        let conn = self.conn()?;
        let current = conn
            .query_row(
                r#"
                SELECT backend, source_description, source_width, source_height, media_kind, frame_encrypted
                FROM streams WHERE stream_id = ?1
                "#,
                params![stream_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? as u32,
                        row.get::<_, i64>(3)? as u32,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)? != 0,
                    ))
                },
            )
            .optional()?;

        Ok(current.is_some_and(
            |(backend, description, width, height, current_media_kind, current_frame_encrypted)| {
                backend != source.backend
                    || description != source.description
                    || width != source.width
                    || height != source.height
                    || stream_media_kind_from_db(&current_media_kind) != media_kind
                    || current_frame_encrypted != frame_encrypted
            },
        ))
    }

    fn clear_stream_data(&self, stream_id: Uuid) -> Result<()> {
        self.clear_live_stream(stream_id)?;
        let paths = {
            let conn = self.conn()?;
            let mut stmt = conn.prepare("SELECT path FROM frames WHERE stream_id = ?1")?;
            let rows = stmt.query_map(params![stream_id.to_string()], |row| {
                row.get::<_, String>(0).map(PathBuf::from)
            })?;
            let mut paths = rows.collect::<std::result::Result<Vec<_>, _>>()?;
            let mut stmt = conn.prepare("SELECT path FROM video_chunks WHERE stream_id = ?1")?;
            let rows = stmt.query_map(params![stream_id.to_string()], |row| {
                row.get::<_, String>(0).map(PathBuf::from)
            })?;
            paths.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
            conn.execute(
                "DELETE FROM frames WHERE stream_id = ?1",
                params![stream_id.to_string()],
            )?;
            conn.execute(
                "DELETE FROM video_chunks WHERE stream_id = ?1",
                params![stream_id.to_string()],
            )?;
            conn.execute(
                "DELETE FROM cursors WHERE stream_id = ?1",
                params![stream_id.to_string()],
            )?;
            paths
        };

        for path in paths {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir_all(self.stream_dir(stream_id));
        std::fs::create_dir_all(self.stream_dir(stream_id))?;
        self.queue_archive(ArchiveCommand::ClearStream { stream_id })?;
        Ok(())
    }

    pub fn delete_stream(&self, stream_id: Uuid) -> Result<bool> {
        self.clear_live_stream(stream_id)?;
        self.clear_stream_data(stream_id)?;
        let deleted = self.conn()?.execute(
            "DELETE FROM streams WHERE stream_id = ?1",
            params![stream_id.to_string()],
        )?;
        self.queue_archive(ArchiveCommand::DeleteStream { stream_id })?;
        Ok(deleted > 0)
    }

    pub fn activate_stream(
        &self,
        stream_id: Uuid,
        client_id: &str,
        display_name: &str,
        source: &CaptureSource,
        media_kind: StreamMediaKind,
        frame_encrypted: bool,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            UPDATE streams
            SET client_id = ?2,
                display_name = ?3,
                backend = ?4,
                source_description = ?5,
                source_width = ?6,
                source_height = ?7,
                media_kind = ?8,
                frame_encrypted = ?9,
                last_seen_at_ms = ?10,
                active = 1
            WHERE stream_id = ?1 OR client_id = ?2
            "#,
            params![
                stream_id.to_string(),
                client_id,
                display_name,
                source.backend,
                source.description,
                source.width,
                source.height,
                media_kind_to_db(media_kind),
                frame_encrypted as i64,
                glacialcast_protocol::now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn mark_stream_inactive(&self, stream_id: Uuid) -> Result<()> {
        self.conn()?.execute(
            "UPDATE streams SET active = 0, last_seen_at_ms = ?2 WHERE stream_id = ?1",
            params![stream_id.to_string(), glacialcast_protocol::now_ms()],
        )?;
        Ok(())
    }

    pub fn stream_exists(&self, stream_id: Uuid) -> Result<bool> {
        let found: Option<i64> = self
            .conn()?
            .query_row(
                "SELECT 1 FROM streams WHERE stream_id = ?1",
                params![stream_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn list_streams(&self) -> Result<Vec<PublicStream>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT s.stream_id, s.display_name, s.backend, s.source_description,
                   s.source_width, s.source_height, s.media_kind, s.frame_encrypted, s.active,
                   s.last_seen_at_ms,
                   (SELECT COALESCE(SUM(size_bytes), 0) FROM frames WHERE stream_id = s.stream_id) +
                   (SELECT COALESCE(SUM(size_bytes), 0) FROM video_chunks WHERE stream_id = s.stream_id),
                   NULLIF(MAX(
                       COALESCE((SELECT MAX(seq) FROM frames WHERE stream_id = s.stream_id), 0),
                       COALESCE((SELECT MAX(seq) FROM video_chunks WHERE stream_id = s.stream_id), 0)
                   ), 0),
                   NULLIF(MAX(
                       COALESCE((SELECT MAX(captured_at_ms) FROM frames WHERE stream_id = s.stream_id), 0),
                       COALESCE((SELECT MAX(captured_at_ms) FROM video_chunks WHERE stream_id = s.stream_id), 0)
                   ), 0)
            FROM streams s
            ORDER BY s.active DESC, COALESCE(s.last_seen_at_ms, s.created_at_ms) DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let stream_id: String = row.get(0)?;
            Ok(PublicStream {
                stream_id: Uuid::parse_str(&stream_id).unwrap_or_else(|_| Uuid::nil()),
                display_name: row.get(1)?,
                source: CaptureSource {
                    backend: row.get(2)?,
                    description: row.get(3)?,
                    width: row.get::<_, i64>(4)? as u32,
                    height: row.get::<_, i64>(5)? as u32,
                },
                media_kind: stream_media_kind_from_db(&row.get::<_, String>(6)?),
                frame_encrypted: row.get::<_, i64>(7)? != 0,
                active: row.get::<_, i64>(8)? != 0,
                last_seen_at_ms: row.get(9)?,
                retained_bytes: row.get::<_, i64>(10)? as u64,
                last_frame_seq: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
                last_frame_at_ms: row.get(12)?,
            })
        })?;
        let mut streams = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let live = self.live_summaries()?;
        for stream in &mut streams {
            if let Some(summary) = live.get(&stream.stream_id) {
                stream.retained_bytes = stream.retained_bytes.max(summary.bytes);
                stream.last_frame_seq = max_option(stream.last_frame_seq, summary.last_seq);
                stream.last_frame_at_ms = max_option(stream.last_frame_at_ms, summary.last_at_ms);
            }
        }
        Ok(streams)
    }

    pub fn store_frame(&self, mut frame: StoredFrame, ciphertext: &[u8]) -> Result<()> {
        let path = self.frame_path(frame.stream_id, frame.seq);
        frame.path = path.clone();
        let bytes = Arc::new(ciphertext.to_vec());
        self.push_live_frame(frame.clone(), bytes.clone())?;
        self.queue_archive(ArchiveCommand::Frame { frame, bytes })?;
        Ok(())
    }

    pub fn store_video_chunk(&self, mut chunk: StoredVideoChunk, payload: &[u8]) -> Result<()> {
        let path = self.video_chunk_path(chunk.stream_id, chunk.seq);
        chunk.path = path;
        let bytes = Arc::new(payload.to_vec());
        self.push_live_video_chunk(chunk.clone(), bytes.clone())?;
        self.queue_archive(ArchiveCommand::VideoChunk { chunk, bytes })?;
        Ok(())
    }

    fn get_archived_frame(&self, stream_id: Uuid, seq: u64) -> Result<Option<StoredFrame>> {
        let conn = self.conn()?;
        conn.query_row(
            r#"
            SELECT captured_at_ms, width, height, mime, key_id, nonce, content_hash,
                   size_bytes, path
            FROM frames WHERE stream_id = ?1 AND seq = ?2
            "#,
            params![stream_id.to_string(), seq as i64],
            |row| {
                let nonce: Vec<u8> = row.get(5)?;
                Ok(StoredFrame {
                    stream_id,
                    seq,
                    captured_at_ms: row.get(0)?,
                    width: row.get::<_, i64>(1)? as u32,
                    height: row.get::<_, i64>(2)? as u32,
                    mime: row.get(3)?,
                    key_id: row.get(4)?,
                    nonce: vec_to_array(nonce)?,
                    content_hash: row.get::<_, i64>(6)? as u32,
                    size_bytes: row.get::<_, i64>(7)? as u64,
                    path: PathBuf::from(row.get::<_, String>(8)?),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_frame_payload(
        &self,
        stream_id: Uuid,
        seq: u64,
    ) -> Result<Option<StoredFramePayload>> {
        if let Some(frame) = self.live_frame(stream_id, seq)? {
            return Ok(Some(StoredFramePayload {
                frame: frame.frame,
                bytes: frame.bytes.as_ref().clone(),
            }));
        }
        let Some(frame) = self.get_archived_frame(stream_id, seq)? else {
            return Ok(None);
        };
        let bytes = std::fs::read(&frame.path)
            .with_context(|| format!("reading archived frame {}", frame.path.display()))?;
        Ok(Some(StoredFramePayload { frame, bytes }))
    }

    fn get_archived_video_chunk(
        &self,
        stream_id: Uuid,
        seq: u64,
    ) -> Result<Option<StoredVideoChunk>> {
        let conn = self.conn()?;
        conn.query_row(
            r#"
            SELECT captured_at_ms, pts_ms, duration_ms, width, height, source_width,
                   source_height, codec, packetization, keyframe, mime, key_id, nonce,
                   content_hash, size_bytes, path
            FROM video_chunks WHERE stream_id = ?1 AND seq = ?2
            "#,
            params![stream_id.to_string(), seq as i64],
            |row| {
                let nonce: Vec<u8> = row.get(12)?;
                let codec: String = row.get(7)?;
                let packetization: String = row.get(8)?;
                Ok(StoredVideoChunk {
                    stream_id,
                    seq,
                    captured_at_ms: row.get(0)?,
                    pts_ms: row.get(1)?,
                    duration_ms: row.get::<_, i64>(2)? as u64,
                    width: row.get::<_, i64>(3)? as u32,
                    height: row.get::<_, i64>(4)? as u32,
                    source_width: row.get::<_, i64>(5)? as u32,
                    source_height: row.get::<_, i64>(6)? as u32,
                    codec: video_codec_from_db(&codec),
                    packetization: video_packetization_from_db(&packetization),
                    keyframe: row.get::<_, i64>(9)? != 0,
                    mime: row.get(10)?,
                    key_id: row.get(11)?,
                    nonce: vec_to_array(nonce)?,
                    content_hash: row.get::<_, i64>(13)? as u32,
                    size_bytes: row.get::<_, i64>(14)? as u64,
                    path: PathBuf::from(row.get::<_, String>(15)?),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_video_chunk_payload(
        &self,
        stream_id: Uuid,
        seq: u64,
    ) -> Result<Option<StoredVideoChunkPayload>> {
        if let Some(chunk) = self.live_video_chunk(stream_id, seq)? {
            return Ok(Some(StoredVideoChunkPayload {
                chunk: chunk.chunk,
                bytes: chunk.bytes.as_ref().clone(),
            }));
        }
        let Some(chunk) = self.get_archived_video_chunk(stream_id, seq)? else {
            return Ok(None);
        };
        let bytes = std::fs::read(&chunk.path)
            .with_context(|| format!("reading archived video chunk {}", chunk.path.display()))?;
        Ok(Some(StoredVideoChunkPayload { chunk, bytes }))
    }

    pub fn latest_video_keyframe_payload(
        &self,
        stream_id: Uuid,
    ) -> Result<Option<StoredVideoChunkPayload>> {
        if let Some(chunk) = self.live_latest_video_keyframe(stream_id)? {
            return Ok(Some(StoredVideoChunkPayload {
                chunk: chunk.chunk,
                bytes: chunk.bytes.as_ref().clone(),
            }));
        }
        let conn = self.conn()?;
        let seq = conn
            .query_row(
                r#"
                SELECT seq FROM video_chunks
                WHERE stream_id = ?1 AND keyframe = 1
                ORDER BY seq DESC LIMIT 1
                "#,
                params![stream_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(seq) = seq else {
            return Ok(None);
        };
        drop(conn);
        self.get_video_chunk_payload(stream_id, seq as u64)
    }

    pub fn list_frames(&self, stream_id: Uuid) -> Result<Vec<FrameManifest>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT seq, captured_at_ms, width, height, mime, key_id, nonce,
                   content_hash, size_bytes
            FROM frames WHERE stream_id = ?1 ORDER BY seq ASC
            "#,
        )?;
        let rows = stmt.query_map(params![stream_id.to_string()], |row| {
            let nonce: Vec<u8> = row.get(6)?;
            Ok(FrameManifest {
                stream_id,
                seq: row.get::<_, i64>(0)? as u64,
                captured_at_ms: row.get(1)?,
                width: row.get::<_, i64>(2)? as u32,
                height: row.get::<_, i64>(3)? as u32,
                mime: row.get(4)?,
                key_id: row.get(5)?,
                nonce: vec_to_array(nonce)?,
                content_hash: row.get::<_, i64>(7)? as u32,
                size_bytes: row.get::<_, i64>(8)? as u64,
            })
        })?;
        let mut frames = rows
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|frame| (frame.seq, frame))
            .collect::<BTreeMap<_, _>>();
        for frame in self.live_frame_manifests(stream_id)? {
            frames.insert(frame.seq, frame);
        }
        Ok(frames.into_values().collect())
    }

    pub fn list_video_chunks(&self, stream_id: Uuid) -> Result<Vec<VideoChunkManifest>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT seq, captured_at_ms, pts_ms, duration_ms, width, height,
                   source_width, source_height, codec, packetization, keyframe, mime,
                   key_id, nonce, content_hash, size_bytes
            FROM video_chunks WHERE stream_id = ?1 ORDER BY seq ASC
            "#,
        )?;
        let rows = stmt.query_map(params![stream_id.to_string()], |row| {
            let nonce: Vec<u8> = row.get(13)?;
            let codec: String = row.get(8)?;
            let packetization: String = row.get(9)?;
            Ok(VideoChunkManifest {
                stream_id,
                seq: row.get::<_, i64>(0)? as u64,
                captured_at_ms: row.get(1)?,
                pts_ms: row.get(2)?,
                duration_ms: row.get::<_, i64>(3)? as u64,
                width: row.get::<_, i64>(4)? as u32,
                height: row.get::<_, i64>(5)? as u32,
                source_width: row.get::<_, i64>(6)? as u32,
                source_height: row.get::<_, i64>(7)? as u32,
                codec: video_codec_from_db(&codec),
                packetization: video_packetization_from_db(&packetization),
                keyframe: row.get::<_, i64>(10)? != 0,
                mime: row.get(11)?,
                key_id: row.get(12)?,
                nonce: vec_to_array(nonce)?,
                content_hash: row.get::<_, i64>(14)? as u32,
                size_bytes: row.get::<_, i64>(15)? as u64,
            })
        })?;
        let mut chunks = rows
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|chunk| (chunk.seq, chunk))
            .collect::<BTreeMap<_, _>>();
        for chunk in self.live_video_chunk_manifests(stream_id)? {
            chunks.insert(chunk.seq, chunk);
        }
        Ok(chunks.into_values().collect())
    }

    pub fn store_cursor(&self, cursor: &CursorMessage) -> Result<()> {
        self.push_live_cursor(cursor.clone())?;
        self.queue_archive(ArchiveCommand::Cursor(cursor.clone()))?;
        Ok(())
    }

    pub fn list_cursors(&self, stream_id: Uuid, limit: usize) -> Result<Vec<CursorMessage>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT seq, captured_at_ms, x, y, source_width, source_height,
                   cursor_bitmap_width, cursor_bitmap_height,
                   cursor_hotspot_x, cursor_hotspot_y, cursor_png_b64
            FROM (
                SELECT seq, captured_at_ms, x, y, source_width, source_height,
                       cursor_bitmap_width, cursor_bitmap_height,
                       cursor_hotspot_x, cursor_hotspot_y, cursor_png_b64
                FROM cursors WHERE stream_id = ?1 ORDER BY seq DESC LIMIT ?2
            ) ORDER BY seq ASC
            "#,
        )?;
        let rows = stmt.query_map(params![stream_id.to_string(), limit as i64], |row| {
            Ok(CursorMessage {
                stream_id,
                seq: row.get::<_, i64>(0)? as u64,
                captured_at_ms: row.get(1)?,
                x: row.get(2)?,
                y: row.get(3)?,
                source_width: row.get::<_, i64>(4)? as u32,
                source_height: row.get::<_, i64>(5)? as u32,
                bitmap: cursor_bitmap_from_db(
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ),
            })
        })?;
        let mut cursors = rows
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|cursor| (cursor.seq, cursor))
            .collect::<BTreeMap<_, _>>();
        for cursor in self.live_cursors(stream_id)? {
            cursors.insert(cursor.seq, cursor);
        }
        let mut out = cursors.into_values().collect::<Vec<_>>();
        if out.len() > limit {
            out.drain(0..out.len() - limit);
        }
        Ok(out)
    }

    pub fn last_frame_seq(&self, stream_id: Uuid) -> Result<Option<u64>> {
        let live_last = self.live_last_seq(stream_id)?;
        let conn = self.conn()?;
        let archived_frame = conn
            .query_row(
                "SELECT MAX(seq) FROM frames WHERE stream_id = ?1",
                params![stream_id.to_string()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map(|v| v.map(|seq| seq as u64))?;
        let archived_video = conn
            .query_row(
                "SELECT MAX(seq) FROM video_chunks WHERE stream_id = ?1",
                params![stream_id.to_string()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map(|v| v.map(|seq| seq as u64))?;
        Ok(max_option(
            max_option(archived_frame, archived_video),
            live_last,
        ))
    }

    fn push_live_frame(&self, frame: StoredFrame, bytes: Arc<Vec<u8>>) -> Result<()> {
        let stream_id = frame.stream_id;
        let mut live = self.live()?;
        let stream = live.entry(stream_id).or_default();
        if let Some(existing) = stream
            .frames
            .iter()
            .position(|live| live.frame.seq == frame.seq)
            && let Some(old) = stream.frames.remove(existing)
        {
            stream.bytes = stream.bytes.saturating_sub(old.frame.size_bytes);
        }
        stream.bytes = stream.bytes.saturating_add(frame.size_bytes);
        stream.frames.push_back(LiveFrame { frame, bytes });
        evict_live_payloads(stream, self.inner.retention_bytes_per_stream);
        Ok(())
    }

    fn push_live_video_chunk(&self, chunk: StoredVideoChunk, bytes: Arc<Vec<u8>>) -> Result<()> {
        let stream_id = chunk.stream_id;
        let mut live = self.live()?;
        let stream = live.entry(stream_id).or_default();
        if let Some(existing) = stream
            .video_chunks
            .iter()
            .position(|live| live.chunk.seq == chunk.seq)
            && let Some(old) = stream.video_chunks.remove(existing)
        {
            stream.bytes = stream.bytes.saturating_sub(old.chunk.size_bytes);
        }
        stream.bytes = stream.bytes.saturating_add(chunk.size_bytes);
        stream
            .video_chunks
            .push_back(LiveVideoChunk { chunk, bytes });
        evict_live_payloads(stream, self.inner.retention_bytes_per_stream);
        Ok(())
    }

    fn clear_live_stream(&self, stream_id: Uuid) -> Result<()> {
        self.live()?.remove(&stream_id);
        Ok(())
    }

    fn live_frame(&self, stream_id: Uuid, seq: u64) -> Result<Option<LiveFrame>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .and_then(|stream| stream.frames.iter().find(|frame| frame.frame.seq == seq))
            .cloned())
    }

    fn live_frame_manifests(&self, stream_id: Uuid) -> Result<Vec<FrameManifest>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .map(|stream| {
                stream
                    .frames
                    .iter()
                    .map(|frame| frame.frame.manifest())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn live_video_chunk(&self, stream_id: Uuid, seq: u64) -> Result<Option<LiveVideoChunk>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .and_then(|stream| {
                stream
                    .video_chunks
                    .iter()
                    .find(|chunk| chunk.chunk.seq == seq)
            })
            .cloned())
    }

    fn live_latest_video_keyframe(&self, stream_id: Uuid) -> Result<Option<LiveVideoChunk>> {
        Ok(self.live()?.get(&stream_id).and_then(|stream| {
            stream
                .video_chunks
                .iter()
                .rev()
                .find(|chunk| chunk.chunk.keyframe)
                .cloned()
        }))
    }

    fn live_video_chunk_manifests(&self, stream_id: Uuid) -> Result<Vec<VideoChunkManifest>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .map(|stream| {
                stream
                    .video_chunks
                    .iter()
                    .map(|chunk| chunk.chunk.manifest())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn live_last_seq(&self, stream_id: Uuid) -> Result<Option<u64>> {
        Ok(self.live()?.get(&stream_id).and_then(|stream| {
            max_option(
                stream.frames.back().map(|frame| frame.frame.seq),
                stream.video_chunks.back().map(|chunk| chunk.chunk.seq),
            )
        }))
    }

    fn push_live_cursor(&self, cursor: CursorMessage) -> Result<()> {
        const MAX_LIVE_CURSORS: usize = 5_000;

        let mut live = self.live()?;
        let stream = live.entry(cursor.stream_id).or_default();
        if let Some(existing) = stream
            .cursors
            .iter()
            .position(|live| live.seq == cursor.seq)
        {
            stream.cursors.remove(existing);
        }
        stream.cursors.push_back(cursor);
        while stream.cursors.len() > MAX_LIVE_CURSORS {
            stream.cursors.pop_front();
        }
        Ok(())
    }

    fn live_cursors(&self, stream_id: Uuid) -> Result<Vec<CursorMessage>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .map(|stream| stream.cursors.iter().cloned().collect())
            .unwrap_or_default())
    }

    fn live_summaries(&self) -> Result<HashMap<Uuid, LiveSummary>> {
        Ok(self
            .live()?
            .iter()
            .map(|(stream_id, stream)| {
                (
                    *stream_id,
                    LiveSummary {
                        bytes: stream.bytes,
                        last_seq: max_option(
                            stream.frames.back().map(|frame| frame.frame.seq),
                            stream.video_chunks.back().map(|chunk| chunk.chunk.seq),
                        ),
                        last_at_ms: max_option(
                            stream.frames.back().map(|frame| frame.frame.captured_at_ms),
                            stream
                                .video_chunks
                                .back()
                                .map(|chunk| chunk.chunk.captured_at_ms),
                        ),
                    },
                )
            })
            .collect())
    }

    fn queue_archive(&self, command: ArchiveCommand) -> Result<()> {
        self.inner
            .archive_tx
            .send(command)
            .map_err(|_| anyhow::anyhow!("archive worker stopped"))
    }

    fn live(&self) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, LiveStream>>> {
        self.inner
            .live
            .lock()
            .map_err(|_| anyhow::anyhow!("live storage mutex poisoned"))
    }

    #[cfg(test)]
    fn live_frame_seqs(&self, stream_id: Uuid) -> Result<Vec<u64>> {
        Ok(self
            .live()?
            .get(&stream_id)
            .map(|stream| stream.frames.iter().map(|frame| frame.frame.seq).collect())
            .unwrap_or_default())
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.inner
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("store mutex poisoned"))
    }

    fn stream_dir(&self, stream_id: Uuid) -> PathBuf {
        self.inner
            .data_dir
            .join("streams")
            .join(stream_id.to_string())
    }

    fn frame_path(&self, stream_id: Uuid, seq: u64) -> PathBuf {
        self.stream_dir(stream_id).join(format!("{seq:020}.bin"))
    }

    fn video_chunk_path(&self, stream_id: Uuid, seq: u64) -> PathBuf {
        self.stream_dir(stream_id).join(format!("{seq:020}.video"))
    }
}

fn start_archive_worker(data_dir: PathBuf) -> mpsc::Sender<ArchiveCommand> {
    let (tx, rx) = mpsc::channel::<ArchiveCommand>();
    std::thread::Builder::new()
        .name("glacialcast-archive".to_string())
        .spawn(move || archive_worker_loop(data_dir, rx))
        .expect("failed to spawn archive worker");
    tx
}

fn archive_worker_loop(data_dir: PathBuf, rx: mpsc::Receiver<ArchiveCommand>) {
    let db_path = data_dir.join("glacialcast.sqlite3");
    let conn = match Connection::open(&db_path) {
        Ok(conn) => conn,
        Err(err) => {
            warn!(?err, path = %db_path.display(), "archive worker could not open database");
            return;
        }
    };
    if let Err(err) = conn.execute_batch("PRAGMA journal_mode = WAL;") {
        warn!(?err, "archive worker could not enable WAL mode");
    }

    while let Ok(command) = rx.recv() {
        if let Err(err) = archive_command(&conn, &data_dir, command) {
            warn!(?err, "archive worker command failed");
        }
    }
}

fn archive_command(conn: &Connection, data_dir: &Path, command: ArchiveCommand) -> Result<()> {
    match command {
        ArchiveCommand::Frame { mut frame, bytes } => {
            let path = frame_path_for(data_dir, frame.stream_id, frame.seq);
            let parent = path.parent().context("frame path has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::write(&path, bytes.as_ref())?;
            frame.path = path;
            insert_frame_metadata(conn, &frame)?;
        }
        ArchiveCommand::VideoChunk { mut chunk, bytes } => {
            let path = video_chunk_path_for(data_dir, chunk.stream_id, chunk.seq);
            let parent = path.parent().context("video chunk path has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::write(&path, bytes.as_ref())?;
            chunk.path = path;
            insert_video_chunk_metadata(conn, &chunk)?;
        }
        ArchiveCommand::Cursor(cursor) => {
            insert_cursor_metadata(conn, &cursor)?;
        }
        ArchiveCommand::ClearStream { stream_id } => {
            archive_clear_stream(conn, data_dir, stream_id, false)?;
        }
        ArchiveCommand::DeleteStream { stream_id } => {
            archive_clear_stream(conn, data_dir, stream_id, true)?;
        }
    }
    Ok(())
}

fn insert_frame_metadata(conn: &Connection, frame: &StoredFrame) -> Result<()> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO frames
            (stream_id, seq, captured_at_ms, width, height, mime, key_id, nonce,
             content_hash, size_bytes, path)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            frame.stream_id.to_string(),
            frame.seq as i64,
            frame.captured_at_ms,
            frame.width as i64,
            frame.height as i64,
            frame.mime,
            frame.key_id,
            frame.nonce.to_vec(),
            frame.content_hash as i64,
            frame.size_bytes as i64,
            frame.path.to_string_lossy(),
        ],
    )?;
    Ok(())
}

fn insert_video_chunk_metadata(conn: &Connection, chunk: &StoredVideoChunk) -> Result<()> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO video_chunks
            (stream_id, seq, captured_at_ms, pts_ms, duration_ms, width, height,
             source_width, source_height, codec, packetization, keyframe, mime, key_id,
             nonce, content_hash, size_bytes, path)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        "#,
        params![
            chunk.stream_id.to_string(),
            chunk.seq as i64,
            chunk.captured_at_ms,
            chunk.pts_ms,
            chunk.duration_ms as i64,
            chunk.width as i64,
            chunk.height as i64,
            chunk.source_width as i64,
            chunk.source_height as i64,
            video_codec_to_db(chunk.codec),
            video_packetization_to_db(chunk.packetization),
            chunk.keyframe as i64,
            chunk.mime,
            chunk.key_id,
            chunk.nonce.to_vec(),
            chunk.content_hash as i64,
            chunk.size_bytes as i64,
            chunk.path.to_string_lossy(),
        ],
    )?;
    Ok(())
}

fn insert_cursor_metadata(conn: &Connection, cursor: &CursorMessage) -> Result<()> {
    let bitmap_width = cursor.bitmap.as_ref().map(|bitmap| bitmap.width as i64);
    let bitmap_height = cursor.bitmap.as_ref().map(|bitmap| bitmap.height as i64);
    let hotspot_x = cursor.bitmap.as_ref().map(|bitmap| bitmap.hotspot_x as i64);
    let hotspot_y = cursor.bitmap.as_ref().map(|bitmap| bitmap.hotspot_y as i64);
    let png_b64 = cursor.bitmap.as_ref().map(|bitmap| bitmap.png_b64.as_str());
    conn.execute(
        r#"
        INSERT OR REPLACE INTO cursors
            (stream_id, seq, captured_at_ms, x, y, source_width, source_height,
             cursor_bitmap_width, cursor_bitmap_height, cursor_hotspot_x,
             cursor_hotspot_y, cursor_png_b64)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            cursor.stream_id.to_string(),
            cursor.seq as i64,
            cursor.captured_at_ms,
            cursor.x,
            cursor.y,
            cursor.source_width as i64,
            cursor.source_height as i64,
            bitmap_width,
            bitmap_height,
            hotspot_x,
            hotspot_y,
            png_b64,
        ],
    )?;
    Ok(())
}

fn cursor_bitmap_from_db(
    width: Option<i64>,
    height: Option<i64>,
    hotspot_x: Option<i64>,
    hotspot_y: Option<i64>,
    png_b64: Option<String>,
) -> Option<CursorBitmap> {
    let width = width?;
    let height = height?;
    if width <= 0 || height <= 0 {
        return None;
    }
    Some(CursorBitmap {
        width: width as u32,
        height: height as u32,
        hotspot_x: hotspot_x.unwrap_or_default() as i32,
        hotspot_y: hotspot_y.unwrap_or_default() as i32,
        png_b64: png_b64?,
    })
}

fn archive_clear_stream(
    conn: &Connection,
    data_dir: &Path,
    stream_id: Uuid,
    delete_stream: bool,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT path FROM frames WHERE stream_id = ?1")?;
    let rows = stmt.query_map(params![stream_id.to_string()], |row| {
        row.get::<_, String>(0).map(PathBuf::from)
    })?;
    let mut paths = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut stmt = conn.prepare("SELECT path FROM video_chunks WHERE stream_id = ?1")?;
    let rows = stmt.query_map(params![stream_id.to_string()], |row| {
        row.get::<_, String>(0).map(PathBuf::from)
    })?;
    paths.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
    drop(stmt);

    conn.execute(
        "DELETE FROM frames WHERE stream_id = ?1",
        params![stream_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM video_chunks WHERE stream_id = ?1",
        params![stream_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM cursors WHERE stream_id = ?1",
        params![stream_id.to_string()],
    )?;
    if delete_stream {
        conn.execute(
            "DELETE FROM streams WHERE stream_id = ?1",
            params![stream_id.to_string()],
        )?;
    }

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
    let stream_dir = stream_dir_for(data_dir, stream_id);
    let _ = std::fs::remove_dir_all(&stream_dir);
    if !delete_stream {
        std::fs::create_dir_all(stream_dir)?;
    }
    Ok(())
}

fn evict_live_payloads(stream: &mut LiveStream, max_bytes: u64) {
    while stream.bytes > max_bytes {
        let frame_at = stream
            .frames
            .front()
            .map(|frame| frame.frame.captured_at_ms);
        let chunk_at = stream
            .video_chunks
            .front()
            .map(|chunk| chunk.chunk.captured_at_ms);
        match (frame_at, chunk_at) {
            (Some(frame_at), Some(chunk_at)) if frame_at <= chunk_at => {
                if let Some(old) = stream.frames.pop_front() {
                    stream.bytes = stream.bytes.saturating_sub(old.frame.size_bytes);
                }
            }
            (Some(_), None) => {
                if let Some(old) = stream.frames.pop_front() {
                    stream.bytes = stream.bytes.saturating_sub(old.frame.size_bytes);
                }
            }
            (None, Some(_)) | (Some(_), Some(_)) => {
                if let Some(old) = stream.video_chunks.pop_front() {
                    stream.bytes = stream.bytes.saturating_sub(old.chunk.size_bytes);
                }
            }
            (None, None) => break,
        }
    }
}

fn stream_dir_for(data_dir: &Path, stream_id: Uuid) -> PathBuf {
    data_dir.join("streams").join(stream_id.to_string())
}

fn frame_path_for(data_dir: &Path, stream_id: Uuid, seq: u64) -> PathBuf {
    stream_dir_for(data_dir, stream_id).join(format!("{seq:020}.bin"))
}

fn video_chunk_path_for(data_dir: &Path, stream_id: Uuid, seq: u64) -> PathBuf {
    stream_dir_for(data_dir, stream_id).join(format!("{seq:020}.video"))
}

fn media_kind_to_db(kind: StreamMediaKind) -> &'static str {
    match kind {
        StreamMediaKind::Image => "image",
        StreamMediaKind::Video => "video",
    }
}

fn stream_media_kind_from_db(kind: &str) -> StreamMediaKind {
    match kind {
        "video" => StreamMediaKind::Video,
        _ => StreamMediaKind::Image,
    }
}

fn video_codec_to_db(codec: glacialcast_protocol::VideoCodec) -> &'static str {
    match codec {
        glacialcast_protocol::VideoCodec::H264 => "h264",
        glacialcast_protocol::VideoCodec::Vp8 => "vp8",
        glacialcast_protocol::VideoCodec::Av1 => "av1",
    }
}

fn video_codec_from_db(codec: &str) -> glacialcast_protocol::VideoCodec {
    match codec {
        "vp8" => glacialcast_protocol::VideoCodec::Vp8,
        "av1" => glacialcast_protocol::VideoCodec::Av1,
        _ => glacialcast_protocol::VideoCodec::H264,
    }
}

fn video_packetization_to_db(
    packetization: glacialcast_protocol::VideoPacketization,
) -> &'static str {
    match packetization {
        glacialcast_protocol::VideoPacketization::AnnexB => "annex-b",
        glacialcast_protocol::VideoPacketization::RtpPayload => "rtp-payload",
    }
}

fn video_packetization_from_db(packetization: &str) -> glacialcast_protocol::VideoPacketization {
    match packetization {
        "rtp-payload" => glacialcast_protocol::VideoPacketization::RtpPayload,
        _ => glacialcast_protocol::VideoPacketization::AnnexB,
    }
}

fn max_option<T: Ord>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn vec_to_array<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|value: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Blob,
            format!("expected {N} bytes").into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_evicts_oldest_frames_per_stream() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 10).unwrap();
        let source = CaptureSource {
            backend: "test".to_string(),
            description: "generated".to_string(),
            width: 2,
            height: 2,
        };
        let stream_id = store
            .ensure_stream_for_client("test-client", "test", &source, StreamMediaKind::Image, true)
            .unwrap();

        for seq in 1..=3 {
            let frame = StoredFrame {
                stream_id,
                seq,
                captured_at_ms: seq as i64,
                width: 2,
                height: 2,
                mime: "image/jpeg".to_string(),
                key_id: "v1".to_string(),
                nonce: [seq as u8; 12],
                content_hash: seq as u32,
                size_bytes: 5,
                path: PathBuf::new(),
            };
            store.store_frame(frame, &[seq as u8; 5]).unwrap();
        }

        assert_eq!(store.live_frame_seqs(stream_id).unwrap(), vec![2, 3]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ensure_stream_reuses_client_identity() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 10).unwrap();
        let first_source = CaptureSource {
            backend: "test".to_string(),
            description: "first".to_string(),
            width: 2,
            height: 2,
        };
        let second_source = CaptureSource {
            backend: "test".to_string(),
            description: "second".to_string(),
            width: 4,
            height: 4,
        };

        let first = store
            .ensure_stream_for_client(
                "test-client",
                "first",
                &first_source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();
        let second = store
            .ensure_stream_for_client(
                "test-client",
                "second",
                &second_source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();

        assert_eq!(first, second);
        let streams = store.list_streams().unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].display_name, "second");
        assert_eq!(streams[0].source.width, 4);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn source_change_clears_retained_frames() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 1024).unwrap();
        let first_source = CaptureSource {
            backend: "test".to_string(),
            description: "first".to_string(),
            width: 2,
            height: 2,
        };
        let second_source = CaptureSource {
            backend: "test".to_string(),
            description: "second".to_string(),
            width: 4,
            height: 4,
        };
        let stream_id = store
            .ensure_stream_for_client(
                "test-client",
                "first",
                &first_source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();
        let frame = StoredFrame {
            stream_id,
            seq: 1,
            captured_at_ms: 1,
            width: 2,
            height: 2,
            mime: "image/jpeg".to_string(),
            key_id: "v1".to_string(),
            nonce: [1; 12],
            content_hash: 1,
            size_bytes: 5,
            path: PathBuf::new(),
        };
        store.store_frame(frame, &[1; 5]).unwrap();

        let reused = store
            .ensure_stream_for_client(
                "test-client",
                "second",
                &second_source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();

        assert_eq!(stream_id, reused);
        assert!(store.list_frames(stream_id).unwrap().is_empty());
        assert_eq!(store.last_frame_seq(stream_id).unwrap(), None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn encryption_mode_change_clears_retained_frames() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 1024).unwrap();
        let source = CaptureSource {
            backend: "test".to_string(),
            description: "same-source".to_string(),
            width: 2,
            height: 2,
        };
        let stream_id = store
            .ensure_stream_for_client("test-client", "test", &source, StreamMediaKind::Image, true)
            .unwrap();
        let frame = StoredFrame {
            stream_id,
            seq: 1,
            captured_at_ms: 1,
            width: 2,
            height: 2,
            mime: "image/jpeg".to_string(),
            key_id: "v1".to_string(),
            nonce: [1; 12],
            content_hash: 1,
            size_bytes: 5,
            path: PathBuf::new(),
        };
        store.store_frame(frame, &[1; 5]).unwrap();

        let reused = store
            .ensure_stream_for_client(
                "test-client",
                "test",
                &source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();

        assert_eq!(stream_id, reused);
        assert!(store.list_frames(stream_id).unwrap().is_empty());
        assert_eq!(store.last_frame_seq(stream_id).unwrap(), None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migration_backfills_encryption_mode_from_existing_frames() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("glacialcast.sqlite3");
        let stream_id = Uuid::new_v4();
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE streams (
                    stream_id TEXT PRIMARY KEY,
                    client_id TEXT UNIQUE,
                    display_name TEXT NOT NULL,
                    token_hash TEXT NOT NULL DEFAULT '',
                    backend TEXT NOT NULL DEFAULT '',
                    source_description TEXT NOT NULL DEFAULT '',
                    source_width INTEGER NOT NULL DEFAULT 0,
                    source_height INTEGER NOT NULL DEFAULT 0,
                    frame_encrypted INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    last_seen_at_ms INTEGER,
                    active INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE frames (
                    stream_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    captured_at_ms INTEGER NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    mime TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    content_hash INTEGER NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    PRIMARY KEY (stream_id, seq)
                );
                "#,
            )
            .unwrap();
            conn.execute(
                r#"
                INSERT INTO streams
                    (stream_id, client_id, display_name, backend, source_description,
                     source_width, source_height, created_at_ms, active)
                VALUES (?1, 'test-client', 'test', 'test', 'backfill-source', 2, 2, 1, 0)
                "#,
                params![stream_id.to_string()],
            )
            .unwrap();
            conn.execute(
                r#"
                INSERT INTO frames
                    (stream_id, seq, captured_at_ms, width, height, mime, key_id,
                     nonce, content_hash, size_bytes, path)
                VALUES (?1, 1, 1, 2, 2, 'image/jpeg', 'v1', ?2, 1, 5, 'missing.bin')
                "#,
                params![stream_id.to_string(), vec![1u8; 12]],
            )
            .unwrap();
        }

        let store = Store::open(dir.clone(), 1024).unwrap();
        let source = CaptureSource {
            backend: "test".to_string(),
            description: "backfill-source".to_string(),
            width: 2,
            height: 2,
        };

        let reused = store
            .ensure_stream_for_client(
                "test-client",
                "test",
                &source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();

        assert_eq!(stream_id, reused);
        assert!(store.list_frames(stream_id).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stored_frame_payload_round_trips_with_content_hash() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 1024).unwrap();
        let source = CaptureSource {
            backend: "test".to_string(),
            description: "round-trip".to_string(),
            width: 4,
            height: 3,
        };
        let stream_id = store
            .ensure_stream_for_client(
                "test-client",
                "test",
                &source,
                StreamMediaKind::Image,
                false,
            )
            .unwrap();
        let payload = b"known encoded image bytes";
        let content_hash = glacialcast_protocol::fast_content_hash(payload);
        let frame = StoredFrame {
            stream_id,
            seq: 1,
            captured_at_ms: 1,
            width: 4,
            height: 3,
            mime: "image/jpeg".to_string(),
            key_id: String::new(),
            nonce: [0; 12],
            content_hash,
            size_bytes: payload.len() as u64,
            path: PathBuf::new(),
        };

        store.store_frame(frame, payload).unwrap();

        let stored = store.get_frame_payload(stream_id, 1).unwrap().unwrap();
        assert_eq!(stored.bytes, payload);
        assert_eq!(stored.frame.content_hash, content_hash);
        assert_eq!(
            store.list_frames(stream_id).unwrap()[0].content_hash,
            content_hash
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stored_video_chunk_round_trips_and_counts_retained_bytes() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 1024).unwrap();
        let source = CaptureSource {
            backend: "test-video".to_string(),
            description: "round-trip".to_string(),
            width: 640,
            height: 360,
        };
        let stream_id = store
            .ensure_stream_for_client(
                "test-client",
                "test",
                &source,
                StreamMediaKind::Video,
                false,
            )
            .unwrap();
        let payload = b"annex-b access unit bytes";
        let content_hash = glacialcast_protocol::fast_content_hash(payload);
        let chunk = StoredVideoChunk {
            stream_id,
            seq: 1,
            captured_at_ms: 1,
            pts_ms: 0,
            duration_ms: 1000,
            width: 640,
            height: 360,
            source_width: 640,
            source_height: 360,
            codec: glacialcast_protocol::VideoCodec::H264,
            packetization: glacialcast_protocol::VideoPacketization::AnnexB,
            keyframe: true,
            mime: "video/h264".to_string(),
            key_id: String::new(),
            nonce: [0; 12],
            content_hash,
            size_bytes: payload.len() as u64,
            path: PathBuf::new(),
        };

        store.store_video_chunk(chunk, payload).unwrap();

        let stored = store
            .get_video_chunk_payload(stream_id, 1)
            .unwrap()
            .unwrap();
        assert_eq!(stored.bytes, payload);
        assert_eq!(stored.chunk.content_hash, content_hash);
        assert_eq!(
            store.list_video_chunks(stream_id).unwrap()[0].codec,
            glacialcast_protocol::VideoCodec::H264
        );
        assert_eq!(
            store.list_streams().unwrap()[0].retained_bytes,
            payload.len() as u64
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stored_cursor_round_trips_bitmap_and_hotspot() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone(), 1024).unwrap();
        let source = CaptureSource {
            backend: "test-cursor".to_string(),
            description: "round-trip".to_string(),
            width: 640,
            height: 360,
        };
        let stream_id = store
            .ensure_stream_for_client(
                "test-client",
                "test",
                &source,
                StreamMediaKind::Video,
                false,
            )
            .unwrap();
        let cursor = CursorMessage {
            stream_id,
            seq: 7,
            captured_at_ms: 123,
            x: 12.5,
            y: 24.5,
            source_width: 640,
            source_height: 360,
            bitmap: Some(CursorBitmap {
                width: 16,
                height: 24,
                hotspot_x: 2,
                hotspot_y: 3,
                png_b64: "cursor-png".to_string(),
            }),
        };

        {
            let conn = store.conn().unwrap();
            insert_cursor_metadata(&conn, &cursor).unwrap();
        }

        let cursors = store.list_cursors(stream_id, 10).unwrap();
        assert_eq!(cursors.len(), 1);
        assert_eq!(cursors[0].seq, 7);
        assert_eq!(cursors[0].x, 12.5);
        let bitmap = cursors[0].bitmap.as_ref().expect("cursor bitmap");
        assert_eq!(bitmap.width, 16);
        assert_eq!(bitmap.height, 24);
        assert_eq!(bitmap.hotspot_x, 2);
        assert_eq!(bitmap.hotspot_y, 3);
        assert_eq!(bitmap.png_b64, "cursor-png");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migration_removes_legacy_plaintext_hash_column() {
        let dir = std::env::temp_dir().join(format!("glacialcast-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("glacialcast.sqlite3");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE frames (
                    stream_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    captured_at_ms INTEGER NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    mime TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    plaintext_sha256 BLOB NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    PRIMARY KEY (stream_id, seq)
                );
                "#,
            )
            .unwrap();
        }

        let store = Store::open(dir.clone(), 1024).unwrap();

        assert!(store.column_exists("frames", "content_hash").unwrap());
        assert!(!store.column_exists("frames", "plaintext_sha256").unwrap());

        let _ = std::fs::remove_dir_all(dir);
    }
}
