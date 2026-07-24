use anyhow::{Context, Result};
use glacialcast_protocol::{CaptureSource, PublicStream};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("creating catalog directory {}", data_dir.display()))?;
        let conn = Connection::open(data_dir.join("glacialcast.sqlite3"))
            .context("opening stream catalog")?;
        let store = Self {
            inner: Arc::new(StoreInner {
                conn: Mutex::new(conn),
            }),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn()?.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS streams (
                stream_id TEXT PRIMARY KEY,
                client_id TEXT UNIQUE,
                display_name TEXT NOT NULL,
                backend TEXT NOT NULL DEFAULT '',
                source_description TEXT NOT NULL DEFAULT '',
                source_width INTEGER NOT NULL DEFAULT 0,
                source_height INTEGER NOT NULL DEFAULT 0,
                created_at_ms INTEGER NOT NULL,
                last_seen_at_ms INTEGER,
                active INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_streams_client_id
                ON streams(client_id)
                WHERE client_id IS NOT NULL;
            UPDATE streams SET active = 0;
            "#,
        )?;
        Ok(())
    }

    pub fn ensure_stream_for_client(
        &self,
        client_id: &str,
        display_name: &str,
        source: &CaptureSource,
    ) -> Result<Uuid> {
        let now = glacialcast_protocol::now_ms();
        if let Some(stream_id) = self.stream_id_for_client(client_id)? {
            self.conn()?.execute(
                r#"
                UPDATE streams
                SET display_name = ?2,
                    backend = ?3,
                    source_description = ?4,
                    source_width = ?5,
                    source_height = ?6,
                    last_seen_at_ms = ?7,
                    active = 1
                WHERE stream_id = ?1
                "#,
                params![
                    stream_id.to_string(),
                    display_name,
                    source.backend,
                    source.description,
                    source.width,
                    source.height,
                    now,
                ],
            )?;
            return Ok(stream_id);
        }

        let stream_id = Uuid::new_v4();
        self.conn()?.execute(
            r#"
            INSERT INTO streams
                (stream_id, client_id, display_name, backend, source_description,
                 source_width, source_height, created_at_ms, last_seen_at_ms, active)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 1)
            "#,
            params![
                stream_id.to_string(),
                client_id,
                display_name,
                source.backend,
                source.description,
                source.width,
                source.height,
                now,
            ],
        )?;
        Ok(stream_id)
    }

    fn stream_id_for_client(&self, client_id: &str) -> Result<Option<Uuid>> {
        let value = self
            .conn()?
            .query_row(
                "SELECT stream_id FROM streams WHERE client_id = ?1",
                params![client_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|value| Uuid::parse_str(&value).context("invalid stream_id in stream catalog"))
            .transpose()
    }

    pub fn mark_stream_inactive(&self, stream_id: Uuid) -> Result<()> {
        self.conn()?.execute(
            "UPDATE streams SET active = 0, last_seen_at_ms = ?2 WHERE stream_id = ?1",
            params![stream_id.to_string(), glacialcast_protocol::now_ms()],
        )?;
        Ok(())
    }

    pub fn stream_exists(&self, stream_id: Uuid) -> Result<bool> {
        let found = self
            .conn()?
            .query_row(
                "SELECT 1 FROM streams WHERE stream_id = ?1",
                params![stream_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn list_streams(&self) -> Result<Vec<PublicStream>> {
        let conn = self.conn()?;
        let mut statement = conn.prepare(
            r#"
            SELECT stream_id, display_name, backend, source_description,
                   source_width, source_height, active, last_seen_at_ms
            FROM streams
            ORDER BY active DESC, COALESCE(last_seen_at_ms, created_at_ms) DESC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ))
        })?;

        rows.map(|row| {
            let (stream_id, display_name, backend, description, width, height, active, last_seen) =
                row?;
            Ok(PublicStream {
                stream_id: Uuid::parse_str(&stream_id)
                    .context("invalid stream_id in stream catalog")?,
                display_name,
                source: CaptureSource {
                    backend,
                    description,
                    width: u32::try_from(width)
                        .context("invalid source width in stream catalog")?,
                    height: u32::try_from(height)
                        .context("invalid source height in stream catalog")?,
                },
                active: active != 0,
                last_seen_at_ms: last_seen,
                last_object_sequence: None,
                retained_bytes: 0,
            })
        })
        .collect()
    }

    pub fn delete_stream(&self, stream_id: Uuid) -> Result<bool> {
        let deleted = self.conn()?.execute(
            "DELETE FROM streams WHERE stream_id = ?1",
            params![stream_id.to_string()],
        )?;
        Ok(deleted > 0)
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.inner
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("stream catalog lock poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(description: &str) -> CaptureSource {
        CaptureSource {
            backend: "test".to_string(),
            description: description.to_string(),
            width: 1280,
            height: 720,
        }
    }

    #[test]
    fn catalog_reuses_identity_and_persists_metadata() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-stream-catalog-{}", Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let stream_id = store
            .ensure_stream_for_client("desk", "Desktop", &source("first"))
            .unwrap();
        let reconnected = store
            .ensure_stream_for_client("desk", "Renamed", &source("second"))
            .unwrap();
        assert_eq!(reconnected, stream_id);
        drop(store);

        let reopened = Store::open(root.clone()).unwrap();
        let streams = reopened.list_streams().unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].display_name, "Renamed");
        assert_eq!(streams[0].source.description, "second");
        assert!(!streams[0].active);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_marks_inactive_and_deletes_exact_stream() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-stream-catalog-{}", Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let stream_id = store
            .ensure_stream_for_client("desk", "Desktop", &source("screen"))
            .unwrap();
        assert!(store.stream_exists(stream_id).unwrap());
        store.mark_stream_inactive(stream_id).unwrap();
        assert!(!store.list_streams().unwrap()[0].active);
        assert!(store.delete_stream(stream_id).unwrap());
        assert!(!store.stream_exists(stream_id).unwrap());
        assert!(!store.delete_stream(stream_id).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
