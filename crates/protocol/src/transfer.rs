//! Versioned portable-transfer index parsing.
//!
//! The disconnected viewer accepts the legacy single-file v1 index and writes
//! a v2 root that references bounded, content-addressed chunk files. Parsing is
//! kept at the protocol boundary so the exact JSON accepted by the executable
//! is also exercised by the repository fuzz suite.

use crate::DashObjectHeader;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Legacy single-file root-manifest version.
pub const LEGACY_TRANSFER_MANIFEST_VERSION: u16 = 1;
/// Current chunked root-manifest version.
pub const TRANSFER_MANIFEST_VERSION: u16 = 2;
/// Current immutable chunk-file version.
pub const TRANSFER_CHUNK_VERSION: u16 = 1;

/// A current root transfer manifest.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferManifest {
    /// Root format version.
    pub version: u16,
    /// Stream whose objects are indexed.
    pub stream_id: Uuid,
    /// Positive Unix generation time in milliseconds.
    pub generated_at_ms: i64,
    /// Strictly sequence-ordered immutable chunk descriptors.
    pub chunks: Vec<TransferChunkDescriptor>,
}

/// A legacy v1 root transfer manifest retained for read compatibility.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTransferManifest {
    /// Root format version.
    pub version: u16,
    /// Stream whose objects are indexed.
    pub stream_id: Uuid,
    /// Positive Unix generation time in milliseconds.
    pub generated_at_ms: i64,
    /// Portable object records in the legacy unchunked index.
    pub objects: Vec<TransferObject>,
}

/// Integrity and routing metadata for one portable `.gco` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferObject {
    /// Basename of the portable object.
    pub filename: String,
    /// Exact encoded file length in bytes.
    pub length: u64,
    /// Lowercase hexadecimal SHA-256 digest of the complete file.
    pub sha256: String,
    /// Authenticated public DASH object header.
    pub header: DashObjectHeader,
}

/// Integrity and range metadata for one immutable transfer-index chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferChunkDescriptor {
    /// Content-addressed chunk basename.
    pub filename: String,
    /// Exact encoded chunk length in bytes.
    pub length: u64,
    /// Lowercase hexadecimal SHA-256 digest of the complete chunk.
    pub sha256: String,
    /// First object sequence declared by the chunk.
    pub first_sequence: u64,
    /// Last object sequence declared by the chunk.
    pub last_sequence: u64,
    /// Number of object records declared by the chunk.
    pub object_count: u64,
}

/// One bounded immutable transfer-index chunk.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferChunk {
    /// Chunk format version.
    pub version: u16,
    /// Stream whose objects are indexed.
    pub stream_id: Uuid,
    /// Strictly sequence-ordered portable object records.
    pub objects: Vec<TransferObject>,
}

/// A parsed, supported root transfer manifest.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferRoot {
    /// Legacy v1 single-file index.
    Legacy(LegacyTransferManifest),
    /// Current v2 chunked root index.
    Chunked(TransferManifest),
}

/// Parse a supported transfer root and enforce its version and generation time.
pub fn parse_transfer_root(bytes: &[u8]) -> Result<TransferRoot> {
    #[derive(Deserialize)]
    struct ManifestVersion {
        version: u16,
    }

    let version: ManifestVersion =
        serde_json::from_slice(bytes).context("decoding transfer manifest version")?;
    match version.version {
        LEGACY_TRANSFER_MANIFEST_VERSION => {
            let manifest: LegacyTransferManifest =
                serde_json::from_slice(bytes).context("decoding legacy transfer manifest")?;
            if manifest.generated_at_ms <= 0 {
                bail!("legacy transfer manifest has invalid metadata");
            }
            Ok(TransferRoot::Legacy(manifest))
        }
        TRANSFER_MANIFEST_VERSION => {
            let manifest: TransferManifest =
                serde_json::from_slice(bytes).context("decoding transfer manifest")?;
            if manifest.generated_at_ms <= 0 {
                bail!("transfer manifest has invalid metadata");
            }
            Ok(TransferRoot::Chunked(manifest))
        }
        version => bail!("unsupported transfer manifest version {version}"),
    }
}

/// Parse a transfer chunk and reject unsupported versions.
pub fn parse_transfer_chunk(bytes: &[u8]) -> Result<TransferChunk> {
    let chunk: TransferChunk =
        serde_json::from_slice(bytes).context("decoding transfer manifest chunk")?;
    if chunk.version != TRANSFER_CHUNK_VERSION {
        bail!(
            "unsupported transfer manifest chunk version {}",
            chunk.version
        );
    }
    Ok(chunk)
}

/// Exercise transfer root and chunk parsers with arbitrary bytes.
#[doc(hidden)]
pub fn fuzz_transfer_index(bytes: &[u8]) {
    if let Ok(root) = parse_transfer_root(bytes) {
        let encoded = match &root {
            TransferRoot::Legacy(manifest) => serde_json::to_vec(manifest),
            TransferRoot::Chunked(manifest) => serde_json::to_vec(manifest),
        }
        .expect("re-encoding parsed transfer root");
        let reparsed = parse_transfer_root(&encoded).expect("reparsing transfer root");
        assert_eq!(reparsed, root);
    }
    if let Ok(chunk) = parse_transfer_chunk(bytes) {
        let encoded = serde_json::to_vec(&chunk).expect("re-encoding parsed transfer chunk");
        let reparsed = parse_transfer_chunk(&encoded).expect("reparsing transfer chunk");
        assert_eq!(reparsed, chunk);
    }
}
