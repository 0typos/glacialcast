//! Installed native relay runtime and configuration.

use crate::{
    native_access::NativeAccessPolicy, native_service::NativeRelayService,
    native_store::NativeStore,
};
use anyhow::{Context, Result};
use clap::Parser;
use glacialcast_protocol::{
    config_path::{self, ConfigSource},
    credential::{CertificateAuthorityPublic, RevocationList},
    encode_noise_public_key, load_or_create_noise_keypair, parse_human_bytes,
};
use serde::Deserialize;
use std::{
    fs,
    io::{IsTerminal, Read},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch};
use tracing::{error, info};

const DEFAULT_VIEWER_ADDR: &str = "0.0.0.0:8899";
const DEFAULT_PUBLISHER_ADDR: &str = "0.0.0.0:8900";
const DEFAULT_RETENTION_BYTES: u64 = 100 * 1024 * 1024;
const DEFAULT_RETENTION_SECONDS: u64 = 24 * 60 * 60;
const MAX_PUBLIC_MATERIAL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(version, about = "Store and relay opaque GlacialCast streams")]
struct Args {
    /// Relay TOML configuration file.
    #[arg(long, env = "GLACIALCAST_CONFIG")]
    config: Option<PathBuf>,
    /// Ignore discovered configuration and use built-in public-mode defaults.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,
    /// Override the publisher listener.
    #[arg(long)]
    publisher_addr: Option<SocketAddr>,
    /// Override the viewer listener.
    #[arg(long)]
    viewer_addr: Option<SocketAddr>,
    /// Override retained bytes per stream (for example `100MiB`).
    #[arg(long, value_parser = parse_human_bytes)]
    retention_bytes: Option<u64>,
    /// Override retained age per stream in seconds.
    #[arg(long)]
    retention_seconds: Option<u64>,
    /// Durable state directory.
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    /// Persistent Noise XX identity file.
    #[arg(long)]
    noise_key_file: Option<PathBuf>,
    /// Print the relay Noise public key and exit.
    #[arg(long)]
    print_server_key: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NativeConfig {
    listeners: ListenerConfig,
    retention: RetentionConfig,
    access: AccessConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ListenerConfig {
    publisher: SocketAddr,
    viewer: SocketAddr,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            publisher: DEFAULT_PUBLISHER_ADDR.parse().expect("valid default"),
            viewer: DEFAULT_VIEWER_ADDR.parse().expect("valid default"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RetentionConfig {
    bytes_per_stream: Option<u64>,
    seconds_per_stream: Option<u64>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            bytes_per_stream: Some(DEFAULT_RETENTION_BYTES),
            seconds_per_stream: Some(DEFAULT_RETENTION_SECONDS),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum AccessConfig {
    /// Any Noise-authenticated connection may use the appropriate endpoint.
    #[default]
    Public,
    /// Connections must carry a role- and Noise-key-bound native credential.
    Signed {
        authority_file: PathBuf,
        #[serde(default)]
        revocations_file: Option<PathBuf>,
    },
}

/// Parses configuration and serves native publisher and viewer listeners.
///
/// # Errors
///
/// Returns an error for invalid configuration, unsafe state, listener failure,
/// or a failed native service task.
pub fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("pki") {
        return crate::native_pki::run();
    }
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_relay=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building relay runtime")?
        .block_on(serve(args))
}

async fn serve(args: Args) -> Result<()> {
    let source = if args.no_config {
        ConfigSource::Defaults
    } else {
        config_path::resolve(args.config.clone(), "relay.toml")
    };
    let config = load_config(&source)?;
    let publisher_addr = args.publisher_addr.unwrap_or(config.listeners.publisher);
    let viewer_addr = args.viewer_addr.unwrap_or(config.listeners.viewer);
    let retention_bytes = args.retention_bytes.or(config.retention.bytes_per_stream);
    let retention_age = args
        .retention_seconds
        .or(config.retention.seconds_per_stream)
        .map(Duration::from_secs);
    if retention_bytes == Some(0) || retention_age == Some(Duration::ZERO) {
        anyhow::bail!("retention limits must be positive or omitted");
    }

    fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating relay data directory {}", args.data_dir.display()))?;
    fs::set_permissions(&args.data_dir, fs::Permissions::from_mode(0o700))?;
    let noise_path = args
        .noise_key_file
        .unwrap_or_else(|| args.data_dir.join("relay-noise.key"));
    let noise_identity = load_or_create_noise_keypair(&noise_path)?;
    if args.print_server_key {
        println!("{}", encode_noise_public_key(&noise_identity.public));
        return Ok(());
    }

    let access = load_access(config.access)?;
    let store = NativeStore::open(args.data_dir.join("native"), retention_bytes, retention_age)?;
    if let Some(path) = store.quarantined_v1_path() {
        tracing::warn!(path = %path.display(), "quarantined incompatible version 1 store");
    }
    let service = NativeRelayService::new(store.clone(), access, noise_identity)?;
    let publisher_listener = TcpListener::bind(publisher_addr)
        .await
        .with_context(|| format!("binding publisher listener {publisher_addr}"))?;
    let viewer_listener = TcpListener::bind(viewer_addr)
        .await
        .with_context(|| format!("binding viewer listener {viewer_addr}"))?;
    info!(
        %publisher_addr,
        %viewer_addr,
        server_key = %encode_noise_public_key(&service.noise_public_key()),
        "native relay listening"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let publisher_service = service.clone();
    let publisher_shutdown = shutdown_rx.clone();
    let publishers = tokio::spawn(async move {
        publisher_service
            .serve_publishers(publisher_listener, publisher_shutdown)
            .await
    });
    let viewer_service = service.clone();
    let viewer_shutdown = shutdown_rx.clone();
    let viewers = tokio::spawn(async move {
        viewer_service
            .serve_viewers(viewer_listener, viewer_shutdown)
            .await
    });
    let retention = tokio::spawn(run_retention(store, shutdown_rx));
    tokio::signal::ctrl_c()
        .await
        .context("installing Ctrl-C handler")?;
    let _ = shutdown_tx.send(true);
    for (name, task) in [
        ("publisher", publishers),
        ("viewer", viewers),
        ("retention", retention),
    ] {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                error!(?error, task = name, "relay task failed");
                return Err(error);
            }
            Err(error) => anyhow::bail!("{name} relay task panicked: {error}"),
        }
    }
    Ok(())
}

async fn run_retention(store: NativeStore, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
            _ = interval.tick() => {
                let retained = store.clone();
                tokio::task::spawn_blocking(move || retained.enforce_retention_at(glacialcast_protocol::now_ms()))
                    .await
                    .context("retention worker panicked")??;
            }
        }
    }
}

fn load_config(source: &ConfigSource) -> Result<NativeConfig> {
    let Some(path) = source.path() else {
        return Ok(NativeConfig::default());
    };
    if source.must_exist() && !path.exists() {
        anyhow::bail!("relay config {} does not exist", path.display());
    }
    if !path.exists() {
        return Ok(NativeConfig::default());
    }
    let raw = read_bounded(path, 1024 * 1024, true)?;
    toml::from_str(std::str::from_utf8(&raw).context("relay config is not UTF-8")?)
        .with_context(|| format!("parsing relay config {}", path.display()))
}

fn load_access(config: AccessConfig) -> Result<NativeAccessPolicy> {
    match config {
        AccessConfig::Public => Ok(NativeAccessPolicy::Public),
        AccessConfig::Signed {
            authority_file,
            revocations_file,
        } => {
            let authority = CertificateAuthorityPublic::decode(&read_bounded(
                &authority_file,
                MAX_PUBLIC_MATERIAL_BYTES,
                false,
            )?)?;
            let revocations = revocations_file
                .map(|path| {
                    RevocationList::decode(&read_bounded(&path, MAX_PUBLIC_MATERIAL_BYTES, false)?)
                        .map_err(anyhow::Error::from)
                })
                .transpose()?;
            if let Some(list) = &revocations {
                list.verify_at(&authority, glacialcast_protocol::now_ms())?;
            }
            Ok(NativeAccessPolicy::Signed {
                authority,
                revocations,
            })
        }
    }
}

fn read_bounded(path: &Path, max_len: u64, require_private: bool) -> Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_len {
        anyhow::bail!("{} is not a bounded regular file", path.display());
    }
    if require_private && metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("{} must have mode 0600", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults_are_public_and_bounded_to_one_day_or_one_hundred_mibibytes() {
        let config = NativeConfig::default();
        assert!(matches!(config.access, AccessConfig::Public));
        assert_eq!(config.retention.bytes_per_stream, Some(100 * 1024 * 1024));
        assert_eq!(config.retention.seconds_per_stream, Some(86_400));
    }

    #[test]
    fn unknown_config_and_zero_retention_are_rejected() {
        assert!(toml::from_str::<NativeConfig>("unknown = 1").is_err());
        let args = Args::try_parse_from(["gcrelay", "--retention-bytes", "0"]);
        assert!(args.is_ok(), "semantic validation happens after parsing");
    }
}
