//! HTTPS terminated by the relay itself.
//!
//! Encrypted playback needs Web Crypto and Encrypted Media Extensions, and
//! browsers withhold both outside a secure context. A plain `http://` address
//! that is not loopback is not one, which left a local-network deployment
//! needing a second process in front of it purely to reach `https://`.
//!
//! This is that second process removed, not the requirement relaxed: the
//! requirement is a browser rule about origins and nothing a server sends can
//! change it. The relay generates a certificate, serves TLS, and the origin
//! becomes one browsers will do cryptography on.
//!
//! A generated certificate signs for itself, so the first visit from each
//! browser shows a warning to accept. The alternative -- a certificate from a
//! CA the viewer already trusts -- is supported by passing one in, and is the
//! better answer wherever there is one to pass.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

/// The certificate and key a TLS listener is built from.
pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the leaf certificate, colon-separated hex.
    ///
    /// Printed at startup so the warning a self-signed certificate produces can
    /// be answered with something better than "it is probably fine": the
    /// fingerprint the browser shows is comparable against this one.
    pub fingerprint: String,
    /// Names and addresses the certificate is valid for.
    pub names: Vec<String>,
    /// Whether this was generated here rather than supplied.
    pub generated: bool,
}

/// Redacts the key rather than deriving this.
///
/// The certificate is public and the fingerprint is meant to be read aloud; the
/// key beside them is neither, and a derived `Debug` would put it in the first
/// error message that formatted this struct.
impl fmt::Debug for TlsMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsMaterial")
            .field("fingerprint", &self.fingerprint)
            .field("names", &self.names)
            .field("generated", &self.generated)
            .field("key_pem", &"[REDACTED]")
            .finish()
    }
}

/// Reads a supplied certificate, or reuses and otherwise creates a generated one.
///
/// A generated certificate is kept in `<data-dir>/tls` so a viewer that accepted
/// it once is not asked again after a restart. The key is written `0600` and
/// refused on load if its permissions have since widened.
///
/// # Errors
///
/// Returns an error when only one of `cert_path` and `key_path` is given, when
/// a supplied file cannot be read or is not PEM, or when the generated pair
/// cannot be written durably.
pub fn load_or_create(
    data_dir: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    control_addr: SocketAddr,
    extra_names: &[String],
) -> Result<TlsMaterial> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => load_supplied(cert, key),
        (None, None) => {
            let dir = data_dir.join("tls");
            load_or_generate(&dir, control_addr, extra_names)
        }
        _ => bail!("--tls-cert and --tls-key must be given together"),
    }
}

fn load_supplied(cert_path: &Path, key_path: &Path) -> Result<TlsMaterial> {
    let cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("reading TLS certificate {}", cert_path.display()))?;
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("reading TLS key {}", key_path.display()))?;
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        bail!("{} is not a PEM certificate", cert_path.display());
    }
    if !key_pem.contains("PRIVATE KEY") {
        bail!("{} is not a PEM private key", key_path.display());
    }
    let fingerprint = fingerprint(&cert_pem).unwrap_or_else(|| "unavailable".to_string());
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        fingerprint,
        names: Vec::new(),
        generated: false,
    })
}

/// Reuses a generated certificate only while it still covers what is wanted.
///
/// The names are recorded beside the pair when it is written, because they
/// cannot be recovered from the PEM without parsing the certificate's SANs. Two
/// things went wrong without them. The startup warning printed an empty
/// `valid_for` on every restart after the first -- losing exactly the address
/// list the warning exists to convey. And an operator who added `--tls-name`,
/// or whose LAN address changed, silently kept the old certificate: nothing
/// compared what was asked for against what was stored, so the browser reported
/// a name mismatch and the only way out was deleting the directory by hand.
///
/// A stored pair that covers every wanted name is kept, so restarting does not
/// ask viewers to accept a new certificate. Anything else is regenerated, which
/// does -- once, and for a reason the operator can act on.
fn load_or_generate(
    dir: &Path,
    control_addr: SocketAddr,
    extra_names: &[String],
) -> Result<TlsMaterial> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let names_path = dir.join("names");
    let wanted = certificate_names(control_addr, extra_names);

    if cert_path.exists() && key_path.exists() {
        let key_mode = fs::metadata(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if key_mode & 0o077 != 0 {
            bail!(
                "TLS key {} must not be readable by group or others (mode {:o})",
                key_path.display(),
                key_mode
            );
        }
        let stored = read_names(&names_path);
        let missing: Vec<&String> = wanted
            .iter()
            .filter(|name| !stored.contains(*name))
            .collect();
        // An empty `stored` cannot pass this: `certificate_names` always yields
        // at least loopback, so `missing` is non-empty whenever nothing was
        // recorded. That is the upgrade path, and it needs no clause of its own.
        if missing.is_empty() {
            let mut material = load_supplied(&cert_path, &key_path)?;
            material.generated = true;
            material.names = stored;
            return Ok(material);
        }
        warn!(
            path = %cert_path.display(),
            missing = ?missing,
            "regenerating the relay certificate: the stored one does not cover every \
             address this relay answers to, so viewers will be asked to accept it once more"
        );
    }

    let (cert_pem, key_pem) = generate(&wanted)?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {}", dir.display()))?;
    write_private(&key_path, key_pem.as_bytes())?;
    fs::write(&cert_path, &cert_pem).with_context(|| format!("writing {}", cert_path.display()))?;
    // Last, so a crash between the two leaves a pair with no name list rather
    // than a name list describing a certificate that was never written. The
    // first is regenerated on the next start; the second would be trusted.
    fs::write(&names_path, wanted.join("\n"))
        .with_context(|| format!("writing {}", names_path.display()))?;
    let fingerprint = fingerprint(&cert_pem).unwrap_or_else(|| "unavailable".to_string());
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        fingerprint,
        names: wanted,
        generated: true,
    })
}

/// The names a stored generated certificate was issued for.
///
/// An unreadable or absent list reads as "nothing known", which forces a
/// regeneration rather than a guess -- including for a pair written by a
/// version that did not keep this file.
fn read_names(path: &Path) -> Vec<String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// The names a generated certificate should answer to.
///
/// A viewer reaches the relay by whatever address they were given, so the
/// certificate covers loopback, this host's name, and the address this host
/// uses to reach the network -- which is the one a LAN viewer types. A
/// mismatch here is not fatal, since a self-signed certificate is accepted by
/// hand anyway, but a matching name is one less thing the warning complains
/// about.
fn certificate_names(control_addr: SocketAddr, extra_names: &[String]) -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = hostname() {
        names.push(host);
    }
    if !control_addr.ip().is_unspecified() {
        names.push(control_addr.ip().to_string());
    }
    if let Some(address) = outbound_address() {
        names.push(address.to_string());
    }
    for name in extra_names {
        names.push(name.clone());
    }
    names.sort();
    names.dedup();
    names
}

fn hostname() -> Option<String> {
    let raw = fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    let host = raw.trim();
    if host.is_empty() || host == "localhost" {
        return None;
    }
    Some(host.to_string())
}

/// The local address this host would use to reach the wider network.
///
/// A connected UDP socket sends nothing; it only asks the routing table which
/// source address a packet to that destination would leave from. That is the
/// address a viewer on the same network reaches this relay by, and it needs no
/// interface enumeration to find. The destination is TEST-NET-1, which is
/// reserved and never routed.
fn outbound_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:80").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified() && !address.is_loopback()).then_some(address)
}

fn generate(names: &[String]) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    for name in names {
        match name.parse::<IpAddr>() {
            Ok(address) => params.subject_alt_names.push(SanType::IpAddress(address)),
            Err(_) => params.subject_alt_names.push(SanType::DnsName(
                name.clone()
                    .try_into()
                    .with_context(|| format!("{name} is not usable as a certificate name"))?,
            )),
        }
    }
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, "GlacialCast relay");
    params.distinguished_name = subject;

    let key = KeyPair::generate().context("generating a TLS key")?;
    let cert = params
        .self_signed(&key)
        .context("generating a self-signed TLS certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// SHA-256 over the certificate's DER, which is what a browser displays.
fn fingerprint(cert_pem: &str) -> Option<String> {
    let body: String = cert_pem
        .lines()
        .skip_while(|line| !line.contains("BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|line| !line.contains("END CERTIFICATE"))
        .collect();
    let der = STANDARD.decode(body.trim()).ok()?;
    let digest = Sha256::digest(&der);
    Some(
        digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

/// How long one client may take over its TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Completed handshakes waiting to be served, before new ones stop being taken.
const READY_BACKLOG: usize = 64;

/// A TCP listener that hands `axum::serve` connections which are already
/// encrypted.
///
/// `axum::serve` accepts anything implementing its `Listener` trait, so the
/// whole router -- routes, connect-info, graceful shutdown -- is reused as it
/// is, and TLS is the only thing added.
pub struct TlsListener {
    local_addr: SocketAddr,
    ready: mpsc::Receiver<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    /// Binds `addr` and starts accepting, handshaking off the accept path.
    ///
    /// Each handshake runs in its own task, so one client that opens a
    /// connection and then says nothing delays only itself. It is also bounded
    /// twice over: by a timeout, and by a backlog of completed handshakes that
    /// stops new connections being taken while the server is behind.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate and key do not parse, do not agree,
    /// or the address cannot be bound.
    pub async fn bind(addr: SocketAddr, material: &TlsMaterial) -> Result<Self> {
        let certs = CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing the TLS certificate chain")?;
        if certs.is_empty() {
            bail!("the TLS certificate held no certificates");
        }
        let key = PrivateKeyDer::from_pem_slice(material.key_pem.as_bytes())
            .context("parsing the TLS private key")?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("the TLS certificate and key do not match")?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        let local_addr = listener.local_addr().context("reading the bound address")?;
        let (tx, ready) = mpsc::channel(READY_BACKLOG);
        tokio::spawn(accept_loop(listener, acceptor, tx));
        Ok(Self { local_addr, ready })
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    ready: mpsc::Sender<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>,
) {
    loop {
        // Reserving before accepting is the backpressure: while the server is
        // behind, connections stay in the kernel queue rather than piling up as
        // tasks here.
        let Ok(permit) = ready.clone().reserve_owned().await else {
            return;
        };
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                // Per-connection errors are transient; the listener itself is
                // still good, and returning here would stop serving entirely.
                warn!(?error, "accepting a TLS connection failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    permit.send((tls, peer));
                }
                Ok(Err(error)) => {
                    // A browser refusing a self-signed certificate lands here,
                    // as does anything speaking plain HTTP to this port, so it
                    // is ordinary rather than alarming.
                    debug!(%peer, ?error, "TLS handshake failed");
                }
                Err(_) => debug!(%peer, "TLS handshake timed out"),
            }
        });
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(accepted) = self.ready.recv().await {
                return accepted;
            }
            // The accept loop is gone, so nothing will arrive again. Returning
            // is not allowed by the trait, so wait rather than spin.
            std::future::pending::<()>().await;
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("glacialcast-tls-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_generated_pair_is_reused_and_its_key_stays_private() {
        let dir = scratch_dir();
        let addr: SocketAddr = "0.0.0.0:8899".parse().unwrap();
        let first = load_or_create(&dir, None, None, addr, &[]).unwrap();
        assert!(first.generated);
        assert!(first.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(first.names.iter().any(|name| name == "localhost"));

        // Reused rather than regenerated: a viewer that accepted this once must
        // not be asked again after a restart.
        let second = load_or_create(&dir, None, None, addr, &[]).unwrap();
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(first.fingerprint, second.fingerprint);
        // And it still knows what it answers to. The startup warning prints
        // this list, and reuse used to empty it.
        assert_eq!(first.names, second.names);
        assert!(second.names.iter().any(|name| name == "localhost"));

        let key = dir.join("tls/key.pem");
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "generated TLS key must stay private");

        // A key anyone can read is refused rather than served.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create(&dir, None, None, addr, &[]).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_certificate_covers_the_address_a_viewer_would_type() {
        let addr: SocketAddr = "192.168.1.2:8899".parse().unwrap();
        let names = certificate_names(addr, &["cast.internal".to_string()]);
        assert!(names.iter().any(|name| name == "127.0.0.1"));
        assert!(names.iter().any(|name| name == "192.168.1.2"));
        assert!(names.iter().any(|name| name == "cast.internal"));
        // A wildcard bind names no address of its own, so it must not add one.
        let wildcard = certificate_names("0.0.0.0:8899".parse().unwrap(), &[]);
        assert!(!wildcard.iter().any(|name| name == "0.0.0.0"));
    }

    #[test]
    fn a_newly_wanted_name_regenerates_the_certificate() {
        // The reuse path used to keep the stored pair no matter what was asked
        // for, so adding --tls-name changed nothing and the browser reported a
        // name mismatch with no way out but deleting the directory.
        let dir = scratch_dir();
        let addr: SocketAddr = "0.0.0.0:8899".parse().unwrap();
        let first = load_or_create(&dir, None, None, addr, &[]).unwrap();

        let renamed =
            load_or_create(&dir, None, None, addr, &["cast.example".to_string()]).unwrap();
        assert_ne!(first.fingerprint, renamed.fingerprint);
        assert!(renamed.names.iter().any(|name| name == "cast.example"));

        // Asking for the same set again reuses it: regenerating is the cost of
        // a changed answer, not of every restart.
        let again = load_or_create(&dir, None, None, addr, &["cast.example".to_string()]).unwrap();
        assert_eq!(renamed.fingerprint, again.fingerprint);

        // Dropping a name keeps the certificate, which still covers what is
        // wanted. A transiently missing address must not churn the pair.
        let fewer = load_or_create(&dir, None, None, addr, &[]).unwrap();
        assert_eq!(renamed.fingerprint, fewer.fingerprint);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pair_with_no_recorded_names_is_regenerated() {
        // What an upgrade finds: a certificate written before the name list
        // existed. Keeping it would mean serving a certificate nobody can say
        // anything about, so it is replaced once.
        let dir = scratch_dir();
        let addr: SocketAddr = "0.0.0.0:8899".parse().unwrap();
        let first = load_or_create(&dir, None, None, addr, &[]).unwrap();
        fs::remove_file(dir.join("tls/names")).unwrap();

        let second = load_or_create(&dir, None, None, addr, &[]).unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
        assert!(!second.names.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn half_a_certificate_is_refused() {
        let dir = scratch_dir();
        let addr: SocketAddr = "0.0.0.0:8899".parse().unwrap();
        let error = load_or_create(&dir, Some(Path::new("/x/cert.pem")), None, addr, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be given together"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
