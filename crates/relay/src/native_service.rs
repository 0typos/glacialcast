//! Native Noise XX publisher/viewer relay data plane.

use crate::{
    native_access::{NativeAccessPolicy, NativeAdmission},
    native_store::{NativeRetainedBounds, NativeStore},
    pairing_store::PairingStore,
};
use anyhow::{Context, Result};
use glacialcast_protocol::{
    NoiseKeypair, NoiseSocket,
    credential::CredentialRole,
    envelope::KeyEnvelope,
    identity::{IDENTITY_ID_LEN, IdentityPublic},
    native::NativeObject,
    responder_handshake_xx,
    wire::{
        CatalogEntry, NativeWireMessage, PublisherMessage, PublisherResumeStream, RelayError,
        RelayErrorCode, RelayPublisherMessage, RelayResumeStream, RelayViewerMessage, RelayWelcome,
        RetainedBounds, SessionHello, SubscriptionStart, ViewerMessage,
    },
};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, broadcast, watch},
};
use uuid::Uuid;

const SUBSCRIPTION_PAGE: usize = 1_024;
const PAIRING_REQUEST_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;

/// Hard bounds applied to native relay connections.
#[derive(Clone, Copy, Debug)]
pub struct NativeServiceLimits {
    /// Maximum publisher and viewer TCP sessions combined.
    pub max_connections: usize,
    /// Maximum time allowed for Noise and the first application message.
    pub handshake_timeout: Duration,
    /// Maximum time a connected peer may send no application data.
    pub idle_timeout: Duration,
    /// Maximum opaque live items retained in memory per stream.
    pub live_channel_capacity: usize,
}

impl Default for NativeServiceLimits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            live_channel_capacity: 32,
        }
    }
}

/// Shared native relay service state.
#[derive(Clone)]
pub struct NativeRelayService {
    inner: Arc<NativeRelayInner>,
}

struct NativeRelayInner {
    store: NativeStore,
    access: NativeAccessPolicy,
    noise_identity: NoiseKeypair,
    pairing: PairingStore,
    live: Mutex<HashMap<Uuid, broadcast::Sender<LiveItem>>>,
    online_streams: RwLock<HashSet<Uuid>>,
    limits: NativeServiceLimits,
    connections: Arc<Semaphore>,
}

#[derive(Clone)]
enum LiveItem {
    Object(NativeObject),
    Envelope(KeyEnvelope),
}

impl NativeRelayService {
    /// Creates a native relay around one durable store and one shared Noise identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied Noise public/private pair is inconsistent.
    pub fn new(
        store: NativeStore,
        access: NativeAccessPolicy,
        noise_identity: NoiseKeypair,
    ) -> Result<Self> {
        Self::new_with_limits(
            store,
            access,
            noise_identity,
            NativeServiceLimits::default(),
        )
    }

    /// Creates a native relay with explicit hard connection and timeout bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid Noise identity or zero-valued bounds.
    pub fn new_with_limits(
        store: NativeStore,
        access: NativeAccessPolicy,
        noise_identity: NoiseKeypair,
        limits: NativeServiceLimits,
    ) -> Result<Self> {
        if limits.max_connections == 0
            || limits.handshake_timeout.is_zero()
            || limits.idle_timeout.is_zero()
            || limits.live_channel_capacity == 0
        {
            anyhow::bail!("native service limits must be positive");
        }
        noise_identity
            .validate_xx()
            .context("validating native relay Noise identity")?;
        let pairing = PairingStore::open(store.root().join("pairing"))?;
        Ok(Self {
            inner: Arc::new(NativeRelayInner {
                store,
                access,
                noise_identity,
                pairing,
                live: Mutex::new(HashMap::new()),
                online_streams: RwLock::new(HashSet::new()),
                limits,
                connections: Arc::new(Semaphore::new(limits.max_connections)),
            }),
        })
    }

    /// Returns the relay's Noise public key for invitations and explicit pins.
    #[must_use]
    pub fn noise_public_key(&self) -> [u8; 32] {
        self.inner.noise_identity.public
    }

    /// Serves one publisher connection over an arbitrary asynchronous stream.
    ///
    /// # Errors
    ///
    /// Returns an error for Noise, framing, admission, protocol, storage, or I/O
    /// failure. No publish acknowledgement precedes durable storage.
    pub async fn handle_publisher<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (transport, remote_noise_key) = tokio::time::timeout(
            self.inner.limits.handshake_timeout,
            responder_handshake_xx(&mut stream, &self.inner.noise_identity.private),
        )
        .await
        .context("publisher Noise XX handshake timed out")?
        .context("performing publisher Noise XX handshake")?;
        let mut socket = NoiseSocket::new(stream, transport);
        let hello_message = tokio::time::timeout(
            self.inner.limits.handshake_timeout,
            socket.read::<PublisherMessage>(),
        )
        .await
        .context("publisher hello timed out")?
        .context("reading publisher hello")?;
        hello_message
            .validate_wire()
            .context("validating publisher hello")?;
        let PublisherMessage::Hello(hello) = hello_message else {
            send_publisher_error(
                &mut socket,
                RelayErrorCode::ProtocolViolation,
                "publisher hello must be first",
            )
            .await?;
            anyhow::bail!("publisher hello was not first");
        };
        let admission = match self.inner.access.admit(
            &hello,
            CredentialRole::Publisher,
            &remote_noise_key,
            glacialcast_protocol::now_ms(),
        ) {
            Ok(admission) => admission,
            Err(error) => {
                send_publisher_error(
                    &mut socket,
                    RelayErrorCode::Unauthorized,
                    "publisher credential rejected",
                )
                .await?;
                return Err(error).context("admitting publisher");
            }
        };
        write_publisher(
            &mut socket,
            &RelayPublisherMessage::Welcome(welcome(admission)),
        )
        .await?;

        let mut touched_streams = HashSet::new();
        let result = self
            .publisher_loop(&mut socket, &hello, admission, &mut touched_streams)
            .await;
        for stream_id in &touched_streams {
            if let Err(error) = self
                .store_call({
                    let stream_id = *stream_id;
                    move |store| store.finalize_stream(stream_id)
                })
                .await
            {
                tracing::error!(?error, %stream_id, "failed to finalize disconnected stream");
            }
        }
        if let Ok(mut online) = self.inner.online_streams.write() {
            for stream_id in touched_streams {
                online.remove(&stream_id);
            }
        }
        result
    }

    async fn publisher_loop<S>(
        &self,
        socket: &mut NoiseSocket<S>,
        hello: &SessionHello,
        admission: NativeAdmission,
        touched_streams: &mut HashSet<Uuid>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let publisher_id = hello
            .identity
            .id()
            .context("fingerprinting publisher identity")?;
        loop {
            if let Err(error) = self
                .inner
                .access
                .ensure_active(admission, glacialcast_protocol::now_ms())
            {
                send_publisher_error(
                    socket,
                    active_credential_error_code(admission),
                    "publisher credential is no longer valid",
                )
                .await?;
                return Err(error.into());
            }
            let message = match read_publisher_until_expiry(
                socket,
                admission.expires_at_ms,
                self.inner.limits.idle_timeout,
            )
            .await
            {
                Ok(message) => message,
                Err(SessionReadError::Expired) => {
                    send_publisher_error(
                        socket,
                        RelayErrorCode::CredentialExpired,
                        "publisher credential expired",
                    )
                    .await?;
                    anyhow::bail!("publisher credential expired");
                }
                Err(SessionReadError::Idle) => anyhow::bail!("publisher session idle timeout"),
                Err(SessionReadError::Protocol(error)) => return Err(error),
            };
            message
                .validate_wire()
                .context("validating publisher message")?;
            match message {
                PublisherMessage::Hello(_) => {
                    send_publisher_error(
                        socket,
                        RelayErrorCode::ProtocolViolation,
                        "duplicate publisher hello",
                    )
                    .await?;
                    anyhow::bail!("duplicate publisher hello");
                }
                PublisherMessage::Resume {
                    publisher_id: claimed,
                    streams,
                } => {
                    if claimed != publisher_id {
                        anyhow::bail!("publisher resume identity mismatch");
                    }
                    let mut states = Vec::with_capacity(streams.len());
                    for stream in streams {
                        self.validate_resume_stream(&hello.identity, &stream)
                            .await?;
                        self.claim_online(stream.stream_id, touched_streams)?;
                        let high_water = self
                            .store_call({
                                let stream_id = stream.stream_id;
                                move |store| store.high_water(stream_id)
                            })
                            .await?
                            .unwrap_or(0);
                        states.push(RelayResumeStream {
                            stream_id: stream.stream_id,
                            committed_through: high_water,
                        });
                    }
                    write_publisher(socket, &RelayPublisherMessage::ResumeState(states)).await?;
                }
                PublisherMessage::Descriptor(descriptor) => {
                    require_publisher(&descriptor.body.publisher, &hello.identity)?;
                    let stream_id = descriptor.body.stream_id;
                    self.claim_online(stream_id, touched_streams)?;
                    self.store_call(move |store| store.put_descriptor(&descriptor))
                        .await?;
                }
                PublisherMessage::Object(object) => {
                    if object.header.publisher_id != publisher_id {
                        anyhow::bail!("native object publisher identity mismatch");
                    }
                    let stream_id = object.header.stream_id;
                    self.claim_online(stream_id, touched_streams)?;
                    let broadcast_object = object.clone();
                    let commit = self
                        .store_call(move |store| {
                            store.store_object(&object, glacialcast_protocol::now_ms())
                        })
                        .await?;
                    if commit.inserted {
                        let _ = self
                            .live_sender(stream_id)?
                            .send(LiveItem::Object(broadcast_object));
                    }
                    write_publisher(
                        socket,
                        &RelayPublisherMessage::PublishAck {
                            stream_id,
                            committed_through: commit.committed_through,
                        },
                    )
                    .await?;
                }
                PublisherMessage::KeyEnvelope(envelope) => {
                    if envelope.header.publisher_id != publisher_id {
                        anyhow::bail!("key envelope publisher identity mismatch");
                    }
                    let broadcast_envelope = envelope.clone();
                    let stream_id = envelope.header.stream_id;
                    let inserted = self
                        .store_call(move |store| {
                            store.store_envelope(&envelope, glacialcast_protocol::now_ms())
                        })
                        .await?;
                    if inserted {
                        let _ = self
                            .live_sender(stream_id)?
                            .send(LiveItem::Envelope(broadcast_envelope));
                    }
                }
                PublisherMessage::PairOffer(offer) => {
                    if offer.body.publisher != hello.identity {
                        anyhow::bail!("pair offer publisher identity mismatch");
                    }
                    let request_id = offer.body.request_id;
                    self.pairing_call(move |store| {
                        store.store_offer(
                            &offer,
                            glacialcast_protocol::now_ms(),
                            PAIRING_REQUEST_LIFETIME_MS,
                        )
                    })
                    .await?;
                    write_publisher(socket, &RelayPublisherMessage::PairingAck { request_id })
                        .await?;
                }
                PublisherMessage::PairDecision(decision) => {
                    let request_id = decision.body.request_id;
                    self.pairing_call(move |store| {
                        store.store_decision(&decision, glacialcast_protocol::now_ms())
                    })
                    .await?;
                    write_publisher(socket, &RelayPublisherMessage::PairingAck { request_id })
                        .await?;
                }
                PublisherMessage::FetchPairingInbox => {
                    let identity = hello.identity;
                    let inbox = self
                        .pairing_call(move |store| {
                            store.publisher_inbox(&identity, glacialcast_protocol::now_ms())
                        })
                        .await?;
                    for delivery in inbox.requests {
                        write_publisher(
                            socket,
                            &RelayPublisherMessage::PairRequest {
                                request: Box::new(delivery.request),
                                source_addr: delivery.source_addr,
                                received_at_ms: delivery.received_at_ms,
                            },
                        )
                        .await?;
                    }
                    for confirmation in inbox.confirmations {
                        write_publisher(
                            socket,
                            &RelayPublisherMessage::ViewerConfirmation(confirmation),
                        )
                        .await?;
                    }
                    write_publisher(socket, &RelayPublisherMessage::PairingInboxComplete).await?;
                }
                PublisherMessage::Ping { .. } => {
                    write_publisher(
                        socket,
                        &RelayPublisherMessage::Pong {
                            now_ms: glacialcast_protocol::now_ms(),
                        },
                    )
                    .await?;
                }
            }
        }
    }

    /// Serves one viewer control or dedicated subscription connection.
    ///
    /// # Errors
    ///
    /// Returns an error for Noise, admission, protocol, storage, or I/O failure.
    /// Signed-mode peers receive no catalog data before successful admission.
    pub async fn handle_viewer<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.handle_viewer_from(stream, SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
    }

    /// Serves one viewer connection with its relay-observed source address.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::handle_viewer`]. The address is only
    /// informational pairing metadata and a rate-limit key, never identity.
    pub async fn handle_viewer_from<S>(&self, mut stream: S, source_addr: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (transport, remote_noise_key) = tokio::time::timeout(
            self.inner.limits.handshake_timeout,
            responder_handshake_xx(&mut stream, &self.inner.noise_identity.private),
        )
        .await
        .context("viewer Noise XX handshake timed out")?
        .context("performing viewer Noise XX handshake")?;
        let mut socket = NoiseSocket::new(stream, transport);
        let hello_message = tokio::time::timeout(
            self.inner.limits.handshake_timeout,
            socket.read::<ViewerMessage>(),
        )
        .await
        .context("viewer hello timed out")?
        .context("reading viewer hello")?;
        hello_message
            .validate_wire()
            .context("validating viewer hello")?;
        let ViewerMessage::Hello(hello) = hello_message else {
            send_viewer_error(
                &mut socket,
                RelayErrorCode::ProtocolViolation,
                "viewer hello must be first",
            )
            .await?;
            anyhow::bail!("viewer hello was not first");
        };
        let admission = match self.inner.access.admit(
            &hello,
            CredentialRole::Viewer,
            &remote_noise_key,
            glacialcast_protocol::now_ms(),
        ) {
            Ok(admission) => admission,
            Err(error) => {
                send_viewer_error(
                    &mut socket,
                    RelayErrorCode::Unauthorized,
                    "viewer credential rejected",
                )
                .await?;
                return Err(error).context("admitting viewer");
            }
        };
        write_viewer(
            &mut socket,
            &RelayViewerMessage::Welcome(welcome(admission)),
        )
        .await?;
        self.viewer_loop(&mut socket, &hello, admission, source_addr)
            .await
    }

    async fn viewer_loop<S>(
        &self,
        socket: &mut NoiseSocket<S>,
        hello: &SessionHello,
        admission: NativeAdmission,
        source_addr: SocketAddr,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            if let Err(error) = self
                .inner
                .access
                .ensure_active(admission, glacialcast_protocol::now_ms())
            {
                send_viewer_error(
                    socket,
                    active_credential_error_code(admission),
                    "viewer credential is no longer valid",
                )
                .await?;
                return Err(error.into());
            }
            let message = match read_viewer_until_expiry(
                socket,
                admission.expires_at_ms,
                self.inner.limits.idle_timeout,
            )
            .await
            {
                Ok(message) => message,
                Err(SessionReadError::Expired) => {
                    send_viewer_error(
                        socket,
                        RelayErrorCode::CredentialExpired,
                        "viewer credential expired",
                    )
                    .await?;
                    anyhow::bail!("viewer credential expired");
                }
                Err(SessionReadError::Idle) => anyhow::bail!("viewer session idle timeout"),
                Err(SessionReadError::Protocol(error)) => return Err(error),
            };
            message
                .validate_wire()
                .context("validating viewer message")?;
            match message {
                ViewerMessage::Hello(_) => anyhow::bail!("duplicate viewer hello"),
                ViewerMessage::Catalog => {
                    let catalog = self.catalog().await?;
                    write_viewer(socket, &RelayViewerMessage::Catalog(catalog)).await?;
                }
                ViewerMessage::Subscribe {
                    publisher_id,
                    stream_id,
                    start,
                } => {
                    self.subscription(
                        socket,
                        hello.identity.id()?,
                        publisher_id,
                        stream_id,
                        start,
                        admission,
                    )
                    .await?;
                    return Ok(());
                }
                ViewerMessage::Ping { .. } => {
                    write_viewer(
                        socket,
                        &RelayViewerMessage::Pong {
                            now_ms: glacialcast_protocol::now_ms(),
                        },
                    )
                    .await?;
                }
                ViewerMessage::PairRequest(request) => {
                    if request.body.viewer != hello.identity {
                        anyhow::bail!("pair request viewer identity mismatch");
                    }
                    let requested_stream = request.body.stream_id;
                    let requested_publisher = request.body.publisher;
                    let descriptor = self
                        .store_call(move |store| store.descriptor(requested_stream))
                        .await?;
                    if descriptor
                        .as_ref()
                        .map(|descriptor| descriptor.body.publisher)
                        != Some(requested_publisher)
                    {
                        send_viewer_error(
                            socket,
                            RelayErrorCode::NotFound,
                            "requested stream is not published by that identity",
                        )
                        .await?;
                        continue;
                    }
                    let request_id = request.id()?;
                    self.pairing_call(move |store| {
                        store.enqueue_request(
                            request.as_ref(),
                            source_addr,
                            glacialcast_protocol::now_ms(),
                            PAIRING_REQUEST_LIFETIME_MS,
                        )
                    })
                    .await?;
                    write_viewer(socket, &RelayViewerMessage::PairingQueued { request_id }).await?;
                }
                ViewerMessage::PairConfirmation(confirmation) => {
                    if confirmation.body.viewer_id != hello.identity.id()? {
                        anyhow::bail!("pair confirmation viewer identity mismatch");
                    }
                    let request_id = confirmation.body.request_id;
                    self.pairing_call(move |store| {
                        store.store_confirmation(&confirmation, glacialcast_protocol::now_ms())
                    })
                    .await?;
                    write_viewer(socket, &RelayViewerMessage::PairingQueued { request_id }).await?;
                }
                ViewerMessage::FetchInbox => {
                    let identity = hello.identity;
                    let inbox = self
                        .pairing_call(move |store| {
                            store.viewer_inbox(&identity, glacialcast_protocol::now_ms())
                        })
                        .await?;
                    for offer in inbox.offers {
                        write_viewer(socket, &RelayViewerMessage::PairOffer(offer)).await?;
                    }
                    for decision in inbox.decisions {
                        write_viewer(socket, &RelayViewerMessage::PairDecision(decision)).await?;
                    }
                    let recipient_id = hello.identity.id()?;
                    let summaries = self.store_call(NativeStore::summaries).await?;
                    for (stream_id, _) in summaries {
                        let envelopes = self
                            .store_call(move |store| {
                                store.list_envelopes(stream_id, recipient_id, 4_096)
                            })
                            .await?;
                        for envelope in envelopes {
                            write_viewer(socket, &RelayViewerMessage::KeyEnvelope(envelope))
                                .await?;
                        }
                    }
                    write_viewer(socket, &RelayViewerMessage::InboxComplete).await?;
                }
                ViewerMessage::Reanchor { .. } => {
                    send_viewer_error(
                        socket,
                        RelayErrorCode::ProtocolViolation,
                        "re-anchor requires an active subscription",
                    )
                    .await?;
                }
            }
        }
    }

    async fn catalog(&self) -> Result<Vec<CatalogEntry>> {
        let summaries = self.store_call(NativeStore::summaries).await?;
        let online = self
            .inner
            .online_streams
            .read()
            .map_err(|_| anyhow::anyhow!("native online-stream lock poisoned"))?
            .clone();
        let mut catalog = Vec::with_capacity(summaries.len());
        for (stream_id, summary) in summaries {
            let descriptor = self
                .store_call(move |store| store.descriptor(stream_id))
                .await?
                .context("native summary lost its descriptor")?;
            catalog.push(CatalogEntry {
                descriptor,
                publisher_online: online.contains(&stream_id),
                retained: summary.retained.map(retained_wire),
            });
        }
        Ok(catalog)
    }

    async fn subscription<S>(
        &self,
        socket: &mut NoiseSocket<S>,
        recipient_id: [u8; IDENTITY_ID_LEN],
        publisher_id: [u8; IDENTITY_ID_LEN],
        stream_id: Uuid,
        start: SubscriptionStart,
        admission: NativeAdmission,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let expires_at_ms = admission.expires_at_ms;
        let descriptor = self
            .store_call(move |store| store.descriptor(stream_id))
            .await?
            .context("subscription stream not found")?;
        if descriptor.body.publisher.id()? != publisher_id {
            anyhow::bail!("subscription publisher identity mismatch");
        }
        let mut receiver = self.live_sender(stream_id)?.subscribe();
        let anchor = self
            .store_call(move |store| store.subscription_anchor(stream_id, start))
            .await?;
        let retained = self
            .store_call(move |store| store.retained_bounds(stream_id))
            .await?;
        let high_water = self
            .store_call(move |store| store.high_water(stream_id))
            .await?
            .unwrap_or(0);
        write_viewer(
            socket,
            &RelayViewerMessage::SubscriptionStarted {
                first_sequence: anchor,
                retained: retained.map(retained_wire),
                live: anchor > high_water,
            },
        )
        .await?;

        if anchor > high_water
            && high_water > 0
            && let Some(object) = self
                .store_call(move |store| store.get_object(stream_id, high_water))
                .await?
        {
            self.send_group_envelope(
                socket,
                stream_id,
                object.header.epoch_id,
                object.header.key_group,
                recipient_id,
            )
            .await?;
        }

        let mut last_sequence = anchor.saturating_sub(1);
        self.reanchor_from_store(socket, stream_id, recipient_id, &mut last_sequence)
            .await?;
        if last_sequence > 0 {
            write_viewer(
                socket,
                &RelayViewerMessage::Live {
                    through_sequence: last_sequence,
                },
            )
            .await?;
        }

        let mut last_live_activity = tokio::time::Instant::now();
        loop {
            if expires_at_ms.is_some_and(|expiry| glacialcast_protocol::now_ms() >= expiry) {
                send_viewer_error(
                    socket,
                    RelayErrorCode::CredentialExpired,
                    "viewer credential expired",
                )
                .await?;
                anyhow::bail!("viewer credential expired");
            }
            if let Err(error) = self
                .inner
                .access
                .ensure_active(admission, glacialcast_protocol::now_ms())
            {
                send_viewer_error(
                    socket,
                    active_credential_error_code(admission),
                    "viewer credential is no longer valid",
                )
                .await?;
                return Err(error.into());
            }
            let idle_remaining = self
                .inner
                .limits
                .idle_timeout
                .saturating_sub(last_live_activity.elapsed());
            if idle_remaining.is_zero() {
                anyhow::bail!("viewer subscription idle timeout");
            }
            let policy_tick = Duration::from_secs(1).min(idle_remaining);
            let received = match tokio::time::timeout(policy_tick, receiver.recv()).await {
                Ok(received) => received,
                Err(_) => continue,
            };
            last_live_activity = tokio::time::Instant::now();
            match received {
                Ok(LiveItem::Envelope(envelope)) => {
                    if envelope.header.recipient_id == recipient_id {
                        write_viewer(socket, &RelayViewerMessage::KeyEnvelope(envelope)).await?;
                    }
                }
                Ok(LiveItem::Object(object)) if object.header.sequence <= last_sequence => {}
                Ok(LiveItem::Object(object))
                    if object.header.sequence == last_sequence.saturating_add(1) =>
                {
                    last_sequence = object.header.sequence;
                    write_viewer(socket, &RelayViewerMessage::Object(object)).await?;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    let before = last_sequence;
                    self.reanchor_from_store(socket, stream_id, recipient_id, &mut last_sequence)
                        .await?;
                    if last_sequence == before {
                        send_viewer_error(
                            socket,
                            RelayErrorCode::HistoryUnavailable,
                            "live subscription gap is no longer retained",
                        )
                        .await?;
                        anyhow::bail!("live subscription gap could not be re-anchored");
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    anyhow::bail!("native live stream channel closed");
                }
            }
        }
    }

    async fn reanchor_from_store<S>(
        &self,
        socket: &mut NoiseSocket<S>,
        stream_id: Uuid,
        recipient_id: [u8; IDENTITY_ID_LEN],
        last_sequence: &mut u64,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let after = *last_sequence;
            let objects = self
                .store_call(move |store| store.list_objects(stream_id, after, SUBSCRIPTION_PAGE))
                .await?;
            if objects.is_empty() {
                return Ok(());
            }
            let count = objects.len();
            let mut delivered_group = None;
            for object in objects {
                if object.header.sequence != last_sequence.saturating_add(1) {
                    anyhow::bail!("retained native stream contains a sequence gap");
                }
                let group = (object.header.epoch_id, object.header.key_group);
                if delivered_group != Some(group) {
                    self.send_group_envelope(socket, stream_id, group.0, group.1, recipient_id)
                        .await?;
                    delivered_group = Some(group);
                }
                *last_sequence = object.header.sequence;
                write_viewer(socket, &RelayViewerMessage::Object(object)).await?;
            }
            if count < SUBSCRIPTION_PAGE {
                return Ok(());
            }
        }
    }

    async fn send_group_envelope<S>(
        &self,
        socket: &mut NoiseSocket<S>,
        stream_id: Uuid,
        epoch_id: Uuid,
        key_group: u64,
        recipient_id: [u8; IDENTITY_ID_LEN],
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let envelope = self
            .store_call(move |store| {
                store.get_envelope(stream_id, epoch_id, key_group, recipient_id)
            })
            .await?;
        if let Some(envelope) = envelope {
            write_viewer(socket, &RelayViewerMessage::KeyEnvelope(envelope)).await?;
        }
        Ok(())
    }

    async fn validate_resume_stream(
        &self,
        publisher: &IdentityPublic,
        stream: &PublisherResumeStream,
    ) -> Result<()> {
        if let Some(descriptor) = self
            .store_call({
                let stream_id = stream.stream_id;
                move |store| store.descriptor(stream_id)
            })
            .await?
        {
            require_publisher(&descriptor.body.publisher, publisher)?;
        }
        Ok(())
    }

    fn claim_online(&self, stream_id: Uuid, touched_streams: &mut HashSet<Uuid>) -> Result<()> {
        if touched_streams.contains(&stream_id) {
            return Ok(());
        }
        let inserted = self
            .inner
            .online_streams
            .write()
            .map_err(|_| anyhow::anyhow!("native online-stream lock poisoned"))?
            .insert(stream_id);
        if !inserted {
            anyhow::bail!("stream already has an active publisher session");
        }
        touched_streams.insert(stream_id);
        Ok(())
    }

    fn live_sender(&self, stream_id: Uuid) -> Result<broadcast::Sender<LiveItem>> {
        let mut senders = self
            .inner
            .live
            .lock()
            .map_err(|_| anyhow::anyhow!("native live-channel lock poisoned"))?;
        Ok(senders
            .entry(stream_id)
            .or_insert_with(|| broadcast::channel(self.inner.limits.live_channel_capacity).0)
            .clone())
    }

    async fn store_call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&NativeStore) -> Result<T> + Send + 'static,
    {
        let store = self.inner.store.clone();
        tokio::task::spawn_blocking(move || operation(&store))
            .await
            .context("native store worker panicked")?
    }

    async fn pairing_call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&PairingStore) -> Result<T> + Send + 'static,
    {
        let store = self.inner.pairing.clone();
        tokio::task::spawn_blocking(move || operation(&store))
            .await
            .context("pairing store worker panicked")?
    }

    /// Accepts publisher TCP connections until the watch value becomes true.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting from the listener fails.
    pub async fn serve_publishers(
        &self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        self.serve_listener(
            listener,
            &mut shutdown,
            |service, stream, _peer| async move { service.handle_publisher(stream).await },
        )
        .await
    }

    /// Accepts viewer TCP connections until the watch value becomes true.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting from the listener fails.
    pub async fn serve_viewers(
        &self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        self.serve_listener(
            listener,
            &mut shutdown,
            |service, stream, peer| async move { service.handle_viewer_from(stream, peer).await },
        )
        .await
    }

    async fn serve_listener<F, Fut>(
        &self,
        listener: TcpListener,
        shutdown: &mut watch::Receiver<bool>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Self, TcpStream, SocketAddr) -> Fut + Copy + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.context("accepting native relay connection")?;
                    let Ok(permit) = self.inner.connections.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "native relay connection limit reached");
                        drop(stream);
                        continue;
                    };
                    let service = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handler(service, stream, peer).await {
                            tracing::warn!(?error, %peer, "native relay connection ended with error");
                        }
                    });
                }
            }
        }
    }
}

fn welcome(admission: NativeAdmission) -> RelayWelcome {
    RelayWelcome {
        protocol_version: glacialcast_protocol::PROTOCOL_VERSION,
        access_mode: admission.mode,
        relay_time_ms: glacialcast_protocol::now_ms(),
        credential_expires_at_ms: admission.expires_at_ms,
    }
}

fn active_credential_error_code(admission: NativeAdmission) -> RelayErrorCode {
    if admission
        .expires_at_ms
        .is_some_and(|expiry| glacialcast_protocol::now_ms() >= expiry)
    {
        RelayErrorCode::CredentialExpired
    } else {
        RelayErrorCode::Unauthorized
    }
}

fn retained_wire(bounds: NativeRetainedBounds) -> RetainedBounds {
    RetainedBounds {
        oldest_sequence: bounds.oldest_sequence,
        newest_sequence: bounds.newest_sequence,
        oldest_timestamp: bounds.oldest_timestamp,
        newest_timestamp: bounds.newest_timestamp,
    }
}

fn require_publisher(actual: &IdentityPublic, expected: &IdentityPublic) -> Result<()> {
    if actual != expected {
        anyhow::bail!("publisher application identity mismatch");
    }
    Ok(())
}

async fn write_publisher<S>(
    socket: &mut NoiseSocket<S>,
    message: &RelayPublisherMessage,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    message.validate_wire()?;
    socket
        .write(message)
        .await
        .context("writing publisher reply")
}

async fn write_viewer<S>(socket: &mut NoiseSocket<S>, message: &RelayViewerMessage) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    message.validate_wire()?;
    socket.write(message).await.context("writing viewer reply")
}

async fn send_publisher_error<S>(
    socket: &mut NoiseSocket<S>,
    code: RelayErrorCode,
    detail: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_publisher(
        socket,
        &RelayPublisherMessage::Error(RelayError {
            code,
            detail: detail.to_string(),
        }),
    )
    .await
}

async fn send_viewer_error<S>(
    socket: &mut NoiseSocket<S>,
    code: RelayErrorCode,
    detail: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_viewer(
        socket,
        &RelayViewerMessage::Error(RelayError {
            code,
            detail: detail.to_string(),
        }),
    )
    .await
}

enum SessionReadError {
    Expired,
    Idle,
    Protocol(anyhow::Error),
}

async fn read_publisher_until_expiry<S>(
    socket: &mut NoiseSocket<S>,
    expires_at_ms: Option<i64>,
    idle_timeout: Duration,
) -> std::result::Result<PublisherMessage, SessionReadError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_until_expiry(
        socket.read::<PublisherMessage>(),
        expires_at_ms,
        idle_timeout,
    )
    .await
}

async fn read_viewer_until_expiry<S>(
    socket: &mut NoiseSocket<S>,
    expires_at_ms: Option<i64>,
    idle_timeout: Duration,
) -> std::result::Result<ViewerMessage, SessionReadError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_until_expiry(socket.read::<ViewerMessage>(), expires_at_ms, idle_timeout).await
}

async fn read_until_expiry<T, F>(
    read: F,
    expires_at_ms: Option<i64>,
    idle_timeout: Duration,
) -> std::result::Result<T, SessionReadError>
where
    F: Future<Output = glacialcast_protocol::Result<T>>,
{
    match expires_at_ms {
        None => match tokio::time::timeout(idle_timeout, read).await {
            Ok(result) => result.map_err(|error| SessionReadError::Protocol(error.into())),
            Err(_) => Err(SessionReadError::Idle),
        },
        Some(expiry) => {
            let remaining_ms = expiry.saturating_sub(glacialcast_protocol::now_ms());
            let Ok(remaining_ms) = u64::try_from(remaining_ms) else {
                return Err(SessionReadError::Expired);
            };
            let remaining = Duration::from_millis(remaining_ms);
            let timeout = remaining.min(idle_timeout);
            match tokio::time::timeout(timeout, read).await {
                Ok(result) => result.map_err(|error| SessionReadError::Protocol(error.into())),
                Err(_) if remaining <= idle_timeout => Err(SessionReadError::Expired),
                Err(_) => Err(SessionReadError::Idle),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_protocol::{
        credential::CertificateAuthoritySecret,
        envelope::KeyEnvelope,
        generate_noise_keypair,
        identity::IdentitySecret,
        initiator_handshake_xx,
        native::{
            CodecId, ContentKey, GroupEncryptor, H264EpochPayload, NativeObjectKind,
            NewNativeObject, StreamDescriptor,
        },
        pairing::{PairOffer, PairRequest, PublisherDecision, ViewerConfirmation},
        wire::RelayAccessMode,
    };

    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("glacialcast-native-service-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn service_limits_reject_zero_and_idle_reads_time_out() {
        let root = root();
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        let limits = NativeServiceLimits {
            max_connections: 0,
            ..NativeServiceLimits::default()
        };
        assert!(
            NativeRelayService::new_with_limits(
                store,
                NativeAccessPolicy::Public,
                generate_noise_keypair().unwrap(),
                limits,
            )
            .is_err()
        );
        let result = read_until_expiry(
            std::future::pending::<glacialcast_protocol::Result<()>>(),
            None,
            Duration::from_millis(1),
        )
        .await;
        assert!(matches!(result, Err(SessionReadError::Idle)));
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn viewer_socket(
        service: NativeRelayService,
        identity: IdentityPublic,
        noise: NoiseKeypair,
    ) -> NoiseSocket<tokio::io::DuplexStream> {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let expected = service.noise_public_key();
        tokio::spawn(async move {
            let _ = service.handle_viewer(server).await;
        });
        let (transport, _) = initiator_handshake_xx(&mut client, &noise.private, |actual| {
            if actual == &expected {
                Ok(())
            } else {
                Err(glacialcast_protocol::ProtocolError::Noise(
                    "unexpected relay".into(),
                ))
            }
        })
        .await
        .unwrap();
        let mut socket = NoiseSocket::new(client, transport);
        socket
            .write(&ViewerMessage::Hello(SessionHello {
                protocol_version: glacialcast_protocol::PROTOCOL_VERSION,
                role: CredentialRole::Viewer,
                identity,
                credential: None,
            }))
            .await
            .unwrap();
        assert!(matches!(
            socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Welcome(RelayWelcome {
                access_mode: RelayAccessMode::Public,
                ..
            })
        ));
        socket
    }

    async fn publisher_socket(
        service: NativeRelayService,
        identity: IdentityPublic,
        noise: NoiseKeypair,
    ) -> NoiseSocket<tokio::io::DuplexStream> {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let expected = service.noise_public_key();
        tokio::spawn(async move {
            let _ = service.handle_publisher(server).await;
        });
        let (transport, _) = initiator_handshake_xx(&mut client, &noise.private, |actual| {
            if actual == &expected {
                Ok(())
            } else {
                Err(glacialcast_protocol::ProtocolError::Noise(
                    "unexpected relay".into(),
                ))
            }
        })
        .await
        .unwrap();
        let mut socket = NoiseSocket::new(client, transport);
        socket
            .write(&PublisherMessage::Hello(SessionHello {
                protocol_version: glacialcast_protocol::PROTOCOL_VERSION,
                role: CredentialRole::Publisher,
                identity,
                credential: None,
            }))
            .await
            .unwrap();
        assert!(matches!(
            socket.read::<RelayPublisherMessage>().await.unwrap(),
            RelayPublisherMessage::Welcome(RelayWelcome {
                access_mode: RelayAccessMode::Public,
                ..
            })
        ));
        socket
    }

    #[tokio::test]
    async fn public_relay_publishes_catalog_and_gapless_retained_subscription() {
        let root = root();
        let store = NativeStore::open(root.clone(), Some(10_000_000), None).unwrap();
        let relay_noise = generate_noise_keypair().unwrap();
        let service =
            NativeRelayService::new(store, NativeAccessPolicy::Public, relay_noise).unwrap();
        let publisher = IdentitySecret::generate();
        let publisher_noise = generate_noise_keypair().unwrap();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();

        let (mut publisher_client, publisher_server) = tokio::io::duplex(1024 * 1024);
        let publisher_service = service.clone();
        tokio::spawn(async move {
            let _ = publisher_service.handle_publisher(publisher_server).await;
        });
        let expected = service.noise_public_key();
        let (transport, _) =
            initiator_handshake_xx(&mut publisher_client, &publisher_noise.private, |actual| {
                if actual == &expected {
                    Ok(())
                } else {
                    Err(glacialcast_protocol::ProtocolError::Noise(
                        "unexpected relay".into(),
                    ))
                }
            })
            .await
            .unwrap();
        let mut publisher_socket = NoiseSocket::new(publisher_client, transport);
        publisher_socket
            .write(&PublisherMessage::Hello(SessionHello {
                protocol_version: glacialcast_protocol::PROTOCOL_VERSION,
                role: CredentialRole::Publisher,
                identity: publisher.public().unwrap(),
                credential: None,
            }))
            .await
            .unwrap();
        assert!(matches!(
            publisher_socket
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::Welcome(_)
        ));
        let descriptor = StreamDescriptor::new(
            &publisher,
            stream_id,
            "screen".into(),
            "DP-1".into(),
            true,
            1,
        )
        .unwrap();
        publisher_socket
            .write(&PublisherMessage::Descriptor(descriptor.clone()))
            .await
            .unwrap();

        let mut first =
            GroupEncryptor::generate(&publisher.public().unwrap(), stream_id, epoch_id, 1, 0)
                .unwrap();
        let object_one = first
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 1,
                    timestamp: 0,
                    duration: 3_000,
                    kind: NativeObjectKind::Media,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &[0, 0, 1, 0x65],
            )
            .unwrap();
        publisher_socket
            .write(&PublisherMessage::Object(object_one.clone()))
            .await
            .unwrap();
        assert!(matches!(
            publisher_socket
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PublishAck {
                committed_through: 1,
                ..
            }
        ));
        let mut second =
            GroupEncryptor::generate(&publisher.public().unwrap(), stream_id, epoch_id, 2, 1)
                .unwrap();
        let object_two = second
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 2,
                    timestamp: 3_000,
                    duration: 3_000,
                    kind: NativeObjectKind::Media,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &[0, 0, 1, 0x65, 2],
            )
            .unwrap();
        publisher_socket
            .write(&PublisherMessage::Object(object_two.clone()))
            .await
            .unwrap();
        publisher_socket
            .read::<RelayPublisherMessage>()
            .await
            .unwrap();

        let viewer = IdentitySecret::generate();
        let viewer_noise = generate_noise_keypair().unwrap();
        let mut viewer_socket =
            viewer_socket(service.clone(), viewer.public().unwrap(), viewer_noise).await;
        viewer_socket.write(&ViewerMessage::Catalog).await.unwrap();
        let RelayViewerMessage::Catalog(catalog) =
            viewer_socket.read::<RelayViewerMessage>().await.unwrap()
        else {
            panic!("expected catalog");
        };
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].descriptor, descriptor);
        assert!(catalog[0].publisher_online);

        viewer_socket
            .write(&ViewerMessage::Subscribe {
                publisher_id: publisher.public().unwrap().id().unwrap(),
                stream_id,
                start: SubscriptionStart::OldestRetained,
            })
            .await
            .unwrap();
        assert!(matches!(
            viewer_socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::SubscriptionStarted {
                first_sequence: 1,
                ..
            }
        ));
        assert_eq!(
            viewer_socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Object(object_one)
        );
        assert_eq!(
            viewer_socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Object(object_two)
        );
        assert!(matches!(
            viewer_socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Live {
                through_sequence: 2
            }
        ));
        drop(publisher_socket);
        drop(viewer_socket);
        tokio::time::sleep(Duration::from_millis(20)).await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn signed_relay_rejects_before_exposing_catalog() {
        let root = root();
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        let authority = CertificateAuthoritySecret::generate();
        let service = NativeRelayService::new(
            store,
            NativeAccessPolicy::Signed {
                authority: authority.public(),
                revocations: std::sync::Arc::new(std::sync::RwLock::new(None)),
            },
            generate_noise_keypair().unwrap(),
        )
        .unwrap();
        let viewer = IdentitySecret::generate();
        let viewer_noise = generate_noise_keypair().unwrap();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let expected = service.noise_public_key();
        let server_service = service.clone();
        tokio::spawn(async move {
            let _ = server_service.handle_viewer(server).await;
        });
        let (transport, _) = initiator_handshake_xx(&mut client, &viewer_noise.private, |actual| {
            if actual == &expected {
                Ok(())
            } else {
                Err(glacialcast_protocol::ProtocolError::Noise(
                    "unexpected relay".into(),
                ))
            }
        })
        .await
        .unwrap();
        let mut socket = NoiseSocket::new(client, transport);
        socket
            .write(&ViewerMessage::Hello(SessionHello {
                protocol_version: glacialcast_protocol::PROTOCOL_VERSION,
                role: CredentialRole::Viewer,
                identity: viewer.public().unwrap(),
                credential: None,
            }))
            .await
            .unwrap();
        assert!(matches!(
            socket.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Error(RelayError {
                code: RelayErrorCode::Unauthorized,
                ..
            })
        ));
        let _ = socket.write(&ViewerMessage::Catalog).await;
        assert!(socket.read::<RelayViewerMessage>().await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn pairing_request_offer_confirmation_and_decision_queue_while_offline() {
        let root = root();
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let now = glacialcast_protocol::now_ms();
        let stream_id = Uuid::from_u128(1);
        let store = NativeStore::open(root.clone(), None, None).unwrap();
        store
            .put_descriptor(
                &StreamDescriptor::new(
                    &publisher,
                    stream_id,
                    "end-to-end".into(),
                    "test".into(),
                    false,
                    now,
                )
                .unwrap(),
            )
            .unwrap();
        let service = NativeRelayService::new(
            store,
            NativeAccessPolicy::Public,
            generate_noise_keypair().unwrap(),
        )
        .unwrap();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            stream_id,
            "viewer".into(),
            now,
            now + PAIRING_REQUEST_LIFETIME_MS,
        )
        .unwrap();
        let request_id = request.id().unwrap();

        let mut viewer_connection = viewer_socket(
            service.clone(),
            viewer.public().unwrap(),
            generate_noise_keypair().unwrap(),
        )
        .await;
        let unknown_stream_request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            Uuid::from_u128(2),
            "viewer".into(),
            now,
            now + PAIRING_REQUEST_LIFETIME_MS,
        )
        .unwrap();
        viewer_connection
            .write(&ViewerMessage::PairRequest(Box::new(
                unknown_stream_request,
            )))
            .await
            .unwrap();
        assert!(matches!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::Error(RelayError {
                code: RelayErrorCode::NotFound,
                ..
            })
        ));
        viewer_connection
            .write(&ViewerMessage::PairRequest(Box::new(request.clone())))
            .await
            .unwrap();
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairingQueued { request_id }
        );
        drop(viewer_connection);

        let mut publisher_connection = publisher_socket(
            service.clone(),
            publisher.public().unwrap(),
            generate_noise_keypair().unwrap(),
        )
        .await;
        publisher_connection
            .write(&PublisherMessage::FetchPairingInbox)
            .await
            .unwrap();
        let RelayPublisherMessage::PairRequest {
            request: delivered, ..
        } = publisher_connection
            .read::<RelayPublisherMessage>()
            .await
            .unwrap()
        else {
            panic!("expected queued pair request");
        };
        assert_eq!(*delivered, request);
        assert_eq!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PairingInboxComplete
        );
        let offer = PairOffer::new(
            &publisher,
            &request,
            [7; 32],
            now + 1,
            now + PAIRING_REQUEST_LIFETIME_MS,
            PAIRING_REQUEST_LIFETIME_MS,
        )
        .unwrap();
        publisher_connection
            .write(&PublisherMessage::PairOffer(offer.clone()))
            .await
            .unwrap();
        assert_eq!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PairingAck { request_id }
        );
        drop(publisher_connection);

        let mut viewer_connection = viewer_socket(
            service.clone(),
            viewer.public().unwrap(),
            generate_noise_keypair().unwrap(),
        )
        .await;
        viewer_connection
            .write(&ViewerMessage::FetchInbox)
            .await
            .unwrap();
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairOffer(offer.clone())
        );
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::InboxComplete
        );
        let confirmation = ViewerConfirmation::approve(&viewer, &request, &offer, now + 2).unwrap();
        viewer_connection
            .write(&ViewerMessage::PairConfirmation(confirmation.clone()))
            .await
            .unwrap();
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairingQueued { request_id }
        );

        let mut publisher_connection = publisher_socket(
            service.clone(),
            publisher.public().unwrap(),
            generate_noise_keypair().unwrap(),
        )
        .await;
        publisher_connection
            .write(&PublisherMessage::FetchPairingInbox)
            .await
            .unwrap();
        assert!(matches!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PairRequest { .. }
        ));
        assert_eq!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::ViewerConfirmation(confirmation.clone())
        );
        assert_eq!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PairingInboxComplete
        );
        let decision =
            PublisherDecision::approve_manual(&publisher, &request, &offer, &confirmation, now + 3)
                .unwrap();
        publisher_connection
            .write(&PublisherMessage::PairDecision(decision.clone()))
            .await
            .unwrap();
        assert_eq!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PairingAck { request_id }
        );

        viewer_connection
            .write(&ViewerMessage::FetchInbox)
            .await
            .unwrap();
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairOffer(offer)
        );
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairDecision(decision)
        );
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::InboxComplete
        );

        let epoch_id = Uuid::new_v4();
        let descriptor = StreamDescriptor::new(
            &publisher,
            stream_id,
            "end-to-end".into(),
            "test".into(),
            false,
            now,
        )
        .unwrap();
        publisher_connection
            .write(&PublisherMessage::Descriptor(descriptor))
            .await
            .unwrap();
        let mut first_group =
            GroupEncryptor::generate(&publisher.public().unwrap(), stream_id, epoch_id, 1, 0)
                .unwrap();
        let epoch_payload = H264EpochPayload {
            width: 16,
            height: 16,
            codec_config: vec![0, 0, 0, 1, 0x67, 1],
        }
        .encode()
        .unwrap();
        let epoch_object = first_group
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 1,
                    timestamp: 0,
                    duration: 1,
                    kind: NativeObjectKind::Epoch,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &epoch_payload,
            )
            .unwrap();
        let media_plaintext = vec![0, 0, 0, 1, 0x65, 9, 8, 7];
        let media_object = first_group
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 2,
                    timestamp: 0,
                    duration: 45_000,
                    kind: NativeObjectKind::Media,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &media_plaintext,
            )
            .unwrap();
        let mut second_group =
            GroupEncryptor::generate(&publisher.public().unwrap(), stream_id, epoch_id, 2, 2)
                .unwrap();
        let second_epoch = second_group
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 3,
                    timestamp: 45_000,
                    duration: 1,
                    kind: NativeObjectKind::Epoch,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &epoch_payload,
            )
            .unwrap();
        for object in [epoch_object.clone(), media_object.clone(), second_epoch] {
            let sequence = object.header.sequence;
            publisher_connection
                .write(&PublisherMessage::Object(object))
                .await
                .unwrap();
            assert!(matches!(
                publisher_connection
                    .read::<RelayPublisherMessage>()
                    .await
                    .unwrap(),
                RelayPublisherMessage::PublishAck { committed_through, .. }
                    if committed_through == sequence
            ));
        }
        let first_envelope = KeyEnvelope::seal(
            &publisher,
            &viewer.public().unwrap(),
            stream_id,
            epoch_id,
            1,
            first_group.key_id(),
            &first_group.content_key(),
        )
        .unwrap();
        publisher_connection
            .write(&PublisherMessage::KeyEnvelope(first_envelope.clone()))
            .await
            .unwrap();
        publisher_connection
            .write(&PublisherMessage::Ping { now_ms: now })
            .await
            .unwrap();
        assert!(matches!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::Pong { .. }
        ));

        viewer_connection
            .write(&ViewerMessage::FetchInbox)
            .await
            .unwrap();
        assert!(matches!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairOffer(_)
        ));
        assert!(matches!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::PairDecision(_)
        ));
        let RelayViewerMessage::KeyEnvelope(delivered_envelope) = viewer_connection
            .read::<RelayViewerMessage>()
            .await
            .unwrap()
        else {
            panic!("expected viewer key envelope");
        };
        assert_eq!(delivered_envelope, first_envelope);
        let content_key = delivered_envelope
            .open(&viewer, &publisher.public().unwrap())
            .unwrap();
        assert_eq!(content_key, first_group.content_key());
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::InboxComplete
        );
        viewer_connection
            .write(&ViewerMessage::Subscribe {
                publisher_id: publisher.public().unwrap().id().unwrap(),
                stream_id,
                start: SubscriptionStart::OldestRetained,
            })
            .await
            .unwrap();
        assert!(matches!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::SubscriptionStarted {
                first_sequence: 1,
                ..
            }
        ));
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::KeyEnvelope(first_envelope)
        );
        let RelayViewerMessage::Object(delivered_epoch) = viewer_connection
            .read::<RelayViewerMessage>()
            .await
            .unwrap()
        else {
            panic!("expected retained epoch");
        };
        assert_eq!(
            delivered_epoch
                .open(
                    &publisher.public().unwrap(),
                    &ContentKey::from_bytes(content_key).unwrap(),
                    &first_group.key_id(),
                )
                .unwrap(),
            epoch_payload
        );
        let RelayViewerMessage::Object(delivered_media) = viewer_connection
            .read::<RelayViewerMessage>()
            .await
            .unwrap()
        else {
            panic!("expected retained media");
        };
        assert_eq!(
            delivered_media
                .open(
                    &publisher.public().unwrap(),
                    &ContentKey::from_bytes(content_key).unwrap(),
                    &first_group.key_id(),
                )
                .unwrap(),
            media_plaintext
        );
        assert!(matches!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::Object(object) if object.header.sequence == 3
        ));
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::Live {
                through_sequence: 3
            }
        );

        let second_envelope = KeyEnvelope::seal(
            &publisher,
            &viewer.public().unwrap(),
            stream_id,
            epoch_id,
            2,
            second_group.key_id(),
            &second_group.content_key(),
        )
        .unwrap();
        publisher_connection
            .write(&PublisherMessage::KeyEnvelope(second_envelope.clone()))
            .await
            .unwrap();
        assert_eq!(
            viewer_connection
                .read::<RelayViewerMessage>()
                .await
                .unwrap(),
            RelayViewerMessage::KeyEnvelope(second_envelope.clone())
        );
        let second_media_plaintext = vec![0, 0, 0, 1, 0x65, 6, 5, 4];
        let second_media = second_group
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 4,
                    timestamp: 45_000,
                    duration: 45_000,
                    kind: NativeObjectKind::Media,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &second_media_plaintext,
            )
            .unwrap();
        publisher_connection
            .write(&PublisherMessage::Object(second_media))
            .await
            .unwrap();
        assert!(matches!(
            publisher_connection
                .read::<RelayPublisherMessage>()
                .await
                .unwrap(),
            RelayPublisherMessage::PublishAck {
                committed_through: 4,
                ..
            }
        ));
        let RelayViewerMessage::Object(delivered_second_media) = viewer_connection
            .read::<RelayViewerMessage>()
            .await
            .unwrap()
        else {
            panic!("expected live media after rotated envelope");
        };
        assert_eq!(
            delivered_second_media
                .open(
                    &publisher.public().unwrap(),
                    &ContentKey::from_bytes(second_group.content_key()).unwrap(),
                    &second_group.key_id(),
                )
                .unwrap(),
            second_media_plaintext
        );
        let mut live_joiner = viewer_socket(
            service.clone(),
            viewer.public().unwrap(),
            generate_noise_keypair().unwrap(),
        )
        .await;
        live_joiner
            .write(&ViewerMessage::Subscribe {
                publisher_id: publisher.public().unwrap().id().unwrap(),
                stream_id,
                start: SubscriptionStart::Live,
            })
            .await
            .unwrap();
        // A live join anchors at the current group's start — its epoch and
        // keyframe — so the joiner can decode immediately instead of waiting
        // blind for the next rotation. The group envelope precedes the
        // replayed objects, and the live marker closes the replay.
        assert!(matches!(
            live_joiner.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::SubscriptionStarted {
                first_sequence: 3,
                live: false,
                ..
            }
        ));
        assert_eq!(
            live_joiner.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::KeyEnvelope(second_envelope)
        );
        assert!(matches!(
            live_joiner.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Object(object) if object.header.sequence == 3
        ));
        assert!(matches!(
            live_joiner.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Object(object) if object.header.sequence == 4
        ));
        assert_eq!(
            live_joiner.read::<RelayViewerMessage>().await.unwrap(),
            RelayViewerMessage::Live {
                through_sequence: 4
            }
        );
        drop(live_joiner);
        drop(viewer_connection);
        drop(publisher_connection);
        tokio::time::sleep(Duration::from_millis(20)).await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
