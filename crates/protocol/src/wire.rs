//! Bounded protocol-v8 messages exchanged over native Noise transports.

use crate::{
    MAX_FRAME_LEN, PROTOCOL_VERSION,
    credential::{
        CREDENTIAL_VERSION, CredentialRole, MAX_CREDENTIAL_SUBJECT_LEN, NativeCredential,
    },
    envelope::KeyEnvelope,
    identity::{IDENTITY_ID_LEN, IdentityPublic},
    native::{NativeObject, StreamDescriptor},
    pairing::{PAIRING_VERSION, PairOffer, PairRequest, PublisherDecision, ViewerConfirmation},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;
use uuid::Uuid;

/// Maximum streams represented in one catalog, resume, or status message.
pub const MAX_STREAMS_PER_MESSAGE: usize = 4_096;
/// Maximum UTF-8 detail attached to a stable relay error code.
pub const MAX_ERROR_DETAIL_LEN: usize = 512;

/// Errors produced by bounded native wire-message parsing and validation.
#[derive(Debug, Error)]
pub enum WireError {
    /// A message used a protocol version other than v8.
    #[error("unsupported native protocol version {0}")]
    UnsupportedVersion(u16),
    /// A message exceeded [`MAX_FRAME_LEN`].
    #[error("native wire message exceeds its bound")]
    TooLarge,
    /// A message field or variant violated the named invariant.
    #[error("invalid native wire message: {0}")]
    Invalid(&'static str),
    /// Canonical Postcard encoding or decoding failed.
    #[error("native wire serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Admission policy announced after the relay accepts a Noise connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayAccessMode {
    /// Any Noise peer may enumerate metadata and use native relay services.
    Public,
    /// A valid role credential is required and the catalog otherwise stays hidden.
    Signed,
}

/// First application message sent by a publisher or viewer after Noise XX.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionHello {
    /// Required native protocol version.
    pub protocol_version: u16,
    /// Endpoint role requested by this connection.
    pub role: CredentialRole,
    /// Persistent application identity for public admission or credential binding.
    pub identity: IdentityPublic,
    /// Native relay-access credential; optional only when relay policy is public.
    pub credential: Option<NativeCredential>,
}

impl SessionHello {
    fn validate(&self, expected_role: CredentialRole) -> Result<(), WireError> {
        check_version(self.protocol_version)?;
        if self.role != expected_role {
            return Err(WireError::Invalid("session hello has the wrong role"));
        }
        self.identity
            .validate()
            .map_err(|_| WireError::Invalid("invalid session identity"))?;
        if let Some(credential) = &self.credential
            && (credential.body.role != expected_role || credential.body.identity != self.identity)
        {
            return Err(WireError::Invalid(
                "credential role or identity differs from session",
            ));
        }
        if let Some(credential) = &self.credential
            && (credential.body.version != CREDENTIAL_VERSION
                || credential.body.subject.is_empty()
                || credential.body.subject.len() > MAX_CREDENTIAL_SUBJECT_LEN
                || credential.body.subject.trim() != credential.body.subject
                || credential.body.subject.chars().any(char::is_control))
        {
            return Err(WireError::Invalid("invalid credential metadata"));
        }
        Ok(())
    }
}

/// Relay response after admission and role validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayWelcome {
    /// Negotiated protocol version.
    pub protocol_version: u16,
    /// Relay admission policy in effect.
    pub access_mode: RelayAccessMode,
    /// Relay wall clock as Unix milliseconds.
    pub relay_time_ms: i64,
    /// Credential expiry for this session, if admitted by a signed credential.
    pub credential_expires_at_ms: Option<i64>,
}

/// Publisher resume information for one stream after reconnect or restart.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherResumeStream {
    /// Stable stream identifier.
    pub stream_id: Uuid,
    /// Publisher's next sequence number.
    pub next_sequence: u64,
    /// Current epoch identifier.
    pub epoch_id: Uuid,
    /// Current or next keyframe-group number.
    pub key_group: u64,
}

/// Relay high-water mark returned for one publisher stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayResumeStream {
    /// Stable stream identifier.
    pub stream_id: Uuid,
    /// Highest durably committed sequence, or zero for a new stream.
    pub committed_through: u64,
}

/// Publisher-to-relay application messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublisherMessage {
    /// Required first message on a publisher connection.
    Hello(SessionHello),
    /// Reconcile durable high-water marks before sending objects.
    Resume {
        /// Publisher identity fingerprint.
        publisher_id: [u8; IDENTITY_ID_LEN],
        /// Bounded publisher stream states.
        streams: Vec<PublisherResumeStream>,
    },
    /// Publish or replace the signed descriptor for one stream.
    Descriptor(StreamDescriptor),
    /// Publish one signed encrypted stream object.
    Object(NativeObject),
    /// Publish one viewer-addressed group key envelope.
    KeyEnvelope(KeyEnvelope),
    /// Deliver a publisher offer in response to a pending request.
    PairOffer(PairOffer),
    /// Deliver the publisher's final signed pairing decision.
    PairDecision(PublisherDecision),
    /// Keepalive carrying sender wall clock.
    Ping {
        /// Unix milliseconds.
        now_ms: i64,
    },
}

impl PublisherMessage {
    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Hello(hello) => hello.validate(CredentialRole::Publisher),
            Self::Resume {
                publisher_id,
                streams,
            } => {
                if *publisher_id == [0; IDENTITY_ID_LEN]
                    || streams.len() > MAX_STREAMS_PER_MESSAGE
                    || streams.iter().any(|stream| {
                        stream.stream_id.is_nil()
                            || stream.next_sequence == 0
                            || stream.epoch_id.is_nil()
                            || stream.key_group == 0
                    })
                {
                    return Err(WireError::Invalid("invalid publisher resume state"));
                }
                sorted_unique_streams(streams.iter().map(|stream| stream.stream_id))
            }
            Self::Descriptor(descriptor) => descriptor
                .verify()
                .map_err(|_| WireError::Invalid("invalid stream descriptor")),
            Self::Object(object) => object
                .validate_shape()
                .map_err(|_| WireError::Invalid("invalid native object")),
            Self::KeyEnvelope(envelope) => envelope
                .validate_shape()
                .map_err(|_| WireError::Invalid("invalid key envelope")),
            Self::PairOffer(offer) => validate_offer_shape(offer),
            Self::PairDecision(decision) => validate_decision_shape(decision),
            Self::Ping { .. } => Ok(()),
        }
    }
}

/// Relay-to-publisher events and durable acknowledgements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayPublisherMessage {
    /// Admission succeeded.
    Welcome(RelayWelcome),
    /// Durable stream high-water marks after a resume request.
    ResumeState(Vec<RelayResumeStream>),
    /// All stream objects through this sequence are durably committed.
    PublishAck {
        /// Stream being acknowledged.
        stream_id: Uuid,
        /// Inclusive durable sequence.
        committed_through: u64,
    },
    /// One queued viewer request with informational network metadata.
    PairRequest {
        /// Unmodified signed viewer request.
        request: PairRequest,
        /// Network peer address observed by the relay.
        source_addr: SocketAddr,
        /// Relay receive time as Unix milliseconds.
        received_at_ms: i64,
    },
    /// Viewer yes confirmation for a pending manual ceremony.
    ViewerConfirmation(ViewerConfirmation),
    /// Stable relay failure.
    Error(RelayError),
    /// Keepalive reply.
    Pong {
        /// Relay Unix milliseconds.
        now_ms: i64,
    },
}

impl RelayPublisherMessage {
    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Welcome(welcome) => validate_welcome(welcome),
            Self::ResumeState(streams) => {
                if streams.len() > MAX_STREAMS_PER_MESSAGE
                    || streams.iter().any(|stream| stream.stream_id.is_nil())
                {
                    return Err(WireError::Invalid("invalid relay resume state"));
                }
                sorted_unique_streams(streams.iter().map(|stream| stream.stream_id))
            }
            Self::PublishAck {
                stream_id,
                committed_through,
            } if stream_id.is_nil() || *committed_through == 0 => {
                Err(WireError::Invalid("invalid publish acknowledgement"))
            }
            Self::PairRequest { request, .. } => request
                .encode()
                .map(|_| ())
                .map_err(|_| WireError::Invalid("invalid pairing request")),
            Self::ViewerConfirmation(confirmation) => validate_confirmation_shape(confirmation),
            Self::Error(error) => error.validate(),
            Self::PublishAck { .. } | Self::Pong { .. } => Ok(()),
        }
    }
}

/// Catalog metadata and retained bounds for one admitted stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogEntry {
    /// Publisher-authenticated stream descriptor.
    pub descriptor: StreamDescriptor,
    /// Whether a publisher session is currently active.
    pub publisher_online: bool,
    /// Oldest complete retained group, if any.
    pub retained: Option<RetainedBounds>,
}

/// Complete retained range for one stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetainedBounds {
    /// First retained sequence at a keyframe-group boundary.
    pub oldest_sequence: u64,
    /// Last retained sequence.
    pub newest_sequence: u64,
    /// Oldest retained timestamp in 90 kHz ticks.
    pub oldest_timestamp: u64,
    /// Newest retained timestamp in 90 kHz ticks.
    pub newest_timestamp: u64,
}

impl RetainedBounds {
    fn validate(&self) -> Result<(), WireError> {
        if self.oldest_sequence == 0
            || self.oldest_sequence > self.newest_sequence
            || self.oldest_timestamp > self.newest_timestamp
        {
            return Err(WireError::Invalid("invalid retained bounds"));
        }
        Ok(())
    }
}

/// Starting point for a dedicated stream subscription connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SubscriptionStart {
    /// Begin at the gapless live tail.
    Live,
    /// Begin at the oldest complete retained group.
    OldestRetained,
    /// Begin at or before this explicit sequence, anchored to a complete group.
    Sequence(u64),
    /// Begin at or before this 90 kHz timestamp, anchored to a complete group.
    Timestamp(u64),
}

/// Viewer-to-relay control and subscription messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ViewerMessage {
    /// Required first message on every viewer connection.
    Hello(SessionHello),
    /// Request the admitted stream catalog.
    Catalog,
    /// Queue a signed request for its named publisher.
    PairRequest(PairRequest),
    /// Deliver the viewer's explicit yes confirmation.
    PairConfirmation(ViewerConfirmation),
    /// Fetch queued offers, decisions, and envelopes for this viewer.
    FetchInbox,
    /// Start one stream on this dedicated connection.
    Subscribe {
        /// Publisher identity fingerprint.
        publisher_id: [u8; IDENTITY_ID_LEN],
        /// Stream identifier.
        stream_id: Uuid,
        /// Requested retained/live anchor.
        start: SubscriptionStart,
    },
    /// Ask a live subscription to re-anchor through the retained store.
    Reanchor {
        /// Last sequence the viewer accepted.
        after_sequence: u64,
    },
    /// Keepalive carrying sender wall clock.
    Ping {
        /// Unix milliseconds.
        now_ms: i64,
    },
}

impl ViewerMessage {
    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Hello(hello) => hello.validate(CredentialRole::Viewer),
            Self::PairRequest(request) => request
                .encode()
                .map(|_| ())
                .map_err(|_| WireError::Invalid("invalid pairing request")),
            Self::PairConfirmation(confirmation) => validate_confirmation_shape(confirmation),
            Self::Subscribe {
                publisher_id,
                stream_id,
                start,
            } => {
                if *publisher_id == [0; IDENTITY_ID_LEN]
                    || stream_id.is_nil()
                    || matches!(start, SubscriptionStart::Sequence(0))
                {
                    return Err(WireError::Invalid("invalid subscription request"));
                }
                Ok(())
            }
            Self::Reanchor { after_sequence } if *after_sequence == 0 => {
                Err(WireError::Invalid("invalid subscription re-anchor"))
            }
            Self::Catalog | Self::FetchInbox | Self::Reanchor { .. } | Self::Ping { .. } => Ok(()),
        }
    }
}

/// Relay-to-viewer control and subscription messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayViewerMessage {
    /// Admission succeeded.
    Welcome(RelayWelcome),
    /// Complete currently admitted stream catalog.
    Catalog(Vec<CatalogEntry>),
    /// Queued publisher offer for manual comparison.
    PairOffer(PairOffer),
    /// Queued final publisher decision.
    PairDecision(PublisherDecision),
    /// Viewer-addressed content-key envelope.
    KeyEnvelope(KeyEnvelope),
    /// Subscription anchor and current retained range.
    SubscriptionStarted {
        /// First sequence the relay will send.
        first_sequence: u64,
        /// Retained range at subscription time.
        retained: Option<RetainedBounds>,
        /// Whether the connection has reached the live tail.
        live: bool,
    },
    /// One opaque signed encrypted object.
    Object(NativeObject),
    /// Catch-up reached the live tail without a sequence gap.
    Live {
        /// Last sequence sent before live following began.
        through_sequence: u64,
    },
    /// Stable relay failure.
    Error(RelayError),
    /// Keepalive reply.
    Pong {
        /// Relay Unix milliseconds.
        now_ms: i64,
    },
}

impl RelayViewerMessage {
    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Welcome(welcome) => validate_welcome(welcome),
            Self::Catalog(entries) => {
                if entries.len() > MAX_STREAMS_PER_MESSAGE {
                    return Err(WireError::Invalid("catalog contains too many streams"));
                }
                let mut stream_ids = Vec::with_capacity(entries.len());
                for entry in entries {
                    entry
                        .descriptor
                        .verify()
                        .map_err(|_| WireError::Invalid("invalid catalog descriptor"))?;
                    if let Some(bounds) = &entry.retained {
                        bounds.validate()?;
                    }
                    stream_ids.push(entry.descriptor.body.stream_id);
                }
                sorted_unique_streams(stream_ids)
            }
            Self::PairOffer(offer) => validate_offer_shape(offer),
            Self::PairDecision(decision) => validate_decision_shape(decision),
            Self::KeyEnvelope(envelope) => envelope
                .validate_shape()
                .map_err(|_| WireError::Invalid("invalid key envelope")),
            Self::SubscriptionStarted {
                first_sequence,
                retained,
                ..
            } => {
                if *first_sequence == 0 {
                    return Err(WireError::Invalid("invalid subscription anchor"));
                }
                if let Some(bounds) = retained {
                    bounds.validate()?;
                }
                Ok(())
            }
            Self::Object(object) => object
                .validate_shape()
                .map_err(|_| WireError::Invalid("invalid native object")),
            Self::Live { through_sequence } if *through_sequence == 0 => {
                Err(WireError::Invalid("invalid live-tail sequence"))
            }
            Self::Error(error) => error.validate(),
            Self::Live { .. } | Self::Pong { .. } => Ok(()),
        }
    }
}

/// Stable machine-readable relay error codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayErrorCode {
    /// Session was not admitted by relay policy.
    Unauthorized,
    /// Credential expired during an established session.
    CredentialExpired,
    /// Credential has the wrong endpoint role.
    WrongRole,
    /// Stream or publisher does not exist or is hidden.
    NotFound,
    /// Request exceeded a bounded queue or rate limit.
    RateLimited,
    /// Requested retained data has already been evicted.
    HistoryUnavailable,
    /// Peer sent a malformed or out-of-order message.
    ProtocolViolation,
    /// Relay could not durably commit an accepted request.
    StorageFailure,
}

/// Relay error with bounded operator-facing detail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayError {
    /// Stable error code.
    pub code: RelayErrorCode,
    /// Short non-secret diagnostic text.
    pub detail: String,
}

impl RelayError {
    fn validate(&self) -> Result<(), WireError> {
        if self.detail.len() > MAX_ERROR_DETAIL_LEN
            || self.detail.trim() != self.detail
            || self.detail.chars().any(char::is_control)
        {
            return Err(WireError::Invalid("invalid relay error detail"));
        }
        Ok(())
    }
}

/// Trait implemented by each top-level native v8 message family.
pub trait NativeWireMessage: Serialize + for<'de> Deserialize<'de> {
    /// Validates all structural and bounded invariants available without state.
    ///
    /// # Errors
    ///
    /// Returns an error when a message cannot safely enter a state machine.
    fn validate_wire(&self) -> Result<(), WireError>;
}

impl NativeWireMessage for PublisherMessage {
    fn validate_wire(&self) -> Result<(), WireError> {
        self.validate()
    }
}

impl NativeWireMessage for RelayPublisherMessage {
    fn validate_wire(&self) -> Result<(), WireError> {
        self.validate()
    }
}

impl NativeWireMessage for ViewerMessage {
    fn validate_wire(&self) -> Result<(), WireError> {
        self.validate()
    }
}

impl NativeWireMessage for RelayViewerMessage {
    fn validate_wire(&self) -> Result<(), WireError> {
        self.validate()
    }
}

/// Canonically encodes one validated protocol-v8 message.
///
/// # Errors
///
/// Returns an error for invalid structure, serialization, or frame bounds.
pub fn encode_native_message<T: NativeWireMessage>(message: &T) -> Result<Vec<u8>, WireError> {
    message.validate_wire()?;
    let encoded = postcard::to_stdvec(message)?;
    if encoded.len() > MAX_FRAME_LEN {
        return Err(WireError::TooLarge);
    }
    Ok(encoded)
}

/// Decodes one bounded canonical protocol-v8 message.
///
/// # Errors
///
/// Returns an error for bounds, truncation, trailing/noncanonical bytes, or any
/// structural invariant available before session-state validation.
pub fn decode_native_message<T: NativeWireMessage>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(WireError::TooLarge);
    }
    let (message, remainder) = postcard::take_from_bytes::<T>(bytes)?;
    if !remainder.is_empty() {
        return Err(WireError::Invalid("trailing native message data"));
    }
    message.validate_wire()?;
    if postcard::to_stdvec(&message)? != bytes {
        return Err(WireError::Invalid("noncanonical native message"));
    }
    Ok(message)
}

fn check_version(version: u16) -> Result<(), WireError> {
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    Ok(())
}

fn validate_welcome(welcome: &RelayWelcome) -> Result<(), WireError> {
    check_version(welcome.protocol_version)?;
    match (welcome.access_mode, welcome.credential_expires_at_ms) {
        (RelayAccessMode::Public, None) | (RelayAccessMode::Signed, Some(_)) => Ok(()),
        _ => Err(WireError::Invalid(
            "relay welcome admission mode and expiry disagree",
        )),
    }
}

fn sorted_unique_streams<I>(stream_ids: I) -> Result<(), WireError>
where
    I: IntoIterator<Item = Uuid>,
{
    let mut previous = None;
    for stream_id in stream_ids {
        if previous.is_some_and(|prior| prior >= stream_id) {
            return Err(WireError::Invalid(
                "stream records are not sorted and unique",
            ));
        }
        previous = Some(stream_id);
    }
    Ok(())
}

fn validate_offer_shape(offer: &PairOffer) -> Result<(), WireError> {
    offer
        .body
        .publisher
        .validate()
        .map_err(|_| WireError::Invalid("invalid offer publisher"))?;
    if offer.body.version != PAIRING_VERSION
        || offer.body.request_id == [0; 32]
        || offer.body.viewer_id == [0; IDENTITY_ID_LEN]
        || offer.body.nonce == [0; 32]
        || offer.body.relay_context == [0; 32]
        || offer.body.expires_at_ms <= offer.body.issued_at_ms
    {
        return Err(WireError::Invalid("invalid pair offer"));
    }
    Ok(())
}

fn validate_confirmation_shape(confirmation: &ViewerConfirmation) -> Result<(), WireError> {
    if confirmation.body.version != PAIRING_VERSION
        || confirmation.body.request_id == [0; 32]
        || confirmation.body.transcript_hash == [0; 32]
        || confirmation.body.viewer_id == [0; IDENTITY_ID_LEN]
    {
        return Err(WireError::Invalid("invalid viewer confirmation"));
    }
    Ok(())
}

fn validate_decision_shape(decision: &PublisherDecision) -> Result<(), WireError> {
    if decision.body.version != PAIRING_VERSION
        || decision.body.request_id == [0; 32]
        || decision.body.viewer_id == [0; IDENTITY_ID_LEN]
    {
        return Err(WireError::Invalid("invalid publisher decision"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::IdentitySecret,
        native::{CodecId, GroupEncryptor, NativeObjectKind, NewNativeObject},
    };

    #[test]
    fn viewer_hello_round_trips_and_rejects_wrong_version_or_role() {
        let identity = IdentitySecret::generate().public().unwrap();
        let message = ViewerMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Viewer,
            identity,
            credential: None,
        });
        let encoded = encode_native_message(&message).unwrap();
        assert_eq!(
            decode_native_message::<ViewerMessage>(&encoded).unwrap(),
            message
        );
        let wrong_version = ViewerMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION - 1,
            role: CredentialRole::Viewer,
            identity,
            credential: None,
        });
        assert!(encode_native_message(&wrong_version).is_err());
        let wrong_role = ViewerMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Publisher,
            identity,
            credential: None,
        });
        assert!(encode_native_message(&wrong_role).is_err());
    }

    #[test]
    fn native_message_parser_rejects_all_truncations_and_trailing_data() {
        let publisher = IdentitySecret::generate();
        let public = publisher.public().unwrap();
        let mut group =
            GroupEncryptor::generate(&public, Uuid::from_u128(1), Uuid::from_u128(2), 1, 0)
                .unwrap();
        let object = group
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
        let message = RelayViewerMessage::Object(object);
        let encoded = encode_native_message(&message).unwrap();
        for end in 0..encoded.len() {
            assert!(decode_native_message::<RelayViewerMessage>(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_native_message::<RelayViewerMessage>(&trailing).is_err());
    }

    #[test]
    fn catalog_must_be_sorted_unique_and_publisher_signed() {
        let publisher = IdentitySecret::generate();
        let descriptor = StreamDescriptor::new(
            &publisher,
            Uuid::from_u128(2),
            "screen".into(),
            "DP-1".into(),
            true,
            1,
        )
        .unwrap();
        let entry = CatalogEntry {
            descriptor,
            publisher_online: true,
            retained: None,
        };
        assert!(encode_native_message(&RelayViewerMessage::Catalog(vec![entry.clone()])).is_ok());
        assert!(
            encode_native_message(&RelayViewerMessage::Catalog(vec![entry.clone(), entry]))
                .is_err()
        );
    }

    #[test]
    fn signed_welcome_requires_expiry_and_public_welcome_forbids_it() {
        assert!(
            encode_native_message(&RelayViewerMessage::Welcome(RelayWelcome {
                protocol_version: PROTOCOL_VERSION,
                access_mode: RelayAccessMode::Signed,
                relay_time_ms: 1,
                credential_expires_at_ms: None,
            }))
            .is_err()
        );
        assert!(
            encode_native_message(&RelayViewerMessage::Welcome(RelayWelcome {
                protocol_version: PROTOCOL_VERSION,
                access_mode: RelayAccessMode::Public,
                relay_time_ms: 1,
                credential_expires_at_ms: Some(2),
            }))
            .is_err()
        );
    }
}
