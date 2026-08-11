//! Two-sided publisher/viewer pairing with a human authentication string.

use crate::{
    PROTOCOL_VERSION,
    identity::{
        IDENTITY_ID_LEN, IdentityError, IdentityPublic, IdentitySecret, SignatureBytes, verify,
    },
    viewer_key::wordlist,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Pairing message format version.
pub const PAIRING_VERSION: u16 = 1;
/// Maximum encoded pairing record length.
pub const MAX_PAIRING_MESSAGE_LEN: usize = 32 * 1024;
/// Maximum UTF-8 device-label length.
pub const MAX_DEVICE_LABEL_LEN: usize = 128;

const REQUEST_DOMAIN: &[u8] = b"glacialcast-pair-request-v1";
const OFFER_DOMAIN: &[u8] = b"glacialcast-pair-offer-v1";
const CONFIRM_DOMAIN: &[u8] = b"glacialcast-pair-viewer-confirm-v1";
const DECISION_DOMAIN: &[u8] = b"glacialcast-pair-publisher-decision-v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"glacialcast-pair-transcript-v1";
const REQUEST_ID_DOMAIN: &[u8] = b"glacialcast-pair-request-id-v1";
const CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;

/// Errors produced by native pairing messages and transcript verification.
#[derive(Debug, Error)]
pub enum PairingError {
    /// A pairing record used an unsupported pairing or protocol version.
    #[error("unsupported pairing version")]
    UnsupportedVersion,
    /// A field, timestamp, nonce, identity, or state transition was invalid.
    #[error("invalid pairing metadata: {0}")]
    InvalidMetadata(&'static str),
    /// A pairing record was not signed by the identity it claims.
    #[error("pairing signature verification failed")]
    InvalidSignature,
    /// A pairing message was created too far in the future.
    #[error("pairing message is not valid yet")]
    NotYetValid,
    /// A pairing message expired.
    #[error("pairing message expired")]
    Expired,
    /// Identities, request IDs, or transcript hashes did not match.
    #[error("pairing transcript or identity mismatch")]
    TranscriptMismatch,
    /// A bounded canonical pairing message could not be encoded or decoded.
    #[error("pairing serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    /// Identity validation or signing failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

fn validate_time(
    issued_at_ms: i64,
    expires_at_ms: i64,
    now_ms: i64,
    max_lifetime_ms: i64,
) -> Result<(), PairingError> {
    let lifetime = expires_at_ms
        .checked_sub(issued_at_ms)
        .ok_or(PairingError::InvalidMetadata(
            "pairing time range overflows",
        ))?;
    if lifetime <= 0 || max_lifetime_ms <= 0 || lifetime > max_lifetime_ms {
        return Err(PairingError::InvalidMetadata(
            "pairing lifetime exceeds policy",
        ));
    }
    if issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(PairingError::NotYetValid);
    }
    if expires_at_ms <= now_ms {
        return Err(PairingError::Expired);
    }
    Ok(())
}

fn validate_device_label(label: &str) -> Result<(), PairingError> {
    if label.is_empty()
        || label.len() > MAX_DEVICE_LABEL_LEN
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(PairingError::InvalidMetadata("invalid device label"));
    }
    Ok(())
}

fn random_nonzero<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    while bytes == [0; N] {
        rand::rngs::OsRng.fill_bytes(&mut bytes);
    }
    bytes
}

fn map_signature(error: IdentityError) -> PairingError {
    match error {
        IdentityError::InvalidSignature => PairingError::InvalidSignature,
        other => PairingError::Identity(other),
    }
}

/// Canonical fields in a viewer's signed pairing request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairRequestBody {
    /// Pairing format version.
    pub version: u16,
    /// Native protocol version this request requires.
    pub protocol_version: u16,
    /// Exact publisher identity the viewer intends to pair with.
    pub publisher: IdentityPublic,
    /// Persistent viewer identity requesting approval.
    pub viewer: IdentityPublic,
    /// Human-readable informational device label.
    pub device_label: String,
    /// Fresh request nonce.
    pub nonce: [u8; 32],
    /// Request creation time as Unix milliseconds.
    pub issued_at_ms: i64,
    /// Exclusive request expiration as Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Viewer-signed request to begin pairing with one exact publisher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairRequest {
    /// Canonical request fields covered by `signature`.
    pub body: PairRequestBody,
    /// Viewer signature proving possession of `body.viewer`.
    pub signature: SignatureBytes,
}

impl PairRequest {
    /// Creates a signed, publisher-specific pairing request.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, label, time range, or signing.
    pub fn new(
        viewer: &IdentitySecret,
        publisher: IdentityPublic,
        device_label: String,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<Self, PairingError> {
        validate_device_label(&device_label)?;
        publisher.validate()?;
        let body = PairRequestBody {
            version: PAIRING_VERSION,
            protocol_version: PROTOCOL_VERSION,
            publisher,
            viewer: viewer.public()?,
            device_label,
            nonce: random_nonzero(),
            issued_at_ms,
            expires_at_ms,
        };
        validate_request_metadata(&body)?;
        let signature = viewer.sign(REQUEST_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Verifies request metadata, freshness, identity, and proof of possession.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, stale, overlong, or forged requests.
    pub fn verify(&self, now_ms: i64, max_lifetime_ms: i64) -> Result<(), PairingError> {
        validate_request_metadata(&self.body)?;
        validate_time(
            self.body.issued_at_ms,
            self.body.expires_at_ms,
            now_ms,
            max_lifetime_ms,
        )?;
        verify(
            &self.body.viewer,
            REQUEST_DOMAIN,
            &self.body,
            &self.signature,
        )
        .map_err(map_signature)
    }

    /// Returns the domain-separated canonical request identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn id(&self) -> Result<[u8; 32], PairingError> {
        domain_hash(REQUEST_ID_DOMAIN, self)
    }

    /// Canonically encodes this bounded request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, serialization, or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        validate_request_metadata(&self.body)?;
        encode_bounded(self)
    }

    /// Decodes one canonical request, rejecting truncation and trailing data.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, PairingError> {
        let request: Self = decode_bounded(bytes)?;
        validate_request_metadata(&request.body)?;
        Ok(request)
    }
}

fn validate_request_metadata(body: &PairRequestBody) -> Result<(), PairingError> {
    if body.version != PAIRING_VERSION || body.protocol_version != PROTOCOL_VERSION {
        return Err(PairingError::UnsupportedVersion);
    }
    body.publisher.validate()?;
    body.viewer.validate()?;
    validate_device_label(&body.device_label)?;
    if body.nonce == [0; 32] {
        return Err(PairingError::InvalidMetadata("zero request nonce"));
    }
    if body.expires_at_ms <= body.issued_at_ms {
        return Err(PairingError::InvalidMetadata("invalid request time range"));
    }
    Ok(())
}

/// Canonical fields in a publisher's signed pairing offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairOfferBody {
    /// Pairing format version.
    pub version: u16,
    /// Exact signed request being answered.
    pub request_id: [u8; 32],
    /// Persistent publisher identity.
    pub publisher: IdentityPublic,
    /// Persistent viewer identity copied from the request.
    pub viewer_id: [u8; IDENTITY_ID_LEN],
    /// Fresh publisher contribution to the comparison transcript.
    pub nonce: [u8; 32],
    /// Hash of the authenticated relay context for this delivery.
    pub relay_context: [u8; 32],
    /// Offer creation time as Unix milliseconds.
    pub issued_at_ms: i64,
    /// Exclusive offer expiration as Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Publisher-signed response that creates the human comparison transcript.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairOffer {
    /// Canonical offer fields covered by `signature`.
    pub body: PairOfferBody,
    /// Publisher signature proving possession of `body.publisher`.
    pub signature: SignatureBytes,
}

impl PairOffer {
    /// Creates an offer for one verified request and authenticated relay context.
    ///
    /// # Errors
    ///
    /// Returns an error if the request, context, validity, or signature fails.
    pub fn new(
        publisher: &IdentitySecret,
        request: &PairRequest,
        relay_context: [u8; 32],
        issued_at_ms: i64,
        expires_at_ms: i64,
        max_request_lifetime_ms: i64,
    ) -> Result<Self, PairingError> {
        request.verify(issued_at_ms, max_request_lifetime_ms)?;
        let public = publisher.public()?;
        if public != request.body.publisher || relay_context == [0; 32] {
            return Err(PairingError::TranscriptMismatch);
        }
        let body = PairOfferBody {
            version: PAIRING_VERSION,
            request_id: request.id()?,
            publisher: public,
            viewer_id: request.body.viewer.id()?,
            nonce: random_nonzero(),
            relay_context,
            issued_at_ms,
            expires_at_ms,
        };
        validate_offer_metadata(&body)?;
        let signature = publisher.sign(OFFER_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Verifies the offer against its exact request and configured lifetimes.
    ///
    /// # Errors
    ///
    /// Returns an error for expiry, substitution, replay, or invalid signatures.
    pub fn verify(
        &self,
        request: &PairRequest,
        now_ms: i64,
        max_lifetime_ms: i64,
    ) -> Result<(), PairingError> {
        validate_offer_metadata(&self.body)?;
        request.verify(now_ms, max_lifetime_ms)?;
        validate_time(
            self.body.issued_at_ms,
            self.body.expires_at_ms,
            now_ms,
            max_lifetime_ms,
        )?;
        if self.body.request_id != request.id()?
            || self.body.publisher != request.body.publisher
            || self.body.viewer_id != request.body.viewer.id()?
        {
            return Err(PairingError::TranscriptMismatch);
        }
        verify(
            &self.body.publisher,
            OFFER_DOMAIN,
            &self.body,
            &self.signature,
        )
        .map_err(map_signature)
    }
}

fn validate_offer_metadata(body: &PairOfferBody) -> Result<(), PairingError> {
    if body.version != PAIRING_VERSION {
        return Err(PairingError::UnsupportedVersion);
    }
    body.publisher.validate()?;
    if body.request_id == [0; 32]
        || body.viewer_id == [0; IDENTITY_ID_LEN]
        || body.nonce == [0; 32]
        || body.relay_context == [0; 32]
        || body.expires_at_ms <= body.issued_at_ms
    {
        return Err(PairingError::InvalidMetadata("invalid offer metadata"));
    }
    Ok(())
}

#[derive(Serialize)]
struct PairTranscript<'a> {
    protocol_version: u16,
    request: &'a PairRequest,
    offer: &'a PairOffer,
}

/// Derives the transcript hash independently compared by publisher and viewer.
///
/// # Errors
///
/// Returns an error if either message is structurally invalid or serialization
/// fails. Callers must also run the time-aware verification methods.
pub fn transcript_hash(request: &PairRequest, offer: &PairOffer) -> Result<[u8; 32], PairingError> {
    validate_request_metadata(&request.body)?;
    validate_offer_metadata(&offer.body)?;
    if offer.body.request_id != request.id()?
        || offer.body.publisher != request.body.publisher
        || offer.body.viewer_id != request.body.viewer.id()?
    {
        return Err(PairingError::TranscriptMismatch);
    }
    domain_hash(
        TRANSCRIPT_DOMAIN,
        &PairTranscript {
            protocol_version: PROTOCOL_VERSION,
            request,
            offer,
        },
    )
}

/// Formats a transcript as three unambiguous words and two decimal digits.
///
/// The three words carry 30 bits from the existing 1024-word comparison list;
/// the suffix adds about 6.6 bits. This value is public authentication data,
/// not a shared decryption secret.
///
/// # Errors
///
/// Returns an error if the request and offer do not form one transcript.
pub fn authentication_string(
    request: &PairRequest,
    offer: &PairOffer,
) -> Result<String, PairingError> {
    let hash = transcript_hash(request, offer)?;
    let bits = u32::from_be_bytes(hash[..4].try_into().expect("four-byte hash prefix"));
    let words = wordlist();
    let first = words[((bits >> 22) & 0x03ff) as usize];
    let second = words[((bits >> 12) & 0x03ff) as usize];
    let third = words[((bits >> 2) & 0x03ff) as usize];
    let digits = u16::from_be_bytes([hash[4], hash[5]]) % 100;
    Ok(format!("{first}-{second}-{third} {digits:02}"))
}

/// Canonical fields in the viewer's explicit yes confirmation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewerConfirmationBody {
    /// Pairing format version.
    pub version: u16,
    /// Request being confirmed.
    pub request_id: [u8; 32],
    /// Exact transcript the viewer displayed and accepted.
    pub transcript_hash: [u8; 32],
    /// Confirming viewer identity.
    pub viewer_id: [u8; IDENTITY_ID_LEN],
    /// Confirmation time as Unix milliseconds.
    pub confirmed_at_ms: i64,
}

/// Viewer-signed evidence that the human answered yes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewerConfirmation {
    /// Canonical confirmation fields covered by `signature`.
    pub body: ViewerConfirmationBody,
    /// Viewer signature.
    pub signature: SignatureBytes,
}

impl ViewerConfirmation {
    /// Signs a viewer yes for one verified request/offer transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if identities, transcript, or signing fail.
    pub fn approve(
        viewer: &IdentitySecret,
        request: &PairRequest,
        offer: &PairOffer,
        confirmed_at_ms: i64,
    ) -> Result<Self, PairingError> {
        let viewer_id = viewer.public()?.id()?;
        if viewer_id != request.body.viewer.id()? {
            return Err(PairingError::TranscriptMismatch);
        }
        let body = ViewerConfirmationBody {
            version: PAIRING_VERSION,
            request_id: request.id()?,
            transcript_hash: transcript_hash(request, offer)?,
            viewer_id,
            confirmed_at_ms,
        };
        let signature = viewer.sign(CONFIRM_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Verifies the viewer yes against the exact request and offer.
    ///
    /// # Errors
    ///
    /// Returns an error for substitution, transcript mismatch, or forgery.
    pub fn verify(&self, request: &PairRequest, offer: &PairOffer) -> Result<(), PairingError> {
        if self.body.version != PAIRING_VERSION
            || self.body.request_id != request.id()?
            || self.body.transcript_hash != transcript_hash(request, offer)?
            || self.body.viewer_id != request.body.viewer.id()?
        {
            return Err(PairingError::TranscriptMismatch);
        }
        verify(
            &request.body.viewer,
            CONFIRM_DOMAIN,
            &self.body,
            &self.signature,
        )
        .map_err(map_signature)
    }
}

/// Reason a publisher persisted an approval or rejection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PairDecisionReason {
    /// Both humans compared the authentication string and answered yes.
    ManualVerified,
    /// A credential from an explicitly configured viewer-approval CA verified.
    TrustedViewerCa,
    /// Publisher policy deliberately approves every identity.
    OpenPolicy,
    /// Publisher explicitly rejected the request.
    Rejected,
}

/// Canonical publisher decision fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherDecisionBody {
    /// Pairing format version.
    pub version: u16,
    /// Request being decided.
    pub request_id: [u8; 32],
    /// Viewer identity affected permanently until revocation.
    pub viewer_id: [u8; IDENTITY_ID_LEN],
    /// Transcript hash for manual decisions, or zero for prior-verification modes.
    pub transcript_hash: [u8; 32],
    /// Whether this decision grants access.
    pub approved: bool,
    /// Verification or rejection path used.
    pub reason: PairDecisionReason,
    /// Decision time as Unix milliseconds.
    pub decided_at_ms: i64,
}

/// Publisher-signed final pairing decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherDecision {
    /// Canonical decision fields covered by `signature`.
    pub body: PublisherDecisionBody,
    /// Publisher signature.
    pub signature: SignatureBytes,
}

impl PublisherDecision {
    /// Signs a manual approval after verifying the viewer confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error if the transcript, identities, confirmation, or signing fail.
    pub fn approve_manual(
        publisher: &IdentitySecret,
        request: &PairRequest,
        offer: &PairOffer,
        confirmation: &ViewerConfirmation,
        decided_at_ms: i64,
    ) -> Result<Self, PairingError> {
        confirmation.verify(request, offer)?;
        if publisher.public()? != request.body.publisher {
            return Err(PairingError::TranscriptMismatch);
        }
        Self::sign(
            publisher,
            PublisherDecisionBody {
                version: PAIRING_VERSION,
                request_id: request.id()?,
                viewer_id: request.body.viewer.id()?,
                transcript_hash: transcript_hash(request, offer)?,
                approved: true,
                reason: PairDecisionReason::ManualVerified,
                decided_at_ms,
            },
        )
    }

    /// Signs an approval backed by trusted-viewer-CA or explicit open policy.
    ///
    /// Credential verification and the open-mode warning are caller policy
    /// responsibilities; this method rejects manual/rejection reasons.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong identity, invalid reason, or signing failure.
    pub fn approve_by_policy(
        publisher: &IdentitySecret,
        request: &PairRequest,
        reason: PairDecisionReason,
        decided_at_ms: i64,
    ) -> Result<Self, PairingError> {
        if publisher.public()? != request.body.publisher {
            return Err(PairingError::TranscriptMismatch);
        }
        if !matches!(
            reason,
            PairDecisionReason::TrustedViewerCa | PairDecisionReason::OpenPolicy
        ) {
            return Err(PairingError::InvalidMetadata(
                "invalid automatic approval reason",
            ));
        }
        Self::sign(
            publisher,
            PublisherDecisionBody {
                version: PAIRING_VERSION,
                request_id: request.id()?,
                viewer_id: request.body.viewer.id()?,
                transcript_hash: [0; 32],
                approved: true,
                reason,
                decided_at_ms,
            },
        )
    }

    fn sign(publisher: &IdentitySecret, body: PublisherDecisionBody) -> Result<Self, PairingError> {
        validate_decision(&body)?;
        let signature = publisher.sign(DECISION_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Verifies this decision for one request and pinned publisher.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong request/viewer/transcript semantics or forgery.
    pub fn verify(
        &self,
        request: &PairRequest,
        publisher: &IdentityPublic,
    ) -> Result<(), PairingError> {
        validate_decision(&self.body)?;
        if publisher != &request.body.publisher
            || self.body.request_id != request.id()?
            || self.body.viewer_id != request.body.viewer.id()?
        {
            return Err(PairingError::TranscriptMismatch);
        }
        verify(publisher, DECISION_DOMAIN, &self.body, &self.signature).map_err(map_signature)
    }
}

fn validate_decision(body: &PublisherDecisionBody) -> Result<(), PairingError> {
    if body.version != PAIRING_VERSION
        || body.request_id == [0; 32]
        || body.viewer_id == [0; IDENTITY_ID_LEN]
    {
        return Err(PairingError::InvalidMetadata("invalid decision metadata"));
    }
    match (body.approved, body.reason, body.transcript_hash == [0; 32]) {
        (true, PairDecisionReason::ManualVerified, false)
        | (true, PairDecisionReason::TrustedViewerCa, true)
        | (true, PairDecisionReason::OpenPolicy, true)
        | (false, PairDecisionReason::Rejected, true) => Ok(()),
        _ => Err(PairingError::InvalidMetadata(
            "decision reason does not match approval state",
        )),
    }
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], PairingError> {
    let encoded = postcard::to_stdvec(value)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(
        u64::try_from(encoded.len())
            .expect("usize fits in u64 on supported Linux targets")
            .to_be_bytes(),
    );
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, PairingError> {
    let encoded = postcard::to_stdvec(value)?;
    if encoded.len() > MAX_PAIRING_MESSAGE_LEN {
        return Err(PairingError::InvalidMetadata("pairing message too large"));
    }
    Ok(encoded)
}

fn decode_bounded<T>(bytes: &[u8]) -> Result<T, PairingError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > MAX_PAIRING_MESSAGE_LEN {
        return Err(PairingError::InvalidMetadata("pairing message too large"));
    }
    let (value, remainder) = postcard::take_from_bytes::<T>(bytes)?;
    if !remainder.is_empty() || postcard::to_stdvec(&value)? != bytes {
        return Err(PairingError::InvalidMetadata(
            "trailing or noncanonical pairing data",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn ceremony() -> (
        IdentitySecret,
        IdentitySecret,
        PairRequest,
        PairOffer,
        ViewerConfirmation,
    ) {
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            "living-room".into(),
            1_000,
            1_000 + DAY_MS,
        )
        .unwrap();
        let offer =
            PairOffer::new(&publisher, &request, [7; 32], 2_000, 2_000 + DAY_MS, DAY_MS).unwrap();
        let confirmation = ViewerConfirmation::approve(&viewer, &request, &offer, 3_000).unwrap();
        (publisher, viewer, request, offer, confirmation)
    }

    #[test]
    fn both_sides_derive_the_same_unambiguous_authentication_string() {
        let (publisher, _, request, offer, confirmation) = ceremony();
        request.verify(3_000, DAY_MS).unwrap();
        offer.verify(&request, 3_000, DAY_MS).unwrap();
        confirmation.verify(&request, &offer).unwrap();
        let viewer_display = authentication_string(&request, &offer).unwrap();
        let publisher_display = authentication_string(&request, &offer).unwrap();
        assert_eq!(viewer_display, publisher_display);
        assert_eq!(viewer_display.split('-').count(), 3);
        let decision =
            PublisherDecision::approve_manual(&publisher, &request, &offer, &confirmation, 4_000)
                .unwrap();
        decision
            .verify(&request, &publisher.public().unwrap())
            .unwrap();
    }

    #[test]
    fn substituted_identity_or_relay_context_changes_or_breaks_transcript() {
        let (_, _, request, offer, _) = ceremony();
        let original = authentication_string(&request, &offer).unwrap();

        let mut context_changed = offer.clone();
        context_changed.body.relay_context = [8; 32];
        assert_ne!(
            authentication_string(&request, &context_changed).unwrap(),
            original
        );
        assert!(context_changed.verify(&request, 3_000, DAY_MS).is_err());

        let mut identity_changed = request.clone();
        identity_changed.body.viewer = IdentitySecret::generate().public().unwrap();
        assert!(transcript_hash(&identity_changed, &offer).is_err());
    }

    #[test]
    fn viewer_confirmation_cannot_be_replayed_for_another_offer() {
        let (publisher, _, request, offer, confirmation) = ceremony();
        let other_offer =
            PairOffer::new(&publisher, &request, [9; 32], 2_000, 2_000 + DAY_MS, DAY_MS).unwrap();
        assert!(confirmation.verify(&request, &other_offer).is_err());
        assert!(
            PublisherDecision::approve_manual(
                &publisher,
                &request,
                &other_offer,
                &confirmation,
                4_000,
            )
            .is_err()
        );
        assert!(offer.verify(&request, 3_000, DAY_MS).is_ok());
    }

    #[test]
    fn request_parser_rejects_every_truncation_and_trailing_data() {
        let (_, _, request, _, _) = ceremony();
        let encoded = request.encode().unwrap();
        assert_eq!(PairRequest::decode(&encoded).unwrap(), request);
        for end in 0..encoded.len() {
            assert!(PairRequest::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PairRequest::decode(&trailing).is_err());
    }

    #[test]
    fn policy_approval_is_distinct_from_manual_confirmation() {
        let (publisher, _, request, _, _) = ceremony();
        for reason in [
            PairDecisionReason::TrustedViewerCa,
            PairDecisionReason::OpenPolicy,
        ] {
            let decision =
                PublisherDecision::approve_by_policy(&publisher, &request, reason, 4_000).unwrap();
            decision
                .verify(&request, &publisher.public().unwrap())
                .unwrap();
            assert_eq!(decision.body.transcript_hash, [0; 32]);
        }
        assert!(
            PublisherDecision::approve_by_policy(
                &publisher,
                &request,
                PairDecisionReason::ManualVerified,
                4_000,
            )
            .is_err()
        );
    }

    #[test]
    fn pairing_v8_golden_vector_is_stable_and_decodable() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/protocol-v8.json")).unwrap();
        let publisher = IdentitySecret::from_private_bytes([1; 32], [2; 32]).unwrap();
        let viewer = IdentitySecret::from_private_bytes([6; 32], [7; 32]).unwrap();
        let request_body = PairRequestBody {
            version: PAIRING_VERSION,
            protocol_version: PROTOCOL_VERSION,
            publisher: publisher.public().unwrap(),
            viewer: viewer.public().unwrap(),
            device_label: "viewer".into(),
            nonce: [8; 32],
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + DAY_MS,
        };
        let request = PairRequest {
            signature: viewer.sign(REQUEST_DOMAIN, &request_body).unwrap(),
            body: request_body,
        };
        let offer_body = PairOfferBody {
            version: PAIRING_VERSION,
            request_id: request.id().unwrap(),
            publisher: publisher.public().unwrap(),
            viewer_id: viewer.public().unwrap().id().unwrap(),
            nonce: [9; 32],
            relay_context: [10; 32],
            issued_at_ms: 2_000,
            expires_at_ms: 2_000 + DAY_MS,
        };
        let offer = PairOffer {
            signature: publisher.sign(OFFER_DOMAIN, &offer_body).unwrap(),
            body: offer_body,
        };
        assert_eq!(
            vector["pair_request_b64"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(request.encode().unwrap())
        );
        assert_eq!(
            vector["pair_offer_b64"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(postcard::to_stdvec(&offer).unwrap())
        );
        assert_eq!(
            vector["pair_transcript_b64"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(transcript_hash(&request, &offer).unwrap())
        );
        assert_eq!(
            vector["authentication_string"].as_str().unwrap(),
            authentication_string(&request, &offer).unwrap()
        );
        let encoded_request = URL_SAFE_NO_PAD
            .decode(vector["pair_request_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(PairRequest::decode(&encoded_request).unwrap(), request);
    }
}
