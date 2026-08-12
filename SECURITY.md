# Security Policy

GlacialCast carries the contents of someone's screen. A break in it is a break
in whatever they had open, so please treat findings here as sensitive.

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://github.com/0typos/glacialcast/security/advisories/new). Do
not open a public issue for anything that affects stream confidentiality,
identity or credential validation, relay admission, viewer approval, or object
integrity.

Include the version or commit, platform and compositor, and enough detail to
reproduce. A failing test or script under `scripts/` is the most useful report.

There is no paid bounty or guaranteed response time. Maintainers will
acknowledge actionable reports as capacity permits and coordinate disclosure
before publishing a fix.

## Supported versions

The latest 1.x release and the tip of `main` are supported. Security fixes ship
as patch releases on the current minor line; older minor lines are unsupported
after a newer minor release is available.

## Security boundary

The publisher and approved viewer device are trusted with plaintext. The relay
and network are not. A relay may actively alter, substitute, replay, reorder,
delay, or discard traffic. Publisher-to-relay and viewer-to-relay Noise XX
sessions protect each network hop, while publisher signatures, AEAD stream
objects, and viewer-specific HPKE key envelopes form the separate end-to-end
boundary.

The following properties are in scope:

- **A relay cannot read a protected stream.** Codec configuration, video, and
  cursor data remain encrypted under content keys the relay never receives.
- **Encryption cannot be stripped.** There is no plaintext stream format. A
  paired viewer rejects missing or invalid signatures, envelopes, AEAD tags,
  versions, identity bindings, and publisher pins.
- **A relay cannot silently substitute a viewer.** Manual pairing binds both
  persistent identities and fresh material into a short authentication string
  compared through an independent channel. Both endpoints must confirm it and
  neither offers a skip action.
- **A relay cannot forge a publisher.** Viewers pin the publisher identity and
  verify signed descriptors, objects, pairing decisions, and key envelopes.
- **Relay admission fails closed in signed mode.** Native credentials bind the
  authenticated Noise client key, role, validity period, application keys, and
  issuer. Missing, expired, revoked, wrongly signed, or wrong-role credentials
  reveal no catalog and authorize no operation.
- **Relay and viewer-approval trust do not bleed together.** A relay-access CA
  is not a publisher viewer-approval CA unless the operator explicitly
  configures the same external issuer for both jobs.
- **Revocation stops future access.** The publisher durably revokes the viewer,
  rotates the content key, forces a new random-access group, and issues no new
  envelope to that identity.
- **Objects and state fail closed.** Malformed, oversized, truncated,
  noncanonical, cross-stream, replayed-as-live, or unauthenticated inputs are
  rejected before unsafe allocation or state mutation. Private state refuses
  unsafe permissions and symlinks.

Memory-safety faults reachable from a hostile relay, publisher, viewer,
credential, stream object, state file, or retained catalog are in scope. The
bounded fuzz targets exist for those boundaries.

## Deliberate limits

These are design limits rather than vulnerabilities:

- **Open publisher approval is public.** `approval = "open"` automatically
  grants every requester a viewer envelope. Data remains encrypted on the wire,
  but the relay itself may request access, so this policy does not protect
  plaintext from a malicious relay.
- **Public relay admission exposes metadata.** `access.mode = "public"` lets
  anyone enumerate the catalog and request pairing. Publisher viewer approval
  still controls content keys.
- **Already delivered keys cannot be recalled.** Revocation prevents access to
  later key groups. It cannot erase plaintext, ciphertext, screenshots, or
  historical keys a viewer already obtained.
- **The relay learns metadata.** Publisher and stream existence and names,
  peer IP addresses, request timing, ciphertext sizes, envelope recipient
  identifiers, and subscription choices are visible. Traffic-analysis
  resistance is not claimed.
- **A malicious relay can deny service.** It can drop, delay, selectively hide,
  or replay old signed data. Viewers detect invalid or stale claims where the
  signed protocol permits, but GlacialCast cannot force delivery.
- **TOFU does not authenticate an unseen relay out of band.** Manual first
  contact trusts the first Noise key. An invitation or explicit key pin avoids
  that first-contact assumption. Later key changes fail closed.
- **A configured trust authority is trusted.** A viewer-approval CA can enroll
  viewers without the manual comparison. Compromise or misuse of that CA is
  equivalent to approving those identities. CA private keys should remain on
  an offline administration host.
- **Publisher or viewer host compromise is terminal.** An attacker able to read
  the private `0600` state in either desktop session can access the same screen,
  keys, or decoded content as the application.
- **Viewer identity is per device.** Copying private identity state copies the
  device's authority. Automated identity synchronization and encrypted backup
  are not part of 1.0.
- **Audio, remote input, and offline recordings are absent.** Findings premised
  on those unsupported features are outside the current boundary.

## Cryptography

GlacialCast composes maintained implementations of Noise XX, Ed25519, RFC 9180
HPKE with X25519 and HKDF-SHA-256, SHA-256, and an AEAD. Signing and
key-encapsulation keys are separate. Canonical encodings and domain-separation
labels are versioned and covered by golden vectors. Reports about nonce reuse,
weak transcript binding, signature confusion, key substitution, downgrade,
cross-recipient envelopes, or misuse of these primitives are in scope.
