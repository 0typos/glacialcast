# GlacialCast Architecture

## Product contract

GlacialCast is a low-bandwidth, end-to-end-encrypted Wayland screen viewer. It
ships three native Linux programs:

- `gcpub` captures and publishes screens and authorizes viewer devices;
- `gcrelay` stores and forwards opaque encrypted streams;
- `gcview` discovers, pairs with, and displays one or more streams.

The first native release is video-only and view-only. It targets Wayland first,
supports X11 viewing where the host stack permits it, and carries H.264 Annex-B
access units. Audio, remote input, browser playback, portable/offline playback,
relay clustering, and federation are outside the 0.6 contract.

The publisher uses the XDG Desktop Portal and PipeWire, samples changed video
at a low rate, encodes H.264, and publishes cursor state independently at a
higher cadence. The relay keeps history bounded by age and bytes. A native
viewer can seek through retained history and return to live playback.

## Trust model

The relay is an untrusted store-and-forward peer. It may be malicious: it can
observe metadata, delay, drop, replay, reorder, or invent relay messages. It
must not be able to decrypt screen or cursor content, forge publisher content,
substitute a viewer during a verified pairing, or strip encryption. Availability
against a malicious relay is not promised.

Publisher-to-relay and viewer-to-relay connections use Noise XX. Clients learn
the relay static key through trust on first use (TOFU) or receive an explicit
pin in configuration or a `glacialcast://` invitation. A learned key change
fails closed until the operator explicitly forgets or replaces it. Noise
protects the two network hops; it is not the stream's end-to-end boundary.

Each publisher and each viewer device owns a persistent identity with separate
Ed25519 signing and X25519 key-encapsulation keys. A publisher signs descriptors,
encrypted objects, pairing decisions, and viewer-specific key envelopes. A
viewer pins the publisher identity when pairing and verifies those signatures
itself. Relay validation is only an early corruption check.

```text
publisher                    untrusted relay                     viewer
    |<-------- Noise XX ---------->|<---------- Noise XX ---------->|
    |                                                                |
    |<--- signed pairing transcript / verified short auth string --->|
    |                                                                |
    |---- signed AEAD ciphertext + viewer-specific HPKE envelopes --->|
    |                                                                |
    +---------------- end-to-end confidentiality ---------------------+
```

## Relay admission and viewing approval

Relay admission is separate from publisher-controlled viewing approval.

A relay operates in one of two modes:

- `signed`: after Noise, require a valid native credential bound to the Noise
  client key and carrying the correct `publisher` or `viewer` role. Until then,
  the catalog is hidden and data operations are denied.
- `public`: accept any Noise client and expose stream metadata. This does not
  grant a content key.

Native credentials contain a format version, issuer, unique serial, subject,
role, validity bounds, the subject's Noise, signing, and key-encapsulation
public keys, and an Ed25519 issuer signature. Long-running sessions disconnect
at credential expiry. The relay reloads a configured signed revocation list
every second and rechecks active subscriptions, so a newly revoked credential
cannot continue receiving data. Invalid replacements preserve the last valid
list. The relay has only CA public material; CA private keys are managed
offline with explicit `gcrelay` PKI commands.

A publisher independently chooses one viewer policy:

- `required`: manual pairing with a two-sided authentication-string check;
- `trusted_ca`: automatically approve viewer identities signed by one of the
  publisher's explicitly configured viewer-approval CAs;
- `open`: approve every requesting identity.

Relay-access and viewer-approval CAs are distinct trust domains. Configuring
the same external CA for both is an explicit operator decision, never an
implicit trust inheritance. `open` still encrypts every stream, but the relay
can request a key as a viewer, so the mode deliberately gives up confidentiality
from a malicious relay.

## Manual pairing

The viewer sends a signed, expiring request bound to the intended publisher,
one exact stream, its device identity, a fresh nonce, and the protocol version.
The relay queues bounded requests while the publisher is offline. The
publisher replies with a signed offer containing its identity and fresh
handshake material.

Both peers derive a transcript hash from the request, offer, both persistent
identities, the relay context, and a domain separator. They independently turn
that hash into the same short authentication string. The viewer and publisher
each ask a yes/no question after the people compare the strings through an
independent channel. Neither application offers a skip action. Only two valid,
signed confirmations for the same transcript make the approval durable.

An approved viewer grant is per device and per stream, and is permanent across
IP and relay changes. IP and the viewer-chosen device name are displayed as
context but are not identity. A revoked viewer/stream grant remains on a deny
list, preventing an old queued request or certificate from silently restoring
that access while leaving other stream grants untouched.

## Stream encryption and authenticity

Every stream consists of keyframe groups. A group starts at an IDR and uses an
independent random content-encryption key. The normal keyframe target is about
four seconds; revocation immediately ends the current group, creates a new key,
and forces an IDR.

Codec configuration, H.264 access units, and cursor batches are AEAD-encrypted.
Canonical object headers are associated data and include version, publisher,
stream, epoch and key-group identities, sequence, timing, kind, random-access
state, codec identifier where applicable, ciphertext length and hash, and a
nonce. The publisher signs the canonical header and ciphertext hash. Nonce
uniqueness is an explicit protocol invariant. There is no plaintext stream
variant and a paired viewer never accepts a downgrade.

For every approved viewer, the publisher seals the group's content key into an
RFC 9180 HPKE envelope. The signed envelope binds publisher, recipient, stream,
epoch, key group, and key identifier. Per-viewer envelopes are intentionally
simple; the expected upper end is about twenty concurrent viewer devices.

The relay stores ciphertext and envelopes together and evicts them as one
group. An already approved viewer can therefore reconnect and play retained or
live content while the publisher is offline. The publisher privately retains
recent group keys and byte/time accounting so it can generate historical
envelopes for a newly approved viewer. History is selected newest-first in
complete groups, independently per stream, and stops when either configured
limit is reached. Defaults are 100 MB and 24 hours per stream.

History envelope generation is asynchronous: live playback may start first and
older authorized groups appear afterward. Revocation prevents future access,
but cannot retract content or keys already delivered to the viewer.

## Native stream protocol

Protocol version 9 uses bounded Postcard control messages over segmented Noise
records. Stream-object format version 2 replaces MPEG-DASH and fMP4 packaging.
The outer media profile has an explicit codec identifier so a later codec does
not require redesigning routing, history, or subscriptions; H.264 Annex-B is
the only 0.6 codec.

Initial object roles are:

- a signed stream descriptor containing public name/source metadata;
- an encrypted epoch descriptor containing codec configuration and dimensions;
- an encrypted media object containing one timestamped H.264 access unit;
- an encrypted compact cursor batch;
- viewer-addressed key envelopes indexed alongside their group.

The relay listens for publishers on port 8900 and viewers on port 8899 by
default. The viewer uses one control connection and one connection per active
subscription, avoiding head-of-line blocking between streams. A subscription
may start live, at the oldest retained group, or at an explicit sequence/time.
The relay catches up from durable storage and then changes gaplessly to a
broadcast tail. A lagged consumer re-anchors from storage instead of silently
losing objects.

All inbound lengths, counts, labels, dimensions, timestamps, and enum values
are bounded and validated before allocation or state mutation. Unknown versions
and codecs fail closed. Canonical decoders reject truncation and trailing data.

## Capture, decoding, and presentation

The publisher retains the portal/PipeWire capture, damage-aware sampling,
OpenH264 encoding, and cursor metadata machinery. Native media publication uses
H.264 Annex-B access units directly rather than wrapping frames in fMP4. Video
and cursor share the publisher's monotonic media clock.

`gcview` separates a GUI-independent session/decode/timeline core from an
eframe/egui shell. Tokio networking and one OpenH264 decoder per active stream
run on background workers. Channels deliver copied RGBA frames and
state changes to the UI, which maintains one texture per tile and paints the
cursor independently.

The viewer provides 1, 2, 4, and 6-stream layouts. It is performance-gated for
four concurrent streams, supports the six-tile layout, and imposes no protocol
stream-count limit. Any tile can become fullscreen. Keyboard controls select a
visible tile, enter/leave fullscreen, and move to the next or previous active
stream. Retained playback has a timeline and an explicit return-to-live action.
Catalog and pairing inboxes refresh periodically. A disconnected subscription
reconnects with bounded backoff from its last decrypted sequence, while both
ciphertext awaiting a key and the in-memory group-key cache have hard limits.

After a signed publisher approval, the viewer durably pins that publisher
identity to the exact stream. A catalog entry that later presents the same
stream under another identity is hidden; relay TOFU and catalog metadata cannot
silently replace the publisher-to-viewer trust decision.

## Retention and durability

The relay uses SQLite WAL storage with full synchronization, atomic object and
envelope transactions, fsync-backed acknowledgement, idempotent retry, bounded
regular-file reads, symlink refusal, startup recovery, and monotonic high-water
marks. Configured hard limits bound concurrent connections, handshake and idle
time, live queues, stream counts, group objects and bytes, envelopes, and
global/per-publisher storage. Limit violations reject the transaction without
advancing the stream high-water mark. Retention is per stream and
evicts complete decodable keyframe groups when either the age or byte limit is
exceeded. Cursor objects and key envelopes cannot outlive their media group.

Pairing queues and envelope indexes are also durable, bounded, expiring, and
safe under crash/replay. Acknowledgement means the corresponding object and
catalog transaction are durable, not merely queued in memory.

Version 1 DASH history is not migrated. A 0.6 relay detects it, moves it to an
explicit incompatible quarantine path without deleting it, and starts a new
version 2 store.

## Local state and metadata exposure

Secret identity, approval, revocation, and retained-key state uses private
regular files with mode `0600`, `O_NOFOLLOW`, bounded reads, atomic replacement,
and directory fsync. Stable private advisory-lock files serialize publisher
state transactions; only one publishing process may own a state directory.
Multi-monitor key history is merged per stream, and pairing offers, decisions,
and retained-key authorizations are persisted in idempotent outboxes before
network delivery. Relay known-host records use the same discipline. Encrypted
state export/import is deferred.

The relay necessarily learns publisher and stream existence, display names,
viewer and publisher network addresses, connection and request timing,
ciphertext sizes, viewer recipient identifiers for envelopes, and requested
streams. Traffic-analysis resistance is not claimed. A malicious relay may
censor service or lie about availability; signed timestamps, sequences, and
publisher heartbeats let the viewer label stale data but cannot restore
availability.

## Runtime dependency boundary

GlacialCast does not require FFmpeg, GStreamer, MediaMTX, or a browser. The
publisher depends on the Linux portal/PipeWire and an H.264 encoder. The viewer
depends on egui/winit and a loadable OpenH264 decoder. Cryptography uses
maintained implementations of Noise XX, Ed25519, RFC 9180 HPKE, HKDF/SHA-256,
and an AEAD; GlacialCast defines composition, canonical messages, and domain
separation but no new primitive.
