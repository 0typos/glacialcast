# GlacialCast 0.2 Architecture

## Product Contract

GlacialCast is a low-bandwidth, end-to-end-encrypted Wayland screen viewer. It
captures through the XDG Desktop Portal and PipeWire, publishes video at a very
low frame rate, publishes cursor updates independently at a higher rate, keeps
a bounded replay window, and can copy the same stream files to an offline
machine for playback.

The first 0.2 release is deliberately video-only and view-only. Remote input and
audio are outside the MVP.

## MVP Requirements

The MVP is complete when all of the following are true:

1. The client captures a selected Wayland monitor or window through the XDG
   Desktop Portal and PipeWire.
2. Video defaults to 1 frame per second. A captured frame is available to an
   already-connected viewer within 250 milliseconds under local test
   conditions.
3. Cursor position, visibility, hotspot, and bitmap changes are carried
   independently of video at up to 30 updates per second.
4. The client produces an MPEG-DASH presentation made from fragmented MP4 H.264
   media. Every segment begins at a decodable random-access point.
5. Media samples use MPEG Common Encryption (`cenc`). The relay never receives
   the content key. Firefox and Chromium decrypt through the
   `org.w3.clearkey` EME key system.
6. Cursor records use authenticated encryption and share the media timebase.
7. The server relays opaque stream objects and retains them using both a maximum
   age and a maximum byte count per stream.
8. A reconnecting viewer can begin at the newest retained random-access point
   and scrub through the retained window.
9. A self-contained `glacialcast-offline` executable serves a copied stream
   bundle on loopback for playback by an installed Firefox or Chromium without
   Internet access.
10. The runtime does not depend on FFmpeg, GStreamer, MediaMTX, or a third-party
    DASH player.
11. The capture path detects whether the selected portal backend supports
    cursor metadata. Missing metadata is reported as an unmet capability rather
    than silently claiming independent cursor support.

## System Shape

```text
XDG portal / PipeWire
       |
       +-- raw video --> damage-aware sampler --> H.264 encoder --> fMP4/CENC
       |
       +-- cursor metadata ------------------------------> AEAD cursor records
                                                                  |
                                                        stream object protocol
                                                                  |
                                  +-------------------------------+-------------+
                                  |                                             |
                         authenticated relay                         stream bundle files
                       + bounded opaque history                     + signed manifest
                                  |                                             |
                                  +----------- Firefox/Chromium ----------------+
                                                MSE + EME
                                          independent cursor overlay
```

The server is trusted for availability and authorization, but not with captured
content. The ingest channel uses a pinned Noise NK server identity to encrypt
the ingest token and stream objects in transit. In the Internet profile, Caddy
terminates browser HTTPS and proxies to a loopback-only application listener.
Content encryption remains necessary because browser transport encryption
terminates at the server.

Browser access uses independently rotatable high-entropy access tokens. A
successful login creates a signed, expiring, `HttpOnly`, `Secure`,
`SameSite=Strict` session. Viewer principals are scoped to authenticated
publisher identities; administrators can manage all streams. WebSocket
upgrades and mutations require the exact configured public origin, and
cookie-authorized mutations also require a session-bound CSRF value. A
principal's token, role, or scope change changes its session version and
invalidates prior sessions after configuration reload through a relay restart.

HTTP requests, browser WebSockets, publisher connections, login attempts, and
authenticated request rates are bounded. Per-principal WebSocket and
per-source-address ingest limits prevent one credential or host from consuming
the global connection pools. Noise handshakes and idle publisher connections
have deadlines. The publisher resolves DNS names and reconnects with capped
exponential backoff and jitter. Health endpoints and administrator-only
counters expose availability and rejection signals without exposing stream
contents or credentials.

## Media Profile

The initial interoperable media profile is:

- ISO Base Media File Format initialization and media fragments
- H.264/AVC constrained baseline where the encoder supports it
- MPEG Common Encryption using the `cenc` AES-CTR scheme
- 90,000 tick media timescale
- 1 FPS default video cadence
- no B-frames
- four-second group of pictures and segment target
- one complete `moof`/`mdat` fragment per published frame
- IDR plus SPS and PPS at the start of each segment

The configured video rate is the maximum sampling and change-notification
cadence. The client requests PipeWire video-damage regions, falls back to
fingerprinting CPU-readable pixels, and treats DMA-BUF content without damage
metadata as changed. Unchanged content is coalesced into a variable-duration
predicted sample and emitted on the bounded idle heartbeat. If content changes
while such a sample is pending, the client publishes the completed idle span
before immediately publishing the changed frame. This keeps retained history
continuous without resending static pixels every video tick. Independent live
cursor rendering always uses the newest cursor event and does not wait for the
media clock.

The relay may assemble four published fragments into one retained `.m4s`
object without delaying live notification. Segment timeline duration spans
from the first sample start through the final sample end, including any sparse
publication interval.

The MPD uses a dynamic `SegmentTemplate` and `SegmentTimeline` for live viewing.
A finalized copy uses a static MPD. GlacialCast implements the constrained
profile it generates instead of embedding a general DASH player.

## Content Keys and Integrity

Each capture epoch has a random 128-bit CENC content key and key identifier.
During the MVP, the client owner distributes the URL-safe base64 key to an
authorized viewer out of band. The key is never included in an ingest message,
server response, URL, or log record.

The browser supplies the key to EME Clear Key. Clear Key is not a DRM boundary;
an authorized viewer can access the content key. The security property is that
the relay, archive, and unauthorized network participants cannot decrypt the
capture.

CENC does not authenticate media samples. A separate epoch authentication key
therefore authenticates the presentation index and object hashes. Cursor
records use AES-256-GCM with stream ID, epoch, sequence, media timestamp, source
dimensions, and record type as associated data. A later release can replace
manual key distribution with per-viewer public-key envelopes without changing
the stored media profile.

## Stream Objects

The client publishes versioned objects:

- `epoch`: stream metadata, dimensions, codec configuration, key identifier,
  and encrypted-content declarations
- `init`: an fMP4 initialization segment
- `media`: one independently addressable media fragment
- `cursor`: an authenticated batch of cursor events
- `index`: timing, hashes, and random-access metadata
- `end`: a clean epoch boundary

Object headers expose only routing and retention information: stream identity,
object kind, epoch, sequence, media timestamp, duration, random-access status,
and payload length. Captured pixels, cursor coordinates, and cursor bitmaps are
opaque to the relay.

The protocol has explicit size limits and rejects unknown versions and invalid
dimensions before allocating payload storage.

Ingest control envelopes use Postcard's documented stable wire format behind
the GlacialCast protocol-version gate. Media payloads remain opaque byte
strings and are not re-encoded by the relay.

The server persists one Noise static keypair in its data directory with private
file mode `0600`. Clients pin the URL-safe base64 public key. A client never
sends its ingest token until the Noise NK handshake has authenticated the
server, preventing credential disclosure to an accidental or malicious relay
endpoint. Replacing the server identity is an explicit client configuration
change.

Cursor batches use a compact, versioned binary payload. Position-only events
do not repeat bitmap pixels; a bitmap is included only when its identity or
content changes. Batches flush often enough to keep live cursor latency below
250 ms without paying per-event object and authentication overhead. Cursor
events are validated for ordered timestamps, bounded source coordinates,
visibility-state consistency, bitmap dimensions, hotspots, exact RGBA length,
and authenticated stream/epoch/timing context before use.

## Retention

Retention is evaluated per stream. Objects are evicted when either:

- their segment is older than the configured maximum age, or
- total retained bytes exceed the configured maximum.

The default is 30 minutes and 512 MiB. Eviction operates on decodable segment
groups and retains the epoch initialization object required by every surviving
group. Cursor batches are evicted with their corresponding media time range,
and cursor-only groups are subject to the same age and byte limits.

Acknowledgement means an object is durably written and indexed, not merely
queued in memory.

The durable index uses an independent mutex and checksummed append journal per
stream. A newly accepted object is acknowledged only after both its immutable
payload file and catalog transaction have been synchronized. Atomic catalog
snapshots periodically compact the journal; recovery tolerates and truncates
only an incomplete final record, rejects corrupt complete records, and safely
ignores transactions already represented by a completed snapshot. Independent
streams do not serialize their filesystem work through one global catalog
mutex.

## Cursor Timing

Video and cursor events use the same monotonic capture clock. Live cursor
rendering advances from a viewer-side monotonic anchor rather than depending on
`HTMLMediaElement.currentTime` at the sparse buffered edge. Historical cursor
rendering follows the media playhead.

The viewer maps cursor coordinates into the actual contained video rectangle,
including letterbox and pillarbox offsets. A cursor bitmap is sent only when its
identity or pixels change, with a periodic refresh so a retained-history viewer
can recover the current shape. The browser converts a bitmap to a canvas surface
once and reuses it; unchanged cursor states do not rebuild image data every
animation frame.

Metadata cursor mode is mandatory for the independent overlay. Embedded cursor
mode may be exposed as an explicitly degraded diagnostic option, but it does not
satisfy the MVP capability.

## Offline Object Stream

Every authenticated stream object can be wrapped in a standalone `GCO1`
portable file containing its public header and opaque payload. Files are named
by monotonically increasing object sequence and are independently verifiable,
so a one-way file transport can copy them incrementally without understanding
the media or possessing the viewer key.

`glacialcast-offline mirror` materializes these files atomically from a relay.
After each pass it atomically publishes a versioned
`glacialcast-transfer.json` containing the stream identity, exact object
headers, lengths, and SHA-256 checksums. Existing valid objects are skipped, so
mirroring resumes at object granularity. `glacialcast-offline verify` checks
the manifest and reports missing or unexpected filenames, allowing files to
arrive out of order through any out-of-band mechanism.
`glacialcast-offline serve` watches a received directory and embeds the complete
local viewer and MPEG-DASH endpoints in one binary. The offline host therefore
needs only that binary, the object files, and an installed Firefox or Chromium
browser; it does not need Internet access or third-party JavaScript. The
offline catalog accepts only bounded regular `.gco` files, rejects duplicate
stream/sequence identities, and ignores symlinks and incomplete transfer files.
The service binds to loopback by default and requires an explicit
`--allow-non-loopback` override before exposing the key-entry viewer to a
trusted network.

## Runtime Dependency Boundary

The intended runtime boundary includes:

- XDG Desktop Portal, D-Bus, PipeWire, and SPA for capture
- VA-API for the initial Intel/AMD hardware encoder
- focused, audited cryptography and HTTP/WebSocket libraries
- Firefox or Chromium for browser playback

FFmpeg, GStreamer, MediaMTX, WebRTC, and dash.js are not part of the target
runtime. The project may use external conformance tools during development
without shipping them.

When VA-API H.264 encoding is unavailable, automatic mode falls back to the
focused OpenH264 software encoder. An operator can require either backend
explicitly. NVIDIA hardware encoding is not required for 0.2.

On Intel and AMD render nodes that expose both constrained-baseline H.264
encoding and the VA-API video-processing entrypoint, the Wayland path imports
the compositor's RGB DMA-BUF and converts/scales it into an owned NV12 GBM
surface before encoding. The client does not return the PipeWire buffer to its
pool until that GPU operation has synchronized. If either capability is absent,
the portal stream requests CPU-readable buffers instead.

## Compatibility Matrix

Release verification covers:

- current Firefox on Linux
- current Chromium on Linux
- XDG portal implementations used by GNOME and KDE Plasma
- the wlroots portal family
- niri's supported portal path

The browser gate verifies MSE fragmented-MP4 playback, EME Clear Key decryption,
live append, reconnect from a retained random-access point, history seeking, and
cursor synchronization. The compositor gate records portal source selection,
PipeWire buffer types, video damage metadata, and cursor metadata availability.

## Completed Replacement

The 0.2 vertical slice replaced the 0.1 transport in this order:

1. Introduce the format and cryptographic primitives.
2. Add opaque relay and storage.
3. Add Firefox-first DASH playback.
4. Add client packaging and direct encoding.
5. Add offline bundle playback.
6. Remove WebRTC, Noise NN, and FFmpeg runtime paths.

This is a breaking protocol and configuration change. Version 0.2 does not
promise compatibility with retained 0.1 media or clients.
