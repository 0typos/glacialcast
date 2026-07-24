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
9. A self-contained `glacialcast-viewer` executable serves a copied stream
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
       +-- raw video --> 1 FPS sampler --> H.264 encoder --> fMP4/CENC packager
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
content. TLS protects deployment credentials and server identity. Content
encryption remains necessary because TLS terminates at the server.

## Media Profile

The initial interoperable media profile is:

- ISO Base Media File Format initialization and media fragments
- H.264/AVC constrained baseline where the encoder supports it
- MPEG Common Encryption using the `cenc` AES-CTR scheme
- 90,000 tick media timescale
- 1 FPS default video cadence
- no B-frames
- four-second group of pictures and segment target
- one complete `moof`/`mdat` fragment per captured frame
- IDR plus SPS and PPS at the start of each segment

The client sends each completed fragment immediately. The relay may assemble
four fragments into one retained `.m4s` object without delaying the live
notification. An unchanged desktop still emits a small predicted frame at the
configured cadence for the MVP so the browser media clock has continuous
samples.

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

Cursor batches use a compact, versioned binary payload. Position-only events
do not repeat bitmap pixels; a bitmap is included only when its identity or
content changes. Batches flush often enough to keep live cursor latency below
250 ms without paying per-event object and authentication overhead.

## Retention

Retention is evaluated per stream. Objects are evicted when either:

- their segment is older than the configured maximum age, or
- total retained bytes exceed the configured maximum.

The default is 30 minutes and 512 MiB. Eviction operates on decodable segment
groups and retains the epoch initialization object required by every surviving
group. Cursor batches are evicted with their corresponding media time range.

Acknowledgement means an object is durably written and indexed, not merely
queued in memory.

## Cursor Timing

Video and cursor events use the same monotonic capture clock. Live cursor
rendering advances from a viewer-side monotonic anchor rather than depending on
`HTMLMediaElement.currentTime` at the sparse buffered edge. Historical cursor
rendering follows the media playhead.

The viewer maps cursor coordinates into the actual contained video rectangle,
including letterbox and pillarbox offsets. A cursor bitmap is sent only when its
identity or pixels change.

Metadata cursor mode is mandatory for the independent overlay. Embedded cursor
mode may be exposed as an explicitly degraded diagnostic option, but it does not
satisfy the MVP capability.

## Runtime Dependency Boundary

The intended runtime boundary includes:

- XDG Desktop Portal, D-Bus, PipeWire, and SPA for capture
- VA-API for the initial Intel/AMD hardware encoder
- focused, audited cryptography and HTTP/WebSocket libraries
- Firefox or Chromium for browser playback

FFmpeg, GStreamer, MediaMTX, WebRTC, and dash.js are not part of the target
runtime. The project may use external conformance tools during development
without shipping them.

When VA-API H.264 encoding is unavailable, the MVP reports the missing
capability and can expose the existing sparse-image diagnostic path. NVIDIA
hardware encoding is not required for 0.2.

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

## Replacement Strategy

The 0.1 paths remain available only while the new vertical slice is being
verified. Removal order is:

1. Introduce the format and cryptographic primitives.
2. Add opaque relay and storage.
3. Add Firefox-first DASH playback.
4. Add client packaging and direct encoding.
5. Add offline bundle playback.
6. Remove WebRTC, Noise NN, and FFmpeg runtime paths.

This is a breaking protocol and configuration change. Version 0.2 does not
promise compatibility with retained 0.1 media or clients.
