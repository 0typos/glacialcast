# GlacialCast Robustness and Performance Review

Last updated: 2026-07-24.

## Conclusion

The current architecture is appropriate for GlacialCast's stated primary use:
one or a small number of very-low-frame-rate Wayland captures on a trusted LAN,
with interactive viewing, bounded history, end-to-end content encryption, an
independent cursor, and one-way transfer to an offline viewer.

The combination of PipeWire capture, focused H.264/fMP4 generation, CENC media,
AES-GCM cursor records, Noise NK ingest, an opaque relay, MSE/EME playback, and
portable object files serves those requirements with one media representation.
WebRTC would offer a more standard Internet real-time transport, but it would
not directly provide the required retained/offline file stream and would add a
larger runtime dependency boundary. A general media server or DASH player would
reduce custom code but conflict with the project's dependency goals.

The subsequent Internet-readiness work added the missing deployment boundary:
loopback-only application HTTP behind Caddy-managed HTTPS, viewer/admin access
tokens, publisher-scoped authorization, signed sessions, exact origin and CSRF
checks, request and connection limits, authentication throttling, monitoring,
and documented access/E2EE key rotation. Clear Key supplies browser decryption,
not DRM or access control.

## Correctness and Robustness Findings

The hardening pass addressed the highest-risk defects found in the review:

- PipeWire cursor hide transitions are preserved, malformed cursor allocations
  and bitmaps are rejected, coordinates are bounded, and the latest movement is
  no longer permanently lost to callback-level rate limiting.
- Cursor bitmaps remain raw shared RGBA in the capture path instead of taking a
  PNG/base64 encode/decode round trip. The wire format and browser parser now
  enforce the same size, timeline, coordinate, visibility, hotspot, and
  authenticated-context invariants.
- The browser serializes live processing, reconciles retained headers after
  connection gaps, bounds media/cursor history, caches cursor surfaces, and
  proves paint/move/hide/restore behavior in Firefox and Chromium.
- Noise segments reject inconsistent totals, gaps, replayed offsets,
  zero-progress chunks, oversized declarations, caller-specific control-message
  limits, and noncanonical Postcard messages. Portable files reject every
  tested truncation and trailing data.
- Relay storage confines catalog entries to exact per-stream object paths,
  rejects symlinks, corruption, size mismatches, media chunk gaps/overlap, and
  no-clobber publication conflicts. Cursor-only groups now obey retention.
- Offline catalogs accept only bounded regular files, enforce unique
  stream/sequence identities, update atomically in memory, and reject malformed
  media chunk sets.
- The authenticated recovery gate proves invalid-token rejection, persistent
  Noise identity, stable stream assignment, contiguous sequence recovery, new
  epoch creation, and durable high-water state across a forced relay crash and a
  second restart.

The wire protocol uses Postcard. There is no bincode, FFmpeg, GStreamer,
MediaMTX, WebRTC, or third-party DASH-player dependency in the runtime.

## Test and Coverage State

The normal Rust suite increased from 60 to 130 defined tests, of which 129 run
in the ordinary debug profile and one performance test runs explicitly in
release mode:

| Area | Tests |
| --- | ---: |
| Client and Wayland/cursor capture | 42 |
| DASH, fMP4, CENC, and cursor format | 16 |
| Offline mirror/viewer | 10 |
| Protocol and daemon control | 24 |
| Relay, authorization, and storage | 38 |
| Whole Rust workspace | 130 |

Three checked rustdoc examples cover epoch-key derivation, authenticated object
construction, and byte-size parsing. The current coverage run measured 57.89%
line coverage. The browser core has another 14 JavaScript tests. Multi-process
gates cover live ingest, portable mirroring, offline serving, authentication,
crash/restart, and optional Firefox/Chromium playback. The lower client and
server-main coverage is concentrated in process orchestration,
D-Bus/PipeWire/VA-API integration, and HTTP wiring; those paths are better
represented by the process and host-specific gates than by the current unit
coverage report.

## Performance Results

`scripts/verify-performance.sh` runs optimized probes with conservative
regression floors. On an AMD Ryzen Threadripper 7970X host, the observed results
were:

| Path | Observed | Gate floor |
| --- | ---: | ---: |
| Cursor AES-GCM encode/decode round trip | 827 MiB/s | 5 MiB/s |
| CENC fMP4 fragment generation | 812 MiB/s | 10 MiB/s |
| Authenticated portable object round trip | 294 MiB/s | 10 MiB/s |
| Durable relay object persistence at 1,000 retained objects | 883 objects/s | 10 objects/s |

These numbers are host and filesystem dependent; the floors, not the exact
measurements, are the repeatable contract. At the maximum configured 15 video
frames per second plus five cursor batches per second, the measured persistence
path has substantial local headroom. The intended default is much lower.

The principal performance improvement was browser and capture cursor handling:
raw bitmap data is shared in the client, and the browser creates one reusable
surface per bitmap rather than allocating `ImageData` and `OffscreenCanvas`
objects every animation frame. Live cursor batches are merged in order and
history is pruned with relay retention.

## Remaining Risks and Next Architecture Thresholds

- Real cursor correctness still depends on compositor/portal
  `SPA_META_Cursor` behavior. Run the compositor gate on GNOME, KDE, wlroots,
  and niri targets; this shell has no `WAYLAND_DISPLAY`.
- The direct VA-API/DMA-BUF path needs the hardware gate on representative
  Intel and AMD render nodes; this shell has no `/dev/dri`.
- The relay rewrites a JSON catalog after each durable object and protects the
  in-memory stream map with one mutex. It passes the current low-rate gate, but
  an append journal or transactional per-stream index and per-stream locking
  should replace it before long-retention, high-rate, or multi-tenant service.
- Client and server executables contain substantial logic directly in
  `main.rs`. Moving orchestration into library modules would enable focused
  HTTP/ingest state-machine tests and improve coverage without process spawning.
- The custom constrained fMP4/CENC and viewer code intentionally avoids large
  dependencies, but that makes browser interoperability tests and format
  fuzzing permanent maintenance requirements. Fuzz targets for portable,
  cursor, Noise-segment, and catalog parsers are the next useful test layer.
- E2EE does not hide timing, dimensions, object sizes, activity, or availability
  from the relay. Internet deployment should document this traffic-analysis
  boundary explicitly; `internet-deployment.md` now does.

## Repeatable Commands

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny -L error check
cargo doc --workspace --no-deps
node scripts/test-viewer-core.mjs
scripts/verify-dash-e2e.sh
scripts/verify-ingest-recovery.sh
scripts/verify-internet-security.sh
scripts/verify-internet-browser.sh
scripts/verify-performance.sh
cargo llvm-cov --workspace --summary-only
```

Enable the live and offline browser matrix as documented in
`completion-audit.md`. Run the Wayland cursor and VA-API scripts inside the
target graphical session.
