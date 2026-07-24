# Glacialcast Goal Completion Audit

Last updated: 2026-07-23.

## Objective

Support PipeWire screen/video streaming at 1-15 fps with an independent mouse
overlay running around 10-30 Hz; verify encrypted and unencrypted viewing
end-to-end; prove transmitted frame bytes match what the viewer renders; and
prefer hardware codecs with CPU fallback only when needed.

## Success Criteria

1. PipeWire capture can send screen/video frames at 1-15 fps.
2. Cursor overlay is independent from the video frame cadence and can operate at
   10-30 Hz.
3. Cursor overlay carries compositor-authoritative position, and cursor
   bitmap/hotspot when supplied.
4. Client-to-server ingest works through the encrypted Noise transport.
5. Browser viewing works for unencrypted frame payloads.
6. Browser viewing works for end-to-end encrypted frame payloads.
7. Viewer-rendered frame bytes are validated against the frame sent over the
   wire.
8. `wayland-video` uses hardware H.264 through VAAPI/DMA-BUF first.
9. CPU encoding/readback is retained only as an explicit fallback/diagnostic
   path.
10. A hard verifier fails when real cursor metadata is missing.

## Prompt-To-Artifact Checklist

| Requirement | Evidence | Status |
| --- | --- | --- |
| PipeWire 1-15 fps capture | `--fps` is parsed as `0.5..=15`; PipeWire cadence is computed in `pipewire_capture_rate`; verifier runs with `--fps 1`. | Implemented |
| Independent 10-30 Hz cursor cadence | `--cursor-hz` drives a separate cursor tick and PipeWire cursor rate; `pipewire_capture_rate(1.0, 30) == 30.0` is covered by client tests; `scripts/verify-cursor-cadence.sh` passed with 1 frame and 10 cursor messages at 1 fps / 15 Hz. | Verified for app-layer transport |
| Real cursor source | Client requests `SPA_META_Cursor`, parses cursor position, bitmap, and hotspot, and sends cursor messages separately. | Implemented, not environment-verified |
| Cursor bitmap/hotspot transport | `CursorBitmap` is part of `CursorMessage`; client decodes `spa_meta_bitmap`; browser renders PNG with hotspot transform; server archives bitmap fields; protocol test `noise_socket_round_trips_frame_status_ack_then_cursors` verifies cursor messages survive Noise/bincode framing after frame ACKs. | Verified for transport and storage |
| Missing cursor metadata fails closed | `--require-cursor-metadata` holds frames during grace and exits if buffers lack `SPA_META_Cursor`; verifier script checks server cursor messages. | Implemented and failing correctly on current niri |
| Encrypted ingest transport | Protocol uses Noise handshake/socket framing for client/server messages. | Implemented |
| End-to-end frame encryption | `viewer_key_b64` enables AES-GCM payload encryption; protocol tests cover encrypt/decrypt and clear payload behavior; `scripts/verify-frame-integrity.sh` verifies an encrypted retained frame with viewer-side WebCrypto. | Verified |
| Unencrypted browser viewing | `--no-viewer-key` clear frame path is supported; `scripts/verify-frame-integrity.sh` verifies a clear retained frame with viewer-side hash logic; `scripts/verify-browser-frame-render.sh` drives the dashboard in headless Chromium and verifies the displayed clear image blob hash. | Verified |
| Encrypted browser viewing | Browser accepts viewer key and decrypts AES-GCM image frames before rendering; `scripts/verify-frame-integrity.sh` exercises the same WebCrypto decrypt/hash path in Node; `scripts/verify-browser-frame-render.sh` verifies keyed dashboard rendering in Chromium. | Verified |
| Viewer sees transmitted frames | Frame manifests carry `content_hash`; browser checks rendered/decrypted bytes with `fastContentHash`; `scripts/verify-frame-integrity.sh` verifies clear and encrypted payloads against manifest hashes; `scripts/verify-browser-frame-render.sh` hashes the actual blob bytes backing the rendered `<img>`. | Verified |
| Live H.264 viewer transport | Browser UI uses WebRTC for active video streams; viewer joins trigger a keyframe request, and client/server startup gates suppress incomplete access units until SPS/PPS/IDR is available. `scripts/verify-video-webrtc.sh` verifies the RTP random-access point, while `scripts/verify-browser-frame-render.sh` verifies decoded, painted pixels and sub-three-second reload recovery in Chrome and Firefox. | Browser-verified |
| Hardware-first video | `wayland-video` with `ffmpeg-vaapi` uses DMA-BUF frames and VAAPI H.264 backend first; `scripts/verify-wayland-video-hardware.sh` requires a VAAPI/DMA-BUF attempt before accepting video output. | Verified |
| Reduced CPU fallback | If DMA-BUF VAAPI fails but `h264_vaapi` is usable, the client restarts with CPU-readable PipeWire and uploads converted frames to VAAPI for hardware H.264 before using full software H.264. | Implemented, verifier distinguishes path |
| CPU fallback | Software H.264 and CPU-readable PipeWire paths are fallback/diagnostic paths after VAAPI failure or explicit mode; `scripts/verify-wayland-video-hardware.sh` accepts fallback only after observing the VAAPI failure path unless strict hardware mode is enabled. The full software path now tries `h264_nvenc`, then `libx264`, `libopenh264`, then generic `h264`, and falls through if an advertised encoder cannot actually open. | Verified |
| Direct niri/Mutter ScreenCast backend | `--screencast-backend mutter --monitor-name <connector>` calls `RecordMonitor` with metadata cursor mode. | Implemented |
| Upstream/debug evidence | `docs/wayland-cursor-metadata-upstream-report.md` captures reproducer, environment, niri logs, and observed buffer metadata. | Complete |

## Current Verification Commands

Green gates run in this workspace:

```sh
scripts/verify-prerequisites.sh
cargo fmt --check
cargo test --workspace --features ffmpeg-vaapi
cargo clippy --workspace --all-targets --features ffmpeg-vaapi -- -D warnings
bash -n scripts/verify-cursor-cadence.sh scripts/verify-frame-integrity.sh scripts/verify-browser-frame-render.sh scripts/verify-wayland-video-hardware.sh scripts/verify-wayland-cursor-metadata.sh
scripts/verify-cursor-cadence.sh
scripts/verify-frame-integrity.sh
scripts/verify-browser-frame-render.sh
scripts/verify-video-webrtc.sh
GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 scripts/verify-wayland-video-hardware.sh
```

Recent verifier output:

```text
PASS: cargo test --workspace --features ffmpeg-vaapi (49 tests)
PASS: server received 1 frame(s) and 10 cursor messages; cursor cadence is independent of frame cadence
PASS: clear and encrypted dashboard image frames rendered in Google Chrome with matching displayed blob hashes
PASS: live H.264 decoded and painted non-uniform 1280x720 pixels in Google Chrome and Firefox; reload recovery completed within 3 seconds
PASS: WebRTC viewer received decodable H.264 random access point after 155 RTP packets (161926 payload bytes, 3 access units, nal_types=[7, 8, 5, ...])
PASS: Wayland capture attempted DMA-BUF VAAPI and CPU-upload VAAPI before delivering H.264 through the software fallback
```

The Fedora FFmpeg 8 feature build was also validated against matching Fedora 44
development headers extracted into a temporary local prefix. The host still
needs the packages listed in the README installed system-wide before ordinary
feature builds and the real Wayland hardware gate can run without that temporary
`PKG_CONFIG_PATH`.

The hard real-cursor gate still fails on this niri session:

```sh
env \
  GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
  GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
  GLACIALCAST_VERIFY_CAPTURE=wayland-video \
  scripts/verify-wayland-cursor-metadata.sh
```

Observed failure:

```text
DIAG: NIRI_SOCKET is set but not reachable: /run/user/1000/niri.wayland-1.7608.sock
DIAG: using discovered niri socket for IPC checks: /run/user/1000/niri.wayland-1.1294988.sock
{"cli":"26.04 (8ed0da4)","compositor":"26.04 (8ed0da4)"}
niri IPC: no cursor-position or pointer-position command is advertised
DIAG: cursor metadata mode was requested, but PipeWire buffers did not include SPA_META_Cursor
DIAG: first PipeWire buffer metadata summary contained only SPA_META_Busy
DIAG: direct Mutter/niri ScreenCast opened successfully; this points at compositor-side cursor metadata emission
```

Upstream documentation checked on 2026-05-06:

- <https://github.com/niri-wm/niri/wiki/Screencasting> says niri's primary
  screencasting interface is portals plus PipeWire, with wlr-screencopy as an
  alternative for compatible tools. It does not document a separate
  `SPA_META_Cursor` cursor metadata stream.
- <https://github.com/niri-wm/niri/wiki/Configuration:-Debug-Options>
  documents `debug { disable-cursor-plane }`, which renders the cursor together
  with the rest of the frame. That can make cursor visibility more reliable for
  embedded-cursor video, but it is not an independent overlay and cannot satisfy
  the 10-30 Hz cursor cadence requirement when the video stream itself is
  running at a lower frame rate.

## Remaining Gap

The goal is not complete because the current compositor/session does not emit a
usable compositor-authoritative cursor source:

- XDG portal advertises metadata mode (`AvailableCursorModes = 7`), but buffers
  still lack `SPA_META_Cursor`.
- Direct niri/Mutter ScreenCast accepts `cursor-mode = Metadata`, but buffers
  still lack `SPA_META_Cursor`.
- `ext_image_copy_capture_manager_v1` is absent.
- `scripts/verify-wayland-cursor-metadata.sh` now reports a stale or
  unreachable `NIRI_SOCKET` explicitly and auto-discovers the live socket under
  `/run/user/$(id -u)` for niri IPC checks.
- With the live socket, `niri msg --help` still advertises no
  cursor-position or pointer-position command, and `niri msg -j event-stream`
  reports workspace/window/cast/config events rather than pointer-motion or
  global cursor state.
- `wayland-info` shows only cursor-shape, relative-pointer, and
  virtual-pointer protocols beyond screencopy; those do not expose global
  compositor cursor position/shape for an observer.
- The XDG RemoteDesktop portal exposes pointer notification methods for input
  injection, not cursor observation.

Until one of those sources becomes available, Glacialcast cannot prove the
required independent 10-30 Hz cursor overlay end-to-end in this environment.

## Completion Decision

Do not mark the goal complete yet. The implementation is ready to consume and
transport independent cursor metadata, including bitmap/hotspot data, but the
real compositor metadata gate has not passed.
