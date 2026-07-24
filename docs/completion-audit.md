# GlacialCast 0.2 Completion Audit

Last updated: 2026-07-24.

## Decision

The 0.2 MVP implementation is complete for the supported encrypted DASH path.
The synthetic transport, live browser, retained history, and portable offline
paths pass end to end in both Firefox and Chromium.

Real Wayland cursor metadata and VA-API/DMA-BUF acceptance remain
host-dependent gates. They could not be run from the final audit shell because
it had no `WAYLAND_DISPLAY` and no `/dev/dri` render node. The repository
contains strict scripts for running both gates in a suitable compositor
session.

## Requirement Evidence

| Requirement | Evidence | Status |
| --- | --- | --- |
| Wayland capture | Native XDG Desktop Portal/PipeWire capture supports monitor/window selection; niri's Mutter-compatible API is an alternative backend. Capture and buffer negotiation have focused unit coverage. | Implemented; host gate pending |
| Very low video cadence | `--fps` accepts 0.5 through 15 and defaults to 1. The DASH test and production capture share the same sampler and packager. | Verified |
| Low live latency | `scripts/verify-dash-e2e.sh` rejects periodic capture-to-durable-relay acknowledgement above 250 ms. The latest maximum was 45 ms. The browser gate rejects live announcement-to-MSE-append above 250 ms; latest results were 16 ms in Firefox and 13 ms in Chromium. | Verified under local synthetic conditions |
| Independent cursor | Video and cursor timers are separate. Cursor batches flush every 200 ms and carry their own media timestamps. The encrypted browser gate decoded dozens of cursor events while sparse video fragments arrived. | Verified synthetically |
| Real cursor metadata | `dash-wayland` requests and parses `SPA_META_Cursor`, including position, visibility, bitmap, and hotspot. `--require-cursor-metadata` fails closed when the compositor omits it. | Implemented; compositor gate pending |
| MPEG-DASH/fMP4 | The client emits an initialization segment plus immediate encrypted `moof`/`mdat` fragments and a dynamic MPD. Segment boundaries require an IDR. | Verified |
| Server-blind E2EE | Media samples use CENC AES-CTR; cursor records use AES-256-GCM; every object is HMAC authenticated. Viewer keys are not sent to or logged by the relay. | Verified |
| Authenticated ingest | Protocol version 5 uses Noise NK with a persistent `0600` relay identity. Clients pin the public key before sending tokens or objects. | Verified |
| Bounded history | The relay evicts complete segment groups by both age and bytes, retains required epoch metadata and a persistent ingest sequence high-water mark, uses arrival time rather than UUID ordering, and reapplies policy at restart. | Verified |
| Firefox primary target | Clear Key EME, MSE append, painted 320×180 video, live updates, and cursor decryption passed in Playwright Firefox. | Verified |
| Chromium target | The same live checks passed in Playwright Chromium. | Verified |
| Portable file stream | Relay objects mirror atomically to versioned `.gco` files. A following mirror and the self-contained offline server delivered continued playback without Internet access. | Verified |
| Offline browser playback | Copied objects decoded and painted in both Firefox and Chromium. Latest live append results were 3 ms and 7 ms respectively after offline file announcements. | Verified |
| Intel/AMD hardware path | The direct VA-API encoder and PipeWire DMA-BUF import/VPP conversion are implemented; buffer leases remain held until conversion synchronizes. | Unit/build verified; hardware gate pending |
| Software fallback | Auto mode falls back to dynamically loaded OpenH264; no FFmpeg/GStreamer runtime is present. The complete synthetic gate uses this path. | Verified |
| Focused dependencies | The runtime has no MediaMTX, FFmpeg, GStreamer, WebRTC, dash.js, or bincode dependency. Protocol envelopes use Postcard and opaque media is not re-encoded by the relay. | Verified |

## Green Gates

The final repository gate is:

```sh
scripts/verify-prerequisites.sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps
bash -n scripts/*.sh
scripts/verify-dash-e2e.sh
```

Browser playback is enabled when a Playwright installation is available:

```sh
GLACIALCAST_VERIFY_BROWSERS=firefox,chromium \
GLACIALCAST_VERIFY_OFFLINE_BROWSERS=firefox,chromium \
scripts/verify-dash-e2e.sh
```

The current workspace has 60 unit tests: 32 client, 7 DASH, 1 offline, 7
protocol, and 13 server tests.

## Environment-Specific Gates

Run these inside the target graphical session:

```sh
scripts/verify-wayland-cursor-metadata.sh
scripts/verify-wayland-video-hardware.sh
```

For direct niri capture:

```sh
GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
scripts/verify-wayland-cursor-metadata.sh

GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
GLACIALCAST_VERIFY_REQUIRE_DMABUF=1 \
scripts/verify-wayland-video-hardware.sh
```

The cursor gate requires both encrypted media and a cursor object from the real
PipeWire stream. The hardware gate requires the VA-API backend; optional strict
mode also requires a compositor DMA-BUF to reach VA-API import.

## Deployment Boundary

The current deployment target is a trusted LAN. Noise protects and
authenticates ingest, while viewer content remains end-to-end encrypted. The
HTTP management and viewer surface does not yet provide viewer authorization,
HTTPS termination, rate limiting, or Internet-facing operational hardening.
Those are post-MVP requirements and must be added before public exposure.

The relay can still observe routing metadata, dimensions, MIME types, timing,
object sizes, and activity. E2EE protects screen pixels and cursor contents,
not traffic analysis or availability.
