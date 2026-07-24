# GlacialCast 0.4 Completion Audit

Last updated: 2026-07-24.

## Decision

The 0.4 implementation is complete for the supported encrypted DASH path,
managed viewer access, checksummed offline transfer, and documented Internet
deployment and release profiles. The deterministic full quality gate passes at
version 0.4.0. Prior Firefox and Chromium browser gates validate the live and
portable viewers; the release policy requires rerunning that matrix for each
candidate artifact.

Real Wayland cursor metadata and VA-API/DMA-BUF acceptance remain
host-dependent gates. They could not be run from the final audit shell because
it had no `WAYLAND_DISPLAY` and no `/dev/dri` render node. The repository
contains strict scripts for running both gates in a suitable compositor
session.

## Requirement Evidence

| Requirement | Evidence | Status |
| --- | --- | --- |
| Wayland capture | Native XDG Desktop Portal/PipeWire capture supports monitor/window selection; niri's Mutter-compatible API is an alternative backend. Capture and buffer negotiation have focused unit coverage. | Implemented; host gate pending |
| Very low video cadence | `--fps` accepts 0.5 through 15 and defaults to 1. PipeWire damage metadata or a CPU-frame fingerprint suppresses unchanged samples, while a bounded idle heartbeat preserves timeline progress. Static, typing, scroll, and motion profiles have separate traffic ceilings. | Verified |
| Low live latency | `scripts/verify-dash-e2e.sh` rejects periodic capture-to-durable-relay acknowledgement above 250 ms. The final maximum was 46 ms. The browser gate rejects live announcement-to-MSE-append above 250 ms; the final live results were 13 ms in Firefox and 2 ms in Chromium. | Verified under local synthetic conditions |
| Independent cursor | Video and cursor timers are separate. Cursor batches flush every 200 ms and carry their own media timestamps. Live and offline Firefox/Chromium gates require the overlay to paint, move independently, hide, and reappear. | Verified synthetically |
| Real cursor metadata | `dash-wayland` requests and parses `SPA_META_Cursor`, including position, visibility, bitmap, and hotspot. `--require-cursor-metadata` fails closed when the compositor omits it. | Implemented; compositor gate pending |
| MPEG-DASH/fMP4 | The client emits an initialization segment plus immediate encrypted `moof`/`mdat` fragments and a dynamic MPD. Segment boundaries require an IDR. | Verified |
| Server-blind E2EE | Media samples use CENC AES-CTR; cursor records use AES-256-GCM; every object is HMAC authenticated. Viewer keys are not sent to or logged by the relay. | Verified |
| Authenticated ingest | Protocol version 5 uses Noise NK with a persistent `0600` relay identity. Clients pin the public key before sending tokens or objects. | Verified |
| Internet transport boundary | Internet mode requires an exact path-free HTTPS public origin, keeps application HTTP on loopback, and provides a validated Caddy reverse-proxy profile. HSTS and restrictive response headers are emitted by the application. | Verified |
| Viewer authorization | High-entropy access tokens create signed `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict` sessions. Administrators can create publisher-scoped viewer identities in the dashboard; the token is shown once, only its hash is stored, and revocation immediately invalidates both bearer and browser-session authority. The relay access token remains distinct from the E2EE viewer key. | Verified |
| Browser request integrity | State changes require exact-origin validation and session-bound CSRF authority. WebSocket upgrades require the configured origin. Bearer access is supported for non-browser mirroring without relying on ambient cookies. | Verified |
| Abuse containment | HTTP work, authenticated requests, login attempts, WebSockets, ingest attempts, and active publisher connections are bounded globally and by principal or source address. HTTP, Noise handshake, and ingest-idle deadlines are enforced. | Verified |
| Bounded history | The relay evicts complete media/cursor groups by both age and bytes, including cursor-only groups; it retains required epoch metadata and a persistent ingest sequence high-water mark, uses arrival time rather than UUID ordering, and reapplies policy at restart. Per-stream append journals remove catalog snapshot rewrites from the ingest hot path and recover incomplete final records safely. | Verified |
| Firefox primary target | Clear Key EME, MSE append, painted 320×180 video, live updates, and cursor decryption passed in Playwright Firefox. | Verified |
| Chromium target | The same live checks passed in Playwright Chromium. | Verified |
| Portable file stream | Relay objects mirror atomically to versioned `.gco` files. A v1 transfer manifest records exact public headers, lengths, and SHA-256 checksums; verification reports missing and unexpected objects for resumable, out-of-order delivery and rejects corruption, symlinks, or metadata mismatch. The self-contained server watches the input read-only. | Verified |
| Offline browser playback | Copied objects decoded and painted in both Firefox and Chromium. Final append results were 16 ms and 2 ms respectively after offline file announcements. | Verified |
| Authenticated HTTPS playback | A real Caddy TLS proxy, login flow, secure session cookie, scoped stream API, live WebSocket, CENC playback, and cursor paint/move/hide/restore passed in Firefox and Chromium. | Verified |
| Intel/AMD hardware path | The direct VA-API encoder and PipeWire DMA-BUF import/VPP conversion are implemented; buffer leases remain held until conversion synchronizes. | Unit/build verified; hardware gate pending |
| Software fallback | Auto mode falls back to dynamically loaded OpenH264; no FFmpeg/GStreamer runtime is present. The complete synthetic gate uses this path. | Verified |
| Operator diagnostics | The administrator dashboard reports rolling media/cursor ingress, connection and HTTP health, retention limits, per-stream activity/sequence state, and managed-viewer count without exposing credentials or content keys. | Verified |
| Release artifacts | A deterministic Linux archive includes version-reporting binaries, deployment examples, operator documentation, an SPDX 2.3 SBOM, and SHA-256 checksum. The gate rebuilds twice, compares digests, validates contents, and checks the systemd unit. Optional Minisign signing and backup/upgrade/rollback procedures are documented. | Verified |
| Focused dependencies | The runtime has no MediaMTX, FFmpeg, GStreamer, WebRTC, dash.js, or bincode dependency. Protocol envelopes use Postcard and opaque media is not re-encoded by the relay. | Verified |
| Supply-chain policy | `cargo-deny` rejects known advisories, unapproved licenses and sources, duplicate/high-risk crates, wildcards, and any future bincode dependency. Parser fuzz targets cover all externally supplied binary and catalog formats, and the release SBOM records the resolved Cargo dependency graph. | Verified |

## Green Gates

The final deterministic repository gate is:

```sh
scripts/verify-quality.sh full
```

It includes formatting, Rust and JavaScript suites, Clippy, strict rustdoc,
dependency policy, shell validation, encrypted live/offline transfer, forced
ingest recovery, Internet security, all low-bandwidth profiles, release
performance floors, and reproducible package verification.

Browser playback remains an explicit environment gate when a matching
Playwright installation is available:

```sh
GLACIALCAST_VERIFY_BROWSERS=firefox,chromium \
GLACIALCAST_VERIFY_OFFLINE_BROWSERS=firefox,chromium \
scripts/verify-dash-e2e.sh
```

Parser changes additionally run `scripts/verify-fuzz.sh` with the pinned
nightly toolchain. Release candidates run the 30-minute soak and preserve the
platform evidence described below.

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

## Internet Deployment Boundary

The supported public shape is Caddy on TCP 80/443, the authenticated
Noise-encrypted publisher listener on TCP 8900, and the Rust HTTP listener on
loopback only. `docs/internet-deployment.md` is part of the deployment
contract. It covers bootstrap and dashboard-managed credential enrollment,
rotation/revocation, firewall policy, monitoring, backups, health checks,
systemd containment, and fail-closed startup checks. The release runbook adds
artifact verification, SBOM/signing boundaries, upgrade, and rollback. Public
deployment still depends on the operator supplying correct DNS, a valid
certificate path, host updates, and firewall rules.

The relay can still observe routing metadata, dimensions, MIME types, timing,
object sizes, and activity. E2EE protects screen pixels and cursor contents,
not traffic analysis or availability. Clear Key is a browser interoperability
mechanism rather than DRM: a legitimately authorized viewer can extract the
viewer key.
