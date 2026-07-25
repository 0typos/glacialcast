# GlacialCast

GlacialCast is an end-to-end-encrypted, low-bandwidth Wayland screen viewer
with bounded history. It captures a selected monitor or window through the XDG
Desktop Portal and PipeWire, sends H.264 video at about one frame per second,
and renders cursor updates as an independent higher-rate overlay.

The 0.2 MVP provides:

- native portal and PipeWire capture without GStreamer;
- direct VA-API H.264 encoding on supported Intel/AMD devices;
- an in-process OpenH264 software fallback without FFmpeg;
- CENC-encrypted fragmented MP4 presented as MPEG-DASH;
- authenticated cursor batches at up to 30 updates per second;
- a durable relay bounded by both object age and bytes per stream;
- a dependency-free Firefox/Chromium viewer using MSE and EME Clear Key; and
- portable `.gco` object files and a self-contained offline viewer.

The relay does not receive the viewer key and cannot decrypt media or cursor
contents. The capture client pins the relay's Noise public key, so ingest
credentials and objects are encrypted to the intended server. The current HTTP
viewer supports a fail-closed Internet profile with HTTPS proxying, signed
viewer sessions, publisher-scoped authorization, admin controls, CSRF and
origin enforcement, request/connection limits, and operational probes.

GlacialCast 0.2 is video-only and view-only. Audio and remote input are outside
the MVP.

## Dependencies

The default build uses the exact Rust release pinned in
`rust-toolchain.toml` and needs PipeWire, libva, GBM, and Clang development
files. OpenH264 is loaded dynamically at runtime for software encoding.

On Fedora:

```sh
sudo dnf install pipewire-devel libva-devel mesa-libgbm-devel clang-devel openh264
scripts/verify-prerequisites.sh
```

Build all binaries:

```sh
cargo build --workspace --release
```

## Configure server identity and ingest authorization

The server creates a persistent Noise identity at
`<data-dir>/ingest-noise.key` with mode `0600`. Print its public key once:

```sh
./target/release/glacialcast-server \
  --data-dir data \
  --print-ingest-server-key
```

Back up the private identity file with the server data. Clients must be updated
if it is replaced. A different path can be selected with `--ingest-key-file`.

The server reads `server.toml` when present. Ingest tokens are optional only on
a loopback or explicitly insecure trusted-LAN deployment:

```toml
[ingest]
require_token = true

[[ingest.tokens]]
name = "workstation"
token = "replace-with-a-random-secret"
```

The token name is the durable client identity used to recover the same
server-assigned stream ID after reconnecting.

The client reads `client.toml` when present:

```toml
client_id = "workstation"
display_name = "Workstation"
ingest_token = "replace-with-a-random-secret"
ingest_server_key = "URL-safe-base64-public-key-printed-by-the-server"
viewer_key_b64 = "URL-safe-base64-32-byte-viewer-key"
```

Generate the independent viewer key once and distribute it to viewers out of
band:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Neither key belongs in a URL, log, or server configuration. The ingest server
key is public; the viewer key is secret.

Configuration files containing credentials must be private regular files with
mode `0600`. Unknown configuration keys are rejected.

## Internet deployment

For Internet use, the Rust HTTP listener remains on loopback and Caddy
terminates public HTTPS. The publisher's separate TCP endpoint is protected by
Noise with a pinned server identity and mandatory strong token.

Start with:

- `deploy/server.internet.toml.example`
- `deploy/Caddyfile.example`
- `deploy/glacialcast-server.service`
- `docs/internet-deployment.md`

Internet mode is enabled by setting an HTTPS `security.public_origin`. It
requires viewer access tokens and authenticated ingest, emits secure cookies
and HSTS, and refuses a non-loopback plaintext HTTP listener. Viewer tokens
have `viewer` or `admin` roles and can be scoped to authenticated publisher
names. TLS, enrollment, rotation, firewall, monitoring, and backup procedures
are covered in the deployment guide.

## Run

Start the relay:

```sh
./target/release/glacialcast-server \
  --config server.toml \
  --control-addr 127.0.0.1:8899 \
  --ingest-addr 127.0.0.1:8900 \
  --data-dir data \
  --retention-bytes-per-stream 512MiB \
  --retention-seconds 1800
```

Publish a selected Wayland monitor:

```sh
./target/release/glacialcast-client \
  --config client.toml \
  --ingest-addr 127.0.0.1:8900 \
  --capture dash-wayland \
  --portal-source monitor \
  --portal-cursor metadata \
  --require-cursor-metadata \
  --fps 1 \
  --idle-heartbeat-seconds 10 \
  --cursor-hz 30
```

Open `http://127.0.0.1:8899`, select the stream, and enter the viewer key. The
browser receives encrypted DASH objects from the relay and performs content
authentication and decryption locally.

For a noninteractive transport test, publish the built-in pattern:

```sh
./target/release/glacialcast-client \
  --config client.toml \
  --capture dash-test \
  --width 1280 \
  --height 720 \
  --test-pattern motion \
  --fps 1 \
  --cursor-hz 30
```

Command-line flags override configuration. `GLACIALCAST_INGEST_SERVER_KEY` can
provide the pinned public key without placing it on the command line.

## Capture and encoding

`--portal-source` accepts `monitor`, `window`, or `any`. The portal backend is
the default. Niri's Mutter-compatible ScreenCast API can be selected directly:

```sh
./target/release/glacialcast-client \
  --config client.toml \
  --capture dash-wayland \
  --screencast-backend mutter \
  --monitor-name DP-3
```

`--portal-cursor auto` prefers PipeWire `SPA_META_Cursor`. Use
`--require-cursor-metadata` when an independent cursor is mandatory. Embedded
cursor mode is an explicit degraded fallback: the cursor remains visible but
only updates with video frames.

The video cadence is damage-aware. PipeWire `SPA_META_VideoDamage` is preferred;
CPU-readable frames fall back to a pixel fingerprint, and a DMA-BUF source
without damage metadata safely remains at the configured `--fps`. Unchanged
content is represented by a variable-duration sample at
`--idle-heartbeat-seconds` instead of resending a frame every tick. A changed
frame is still published on the next video tick, while cursor objects continue
at `--cursor-hz`. Set the heartbeat to `1` for a denser compatibility profile.

For repeatable bandwidth tests, `--test-pattern` accepts `static`, `typing`,
`scroll`, and `motion`.

`--dash-encoder auto` first tries constrained-baseline VA-API on
`/dev/dri/renderD128`, then OpenH264. Use another render node with
`--vaapi-device`, or require a backend with `--dash-encoder vaapi` or
`--dash-encoder openh264`.

When VA-API video processing is available, compositor DMA-BUFs are imported and
converted directly to owned NV12 surfaces. Otherwise capture negotiates
CPU-readable buffers for VA-API upload or OpenH264.

## Offline transfer

Mirror the relay's opaque objects into independently transferable files:

```sh
export GLACIALCAST_ACCESS_TOKEN='<viewer-access-token>'
./target/release/glacialcast-offline mirror \
  --server https://cast.example.com \
  --stream-id <stream-uuid> \
  --output glacialcast-transfer \
  --follow
```

Copy completed `.gco` files and
`glacialcast-transfer-chunk-*.json` files through the one-way file transport.
The chunk indexes are immutable and content-addressed. Do not transfer temporary
`.part` files. Copy the atomically replaced `glacialcast-transfer.json` last
after each batch so it never references chunks that have not arrived.

On the disconnected machine:

```sh
glacialcast-offline verify \
  --input glacialcast-transfer

glacialcast-offline serve \
  --input glacialcast-transfer \
  --listen 127.0.0.1:8910
```

Open `http://127.0.0.1:8910`, select the stream, and enter the out-of-band
viewer key. The binary embeds the local HTTP service, DASH endpoints, and
viewer assets; only it, the `.gco` files, and an installed Firefox or Chromium
are required. The versioned transfer index records public headers, byte
lengths, and SHA-256 checksums in bounded chunks; `verify --json` reports
missing and unexpected objects for resumable, out-of-order transfer automation.
Its checksums detect corruption but do not authenticate the transport. The
offline viewer refuses a non-loopback listener unless
`--allow-non-loopback` is supplied explicitly; use that escape hatch only on a
trusted network.

## Release archive

Build and validate a versioned Linux archive with:

```sh
scripts/verify-packaging.sh
```

The ignored `dist/` output contains all three binaries, deployment examples,
operator documentation, an SPDX 2.3 SBOM, and a SHA-256 checksum. The gate
compares archives built in two independent target directories, requires exact
binary versions, and records dirty-worktree provenance honestly. Optional
Minisign signing, installation, backup, upgrade, and rollback procedures are in
the [release operations runbook](docs/release-operations.md).

## Daemon mode

Both network processes support a local Unix control socket:

```sh
./target/release/glacialcast-server \
  --daemon \
  --daemon-socket /tmp/glacialcast-server.sock \
  --control-addr 0.0.0.0:8899 \
  --ingest-addr 0.0.0.0:8900 \
  --data-dir data

./target/release/glacialcast-server \
  --daemon-status \
  --daemon-socket /tmp/glacialcast-server.sock

./target/release/glacialcast-server \
  --daemon-stop \
  --daemon-socket /tmp/glacialcast-server.sock
```

The client supports the same `--daemon`, `--daemon-status`, `--daemon-stop`,
and `--daemon-socket` flags.

## Wayland cursor diagnostics

An independent overlay requires compositor-authoritative cursor metadata. If a
portal advertises metadata mode but does not attach `SPA_META_Cursor`, the
stream continues only when `--require-cursor-metadata` is absent.

Useful host checks:

```sh
wayland-info | rg 'ext_image_copy_capture_manager_v1|zwlr_screencopy_manager_v1'
niri msg -j version
systemctl --user status xdg-desktop-portal.service xdg-desktop-portal-gnome.service
```

For niri portal routing helpers and an upstream diagnostic template, see
`scripts/setup-niri-gnome-portal.sh`, `scripts/setup-niri-wlr-portal.sh`,
`scripts/setup-user-wlr-portal.sh`, and
`docs/wayland-cursor-metadata-upstream-report.md`.

## Verify

```sh
scripts/verify-quality.sh standard
scripts/verify-quality.sh full
GLACIALCAST_SOAK_SECONDS=1800 scripts/verify-quality.sh soak
scripts/verify-internet-browser.sh
```

The `standard` profile is the normal commit gate. The `full` profile includes
that gate plus the synthetic DASH/offline, crash-recovery, Internet-security,
and release-performance integrations. The `soak` profile adds a bounded
long-running publisher/relay reliability check with progress, memory, traffic,
retention, and key-leak assertions. Run the browser command separately when
Docker and Playwright are available.

`scripts/verify-dash-e2e.sh` exercises an authenticated encrypted test stream
against a temporary relay and portable offline viewer. The recovery gate
crashes and restarts an authenticated relay under an active publisher. The
Internet gate exercises session and bearer authentication, authorization,
origin and CSRF enforcement, throttling, security headers, protected mirroring,
monitoring, and fail-closed configuration. The Internet browser gate places
the relay behind a real Caddy HTTPS proxy and verifies authenticated playback
and cursor behavior in both Firefox and Chromium. The performance gate runs
conservative release-mode throughput and durable-object floors. The bandwidth
gate enforces application-byte ceilings for the default moving 1280×720,
1 FPS video and independent 30 Hz cursor profile; framing overhead remains a
deployment measurement. Hardware checks require the corresponding host
capabilities and are described in `docs/completion-audit.md`. The
release-validation targets and evidence collection command are in
`docs/support-matrix.md`.

For a staged checklist, interactive local demo, browser setup, real Wayland and
VA-API gates, offline-file demonstration, deployed-host smoke test, and
troubleshooting, see the [testing and demo guide](docs/testing-demo-guide.md).

The architecture is described in `docs/architecture-v0.2.md`; version and
format evolution follows `docs/compatibility.md`.
The latest robustness, code-quality, and performance assessment is in
`docs/robustness-performance-review.md`.
