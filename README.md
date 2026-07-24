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

The default build needs a Rust toolchain, PipeWire, libva, GBM, and Clang
development files. OpenH264 is loaded dynamically at runtime for software
encoding.

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
./target/release/glacialcast-offline mirror \
  --server https://cast.example.com \
  --access-token "$GLACIALCAST_ACCESS_TOKEN" \
  --stream-id <stream-uuid> \
  --output glacialcast-transfer \
  --follow
```

Copy completed `.gco` files through the one-way file transport. Do not transfer
temporary `.part` files.

On the disconnected machine:

```sh
glacialcast-offline serve \
  --input glacialcast-transfer \
  --listen 127.0.0.1:8910
```

Open `http://127.0.0.1:8910`, select the stream, and enter the out-of-band
viewer key. The binary embeds the local HTTP service, DASH endpoints, and
viewer assets; only it, the `.gco` files, and an installed Firefox or Chromium
are required.

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
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
node scripts/test-viewer-core.mjs
scripts/verify-ingest-recovery.sh
scripts/verify-internet-security.sh
scripts/verify-performance.sh
```

`scripts/verify-dash-e2e.sh` exercises an authenticated encrypted test stream
against a temporary relay and portable offline viewer. The recovery gate
crashes and restarts an authenticated relay under an active publisher. The
Internet gate exercises session and bearer authentication, authorization,
origin and CSRF enforcement, throttling, security headers, protected mirroring,
monitoring, and fail-closed configuration. The performance gate runs
conservative release-mode throughput and durable-object floors. Hardware and
browser checks require the corresponding host capabilities and are described
in `docs/completion-audit.md`.

The protocol and compatibility contract is in `docs/architecture-v0.2.md`.
The latest robustness, code-quality, and performance assessment is in
`docs/robustness-performance-review.md`.
