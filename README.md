# GlacialCast

GlacialCast is an end-to-end-encrypted, low-bandwidth Wayland screen viewer
with bounded history. It captures a selected monitor or window through the XDG
Desktop Portal and PipeWire, sends H.264 video at a few frames per second, and
renders cursor updates as an independent, much higher-rate overlay.

The current pre-1.0 implementation provides:

- native portal and PipeWire capture without GStreamer;
- direct VA-API H.264 encoding on supported Intel/AMD devices;
- an in-process OpenH264 software fallback without FFmpeg;
- CENC-encrypted fragmented MP4 presented as MPEG-DASH;
- authenticated cursor batches at up to 60 updates per second, on a timeline
  independent of the video;
- a durable relay bounded by both object age and bytes per stream;
- a dependency-free Firefox/Chromium viewer using MSE and EME Clear Key; and
- portable `.gco` object files and a self-contained offline viewer.

The relay does not receive the viewer key and cannot decrypt media or cursor
contents. The capture client pins the relay's Noise public key, so ingest
credentials and objects are encrypted to the intended server. The current HTTP
viewer supports a fail-closed Internet profile with HTTPS proxying, signed
viewer sessions, publisher-scoped authorization, admin controls, CSRF and
origin enforcement, request/connection limits, and operational probes.

GlacialCast is video-only and view-only. Audio and remote input are outside the
current product contract.

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
viewer_url = "https://cast.example.com"
```

The viewer key is created on first start and kept at
`$XDG_STATE_HOME/glacialcast/viewer-<client-id>.key` with mode `0600`, so every
later run publishes under the same key and viewers keep the secret they already
have. Print it at any time without starting a capture:

```sh
./target/release/glacialcast-client --config client.toml --print-viewer-key
```

Select another location with `--viewer-key-file`, or pin an existing key with
`--viewer-key` or a `viewer_key_b64` entry in `client.toml`; either takes
precedence and nothing is then written to disk. `viewer_url` is only printed
with the startup summary so the invitation is complete.

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
- `deploy/glacialcast-publisher.service`
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
  --idle-heartbeat-seconds 10
```

The publisher detaches into the background and returns immediately, after
printing the viewer key, the log path, and its control socket:

```text
GlacialCast publisher "Workstation"
  viewer key   O8VyOonGQ4Bf1Cz9JHyuX6BcLXrt3NNsEwZZsPQXIr0
  key file     /home/you/.local/state/glacialcast/viewer-workstation.key
  log file     /home/you/.local/state/glacialcast/client-workstation.log
  control      /tmp/glacialcast-client-workstation.sock
```

Send that key to viewers over a secure out-of-band channel; it is the only
secret they need and it does not change when the publisher restarts. Use
`--foreground` when another supervisor owns the process, `--log-file` to place
the detached log elsewhere, and `--daemon-status` or `--daemon-stop` to inspect
or end the running publisher.

Open `http://127.0.0.1:8899` and enter the viewer key. The browser receives
encrypted DASH objects from the relay and performs content authentication and
decryption locally.

## Watching

`/` is the viewer: up to four streams at once. Pick a 1, 2, or 4 tile layout,
drag a stream from the side panel into a tile — or press its **Watch** button,
which does the same thing from a keyboard — and full-screen any tile on its
own. Dropping a stream onto an occupied tile swaps the two, and shrinking the
layout destroys the players it drops rather than leaving them decoding out of
sight. The side panel collapses with the button beside the title, and stays
collapsed until you open it again.

The operations dashboard — stream health, retention, admin controls — is at
`/streams`. A single stream can still be deep-linked at `/dash/{stream_id}`.

The side panel lists the streams this browser holds a key for, which means the
keys have to persist. They are kept in `localStorage` wrapped with AES-GCM under
a key derived from a passphrase by PBKDF2-SHA-256, so the passphrase is asked
for once per session and never stored. This is a real change in exposure over
pasting a key per visit: a stolen browser profile yields ciphertext and a salt
rather than nothing at all, and anyone who learns the passphrase and has that
profile gets every stream in it. A wrong passphrase is reported rather than
silently opening an empty keyring. **Forget all keys** clears the store.

Viewer keys still never leave the page and are never sent to the relay.

For a noninteractive transport test, publish the built-in pattern:

```sh
./target/release/glacialcast-client \
  --config client.toml \
  --capture dash-test \
  --width 1280 \
  --height 720 \
  --test-pattern motion \
  --fps 1 \
  --cursor-hz 60
```

Command-line flags override configuration. `GLACIALCAST_INGEST_SERVER_KEY` can
provide the pinned public key without placing it on the command line.

## Capture and encoding

`--portal-source` accepts `monitor`, `window`, or `any`.

`--screencast-backend auto` is the default. Under niri it uses that
compositor's own Mutter-compatible ScreenCast interface, which lets a detached
publisher pick a monitor with no desktop dialog; the monitor is the primary
output unless `--monitor-name` names another. GNOME, KDE, and sway keep the XDG
portal, whose permission prompt is the sanctioned consent step there. Force
either interface with `--screencast-backend portal` or
`--screencast-backend mutter`:

```sh
./target/release/glacialcast-client \
  --config client.toml \
  --capture dash-wayland \
  --screencast-backend mutter \
  --monitor-name DP-3
```

Cast several screens at once with a repeated `--monitor-name`, or all of them
with `--all-monitors`:

```sh
./target/release/glacialcast-client --config client.toml --list-monitors
./target/release/glacialcast-client --config client.toml --all-monitors
```

Each screen becomes its own stream, published over its own relay connection and
named `<display name> (<connector>)`, so viewers can watch one screen or
several. They all share the one viewer key. Selecting several screens needs the
compositor's ScreenCast interface, so it is available under niri; the portal
chooses its own sources in its dialog.

Publishing more than one screen labels each stream's durable relay identity as
`<publisher>:<connector>`. A publisher that casts a single screen keeps the
bare identity, so an existing single-screen deployment recovers exactly the
stream it had before. Viewer access scopes still name the publisher and cover
all of its screens.

On GNOME, KDE, and sway the portal dialog chooses the sources, and it accepts
several at once — every approved output becomes its own stream, exactly as with
`--all-monitors`. The publisher asks the portal to remember the grant and stores
the returned token at
`$XDG_STATE_HOME/glacialcast/portal-<client-id>.token` with mode `0600`, so a
restart or reboot resumes the same screens without another dialog. Measured on
this host, a first start took 3.5 seconds of dialog and the next took 15
milliseconds with no prompt. Delete that file to be asked again, and use
`--portal-token-file` to move it. A stale or rejected token falls back to
prompting rather than failing.

The portal grants a session to a specific process, so a portal-backed publisher
must be started from the desktop session. `deploy/glacialcast-publisher.service`
is a user unit that starts the publisher with the graphical session.

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

Capture defaults to 2560x1440 at 2.5 Mbit/s. That is a legibility choice rather
than a bandwidth one: a screen is mostly text, and downscaling is what makes
text look soft, far more than the bitrate does. Publishing a 2560x1440 panel at
its native size measured 2.8 to 3.1 MB/min per screen under continuous use and
correlated 0.978 with the compositor's own screenshot. The damage-aware cadence
means a still screen costs almost nothing regardless of the cap. Lower
`--max-frame-width`/`--max-frame-height` if you would rather spend less; the
frame is only ever scaled down, never up.

`--fps` defaults to 5. Segment length follows it so a segment stays near four
seconds: segment boundaries force a keyframe, and holding the frame count fixed
while raising the frame rate multiplies keyframes rather than frames. This is
why the frame rate is nearly free — going from 1 to 5 fps at a fixed segment
*duration* cost about 20% more, while the same change at the old fixed four-frame
segment count cost five times as much. Override with `--segment-frames` only if
you know you want a different segment duration.

`--cursor-hz` defaults to 60 and is the rate the publisher forwards cursor
samples at, independent of `--fps`. It cannot exceed what the compositor
delivers: a screen-capture stream carries cursor metadata on its buffers, so a
60 Hz panel yields at most 60 samples per second. Run the publisher with
`RUST_LOG=glacialcast_client=debug` to see the measured `compositor capture
rate` line reporting both the delivered buffer rate and the rate at which the
cursor actually moved. `--cursor-flush-ms` (default 25) bounds how long a
sample waits to be batched. It is the dominant term in how smooth the overlay
looks, because the viewer can only animate through samples it has: raising it
saves relay objects and costs smoothness.

For repeatable bandwidth tests, `--test-pattern` accepts `static`, `typing`,
`scroll`, and `motion`.

`--dash-encoder auto` first tries constrained-baseline VA-API on
`/dev/dri/renderD128`, then OpenH264. Use another render node with
`--vaapi-device`; that option also selects the GBM device used to read
non-linear compositor DMA-BUFs. Require a backend with `--dash-encoder vaapi`
or `--dash-encoder openh264`.

When VA-API video processing is available, compositor DMA-BUFs are imported and
converted directly to owned NV12 surfaces. Otherwise capture negotiates
CPU-readable buffers for VA-API upload or OpenH264. Some compositors still
supply tiled or otherwise non-mappable DMA-BUFs. Those are copied through the
render driver: first `gbm_bo_map`, and when the driver refuses to map a foreign
buffer object, an `EGLImage` import that reads the frame back through OpenGL
ES. The proprietary NVIDIA stack only supports the second path, so `libEGL` and
`libGLESv2` are loaded at runtime when they are needed. GlacialCast refuses to
map such buffers as linear memory when neither driver-backed readback path is
available, because doing so would publish a corrupted picture.

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

Both network processes support a local Unix control socket. The relay stays in
the foreground unless `--daemon` is given:

```sh
./target/release/glacialcast-server \
  --daemon \
  --daemon-socket /tmp/glacialcast-server.sock \
  --log-file /var/log/glacialcast-server.log \
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

The publisher detaches by default and accepts the same `--daemon-status`,
`--daemon-stop`, `--daemon-socket`, and `--log-file` flags. Its control socket
defaults to `/tmp/glacialcast-client-<client-id>.sock` and its log to
`$XDG_STATE_HOME/glacialcast/client-<client-id>.log`, both created with mode
`0600`. Pass `--foreground` under systemd or any other supervisor; `--daemon`
remains accepted and is now the default.

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

`scripts/verify-wayland-picture.sh` is the acceptance check for the published
image itself: it publishes the real screen, decodes a frame in Firefox or
Chromium with the viewer key, and requires it to match a `grim` screenshot of
the same output. Object-level gates cannot catch a tiled or wrongly swizzled
readback, because scrambled pixels still produce valid encrypted objects.

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
gate enforces application-byte ceilings across static, typing, scroll, and
motion profiles, measured at the shipped default frame rate and cursor rate so
a change to those defaults has to face its own bandwidth cost; framing overhead
remains a deployment measurement. Hardware checks require the corresponding host
capabilities and are described in `docs/completion-audit.md`. The
release-validation targets and evidence collection command are in
`docs/support-matrix.md`.

For a staged checklist, interactive local demo, browser setup, real Wayland and
VA-API gates, offline-file demonstration, deployed-host smoke test, and
troubleshooting, see the [testing and demo guide](docs/testing-demo-guide.md).

The architecture is described in `docs/architecture.md`; version and
format evolution follows `docs/compatibility.md`.
The latest robustness, code-quality, and performance assessment is in
`docs/robustness-performance-review.md`.
