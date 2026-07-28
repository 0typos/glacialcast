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

## Quickstart

Two machines, or one playing both parts. The relay stores encrypted objects;
the publisher captures a screen; a browser watches. Nothing is enabled
automatically — you decide when a service starts.

### 1. Install

Download the packages for your architecture from the
[latest release](https://github.com/0typos/glacialcast/releases/latest).

```sh
# Fedora, RHEL, openSUSE
sudo dnf install ./glacialcast-server-*.x86_64.rpm   # the relay
sudo dnf install ./glacialcast-client-*.x86_64.rpm   # the publisher

# Debian, Ubuntu
sudo apt install ./glacialcast-server_*_amd64.deb
sudo apt install ./glacialcast-client_*_amd64.deb
```

The relay depends on nothing but glibc, so a headless host does not pull in a
graphics stack. Install only the publisher on a desktop, only the relay on a
server, or both on one machine to try it out.

> [!CAUTION]
> **The shipped configuration contains a viewer key phrase that is public.**
> It is in this README and in every copy of the package. Until you change it,
> anyone who can reach the relay can watch your screen. The publisher prints a
> warning on every start until you do. See [Securing it](#4-securing-it).

### 2. Start the relay

```sh
sudo install -d -o root -g glacialcast -m 0750 /etc/glacialcast
sudo install -o glacialcast -g glacialcast -m 0600 \
  /usr/share/doc/glacialcast-server/server.toml.example \
  /etc/glacialcast/server.toml
sudo systemctl enable --now glacialcast-server
```

Then read the relay's public identity, which the publisher pins:

```sh
sudo -u glacialcast glacialcast-server \
  --data-dir /var/lib/glacialcast --print-ingest-server-key
```

The relay's identity is stored in its data directory, so this has to name the
same one the unit uses or it prints a different key than the service presents.

### 3. Start the publisher

As the user whose screen is being published, not as root:

```sh
mkdir -p ~/.config/glacialcast
cp /usr/share/doc/glacialcast-client/client.toml.example \
  ~/.config/glacialcast/client.toml
chmod 600 ~/.config/glacialcast/client.toml
```

Edit `~/.config/glacialcast/client.toml`: set `ingest_server_key` to what the
relay printed, and `ingest_token` to the token you put in the relay's config.
Then:

```sh
systemctl --user enable --now glacialcast-publisher
```

Every connected monitor is published, each as its own stream, all unlocked by
one key. Open `http://<relay-host>:8899` and enter the viewing key:

```sh
glacialcast-client --print-viewer-key
```

### 4. Securing it

The example configurations exist so the previous three steps work. They are not
a deployment.

- **Change `viewer_key_phrase`** in `~/.config/glacialcast/client.toml`. Either
  set your own seven words from the built-in list, or delete the line entirely
  to have a private one generated and stored with mode 0600 — the better choice.
  Then `systemctl --user restart glacialcast-publisher` and share the new key.
- **Replace every token** in `/etc/glacialcast/server.toml` with
  `openssl rand -base64 32`.
- **Reaching it from the Internet** needs the fail-closed profile: set
  `security.public_origin` and put HTTPS in front. See
  [`docs/internet-deployment.md`](docs/internet-deployment.md).

Changing tokens does not protect a stream still published under the example
phrase. The relay never sees the viewer key, so nothing it is configured with
can substitute for changing that phrase.

### Trying it without packages

```sh
cargo build --workspace --release
./target/release/glacialcast-server --data-dir ./data &
./target/release/glacialcast-client --no-config --ingest-addr 127.0.0.1:8900
```

The publisher prints a generated viewing key and the page to enter it on.

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

### Where configuration is found

Both binaries take `--config`, or `GLACIALCAST_CONFIG` in the environment. A
path given that way is used exactly as given, and a file that is not there
fails startup rather than falling back to built-in defaults — under a service
manager that difference is the gap between a broken unit and a relay running
with no ingest tokens.

Without one, the standard locations are searched in order:

1. `$XDG_CONFIG_HOME/glacialcast/<name>.toml`, or
   `$HOME/.config/glacialcast/<name>.toml`
2. `/etc/glacialcast/<name>.toml`
3. `<name>.toml` in the working directory

The user location comes first so a desktop publisher prefers the operator's own
file; a system service reaches `/etc` because its unit denies it a home
directory. The working directory stays last so running from a source checkout
keeps working. Finding nothing is the ordinary first-run case and starts on
defaults. Both binaries log which file they read, and the publisher prints it
in its startup summary.

A relative default would not survive a service manager: a unit without
`WorkingDirectory=` runs with `/` as its working directory, so `server.toml`
would mean `/server.toml`.

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
  viewer key   dodge-pen-laugh-magic-crab-badge-hip
  key file     /home/you/.local/state/glacialcast/viewer-workstation.key
  log file     /home/you/.local/state/glacialcast/client-workstation.log
  control      /tmp/glacialcast-client-workstation.sock
```

Send that key to viewers over a secure out-of-band channel; it is the only
secret they need and it does not change when the publisher restarts. Use
`--foreground` when another supervisor owns the process, `--log-file` to place
the detached log elsewhere, and `--daemon-status` or `--daemon-stop` to inspect
or end the running publisher.

### What a viewing key is

The key is seven words drawn from a fixed 1024-word list — 70 bits, generated
by the publisher, never chosen by hand. Sharing a key is the one manual step in
setting up a stream, and 43 characters of base64 is not something anyone reads
over a phone or retypes without a mistake; seven short words is.

The words are only how the secret travels. The 32 bytes the media is actually
encrypted under are derived from the phrase with PBKDF2-HMAC-SHA-256 at 600,000
iterations, over a random per-publisher salt the relay republishes as ordinary
stream metadata. The salt is not secret. It exists so that one phrase produces
different key material for each publisher, and so guessing work cannot be
precomputed once and reused against every deployment.

Entry is forgiving in the ways that do not cost anything: case is ignored, words
may be separated by spaces or hyphens, and any word may be shortened to its
first three letters, because no two words in the list share them. Entry is
strict in the way that matters — a word that is not in the list is rejected
rather than quietly resolved to something else.

Keys created before this format was introduced are raw base64 and keep working
unchanged; loading one never rewrites it, because that would silently invalidate
every key already shared. `--new-viewer-key` replaces the stored key with a
fresh phrase, which does invalidate them.

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

The viewing key is entered once. One key covers every screen a publisher casts,
so entering it unlocks all of them rather than asking again per monitor, and the
unlocked key is held in `sessionStorage` so a reload does not ask again either.
It lives as long as the browser tab and no longer, which means closing the
browser leaves nothing on disk. A key that opens nothing published here is
reported as wrong rather than silently unlocking tiles that then fail to
decode — the check authenticates a real object with the derived key.

Viewer keys never leave the page and are never sent to the relay.

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
60 Hz panel yields at most 60 samples per second, and asking for 120 on a 60 Hz
output changes nothing. Run the publisher with
`RUST_LOG=glacialcast_client=debug` to see the measured `compositor capture
rate` line, which reports the delivered buffer rate, the rate at which the
cursor actually moved, and the longest pause between two cursor samples.
`--cursor-flush-ms` (default 25) bounds how long a sample waits to be batched.
It is the dominant term in how smooth the overlay looks, because the viewer can
only animate through samples it has: raising it saves relay objects and costs
smoothness.

What the compositor actually delivers is worth measuring rather than assuming.
On niri 26.04 with three 2560x1440 outputs at 60 Hz, a moving pointer produces
55–59 buffers per second, every one of them carrying cursor motion, with a
worst pause between cursor samples of 32–37 ms. The publisher forwards 90–100%
of those, and the overlay paints a median gap of 17 ms — one display frame —
with a p90 of 33 ms and a worst case of 51–52 ms.

At the same panels' 143.998 Hz mode the compositor delivers *fewer*: 48 per
second, with one output or three. The publisher still forwards 100% of them.
So `--cursor-hz 60` is fully served, while a request for 120 is bounded by what
the compositor hands over rather than by anything here.

Measuring this correctly is harder than it looks, and two mistakes are easy.
A synthetic *absolute* pointing device is coalesced somewhere between libinput
and the compositor: the same machine reports 37 buffers and 30 cursor samples
per second with pauses up to 267 ms when driven that way, which looks exactly
like a compositor limit and is not one. And a pointer that wanders onto another
output publishes "not visible" for the output being measured, so counting that
as a stall measures the probe rather than the stream — it produced apparent
stalls of 6 to 16 seconds that were nothing of the kind.
`scripts/pointer-probe.py` therefore emits relative motion, as a mouse does,
and `scripts/verify-wayland-cursor-rate.sh` excludes the periods when the
pointer is elsewhere.

For repeatable bandwidth tests, `--test-pattern` accepts `static`, `typing`,
`scroll`, and `motion`.

When a frame is published smaller than the source, the shrink happens on the
GPU: a shader pass renders the imported DMA-BUF into a smaller framebuffer and
`glReadPixels` transfers only the pixels that survive it. Three 2560x1440
outputs published at 1280x720 cost 12% of one core that way against 46% reading
them back full size, because the readback moves 3.7 MB per frame instead of
14.7 MB. At the default frame size the pass is skipped entirely, since the
target already equals the source. A driver that lacks the entry points or
refuses the program falls back to a full-size readback and a CPU resize, once,
rather than per frame; `GLACIALCAST_DISABLE_GPU_SCALING=1` forces that path for
a driver that accepts the pass but renders it wrongly.

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

## Packages

`scripts/build-packages.sh` produces `.rpm` and `.deb` for both binaries into
`dist/`, using [nfpm](https://nfpm.goreleaser.com/). Pushing a `v*` tag runs the
full acceptance gate, builds them, and attaches them to a GitHub release along
with the tarball and checksums.

The two packages are separate because their dependencies are: the relay and the
offline viewer link nothing beyond glibc, so a headless host installing
`glacialcast-server` gets no PipeWire and no GPU stack. `glacialcast-client`
depends on what it links and recommends what it loads at runtime, since VA-API,
OpenH264, and the EGL readback path are each optional.

The required glibc is read out of the built binaries rather than assumed, so a
distribution too old to run them declines to install rather than installing
something that cannot start. Release artifacts are built on ubuntu-24.04; for
anything older, build from source.

Neither package enables or starts a service.
`packaging/verify-packages.sh` checks that against a stubbed `systemctl`, along
with an upgrade leaving a running relay alone and a removal stopping it.

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
