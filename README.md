# GlacialCast

GlacialCast is a low-frame-rate screen stream for live viewing with bounded
history. Its primary path captures Wayland through the desktop portal and
PipeWire, encodes H.264 at about one frame per second, packages Common
Encryption (CENC) fragmented MP4 as MPEG-DASH, and renders cursor metadata as an
independent higher-rate overlay.

The current `0.2` vertical slice provides:

- Native XDG Desktop Portal and PipeWire capture without GStreamer.
- Direct VA-API H.264 encoding on supported Intel/AMD devices, with an
  in-process OpenH264 software fallback and no FFmpeg.
- Authenticated, server-blind CENC media and AES-GCM cursor objects.
- Durable, age-and-byte-bounded history on the relay.
- A dependency-free browser viewer using MSE and EME Clear Key.
- Verified encrypted playback in Firefox (the primary target) and Chromium.
- 30 Hz cursor capture and overlay independent of the one FPS media stream.
- Server-assigned stream IDs and optional ingest tokens.

The viewer key is owned by the capture client and is never sent to the relay.
Store it in `client.toml` or pass `--viewer-key`; encrypted DASH capture refuses
to start without it. The current relay and viewer are suitable for a trusted
LAN. Authentication, TLS, and Internet-facing deployment hardening remain
required before exposing them publicly.

The earlier JPEG and WebRTC modes are retained as compatibility and diagnostic
paths while the DASH implementation is completed. They are not the intended
GlacialCast transport.

Wayland capture prefers PipeWire cursor metadata so the browser can draw the
cursor overlay independently from the captured frame rate, including cursor
bitmap and hotspot data when the compositor supplies it. If a portal only
offers embedded cursor frames, the cursor remains part of the image/video frame
instead of being sent as a separate overlay. Some compositor/portal
combinations can advertise metadata mode but still omit `SPA_META_Cursor` from
allocated PipeWire buffers; in that case the stream continues, but no separate
cursor overlay can be emitted until the compositor/portal provides that
metadata.

To diagnose a missing separate cursor overlay on Wayland, check the active
desktop stack rather than the viewer first:

```sh
wayland-info | rg 'ext_image_copy_capture_manager_v1|zwlr_screencopy_manager_v1'
niri msg -j version
systemctl --user status xdg-desktop-portal.service xdg-desktop-portal-gnome.service
```

`ext_image_copy_capture_manager_v1` exposes a Wayland cursor capture session,
but it is not required when the ScreenCast portal delivers `SPA_META_Cursor`.
If neither that global nor PipeWire `SPA_META_Cursor` appears, and the
compositor IPC does not expose pointer position, Glacialcast has no
compositor-authoritative cursor position source for an independent overlay.

## Fedora Host Dependencies

Native PipeWire capture and the default VA-API encoder need the PipeWire,
libva, GBM, and Clang development packages to build. The DASH software fallback
loads the OpenH264 2.6 ABI at runtime:

```sh
sudo dnf install pipewire-devel libva-devel mesa-libgbm-devel clang-devel openh264
```

`--openh264-library` can point at `libopenh264.so.8` or
`libopenh264.so.2.6.0` when it is installed outside the standard library
directories.

The legacy `ffmpeg-vaapi` feature additionally needs FFmpeg/libva development
packages. On Fedora systems using the Fedora `*-free` FFmpeg libraries, install
the matching free devel packages instead of RPM Fusion `ffmpeg-devel`:

```sh
sudo dnf install \
  libavcodec-free-devel \
  libavfilter-free-devel \
  libavutil-free-devel \
  libswscale-free-devel \
  libva-devel \
  pkgconf-pkg-config
```

The Rust bindings target FFmpeg 8 (`ffmpeg-sys-next` 8.1). Check the complete
toolchain and exact `pkg-config` modules before building the feature:

```sh
scripts/verify-prerequisites.sh
```

The runtime portal pieces are already present on this host:

- `pipewire`
- `xdg-desktop-portal`
- `xdg-desktop-portal-gnome`
- `xdg-desktop-portal-gtk`
- `pkgconf-pkg-config`

For niri, start the compositor through `niri-session` or a display manager so
the D-Bus session and portals are configured correctly.

## Config

By default the server reads `server.toml` if it exists. With no config file,
ingest tokens are not required.

```toml
[ingest]
require_token = true

[[ingest.tokens]]
name = "laptop"
token = "replace-with-a-random-secret"

[[ingest.tokens]]
name = "workstation"
token = "replace-with-a-different-secret"
```

The token `name` is the server-side client identity. A reconnecting client with
the same token gets the same server-assigned stream ID. If `require_token` is
false, clients may connect without a token and the server uses the presented
`client_id` instead.

By default the client reads `client.toml` if it exists:

```toml
client_id = "laptop"
display_name = "Laptop"
ingest_token = "replace-with-a-random-secret"
viewer_key_b64 = "replace-with-client-generated-viewer-key"
```

`viewer_key_b64` must decode to 32 bytes for `dash-test` and `dash-wayland`.
The legacy image mode still permits an omitted key.

## Run the encrypted DASH path

Start the server:

```sh
cargo run -p glacialcast-server -- \
  --config server.toml \
  --control-addr 127.0.0.1:8899 \
  --ingest-addr 127.0.0.1:8900 \
  --data-dir data \
  --retention-bytes-per-stream 512MiB \
  --retention-seconds 1800
```

Run the server as a daemon and control it through its Unix socket:

```sh
./target/release/glacialcast-server \
  --daemon \
  --daemon-socket /tmp/glacialcast-server.sock \
  --control-addr 0.0.0.0:8899 \
  --ingest-addr 0.0.0.0:8900 \
  --data-dir data-prod

./target/release/glacialcast-server --daemon-status --daemon-socket /tmp/glacialcast-server.sock
./target/release/glacialcast-server --daemon-stop --daemon-socket /tmp/glacialcast-server.sock
```

Generate a viewer key once and save it in `client.toml`:

```sh
node -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'))"
```

Publish a generated encrypted test stream:

```sh
cargo run -p glacialcast-client -- \
  --ingest-addr 127.0.0.1:8900 \
  --client-id dash-test \
  --display-name "Encrypted DASH Test" \
  --capture dash-test \
  --viewer-key "$VIEWER_KEY" \
  --fps 1 \
  --cursor-hz 30
```

Publish the selected Wayland monitor or window:

```sh
cargo run -p glacialcast-client -- \
  --ingest-addr 127.0.0.1:8900 \
  --client-id workstation \
  --display-name Workstation \
  --capture dash-wayland \
  --viewer-key "$VIEWER_KEY" \
  --fps 1 \
  --cursor-hz 30 \
  --portal-cursor metadata \
  --require-cursor-metadata
```

`--dash-encoder auto` is the default. It tries constrained-baseline VA-API on
`/dev/dri/renderD128`, then falls back to OpenH264 if the device or encoder is
unavailable. Use `--vaapi-device /dev/dri/renderD129` for another render node,
`--dash-encoder vaapi` to require hardware encoding, or
`--dash-encoder openh264` to require the software path. VA-API segment
boundaries start a fresh low-delay encoder sequence so every advertised DASH
segment begins with SPS, PPS, and an IDR.

Open the dashboard, select the DASH stream, and enter the viewer key:

```text
http://127.0.0.1:8899
```

Dashboard shortcuts:

- `1`, `2`, `4`: switch layouts.
- `Alt+1` through `Alt+4`: select a viewer slot.
- `[` and `]`: move slot focus.
- `f`: fullscreen the active stream inside the dashboard window.
- `Shift+f`: request browser fullscreen for the active stream.
- `l`: return the active stream to live playback.

The dedicated DASH viewer verifies every authenticated object before appending
it, derives per-epoch keys locally, and never submits the viewer key to the
server.

## Mirror to an offline viewer

Mirror the relay's opaque objects into independently transferable files:

```sh
cargo run -p glacialcast-offline -- mirror \
  --server http://127.0.0.1:8899 \
  --stream-id <stream-uuid> \
  --output glacialcast-transfer \
  --follow
```

Each `.gco` file contains one versioned, authenticated stream object. Copy the
completed files through the desired one-way file transport; `.part` files are
temporary and should not be transferred.

On the disconnected machine, run the self-contained local viewer:

```sh
glacialcast-offline serve \
  --input glacialcast-transfer \
  --listen 127.0.0.1:8910
```

Open `http://127.0.0.1:8910`, select the stream, and enter the viewer key. The
binary embeds its HTML, CSS, JavaScript, MPEG-DASH endpoints, and file watcher.
Only the binary, the `.gco` files, an installed Firefox or Chromium browser, and
the out-of-band viewer key are needed; no Internet connection is used.

## Compatibility and diagnostic paths

Start a generated test stream:

```sh
cargo run -p glacialcast-client -- \
  --config client.toml \
  --ingest-addr 127.0.0.1:8900 \
  --display-name Desk \
  --capture test-pattern
```

Start a generated WebRTC/H.264 test video stream:

```sh
cargo run -p glacialcast-client -- \
  --config client.toml \
  --ingest-addr 127.0.0.1:8900 \
  --display-name "H.264 Test" \
  --capture test-video \
  --fps 2 \
  --width 1280 \
  --height 720
```

Feed an external Annex-B H.264 source into the same WebRTC path:

```sh
cargo run -p glacialcast-client -- \
  --ingest-addr 127.0.0.1:8900 \
  --client-id external-h264 \
  --display-name "External H.264" \
  --capture external-h264 \
  --video-command 'your-capture-tool --annex-b-h264-with-aud-to-stdout'
```

The external command must write Annex-B H.264 access units to stdout and include
AUD NAL units so the client can split frames without parsing the full H.264
slice headers. For browser compatibility, use baseline or constrained-baseline
H.264 with `packetization-mode=1` semantics.

When using `wf-recorder`, choose an output explicitly with `-o <name>` from
`wf-recorder -L`. Interactive output selection writes prompts to stdout, which
cannot work because stdout is the video stream.

Replay the newest PNG/JPEG from a folder without touching PipeWire:

```sh
cargo run -p glacialcast-client -- \
  --ingest-addr 127.0.0.1:8900 \
  --client-id screenshot-test \
  --display-name "Screenshot Replay" \
  --capture image-dir \
  --image-dir ~/photos/screenshots \
  --fps 0.5
```

Start the CPU-readable native Wayland/PipeWire diagnostic stream:

```sh
RUST_LOG=glacialcast_client=info \
cargo run -p glacialcast-client -- \
  --config client.toml \
  --ingest-addr 127.0.0.1:8900 \
  --display-name Desk \
  --capture wayland
```

Wayland capture defaults to monitor sources only. To share an individual window
or let the portal show both monitors and windows:

```sh
cargo run -p glacialcast-client -- --capture wayland --portal-source window
cargo run -p glacialcast-client -- --capture wayland --portal-source any
```

For niri's Mutter-compatible ScreenCast DBus API, bypass the portal chooser and
select a monitor connector explicitly:

```sh
cargo run -p glacialcast-client -- \
  --capture wayland \
  --screencast-backend mutter \
  --monitor-name DP-3
```

Portal cursor mode defaults to `auto`, which prefers metadata for an
independent browser cursor overlay. For diagnostics on a portal that advertises
metadata but does not emit `SPA_META_Cursor`, force embedded cursor frames with
`--portal-cursor embedded`; this keeps the cursor visible, but it will update at
the frame rate rather than `--cursor-hz`.
Use `--require-cursor-metadata` for a hard verification gate: the client exits
if PipeWire buffers do not expose `SPA_META_Cursor` after a short startup grace
period. Frames are held back during that grace period so the verifier cannot
pass by sending a cursorless screen stream.

To verify the application transport can carry cursor messages independently of
frame cadence when a cursor source exists, run the synthetic cadence verifier:

```sh
scripts/verify-cursor-cadence.sh
```

It starts a local server and generated image client at 1 fps / 15 cursor Hz, and
passes only after the server receives more cursor messages than frames.

After changing compositor or portal setup, run the cursor metadata verifier:

```sh
scripts/verify-wayland-cursor-metadata.sh
```

The script starts a temporary local server, launches `--capture wayland` with
`--require-cursor-metadata`, and passes only after the server receives real
cursor messages. Accept the desktop portal chooser when it appears, select the
monitor that contains the pointer, and move the pointer on that monitor until
the script reports `PASS`.
To run the same gate against the H.264 video capture path:

```sh
GLACIALCAST_VERIFY_CAPTURE=wayland-video scripts/verify-wayland-cursor-metadata.sh
```

To run the verifier through niri's direct Mutter-compatible ScreenCast backend
without the XDG portal chooser:

```sh
GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter scripts/verify-wayland-cursor-metadata.sh
```

By default the script uses the focused niri output as `--monitor-name`; set
`GLACIALCAST_VERIFY_MONITOR_NAME=DP-3` to choose a specific connector.

It also preflights the active ScreenCast portal's `AvailableCursorModes` and
fails early if the metadata bit is absent; set
`GLACIALCAST_VERIFY_SKIP_PREFLIGHT=1` to force the runtime PipeWire check
anyway.
If the verifier reports that metadata was requested but PipeWire buffers still
lack `SPA_META_Cursor`, use
`docs/wayland-cursor-metadata-upstream-report.md` as the upstream/debug
evidence template.
If the verifier shows a newer `niri` CLI than the running compositor, log out
or restart niri before rerunning it; the running compositor must be the build
that provides cursor metadata. For a systemd-managed niri session,
`systemctl --user restart niri.service` restarts the compositor, but it will
interrupt the graphical session. The verifier treats an installed niri 26.x CLI
with a still-running niri 25.x compositor as a preflight failure unless
`GLACIALCAST_VERIFY_SKIP_PREFLIGHT=1` is set.

On Fedora/niri, the distro `niri-portals.conf` can route ScreenCast through
the GNOME backend, which is niri's primary PipeWire screencasting path:

```ini
[preferred]
default=gnome;gtk;
```

If a previous test configured wlr ahead of GNOME, restore the GNOME preference
before verifying current niri builds:

```sh
scripts/setup-niri-gnome-portal.sh
scripts/verify-wayland-cursor-metadata.sh
```

If PipeWire buffers still lack `SPA_META_Cursor` after restarting into the
current niri build with GNOME selected, the next environment-side diagnostic is
installing `xdg-desktop-portal-wlr` and temporarily routing ScreenCast to `wlr`
in a higher-precedence per-user portal config:

```ini
# ~/.config/xdg-desktop-portal/niri-portals.conf
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.ScreenCast=wlr;gnome;
org.freedesktop.impl.portal.RemoteDesktop=wlr;gnome;
org.freedesktop.impl.portal.Access=gtk;
org.freedesktop.impl.portal.Notification=gtk;
org.freedesktop.impl.portal.Secret=gnome-keyring;
```

Restart the user portal services or log out and back in before rerunning the
cursor metadata verifier.

The repo includes a helper for that fallback environment setup:

```sh
scripts/setup-niri-wlr-portal.sh
scripts/verify-wayland-cursor-metadata.sh
```

If `sudo` is unavailable in the current shell, there is also a user-local
variant that downloads the Fedora RPM, extracts the backend under
`~/.local/share/glacialcast`, and registers per-user D-Bus/systemd portal
files:

```sh
scripts/setup-user-wlr-portal.sh
scripts/verify-wayland-cursor-metadata.sh
```

Start the in-process Wayland/WebRTC H.264 stream:

```sh
cargo build --release -p glacialcast-client --features ffmpeg-vaapi
./target/release/glacialcast-client \
  --no-viewer-key \
  --ingest-addr 127.0.0.1:8900 \
  --client-id wayland-video \
  --display-name "Wayland Video" \
  --capture wayland-video \
  --portal-source monitor \
  --fps 10 \
  --width 1280 \
  --height 720 \
  --resend-bytes 100MiB
```

To pass credentials without config files:

```sh
cargo run -p glacialcast-client -- \
  --client-id laptop \
  --ingest-token <token> \
  --viewer-key <key> \
  --ingest-addr 127.0.0.1:8900 \
  --capture test-pattern
```

If `client.toml` has `viewer_key_b64` but you want this run to advertise a clear
browser stream, pass `--no-viewer-key`.

Run a client as a daemon. The default client socket includes the resolved
`client_id`, but passing an explicit socket is easier for scripts:

```sh
./target/release/glacialcast-client \
  --daemon \
  --daemon-socket /tmp/glacialcast-client-wayland.sock \
  --no-viewer-key \
  --ingest-addr 127.0.0.1:8900 \
  --client-id wayland-real \
  --display-name "Wayland Real Desktop" \
  --capture external-h264 \
  --video-command 'wf-recorder -o DP-1 -f - -m h264 -c libx264 -r 10 -F scale=1280:720 -x yuv420p -p preset=ultrafast -p tune=zerolatency -p profile=baseline -p bf=0 -p x264-params=keyint=10:min-keyint=10:scenecut=0:repeat-headers=1:aud=1'

./target/release/glacialcast-client --daemon-status --daemon-socket /tmp/glacialcast-client-wayland.sock
./target/release/glacialcast-client --daemon-stop --daemon-socket /tmp/glacialcast-client-wayland.sock
```

`--fps` accepts `0.5` through `15`. `--resend-bytes` accepts values such as
`50MB`, `100MiB`, or `1GiB`. For video streams, application-level viewer-key
encryption is disabled; WebRTC already encrypts transport with DTLS/SRTP and
the server must see encoded video bytes to relay them into browser peer
connections.

The client never supplies a stream ID. The server assigns one during ingest
handshake, then the dashboard updates through WebSocket events as clients
connect and frames arrive.

The dashboard separates live client connections from archived streams. Archived
streams keep their retained frame data until you delete them from the stream
list.

## Verify

```sh
cargo fmt --check
cargo check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

Run the clear/encrypted frame integrity verifier:

```sh
scripts/verify-frame-integrity.sh
```

It starts a temporary server, runs a clear test-pattern stream and an AES-GCM
viewer-key stream, fetches the retained frame manifests and payloads, then uses
the same viewer-side AES-GCM and `content_hash` logic to verify the bytes the
viewer reconstructs.

Run the browser render verifier:

```sh
scripts/verify-browser-frame-render.sh
```

It starts a temporary server and drives the dashboard through Playwright. It
checks clear and AES-GCM keyed image streams in Google Chrome, then checks live
H.264 in both Google Chrome and Firefox. The video gate requires decoded
dimensions, non-uniform canvas pixels, and recovery after a page reload within
three seconds. The image gate hashes the exact blob bytes displayed by the
matching retained-frame sequence.

Run the Wayland video hardware-first verifier:

```sh
GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
scripts/verify-wayland-video-hardware.sh
```

It starts a temporary server and `--capture wayland-video` client, requires a
VAAPI/DMA-BUF attempt, and passes if H.264 chunks arrive through DMA-BUF VAAPI,
through the CPU-readable VAAPI upload fallback, or through software H.264 only
after the hardware paths fail. Set `GLACIALCAST_VERIFY_REQUIRE_HARDWARE=1` to
fail instead of accepting any CPU-readable fallback.

Run the WebRTC live video verifier:

```sh
scripts/verify-video-webrtc.sh
```

It starts a generated H.264 client, negotiates a real WebRTC receive-only peer
against `/api/streams/<id>/webrtc/offer`, depacketizes the received RTP, and
passes only after the viewer peer receives an H.264 random access point with
SPS, PPS, and IDR NAL units. This verifies that packets arrive in a shape a
browser decoder can initialize, without relying on browser automation.
