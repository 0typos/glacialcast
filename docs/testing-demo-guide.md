# GlacialCast Testing and Demo Guide

This guide starts with tests that work without a graphical session, then moves
through browser playback, a hands-on local demo, real Wayland capture, offline
transfer, and a deployed Internet smoke test. Run commands from the repository
root.

## What each level proves

| Level | Test | Extra requirements | What it proves |
| --- | --- | --- | --- |
| 1 | Rust and JavaScript suites | Build dependencies | Parsers, crypto, authorization, retention, viewer logic, and error paths |
| 2 | Synthetic end to end | OpenH264 | Encrypted ingest, DASH, live cursor objects, retained history, and portable files |
| 3 | Browser matrix | Playwright Firefox and Chromium | Actual MSE/EME decoding, painted video, live append, and independent cursor behavior |
| 4 | Internet profile | Docker and Playwright | Login and secure cookies through a real Caddy HTTPS reverse proxy |
| 5 | Wayland host gates | A graphical Wayland session | Portal/PipeWire capture, real cursor metadata, a published picture that matches the screen, and optional VA-API/DMA-BUF |

The streaming gates in Levels 2 through 4 use a deterministic synthetic source,
so they distinguish a GlacialCast problem from a compositor or GPU integration
problem. Level 5 is the final acceptance test for a particular desktop.

## 1. Check prerequisites and build

On Fedora:

```sh
sudo dnf install \
  pipewire-devel \
  libva-devel \
  mesa-libgbm-devel \
  clang-devel \
  openh264 \
  nodejs
```

Install `cargo-deny` using its upstream instructions or the package appropriate
for the host, then run:

```sh
scripts/verify-prerequisites.sh
cargo build --workspace --release
```

The prerequisite script should end with:

```text
PASS: Rust, Clang, PipeWire, libva, and GBM build prerequisites are available
```

## 2. Run the normal repository checks

These checks do not need Wayland, a browser, or a GPU:

```sh
scripts/verify-quality.sh standard
```

Success means:

- all Rust unit tests and checked rustdoc examples pass, while the release-only
  persistence performance test is ignored by the normal profile;
- the viewer core, operations-dashboard helper, and picture-comparator tests
  report `PASS`;
- Clippy produces no warnings; and
- `cargo-deny` reports `advisories ok, bans ok, licenses ok, sources ok`.

The dependency policy explicitly rejects `bincode`; GlacialCast protocol
envelopes use version-gated Postcard.

Release packaging has its own deterministic gate:

```sh
scripts/verify-packaging.sh
```

It builds the versioned Linux archive twice in independent Cargo target
directories, compares the resulting digests, and verifies its checksum, exact
packaged binary versions, source revision, SPDX Cargo and native-runtime
inventory, required operator files, and systemd unit. A development build from
a dirty tree is marked `-dirty` in the SBOM; release automation instead sets
`GLACIALCAST_REQUIRE_CLEAN=1`. The full quality profile runs this gate
automatically.

Parser changes should also run the bounded fuzz suite. It needs the pinned
nightly and `cargo-fuzz` once:

```sh
rustup toolchain install nightly-2026-07-03
cargo install cargo-fuzz --version 0.13.2 --locked
GLACIALCAST_FUZZ_SECONDS=30 scripts/verify-fuzz.sh
```

The script fuzzes portable objects, cursor envelopes, Noise segment headers,
epoch descriptors, relay catalog-journal records, and v1/v2 transfer-index
JSON. It mutates a temporary copy of the reviewed seed corpus, so a normal run
does not dirty the worktree. Any crashing input is retained in
`fuzz/artifacts/`.

## 3. Run the headless end-to-end gates

The canonical full local gate includes the standard checks and all deterministic
headless integrations:

```sh
scripts/verify-quality.sh full
```

They verify:

- authenticated CENC DASH media and encrypted cursor objects;
- relay acknowledgement latency below the local 250 ms gate;
- portable `.gco` mirroring and offline endpoints;
- invalid publisher-token rejection and recovery across a forced crash;
- viewer/admin roles, publisher scopes, CSRF, exact origins, throttling,
  security headers, private configuration, and fail-closed listeners;
- several concurrent tiles in the multi-stream viewer, each decoding its own
  stream, all unlocked by one viewing key;
- static, typing, scroll, and moving application-traffic ceilings, measured at
  the shipped default frame and cursor rates; and
- conservative crypto, packaging, and durable-storage throughput floors.

Each script prints a final line beginning with `PASS:`. A failure is meaningful:
do not continue to the hardware-specific tests until these pass.

Run the reliability profile for at least 30 minutes before a release:

```sh
GLACIALCAST_SOAK_SECONDS=1800 scripts/verify-quality.sh soak
```

The soak gate samples readiness and durable sequence progress, rejects a
stalled publisher, enforces configurable client/server RSS ceilings, confirms
media and cursor traffic accounting, and checks that the viewer key never
appears in relay logs. Pull requests run a short version; the nightly workflow
runs the 30-minute release duration.

The scripts use isolated `/tmp/glacialcast-*` directories and loopback ports.
If a default port is occupied, override it. For example:

```sh
GLACIALCAST_VERIFY_CONTROL_ADDR=127.0.0.1:28999 \
GLACIALCAST_VERIFY_INGEST_ADDR=127.0.0.1:29000 \
GLACIALCAST_VERIFY_OFFLINE_ADDR=127.0.0.1:29001 \
scripts/verify-dash-e2e.sh
```

The hosted workflows run the standard and deterministic integration gates on
every push or pull request. Nightly automation runs the release-duration soak
and Firefox/Chromium live plus offline playback. Real compositor and GPU gates
remain self-hosted; record their release evidence with the procedure in
`docs/support-matrix.md`.

## 4. Install the browser-test runtime

The browser gates use Playwright as test tooling; it is not a GlacialCast
runtime dependency. A repository-local `node_modules` directory is not
required:

```sh
pw_root="${XDG_CACHE_HOME:-$HOME/.cache}/glacialcast-playwright"
npm install --prefix "$pw_root" playwright@1.59.1
"$pw_root/node_modules/.bin/playwright" install firefox chromium
export GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright"
```

Test live and copied-file playback in both browsers:

```sh
GLACIALCAST_VERIFY_BROWSERS=firefox,chromium \
GLACIALCAST_VERIFY_OFFLINE_BROWSERS=firefox,chromium \
scripts/verify-dash-e2e.sh
```

Then test the Internet boundary. Docker must be running and able to obtain the
official `caddy:2` image:

```sh
scripts/verify-internet-browser.sh
```

For each browser, expect output reporting:

- a 320×180 decoded video;
- a nonempty buffered range;
- media fragments, cursor events, and multiple capture epochs;
- a painted cursor that moved, hid, and returned; and
- live-append latency below 250 ms; and
- continued playback after the gate restarts the publisher once per browser,
  without a page reload, in both the relay and copied-file viewers.

The final Internet-browser line should report that Firefox and Chromium
authenticated through HTTPS and played the E2EE stream.

## 5. Run an interactive local demo

This demo uses the synthetic source first. It exercises the real relay,
publisher, browser viewer, encryption, live updates, and retained-history
controls without involving the portal.

### Prepare a private demo configuration

Run this once in a setup terminal:

```sh
cargo build --workspace --release

demo_dir="$(mktemp -d /tmp/glacialcast-demo.XXXXXX)"
ingest_token="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
umask 077
mkdir -p "$demo_dir/data"

printf '%s\n' \
  '[ingest]' \
  'require_token = true' \
  '' \
  '[[ingest.tokens]]' \
  'name = "demo-publisher"' \
  "token = \"$ingest_token\"" \
  >"$demo_dir/server.toml"

server_key="$(
  target/release/glacialcast-server \
    --config "$demo_dir/server.toml" \
    --data-dir "$demo_dir/data" \
    --print-ingest-server-key
)"

printf '%s\n' \
  'client_id = "demo-publisher"' \
  'display_name = "GlacialCast Demo"' \
  "ingest_token = \"$ingest_token\"" \
  "ingest_server_key = \"$server_key\"" \
  "viewer_key_b64 = \"$viewer_key\"" \
  >"$demo_dir/client.toml"

printf '%s\n' "$viewer_key" >"$demo_dir/viewer-key.txt"
printf 'Demo directory: %s\n' "$demo_dir"
```

Keep the printed demo-directory path. In each terminal below, set it explicitly:

```sh
demo_dir=/tmp/glacialcast-demo.REPLACE_ME
```

### Terminal A: start the relay

```sh
target/release/glacialcast-server \
  --config "$demo_dir/server.toml" \
  --control-addr 127.0.0.1:8899 \
  --ingest-addr 127.0.0.1:8900 \
  --data-dir "$demo_dir/data" \
  --retention-seconds 300 \
  --retention-bytes-per-stream 64MiB
```

Confirm its probes from another terminal:

```sh
curl --fail http://127.0.0.1:8899/health/live
curl --fail http://127.0.0.1:8899/health/ready
```

Both should return a success status and a short text response.

### Terminal B: publish the deterministic demo

```sh
target/release/glacialcast-client \
  --config "$demo_dir/client.toml" \
  --ingest-addr 127.0.0.1:8900 \
  --foreground \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 1280 \
  --height 720 \
  --test-pattern motion \
  --fps 1 \
  --cursor-hz 30 \
  --segment-frames 4
```

Open `http://127.0.0.1:8899` in Firefox first and enter the contents of
`viewer-key.txt` as the viewing key. Then press **Watch** on **GlacialCast
Demo** to put it in a tile.

Expected behavior:

- the test pattern updates at one frame per second;
- the cursor moves much more smoothly than the video;
- the cursor periodically disappears and returns;
- the status changes to `Connected to live encrypted stream`;
- the metrics count both media fragments and cursor events; and
- after the stream has run for a while, the timeline moves backward through
  retained history and **Live** returns to the live edge.

`--foreground` keeps this terminal attached so `Ctrl+C` still stops the
publisher; without it the publisher detaches and prints its viewer key.

Repeat the publisher with `--test-pattern static --idle-heartbeat-seconds 4`.
The cursor should remain smooth, the media-fragment count should rise only on
the heartbeat, and history playback should still span the complete idle time.
The nightly Firefox/Chromium matrix exercises both motion and static profiles.

While leaving a viewer open, stop and restart the publisher with the same
client ID and viewer key. The capture-epoch count should increase, playback
should continue at the live edge without reloading, and the timeline should
still seek into the previous epoch. Cursor state resets at the epoch boundary
and resumes when the new capture publishes cursor metadata.

Repeat in Chromium. Also try a wrong viewer key: playback should fail without
revealing decrypted content.

Stop the publisher and relay with `Ctrl+C` when the demo is complete.

## 6. Replace the test pattern with real Wayland capture

Start the relay as in Terminal A. In Terminal B, run this from the target
graphical user session:

```sh
target/release/glacialcast-client \
  --config "$demo_dir/client.toml" \
  --ingest-addr 127.0.0.1:8900 \
  --capture dash-wayland \
  --portal-source monitor \
  --portal-cursor metadata \
  --require-cursor-metadata \
  --dash-encoder auto \
  --fps 1 \
  --cursor-hz 30
```

Under niri this starts recording the primary output immediately, because
automatic backend selection uses that compositor's own ScreenCast interface;
name another output with `--monitor-name`. On GNOME, KDE, and sway, choose a
monitor in the portal dialog. Then move the pointer over the captured monitor:
the browser should show the real screen at the sparse video cadence while the
independent cursor remains responsive.

The publisher detaches after printing its viewer key, so this terminal returns
immediately. Follow its progress in the printed log file, and stop it with:

```sh
target/release/glacialcast-client --config "$demo_dir/client.toml" --daemon-stop
```

Run the deterministic application-traffic matrix separately:

```sh
scripts/verify-bandwidth.sh
```

It measures static, typing-like, scrolling, and full-motion patterns. Static
and typing profiles have stricter media-byte ceilings; every profile keeps the
same independent cursor ceiling at the shipped 60 Hz default.

For an automated pass/fail check:

```sh
scripts/verify-wayland-cursor-metadata.sh
```

This gate must be run inside the Wayland session. It passes only after receiving
both encrypted media and an independent PipeWire cursor object.

For niri's Mutter-compatible capture path:

```sh
GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
scripts/verify-wayland-cursor-metadata.sh
```

Replace `DP-3` with the output name reported by niri. GNOME, KDE, and wlroots
users should begin with the default portal path.

The object-level gate proves that capture, cursor metadata, encryption, and
relay delivery are active. It cannot determine whether a GPU buffer was
interpreted with the correct pixel layout: a frame of repeated tiles,
horizontal strips, or scrambled blocks still produces valid encrypted objects.
The picture gate answers that question mechanically by comparing what a browser
decodes against the compositor's own screenshot of the captured output:

```sh
GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright" \
scripts/verify-wayland-picture.sh

GLACIALCAST_VERIFY_BROWSER=chromium \
GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright" \
scripts/verify-wayland-picture.sh
```

It needs `grim`, and skips rather than guesses when the portal chooser decided
which output is published; pass `GLACIALCAST_VERIFY_MONITOR_NAME` in that case.
A correct capture scores about 0.99 and an unrelated screen scores near zero,
so the 0.85 default leaves room for compression and a slightly changed desktop.
Run both browsers for a release candidate.

To keep a frame for a human to inspect as well, add a screenshot to the cursor
gate run:

```sh
GLACIALCAST_VERIFY_SCREENSHOT=/tmp/glacialcast-wayland.png \
GLACIALCAST_VERIFY_BROWSER=firefox \
GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright" \
scripts/verify-wayland-cursor-metadata.sh
```

### Cursor rate

That gate proves cursor objects exist. Every cursor defect this project has had
passed it: a sampler polling below the compositor's rate, a flush starved by
its own sampler, a loop that stalled whenever the screen was static. All of
them still produced cursor objects. What separates them from working software
is the rate, so there is a second gate for that:

```sh
GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright" \
scripts/verify-wayland-cursor-rate.sh
```

It publishes every output at the shipped defaults, drives the pointer with a
virtual absolute pointing device, and measures in Firefox how many cursor
updates actually arrive and how evenly they are painted. It needs a writable
`/dev/uinput`, and it builds release rather than debug — its siblings check
correctness, where a debug build answers honestly, while this one measures a
rate that a debug build would misreport.

Thresholds are relative, not absolute, because the compositor sets a ceiling
this code cannot exceed: cursor metadata rides on video buffers, so the cursor
rate cannot beat the buffer rate. The gate requires the viewer to receive at
least 70% of what the compositor sampled, a median painted gap within two
display frames and p90 within four, and no more than 150 ms of stall beyond
what the compositor itself paused for. `GLACIALCAST_CURSOR_MAX_GAP_MS` adds an
absolute ceiling for an acceptance run; it is off by default so that a
compositor limitation cannot be mistaken for a regression here.

Measured on niri 26.04 with PipeWire 1.6.8, three 2560x1440 outputs at 60 Hz,
with the pointer driven by relative motion, across three 30-second runs:

| Measurement | Value |
| --- | --- |
| Compositor buffer rate | 55–59/s, against an advertised `videoMaxFramerate` of 59.951 |
| Compositor cursor samples | 55–59/s — every buffer carries cursor motion |
| Compositor's worst pause between samples | 32–37 ms |
| Delivered to the viewer | 90–100% of what was sampled |
| Painted gap, median | 17 ms — one display frame |
| Painted gap, p90 | 33 ms — two display frames |
| Painted gap, worst | 51–52 ms |

At the 143.998 Hz mode those panels deliver 48 buffers and 48 cursor samples a
second, with one output or with three, and the publisher forwards 100% of them.
A higher panel mode does not raise the cursor rate on this compositor.

Two measurement mistakes are easy here, and both invent a limit that is not
there. A synthetic *absolute* pointing device is coalesced somewhere between
libinput and the compositor: on this machine it yields 37 buffers and 30 cursor
samples per second with pauses up to 267 ms. And a pointer that drifts onto
another output makes the measured output publish "not visible", which counts as
a multi-second stall if the measurement does not exclude it — that artefact
produced apparent stalls of 6 to 16 seconds. `pointer-probe.py` emits relative
motion, and the gate discounts any gap spanning a period when the pointer was
elsewhere.

The per-frame breakdown separates where time goes. At the shipped defaults a
release publisher reports `resize_ms=0`, `fingerprint_ms=4` and
`encode_publish_ms` averaging 40 ms: there is no scaling step, because
`--max-frame-width`/`--max-frame-height` default to the native size of these
outputs, and what remains is the H.264 encode. Scaling only costs anything when
an operator asks for a frame smaller than the source, and then it happens on
the GPU.

Cursor scheduling is reported separately as `cursor timeline scheduling` with
`worst_tick_lateness_ms`. That is the direct check that video work cannot delay
cursor sampling: with all three outputs publishing, the cursor task's ticks are
12 ms late at the median and 17 ms at worst, unchanged at 0.5 fps, at 5 fps, and
with one output instead of three. The residual is the timer's own granularity
against a 16.7 ms interval, not blocking.

### Running these on GNOME, KDE, or sway

Only niri is validated. The gates run on any Wayland session, and what they
report on an unvalidated one is the point of running them.

Everything except niri goes through the XDG Desktop Portal, which changes two
things about how the gates behave:

- **A chooser appears, and someone has to click it.** The gates print a line
  saying so and then wait. The grant is stored as a restore token, so a second
  run of the same gate reuses it without prompting — each gate has its own
  client id and therefore its own token, so expect one dialog per gate the first
  time.
- **`GLACIALCAST_VERIFY_MONITOR_NAME` will not work.** Naming an output needs a
  ScreenCast interface this can drive directly. Under the portal the dialog
  decides, so pick the output there. The picture gate then compares against
  whichever output was granted, and skips rather than guessing if it cannot tell
  which that was.

Record what you find:

```sh
GLACIALCAST_PLAYWRIGHT_MODULE="$pw_root/node_modules/playwright" \
scripts/record-platform-support.sh \
  --compositor "kwin 6.2.4" \
  --gpu-vendor amd --gpu-model "Radeon 780M" \
  --run-gates
```

That writes a report naming the commit, compositor, PipeWire and libva
versions, and the result of each gate, which is what a support claim in
`docs/support-matrix.md` has to rest on. A failure is a useful result: it is the
difference between "implemented" and "validated", and nothing moves out of
"pending" without one of these reports.

## 7. Test VA-API and DMA-BUF

Run:

```sh
GLACIALCAST_VERIFY_VAAPI_DEVICE=/dev/dri/renderD128 \
scripts/verify-wayland-video-hardware.sh
```

This requires the VA-API encoder and fails instead of silently using OpenH264.
To additionally require direct compositor DMA-BUF import:

```sh
GLACIALCAST_VERIFY_VAAPI_DEVICE=/dev/dri/renderD128 \
GLACIALCAST_VERIFY_REQUIRE_DMABUF=1 \
scripts/verify-wayland-video-hardware.sh
```

A normal VA-API pass does not guarantee DMA-BUF import; the compositor and GPU
must negotiate a compatible format and modifier for the strict gate.

## 8. Demonstrate portable offline playback

While the local relay and publisher are running, discover the stream ID and
take a snapshot:

```sh
stream_id="$(
  node -e "
    fetch('http://127.0.0.1:8899/api/streams')
      .then(response => response.json())
      .then(streams => process.stdout.write(streams[0].stream_id))
  "
)"

target/release/glacialcast-offline mirror \
  --server http://127.0.0.1:8899 \
  --stream-id "$stream_id" \
  --output "$demo_dir/outgoing"

mkdir -p "$demo_dir/received"
cp "$demo_dir/outgoing/"*.gco "$demo_dir/received/"
cp "$demo_dir/outgoing/"/glacialcast-transfer-chunk-*.json "$demo_dir/received/"
cp "$demo_dir/outgoing/glacialcast-transfer.json" "$demo_dir/received/"

target/release/glacialcast-offline verify \
  --input "$demo_dir/received"
```

The `received` directory represents the files delivered to the disconnected
machine. The v2 root manifest references immutable, content-addressed index
chunks containing each portable filename, public object header, byte length,
and SHA-256 checksum. `verify` also accepts a legacy v1 single-file manifest.
It exits nonzero for missing, unexpected, corrupt, symlinked, oversized, or
metadata-mismatched objects and index chunks; add `--json` for a transfer tool
or automation. Checksums detect incomplete or corrupt transfer but do not prove
who created the files. The viewer key authenticates and decrypts the `.gco`
contents.

Object files may arrive in any order. For a resumable transfer, copy only the
missing object filenames reported by `verify`, then rerun it. Copy new
content-addressed chunk indexes before the root manifest; publish every file by
atomic rename on the receiver. Stop the live publisher and relay if you want to
demonstrate that no network connection is needed, then run:

```sh
target/release/glacialcast-offline serve \
  --input "$demo_dir/received" \
  --listen 127.0.0.1:8910
```

Open `http://127.0.0.1:8910`, select the stream, and use the same viewer key.
The copied presentation should decode, include cursor history, and allow
timeline seeking. The offline service intentionally refuses a non-loopback bind
unless `--allow-non-loopback` is explicitly supplied. It reads and watches the
input directory but never modifies it, so the verified presentation can be
mounted read-only.

For a continuously updated outgoing directory, add `--follow` to `mirror` and
copy only completed `.gco` and content-addressed chunk files. Copy the
atomically replaced root manifest last after each batch. Never transfer `.part`
files. Re-running `mirror` indexes existing objects once and skips them, so an
interrupted mirror resumes at object granularity; subsequent follow polls ask
the relay only for objects beyond the local sequence high-water mark.

## 9. Smoke-test a deployed Internet instance

Follow the [Internet deployment guide](internet-deployment.md) for
installation. On the server, check the listener boundary:

```sh
ss -ltnp | rg ':(80|443|8899|8900)\b'
```

The application HTTP listener on 8899 must show only a loopback address. Caddy
owns public 80/443, and the authenticated Noise publisher listener owns 8900.

From a different machine:

```sh
curl --fail https://cast.example.com/health/live
curl --fail https://cast.example.com/health/ready
curl --silent --show-error --dump-header - --output /dev/null \
  https://cast.example.com/login
```

Replace the example hostname. Confirm the response includes HSTS, CSP,
`X-Content-Type-Options`, and `Referrer-Policy`. A direct connection to public
TCP 8899 should fail.

Then perform the user-visible acceptance test:

1. Configure a publisher with the public hostname on port 8900, its ingest
   token, and the pinned Noise server public key.
2. Open the HTTPS URL in Firefox.
3. Sign in with a publisher-scoped viewer access token.
4. Confirm that only the permitted publisher appears.
5. Unlock the stream with the separately delivered viewer key.
6. Verify live playback, independent cursor behavior, retained-history seeking,
   and return to the live edge.
7. Repeat in Chromium.
8. Confirm a viewer token cannot access administrator metrics or delete a
   stream.

To exercise first-run viewer management, sign in as the bootstrap
administrator, create a viewer under **Viewer access**, and copy the displayed
access token before leaving the page. Sign in with that token in a private
browser window, then revoke it from the administrator window. Both the active
session and subsequent token login should stop working immediately. The access
token only authorizes relay retrieval; test playback with the separately
delivered E2EE viewer key.

An administrator can check counters without putting a token in the URL:

```sh
export GLACIALCAST_ACCESS_TOKEN='<admin-access-token>'
curl --fail \
  -H "Authorization: Bearer $GLACIALCAST_ACCESS_TOKEN" \
  https://cast.example.com/api/admin/metrics
```

Before exposing a release, rerun:

```sh
scripts/verify-internet-security.sh
scripts/verify-internet-browser.sh
cargo deny -L error check
```

## Troubleshooting

### The configuration is rejected

Credential-bearing files must be regular, non-symlinked, owner-private files:

```sh
chmod 600 server.toml client.toml
```

Unknown or misspelled TOML keys are rejected intentionally.

### OpenH264 cannot be loaded

Install the distribution OpenH264 runtime and confirm its shared library is
visible to the dynamic loader. On Fedora, install the `openh264` package.

### No portal appears or capture exits

Run the client inside the graphical user's Wayland and D-Bus session. Check:

```sh
printf 'WAYLAND_DISPLAY=%s\n' "${WAYLAND_DISPLAY:-unset}"
systemctl --user status \
  xdg-desktop-portal.service \
  xdg-desktop-portal-gnome.service
```

Use the portal implementation appropriate for the compositor. The helper
scripts in `scripts/setup-*-portal.sh` cover the supported niri/wlroots routing
cases.

### Cursor metadata is missing

`--require-cursor-metadata` is deliberately fail-closed. Try the compositor's
recommended portal backend or niri's direct Mutter-compatible path. Removing
the flag or choosing embedded cursor mode is useful for diagnosis, but does not
satisfy the independent-cursor requirement.

Niri 26.04 reserves cursor bitmap metadata through 384×384. Current
Glacialcast builds negotiate that full range. If a previously built binary
reports only `SPA_META_Busy`, rebuild the release binary before rerunning the
cursor gate:

```sh
cargo build --workspace --release
scripts/verify-wayland-cursor-metadata.sh
scripts/verify-wayland-picture.sh
```

Both gates select the capture backend automatically, so they run unattended
under niri and prompt for the portal chooser elsewhere. Force one with
`GLACIALCAST_VERIFY_SCREENCAST_BACKEND=portal` or `=mutter`.

The picture gate is the one that rejects a scrambled readback. It publishes
the real screen, decodes a frame in a browser with the viewer key, screenshots
the same output with `grim`, and requires the two to correlate at least
`GLACIALCAST_VERIFY_PICTURE_CORRELATION` (0.85 by default; a correct capture
scores about 0.99 and an unrelated screen scores near zero). It needs `grim`
and repeats once, because a desktop that changes between the two captures
lowers the score on its own. Set `GLACIALCAST_VERIFY_BROWSER=chromium` to
repeat it in the other engine, and `GLACIALCAST_VERIFY_MONITOR_NAME` when the
portal chooser decides which output is published.

### The Wayland picture is tiled, striped, or capture reports GBM readback failure

Do not continue using a build that publishes scrambled pixels. Current builds
only map explicitly linear, mappable DMA-BUFs directly and otherwise require a
driver-backed readback path: `gbm_bo_map` first, then an `EGLImage` import read
back through OpenGL ES. A host missing `libEGL.so.1` or `libGLESv2.so.2` has
only the GBM path, which the NVIDIA driver does not implement for foreign
buffer objects; install the vendor's EGL and OpenGL ES runtime in that case.

On NVIDIA, first verify that the loaded kernel module and installed userspace
driver agree:

```sh
nvidia-smi
modinfo -F version nvidia
sed -n '1p' /proc/driver/nvidia/version
ls -l /dev/dri/renderD*
```

If `nvidia-smi` cannot initialize, the two reported versions differ, or the
render node disappeared after a driver update, reboot before testing again.
Then rebuild and run the screenshot-enabled Wayland gate above. If the correct
render node is not `/dev/dri/renderD128`, pass it to the client with
`--vaapi-device` and to the verifier with
`GLACIALCAST_VERIFY_VAAPI_DEVICE`.

### The browser gate cannot launch

Confirm `GLACIALCAST_PLAYWRIGHT_MODULE` points to the installed Playwright
module and that Playwright downloaded both browsers:

```sh
test -d "$GLACIALCAST_PLAYWRIGHT_MODULE"
"$(dirname "$GLACIALCAST_PLAYWRIGHT_MODULE")/.bin/playwright" install firefox chromium
```

For the Internet browser gate, also confirm:

```sh
docker version
docker image ls caddy:2
```

### A verification port is already occupied

Every process gate exposes environment variables for its temporary addresses.
Use a different loopback port range, as shown in the headless end-to-end
example, rather than stopping an unrelated service.

## Final acceptance checklist

- [ ] All normal Rust and JavaScript tests pass.
- [ ] Parser fuzzing passes and any new crash artifact has a regression test.
- [ ] Dependency policy passes and the graph contains no `bincode`.
- [ ] Synthetic live and offline E2E gates pass.
- [ ] Forced-crash ingest recovery passes.
- [ ] Firefox and Chromium paint encrypted live and offline media.
- [ ] The cursor moves, hides, and returns independently of video cadence.
- [ ] The Internet security and Caddy HTTPS browser gates pass.
- [ ] Real Wayland capture passes on each supported compositor family.
- [ ] VA-API passes on representative Intel/AMD hosts, or OpenH264 fallback is
      explicitly accepted.
- [ ] The offline viewer works from copied `.gco` files without the relay.
- [ ] Production exposes Caddy HTTPS and Noise ingest, never application HTTP.
- [ ] Viewer access tokens and E2EE viewer keys are distributed separately.
