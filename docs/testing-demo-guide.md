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
| 5 | Wayland host gates | A graphical Wayland session | Portal/PipeWire capture, real cursor metadata, and optional VA-API/DMA-BUF |

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
- the viewer core and operations-dashboard helper tests report `PASS`;
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
- a moving 1280×720, 1 FPS, 30 Hz cursor application-traffic ceiling; and
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
  --capture dash-test \
  --dash-encoder openh264 \
  --width 1280 \
  --height 720 \
  --test-pattern motion \
  --fps 1 \
  --cursor-hz 30 \
  --segment-frames 4
```

Open `http://127.0.0.1:8899` in Firefox first, select **GlacialCast Demo**, and
paste the contents of `viewer-key.txt` into the unlock form.

Expected behavior:

- the test pattern updates at one frame per second;
- the cursor moves much more smoothly than the video;
- the cursor periodically disappears and returns;
- the status changes to `Connected to live encrypted stream`;
- the metrics count both media fragments and cursor events; and
- after the stream has run for a while, the timeline moves backward through
  retained history and **Live** returns to the live edge.

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

Choose a monitor in the portal dialog and move the pointer over that monitor.
The browser should show the real screen at the sparse video cadence while the
independent cursor remains responsive.

Run the deterministic application-traffic matrix separately:

```sh
scripts/verify-bandwidth.sh
```

It measures static, typing-like, scrolling, and full-motion patterns. Static
and typing profiles have stricter media-byte ceilings; every profile keeps the
same independent 30 Hz cursor ceiling.

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
```

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
