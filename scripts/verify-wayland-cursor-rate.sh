#!/usr/bin/env bash
# Asserts the published cursor rate against what the compositor actually
# delivers, at the shipped defaults, with the pointer really moving.
#
# The existing cursor gate proves cursor objects exist. Every cursor bug in
# this project's history passed that test: a sampler polling at half the
# compositor's rate, a flush starved by its own sampler, a loop that stalled
# whenever the screen was static. All of them still produced cursor objects.
# What separates them from correct behaviour is the *rate*, compared against
# the rate the compositor offered — a fixed threshold would either pass on a
# 60 Hz panel while failing a 144 Hz one, or vice versa.
#
# The compositor's rate is a ceiling this process does not control: cursor
# metadata rides on video buffers, so the sample rate cannot exceed the buffer
# rate, which is the panel refresh. The gate reads both from the publisher's
# own measurement and requires the delivered rate to track it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18987}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18988}"
backend="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-auto}"
monitor_name="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
measure_seconds="${GLACIALCAST_CURSOR_RATE_SECONDS:-20}"
# The publisher can only forward what the compositor hands it, and a little is
# legitimately lost to the batching interval at the window edges.
min_ratio="${GLACIALCAST_CURSOR_RATE_MIN_RATIO:-0.70}"
# Absolute worst-case ceiling, off by default: the compositor's own pauses set
# a floor this code cannot go below, so an absolute number here would fail for
# reasons outside it. Set it for an acceptance run on a known-good host.
max_gap_ms="${GLACIALCAST_CURSOR_MAX_GAP_MS:-0}"
# How much worse than the compositor's own worst pause the overlay may be.
max_added_gap_ms="${GLACIALCAST_CURSOR_MAX_ADDED_GAP_MS:-150}"
# Two and four display frames at 60 Hz: the typical case has to stay smooth
# even when the worst case is bounded by something upstream.
max_p50_ms="${GLACIALCAST_CURSOR_MAX_P50_MS:-34}"
max_p90_ms="${GLACIALCAST_CURSOR_MAX_P90_MS:-68}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-cursor-rate.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
server_pid=""
client_pid=""
probe_pid=""

cleanup() {
  for pid in "${probe_pid}" "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

if [[ "${backend}" != "mutter" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  echo "WAYLAND_DISPLAY is not set; run this gate inside the target Wayland session" >&2
  exit 1
fi
if [[ ! -w /dev/uinput ]]; then
  echo "/dev/uinput is not writable; this gate must drive a real pointer" >&2
  echo "grant access (for example an input-group ACL) and rerun" >&2
  exit 1
fi
if [[ -z "${GLACIALCAST_PLAYWRIGHT_MODULE:-}" ]] && ! node -e "require('playwright')" 2>/dev/null; then
  echo "Playwright is unavailable; set GLACIALCAST_PLAYWRIGHT_MODULE" >&2
  exit 1
fi

# Release, unlike the sibling Wayland gates. Those check correctness — the
# picture matches, the hardware path was taken — and a debug build answers
# those questions honestly. This gate measures a rate, and a debug build
# encoding three 1440p outputs in software measures a binary nobody ships.
cargo build --release -p glacialcast-server -p glacialcast-client

ingest_server_key="$(
  target/release/glacialcast-server --data-dir "${work_dir}/data" --print-ingest-server-key
)"
viewer_key="$(
  target/release/glacialcast-client \
    --config "${work_dir}/missing-client.toml" \
    --viewer-key-file "${work_dir}/viewer.key" \
    --print-viewer-key
)"

target/release/glacialcast-server \
  --config "${work_dir}/missing-server.toml" \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  curl -fsS "${origin}/api/streams" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "${origin}/api/streams" >/dev/null

# No --fps or --cursor-hz here on purpose: the gate has to measure what ships,
# or lowering a default silently lowers the bar it is held to.
client_args=(
  --foreground
  --config "${work_dir}/missing-client.toml"
  --ingest-addr "${ingest_addr}"
  "--ingest-server-key=${ingest_server_key}"
  --viewer-key-file "${work_dir}/viewer.key"
  --client-id cursor-rate-verify
  --display-name "Cursor Rate Verify"
  --capture dash-wayland
  --dash-encoder openh264
  --portal-source monitor
  --screencast-backend "${backend}"
  --portal-cursor metadata
  --require-cursor-metadata
)
if [[ -n "${monitor_name}" ]]; then
  client_args+=(--monitor-name "${monitor_name}")
else
  # Publish every output. The compositor decides which one an absolute pointing
  # device is mapped to, so the gate cannot pick the output the pointer will be
  # on; publishing all of them and measuring the one that sees the pointer is
  # what makes this reliable. It also puts the measurement under the concurrent
  # multi-output load that is the interesting case.
  client_args+=(--all-monitors)
fi

RUST_LOG=glacialcast_client=debug target/release/glacialcast-client "${client_args[@]}" \
  >"${client_log}" 2>&1 &
client_pid="$!"

echo "If a desktop chooser appears, select the target output."
node - "${origin}" "${client_pid}" <<'NODE' || {
const [origin, clientPid] = process.argv.slice(2);
const deadline = Date.now() + 90_000;
while (Date.now() < deadline) {
  try {
    process.kill(Number(clientPid), 0);
  } catch {
    process.exit(2);
  }
  try {
    const streams = await fetch(`${origin}/api/streams`).then(r => r.json());
    const ours = streams.filter(s => s.display_name.startsWith('Cursor Rate Verify'));
    let ready = 0;
    for (const stream of ours) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(r => r.json());
      if (objects.some(o => o.kind === 'Media') && objects.some(o => o.kind === 'Cursor')) ready += 1;
    }
    if (ready > 0 && ready === ours.length) process.exit(0);
  } catch {
    // Keep polling while the portal and capture pipeline initialize.
  }
  await new Promise(resolve => setTimeout(resolve, 200));
}
process.exit(1);
NODE
  status="$?"
  if [[ "${status}" -eq 2 ]]; then
    echo "publisher exited before emitting media and cursor objects" >&2
  else
    echo "publisher did not produce media and cursor objects" >&2
  fi
  sed -n '1,200p' "${client_log}" >&2
  exit 1
}

# The probe outlives the measurement at both ends, so the pointer is already
# moving when measurement starts and has not stopped when it ends.
python3 scripts/pointer-probe.py "$((measure_seconds + 40))" >"${work_dir}/probe.log" 2>&1 &
probe_pid="$!"
# A probe that died on startup would otherwise surface several steps later as a
# publishing failure, which is the most misleading thing this gate could do.
sleep 4
if ! kill -0 "${probe_pid}" 2>/dev/null; then
  echo "the pointer probe exited immediately:" >&2
  cat "${work_dir}/probe.log" >&2
  exit 1
fi

# Which output the pointer landed on is the compositor's choice, so find it
# rather than assume it: the stream whose cursor objects grow fastest while the
# probe runs is the one showing the pointer.
stream_id="$(
  node - "${origin}" <<'NODE'
const origin = process.argv[2];
const label = 'Cursor Rate Verify';
const count = async id => (await fetch(
  `${origin}/api/dash/streams/${id}/objects`, { cache: 'no-store' },
).then(r => r.json())).filter(o => o.kind === 'Cursor').length;

const streams = (await fetch(`${origin}/api/streams`).then(r => r.json()))
  .filter(s => s.display_name.startsWith(label));
const before = new Map();
for (const s of streams) before.set(s.stream_id, await count(s.stream_id));
await new Promise(resolve => setTimeout(resolve, 6000));

let best = null;
for (const s of streams) {
  const delta = (await count(s.stream_id)) - before.get(s.stream_id);
  process.stderr.write(`  ${s.display_name}: +${delta} cursor objects\n`);
  if (!best || delta > best.delta) best = { id: s.stream_id, name: s.display_name, delta };
}
if (!best || best.delta === 0) {
  process.stderr.write('no output saw the pointer move\n');
  process.exit(1);
}
process.stderr.write(`measuring ${best.name}\n`);
process.stdout.write(`${best.id}\n`);
NODE
)" || {
  echo "the pointer probe did not reach any published output" >&2
  exit 1
}

measurement="$(
  node scripts/verify-cursor-rate-browser.mjs \
    "${origin}" "${stream_id}" "${viewer_key}" "${measure_seconds}"
)"
echo "viewer: ${measurement}"

kill "${probe_pid}" 2>/dev/null || true
wait "${probe_pid}" 2>/dev/null || true
probe_pid=""

# The publisher measures what the compositor handed it. Take the busiest window
# seen, which is the one where the pointer was actually moving.
compositor_cursor_hz="$(
  grep -o 'cursor_hz="[0-9.]*"' "${client_log}" | sed 's/.*"\(.*\)"/\1/' | sort -g | tail -1
)"
compositor_buffer_hz="$(
  grep -o 'buffer_hz="[0-9.]*"' "${client_log}" | sed 's/.*"\(.*\)"/\1/' | sort -g | tail -1
)"
# The compositor's own worst pause. Excluding the outright multi-second holes,
# which are the publisher starting up or the probe not yet running, rather than
# anything about steady-state delivery.
compositor_gap_ms="$(
  grep -o 'max_cursor_gap_ms=[0-9]*' "${client_log}" | cut -d= -f2 \
    | awk '$1 < 2000' | sort -n | tail -1
)"
if [[ -z "${compositor_cursor_hz}" ]]; then
  echo "the publisher reported no capture-rate measurement" >&2
  echo "(expected debug lines 'compositor capture rate'; is RUST_LOG set?)" >&2
  exit 1
fi
echo "compositor: buffer_hz=${compositor_buffer_hz} cursor_hz=${compositor_cursor_hz}" \
     "max_cursor_gap_ms=${compositor_gap_ms:-unknown}"

node - "${measurement}" "${compositor_cursor_hz}" "${compositor_buffer_hz}" \
      "${min_ratio}" "${max_gap_ms}" "${compositor_gap_ms:-0}" "${max_added_gap_ms}" \
      "${max_p50_ms}" "${max_p90_ms}" <<'NODE'
const [raw, cursorHzText, bufferHzText, minRatioText, maxGapText,
       compositorGapText, maxAddedText, maxP50Text, maxP90Text] = process.argv.slice(2);
const measured = JSON.parse(raw);
const cursorHz = Number(cursorHzText);
const bufferHz = Number(bufferHzText);
const minRatio = Number(minRatioText);
const compositorGap = Number(compositorGapText);
const maxAdded = Number(maxAddedText);
const maxP50 = Number(maxP50Text);
const maxP90 = Number(maxP90Text);
const gap = measured.painted_gap_ms;

const failures = [];

// The compositor is the ceiling. If it never sampled the cursor then the probe
// failed, not the publisher, and passing here would be meaningless.
if (!(cursorHz > 5)) {
  failures.push(
    `the compositor reported only ${cursorHz} cursor samples/s, so the pointer was not moving`
    + ' over the captured output; the probe, not the publisher, is what failed',
  );
}

// The bug this gate exists for: samples that reach the publisher and then do
// not reach the viewer. A sampler polling below the delivery rate, a flush
// starved by its own sampler, and a loop that stalled on a static screen all
// show up right here.
const ratio = measured.delivered_events_per_second / cursorHz;
if (cursorHz > 5 && ratio < minRatio) {
  failures.push(
    `the viewer received ${measured.delivered_events_per_second}/s of the compositor's`
    + ` ${cursorHz}/s (${(ratio * 100).toFixed(0)}%, floor ${(minRatio * 100).toFixed(0)}%):`
    + ' cursor updates are being dropped between sampling and the viewer',
  );
}

if (gap.p50 === null) {
  failures.push('the overlay never advanced its selected cursor sample');
} else {
  if (gap.p50 > maxP50) {
    failures.push(`typical painted gap is ${gap.p50} ms (limit ${maxP50} ms)`);
  }
  if (gap.p90 > maxP90) {
    failures.push(`p90 painted gap is ${gap.p90} ms (limit ${maxP90} ms)`);
  }
}

// Worst-case is judged against the compositor rather than against an absolute
// number. Measured on niri 26.04, the compositor itself pauses cursor-carrying
// buffers for 267 ms with one output and 734 ms with three, at both 720p and
// 1440p — frame size does not move it, so it is not this process's per-frame
// cost. Nothing downstream can be smoother than that, and a fixed ceiling here
// would encode one compositor's behaviour as a property of this code.
if (gap.max !== null && compositorGap > 0 && gap.max > compositorGap + maxAdded) {
  failures.push(
    `the overlay stalled for ${gap.max} ms while the compositor's own worst pause was`
    + ` ${compositorGap} ms: this process added ${(gap.max - compositorGap).toFixed(0)} ms`
    + ` of its own (limit ${maxAdded} ms)`,
  );
}

// An absolute ceiling stays available for acceptance runs, off by default so a
// compositor limitation cannot masquerade as a regression in this code.
if (maxGapText !== '' && Number(maxGapText) > 0 && gap.max !== null && gap.max > Number(maxGapText)) {
  failures.push(`the overlay stalled for ${gap.max} ms (absolute limit ${maxGapText} ms)`);
}

console.log(
  `delivered ${measured.delivered_events_per_second}/s vs compositor ${cursorHz}/s`
  + ` (${(ratio * 100).toFixed(0)}% of a ${bufferHz}/s buffer rate);`
  + ` painted p50=${gap.p50}ms p90=${gap.p90}ms max=${gap.max}ms`
  + ` against a compositor pause of ${compositorGap}ms`,
);

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}
NODE

echo "PASS: published cursor rate tracks the compositor's sample rate at shipped defaults"
