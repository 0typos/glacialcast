#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18999}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:19000}"
offline_addr="${GLACIALCAST_VERIFY_OFFLINE_ADDR:-127.0.0.1:19001}"
origin="http://${control_addr}"
offline_origin="http://${offline_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-dash-e2e.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
server_pid=""
client_pid=""
offline_pid=""
mirror_pid=""

cleanup() {
  if [[ -n "${mirror_pid}" ]] && kill -0 "${mirror_pid}" 2>/dev/null; then
    kill "${mirror_pid}" 2>/dev/null || true
    wait "${mirror_pid}" 2>/dev/null || true
  fi
  if [[ -n "${offline_pid}" ]] && kill -0 "${offline_pid}" 2>/dev/null; then
    kill "${offline_pid}" 2>/dev/null || true
    wait "${offline_pid}" 2>/dev/null || true
  fi
  if [[ -n "${client_pid}" ]] && kill -0 "${client_pid}" 2>/dev/null; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
  fi
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cargo build -p glacialcast-server -p glacialcast-client -p glacialcast-offline

ingest_server_key="$(
  target/debug/glacialcast-server \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/glacialcast-server \
  --config "${work_dir}/missing-server.toml" \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  --retention-seconds 60 \
  --retention-bytes-per-stream 32MiB \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  if curl -fsS "${origin}/api/streams" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    echo "server exited before becoming ready" >&2
    sed -n '1,200p' "${server_log}" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "${origin}/api/streams" >/dev/null

RUST_LOG=glacialcast_client=debug target/debug/glacialcast-client \
  --config "${work_dir}/missing-client.toml" \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --client-id dash-e2e \
  --display-name "DASH E2E" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 2 \
  --cursor-hz 30 \
  --segment-frames 2 \
  >"${client_log}" 2>&1 &
client_pid="$!"

stream_id="$(
  node - "${origin}" <<'NODE'
const origin = process.argv[2];
const deadline = Date.now() + 30_000;
while (Date.now() < deadline) {
  try {
    const streams = await fetch(`${origin}/api/streams`).then(response => {
      if (!response.ok) throw new Error(`stream list returned ${response.status}`);
      return response.json();
    });
    const stream = streams.find(candidate => candidate.display_name === 'DASH E2E');
    if (stream) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => {
        if (!response.ok) throw new Error(`object list returned ${response.status}`);
        return response.json();
      });
      const kinds = new Set(objects.map(object => object.kind));
      const mediaCount = objects.filter(object => object.kind === 'Media').length;
      if (
        kinds.has('Epoch')
        && kinds.has('Initialization')
        && kinds.has('Media')
        && kinds.has('Cursor')
        && mediaCount >= 2
      ) {
        process.stdout.write(stream.stream_id);
        process.exit(0);
      }
    }
  } catch {
    // The processes and final HTTP checks provide diagnostics below.
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
process.exit(1);
NODE
)" || {
  echo "timed out waiting for the encrypted DASH object set" >&2
  sed -n '1,240p' "${server_log}" >&2
  sed -n '1,240p' "${client_log}" >&2
  exit 1
}

manifest="$(curl -fsS "${origin}/api/dash/streams/${stream_id}/manifest.mpd")"
if [[ "${manifest}" != *'urn:mpeg:dash:mp4protection:2011'* ]]; then
  echo "DASH manifest does not declare MPEG Common Encryption" >&2
  exit 1
fi
if grep -Fq "${viewer_key}" "${server_log}"; then
  echo "viewer key leaked into the relay log" >&2
  exit 1
fi
capture_latencies="$(
  sed -n 's/.*capture_to_ack_ms=\([0-9][0-9]*\).*/\1/p' "${client_log}"
)"
if [[ -z "${capture_latencies}" ]]; then
  echo "client did not report a periodic capture-to-relay latency sample" >&2
  exit 1
fi
max_capture_latency_ms=0
while read -r latency_ms; do
  if (( latency_ms > 250 )); then
    echo "capture-to-relay acknowledgement exceeded 250 ms: ${latency_ms} ms" >&2
    exit 1
  fi
  if (( latency_ms > max_capture_latency_ms )); then
    max_capture_latency_ms="${latency_ms}"
  fi
done <<<"${capture_latencies}"

target/debug/glacialcast-offline mirror \
  --server "${origin}" \
  --stream-id "${stream_id}" \
  --output "${work_dir}/offline"
if ! find "${work_dir}/offline" -maxdepth 1 -name '*.gco' -print -quit | grep -q .; then
  echo "offline mirror did not produce portable .gco objects" >&2
  exit 1
fi
target/debug/glacialcast-offline mirror \
  --server "${origin}" \
  --stream-id "${stream_id}" \
  --output "${work_dir}/offline" \
  --poll-ms 100 \
  --follow \
  >"${work_dir}/mirror.log" 2>&1 &
mirror_pid="$!"
target/debug/glacialcast-offline serve \
  --input "${work_dir}/offline" \
  --listen "${offline_addr}" \
  >"${work_dir}/offline.log" 2>&1 &
offline_pid="$!"
for _ in $(seq 1 100); do
  curl -fsS "${offline_origin}/api/dash/streams/${stream_id}/manifest.mpd" >/dev/null 2>&1 \
    && break
  sleep 0.1
done
curl -fsS "${offline_origin}/api/dash/streams/${stream_id}/manifest.mpd" >/dev/null

if [[ -n "${GLACIALCAST_VERIFY_BROWSERS:-}" ]]; then
  IFS=',' read -r -a browsers <<<"${GLACIALCAST_VERIFY_BROWSERS}"
  for browser in "${browsers[@]}"; do
    node scripts/verify-dash-browser.mjs \
      "${origin}" \
      "${stream_id}" \
      "${viewer_key}" \
      "${browser}"
  done
fi

if [[ -n "${GLACIALCAST_VERIFY_OFFLINE_BROWSERS:-}" ]]; then
  IFS=',' read -r -a offline_browsers <<<"${GLACIALCAST_VERIFY_OFFLINE_BROWSERS}"
  for browser in "${offline_browsers[@]}"; do
    node scripts/verify-dash-browser.mjs \
      "${offline_origin}" \
      "${stream_id}" \
      "${viewer_key}" \
      "${browser}"
  done
fi

echo "PASS: authenticated CENC DASH media and cursor objects survived relay and portable offline playback; capture-to-relay max=${max_capture_latency_ms}ms"
