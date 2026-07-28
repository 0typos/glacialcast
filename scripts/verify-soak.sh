#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_SOAK_CONTROL_ADDR:-127.0.0.1:19599}"
ingest_addr="${GLACIALCAST_SOAK_INGEST_ADDR:-127.0.0.1:19600}"
duration_seconds="${GLACIALCAST_SOAK_SECONDS:-300}"
sample_seconds="${GLACIALCAST_SOAK_SAMPLE_SECONDS:-5}"
max_stall_seconds="${GLACIALCAST_SOAK_MAX_STALL_SECONDS:-20}"
max_server_rss_kib="${GLACIALCAST_SOAK_MAX_SERVER_RSS_KIB:-524288}"
max_client_rss_kib="${GLACIALCAST_SOAK_MAX_CLIENT_RSS_KIB:-1048576}"
retention_bytes="${GLACIALCAST_SOAK_RETENTION_BYTES:-8MiB}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-soak.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
server_pid=""
client_pid=""

cleanup() {
  for pid in "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

if ! [[ "${duration_seconds}" =~ ^[0-9]+$ ]] || (( duration_seconds < 10 )); then
  echo "GLACIALCAST_SOAK_SECONDS must be an integer of at least 10" >&2
  exit 2
fi
if ! [[ "${sample_seconds}" =~ ^[0-9]+$ ]] || (( sample_seconds < 1 )); then
  echo "GLACIALCAST_SOAK_SAMPLE_SECONDS must be a positive integer" >&2
  exit 2
fi
if ! [[ "${max_stall_seconds}" =~ ^[0-9]+$ ]] || (( max_stall_seconds < sample_seconds )); then
  echo "GLACIALCAST_SOAK_MAX_STALL_SECONDS must be at least the sample interval" >&2
  exit 2
fi

cargo build -p glacialcast-server -p glacialcast-client
ingest_server_key="$(
  target/debug/glacialcast-server \
    --no-config \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/glacialcast-server \
  --no-config \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  --retention-seconds 60 \
  --retention-bytes-per-stream "${retention_bytes}" \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  if curl -fsS "${origin}/health/ready" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    echo "server exited before the soak gate became ready" >&2
    sed -n '1,240p' "${server_log}" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "${origin}/health/ready" >/dev/null

RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --no-config \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --foreground \
  --client-id soak-client \
  --display-name "Soak Verify" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 640 \
  --height 360 \
  --fps 4 \
  --cursor-hz 30 \
  --segment-frames 4 \
  >"${client_log}" 2>&1 &
client_pid="$!"

node - \
  "${origin}" \
  "${duration_seconds}" \
  "${sample_seconds}" \
  "${max_stall_seconds}" \
  "${server_pid}" \
  "${client_pid}" <<'NODE'
const [origin, durationText, sampleText, stallText, serverPidText, clientPidText] =
  process.argv.slice(2);
const durationMs = Number(durationText) * 1000;
const sampleMs = Number(sampleText) * 1000;
const maxStallMs = Number(stallText) * 1000;
const serverPid = Number(serverPidText);
const clientPid = Number(clientPidText);
const started = Date.now();
const deadline = started + durationMs;
let streamId = null;
let highest = 0;
let lastProgressAt = started;
let samples = 0;

function processAlive(pid, label) {
  try {
    process.kill(pid, 0);
  } catch {
    throw new Error(`${label} process ${pid} exited during soak`);
  }
}

while (Date.now() < deadline) {
  processAlive(serverPid, 'server');
  processAlive(clientPid, 'client');
  const ready = await fetch(`${origin}/health/ready`);
  if (!ready.ok) throw new Error(`readiness returned ${ready.status}`);
  const streams = await fetch(`${origin}/api/streams`).then(response => {
    if (!response.ok) throw new Error(`stream list returned ${response.status}`);
    return response.json();
  });
  const stream = streams.find(candidate => candidate.display_name === 'Soak Verify');
  if (stream) {
    streamId = stream.stream_id;
    const objects = await fetch(
      `${origin}/api/dash/streams/${streamId}/objects`,
    ).then(response => {
      if (!response.ok) throw new Error(`object list returned ${response.status}`);
      return response.json();
    });
    const nextHighest = Math.max(0, ...objects.map(object => Number(object.sequence)));
    if (nextHighest > highest) {
      highest = nextHighest;
      lastProgressAt = Date.now();
    }
  }
  if (Date.now() - lastProgressAt > maxStallMs) {
    throw new Error(`publisher made no durable sequence progress for ${stallText}s`);
  }
  samples += 1;
  await new Promise(resolve => setTimeout(resolve, Math.min(sampleMs, deadline - Date.now())));
}

if (!streamId || highest < 5 || samples < 2) {
  throw new Error(`insufficient soak evidence: stream=${streamId} highest=${highest} samples=${samples}`);
}
const metrics = await fetch(`${origin}/api/admin/metrics`).then(response => {
  if (!response.ok) throw new Error(`metrics returned ${response.status}`);
  return response.json();
});
const streamTraffic = metrics.traffic.streams.find(stream => stream.stream_id === streamId);
if (
  !streamTraffic
  || streamTraffic.lifetime.media.objects < 2
  || streamTraffic.lifetime.cursor.objects < 1
) {
  throw new Error('traffic diagnostics did not observe sustained media and cursor ingest');
}
console.log(JSON.stringify({
  duration_seconds: Number(durationText),
  samples,
  stream_id: streamId,
  highest_sequence: highest,
  media_objects: streamTraffic.lifetime.media.objects,
  media_bytes: streamTraffic.lifetime.media.bytes,
  cursor_objects: streamTraffic.lifetime.cursor.objects,
  cursor_bytes: streamTraffic.lifetime.cursor.bytes,
}));
NODE

if ! kill -0 "${server_pid}" 2>/dev/null || ! kill -0 "${client_pid}" 2>/dev/null; then
  echo "a soak process exited before final resource checks" >&2
  sed -n '1,240p' "${server_log}" >&2
  sed -n '1,240p' "${client_log}" >&2
  exit 1
fi

server_rss_kib="$(ps -o rss= -p "${server_pid}" | tr -d ' ')"
client_rss_kib="$(ps -o rss= -p "${client_pid}" | tr -d ' ')"
if (( server_rss_kib > max_server_rss_kib )); then
  echo "server RSS ${server_rss_kib} KiB exceeds ${max_server_rss_kib} KiB" >&2
  exit 1
fi
if (( client_rss_kib > max_client_rss_kib )); then
  echo "client RSS ${client_rss_kib} KiB exceeds ${max_client_rss_kib} KiB" >&2
  exit 1
fi

if grep -Fq "${viewer_key}" "${server_log}"; then
  echo "viewer key leaked into relay log during soak" >&2
  exit 1
fi

echo "PASS: ${duration_seconds}s soak maintained durable progress; server_rss=${server_rss_kib}KiB client_rss=${client_rss_kib}KiB"
