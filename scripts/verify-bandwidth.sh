#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

profile="${GLACIALCAST_BANDWIDTH_PROFILE:-all}"
if [[ "${profile}" == "all" ]]; then
  for scenario in static typing scroll motion; do
    GLACIALCAST_BANDWIDTH_PROFILE="${scenario}" "${BASH_SOURCE[0]}"
  done
  echo "PASS: static, typing, scroll, and motion bandwidth profiles"
  exit 0
fi
case "${profile}" in
  static)
    default_max_media=65536
    ;;
  typing)
    default_max_media=262144
    ;;
  scroll)
    default_max_media=1048576
    ;;
  motion)
    default_max_media=2097152
    ;;
  *)
    echo "GLACIALCAST_BANDWIDTH_PROFILE must be all, static, typing, scroll, or motion" >&2
    exit 2
    ;;
esac

control_addr="${GLACIALCAST_BANDWIDTH_CONTROL_ADDR:-127.0.0.1:19699}"
ingest_addr="${GLACIALCAST_BANDWIDTH_INGEST_ADDR:-127.0.0.1:19700}"
sample_seconds="${GLACIALCAST_BANDWIDTH_SECONDS:-12}"
max_media_per_minute="${GLACIALCAST_MAX_MEDIA_BYTES_PER_MINUTE:-${default_max_media}}"
max_cursor_per_minute="${GLACIALCAST_MAX_CURSOR_BYTES_PER_MINUTE:-262144}"
default_max_total=$((max_media_per_minute + max_cursor_per_minute))
max_total_per_minute="${GLACIALCAST_MAX_TOTAL_BYTES_PER_MINUTE:-${default_max_total}}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-bandwidth.XXXXXX)"
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

for value in \
  "${sample_seconds}" \
  "${max_media_per_minute}" \
  "${max_cursor_per_minute}" \
  "${max_total_per_minute}"; do
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "bandwidth durations and ceilings must be unsigned integers" >&2
    exit 2
  fi
done
if (( sample_seconds < 10 )); then
  echo "GLACIALCAST_BANDWIDTH_SECONDS must be at least 10" >&2
  exit 2
fi

cargo build -p glacialcast-server -p glacialcast-client
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
  --retention-seconds 120 \
  --retention-bytes-per-stream 32MiB \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  curl -fsS "${origin}/health/ready" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "${origin}/health/ready" >/dev/null

target/debug/glacialcast-client \
  --config "${work_dir}/missing-client.toml" \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --client-id bandwidth-client \
  --display-name "Bandwidth Verify ${profile}" \
  --capture dash-test \
  --test-pattern "${profile}" \
  --dash-encoder openh264 \
  --width 1280 \
  --height 720 \
  --fps 1 \
  --cursor-hz 30 \
  --video-bitrate 250000 \
  --segment-frames 4 \
  >"${client_log}" 2>&1 &
client_pid="$!"

node - \
  "${origin}" \
  "${sample_seconds}" \
  "${max_media_per_minute}" \
  "${max_cursor_per_minute}" \
  "${max_total_per_minute}" \
  "${profile}" \
  "${server_pid}" \
  "${client_pid}" <<'NODE'
const [
  origin,
  secondsText,
  maxMediaText,
  maxCursorText,
  maxTotalText,
  profile,
  serverPidText,
  clientPidText,
] = process.argv.slice(2);
const seconds = Number(secondsText);
const deadline = Date.now() + 30_000;
let streamId;

function alive(pidText, label) {
  try {
    process.kill(Number(pidText), 0);
  } catch {
    throw new Error(`${label} exited during bandwidth measurement`);
  }
}

async function metrics() {
  return fetch(`${origin}/api/admin/metrics`).then(response => {
    if (!response.ok) throw new Error(`metrics returned ${response.status}`);
    return response.json();
  });
}

while (Date.now() < deadline) {
  alive(serverPidText, 'server');
  alive(clientPidText, 'client');
  const streams = await fetch(`${origin}/api/streams`).then(response => response.json());
  streamId = streams.find(
    stream => stream.display_name === `Bandwidth Verify ${profile}`
  )?.stream_id;
  if (streamId) {
    const traffic = (await metrics()).traffic.streams.find(stream => stream.stream_id === streamId);
    if (traffic?.lifetime.media.objects >= 2 && traffic?.lifetime.cursor.objects >= 1) break;
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!streamId) throw new Error('timed out waiting for bandwidth stream');

const before = (await metrics()).traffic.streams.find(stream => stream.stream_id === streamId);
await new Promise(resolve => setTimeout(resolve, seconds * 1000));
alive(serverPidText, 'server');
alive(clientPidText, 'client');
const after = (await metrics()).traffic.streams.find(stream => stream.stream_id === streamId);
if (!before || !after) throw new Error('stream traffic disappeared during measurement');

const delta = (kind, field) =>
  Number(after.lifetime[kind][field]) - Number(before.lifetime[kind][field]);
const mediaBytes = delta('media', 'bytes');
const cursorBytes = delta('cursor', 'bytes');
const otherBytes = ['epoch', 'initialization', 'index', 'end']
  .reduce((sum, kind) => sum + delta(kind, 'bytes'), 0);
const scale = 60 / seconds;
const mediaPerMinute = Math.ceil(mediaBytes * scale);
const cursorPerMinute = Math.ceil(cursorBytes * scale);
const totalPerMinute = Math.ceil((mediaBytes + cursorBytes + otherBytes) * scale);
const result = {
  profile: `${profile}-pattern-1280x720-1fps-30hz-250kbps`,
  sample_seconds: seconds,
  media_bytes_per_minute: mediaPerMinute,
  cursor_bytes_per_minute: cursorPerMinute,
  total_bytes_per_minute: totalPerMinute,
  media_objects: delta('media', 'objects'),
  cursor_objects: delta('cursor', 'objects'),
};
console.log(JSON.stringify(result));
if (mediaPerMinute > Number(maxMediaText)) {
  throw new Error(`media ${mediaPerMinute} B/min exceeds ${maxMediaText} B/min`);
}
if (cursorPerMinute > Number(maxCursorText)) {
  throw new Error(`cursor ${cursorPerMinute} B/min exceeds ${maxCursorText} B/min`);
}
if (totalPerMinute > Number(maxTotalText)) {
  throw new Error(`total ${totalPerMinute} B/min exceeds ${maxTotalText} B/min`);
}
NODE

echo "PASS: ${profile} application traffic stayed within media=${max_media_per_minute} cursor=${max_cursor_per_minute} total=${max_total_per_minute} bytes/minute"
