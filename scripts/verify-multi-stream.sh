#!/usr/bin/env bash
# Runs the multi-stream viewer against several synthetic publishers.
#
# The single-stream gates cannot catch a player that still keeps page-global
# state: one stream works fine either way. This gate fills a tiled layout from
# the encrypted keyring and requires every tile to decode independently.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18991}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18992}"
publishers="${GLACIALCAST_VERIFY_PUBLISHERS:-3}"
browsers="${GLACIALCAST_VERIFY_BROWSERS:-firefox}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-multi-stream.XXXXXX)"
server_log="${work_dir}/server.log"
server_pid=""
client_pids=()

cleanup() {
  for pid in "${client_pids[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! [[ "${publishers}" =~ ^[1-4]$ ]]; then
  echo "GLACIALCAST_VERIFY_PUBLISHERS must be between 1 and 4" >&2
  exit 2
fi

cargo build -p glacialcast-server -p glacialcast-client
ingest_server_key="$(
  target/debug/glacialcast-server \
    --no-config \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
# One key for every stream, matching how a publisher casting several screens
# shares a single viewer key. Creating the key file before any publisher starts
# means they all derive from the same phrase and salt, which is what makes the
# "enter one key, unlock every screen" path real here rather than simulated.
viewer_key_file="${work_dir}/viewer.key"
viewer_key="$(
  target/debug/glacialcast-client \
    --no-config \
    --viewer-key-file "${viewer_key_file}" \
    --print-viewer-key
)"

target/debug/glacialcast-server \
  --no-config \
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

for index in $(seq 1 "${publishers}"); do
  target/debug/glacialcast-client \
    --no-config \
    --ingest-addr "${ingest_addr}" \
    "--ingest-server-key=${ingest_server_key}" \
    --viewer-key-file "${viewer_key_file}" \
    --foreground \
    --client-id "multi-stream-${index}" \
    --display-name "Multi Stream ${index}" \
    --capture dash-test \
    --test-pattern motion \
    --dash-encoder openh264 \
    --width 320 \
    --height 180 \
    --fps 2 \
    --cursor-hz 30 \
    --segment-frames 2 \
    >"${work_dir}/client-${index}.log" 2>&1 &
  client_pids+=("$!")
done

stream_ids="$(
  node - "${origin}" "${publishers}" <<'NODE'
const [origin, expectedText] = process.argv.slice(2);
const expected = Number(expectedText);
const deadline = Date.now() + 60_000;
while (Date.now() < deadline) {
  try {
    const streams = await fetch(`${origin}/api/streams`).then(response => response.json());
    const ready = [];
    for (const stream of streams.filter(entry => entry.display_name.startsWith('Multi Stream'))) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => response.json());
      if (objects.some(object => object.kind === 'Media')) ready.push(stream.stream_id);
    }
    if (ready.length >= expected) {
      process.stdout.write(ready.slice(0, expected).join(' '));
      process.exit(0);
    }
  } catch {
    // Keep polling while the publishers start.
  }
  await new Promise(resolve => setTimeout(resolve, 200));
}
process.exit(1);
NODE
)" || {
  echo "publishers did not produce ${publishers} streams with media" >&2
  sed -n '1,120p' "${work_dir}/client-1.log" >&2
  exit 1
}

IFS=',' read -ra browser_list <<<"${browsers}"
for browser in "${browser_list[@]}"; do
  node scripts/verify-multi-stream-browser.mjs \
    "${origin}" "${viewer_key}" ${stream_ids} "--browser=${browser}"
done

echo "PASS: the multi-stream viewer decoded ${publishers} concurrent tiles in ${browsers}"
