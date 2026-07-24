#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_RECOVERY_CONTROL_ADDR:-127.0.0.1:19299}"
ingest_addr="${GLACIALCAST_RECOVERY_INGEST_ADDR:-127.0.0.1:19300}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-recovery.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
invalid_log="${work_dir}/invalid-client.log"
server_pid=""
client_pid=""
invalid_pid=""

cleanup() {
  for pid in "${invalid_pid}" "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

cat >"${work_dir}/server.toml" <<'TOML'
[ingest]
require_token = true

[[ingest.tokens]]
name = "recovery-client"
token = "correct-recovery-token"
TOML

cargo build -p glacialcast-server -p glacialcast-client

ingest_server_key="$(
  target/debug/glacialcast-server \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

wait_for_server() {
  for _ in $(seq 1 100); do
    if curl -fsS "${origin}/api/streams" >/dev/null 2>&1; then
      return
    fi
    if [[ -n "${server_pid}" ]] && ! kill -0 "${server_pid}" 2>/dev/null; then
      echo "server exited before becoming ready" >&2
      sed -n '1,240p' "${server_log}" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for recovery server" >&2
  sed -n '1,240p' "${server_log}" >&2
  exit 1
}

start_server() {
  target/debug/glacialcast-server \
    --config "${work_dir}/server.toml" \
    --control-addr "${control_addr}" \
    --ingest-addr "${ingest_addr}" \
    --data-dir "${work_dir}/data" \
    --retention-seconds 600 \
    --retention-bytes-per-stream 64MiB \
    >>"${server_log}" 2>&1 &
  server_pid="$!"
  wait_for_server
}

wait_for_log() {
  local path="$1"
  local pattern="$2"
  for _ in $(seq 1 100); do
    if grep -Fq "${pattern}" "${path}"; then
      return
    fi
    sleep 0.1
  done
  echo "timed out waiting for ${pattern@Q} in ${path}" >&2
  sed -n '1,240p' "${path}" >&2
  exit 1
}

stream_state() {
  local minimum_sequence="${1:-0}"
  local minimum_epochs="${2:-1}"
  node - "${origin}" "${minimum_sequence}" "${minimum_epochs}" <<'NODE'
const [origin, minimumText, epochText] = process.argv.slice(2);
const minimum = Number(minimumText);
const minimumEpochs = Number(epochText);
const deadline = Date.now() + 30_000;
while (Date.now() < deadline) {
  try {
    const streams = await fetch(`${origin}/api/streams`).then(response => {
      if (!response.ok) throw new Error(`stream list returned ${response.status}`);
      return response.json();
    });
    const stream = streams.find(candidate => candidate.display_name === 'Recovery E2E');
    if (stream) {
      const headers = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => {
        if (!response.ok) throw new Error(`object list returned ${response.status}`);
        return response.json();
      });
      const highest = Math.max(0, ...headers.map(header => header.sequence));
      const epochs = new Set(
        headers.filter(header => header.kind === 'Epoch').map(header => header.epoch_id),
      ).size;
      const media = headers.filter(header => header.kind === 'Media').length;
      if (highest > minimum && epochs >= minimumEpochs && media >= 2) {
        console.log(
          `${stream.stream_id} ${highest} ${epochs} ${headers.length}`,
        );
        process.exit(0);
      }
    }
  } catch {
    // Retry while the relay or reconnecting publisher settles.
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
process.exit(1);
NODE
}

assert_contiguous_sequences() {
  local stream_id="$1"
  node - "${origin}" "${stream_id}" <<'NODE'
const [origin, streamId] = process.argv.slice(2);
const headers = await fetch(
  `${origin}/api/dash/streams/${streamId}/objects`,
  { cache: 'no-store' },
).then(response => {
  if (!response.ok) throw new Error(`object list returned ${response.status}`);
  return response.json();
});
headers.sort((left, right) => left.sequence - right.sequence);
for (let index = 1; index < headers.length; index += 1) {
  if (headers[index].sequence !== headers[index - 1].sequence + 1) {
    throw new Error(
      `non-contiguous sequence ${headers[index - 1].sequence} -> ${headers[index].sequence}`,
    );
  }
}
console.log(`verified ${headers.length} contiguous retained sequences`);
NODE
}

start_server

RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --config "${work_dir}/missing-client.toml" \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --ingest-token wrong-recovery-token \
  --client-id rejected-client \
  --display-name "Rejected Recovery E2E" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 2 \
  --cursor-hz 30 \
  --segment-frames 2 \
  >"${invalid_log}" 2>&1 &
invalid_pid="$!"
wait_for_log "${invalid_log}" "server rejected hello"
if [[ "$(curl -fsS "${origin}/api/streams")" != "[]" ]]; then
  echo "invalid ingest token created a stream" >&2
  exit 1
fi
kill "${invalid_pid}" 2>/dev/null || true
wait "${invalid_pid}" 2>/dev/null || true
invalid_pid=""

RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --config "${work_dir}/missing-client.toml" \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --ingest-token correct-recovery-token \
  --client-id ignored-when-token-is-present \
  --display-name "Recovery E2E" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 4 \
  --cursor-hz 30 \
  --segment-frames 2 \
  >"${client_log}" 2>&1 &
client_pid="$!"

read -r stream_id before_sequence before_epochs before_count < <(stream_state 0 1)

kill -KILL "${server_pid}"
wait "${server_pid}" 2>/dev/null || true
server_pid=""
wait_for_log "${client_log}" "DASH connection dropped"

start_server
read -r recovered_stream recovered_sequence recovered_epochs recovered_count \
  < <(stream_state "${before_sequence}" 2)

if [[ "${recovered_stream}" != "${stream_id}" ]]; then
  echo "publisher reconnect changed stream identity" >&2
  exit 1
fi
if (( recovered_sequence <= before_sequence )); then
  echo "publisher did not resume after relay restart" >&2
  exit 1
fi
if (( recovered_count <= before_count )); then
  echo "relay did not retain and extend the original object history" >&2
  exit 1
fi
assert_contiguous_sequences "${stream_id}"

kill "${client_pid}" 2>/dev/null || true
wait "${client_pid}" 2>/dev/null || true
client_pid=""
sleep 0.2
read -r recovered_stream recovered_sequence recovered_epochs recovered_count \
  < <(stream_state "$((recovered_sequence - 1))" 2)

kill "${server_pid}" 2>/dev/null || true
wait "${server_pid}" 2>/dev/null || true
server_pid=""
start_server
read -r durable_stream durable_sequence durable_epochs durable_count \
  < <(stream_state "$((recovered_sequence - 1))" 2)

if [[ "${durable_stream}" != "${stream_id}" ]] \
  || (( durable_sequence != recovered_sequence )) \
  || (( durable_epochs != recovered_epochs )) \
  || (( durable_count != recovered_count )); then
  echo "durable recovery changed retained stream state" >&2
  exit 1
fi
if grep -Fq "${viewer_key}" "${server_log}"; then
  echo "viewer key leaked into the relay log" >&2
  exit 1
fi

echo "PASS: ingest authentication rejected invalid credentials; crash recovery resumed stream ${stream_id} from sequence ${before_sequence} through ${recovered_sequence} across ${recovered_epochs} epochs"
