#!/usr/bin/env bash
set -u

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18902}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18901}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-cursor-cadence-verify.$$}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-15}"
CLIENT_ID="${GLACIALCAST_VERIFY_CLIENT_ID:-cursor-cadence-verify}"
CLIENT_LOG="${GLACIALCAST_VERIFY_CLIENT_LOG:-/tmp/glacialcast-cursor-cadence-client.$$.log}"
SERVER_LOG="${GLACIALCAST_VERIFY_SERVER_LOG:-/tmp/glacialcast-cursor-cadence-server.$$.log}"
MIN_CURSOR_COUNT="${GLACIALCAST_VERIFY_MIN_CURSOR_COUNT:-8}"

SERVER_PID=""
CLIENT_PID=""
cleanup() {
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd cargo
need_cmd curl
need_cmd python3

mkdir -p "${DATA_DIR}"

echo "building Glacialcast verifier binaries"
cargo build -p glacialcast-server -p glacialcast-client

echo "starting temporary Glacialcast server on ${CONTROL_ADDR} / ${INGEST_ADDR}"
./target/debug/glacialcast-server \
  --control-addr "${CONTROL_ADDR}" \
  --ingest-addr "${INGEST_ADDR}" \
  --data-dir "${DATA_DIR}" \
  --retention-bytes-per-stream 32MiB >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

for _ in {1..80}; do
  if curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "server exited before becoming ready" >&2
    wait "${SERVER_PID}" 2>/dev/null || true
    exit 1
  fi
  sleep 0.1
done

if ! curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
  echo "server did not become ready on ${CONTROL_ADDR}" >&2
  exit 1
fi

echo "starting synthetic cursor cadence client at 1 fps / 15 cursor Hz"
./target/debug/glacialcast-client \
  --config /tmp/glacialcast-missing-client.toml \
  --ingest-addr "${INGEST_ADDR}" \
  --client-id "${CLIENT_ID}" \
  --display-name "Cursor Cadence Verify" \
  --capture test-pattern \
  --fps 1 \
  --cursor-hz 15 \
  --no-viewer-key >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

deadline=$((SECONDS + CLIENT_TIMEOUT))
while (( SECONDS < deadline )); do
  STREAM_ID="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams" 2>/dev/null | python3 -c '
import json, sys
streams = json.load(sys.stdin)
for stream in streams:
    if stream.get("display_name") == "Cursor Cadence Verify":
        print(stream.get("stream_id", ""))
        break
' 2>/dev/null
  )"
  if [[ -n "${STREAM_ID}" ]]; then
    COUNTS="$(
      python3 - "${CONTROL_ADDR}" "${STREAM_ID}" <<'PY' 2>/dev/null
import json, sys, urllib.request
control, stream_id = sys.argv[1], sys.argv[2]
base = f"http://{control}/api/streams/{stream_id}"
with urllib.request.urlopen(base + "/frames", timeout=1) as resp:
    frames = json.load(resp)
with urllib.request.urlopen(base + "/cursors", timeout=1) as resp:
    cursors = json.load(resp)
print(len(frames), len(cursors))
PY
    )"
    read -r FRAME_COUNT CURSOR_COUNT <<<"${COUNTS:-0 0}"
    if [[ "${FRAME_COUNT:-0}" =~ ^[0-9]+$ && "${CURSOR_COUNT:-0}" =~ ^[0-9]+$ ]]; then
      if (( FRAME_COUNT >= 1 && CURSOR_COUNT >= MIN_CURSOR_COUNT && CURSOR_COUNT > FRAME_COUNT )); then
        echo "PASS: server received ${FRAME_COUNT} frame(s) and ${CURSOR_COUNT} cursor messages; cursor cadence is independent of frame cadence"
        exit 0
      fi
    fi
  fi

  if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
    wait "${CLIENT_PID}"
    STATUS="$?"
    echo "FAIL: client exited before cursor cadence was verified; client log: ${CLIENT_LOG}" >&2
    tail -n 120 "${CLIENT_LOG}" >&2 || true
    echo "server log: ${SERVER_LOG}" >&2
    tail -n 120 "${SERVER_LOG}" >&2 || true
    exit "${STATUS}"
  fi
  sleep 0.25
done

echo "FAIL: timed out before cursor cadence was verified; client log: ${CLIENT_LOG}" >&2
tail -n 120 "${CLIENT_LOG}" >&2 || true
echo "server log: ${SERVER_LOG}" >&2
tail -n 120 "${SERVER_LOG}" >&2 || true
exit 1
