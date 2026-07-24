#!/usr/bin/env bash
set -u

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18904}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18903}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-video-webrtc-verify.$$}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-25}"
CLIENT_ID="${GLACIALCAST_VERIFY_CLIENT_ID:-video-webrtc-verify}"
CLIENT_LOG="${GLACIALCAST_VERIFY_CLIENT_LOG:-/tmp/glacialcast-video-webrtc-client.$$.log}"
SERVER_LOG="${GLACIALCAST_VERIFY_SERVER_LOG:-/tmp/glacialcast-video-webrtc-server.$$.log}"
PROBE_TIMEOUT="${GLACIALCAST_VERIFY_PROBE_TIMEOUT:-10}"

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
cargo build -p glacialcast-server --example webrtc_probe

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

echo "starting generated H.264 video client"
./target/debug/glacialcast-client \
  --config /tmp/glacialcast-missing-client.toml \
  --ingest-addr "${INGEST_ADDR}" \
  --client-id "${CLIENT_ID}" \
  --display-name "Video WebRTC Verify" \
  --capture test-video \
  --fps 5 \
  --no-viewer-key >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

deadline=$((SECONDS + CLIENT_TIMEOUT))
while (( SECONDS < deadline )); do
  STREAM_ID="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams" 2>/dev/null | python3 -c '
import json, sys
streams = json.load(sys.stdin)
for stream in streams:
    if stream.get("display_name") == "Video WebRTC Verify":
        print(stream.get("stream_id", ""))
        break
' 2>/dev/null
  )"
  if [[ -n "${STREAM_ID}" ]]; then
    CHUNK_COUNT="$(
      curl -fsS "http://${CONTROL_ADDR}/api/streams/${STREAM_ID}/video" 2>/dev/null | python3 -c '
import json, sys
print(len(json.load(sys.stdin)))
' 2>/dev/null
    )"
    if [[ "${CHUNK_COUNT:-0}" =~ ^[0-9]+$ ]] && (( CHUNK_COUNT > 0 )); then
      ./target/debug/examples/webrtc_probe "${CONTROL_ADDR}" "${STREAM_ID}" "${PROBE_TIMEOUT}"
      exit "$?"
    fi
  fi

  if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
    wait "${CLIENT_PID}"
    STATUS="$?"
    echo "FAIL: client exited before H.264 video chunks were available; client log: ${CLIENT_LOG}" >&2
    tail -n 120 "${CLIENT_LOG}" >&2 || true
    echo "server log: ${SERVER_LOG}" >&2
    tail -n 120 "${SERVER_LOG}" >&2 || true
    exit "${STATUS}"
  fi
  sleep 0.25
done

echo "FAIL: timed out before WebRTC video was verified; client log: ${CLIENT_LOG}" >&2
tail -n 120 "${CLIENT_LOG}" >&2 || true
echo "server log: ${SERVER_LOG}" >&2
tail -n 120 "${SERVER_LOG}" >&2 || true
exit 1
