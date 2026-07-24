#!/usr/bin/env bash
set -u

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18896}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18895}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-wayland-video-hardware-verify.$$}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-45}"
CLIENT_ID="${GLACIALCAST_VERIFY_CLIENT_ID:-wayland-video-hardware-verify}"
CLIENT_LOG="${GLACIALCAST_VERIFY_CLIENT_LOG:-/tmp/glacialcast-wayland-video-hardware-client.$$.log}"
SCREENCAST_BACKEND="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-mutter}"
MONITOR_NAME="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
REQUIRE_HARDWARE="${GLACIALCAST_VERIFY_REQUIRE_HARDWARE:-0}"
RAP_FILE="/tmp/glacialcast-wayland-video-random-access.$$.h264"

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
  rm -f "${RAP_FILE}"
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
need_cmd ffprobe

if [[ "${SCREENCAST_BACKEND}" == "mutter" && -z "${MONITOR_NAME}" ]] && command -v niri >/dev/null 2>&1; then
  MONITOR_NAME="$(
    niri msg -j focused-output 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get("name", ""))
except Exception:
    pass
' 2>/dev/null || true
  )"
fi

if [[ "${SCREENCAST_BACKEND}" == "mutter" && -z "${MONITOR_NAME}" ]]; then
  echo "FAIL: GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter requires GLACIALCAST_VERIFY_MONITOR_NAME, or a focused niri output must be queryable" >&2
  exit 1
fi

mkdir -p "${DATA_DIR}"

scripts/verify-prerequisites.sh
echo "building hardware-enabled Glacialcast verifier binaries"
cargo build -p glacialcast-server
cargo build -p glacialcast-client --features ffmpeg-vaapi

echo "starting temporary Glacialcast server on ${CONTROL_ADDR} / ${INGEST_ADDR}"
./target/debug/glacialcast-server \
  --control-addr "${CONTROL_ADDR}" \
  --ingest-addr "${INGEST_ADDR}" \
  --data-dir "${DATA_DIR}" \
  --retention-bytes-per-stream 32MiB &
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

CLIENT_ARGS=(
  --config /tmp/glacialcast-missing-client.toml
  --ingest-addr "${INGEST_ADDR}"
  --client-id "${CLIENT_ID}"
  --display-name "Wayland Video Hardware Verify"
  --capture wayland-video
  --portal-source monitor
  --screencast-backend "${SCREENCAST_BACKEND}"
  --portal-cursor metadata
  --fps 1
  --cursor-hz 15
  --no-viewer-key
)
if [[ "${SCREENCAST_BACKEND}" == "mutter" ]]; then
  CLIENT_ARGS+=(--monitor-name "${MONITOR_NAME}")
  echo "using direct Mutter/niri ScreenCast backend on monitor ${MONITOR_NAME}"
else
  echo "using XDG ScreenCast portal backend; accept the desktop chooser if it appears"
fi

echo "starting Wayland video capture; expecting VAAPI/DMA-BUF backend"
./target/debug/glacialcast-client "${CLIENT_ARGS[@]}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

vaapi_attempted() {
  grep -q "PipeWire video delivered DMA-BUF frame for VAAPI import" "${CLIENT_LOG}" ||
    grep -q "backend=VaapiDmabuf" "${CLIENT_LOG}"
}

cpu_fallback_required() {
  grep -q "VAAPI DMA-BUF path failed; falling back to CPU-readable PipeWire plus software H.264" "${CLIENT_LOG}" ||
    grep -q "CPU-readable VAAPI upload failed; falling back to software H.264" "${CLIENT_LOG}" ||
    grep -q "h264_vaapi is unavailable; falling back to CPU-readable PipeWire plus software H.264" "${CLIENT_LOG}"
}

cpu_vaapi_upload_required() {
  grep -q "VAAPI DMA-BUF path failed; falling back to CPU-readable PipeWire plus VAAPI H.264 upload" "${CLIENT_LOG}" ||
    grep -q "backend=CpuVaapiUpload" "${CLIENT_LOG}"
}

software_backend_active() {
  grep -q "backend=CpuSoftware" "${CLIENT_LOG}" ||
    grep -q "CPU-readable VAAPI upload failed; falling back to software H.264" "${CLIENT_LOG}" ||
    grep -q "initialized FFmpeg software H.264 encoder" "${CLIENT_LOG}"
}

random_access_decodes() {
  local stream_id="$1"
  local keyframe_seq
  keyframe_seq="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams/${stream_id}/video" 2>/dev/null |
      python3 -c '
import json, sys
for chunk in json.load(sys.stdin):
    if chunk.get("keyframe"):
        print(chunk["seq"])
        break
' 2>/dev/null
  )"
  [[ -n "${keyframe_seq}" ]] || return 1
  curl -fsS \
    "http://${CONTROL_ADDR}/api/streams/${stream_id}/video/${keyframe_seq}" \
    -o "${RAP_FILE}" || return 1
  python3 - "${RAP_FILE}" <<'PY' >/dev/null || return 1
from pathlib import Path
import sys

payload = Path(sys.argv[1]).read_bytes()
types = []
index = 0
while index + 3 < len(payload):
    if payload[index:index + 4] == b"\x00\x00\x00\x01":
        types.append(payload[index + 4] & 0x1f)
        index += 4
    elif payload[index:index + 3] == b"\x00\x00\x01":
        types.append(payload[index + 3] & 0x1f)
        index += 3
    else:
        index += 1
if not {5, 7, 8}.issubset(types):
    raise SystemExit(f"missing SPS/PPS/IDR in NAL types {types}")
PY
  ffprobe -v error -f h264 -show_entries frame=key_frame \
    -of default=noprint_wrappers=1:nokey=1 "${RAP_FILE}" 2>/dev/null |
    grep -q '^1$'
}

deadline=$((SECONDS + CLIENT_TIMEOUT))
while (( SECONDS < deadline )); do
  STREAM_ID="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams" 2>/dev/null | python3 -c '
import json, sys
streams = json.load(sys.stdin)
for stream in streams:
    if stream.get("display_name") == "Wayland Video Hardware Verify":
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
      if ! random_access_decodes "${STREAM_ID}"; then
        sleep 0.25
        continue
      fi
      if vaapi_attempted && ! cpu_fallback_required; then
        if cpu_vaapi_upload_required; then
          if [[ "${REQUIRE_HARDWARE}" == "1" ]]; then
            echo "FAIL: VAAPI/DMA-BUF was attempted first but CPU-readable PipeWire fallback was required; client log: ${CLIENT_LOG}" >&2
            tail -n 120 "${CLIENT_LOG}" >&2 || true
            exit 1
          fi
          echo "PASS: server received ${CHUNK_COUNT} H.264 video chunks; VAAPI/DMA-BUF was attempted first, then CPU-readable PipeWire plus VAAPI H.264 upload was required"
          exit 0
        fi
        echo "PASS: server received ${CHUNK_COUNT} H.264 video chunks and client used VAAPI/DMA-BUF"
        exit 0
      fi
      if vaapi_attempted && cpu_fallback_required && software_backend_active; then
        if [[ "${REQUIRE_HARDWARE}" == "1" ]]; then
          echo "FAIL: VAAPI/DMA-BUF was attempted first but CPU fallback was required; client log: ${CLIENT_LOG}" >&2
          tail -n 120 "${CLIENT_LOG}" >&2 || true
          exit 1
        fi
        if cpu_vaapi_upload_required; then
          echo "PASS: server received ${CHUNK_COUNT} H.264 video chunks; VAAPI/DMA-BUF and CPU-readable VAAPI upload were attempted first, then software H.264 was required"
          exit 0
        fi
        echo "PASS: server received ${CHUNK_COUNT} H.264 video chunks; VAAPI/DMA-BUF was attempted first, then CPU fallback was required"
        exit 0
      fi
    fi
  fi

  if grep -q "falling back to CPU-readable PipeWire plus" "${CLIENT_LOG}" && ! vaapi_attempted; then
    echo "FAIL: wayland-video fell back before a VAAPI/DMA-BUF attempt was observed; client log: ${CLIENT_LOG}" >&2
    tail -n 120 "${CLIENT_LOG}" >&2 || true
    exit 1
  fi

  if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
    wait "${CLIENT_PID}"
    STATUS="$?"
    echo "FAIL: client exited before VAAPI/DMA-BUF video was verified; client log: ${CLIENT_LOG}" >&2
    tail -n 120 "${CLIENT_LOG}" >&2 || true
    exit "${STATUS}"
  fi
  sleep 0.25
done

echo "FAIL: timed out before VAAPI/DMA-BUF video was verified; client log: ${CLIENT_LOG}" >&2
tail -n 120 "${CLIENT_LOG}" >&2 || true
exit 1
