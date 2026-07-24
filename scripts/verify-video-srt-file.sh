#!/usr/bin/env bash
set -u

OUT="${GLACIALCAST_VERIFY_SRT_FILE:-/tmp/glacialcast-video-srt-verify.$$}.ts"
RUN_SECONDS="${GLACIALCAST_VERIFY_SRT_SECONDS:-5}"

cleanup() {
  rm -f "${OUT}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd cargo
need_cmd ffprobe
need_cmd timeout

rm -f "${OUT}"

scripts/verify-prerequisites.sh
echo "building hardware-enabled Glacialcast client"
cargo build -p glacialcast-client --features ffmpeg-vaapi

set +e
timeout -s INT "${RUN_SECONDS}s" ./target/debug/glacialcast-client \
  --config /tmp/glacialcast-missing-client.toml \
  --capture test-video \
  --fps 5 \
  --video-srt-url "${OUT}" \
  --video-srt-only \
  --no-viewer-key
STATUS="$?"
set -e

if [[ "${STATUS}" != "0" && "${STATUS}" != "124" && "${STATUS}" != "130" ]]; then
  echo "FAIL: direct FFmpeg MPEG-TS output client exited with status ${STATUS}" >&2
  exit "${STATUS}"
fi

if [[ ! -s "${OUT}" ]]; then
  echo "FAIL: direct FFmpeg MPEG-TS output file was not created" >&2
  exit 1
fi

STREAM_INFO="$(ffprobe -hide_banner -loglevel error \
  -select_streams v:0 \
  -show_entries stream=codec_name,width,height,nb_read_packets \
  -count_packets \
  -of default=nw=1 "${OUT}")"

if ! grep -q '^codec_name=h264$' <<<"${STREAM_INFO}"; then
  echo "FAIL: expected h264 video stream in ${OUT}" >&2
  echo "${STREAM_INFO}" >&2
  exit 1
fi

PACKETS="$(awk -F= '/^nb_read_packets=/{print $2; exit}' <<<"${STREAM_INFO}")"
if [[ ! "${PACKETS:-0}" =~ ^[0-9]+$ ]] || (( PACKETS < 1 )); then
  echo "FAIL: expected at least one H.264 packet in ${OUT}" >&2
  echo "${STREAM_INFO}" >&2
  exit 1
fi

echo "PASS: direct FFmpeg MPEG-TS output contains H.264 video (${PACKETS} packets)"
