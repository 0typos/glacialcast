#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

compositor="${GLACIALCAST_PLATFORM_COMPOSITOR:-unknown}"
gpu_vendor="${GLACIALCAST_PLATFORM_GPU_VENDOR:-unknown}"
gpu_model="${GLACIALCAST_PLATFORM_GPU_MODEL:-unknown}"
output="${GLACIALCAST_PLATFORM_OUTPUT:-}"
run_gates="${GLACIALCAST_PLATFORM_RUN_GATES:-0}"

usage() {
  echo "usage: scripts/record-platform-support.sh [--compositor NAME] [--gpu-vendor NAME] [--gpu-model NAME] [--output PATH] [--run-gates]" >&2
}

while (($#)); do
  case "$1" in
    --compositor)
      compositor="${2:?missing compositor name}"
      shift 2
      ;;
    --gpu-vendor)
      gpu_vendor="${2:?missing GPU vendor}"
      shift 2
      ;;
    --gpu-model)
      gpu_model="${2:?missing GPU model}"
      shift 2
      ;;
    --output)
      output="${2:?missing output path}"
      shift 2
      ;;
    --run-gates)
      run_gates=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${output}" ]]; then
  safe_compositor="${compositor//[^[:alnum:]._-]/-}"
  output="/tmp/glacialcast-platform-${safe_compositor}-$(date -u +%Y%m%dT%H%M%SZ).md"
fi

cursor_status="not-run"
picture_status="not-run"
video_status="not-run"
cursor_log=""
picture_log=""
video_log=""
if [[ "${run_gates}" == "1" ]]; then
  cursor_log="${output}.cursor.log"
  picture_log="${output}.picture.log"
  video_log="${output}.video.log"
  if scripts/verify-wayland-cursor-metadata.sh >"${cursor_log}" 2>&1; then
    cursor_status="pass"
  else
    cursor_status="fail"
  fi
  if scripts/verify-wayland-picture.sh >"${picture_log}" 2>&1; then
    picture_status="pass"
    if grep -q '^SKIP:' "${picture_log}"; then
      picture_status="skip"
    fi
  else
    picture_status="fail"
  fi
  if scripts/verify-wayland-video-hardware.sh >"${video_log}" 2>&1; then
    video_status="pass"
  else
    video_status="fail"
  fi
fi

kernel="$(uname -srmo)"
rust_version="$(rustc --version)"
wayland_display="${WAYLAND_DISPLAY:-unset}"
desktop="${XDG_CURRENT_DESKTOP:-unset}"
session_type="${XDG_SESSION_TYPE:-unset}"
pipewire_version="$(pipewire --version 2>/dev/null | head -1 || true)"
libva_version="$(vainfo --version 2>/dev/null | head -1 || true)"

{
  echo "# GlacialCast platform evidence"
  echo
  echo "- Recorded UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Commit: $(git rev-parse HEAD)"
  echo "- Compositor: ${compositor}"
  echo "- Desktop: ${desktop}"
  echo "- Session type: ${session_type}"
  echo "- WAYLAND_DISPLAY: ${wayland_display}"
  echo "- GPU vendor: ${gpu_vendor}"
  echo "- GPU model: ${gpu_model}"
  echo "- Kernel: ${kernel}"
  echo "- Rust: ${rust_version}"
  echo "- PipeWire: ${pipewire_version:-unavailable}"
  echo "- libva: ${libva_version:-unavailable}"
  echo
  echo "## Gate results"
  echo
  echo "| Gate | Result | Log |"
  echo "| --- | --- | --- |"
  echo "| Independent cursor metadata | ${cursor_status} | ${cursor_log:-n/a} |"
  echo "| Published picture matches the screen | ${picture_status} | ${picture_log:-n/a} |"
  echo "| VA-API / DMA-BUF video | ${video_status} | ${video_log:-n/a} |"
  echo
  echo "A release support claim requires these logs, the compositor/portal version,"
  echo "GPU model, and a human playback check in Firefox."
} >"${output}"

echo "Platform evidence written to ${output}"
if [[ "${run_gates}" == "1" ]] \
  && [[ "${cursor_status}" != "pass" \
    || "${picture_status}" == "fail" \
    || "${video_status}" != "pass" ]]; then
  exit 1
fi
