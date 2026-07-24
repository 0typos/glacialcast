#!/usr/bin/env bash
set -euo pipefail

missing_commands=()
for command_name in cargo pkg-config ffprobe; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    missing_commands+=("${command_name}")
  fi
done

if (( ${#missing_commands[@]} > 0 )); then
  echo "missing required commands: ${missing_commands[*]}" >&2
  exit 1
fi

missing_modules=()
for module_name in \
  libavcodec \
  libavfilter \
  libavutil \
  libswscale \
  libva \
  libpipewire-0.3
do
  if ! pkg-config --exists "${module_name}"; then
    missing_modules+=("${module_name}")
  fi
done

if (( ${#missing_modules[@]} > 0 )); then
  echo "missing pkg-config modules: ${missing_modules[*]}" >&2
  echo "Fedora install command:" >&2
  echo "  sudo dnf install pipewire-devel libva-devel pkgconf-pkg-config \\" >&2
  echo "    libavcodec-free-devel libavfilter-free-devel libavutil-free-devel \\" >&2
  echo "    libswscale-free-devel" >&2
  exit 1
fi

ffmpeg_major="$(
  pkg-config --modversion libavcodec |
    awk -F. '{ print $1 }'
)"
if (( ffmpeg_major < 62 )); then
  echo "libavcodec 62 or newer is required for the pinned FFmpeg 8 bindings" >&2
  exit 1
fi

echo "PASS: PipeWire, libva, and FFmpeg 8 development prerequisites are available"
