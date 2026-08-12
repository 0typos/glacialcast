#!/usr/bin/env bash
set -euo pipefail

missing_commands=()
for command_name in cargo clang pkg-config; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    missing_commands+=("${command_name}")
  fi
done

if (( ${#missing_commands[@]} > 0 )); then
  echo "missing required commands: ${missing_commands[*]}" >&2
  exit 1
fi

missing_modules=()
if ! pkg-config --exists libpipewire-0.3; then
  missing_modules+=("libpipewire-0.3")
fi

if (( ${#missing_modules[@]} > 0 )); then
  echo "missing pkg-config modules: ${missing_modules[*]}" >&2
  echo "Fedora install command:" >&2
  echo "  sudo dnf install pipewire-devel clang-devel pkgconf-pkg-config" >&2
  exit 1
fi

echo "PASS: Rust, Clang, and PipeWire build prerequisites are available"
