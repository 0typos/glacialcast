#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

command -v systemd-analyze >/dev/null || {
  echo "SKIP: systemd-analyze is unavailable"
  exit 0
}

work_dir="$(mktemp -d /tmp/glacialcast-systemd.XXXXXX)"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

sed \
  "s#/usr/local/bin/glacialcast-server#${repo_root}/target/release/glacialcast-server#" \
  deploy/glacialcast-server.service >"${work_dir}/glacialcast-server.service"
systemd-analyze verify "${work_dir}/glacialcast-server.service"
echo "PASS: systemd unit is valid"
