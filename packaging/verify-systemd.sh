#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

grep -Fq -- '--foreground' deploy/gcpub.service
grep -Fq -- '--publisher-addr' deploy/gcrelay.service
grep -Fq -- '--viewer-addr' deploy/gcrelay.service
if grep -Eq -- 'control-addr|retention-bytes-per-stream|print-viewer-key' \
  deploy/gcrelay.service deploy/gcpub.service; then
  echo "systemd units contain removed command-line options" >&2
  exit 1
fi

if command -v systemd-analyze >/dev/null; then
  for binary in gcrelay gcpub; do
    [[ -x "target/release/${binary}" ]] || cargo build --release --locked -p "${binary}" >&2
  done
  work_dir="$(mktemp -d /tmp/glacialcast-systemd.XXXXXX)"
  trap 'find "${work_dir}" -depth -delete 2>/dev/null || true' EXIT
  sed "s#/usr/local/bin/gcrelay#${repo_root}/target/release/gcrelay#" \
    deploy/gcrelay.service >"${work_dir}/gcrelay.service"
  sed "s#/usr/local/bin/gcpub#${repo_root}/target/release/gcpub#" \
    deploy/gcpub.service >"${work_dir}/gcpub.service"
  systemd-analyze verify "${work_dir}/gcrelay.service"
  systemd-analyze --user verify "${work_dir}/gcpub.service"
fi

echo "PASS: native systemd units use current commands and validate"
