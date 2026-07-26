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

sed \
  "s#/usr/local/bin/glacialcast-client#${repo_root}/target/release/glacialcast-client#" \
  deploy/glacialcast-publisher.service >"${work_dir}/glacialcast-publisher.service"
systemd-analyze --user verify "${work_dir}/glacialcast-publisher.service"

# The publisher detaches by default, so a supervised unit must keep it in the
# foreground or systemd would treat the immediate parent exit as a failure.
grep -Fq -- '--foreground' deploy/glacialcast-publisher.service || {
  echo "publisher unit must pass --foreground so systemd can supervise it" >&2
  exit 1
}
echo "PASS: systemd units are valid"
