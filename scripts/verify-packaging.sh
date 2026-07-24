#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

archive="$(scripts/build-release.sh)"
archive_dir="${archive%/*}"
archive_name="${archive##*/}"
read -r first_digest _ < <(sha256sum "${archive}")
second_archive="$(scripts/build-release.sh)"
read -r second_digest _ < <(sha256sum "${second_archive}")
[[ "${archive}" == "${second_archive}" && "${first_digest}" == "${second_digest}" ]] || {
  echo "two release builds did not produce the same archive" >&2
  exit 1
}
work_dir="$(mktemp -d /tmp/glacialcast-package.XXXXXX)"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

(
  cd "${archive_dir}"
  sha256sum --check "${archive_name}.sha256"
)
tar -xzf "${archive}" -C "${work_dir}"
bundle_root="$(find "${work_dir}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "${bundle_root}" ]]

for binary in glacialcast-client glacialcast-offline glacialcast-server; do
  "${bundle_root}/bin/${binary}" --version | grep -Fq "0."
done

node - "${bundle_root}/SBOM.spdx.json" <<'NODE'
const fs = require('fs');
const document = JSON.parse(fs.readFileSync(process.argv[2]));
if (document.spdxVersion !== 'SPDX-2.3') throw new Error('unexpected SPDX version');
for (const name of ['glacialcast-client', 'glacialcast-offline', 'glacialcast-server']) {
  if (!document.packages.some(pkg => pkg.name === name)) {
    throw new Error(`SBOM is missing ${name}`);
  }
}
if (!document.relationships.some(item => item.relationshipType === 'DEPENDS_ON')) {
  throw new Error('SBOM contains no dependency relationships');
}
NODE

for expected in \
  LICENSE \
  README.md \
  SBOM.spdx.json \
  deploy/glacialcast-server.service \
  docs/release-operations.md; do
  [[ -f "${bundle_root}/${expected}" ]] || {
    echo "release archive is missing ${expected}" >&2
    exit 1
  }
done

packaging/verify-systemd.sh
echo "PASS: reproducible release archive, binaries, checksum, SBOM, and service unit are valid"
