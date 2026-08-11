#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

version="$(cargo metadata --locked --no-deps --format-version 1 | node -e \
  "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const m=JSON.parse(s);process.stdout.write(m.packages.find(p=>p.name==='gcrelay').version)})")"
work_dir="$(mktemp -d /tmp/glacialcast-package.XXXXXX)"
trap 'find "${work_dir}" -depth -delete 2>/dev/null || true' EXIT

archive="$(GLACIALCAST_DIST_DIR="${work_dir}/dist" \
  CARGO_TARGET_DIR="${work_dir}/target" scripts/build-release.sh)"
archive_name="${archive##*/}"
(
  cd "${work_dir}/dist"
  sha256sum --check "${archive_name}.sha256"
)

mkdir -p "${work_dir}/extracted"
tar -xzf "${archive}" -C "${work_dir}/extracted"
bundle_root="$(find "${work_dir}/extracted" -mindepth 1 -maxdepth 1 -type d -print -quit)"

for binary in gcpub gcrelay gcview; do
  actual="$("${bundle_root}/bin/${binary}" --version)"
  [[ "${actual}" == "${binary} ${version}" ]] || {
    echo "${binary} reported ${actual@Q}, expected ${version}" >&2
    exit 1
  }
done

node - "${bundle_root}/SBOM.spdx.json" "${version}" <<'NODE'
const fs = require('fs');
const document = JSON.parse(fs.readFileSync(process.argv[2]));
const version = process.argv[3];
if (document.spdxVersion !== 'SPDX-2.3') throw new Error('unexpected SPDX version');
for (const name of ['gcpub', 'gcrelay', 'gcview']) {
  if (!document.packages.some(pkg => pkg.name === name && pkg.versionInfo === version)) {
    throw new Error(`SBOM is missing ${name}`);
  }
}
for (const name of ['PipeWire', 'OpenH264']) {
  if (!document.packages.some(pkg => pkg.name === name)) {
    throw new Error(`SBOM is missing ${name}`);
  }
}
if (!document.relationships.some(item => item.relationshipType === 'DEPENDS_ON')) {
  throw new Error('SBOM contains no dependency relationships');
}
NODE

for expected in LICENSE README.md SBOM.spdx.json deploy/gcrelay.service \
  docs/release-operations.md; do
  [[ -f "${bundle_root}/${expected}" ]] || {
    echo "release archive is missing ${expected}" >&2
    exit 1
  }
done

packaging/verify-systemd.sh
echo "PASS: native release archive versions, checksum, SBOM, contents, and service units are valid"
