#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

version="$(
  cargo metadata --locked --no-deps --format-version 1 \
    | node -e \
      "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const m=JSON.parse(s);process.stdout.write(m.packages.find(p=>p.name==='gcrelay').version)})"
)"
revision="$(git rev-parse HEAD 2>/dev/null || printf 'uncommitted')"
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal 2>/dev/null)" ]]; then
  revision="${revision}-dirty"
fi
final_dist="${GLACIALCAST_DIST_DIR:-${repo_root}/dist}"
work_dir="$(mktemp -d /tmp/glacialcast-package.XXXXXX)"
first_dist="${work_dir}/dist-first"
second_dist="${work_dir}/dist-second"
first_target="${work_dir}/target-first"
second_target="${work_dir}/target-second"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

archive="$(
  GLACIALCAST_DIST_DIR="${first_dist}" \
  CARGO_TARGET_DIR="${first_target}" \
    scripts/build-release.sh
)"
archive_name="${archive##*/}"
read -r first_digest _ < <(sha256sum "${archive}")
second_archive="$(
  GLACIALCAST_DIST_DIR="${second_dist}" \
  CARGO_TARGET_DIR="${second_target}" \
    scripts/build-release.sh
)"
read -r second_digest _ < <(sha256sum "${second_archive}")
[[ "${archive_name}" == "${second_archive##*/}" && "${first_digest}" == "${second_digest}" ]] || {
  echo "independent release builds did not produce the same archive" >&2
  exit 1
}

(
  cd "${first_dist}"
  sha256sum --check "${archive_name}.sha256"
)
extract_dir="${work_dir}/extracted"
mkdir -p "${extract_dir}"
tar -xzf "${archive}" -C "${extract_dir}"
bundle_root="$(find "${extract_dir}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "${bundle_root}" ]]

for binary in gcpub glacialcast-offline gcrelay; do
  actual="$("${bundle_root}/bin/${binary}" --version)"
  [[ "${actual}" == "${binary} ${version}" ]] || {
    echo "${binary} reported ${actual@Q}, expected version ${version}" >&2
    exit 1
  }
done

node - "${bundle_root}/SBOM.spdx.json" "${version}" "${revision}" <<'NODE'
const fs = require('fs');
const document = JSON.parse(fs.readFileSync(process.argv[2]));
const version = process.argv[3];
const revision = process.argv[4];
if (document.spdxVersion !== 'SPDX-2.3') throw new Error('unexpected SPDX version');
for (const name of ['gcpub', 'glacialcast-offline', 'gcrelay']) {
  if (!document.packages.some(pkg => pkg.name === name && pkg.versionInfo === version)) {
    throw new Error(`SBOM is missing ${name}`);
  }
}
for (const name of ['PipeWire', 'libgbm', 'libva', 'OpenH264']) {
  if (!document.packages.some(pkg => pkg.name === name)) {
    throw new Error(`SBOM is missing native runtime dependency ${name}`);
  }
}
if (!document.documentNamespace.endsWith(`/${encodeURIComponent(revision)}`)) {
  throw new Error('SBOM revision provenance does not match the source worktree');
}
if (!document.relationships.some(item => item.relationshipType === 'DEPENDS_ON')) {
  throw new Error('SBOM contains no dependency relationships');
}
NODE

for expected in \
  LICENSE \
  README.md \
  SBOM.spdx.json \
  deploy/gcrelay.service \
  docs/release-operations.md; do
  [[ -f "${bundle_root}/${expected}" ]] || {
    echo "release archive is missing ${expected}" >&2
    exit 1
  }
done

packaging/verify-systemd.sh
mkdir -p "${final_dist}"
cp -a "${archive}" "${first_dist}/${archive_name}.sha256" "${final_dist}/"
if [[ -f "${archive}.minisig" ]]; then
  cp -a "${archive}.minisig" "${final_dist}/"
fi
echo "PASS: independently reproducible release archive, exact binary versions, checksum, SBOM, provenance, and service unit are valid"
