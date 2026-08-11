#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

version="$(
  cargo metadata --locked --no-deps --format-version 1 \
    | node -e \
      "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const m=JSON.parse(s);process.stdout.write(m.packages.find(p=>p.name==='gcrelay').version)})"
)"
target="$(rustc -vV | sed -n 's/^host: //p')"
revision="$(git rev-parse HEAD 2>/dev/null || printf 'uncommitted')"
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal 2>/dev/null)" ]]; then
  if [[ "${GLACIALCAST_REQUIRE_CLEAN:-0}" == "1" ]]; then
    echo "release build requires a clean worktree" >&2
    exit 1
  fi
  revision="${revision}-dirty"
fi
source_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
dist_dir="${GLACIALCAST_DIST_DIR:-${repo_root}/dist}"
target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
bundle_name="glacialcast-v${version}-${target}"
archive="${dist_dir}/${bundle_name}.tar.gz"
build_root="$(mktemp -d /tmp/glacialcast-release.XXXXXX)"
bundle_root="${build_root}/${bundle_name}"

cleanup() {
  rm -rf "${build_root}"
}
trap cleanup EXIT

CARGO_TARGET_DIR="${target_dir}" cargo build --workspace --release --locked
mkdir -p \
  "${bundle_root}/bin" \
  "${bundle_root}/deploy" \
  "${bundle_root}/docs" \
  "${dist_dir}"
cp -a \
  "${target_dir}/release/gcpub" \
  "${target_dir}/release/gcrelay" \
  "${target_dir}/release/gcview" \
  "${bundle_root}/bin/"
cp -a deploy/. "${bundle_root}/deploy/"
cp -a \
  docs/internet-deployment.md \
  docs/release-operations.md \
  docs/support-matrix.md \
  docs/testing-demo-guide.md \
  "${bundle_root}/docs/"
cp -a LICENSE README.md "${bundle_root}/"

SOURCE_DATE_EPOCH="${source_epoch}" \
GLACIALCAST_RELEASE_REVISION="${revision}" \
  node scripts/generate-sbom.mjs "${bundle_root}/SBOM.spdx.json"

tar \
  --sort=name \
  "--mtime=@${source_epoch}" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -czf "${archive}" \
  -C "${build_root}" \
  "${bundle_name}"
(
  cd "${dist_dir}"
  sha256sum "${bundle_name}.tar.gz" >"${bundle_name}.tar.gz.sha256"
)

if [[ -n "${GLACIALCAST_MINISIGN_SECRET_KEY:-}" ]]; then
  command -v minisign >/dev/null || {
    echo "GLACIALCAST_MINISIGN_SECRET_KEY was set but minisign is unavailable" >&2
    exit 1
  }
  minisign \
    -S \
    -s "${GLACIALCAST_MINISIGN_SECRET_KEY}" \
    -m "${archive}" \
    -x "${archive}.minisig"
fi

printf '%s\n' "${archive}"
