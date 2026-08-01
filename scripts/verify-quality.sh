#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

profile="${1:-standard}"

usage() {
  echo "usage: scripts/verify-quality.sh [standard|full|soak]" >&2
}

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

standard_checks() {
  run cargo fmt --all -- --check
  run cargo fmt --manifest-path fuzz/Cargo.toml -- --check
  run cargo test --workspace --all-features
  run cargo clippy --workspace --all-targets --all-features -- \
    -D warnings \
    -D clippy::undocumented_unsafe_blocks
  run env "RUSTDOCFLAGS=-D warnings -D missing-docs" cargo doc --workspace --no-deps
  run cargo deny -L error check
  run bash -n scripts/*.sh packaging/*.sh
  run node scripts/test-viewer-core.mjs
  run node scripts/test-viewer-key.mjs
  run node scripts/test-epoch-claim.mjs
  run node scripts/generate-viewer-key-wordlist.mjs --check
  run node scripts/test-index-ui.mjs
  run node scripts/test-compare-frame.mjs
}

full_checks() {
  standard_checks
  run scripts/verify-dash-e2e.sh
  run scripts/verify-viewer-onboarding.sh
  run scripts/verify-multi-stream.sh
  run scripts/verify-ingest-recovery.sh
  run scripts/verify-internet-security.sh
  run scripts/verify-bandwidth.sh
  run scripts/verify-performance.sh
  run scripts/verify-packaging.sh
}

case "${profile}" in
  standard)
    standard_checks
    ;;
  full)
    full_checks
    ;;
  soak)
    standard_checks
    run scripts/verify-soak.sh
    ;;
  *)
    usage
    exit 2
    ;;
esac

printf '\nPASS: %s quality profile\n' "${profile}"
