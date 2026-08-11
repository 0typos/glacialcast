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
  # Without `-L error` the warn-level diagnostics are printed too. Duplicate
  # versions are only a warning here, and silently dropping them meant the gate
  # reported "ok" while the graph grew forks nobody saw.
  run cargo deny check
  run bash -n scripts/*.sh packaging/*.sh
}

full_checks() {
  standard_checks
  run scripts/verify-native-e2e.sh
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
    run scripts/verify-native-e2e.sh
    ;;
  *)
    usage
    exit 2
    ;;
esac

printf '\nPASS: %s quality profile\n' "${profile}"
