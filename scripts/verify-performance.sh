#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

cargo run --release -p glacialcast-protocol --example perf_probe
cargo test --release -p gcrelay \
  relay_persistence_performance_supports_target_object_rate \
  -- --ignored --nocapture --test-threads=1
node scripts/test-viewer-core.mjs
