#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

seconds="${GLACIALCAST_FUZZ_SECONDS:-30}"
toolchain="${GLACIALCAST_FUZZ_TOOLCHAIN:-nightly-2026-07-03}"
if ! [[ "${seconds}" =~ ^[0-9]+$ ]] || (( seconds < 1 )); then
  echo "GLACIALCAST_FUZZ_SECONDS must be a positive integer" >&2
  exit 2
fi
if ! cargo "+${toolchain}" fuzz --help >/dev/null 2>&1; then
  echo "cargo-fuzz and Rust ${toolchain} are required" >&2
  echo "install with: rustup toolchain install ${toolchain} && cargo install cargo-fuzz --locked" >&2
  exit 2
fi

fuzz_tmp_dir="$(mktemp -d -t glacialcast-fuzz.XXXXXX)"
trap 'rm -rf -- "${fuzz_tmp_dir}"' EXIT

for target in \
  portable_object \
  cursor_envelope \
  noise_segment \
  epoch_descriptor \
  catalog_journal; do
  target_corpus="${fuzz_tmp_dir}/${target}"
  target_log="${fuzz_tmp_dir}/${target}.log"
  mkdir -p "${target_corpus}"
  cp -a "fuzz/corpus/${target}/." "${target_corpus}/"
  if ! cargo "+${toolchain}" fuzz run "${target}" "${target_corpus}" -- \
    -dict=fuzz/dictionaries/glacialcast.dict \
    "-max_total_time=${seconds}" \
    -timeout=5 \
    -print_final_stats=1 \
    -verbosity=0 >"${target_log}" 2>&1; then
    cat "${target_log}" >&2
    exit 1
  fi
  executions="$(sed -n 's/^stat::number_of_executed_units:[[:space:]]*//p' "${target_log}" | tail -1)"
  echo "PASS: ${target} (${executions:-unknown} executions)"
done

echo "PASS: all parser fuzz targets completed ${seconds}s each"
