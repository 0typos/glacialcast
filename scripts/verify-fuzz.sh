#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

seconds="${GLACIALCAST_FUZZ_SECONDS:-30}"
toolchain="${GLACIALCAST_FUZZ_TOOLCHAIN:-nightly-2026-07-03}"
# A floor low enough that a slow shared runner clears it easily, and high
# enough that a harness which is not actually running cannot.
min_executions="${GLACIALCAST_FUZZ_MIN_EXECUTIONS:-1000}"
if ! [[ "${seconds}" =~ ^[0-9]+$ ]] || (( seconds < 1 )); then
  echo "GLACIALCAST_FUZZ_SECONDS must be a positive integer" >&2
  exit 2
fi
if ! cargo "+${toolchain}" fuzz --help >/dev/null 2>&1; then
  echo "cargo-fuzz and Rust ${toolchain} are required" >&2
  echo "install with: rustup toolchain install ${toolchain} && cargo install cargo-fuzz --version 0.13.2 --locked" >&2
  exit 2
fi

# Discovered inputs land in the checked-in corpus and stay there.
#
# This used to copy the seeds into a temporary directory and delete it on exit,
# so every run was a cold start from the same few bytes and libFuzzer relearned
# the same shapes forever -- six sixty-second runs a night that could never
# accumulate. Writing into fuzz/corpus means a run that finds new coverage
# leaves it behind for the next one, and for anyone who wants to commit it.
#
# GLACIALCAST_FUZZ_EPHEMERAL=1 restores the old behaviour for a run that must
# not touch the tree.
fuzz_log_dir="$(mktemp -d -t glacialcast-fuzz.XXXXXX)"
trap 'find "${fuzz_log_dir}" -depth -delete' EXIT
ephemeral="${GLACIALCAST_FUZZ_EPHEMERAL:-0}"

for target in \
  noise_segment \
  native_wire \
  pair_request \
  h264_epoch; do
  target_log="${fuzz_log_dir}/${target}.log"
  if [[ "${ephemeral}" == "1" ]]; then
    target_corpus="${fuzz_log_dir}/${target}"
    mkdir -p "${target_corpus}"
    cp -a "fuzz/corpus/${target}/." "${target_corpus}/"
  else
    target_corpus="fuzz/corpus/${target}"
  fi
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
  # Asserted, not merely printed. A target that stops executing -- a harness
  # that panics on every input, a corpus that will not load, a build that no
  # longer instruments -- otherwise reports a clean pass with "unknown"
  # executions, which is what a green nightly looked like.
  if ! [[ "${executions}" =~ ^[0-9]+$ ]]; then
    echo "${target} reported no execution count; the run proved nothing" >&2
    cat "${target_log}" >&2
    exit 1
  fi
  if (( executions < min_executions )); then
    echo "${target} executed only ${executions} inputs in ${seconds}s;" >&2
    echo "expected at least ${min_executions} -- the harness is probably not running" >&2
    cat "${target_log}" >&2
    exit 1
  fi
  echo "PASS: ${target} (${executions} executions)"
done

echo "PASS: all parser fuzz targets completed ${seconds}s each"
