#!/usr/bin/env bash
set -euo pipefail

# End-to-end gate for a stream published without a viewer key.
#
# The mode exists for one reason: WebKit offers FairPlay and never ClearKey, so
# an iPhone can never play an end-to-end encrypted stream however good the key
# is. A publisher on a trusted LAN can send in the clear instead, and this is
# the run that proves the whole path works -- publisher, relay, and both browser
# engines -- without a key existing anywhere in it.
#
# It also checks the fence around the mode: a relay that is not serving a
# trusted LAN must refuse an unencrypted epoch outright rather than store it.
#
# The iPhone half cannot be checked here. Neither engine available to a gate
# exposes ManagedMediaSource, so what runs below is the shared path; the
# ManagedMediaSource branch is exercised only on a real device.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18994}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18995}"
strict_ingest_addr="${GLACIALCAST_VERIFY_STRICT_INGEST_ADDR:-127.0.0.1:18997}"
strict_control_addr="${GLACIALCAST_VERIFY_STRICT_CONTROL_ADDR:-127.0.0.1:18996}"
browsers="${GLACIALCAST_VERIFY_BROWSERS:-firefox,chromium}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-unencrypted.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
strict_server_log="${work_dir}/strict-server.log"
strict_client_log="${work_dir}/strict-client.log"
server_pid=""
client_pid=""
strict_server_pid=""
strict_client_pid=""

cleanup() {
  for pid in "${strict_client_pid}" "${strict_server_pid}" "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

cargo build -p glacialcast-server -p glacialcast-client

ingest_server_key="$(
  target/debug/glacialcast-server \
    --no-config \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"

# --no-tls because the listeners are loopback, which browsers already treat as a
# secure context. A LAN deployment wants the TLS this flag turns off.
RUST_LOG=glacialcast_server=info target/debug/glacialcast-server \
  --no-config \
  --data-dir "${work_dir}/data" \
  --trusted-lan \
  --no-tls \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  >>"${server_log}" 2>&1 &
server_pid="$!"

wait_for_origin() {
  local target="$1"
  for _ in $(seq 1 100); do
    if curl -fsS "${target}/api/streams" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "relay at ${target} never answered" >&2
  return 1
}
wait_for_origin "${origin}"

# Every failure below wants the same thing: say what was expected, show the log
# that would explain it, and stop. Written out at each site it drifted -- the
# tail length already differs between gates in this repo.
fail_with_log() {
  local message="$1"
  shift
  echo "${message}" >&2
  for log in "$@"; do
    sed -n '1,200p' "${log}" >&2
  done
  exit 1
}

RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --no-config \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  --no-encryption \
  --no-viewer-key \
  --foreground \
  --client-id unencrypted-e2e \
  --display-name "Unencrypted E2E" \
  --capture dash-test \
  --test-pattern motion \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 2 \
  --cursor-hz 30 \
  --segment-frames 2 \
  >>"${client_log}" 2>&1 &
client_pid="$!"

stream_id=""
for _ in $(seq 1 150); do
  # `|| true` because this polls: until the publisher registers, grep matches
  # nothing and pipefail would end the run on the first attempt.
  stream_id="$(
    curl -fsS "${origin}/api/streams" 2>/dev/null \
      | grep -oP '"stream_id":"\K[0-9a-f-]+' | head -1 || true
  )"
  if [[ -n "${stream_id}" ]]; then
    break
  fi
  sleep 0.2
done
if [[ -z "${stream_id}" ]]; then
  fail_with_log "the publisher never registered a stream; server and client output follows" \
    "${server_log}" "${client_log}"
fi
echo "publishing unencrypted stream ${stream_id}"

# --no-viewer-key on both publishers on purpose: an unencrypted stream has no
# viewer key, and requiring one anyway made this exact combination print a
# healthy summary and then die in the daemon log without publishing anything.
#
# The descriptor is what the viewer reads to decide there is no key, so it is
# checked here directly rather than only through a browser.
epoch_sequence=""
for _ in $(seq 1 150); do
  epoch_sequence="$(
    curl -fsS "${origin}/api/dash/streams/${stream_id}/objects" 2>/dev/null \
      | grep -oP '"kind":"Epoch"[^}]*"sequence":\K[0-9]+' | tail -1 || true
  )"
  if [[ -n "${epoch_sequence}" ]]; then
    break
  fi
  sleep 0.2
done
if [[ -z "${epoch_sequence}" ]]; then
  echo "no epoch object was published" >&2
  exit 1
fi
descriptor="$(curl -fsS "${origin}/api/dash/streams/${stream_id}/objects/${epoch_sequence}")"
if ! grep -q '"encrypted":false' <<<"${descriptor}"; then
  echo "the epoch descriptor does not declare itself unencrypted: ${descriptor}" >&2
  exit 1
fi
echo "epoch descriptor declares encrypted=false"

for browser in ${browsers//,/ }; do
  node scripts/verify-unencrypted-browser.mjs "${origin}" "${stream_id}" "${browser}"
done

# The fence: the same publisher against a relay that is not serving a trusted
# LAN must be refused, and must leave nothing behind.
#
# Its own data directory means its own ingest identity, so the publisher below
# needs that relay's key. Reusing the first one fails the Noise handshake, which
# looks like a refusal without ever testing one.
strict_ingest_server_key="$(
  target/debug/glacialcast-server \
    --no-config \
    --data-dir "${work_dir}/strict-data" \
    --print-ingest-server-key
)"

RUST_LOG=glacialcast_server=info target/debug/glacialcast-server \
  --no-config \
  --data-dir "${work_dir}/strict-data" \
  --control-addr "${strict_control_addr}" \
  --ingest-addr "${strict_ingest_addr}" \
  >>"${strict_server_log}" 2>&1 &
strict_server_pid="$!"
wait_for_origin "http://${strict_control_addr}"

RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --no-config \
  --ingest-addr "${strict_ingest_addr}" \
  "--ingest-server-key=${strict_ingest_server_key}" \
  --no-encryption \
  --no-viewer-key \
  --foreground \
  --client-id unencrypted-refused \
  --display-name "Unencrypted Refused" \
  --capture dash-test \
  --test-pattern static \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 2 \
  --segment-frames 2 \
  >>"${strict_client_log}" 2>&1 &
strict_client_pid="$!"

refused=0
for _ in $(seq 1 100); do
  if grep -q "refusing an unencrypted epoch" "${strict_server_log}"; then
    refused=1
    break
  fi
  sleep 0.2
done
if (( refused == 0 )); then
  fail_with_log "a relay without --trusted-lan accepted an unencrypted epoch" \
    "${strict_server_log}"
fi

# The refusal has to reach the publisher, not just the relay's log. Dropping the
# connection alone is indistinguishable from a network fault, so the publisher
# used to reconnect forever while the one actionable sentence stayed here.
wait "${strict_client_pid}" 2>/dev/null || true
strict_client_pid=""
if ! grep -q "relay refused object" "${strict_client_log}"; then
  fail_with_log "the publisher was never told why it was refused" "${strict_client_log}"
fi
if ! grep -q "trusted-lan" "${strict_client_log}"; then
  fail_with_log "the refusal reached the publisher without the reason" "${strict_client_log}"
fi
retries="$(grep -c "DASH connection dropped" "${strict_client_log}" || true)"
if [[ "${retries}" != "0" ]]; then
  echo "the publisher retried a refusal ${retries} times instead of stopping" >&2
  exit 1
fi
echo "the publisher was told why, and stopped instead of retrying"
# Refusing has to mean refusing, not logging and storing anyway. The stream is
# registered by the Hello that precedes the epoch, so it is the objects behind
# it that must be absent -- and it is this relay's own stream that is asked
# about, which is not the one the browsers just watched.
strict_stream_id="$(
  curl -fsS "http://${strict_control_addr}/api/streams" 2>/dev/null \
    | grep -oP '"stream_id":"\K[0-9a-f-]+' | head -1 || true
)"
if [[ -n "${strict_stream_id}" ]]; then
  stored="$(
    curl -fsS "http://${strict_control_addr}/api/dash/streams/${strict_stream_id}/objects" \
      2>/dev/null | grep -c '"kind":"Media"' || true
  )"
  if [[ "${stored}" != "0" ]]; then
    echo "the refusing relay retained ${stored} media objects" >&2
    exit 1
  fi
fi
echo "a relay without --trusted-lan refused the unencrypted epoch and stored no media"

echo "PASS: an unencrypted stream published, unlocked itself, and played in ${browsers} with no key and no EME; a relay not serving a trusted LAN refused it"
