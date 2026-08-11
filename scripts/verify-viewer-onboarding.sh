#!/usr/bin/env bash
# Proves a viewer types a key at most once, and that a stream carrying an epoch
# the key cannot open still plays.
#
# Both properties come from the same report: a viewer on GNOME got a black tile
# naming an object that did not exist, and had to re-enter the key constantly.
#
# The black tile was a stream with more than one epoch where one of them could not
# be opened. That is reproduced here by rotating the publisher's viewer key
# mid-run: the first epoch stays in the relay's retention window encrypted to the
# old key, so a viewer holding the new key sees exactly the mix that broke --
# retained media belonging to an epoch that is absent from the viewer's epoch map.
# The guard for that was written as `epoch?.offset !== null`, which admits the
# missing epoch because `undefined !== null` is true, and the next line
# dereferenced it.
#
# The capture is synthetic, so this needs no Wayland session and runs in CI.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:19010}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:19011}"
origin="http://${control_addr}"
browsers="${GLACIALCAST_VERIFY_BROWSERS:-firefox}"

if [[ -z "${GLACIALCAST_PLAYWRIGHT_MODULE:-}" ]] && ! node -e "require('playwright')" 2>/dev/null; then
  echo "Playwright is unavailable; set GLACIALCAST_PLAYWRIGHT_MODULE" >&2
  exit 2
fi

work_dir="$(mktemp -d /tmp/glacialcast-onboarding.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
server_pid=""
client_pid=""

cleanup() {
  if [[ -n "${client_pid}" ]] && kill -0 "${client_pid}" 2>/dev/null; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
  fi
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  rm -rf "${work_dir}"
}
trap cleanup EXIT

cargo build -p gcrelay -p gcpub

ingest_server_key="$(
  target/debug/gcrelay \
    --no-config --data-dir "${work_dir}/data" --print-ingest-server-key
)"

# The retired key and the one a viewer is actually given. Both are raw viewer
# keys, which the viewer accepts wherever it accepts a phrase.
retired_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
current_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/gcrelay \
  --no-config \
  --data-dir "${work_dir}/data" \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --allow-insecure-http \
  --retention-seconds 900 \
  --retention-bytes-per-stream 256MiB \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  if curl -sf "${origin}/api/streams" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -sf "${origin}/api/streams" >/dev/null || {
  echo "the relay did not come up" >&2
  sed -n '1,80p' "${server_log}" >&2
  exit 1
}

start_client() {
  local key="$1"
  target/debug/gcpub \
    --no-config \
    --ingest-addr "${ingest_addr}" \
    "--ingest-server-key=${ingest_server_key}" \
    "--viewer-key=${key}" \
    --foreground \
    --client-id onboarding \
    --display-name "Onboarding" \
    --capture dash-test \
    --test-pattern motion \
    --dash-encoder openh264 \
    --width 320 --height 180 --fps 2 \
    --segment-frames 2 \
    >>"${client_log}" 2>&1 &
  client_pid="$!"
}

stream_id_of() {
  curl -sf "${origin}/api/streams" \
    | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const s=JSON.parse(d);process.stdout.write(s.length?s[0].stream_id:"")})'
}

# Counts distinct epochs that have media behind them, which is what the viewer
# actually has to reconcile.
epochs_with_media() {
  local stream_id="$1"
  curl -sf "${origin}/api/dash/streams/${stream_id}/objects" \
    | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{
        const h=JSON.parse(d);
        const withMedia=new Set(h.filter(x=>x.kind==="Media").map(x=>x.epoch_id));
        process.stdout.write(String(withMedia.size));
      })'
}

wait_for_epochs_with_media() {
  local stream_id="$1" want="$2"
  for _ in $(seq 1 300); do
    if [[ "$(epochs_with_media "${stream_id}")" -ge "${want}" ]]; then return 0; fi
    sleep 0.2
  done
  echo "the stream did not reach ${want} epoch(s) carrying media" >&2
  sed -n '1,120p' "${client_log}" >&2
  return 1
}

echo "publishing an epoch under a key that will be retired"
start_client "${retired_key}"
stream_id=""
for _ in $(seq 1 300); do
  stream_id="$(stream_id_of)"
  [[ -n "${stream_id}" ]] && break
  sleep 0.2
done
[[ -n "${stream_id}" ]] || { echo "no stream was published" >&2; exit 1; }
wait_for_epochs_with_media "${stream_id}" 1

echo "rotating the viewer key, leaving the first epoch unopenable"
kill "${client_pid}"
wait "${client_pid}" 2>/dev/null || true
client_pid=""
start_client "${current_key}"
wait_for_epochs_with_media "${stream_id}" 2

retained_epochs="$(epochs_with_media "${stream_id}")"
echo "the relay holds ${retained_epochs} epochs with media; the viewer key opens one of them"

for browser in ${browsers//,/ }; do
  echo "--- ${browser} ---"
  GLACIALCAST_VIEWER_ORIGIN="${origin}" \
  GLACIALCAST_VIEWER_PHRASE="${current_key}" \
  GLACIALCAST_VERIFY_BROWSER="${browser}" \
    node scripts/verify-viewer-onboarding.mjs
done

echo "PASS viewer onboarding: one key interaction, and a retired epoch does not blank the player"
