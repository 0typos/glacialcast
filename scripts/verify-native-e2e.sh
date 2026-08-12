#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

work_dir="$(mktemp -d /tmp/glacialcast-native-e2e.XXXXXX)"
relay_pid=""
publisher_pid=""
# Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317,SC2329
cleanup() {
  [[ -z "${publisher_pid}" ]] || kill "${publisher_pid}" 2>/dev/null || true
  [[ -z "${relay_pid}" ]] || kill "${relay_pid}" 2>/dev/null || true
  find "${work_dir}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

read -r publisher_port viewer_port < <(python3 - <<'PY'
import socket
sockets = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(*(sock.getsockname()[1] for sock in sockets))
for sock in sockets:
    sock.close()
PY
)

cargo build -p gcrelay -p gcpub -p gcview
cargo test -p gcrelay native_service::tests::pairing_request_offer_confirmation_and_decision_queue_while_offline

mkdir -p "${work_dir}/publisher-state/glacialcast"
printf '%s\n' '[viewers]' 'policy = "open"' \
  >"${work_dir}/publisher-state/glacialcast/config.toml"
chmod 600 "${work_dir}/publisher-state/glacialcast/config.toml"

target/debug/gcrelay \
  --no-config \
  --publisher-addr "127.0.0.1:${publisher_port}" \
  --viewer-addr "127.0.0.1:${viewer_port}" \
  --data-dir "${work_dir}/relay" \
  >"${work_dir}/relay.log" 2>&1 &
relay_pid=$!

for _ in $(seq 1 100); do
  if target/debug/gcview "127.0.0.1:${viewer_port}" \
    --state-dir "${work_dir}/probe" --headless >"${work_dir}/catalog" 2>/dev/null; then
    break
  fi
  sleep 0.05
done

XDG_STATE_HOME="${work_dir}/publisher-state" target/debug/gcpub \
  --foreground \
  --no-config \
  --ingest-addr "127.0.0.1:${publisher_port}" \
  --capture test \
  --encoder openh264 \
  --width 64 \
  --height 64 \
  --fps 2 \
  --client-id native-e2e \
  --display-name "Native E2E" \
  >"${work_dir}/publisher.log" 2>&1 &
publisher_pid=$!

for _ in $(seq 1 200); do
  if target/debug/gcview "127.0.0.1:${viewer_port}" \
      --state-dir "${work_dir}/viewer" --headless >"${work_dir}/catalog" 2>/dev/null \
      && grep -q $'live\tNative E2E' "${work_dir}/catalog"; then
    kill -0 "${publisher_pid}"
    stream_id="$(awk -F '\t' '$2 == "live" && $3 == "Native E2E" { print $1; exit }' "${work_dir}/catalog")"
    if target/debug/gcview "127.0.0.1:${viewer_port}" \
      --state-dir "${work_dir}/viewer" --verify-stream "${stream_id}" \
      >"${work_dir}/verified" 2>"${work_dir}/viewer.log"; then
      grep -q $'verified\t' "${work_dir}/verified"
      grep -q 'rotated-group=' "${work_dir}/verified"
      echo "PASS: real publisher, relay, and viewer paired per stream, decrypted, decoded, and survived key rotation"
      exit 0
    fi
    break
  fi
  sleep 0.05
done

cat "${work_dir}/relay.log" >&2
cat "${work_dir}/publisher.log" >&2
[[ ! -f "${work_dir}/viewer.log" ]] || cat "${work_dir}/viewer.log" >&2
echo "native process smoke test timed out" >&2
exit 1
