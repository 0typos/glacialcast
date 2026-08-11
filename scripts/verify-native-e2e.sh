#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

work_dir="$(mktemp -d /tmp/glacialcast-native-e2e.XXXXXX)"
relay_pid=""
publisher_pid=""
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

target/debug/gcpub \
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
    echo "PASS: native relay and publisher processes expose a live authenticated catalog; the protocol E2E test decrypted retained media"
    exit 0
  fi
  sleep 0.05
done

cat "${work_dir}/relay.log" >&2
cat "${work_dir}/publisher.log" >&2
echo "native process smoke test timed out" >&2
exit 1
