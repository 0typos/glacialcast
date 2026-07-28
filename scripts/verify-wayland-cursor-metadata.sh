#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18997}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18998}"
backend="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-auto}"
monitor_name="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
timeout_seconds="${GLACIALCAST_VERIFY_TIMEOUT_SECONDS:-60}"
screenshot="${GLACIALCAST_VERIFY_SCREENSHOT:-}"
browser="${GLACIALCAST_VERIFY_BROWSER:-firefox}"
gpu_device="${GLACIALCAST_VERIFY_VAAPI_DEVICE:-/dev/dri/renderD128}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-wayland-cursor.XXXXXX)"
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
}
trap cleanup EXIT

if [[ "${backend}" != "mutter" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  echo "WAYLAND_DISPLAY is not set; run this gate inside the target Wayland session" >&2
  exit 1
fi

cargo build -p glacialcast-server -p glacialcast-client
ingest_server_key="$(
  target/debug/glacialcast-server \
    --no-config \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/glacialcast-server \
  --no-config \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  curl -fsS "${origin}/api/streams" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "${origin}/api/streams" >/dev/null

client_args=(
  --foreground
  --no-config
  --ingest-addr "${ingest_addr}"
  "--ingest-server-key=${ingest_server_key}"
  "--viewer-key=${viewer_key}"
  --client-id wayland-cursor-verify
  --display-name "Wayland Cursor Verify"
  --capture dash-wayland
  --dash-encoder openh264
  --vaapi-device "${gpu_device}"
  --portal-source monitor
  --screencast-backend "${backend}"
  --portal-cursor metadata
  --require-cursor-metadata
  --fps 1
  --cursor-hz 30
)
if [[ -n "${monitor_name}" ]]; then
  client_args+=(--monitor-name "${monitor_name}")
fi

target/debug/glacialcast-client "${client_args[@]}" >"${client_log}" 2>&1 &
client_pid="$!"

echo "If a desktop chooser appears, select the target source, then move the pointer over it."
node - "${origin}" "${timeout_seconds}" "${client_pid}" <<'NODE' || {
const [origin, timeoutSeconds, clientPid] = process.argv.slice(2);
const deadline = Date.now() + Number(timeoutSeconds) * 1000;
while (Date.now() < deadline) {
  try {
    process.kill(Number(clientPid), 0);
  } catch {
    process.exit(2);
  }
  try {
    const streams = await fetch(`${origin}/api/streams`).then(response => response.json());
    const stream = streams.find(candidate => candidate.display_name === 'Wayland Cursor Verify');
    if (stream) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => response.json());
      if (
        objects.some(object => object.kind === 'Media')
        && objects.some(object => object.kind === 'Cursor')
      ) {
        process.exit(0);
      }
    }
  } catch {
    // Keep polling while the portal and capture pipeline initialize.
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
process.exit(1);
NODE
  status="$?"
  if [[ "${status}" -eq 2 ]]; then
    echo "client exited before emitting media and cursor objects" >&2
  else
    echo "timed out waiting for real PipeWire cursor metadata" >&2
  fi
  sed -n '1,260p' "${client_log}" >&2
  exit 1
}

if [[ -n "${screenshot}" ]]; then
  stream_id="$(
    node - "${origin}" <<'NODE'
const origin = process.argv[2];
const streams = await fetch(`${origin}/api/streams`).then(response => response.json());
const stream = streams.find(candidate => candidate.display_name === 'Wayland Cursor Verify');
if (!stream) process.exit(1);
process.stdout.write(stream.stream_id);
NODE
  )"
  node scripts/capture-dash-frame.mjs \
    "${origin}" \
    "${stream_id}" \
    "${viewer_key}" \
    "${screenshot}" \
    "${browser}"
fi

echo "PASS: Wayland capture emitted encrypted media and independent PipeWire cursor objects"
