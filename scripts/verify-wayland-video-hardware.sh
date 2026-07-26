#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18995}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18996}"
backend="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-portal}"
monitor_name="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
vaapi_device="${GLACIALCAST_VERIFY_VAAPI_DEVICE:-/dev/dri/renderD128}"
require_dmabuf="${GLACIALCAST_VERIFY_REQUIRE_DMABUF:-0}"
timeout_seconds="${GLACIALCAST_VERIFY_TIMEOUT_SECONDS:-60}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-wayland-vaapi.XXXXXX)"
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

if [[ ! -e "${vaapi_device}" ]]; then
  echo "VA-API render node does not exist: ${vaapi_device}" >&2
  exit 1
fi
if [[ "${backend}" == "portal" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  echo "WAYLAND_DISPLAY is not set; run this gate inside the target Wayland session" >&2
  exit 1
fi

cargo build -p glacialcast-server -p glacialcast-client
ingest_server_key="$(
  target/debug/glacialcast-server \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/glacialcast-server \
  --config "${work_dir}/missing-server.toml" \
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
  --config "${work_dir}/missing-client.toml"
  --ingest-addr "${ingest_addr}"
  "--ingest-server-key=${ingest_server_key}"
  "--viewer-key=${viewer_key}"
  --client-id wayland-vaapi-verify
  --display-name "Wayland VAAPI Verify"
  --capture dash-wayland
  --dash-encoder vaapi
  --vaapi-device "${vaapi_device}"
  --portal-source monitor
  --screencast-backend "${backend}"
  --portal-cursor embedded
  --fps 1
)
if [[ -n "${monitor_name}" ]]; then
  client_args+=(--monitor-name "${monitor_name}")
fi

target/debug/glacialcast-client "${client_args[@]}" >"${client_log}" 2>&1 &
client_pid="$!"

echo "Select the target source in the portal."
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
    const stream = streams.find(candidate => candidate.display_name === 'Wayland VAAPI Verify');
    if (stream) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => response.json());
      if (objects.some(object => object.kind === 'Media')) process.exit(0);
    }
  } catch {
    // Keep polling while the portal and encoder initialize.
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
process.exit(1);
NODE
  echo "VA-API capture did not emit a DASH media object" >&2
  sed -n '1,280p' "${client_log}" >&2
  exit 1
}

if ! grep -Fq "using VA-API H.264 encoder" "${client_log}"; then
  echo "client emitted media without recording the required VA-API backend" >&2
  sed -n '1,280p' "${client_log}" >&2
  exit 1
fi
if [[ "${require_dmabuf}" == "1" ]] \
  && ! grep -Fq "PipeWire video delivered DMA-BUF frame for VAAPI import" "${client_log}"; then
  echo "strict DMA-BUF import was requested but not observed" >&2
  sed -n '1,280p' "${client_log}" >&2
  exit 1
fi

echo "PASS: Wayland capture produced encrypted DASH media with the required VA-API encoder"
