#!/usr/bin/env bash
# Publishes the real screen and checks that a browser decodes the same picture
# the compositor is showing. This is the acceptance step that object-level
# gates cannot cover: a tiled or wrongly swizzled readback still produces valid
# encrypted DASH objects, and only a pixel comparison rejects it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18993}"
ingest_addr="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18994}"
backend="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-auto}"
monitor_name="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
encoder="${GLACIALCAST_VERIFY_DASH_ENCODER:-openh264}"
browser="${GLACIALCAST_VERIFY_BROWSER:-firefox}"
minimum="${GLACIALCAST_VERIFY_PICTURE_CORRELATION:-0.85}"
attempts="${GLACIALCAST_VERIFY_PICTURE_ATTEMPTS:-2}"
timeout_seconds="${GLACIALCAST_VERIFY_TIMEOUT_SECONDS:-90}"
origin="http://${control_addr}"
work_dir="$(mktemp -d /tmp/glacialcast-wayland-picture.XXXXXX)"
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

if [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
  echo "WAYLAND_DISPLAY is not set; run this gate inside the target Wayland session" >&2
  exit 1
fi
# Any one of grim, spectacle, or the portal will do; which one depends on the
# desktop. Checked up front so the gate skips before building rather than after
# publishing a stream it cannot verify.
if ! scripts/screenshot-output.sh "${work_dir}/probe.png" >/dev/null 2>&1; then
  echo "SKIP: no way to screenshot this desktop, so a published picture cannot be compared"
  echo "      (install grim on wlroots or niri, spectacle on KDE, or a working portal)"
  exit 0
fi
rm -f "${work_dir}/probe.png"

cargo build -p gcrelay -p gcpub
ingest_server_key="$(
  target/debug/gcrelay \
    --no-config \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"
viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"

target/debug/gcrelay \
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
  --client-id wayland-picture-verify
  --display-name "Wayland Picture Verify"
  --capture dash-wayland
  --dash-encoder "${encoder}"
  --portal-source monitor
  --screencast-backend "${backend}"
  --fps 1
  --idle-heartbeat-seconds 1
  --cursor-hz 30
)
if [[ -n "${monitor_name}" ]]; then
  client_args+=(--monitor-name "${monitor_name}")
fi
# Publishing smaller than the source is what puts the GPU scaling pass on the
# path. The comparison is scale-invariant, so the same correlation threshold
# holds and a shader that flips, swizzles, or garbles the frame fails here.
if [[ -n "${GLACIALCAST_VERIFY_MAX_FRAME_WIDTH:-}" ]]; then
  client_args+=(--max-frame-width "${GLACIALCAST_VERIFY_MAX_FRAME_WIDTH}")
fi
if [[ -n "${GLACIALCAST_VERIFY_MAX_FRAME_HEIGHT:-}" ]]; then
  client_args+=(--max-frame-height "${GLACIALCAST_VERIFY_MAX_FRAME_HEIGHT}")
fi

RUST_LOG=glacialcast_publisher=info target/debug/gcpub "${client_args[@]}" \
  >"${client_log}" 2>&1 &
client_pid="$!"

echo "If a desktop chooser appears, select the monitor to publish."
stream_id="$(
  node - "${origin}" "${timeout_seconds}" "${client_pid}" <<'NODE'
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
    const stream = streams.find(candidate => candidate.display_name === 'Wayland Picture Verify');
    if (stream) {
      const objects = await fetch(
        `${origin}/api/dash/streams/${stream.stream_id}/objects`,
      ).then(response => response.json());
      if (objects.some(object => object.kind === 'Media')) {
        process.stdout.write(stream.stream_id);
        process.exit(0);
      }
    }
  } catch {
    // Keep polling while capture and the encoder initialize.
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
process.exit(1);
NODE
)" || {
  echo "capture did not publish an encrypted DASH media object" >&2
  sed -n '1,260p' "${client_log}" >&2
  exit 1
}

connector="${monitor_name}"
if [[ -z "${connector}" ]]; then
  connector="$(sed -n 's/.*connector="\([^"]*\)".*/\1/p' "${client_log}" | head -1)"
fi
if [[ -z "${connector}" ]]; then
  echo "SKIP: the published output is unknown, so no reference screenshot can be taken." >&2
  echo "      Re-run with GLACIALCAST_VERIFY_MONITOR_NAME set to the chosen connector." >&2
  exit 0
fi

status=1
for attempt in $(seq 1 "${attempts}"); do
  candidate="${work_dir}/viewer-${attempt}.png"
  reference="${work_dir}/screen-${attempt}.png"
  node scripts/capture-dash-frame.mjs \
    "${origin}" "${stream_id}" "${viewer_key}" "${candidate}" "${browser}"
  # Take the reference as soon as the viewer frame lands so an active desktop
  # has the least opportunity to change between the two.
  reference_source="$(scripts/screenshot-output.sh "${reference}" "${connector}")"
  if node scripts/compare-frame.mjs "${reference}" "${candidate}" "${minimum}"; then
    status=0
    break
  fi
  echo "attempt ${attempt} did not match; the screen may have changed mid-capture" >&2
done

if [[ "${status}" -ne 0 ]]; then
  echo "published picture never matched the compositor's own screenshot of ${connector}" >&2
  sed -n '1,260p' "${client_log}" >&2
  exit 1
fi

echo "PASS: ${browser} decoded the published stream and it matches the compositor's" \
     "${connector}, referenced with ${reference_source:-unknown}"
