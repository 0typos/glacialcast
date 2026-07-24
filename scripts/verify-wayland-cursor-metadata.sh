#!/usr/bin/env bash
set -u

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18899}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18900}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-cursor-metadata-verify.$$}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-45}"
CLIENT_ID="${GLACIALCAST_VERIFY_CLIENT_ID:-cursor-metadata-verify}"
CLIENT_LOG="${GLACIALCAST_VERIFY_CLIENT_LOG:-/tmp/glacialcast-cursor-metadata-client.$$.log}"
SKIP_PREFLIGHT="${GLACIALCAST_VERIFY_SKIP_PREFLIGHT:-0}"
CAPTURE_MODE="${GLACIALCAST_VERIFY_CAPTURE:-wayland}"
SCREENCAST_BACKEND="${GLACIALCAST_VERIFY_SCREENCAST_BACKEND:-portal}"
MONITOR_NAME="${GLACIALCAST_VERIFY_MONITOR_NAME:-}"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
PORTAL_CURSOR_METADATA=4
NIRI_PORTAL_CONFIG="${CONFIG_HOME}/xdg-desktop-portal/niri-portals.conf"
UPSTREAM_REPORT="docs/wayland-cursor-metadata-upstream-report.md"
WAYLAND_INFO=""
HAS_WLR_SCREENCOPY=0
HAS_EXT_IMAGE_COPY_CAPTURE=0
HAS_CURSOR_SHAPE=0
HAS_RELATIVE_POINTER=0
HAS_VIRTUAL_POINTER=0
NIRI_SOCKET_FOR_MSG=""

SERVER_PID=""
CLIENT_PID=""
cleanup() {
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd cargo
need_cmd curl
need_cmd python3

print_cursor_metadata_failure_context() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    return
  fi

  if grep -q "does not include SPA_META_Cursor while --require-cursor-metadata is set" "${log_path}"; then
    echo "DIAG: cursor metadata mode was requested, but PipeWire buffers did not include SPA_META_Cursor" >&2
    if grep -q "summary=Busy(7)" "${log_path}"; then
      echo "DIAG: first PipeWire buffer metadata summary contained only SPA_META_Busy:" >&2
      grep "summary=Busy(7)" "${log_path}" | tail -n 1 >&2 || true
    fi
    if grep -q "opened Mutter ScreenCast PipeWire stream" "${log_path}"; then
      echo "DIAG: direct Mutter/niri ScreenCast opened successfully; this points at compositor-side cursor metadata emission" >&2
    elif grep -q "opened XDG ScreenCast portal PipeWire stream" "${log_path}"; then
      echo "DIAG: XDG ScreenCast portal opened successfully; this points at portal/compositor-side cursor metadata emission" >&2
    fi
    if [[ "${HAS_EXT_IMAGE_COPY_CAPTURE}" == "0" ]]; then
      echo "DIAG: ext_image_copy_capture_manager_v1 is not advertised, so there is no alternate Wayland cursor-capture session" >&2
    fi
    if [[ "${HAS_CURSOR_SHAPE}" == "1" ]]; then
      echo "DIAG: wp_cursor_shape_manager_v1 is advertised, but it only lets clients set their own cursor shape" >&2
    fi
    if [[ "${HAS_RELATIVE_POINTER}" == "1" ]]; then
      echo "DIAG: zwp_relative_pointer_manager_v1 is advertised, but it is surface-relative and only applies while the client has pointer focus" >&2
    fi
    if [[ "${HAS_VIRTUAL_POINTER}" == "1" ]]; then
      echo "DIAG: zwlr_virtual_pointer_manager_v1 is advertised, but it is input injection rather than cursor observation" >&2
    fi
    if command -v busctl >/dev/null 2>&1 &&
      busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.RemoteDesktop 2>/dev/null |
        grep -q "NotifyPointerMotion"; then
      echo "DIAG: XDG RemoteDesktop exposes pointer notification methods for input injection, not compositor cursor observation" >&2
    fi
    echo "DIAG: upstream/debug evidence template: ${UPSTREAM_REPORT}" >&2
  fi
}

read_portal_u32_property() {
  local bus_name="$1"
  local interface="$2"
  local property="$3"
  local output=""

  if ! command -v busctl >/dev/null 2>&1; then
    return 1
  fi

  output="$(busctl --user get-property "${bus_name}" /org/freedesktop/portal/desktop "${interface}" "${property}" 2>/dev/null || true)"
  if [[ "${output}" =~ ^u[[:space:]]+([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi

  return 1
}

find_live_niri_socket() {
  local run_dir="/run/user/$(id -u)"
  local pattern="niri*.sock"
  if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
    pattern="niri.${WAYLAND_DISPLAY}.*.sock"
  fi

  find "${run_dir}" -maxdepth 1 -type s -name "${pattern}" -printf '%T@ %p\n' 2>/dev/null |
    sort -rn |
    awk 'NR == 1 { sub(/^[^ ]+ /, ""); print }'
}

run_niri_msg() {
  if [[ -n "${NIRI_SOCKET_FOR_MSG}" ]]; then
    env NIRI_SOCKET="${NIRI_SOCKET_FOR_MSG}" niri msg "$@"
  else
    niri msg "$@"
  fi
}

if command -v wayland-info >/dev/null 2>&1; then
  WAYLAND_INFO="$(wayland-info 2>/dev/null || true)"
  if grep -q "ext_image_copy_capture_manager_v1" <<<"${WAYLAND_INFO}"; then
    HAS_EXT_IMAGE_COPY_CAPTURE=1
    echo "wayland registry: ext_image_copy_capture_manager_v1 is present"
  elif grep -q "zwlr_screencopy_manager_v1" <<<"${WAYLAND_INFO}"; then
    HAS_WLR_SCREENCOPY=1
    echo "wayland registry: zwlr_screencopy_manager_v1 present, ext_image_copy_capture_manager_v1 absent"
  else
    echo "wayland registry: no recognized screen/cursor capture global found"
  fi
  if grep -q "wp_cursor_shape_manager_v1" <<<"${WAYLAND_INFO}"; then
    HAS_CURSOR_SHAPE=1
  fi
  if grep -q "zwp_relative_pointer_manager_v1" <<<"${WAYLAND_INFO}"; then
    HAS_RELATIVE_POINTER=1
  fi
  if grep -q "zwlr_virtual_pointer_manager_v1" <<<"${WAYLAND_INFO}"; then
    HAS_VIRTUAL_POINTER=1
  fi
  POINTER_PROTOCOLS=()
  if [[ "${HAS_CURSOR_SHAPE}" == "1" ]]; then
    POINTER_PROTOCOLS+=(wp_cursor_shape_manager_v1)
  fi
  if [[ "${HAS_RELATIVE_POINTER}" == "1" ]]; then
    POINTER_PROTOCOLS+=(zwp_relative_pointer_manager_v1)
  fi
  if [[ "${HAS_VIRTUAL_POINTER}" == "1" ]]; then
    POINTER_PROTOCOLS+=(zwlr_virtual_pointer_manager_v1)
  fi
  if [[ "${#POINTER_PROTOCOLS[@]}" -gt 0 ]]; then
    echo "wayland registry: non-observer pointer protocols present: ${POINTER_PROTOCOLS[*]}"
  fi
else
  echo "wayland-info not found; skipping static Wayland registry check"
fi

NIRI_COMPOSITOR_VERSION=""
NIRI_CLI_VERSION=""
if command -v niri >/dev/null 2>&1; then
  if [[ -n "${NIRI_SOCKET:-}" && ! -S "${NIRI_SOCKET}" ]]; then
    echo "DIAG: NIRI_SOCKET is set but not reachable: ${NIRI_SOCKET}" >&2
    echo "DIAG: niri IPC cursor-source checks may be incomplete from this shell" >&2
  fi
  if [[ -n "${NIRI_SOCKET:-}" && -S "${NIRI_SOCKET}" ]]; then
    NIRI_SOCKET_FOR_MSG="${NIRI_SOCKET}"
  else
    NIRI_SOCKET_FOR_MSG="$(find_live_niri_socket || true)"
    if [[ -n "${NIRI_SOCKET_FOR_MSG}" ]]; then
      echo "DIAG: using discovered niri socket for IPC checks: ${NIRI_SOCKET_FOR_MSG}" >&2
    fi
  fi
  NIRI_VERSION_JSON="$(run_niri_msg -j version 2>/dev/null || true)"
  if [[ -n "${NIRI_VERSION_JSON}" ]]; then
    echo "${NIRI_VERSION_JSON}"
    NIRI_PARSED_VERSION="$(
      python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get("cli", ""))
    print(data.get("compositor", ""))
except Exception:
    pass
' <<<"${NIRI_VERSION_JSON}"
    )"
    NIRI_CLI_VERSION="$(sed -n '1p' <<<"${NIRI_PARSED_VERSION}")"
    NIRI_COMPOSITOR_VERSION="$(sed -n '2p' <<<"${NIRI_PARSED_VERSION}")"
    if [[ -n "${NIRI_CLI_VERSION}" &&
      -n "${NIRI_COMPOSITOR_VERSION}" &&
      "${NIRI_CLI_VERSION}" != "${NIRI_COMPOSITOR_VERSION}" ]]; then
      echo "niri version mismatch: cli=${NIRI_CLI_VERSION}, compositor=${NIRI_COMPOSITOR_VERSION}"
      if command -v systemctl >/dev/null 2>&1 &&
        systemctl --user is-active --quiet niri.service 2>/dev/null; then
        echo "niri.service is active; systemctl --user restart niri.service should restart the compositor, but it will interrupt the graphical session"
      fi
    fi
  fi
  NIRI_MSG_HELP="$(run_niri_msg --help 2>/dev/null || true)"
  if [[ -n "${NIRI_MSG_HELP}" ]]; then
    if grep -Eq '(^|[[:space:]])(cursor|pointer)([[:space:]-]|$)' <<<"${NIRI_MSG_HELP}"; then
      echo "DIAG: niri msg help mentions cursor/pointer commands; inspect whether they expose observer cursor state" >&2
    else
      echo "niri IPC: no cursor-position or pointer-position command is advertised"
    fi
  fi
  if [[ "${SCREENCAST_BACKEND}" == "mutter" && -z "${MONITOR_NAME}" ]]; then
    MONITOR_NAME="$(
      run_niri_msg -j focused-output 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get("name", ""))
except Exception:
    pass
' 2>/dev/null || true
    )"
  fi
fi

HAS_NIRI_OR_WLR_PORTAL=0
if compgen -G "/usr/share/xdg-desktop-portal/portals/*niri*.portal" >/dev/null ||
  compgen -G "/usr/share/xdg-desktop-portal/portals/*wlr*.portal" >/dev/null ||
  compgen -G "${DATA_HOME}/xdg-desktop-portal/portals/*niri*.portal" >/dev/null ||
  compgen -G "${DATA_HOME}/xdg-desktop-portal/portals/*wlr*.portal" >/dev/null ||
  [[ -e /usr/lib/systemd/user/xdg-desktop-portal-niri.service ]] ||
  [[ -e /usr/lib/systemd/user/xdg-desktop-portal-wlr.service ]] ||
  [[ -e "${CONFIG_HOME}/systemd/user/xdg-desktop-portal-niri.service" ]] ||
  [[ -e "${CONFIG_HOME}/systemd/user/xdg-desktop-portal-wlr.service" ]] ||
  [[ -e "${CONFIG_HOME}/systemd/user/xdg-desktop-portal-wlr-local.service" ]]; then
  HAS_NIRI_OR_WLR_PORTAL=1
fi

if [[ "${SKIP_PREFLIGHT}" != "1" &&
  "${HAS_EXT_IMAGE_COPY_CAPTURE}" == "0" &&
  "${HAS_NIRI_OR_WLR_PORTAL}" == "0" &&
  "${NIRI_COMPOSITOR_VERSION}" == 25.* ]]; then
  echo "FAIL: current niri session lacks ext_image_copy_capture and no niri/wlr portal backend is installed" >&2
  echo "      compositor=${NIRI_COMPOSITOR_VERSION}" >&2
  echo "      restart into a compositor/portal stack that emits SPA_META_Cursor, or set GLACIALCAST_VERIFY_SKIP_PREFLIGHT=1 to force the runtime portal check" >&2
  exit 1
fi

if [[ "${SKIP_PREFLIGHT}" != "1" &&
  -n "${NIRI_CLI_VERSION}" &&
  -n "${NIRI_COMPOSITOR_VERSION}" &&
  "${NIRI_CLI_VERSION}" != "${NIRI_COMPOSITOR_VERSION}" &&
  "${NIRI_CLI_VERSION}" == 26.* &&
  "${NIRI_COMPOSITOR_VERSION}" == 25.* ]]; then
  echo "FAIL: installed niri is ${NIRI_CLI_VERSION}, but the running compositor is still ${NIRI_COMPOSITOR_VERSION}" >&2
  if command -v systemctl >/dev/null 2>&1 &&
    systemctl --user is-active --quiet niri.service 2>/dev/null; then
    echo "      systemctl --user restart niri.service should restart the compositor, but it will interrupt the graphical session" >&2
  else
    echo "      log out or restart niri so the compositor uses the installed binary" >&2
  fi
  echo "      set GLACIALCAST_VERIFY_SKIP_PREFLIGHT=1 to force the runtime PipeWire check anyway" >&2
  exit 1
fi

PORTAL_CURSOR_MODES="$(read_portal_u32_property \
  org.freedesktop.portal.Desktop \
  org.freedesktop.portal.ScreenCast \
  AvailableCursorModes || true)"
WLR_CURSOR_MODES="$(read_portal_u32_property \
  org.freedesktop.impl.portal.desktop.wlr \
  org.freedesktop.impl.portal.ScreenCast \
  AvailableCursorModes || true)"
if [[ -n "${WLR_CURSOR_MODES}" ]]; then
  echo "wlr backend AvailableCursorModes=${WLR_CURSOR_MODES}"
fi

SCREENCAST_PORTAL_PREF=""
if [[ -f "${NIRI_PORTAL_CONFIG}" ]]; then
  SCREENCAST_PORTAL_PREF="$(
    sed -n 's/^[[:space:]]*org\.freedesktop\.impl\.portal\.ScreenCast[[:space:]]*=[[:space:]]*//p' "${NIRI_PORTAL_CONFIG}" | tail -n 1
  )"
  if [[ -n "${SCREENCAST_PORTAL_PREF}" ]]; then
    echo "user portal ScreenCast preference=${SCREENCAST_PORTAL_PREF}"
  fi
fi

if [[ -n "${PORTAL_CURSOR_MODES}" ]]; then
  echo "portal AvailableCursorModes=${PORTAL_CURSOR_MODES}"
  if [[ "${SKIP_PREFLIGHT}" != "1" &&
    "${SCREENCAST_BACKEND}" != "mutter" &&
    $((PORTAL_CURSOR_MODES & PORTAL_CURSOR_METADATA)) -eq 0 ]]; then
    echo "FAIL: active ScreenCast portal does not advertise cursor metadata mode" >&2
    echo "      AvailableCursorModes=${PORTAL_CURSOR_MODES}, required bit=${PORTAL_CURSOR_METADATA}" >&2
    if [[ -n "${NIRI_CLI_VERSION}" &&
      -n "${NIRI_COMPOSITOR_VERSION}" &&
      "${NIRI_CLI_VERSION}" != "${NIRI_COMPOSITOR_VERSION}" ]]; then
      echo "      niri CLI is ${NIRI_CLI_VERSION}, but the running compositor is ${NIRI_COMPOSITOR_VERSION}; log out or restart niri so the compositor uses the installed binary" >&2
      if command -v systemctl >/dev/null 2>&1 &&
        systemctl --user is-active --quiet niri.service 2>/dev/null; then
        echo "      this session is managed by niri.service; systemctl --user restart niri.service should restart the compositor, but it will interrupt the graphical session" >&2
      fi
    fi
    if [[ "${SCREENCAST_PORTAL_PREF}" == wlr* ]]; then
      echo "      ${NIRI_PORTAL_CONFIG} prefers wlr for ScreenCast; niri's PipeWire screencasting path uses the GNOME portal, so run scripts/setup-niri-gnome-portal.sh after testing the wlr fallback" >&2
    fi
    echo "      hidden=1, embedded=2, metadata=4; restart into a portal/compositor stack that provides metadata, or set GLACIALCAST_VERIFY_SKIP_PREFLIGHT=1 to force the runtime PipeWire check" >&2
    exit 1
  fi
else
  echo "portal AvailableCursorModes unavailable; falling through to runtime PipeWire check"
fi

mkdir -p "${DATA_DIR}"

echo "building Glacialcast cursor verifier binaries"
cargo build -p glacialcast-server
if [[ "${CAPTURE_MODE}" == "wayland-video" ]]; then
  scripts/verify-prerequisites.sh
  cargo build -p glacialcast-client --features ffmpeg-vaapi
else
  cargo build -p glacialcast-client
fi

echo "starting temporary Glacialcast server on ${CONTROL_ADDR} / ${INGEST_ADDR}"
./target/debug/glacialcast-server \
  --control-addr "${CONTROL_ADDR}" \
  --ingest-addr "${INGEST_ADDR}" \
  --data-dir "${DATA_DIR}" \
  --retention-bytes-per-stream 32MiB &
SERVER_PID="$!"

for _ in {1..80}; do
  if curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "server exited before becoming ready" >&2
    wait "${SERVER_PID}" 2>/dev/null || true
    exit 1
  fi
  sleep 0.1
done

if ! curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
  echo "server did not become ready on ${CONTROL_ADDR}" >&2
  exit 1
fi

echo "starting Wayland capture with --require-cursor-metadata"
if [[ "${SCREENCAST_BACKEND}" == "mutter" ]]; then
  if [[ -z "${MONITOR_NAME}" ]]; then
    echo "FAIL: GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter requires GLACIALCAST_VERIFY_MONITOR_NAME, or a focused niri output must be queryable" >&2
    exit 1
  fi
  echo "using direct Mutter/niri ScreenCast backend on monitor ${MONITOR_NAME}"
  echo "keep the pointer on ${MONITOR_NAME} and move it until this script reports PASS"
else
  echo "accept the desktop portal chooser if it appears"
  echo "select the monitor containing the pointer, keep the pointer on that monitor, and move it until this script reports PASS"
fi

CLIENT_ARGS=(
  --config /tmp/glacialcast-missing-client.toml
  --ingest-addr "${INGEST_ADDR}"
  --client-id "${CLIENT_ID}"
  --display-name "Cursor Metadata Verify"
  --capture "${CAPTURE_MODE}"
  --portal-source monitor
  --screencast-backend "${SCREENCAST_BACKEND}"
  --portal-cursor metadata
  --require-cursor-metadata
  --fps 1
  --cursor-hz 15
  --no-viewer-key
)
if [[ "${SCREENCAST_BACKEND}" == "mutter" ]]; then
  CLIENT_ARGS+=(--monitor-name "${MONITOR_NAME}")
fi

./target/debug/glacialcast-client "${CLIENT_ARGS[@]}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

deadline=$((SECONDS + CLIENT_TIMEOUT))
while (( SECONDS < deadline )); do
  STREAM_ID="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams" 2>/dev/null | python3 -c '
import json, sys
streams = json.load(sys.stdin)
for stream in streams:
    if stream.get("display_name") == "Cursor Metadata Verify":
        print(stream.get("stream_id", ""))
        break
' 2>/dev/null
  )"
  if [[ -n "${STREAM_ID}" ]]; then
    CURSOR_COUNT="$(
      curl -fsS "http://${CONTROL_ADDR}/api/streams/${STREAM_ID}/cursors" 2>/dev/null | python3 -c '
import json, sys
print(len(json.load(sys.stdin)))
' 2>/dev/null
    )"
    if [[ "${CURSOR_COUNT:-0}" =~ ^[0-9]+$ ]] && (( CURSOR_COUNT > 0 )); then
      echo "PASS: server received ${CURSOR_COUNT} cursor messages from PipeWire metadata"
      exit 0
    fi
  fi

  if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
    wait "${CLIENT_PID}"
    STATUS="$?"
    echo "FAIL: client exited before cursor metadata was verified; client log: ${CLIENT_LOG}" >&2
    print_cursor_metadata_failure_context "${CLIENT_LOG}"
    tail -n 80 "${CLIENT_LOG}" >&2 || true
    exit "${STATUS}"
  fi
  sleep 0.25
done

echo "FAIL: timed out before cursor metadata was verified; client log: ${CLIENT_LOG}" >&2
print_cursor_metadata_failure_context "${CLIENT_LOG}"
tail -n 80 "${CLIENT_LOG}" >&2 || true
exit 1
