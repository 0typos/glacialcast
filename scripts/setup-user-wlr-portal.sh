#!/usr/bin/env bash
set -euo pipefail

RPM_URL="${GLACIALCAST_XDPW_RPM_URL:-}"
STATE_HOME="${XDG_STATE_HOME:-${HOME}/.local/state}"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
INSTALL_ROOT="${DATA_HOME}/glacialcast/xdg-desktop-portal-wlr"
RPM_PATH="${STATE_HOME}/glacialcast/xdg-desktop-portal-wlr.rpm"
PORTAL_DIR="${DATA_HOME}/xdg-desktop-portal/portals"
DBUS_DIR="${DATA_HOME}/dbus-1/services"
SYSTEMD_DIR="${CONFIG_HOME}/systemd/user"
XDP_CONFIG_DIR="${CONFIG_HOME}/xdg-desktop-portal"
PORTAL_CONFIG="${XDP_CONFIG_DIR}/niri-portals.conf"
SERVICE_NAME="xdg-desktop-portal-wlr-local.service"
BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd curl
need_cmd cpio
need_cmd rpm2cpio
need_cmd systemctl

if [[ -z "${RPM_URL}" ]]; then
  need_cmd dnf
  RPM_URL="$(dnf repoquery --location --latest-limit 1 xdg-desktop-portal-wlr | tail -n 1)"
fi

if [[ -z "${RPM_URL}" ]]; then
  echo "could not resolve xdg-desktop-portal-wlr RPM URL" >&2
  exit 1
fi

mkdir -p "$(dirname -- "${RPM_PATH}")" "${INSTALL_ROOT}" "${PORTAL_DIR}" "${DBUS_DIR}" "${SYSTEMD_DIR}" "${XDP_CONFIG_DIR}"

echo "downloading ${RPM_URL}"
curl -L -o "${RPM_PATH}" "${RPM_URL}"

echo "extracting xdg-desktop-portal-wlr to ${INSTALL_ROOT}"
rm -rf "${INSTALL_ROOT}.new"
mkdir -p "${INSTALL_ROOT}.new"
(cd "${INSTALL_ROOT}.new" && rpm2cpio "${RPM_PATH}" | cpio -id --quiet)
rm -rf "${INSTALL_ROOT}"
mv "${INSTALL_ROOT}.new" "${INSTALL_ROOT}"

BACKEND="${INSTALL_ROOT}/usr/libexec/xdg-desktop-portal-wlr"
if [[ ! -x "${BACKEND}" ]]; then
  echo "extracted backend is missing or not executable: ${BACKEND}" >&2
  exit 1
fi

cat >"${PORTAL_DIR}/wlr.portal" <<'EOF'
[portal]
DBusName=org.freedesktop.impl.portal.desktop.wlr
Interfaces=org.freedesktop.impl.portal.Screenshot;org.freedesktop.impl.portal.ScreenCast;
UseIn=niri;wlroots;sway;Wayfire;river;phosh;Hyprland;
EOF

cat >"${DBUS_DIR}/org.freedesktop.impl.portal.desktop.wlr.service" <<EOF
[D-BUS Service]
Name=org.freedesktop.impl.portal.desktop.wlr
Exec=${BACKEND}
SystemdService=${SERVICE_NAME}
EOF

cat >"${SYSTEMD_DIR}/${SERVICE_NAME}" <<EOF
[Unit]
Description=User-local xdg-desktop-portal-wlr for Glacialcast verification

[Service]
Type=dbus
BusName=org.freedesktop.impl.portal.desktop.wlr
ExecStart=${BACKEND}
Restart=on-failure
EOF

if [[ -f "${PORTAL_CONFIG}" ]]; then
  cp -a "${PORTAL_CONFIG}" "${PORTAL_CONFIG}.${BACKUP_SUFFIX}.bak"
  echo "backed up existing ${PORTAL_CONFIG}"
fi

cat >"${PORTAL_CONFIG}" <<'EOF'
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.ScreenCast=wlr;gnome;
org.freedesktop.impl.portal.RemoteDesktop=wlr;gnome;
org.freedesktop.impl.portal.Access=gtk;
org.freedesktop.impl.portal.Notification=gtk;
org.freedesktop.impl.portal.Secret=gnome-keyring;
EOF

systemctl --user set-environment \
  "HOME=${HOME}" \
  "XDG_CONFIG_HOME=${CONFIG_HOME}" \
  "XDG_DATA_HOME=${DATA_HOME}"
dbus-update-activation-environment --systemd \
  HOME \
  XDG_CONFIG_HOME \
  XDG_DATA_HOME \
  XDG_CURRENT_DESKTOP \
  WAYLAND_DISPLAY

systemctl --user daemon-reload
systemctl --user restart xdg-desktop-portal.service
systemctl --user restart "${SERVICE_NAME}" || true
systemctl --user restart xdg-desktop-portal-gnome.service || true

echo "user-local wlr portal setup complete"
echo "run: scripts/verify-wayland-cursor-metadata.sh"
