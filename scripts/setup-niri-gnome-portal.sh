#!/usr/bin/env bash
set -euo pipefail

CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
CONFIG_DIR="${CONFIG_HOME}/xdg-desktop-portal"
CONFIG_FILE="${CONFIG_DIR}/niri-portals.conf"
BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd systemctl

mkdir -p "${CONFIG_DIR}"
if [[ -f "${CONFIG_FILE}" ]]; then
  cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.${BACKUP_SUFFIX}.bak"
  echo "backed up existing ${CONFIG_FILE}"
fi

cat >"${CONFIG_FILE}" <<'EOF'
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.Access=gtk;
org.freedesktop.impl.portal.Notification=gtk;
org.freedesktop.impl.portal.Secret=gnome-keyring;
EOF

systemctl --user set-environment \
  "HOME=${HOME}" \
  "XDG_CONFIG_HOME=${CONFIG_HOME}" \
  "XDG_DATA_HOME=${DATA_HOME}"
if command -v dbus-update-activation-environment >/dev/null 2>&1; then
  dbus-update-activation-environment --systemd \
    HOME \
    XDG_CONFIG_HOME \
    XDG_DATA_HOME \
    XDG_CURRENT_DESKTOP \
    WAYLAND_DISPLAY
fi

systemctl --user daemon-reload
systemctl --user restart xdg-desktop-portal.service
systemctl --user restart xdg-desktop-portal-gnome.service || true
systemctl --user restart xdg-desktop-portal-wlr.service 2>/dev/null || true
systemctl --user restart xdg-desktop-portal-wlr-local.service 2>/dev/null || true

echo "niri portal config now prefers xdg-desktop-portal-gnome"
echo "log out or restart niri if the running compositor is stale"
echo "run: scripts/verify-wayland-cursor-metadata.sh"
