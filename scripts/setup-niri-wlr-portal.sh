#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/xdg-desktop-portal"
CONFIG_FILE="${CONFIG_DIR}/niri-portals.conf"
BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd sudo
need_cmd dnf
need_cmd systemctl

echo "installing xdg-desktop-portal-wlr"
sudo dnf install -y xdg-desktop-portal-wlr

mkdir -p "${CONFIG_DIR}"
if [[ -f "${CONFIG_FILE}" ]]; then
  cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.${BACKUP_SUFFIX}.bak"
  echo "backed up existing ${CONFIG_FILE}"
fi

cat >"${CONFIG_FILE}" <<'EOF'
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.ScreenCast=wlr;gnome;
org.freedesktop.impl.portal.RemoteDesktop=wlr;gnome;
org.freedesktop.impl.portal.Access=gtk;
org.freedesktop.impl.portal.Notification=gtk;
org.freedesktop.impl.portal.Secret=gnome-keyring;
EOF

echo "wrote ${CONFIG_FILE}"

systemctl --user daemon-reload
systemctl --user restart xdg-desktop-portal.service
systemctl --user restart xdg-desktop-portal-wlr.service || true
systemctl --user restart xdg-desktop-portal-gnome.service || true

echo "portal services restarted"
echo "run: scripts/verify-wayland-cursor-metadata.sh"
