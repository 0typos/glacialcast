#!/bin/sh
# Stops and disables the unit, but only when the package is going away.
#
# An upgrade must leave a running relay alone: RPM passes 1 for the upgrade
# case and 0 for the last removal, dpkg passes "upgrade" or "remove".
set -e

if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl --no-reload disable --now glacialcast-server.service >/dev/null 2>&1 || true
    fi
fi
