#!/bin/sh
# Configuration under /etc and retained objects under /var/lib are left in
# place. Removing a package is not a request to destroy stream history,
# identities, credentials, or other operator state.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
