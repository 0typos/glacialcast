#!/bin/sh
# Configuration under /etc and retained objects under /var/lib are left in
# place. Removing a package is not a request to destroy the stream history or
# the ingest tokens it was serving.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
