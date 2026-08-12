#!/bin/sh
# Nothing is enabled here either. The publisher captures a logged-in graphical
# session, so it is a user unit: there is no system-wide "on", and only the
# person at the session can decide to start it.
set -e

if [ "$1" = "1" ] || { [ "$1" = "configure" ] && [ -z "$2" ]; }; then
    cat <<'NOTE'
gcpub is installed and not running.

As the user whose screen is to be published, not as root:

  1. mkdir -p ~/.config/glacialcast && cp \
       /usr/share/doc/gcpub/client.toml.example \
       ~/.config/glacialcast/client.toml
     chmod 600 ~/.config/glacialcast/client.toml
     Optionally set ingest_server_key to the relay key printed by gcrelay;
     without it, the publisher uses trust on first use and pins that key.
  2. systemctl --user enable --now gcpub

View with `gcview HOST:8899`, then approve the verified request with
`gcpub requests` and `gcpub approve REQUEST_PREFIX`.
NOTE
fi
