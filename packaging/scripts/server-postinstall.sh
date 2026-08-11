#!/bin/sh
# Makes the unit visible to systemd. It is deliberately not enabled or started.
#
# When to run a relay, on which addresses, and with which tokens are decisions
# this package has no basis for making, and a service that starts listening
# because a package was installed is a surprise. The install guide gives the
# two commands that turn it on.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Only on first install, not on every upgrade: an operator who has already read
# this does not need it again. RPM passes 1 here; dpkg passes "configure" with
# no second argument.
if [ "$1" = "1" ] || { [ "$1" = "configure" ] && [ -z "$2" ]; }; then
    cat <<'NOTE'
gcrelay is installed and not running.

  1. Put a configuration at /etc/glacialcast/relay.toml (mode 0600, owned by
     glacialcast). An example is in
     /usr/share/doc/gcrelay/relay.toml.example
  2. sudo systemctl enable --now gcrelay

Print the relay's public Noise identity for devices to pin:
  sudo -u glacialcast gcrelay \
    --data-dir /var/lib/glacialcast --print-server-key
NOTE
fi
