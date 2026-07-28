#!/bin/sh
# Creates the unprivileged account the relay unit runs as.
#
# Done before the files land so the unit is runnable the moment an operator
# chooses to start it. The account is deliberately not removed on uninstall:
# /var/lib/glacialcast may still hold retained objects, and orphaning them to a
# recycled uid is worse than leaving a system account behind.
set -e

if ! getent group glacialcast >/dev/null 2>&1; then
    groupadd --system glacialcast
fi
if ! getent passwd glacialcast >/dev/null 2>&1; then
    useradd \
        --system \
        --gid glacialcast \
        --home-dir /var/lib/glacialcast \
        --no-create-home \
        --shell /sbin/nologin \
        --comment "GlacialCast relay" \
        glacialcast
fi
