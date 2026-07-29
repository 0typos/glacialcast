#!/usr/bin/env bash
# Screenshots the compositor's own view of an output, however this desktop
# allows it.
#
# The picture gate compares what a browser decoded against what the compositor
# actually shows, which is the only check that distinguishes a correct capture
# from a plausible-looking scrambled one. That comparison needs a reference
# image, and no single tool produces one everywhere:
#
#   grim       wlroots' screencopy protocol. niri and sway implement it;
#              GNOME and KDE do not, and grim there says so plainly.
#   spectacle  KDE's own tool, non-interactive with -b -n.
#   portal     org.freedesktop.portal.Screenshot, which every desktop with a
#              portal implements. GNOME allows nothing else: its Shell
#              screenshot interface refuses callers that are not the Shell.
#
# Tried in that order, because the first two name an output directly and the
# portal does not. Exits 2 when none is available, which the caller should treat
# as "cannot verify here" rather than as a failure of the capture.
#
# usage: screenshot-output.sh OUTPUT_PATH [CONNECTOR]
set -euo pipefail

output_path="${1:?usage: screenshot-output.sh OUTPUT_PATH [CONNECTOR]}"
connector="${2:-}"

if command -v grim >/dev/null; then
  if [[ -n "${connector}" ]]; then
    if grim -o "${connector}" "${output_path}" 2>/dev/null; then
      echo "grim"
      exit 0
    fi
  elif grim "${output_path}" 2>/dev/null; then
    echo "grim"
    exit 0
  fi
fi

if command -v spectacle >/dev/null; then
  # -b runs without the GUI, -n suppresses the notification, -f takes the whole
  # desktop. Spectacle cannot select an output by connector name, so a
  # multi-output KDE session captures everything and the comparison has to
  # tolerate that; the caller decides whether that is good enough.
  if spectacle -b -n -f -o "${output_path}" >/dev/null 2>&1 && [[ -s "${output_path}" ]]; then
    echo "spectacle"
    exit 0
  fi
fi

if command -v gdbus >/dev/null && [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" || -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]]; then
  if scripts/screenshot-portal.py "${output_path}" >/dev/null 2>&1; then
    echo "portal"
    exit 0
  fi
fi

echo "no screenshot mechanism available on this desktop" >&2
exit 2
