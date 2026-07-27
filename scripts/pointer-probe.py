#!/usr/bin/env python3
"""Moves the pointer continuously, for cursor-rate gates.

Emits relative motion, because that is what a mouse emits and the difference is
not cosmetic. An absolute-positioning device is coalesced somewhere between
libinput and the compositor: measured on niri 26.04, an absolute probe stepping
at 200 Hz produced 37 buffers and 30 cursor samples a second with pauses up to
267 ms, while a relative probe stepping at 60 Hz on the same machine produced
59.3 of each with a worst pause of 34 ms. Measuring with the absolute device
therefore reports a compositor limit that does not exist, and attributes this
project's own smoothness to something it cannot control.

Relative motion has its own hazard: it goes through pointer acceleration, so a
nominally closed circle drifts and the pointer can wander onto another output.
Steps are kept small to keep acceleration low and travel bounded, and a caller
should publish every output and measure whichever one saw the pointer rather
than assuming which that will be.

usage: pointer-probe.py SECONDS [STEPS_PER_SECOND]
"""

import fcntl
import math
import os
import struct
import sys
import time

UI_SET_EVBIT = 0x40045564
UI_SET_KEYBIT = 0x40045565
UI_SET_RELBIT = 0x40045566
UI_DEV_SETUP = 0x405C5503
UI_DEV_CREATE = 0x5501
UI_DEV_DESTROY = 0x5502

EV_SYN, EV_KEY, EV_REL = 0, 1, 2
REL_X, REL_Y = 0, 1
BTN_LEFT = 0x110
SYN_REPORT = 0

# Pixels per step. Small enough that pointer acceleration stays near unity, so
# the traced circle closes and the pointer stays on one output.
STEP_PIXELS = 6.0
# Default step rate. The compositor cannot deliver above panel refresh, so a
# caller measuring a high-refresh output should raise this to match it.
RATE_HZ = 60.0
# One revolution a second: continuous motion without covering so much distance
# that a frame-to-frame step stops resembling a real pointer.
REVOLUTIONS_PER_SECOND = 1.0
SETTLE_SECONDS = 1.5


def emit(fd, event_type, code, value):
    os.write(fd, struct.pack("llHHi", 0, 0, event_type, code, value))


def main():
    if not 2 <= len(sys.argv) <= 3:
        print(__doc__, file=sys.stderr)
        return 2
    duration = float(sys.argv[1])
    rate_hz = float(sys.argv[2]) if len(sys.argv) == 3 else RATE_HZ

    try:
        fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
        print(f"cannot open /dev/uinput: {error}", file=sys.stderr)
        return 3

    try:
        for code in (EV_KEY, EV_REL, EV_SYN):
            fcntl.ioctl(fd, UI_SET_EVBIT, code)
        # A relative device with a button is unambiguously a mouse to libinput.
        fcntl.ioctl(fd, UI_SET_KEYBIT, BTN_LEFT)
        for axis in (REL_X, REL_Y):
            fcntl.ioctl(fd, UI_SET_RELBIT, axis)
        fcntl.ioctl(
            fd, UI_DEV_SETUP,
            struct.pack("HHHH80sI", 0x03, 0x4321, 0x8765, 1,
                        b"glacialcast-pointer-probe", 0),
        )
        fcntl.ioctl(fd, UI_DEV_CREATE)
        # The compositor needs a moment to notice the new device; emitting
        # before it does simply loses those events.
        time.sleep(SETTLE_SECONDS)

        steps = int(duration * rate_hz)
        started = time.monotonic()
        for step in range(steps):
            angle = 2 * math.pi * REVOLUTIONS_PER_SECOND * step / rate_hz
            emit(fd, EV_REL, REL_X, int(round(STEP_PIXELS * math.cos(angle))))
            emit(fd, EV_REL, REL_Y, int(round(STEP_PIXELS * math.sin(angle))))
            emit(fd, EV_SYN, SYN_REPORT, 0)
            # Absolute deadline, so a slow write cannot stretch the run and
            # quietly lower the pointer rate the caller believes it produced.
            remaining = started + (step + 1) / rate_hz - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
    finally:
        try:
            fcntl.ioctl(fd, UI_DEV_DESTROY)
        finally:
            os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
