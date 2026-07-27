#!/usr/bin/env python3
"""Moves the pointer continuously, for cursor-rate gates.

Uses an absolute-positioning uinput device rather than relative motion.
Relative motion goes through libinput's pointer acceleration, so a nominally
closed circle drifts; over a run of any length the pointer wanders onto another
output and the measurement silently records a stationary cursor, which reads as
a publishing failure rather than as a broken probe.

The device advertises BTN_LEFT rather than BTN_TOUCH: an absolute device with
BTN_TOUCH and no INPUT_PROP_DIRECT reads to libinput as a touchscreen, and a
touchscreen with no matching output is ignored, so the pointer never moves and
the measurement records a publishing failure that did not happen. BTN_LEFT plus
absolute axes is the shape of a virtual-machine tablet, which libinput handles
as an ordinary absolute pointer.

Which output the pointer ends up on is still the compositor's choice, so the
circle is described in normalized device coordinates and a caller that needs to
know which output it landed on should observe it rather than assume it.

usage: pointer-probe.py SECONDS [RADIUS_FRACTION]
"""

import fcntl
import math
import os
import struct
import sys
import time

UI_SET_EVBIT = 0x40045564
UI_SET_KEYBIT = 0x40045565
UI_SET_ABSBIT = 0x40045567
UI_DEV_SETUP = 0x405C5503
UI_ABS_SETUP = 0x401C5504
UI_DEV_CREATE = 0x5501
UI_DEV_DESTROY = 0x5502

EV_SYN, EV_KEY, EV_ABS = 0, 1, 3
ABS_X, ABS_Y = 0, 1
BTN_LEFT = 0x110
SYN_REPORT = 0

ABS_MAX = 32767
# Above any panel refresh this gate targets, so the compositor's delivery rate
# bounds the measurement rather than the probe's step rate.
RATE_HZ = 200.0
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
    radius_fraction = float(sys.argv[2]) if len(sys.argv) == 3 else 0.25

    try:
        fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
        print(f"cannot open /dev/uinput: {error}", file=sys.stderr)
        return 3

    try:
        for code in (EV_KEY, EV_ABS, EV_SYN):
            fcntl.ioctl(fd, UI_SET_EVBIT, code)
        fcntl.ioctl(fd, UI_SET_KEYBIT, BTN_LEFT)
        for axis in (ABS_X, ABS_Y):
            fcntl.ioctl(fd, UI_SET_ABSBIT, axis)
            # struct uinput_abs_setup { __u16 code; struct input_absinfo; }
            # input_absinfo is six __s32: value, minimum, maximum, fuzz, flat, res.
            fcntl.ioctl(
                fd, UI_ABS_SETUP,
                struct.pack("HHiiiiii", axis, 0, 0, 0, ABS_MAX, 0, 0, 0),
            )
        fcntl.ioctl(
            fd, UI_DEV_SETUP,
            struct.pack("HHHH80sI", 0x03, 0x4321, 0x8765, 1,
                        b"glacialcast-pointer-probe", 0),
        )
        fcntl.ioctl(fd, UI_DEV_CREATE)
        # The compositor needs a moment to notice the new device; emitting
        # before it does simply loses those events.
        time.sleep(SETTLE_SECONDS)

        centre = ABS_MAX / 2
        radius = ABS_MAX * radius_fraction
        steps = int(duration * RATE_HZ)
        started = time.monotonic()
        for step in range(steps + 1):
            angle = 2 * math.pi * REVOLUTIONS_PER_SECOND * step / RATE_HZ
            emit(fd, EV_ABS, ABS_X, int(centre + radius * math.cos(angle)))
            emit(fd, EV_ABS, ABS_Y, int(centre + radius * math.sin(angle)))
            emit(fd, EV_SYN, SYN_REPORT, 0)
            # Absolute deadline, so a slow write cannot stretch the run and
            # quietly lower the pointer rate the caller believes it produced.
            remaining = started + (step + 1) / RATE_HZ - time.monotonic()
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
