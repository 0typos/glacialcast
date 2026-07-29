#!/usr/bin/env python3
"""Takes a screenshot through the XDG Desktop Portal.

This is the only mechanism available on GNOME, whose Shell screenshot
interface refuses callers other than the Shell itself, and it works on any
desktop that ships a portal.

The portal does not return the image from the method call. It returns a request
object path and answers later with a Response signal carrying a URI, so the
subscription has to exist before the call is made or the answer is missed. The
handle token is chosen here rather than left to the portal, which makes the
request path predictable and lets the subscription be narrowed to it.

A desktop may ask the user for permission the first time. GNOME does, and
stores the answer, so a gate can be made unattended by granting it once:

    gdbus call --session --dest org.freedesktop.impl.portal.PermissionStore \\
      --object-path /org/freedesktop/impl/portal/PermissionStore \\
      --method org.freedesktop.impl.portal.PermissionStore.SetPermission \\
      screenshot true screenshot "" '["yes"]'

usage: screenshot-portal.py OUTPUT_PATH [TIMEOUT_SECONDS]
"""

import os
import shutil
import sys
import urllib.parse

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

PORTAL_DESTINATION = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    output_path = sys.argv[1]
    timeout_seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    unique = bus.get_unique_name()
    if unique is None:
        print("no session bus connection", file=sys.stderr)
        return 2

    # The portal builds the request path from the caller's bus name and the
    # handle token, so choosing the token means the path is known in advance.
    token = f"glacialcast{os.getpid()}"
    sender = unique.lstrip(":").replace(".", "_")
    request_path = f"/org/freedesktop/portal/desktop/request/{sender}/{token}"

    loop = GLib.MainLoop()
    result: dict[str, object] = {}

    def on_response(_conn, _sender, _path, _iface, _signal, parameters):
        code, results = parameters.unpack()
        result["code"] = code
        result["uri"] = results.get("uri")
        loop.quit()

    subscription = bus.signal_subscribe(
        PORTAL_DESTINATION,
        "org.freedesktop.portal.Request",
        "Response",
        request_path,
        None,
        Gio.DBusSignalFlags.NONE,
        on_response,
    )

    def on_timeout():
        result["timeout"] = True
        loop.quit()
        return False

    GLib.timeout_add_seconds(int(timeout_seconds), on_timeout)

    try:
        bus.call_sync(
            PORTAL_DESTINATION,
            PORTAL_PATH,
            "org.freedesktop.portal.Screenshot",
            "Screenshot",
            GLib.Variant(
                "(sa{sv})",
                (
                    "",
                    {
                        "interactive": GLib.Variant("b", False),
                        "modal": GLib.Variant("b", False),
                        "handle_token": GLib.Variant("s", token),
                    },
                ),
            ),
            GLib.VariantType("(o)"),
            Gio.DBusCallFlags.NONE,
            int(timeout_seconds * 1000),
            None,
        )
    except GLib.Error as error:
        bus.signal_unsubscribe(subscription)
        print(f"portal Screenshot call failed: {error.message}", file=sys.stderr)
        return 1

    loop.run()
    bus.signal_unsubscribe(subscription)

    if result.get("timeout"):
        print(
            "the portal did not answer; a desktop that asks for permission needs "
            "it granted once, interactively or through the permission store",
            file=sys.stderr,
        )
        return 1
    if result.get("code") != 0:
        print(f"the screenshot request was refused (code {result.get('code')})", file=sys.stderr)
        return 1

    uri = result.get("uri")
    if not isinstance(uri, str):
        print("the portal answered without a screenshot URI", file=sys.stderr)
        return 1
    source = urllib.parse.unquote(urllib.parse.urlparse(uri).path)
    if not os.path.isfile(source):
        print(f"the portal reported {source}, which is not there", file=sys.stderr)
        return 1

    shutil.copyfile(source, output_path)
    # The portal writes into a directory it owns; without this a gate run leaves
    # one screenshot behind every time.
    try:
        os.unlink(source)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
