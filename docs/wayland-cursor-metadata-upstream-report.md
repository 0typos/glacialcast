# niri PipeWire Cursor Metadata Report

This is a historical environment report from the 0.1 investigation. The
diagnosis remains relevant, but the current transport and verifier use
encrypted DASH rather than the removed legacy video path.

Generated from the Glacialcast cursor metadata verifier on 2026-05-04
23:54:24-04:00.

## Summary

Glacialcast can request and consume `SPA_META_Cursor` from PipeWire buffers, but
on this niri session the compositor accepts cursor metadata mode and then
allocates buffers without `SPA_META_Cursor`. The first buffer contains only
`SPA_META_Busy`, so an independent cursor overlay cannot be emitted.

This prevents a screen stream where video frames run at 1-15 fps while cursor
updates run independently at 10-30 Hz.

## Environment

- Compositor: niri `26.04 (8ed0da4)`
- Direct ScreenCast API: `org.gnome.Mutter.ScreenCast`, API version 4
- ScreenCast backend: direct Mutter-compatible niri DBus path
- Monitor: `DP-3`, 2560x1440, scale 1.0, logical position `(2560, 0)`
- Portal cursor modes: `AvailableCursorModes = 7`
- Portal services:
  - `xdg-desktop-portal.service`: active
  - `xdg-desktop-portal-gnome.service`: active
- Wayland capture globals:
  - `zwlr_screencopy_manager_v1`: present
  - `ext_image_copy_capture_manager_v1`: absent
  - `wp_cursor_shape_manager_v1`: present, but only lets clients set their own
    cursor shape
  - `zwp_relative_pointer_manager_v1`: present, but only reports motion
    relative to a client surface that owns pointer focus
  - `zwlr_virtual_pointer_manager_v1`: present, but is an input injection API
    rather than an observation API
- niri IPC:
  - The shell's `NIRI_SOCKET` was stale, but the verifier found the live socket
    under `/run/user/1000/niri.wayland-1.1294988.sock`.
  - With the live socket, `niri msg --help` has no cursor-position or
    pointer-position command.
  - `niri msg -j event-stream` reports workspace/window/cast/config events, but
    does not provide pointer-motion events or a global cursor position stream.
- Portal RemoteDesktop API:
  - `NotifyPointerMotion`, `NotifyPointerMotionAbsolute`, and related methods
    are input injection calls; they do not expose the compositor cursor state.

`AvailableCursorModes = 7` means the portal advertises hidden, embedded, and
metadata cursor modes.

## Reproducer

From the Glacialcast repo:

```sh
env \
  GLACIALCAST_VERIFY_SCREENCAST_BACKEND=mutter \
  GLACIALCAST_VERIFY_MONITOR_NAME=DP-3 \
  scripts/verify-wayland-cursor-metadata.sh
```

The verifier launches a temporary server and starts:

```sh
target/debug/glacialcast-client \
  --config /tmp/glacialcast-missing-client.toml \
  --ingest-addr 127.0.0.1:18900 \
  --client-id cursor-metadata-verify \
  --display-name "Cursor Metadata Verify" \
  --capture dash-wayland \
  --dash-encoder openh264 \
  --ingest-server-key <server-public-key> \
  --viewer-key <viewer-key> \
  --portal-source monitor \
  --screencast-backend mutter \
  --portal-cursor metadata \
  --require-cursor-metadata \
  --fps 1 \
  --cursor-hz 30 \
  --monitor-name DP-3
```

The verifier also checks niri IPC. On this machine it found a stale
`NIRI_SOCKET`, discovered the live niri socket, and confirmed the running
compositor:

```text
DIAG: NIRI_SOCKET is set but not reachable: /run/user/1000/niri.wayland-1.7608.sock
DIAG: using discovered niri socket for IPC checks: /run/user/1000/niri.wayland-1.1294988.sock
{"cli":"26.04 (8ed0da4)","compositor":"26.04 (8ed0da4)"}
niri IPC: no cursor-position or pointer-position command is advertised
```

## Expected

When `cursor-mode` is metadata, the PipeWire buffers should include a
`SPA_META_Cursor` entry. Glacialcast then sends cursor messages independently of
the video frame cadence, including cursor position, hotspot, and bitmap if the
compositor includes bitmap data.

The client requests cursor metadata with a `ParamMeta` object:

- `SPA_PARAM_META_type = SPA_META_Cursor`
- `SPA_PARAM_META_size = sizeof(spa_meta_cursor) + sizeof(spa_meta_bitmap) + bitmap_capacity`

This matches the installed SPA headers:

- `/usr/include/spa-0.2/spa/param/buffers.h`
- `/usr/include/spa-0.2/spa/buffer/meta.h`

## Actual

The niri direct ScreenCast API receives metadata cursor mode:

```text
niri::dbus::mutter_screen_cast: record_monitor connector="DP-3" properties=RecordMonitorProperties { cursor_mode: Some(Metadata), _is_recording: Some(true) }
```

The stream reaches `Streaming` and negotiates DMA-BUF successfully:

```text
format: VideoFormat::BGRx
size: 2560x1440
modifier: 216172782128496660
state_changed: Paused -> Streaming
```

But the client sees no cursor metadata on the first PipeWire buffer:

```text
first PipeWire buffer does not include SPA_META_Cursor; separate cursor overlay is unavailable until cursor metadata appears label=PipeWire video summary=Busy(7) size=8 data_null=false
```

The hard verifier then fails after the startup grace period:

```text
PipeWire stream failed: PipeWire video buffer does not include SPA_META_Cursor while --require-cursor-metadata is set
```

## Glacialcast-Side Checks Already Done

- XDG portal path requests cursor metadata when advertised.
- Direct Mutter-compatible path calls `RecordMonitor` with `cursor-mode = 2`
  and `is-recording = true`.
- PipeWire stream requests cursor metadata via post-format
  `stream.update_params`.
- Cursor metadata parsing distinguishes `SPA_META_Cursor` from `SPA_META_Busy`.
- Cursor bitmap and hotspot decoding are covered by a synthetic SPA buffer test.
- Required cursor metadata mode now fails closed instead of sending a cursorless
  stream.
- The current H.264 path negotiates DMA-BUF for direct VA-API import and uses
  OpenH264 only when hardware is unavailable or explicitly disabled.
- niri IPC was checked through the live compositor socket as a possible
  independent cursor source, but this niri version does not expose pointer
  position via `niri msg` commands or `event-stream`.
- The live Wayland registry was checked with `wayland-info`; advertised pointer
  protocols are surface-relative, cursor-shape setting, or input injection, not
  compositor-authoritative cursor observation.

## Current Conclusion

This looks like a compositor/PipeWire emission problem rather than a Glacialcast
transport or viewer problem. niri accepts metadata mode and successfully starts
the screencast, but does not allocate or populate `SPA_META_Cursor` on the
PipeWire buffers.

The missing behavior is observable without the Glacialcast server or browser:
the client exits solely because the PipeWire buffer metadata list lacks
`SPA_META_Cursor`.
