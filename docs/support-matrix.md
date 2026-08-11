# Support matrix

| Component | Implemented | Release evidence |
| --- | --- | --- |
| Publisher capture | XDG Portal/PipeWire on Wayland; deterministic test source | Synthetic CI; compositor-specific validation required |
| Publisher encoding | OpenH264 H.264 Annex-B | Synthetic E2E validated |
| Viewer window | egui/winit on Wayland and X11 | Builds on Linux; target-session validation required |
| Viewer layouts | 1, 2, 4, 6 tiles; tile fullscreen; keyboard switching | Unit/build evidence; four-stream performance host gate pending |
| Retained playback | Oldest, timestamp slider, explicit live edge | Protocol E2E validated |
| Relay | Linux native TCP, SQLite durable opaque history | Crash/retention/unit and process E2E validated |
| Browser/offline viewer | Not supported | Removed before protocol v9 |

Wayland is the primary viewer and capture target. X11 is a viewer target only;
publishing uses the Wayland portal/PipeWire capture path. A platform becomes
release-supported only after expected pixels and interaction are observed in
that actual graphical session. Until then it is experimental, even if CI builds.

The protocol has no stream-count limit. The UI is optimized and acceptance
tested for up to four simultaneous decoders; six tiles are available as a
convenience layout. About twenty concurrent viewers per publisher is the design
envelope for per-viewer HPKE key delivery, not a hard protocol maximum.
