# GlacialCast Support Matrix

This matrix distinguishes implemented paths from release-validated platforms.
A platform is supported only after its evidence was recorded from the target
graphical session with:

```sh
scripts/record-platform-support.sh \
  --compositor <name-and-version> \
  --gpu-vendor <vendor> \
  --gpu-model <model> \
  --run-gates
```

The resulting report and its logs record the commit, compositor, session,
PipeWire, libva, cursor-metadata gate, published-picture gate, and
hardware-video gate. Do not convert an “implemented” row to “validated” based
on compilation or synthetic capture: only the picture gate compares what a
browser decodes against the compositor's own screenshot of the same output, and
scrambled pixels still produce valid encrypted objects.

## Browser and transport matrix

| Target | Required behavior | Current evidence |
| --- | --- | --- |
| Firefox on Linux | Clear Key EME keyring, retained multi-epoch history, live publisher transitions, independent cursor paint/move/hide/restore | Validated by the browser gates; Firefox is primary |
| Chromium on Linux | Same constrained CENC/fMP4 multi-epoch presentation and cursor behavior | Validated by the browser gates |
| Portable offline viewer | Incremental `.gco` arrival, multi-epoch history, and live epoch transitions in both browsers | Validated by the synthetic and browser gates |
| Internet HTTPS profile | Login, scoped authorization, Caddy TLS, secure session, playback in both browsers | Validated by the Internet browser gate |

## Compositor matrix

| Compositor family | Portal/capture path | Independent cursor | Release status |
| --- | --- | --- | --- |
| GNOME / Mutter | XDG Desktop Portal, multi-select, persisted grant | Implemented; host evidence required | Pending target-host validation |
| KDE Plasma / KWin | XDG Desktop Portal, multi-select, persisted grant | Implemented; host evidence required | Pending target-host validation |
| wlroots compositors | xdg-desktop-portal-wlr, multi-select, persisted grant | Implemented; host evidence required | Pending target-host validation |
| niri | Automatic selection uses niri's own Mutter-compatible ScreenCast interface; the configured portal remains available | Cursor metadata and object transport validated on niri 26.04 with PipeWire 1.6.8 | Validated for software encoding on NVIDIA: Firefox and Chromium decoded a frame that correlates 0.985 with the compositor's own screenshot of the captured output. VA-API hardware encoding remains pending representative hardware |

## Encoder matrix

| Hardware | Path | Release status |
| --- | --- | --- |
| Intel VA-API | DMA-BUF import/VPP when exposed, CPU upload fallback | Pending representative hardware validation |
| AMD VA-API | DMA-BUF import/VPP when exposed, CPU upload fallback | Pending representative hardware validation |
| NVIDIA proprietary driver | No VA-API H.264 entry point, so software encoding after EGL DMA-BUF readback | Validated on a GeForce RTX 5070 under niri 26.04; `scripts/verify-wayland-video-hardware.sh` correctly fails closed because the driver exposes no VA-API encode entry point |
| Other / unsupported VA-API | Dynamically loaded OpenH264 software encoder | Validated by deterministic integration gates |

The portal path was exercised on this niri host through
`xdg-desktop-portal-gnome`: a first start prompted and took 3.5 seconds, and the
next reused the stored restore token in 15 milliseconds with no dialog. That
covers the code path but not GNOME, KDE, or sway themselves, whose rows stay
pending until their own evidence is recorded. Multi-source portal selection has
no host evidence at all yet — it needs a desktop whose chooser offers it.

## Release policy

For a release candidate:

1. Run the full quality profile and the Firefox/Chromium browser matrix.
2. Run a minimum 30-minute soak with the intended release binary.
3. Record target-host evidence for every compositor and GPU row claimed as
   supported in the release notes.
4. Attach failing evidence without editing the gate to hide the failure.
5. List unvalidated rows as experimental, not supported.

The repository deliberately retains pending rows. They are explicit release
work, not evidence that a platform passed.
