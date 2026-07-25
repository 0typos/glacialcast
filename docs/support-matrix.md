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

The resulting report and its two logs record the commit, compositor, session,
PipeWire, libva, cursor-metadata gate, and hardware-video gate. Do not convert
an “implemented” row to “validated” based on compilation or synthetic capture.

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
| GNOME / Mutter | XDG Desktop Portal | Implemented; host evidence required | Pending target-host validation |
| KDE Plasma / KWin | XDG Desktop Portal | Implemented; host evidence required | Pending target-host validation |
| wlroots compositors | xdg-desktop-portal-wlr | Implemented; host evidence required | Pending target-host validation |
| niri | Mutter-compatible ScreenCast path or configured portal | Cursor metadata and object transport validated on niri 26.04 with PipeWire 1.6.8 through the direct path | Pending pixel-correct Firefox/Chromium screenshot and hardware gate |

## Encoder matrix

| Hardware | Path | Release status |
| --- | --- | --- |
| Intel VA-API | DMA-BUF import/VPP when exposed, CPU upload fallback | Pending representative hardware validation |
| AMD VA-API | DMA-BUF import/VPP when exposed, CPU upload fallback | Pending representative hardware validation |
| Other / unsupported VA-API | Dynamically loaded OpenH264 software encoder | Validated by deterministic integration gates |

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
