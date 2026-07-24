# GlacialCast cros-libva patches

This directory is the source distribution of `cros-libva 0.0.12` from
crates.io, under its original BSD-3-Clause license. It is patched locally
because `cros-codecs 0.0.6` requires the `0.0.12` semver range.

GlacialCast carries these narrow changes:

- Use a default struct tail for the VP9 encoder picture parameters so the crate
  remains source-compatible with fields added by libva 1.23.
- Register the libva version configuration names emitted by the build script
  with current Rust `check-cfg`.
- Apply compiler-suggested lifetime annotations and a dead-code annotation to
  keep dependency builds warning-free.

No media behavior used by GlacialCast is otherwise changed.
