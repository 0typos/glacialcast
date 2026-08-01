# GlacialCast cros-libva patches

This directory is the source distribution of `cros-libva 0.0.12` from
crates.io, under its original BSD-3-Clause license. It is patched locally
because `cros-codecs 0.0.6` requires the `0.0.12` semver range.

## Provenance

Vendored from the crates.io tarball `cros-libva-0.0.12.crate`, SHA-256
`902c9726e953b678595456bd38f95f31aaf1947c56dd9f4a2290f3f1eca4d228`. Re-vendor
by downloading that version again, verifying the digest, and reapplying the
changes below.

## This crate is outside the advisory gate

`cargo deny` matches RUSTSEC advisories by registry source. `[patch.crates-io]`
gives this crate a path source and no checksum in `Cargo.lock`, so the
`advisories` check cannot see it -- demonstrated by patching a known-vulnerable
crate the same way and watching the check still pass. `bans` and `licenses` do
see it; only advisories and yanked-detection are blind.

That makes the one crate here carrying a local fork of `unsafe` C bindings the
one crate the supply-chain gate does not cover. Until the patches go upstream
and the fork can be dropped, check it by hand when reviewing dependency
updates: look up `cros-libva` on <https://rustsec.org/> against the version
above.

GlacialCast carries these narrow changes:

- Use a default struct tail for the VP9 encoder picture parameters so the crate
  remains source-compatible with fields added by libva 1.23.
- Register the libva version configuration names emitted by the build script
  with current Rust `check-cfg`.
- Apply compiler-suggested lifetime annotations and a dead-code annotation to
  keep dependency builds warning-free.
- Expose a narrow, owned `VAProcPipelineParameterBuffer` wrapper used to
  convert imported PipeWire DMA-BUF surfaces into encoder-ready NV12.

No media behavior used by GlacialCast is otherwise changed.
