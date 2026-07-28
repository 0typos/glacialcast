#!/usr/bin/env bash
# Installs the OpenH264 the publisher loads, for continuous integration.
#
# The software encoder dlopens libopenh264.so.8, which is OpenH264 2.6.
# ubuntu-24.04 packages 2.4 as libopenh264.so.7, a different soname and a
# different ABI, so `apt install libopenh264-dev` satisfies the build and then
# fails at runtime with "OpenH264 2.6 (libopenh264.so.8) was not found". Cisco
# publishes prebuilt binaries only up to 2.5, which has the same problem, so
# this builds 2.6 from source.
#
# nasm is required. Building with USE_ASM=No looks like it avoids that, and
# produces a library that loads and then fails on an undefined
# WelsIDctFourT4Rec_avx2: the C++ still references the AVX2 assembly it did not
# build. That failure only appears when something tries to encode, so it is
# worth stating rather than rediscovering.
set -euo pipefail

# Pinned by commit, not by tag, so the build cannot move under us.
OPENH264_COMMIT="652bdb7719f30b52b08e506645a7322ff1b2cc6f"
OPENH264_VERSION="2.6.0"
install_dir="${1:-/usr/lib/x86_64-linux-gnu}"

command -v nasm >/dev/null || {
  echo "nasm is required to build OpenH264 with its assembly paths" >&2
  exit 2
}

build_dir="$(mktemp -d /tmp/openh264-build.XXXXXX)"
cleanup() {
  rm -rf "${build_dir}"
}
trap cleanup EXIT

git init -q "${build_dir}"
git -C "${build_dir}" remote add origin https://github.com/cisco/openh264
git -C "${build_dir}" fetch -q --depth 1 origin "${OPENH264_COMMIT}"
git -C "${build_dir}" checkout -q FETCH_HEAD
make -C "${build_dir}" -j"$(nproc)" libopenh264.so >/dev/null

library="${build_dir}/libopenh264.so.${OPENH264_VERSION}"
[[ -f "${library}" ]] || {
  echo "the build did not produce ${library}" >&2
  exit 1
}
# The soname is what the publisher searches for, so check it rather than trust
# the file name.
if command -v objdump >/dev/null; then
  objdump -p "${library}" | grep -q 'SONAME.*libopenh264\.so\.8' || {
    echo "built library does not carry the libopenh264.so.8 soname" >&2
    exit 1
  }
fi

install -D -m 0755 "${library}" "${install_dir}/libopenh264.so.${OPENH264_VERSION}"
ln -sf "libopenh264.so.${OPENH264_VERSION}" "${install_dir}/libopenh264.so.8"
echo "installed OpenH264 ${OPENH264_VERSION} to ${install_dir}/libopenh264.so.8"
