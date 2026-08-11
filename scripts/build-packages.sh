#!/usr/bin/env bash
# Builds .rpm and .deb packages for both binaries.
#
# The unit files are generated from deploy/ rather than copied, because the
# only difference is the install prefix: deploy/ documents a manual install
# under /usr/local/bin, and a package owns /usr/bin. Keeping two copies would
# mean every future change to a unit has to be made twice, and the second one
# would eventually be forgotten.
#
# Neither package enables or starts anything. See packaging/scripts/.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

command -v nfpm >/dev/null || {
  echo "nfpm is required: https://nfpm.goreleaser.com/install/" >&2
  exit 2
}

version="$(
  cargo metadata --locked --no-deps --format-version 1 \
    | node -e \
      "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const m=JSON.parse(s);process.stdout.write(m.packages.find(p=>p.name==='gcrelay').version)})"
)"
dist_dir="${GLACIALCAST_DIST_DIR:-${repo_root}/dist}"
staging="${repo_root}/target/package-staging"

case "$(uname -m)" in
  x86_64) package_arch="amd64" ;;
  aarch64) package_arch="arm64" ;;
  *)
    echo "unsupported architecture $(uname -m)" >&2
    exit 2
    ;;
esac

cargo build --workspace --release --locked

rm -rf "${staging}"
mkdir -p "${staging}/systemd" "${dist_dir}"
# The one substitution that separates a packaged unit from the documented
# manual install.
sed 's#/usr/local/bin/#/usr/bin/#g' \
  deploy/gcrelay.service >"${staging}/systemd/gcrelay.service"
sed 's#/usr/local/bin/#/usr/bin/#g' \
  deploy/gcpub.service >"${staging}/systemd/gcpub.service"

# A stale /usr/local path in a packaged unit means a service that cannot start.
for unit in "${staging}"/systemd/*.service; do
  ! grep -q '/usr/local/bin/' "${unit}" || {
    echo "${unit} still refers to /usr/local/bin" >&2
    exit 1
  }
  grep -q '^ExecStart=/usr/bin/' "${unit}" || {
    echo "${unit} has no ExecStart under /usr/bin" >&2
    exit 1
  }
done

# The glibc a binary actually needs, taken from the binary rather than assumed.
# A package that declares a bare libc6 dependency installs happily on an older
# distribution and then fails to execute, which is a worse outcome than
# refusing to install: verified on Debian 12, where binaries built against
# glibc 2.39 install and then cannot start. Whatever host builds the release,
# the dependency describes it truthfully.
minimum_glibc="$(
  for binary in gcrelay gcpub glacialcast-offline; do
    objdump -T "target/release/${binary}" 2>/dev/null \
      | grep -o 'GLIBC_[0-9.]*' \
      | sed 's/GLIBC_//'
  done | sort -V | tail -1
)"
[[ -n "${minimum_glibc}" ]] || {
  echo "could not determine the required glibc version from the built binaries" >&2
  exit 1
}
echo "packages will require glibc >= ${minimum_glibc}" >&2

export GLACIALCAST_VERSION="${version}"
export GLACIALCAST_PACKAGE_ARCH="${package_arch}"
export GLACIALCAST_LIBC_DEB="libc6 (>= ${minimum_glibc})"
export GLACIALCAST_LIBC_RPM="libc.so.6(GLIBC_${minimum_glibc})(64bit)"

for component in server client; do
  for format in rpm deb; do
    nfpm package \
      --config "packaging/nfpm-${component}.yaml" \
      --packager "${format}" \
      --target "${dist_dir}"
  done
done

(
  cd "${dist_dir}"
  for artifact in *.rpm *.deb; do
    [[ -e "${artifact}" ]] || continue
    sha256sum "${artifact}" >"${artifact}.sha256"
  done
)

printf '%s\n' "${dist_dir}"/*.rpm "${dist_dir}"/*.deb
