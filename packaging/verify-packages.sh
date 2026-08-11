#!/usr/bin/env bash
# Checks what the packages install, and what their maintainer scripts do.
#
# The property worth guarding is that installing changes nothing about what is
# running. A relay that begins listening because a package was installed is a
# surprise, and on Debian that is the default behaviour unless a package
# declines it, so it has to be verified rather than assumed.
#
# The scripts are exercised against a stubbed systemctl rather than grepped,
# because the text "systemctl enable" appears in the instructions they print
# and a grep cannot tell that apart from a command.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

dist_dir="${GLACIALCAST_DIST_DIR:-${repo_root}/dist}"
work_dir="$(mktemp -d /tmp/glacialcast-packages.XXXXXX)"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

mkdir -p "${work_dir}/bin"
for tool in systemctl useradd groupadd getent; do
  cat >"${work_dir}/bin/${tool}" <<EOF
#!/bin/sh
echo "${tool} \$*" >>"\${GLACIALCAST_CALL_LOG}"
# getent must report the account as absent so preinstall takes its create path.
[ "${tool}" = "getent" ] && exit 2
exit 0
EOF
  chmod +x "${work_dir}/bin/${tool}"
done

run_script() {
  local script="$1" argument="$2"
  GLACIALCAST_CALL_LOG="${work_dir}/calls.log" \
    PATH="${work_dir}/bin:${PATH}" \
    sh "${script}" "${argument}" >/dev/null 2>&1 || true
}

# Installing must not enable or start anything, on either packaging system.
# RPM passes 1 on first install; dpkg passes "configure".
: >"${work_dir}/calls.log"
for argument in 1 configure; do
  run_script packaging/scripts/server-preinstall.sh "${argument}"
  run_script packaging/scripts/server-postinstall.sh "${argument}"
  run_script packaging/scripts/client-postinstall.sh "${argument}"
done
# Inspect the subcommand as a word rather than by pattern: "systemctl enable"
# has no space before "enable" to anchor on, and an earlier version of this
# check silently matched nothing because of exactly that.
if awk '$1 == "systemctl" { for (i = 2; i <= NF; i++) {
          if ($i == "enable" || $i == "start" || $i == "--now") { print; break }
        } }' "${work_dir}/calls.log" | grep -q .; then
  echo "installing enables or starts a service:" >&2
  grep -E 'systemctl' "${work_dir}/calls.log" >&2
  exit 1
fi
grep -q 'systemctl daemon-reload' "${work_dir}/calls.log" || {
  echo "installing never reloaded systemd, so the unit would not be visible" >&2
  exit 1
}

# An upgrade must leave a running relay alone. RPM passes 1 to preremove when
# upgrading, dpkg passes "upgrade".
for argument in 1 upgrade; do
  : >"${work_dir}/calls.log"
  run_script packaging/scripts/server-preremove.sh "${argument}"
  if grep -q 'disable' "${work_dir}/calls.log"; then
    echo "an upgrade (preremove ${argument}) stopped the running relay" >&2
    exit 1
  fi
done

# A real removal must stop it. RPM passes 0, dpkg passes "remove".
for argument in 0 remove; do
  : >"${work_dir}/calls.log"
  run_script packaging/scripts/server-preremove.sh "${argument}"
  grep -q 'disable --now gcrelay' "${work_dir}/calls.log" || {
    echo "removal (preremove ${argument}) left the relay enabled" >&2
    exit 1
  }
done

# Contents, checked against whichever tooling this host has.
rpm_package="$(find "${dist_dir}" -name 'gcrelay*.rpm' -print -quit)"
deb_package="$(find "${dist_dir}" -name 'gcrelay*.deb' -print -quit)"
client_rpm="$(find "${dist_dir}" -name 'gcpub*.rpm' -print -quit)"

expect_paths() {
  local listing="$1"
  shift
  for path in "$@"; do
    grep -Fq "${path}" <<<"${listing}" || {
      echo "package is missing ${path}" >&2
      exit 1
    }
  done
}

if [[ -n "${rpm_package}" ]] && command -v rpm >/dev/null; then
  listing="$(rpm -qlp "${rpm_package}" 2>/dev/null)"
  expect_paths "${listing}" \
    /usr/bin/gcrelay \
    /usr/bin/glacialcast-offline \
    /usr/lib/systemd/system/gcrelay.service
  # A package that ships a live configuration would overwrite ingest tokens on
  # upgrade. Only the example belongs here.
  ! grep -q '^/etc/glacialcast/server.toml$' <<<"${listing}" || {
    echo "the relay package ships a live /etc/glacialcast/server.toml" >&2
    exit 1
  }
  # The relay must not drag a graphics stack onto a headless host.
  requires="$(rpm -qp --requires "${client_rpm:-${rpm_package}}" 2>/dev/null)"
  if [[ -n "${client_rpm}" ]]; then
    grep -q 'pipewire' <<<"${requires}" || {
      echo "the publisher package does not depend on PipeWire" >&2
      exit 1
    }
  fi
  server_requires="$(rpm -qp --requires "${rpm_package}" 2>/dev/null)"
  ! grep -qE 'pipewire|libva|mesa' <<<"${server_requires}" || {
    echo "the relay package depends on a graphics stack it never calls" >&2
    exit 1
  }
fi

if [[ -n "${deb_package}" ]] && command -v dpkg >/dev/null; then
  listing="$(dpkg -c "${deb_package}" 2>/dev/null | awk '{print $6}')"
  expect_paths "${listing}" \
    ./usr/bin/gcrelay \
    ./usr/lib/systemd/system/gcrelay.service
fi

echo "PASS: packages install files without enabling anything, and split their dependencies"
