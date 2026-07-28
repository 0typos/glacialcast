#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

command -v systemd-analyze >/dev/null || {
  echo "SKIP: systemd-analyze is unavailable"
  exit 0
}

work_dir="$(mktemp -d /tmp/glacialcast-systemd.XXXXXX)"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

sed \
  "s#/usr/local/bin/glacialcast-server#${repo_root}/target/release/glacialcast-server#" \
  deploy/glacialcast-server.service >"${work_dir}/glacialcast-server.service"
systemd-analyze verify "${work_dir}/glacialcast-server.service"

sed \
  "s#/usr/local/bin/glacialcast-client#${repo_root}/target/release/glacialcast-client#" \
  deploy/glacialcast-publisher.service >"${work_dir}/glacialcast-publisher.service"
systemd-analyze --user verify "${work_dir}/glacialcast-publisher.service"

# The publisher detaches by default, so a supervised unit must keep it in the
# foreground or systemd would treat the immediate parent exit as a failure.
grep -Fq -- '--foreground' deploy/glacialcast-publisher.service || {
  echo "publisher unit must pass --foreground so systemd can supervise it" >&2
  exit 1
}

# A relative --config resolves against the working directory, which for a unit
# without WorkingDirectory= is /. That silently reads /server.toml, or nothing.
for unit in deploy/glacialcast-server.service deploy/glacialcast-publisher.service; do
  # Comments discuss --config at length; only what is executed matters here.
  if grep -v '^[[:space:]]*#' "${unit}" \
      | grep -oP -- '--config\s+\K\S+' \
      | grep -qv '^[/%]'; then
    echo "${unit} passes a relative --config; a unit's working directory is /" >&2
    exit 1
  fi
done

# Naming a configuration file that is not there must stop the service rather
# than start it on built-in defaults, which for the relay would mean no ingest
# tokens and for the publisher a stream nobody is expecting.
for binary in glacialcast-server glacialcast-client; do
  if "${repo_root}/target/release/${binary}" \
      --config "${work_dir}/definitely-absent.toml" \
      --print-viewer-key --print-ingest-server-key >/dev/null 2>&1; then
    echo "${binary} accepted a --config path that does not exist" >&2
    exit 1
  fi
done

# The standard location has to be found without --config, or the units above
# would start on defaults while appearing to work.
mkdir -p "${work_dir}/xdg/glacialcast"
printf '[ingest]\nrequire_token = false\n' >"${work_dir}/xdg/glacialcast/server.toml"
chmod 600 "${work_dir}/xdg/glacialcast/server.toml"
discovered="$(
  cd "${work_dir}" && XDG_CONFIG_HOME="${work_dir}/xdg" RUST_LOG=glacialcast_server=info \
    timeout 10 "${repo_root}/target/release/glacialcast-server" \
    --data-dir "${work_dir}/data" \
    --control-addr 127.0.0.1:19797 \
    --ingest-addr 127.0.0.1:19798 2>&1 &
  sleep 4
  pkill -f 'control-addr 127.0.0.1:19797' >/dev/null 2>&1 || true
  wait
)" || true
grep -Fq "${work_dir}/xdg/glacialcast/server.toml" <<<"${discovered}" || {
  echo "the relay did not discover its config in the standard location" >&2
  echo "${discovered}" | head -5 >&2
  exit 1
}

# A gate that names no configuration now discovers whatever sits in a standard
# location on the machine running it, so its result would depend on the
# developer's dotfiles. Every invocation in a gate must say which it wants.
unisolated=0
for script in scripts/*.sh; do
  while IFS= read -r offender; do
    echo "${script}: starts a binary without --config or --no-config: ${offender}" >&2
    unisolated=1
  done < <(
    awk '
      /target\/(debug|release)\/glacialcast-(server|client)/ { collecting = 1; buffer = "" }
      collecting {
        buffer = buffer " " $0
        if ($0 !~ /\\$/) {
          if (buffer !~ /--config/ && buffer !~ /--no-config/ && buffer !~ /client_args/) {
            print substr(buffer, 1, 70)
          }
          collecting = 0
        }
      }
    ' "${script}"
  )
done
[[ "${unisolated}" -eq 0 ]] || exit 1

echo "PASS: systemd units are valid and configuration resolves as documented"
