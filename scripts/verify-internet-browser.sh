#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

backend_addr="${GLACIALCAST_INTERNET_BROWSER_BACKEND_ADDR:-127.0.0.1:19899}"
ingest_addr="${GLACIALCAST_INTERNET_BROWSER_INGEST_ADDR:-127.0.0.1:19900}"
https_port="${GLACIALCAST_INTERNET_BROWSER_HTTPS_PORT:-19898}"
public_origin="https://localhost:${https_port}"
work_dir="$(mktemp -d /tmp/glacialcast-internet-browser.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
caddy_log="${work_dir}/caddy.log"
server_pid=""
client_pid=""
caddy_pid=""
caddy_name="glacialcast-browser-$$"

ingest_token="browser-ingest-0123456789abcdef0123456789"
access_token="browser-access-0123456789abcdef0123456789"

cleanup() {
  if [[ -n "${client_pid}" ]] && kill -0 "${client_pid}" 2>/dev/null; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
  fi
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  docker stop "${caddy_name}" >/dev/null 2>&1 || true
  if [[ -n "${caddy_pid}" ]]; then
    wait "${caddy_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

umask 077
cat >"${work_dir}/server.toml" <<TOML
[security]
public_origin = "${public_origin}"
trust_forwarded_for = true
session_ttl_seconds = 3600

[ingest]
require_token = true

[[ingest.tokens]]
name = "internet-browser"
token = "${ingest_token}"

[[access.tokens]]
name = "browser-viewer"
token = "${access_token}"
role = "viewer"
publishers = ["internet-browser"]
TOML

cat >"${work_dir}/Caddyfile" <<CADDY
{
	auto_https disable_redirects
}

https://localhost:${https_port} {
	tls internal
	reverse_proxy ${backend_addr}
}
CADDY
mkdir -p "${work_dir}/caddy-data" "${work_dir}/caddy-config"

cargo build -p glacialcast-server -p glacialcast-client

ingest_server_key="$(
  target/debug/glacialcast-server \
    --config "${work_dir}/server.toml" \
    --control-addr "${backend_addr}" \
    --ingest-addr "${ingest_addr}" \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"

target/debug/glacialcast-server \
  --config "${work_dir}/server.toml" \
  --control-addr "${backend_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  --retention-seconds 60 \
  --retention-bytes-per-stream 32MiB \
  >"${server_log}" 2>&1 &
server_pid="$!"

docker run --rm \
  --name "${caddy_name}" \
  --network host \
  --security-opt label=disable \
  -v "${work_dir}/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "${work_dir}/caddy-data:/data" \
  -v "${work_dir}/caddy-config:/config" \
  docker.io/library/caddy:2 \
  caddy run --config /etc/caddy/Caddyfile --adapter caddyfile \
  >"${caddy_log}" 2>&1 &
caddy_pid="$!"

for _ in $(seq 1 150); do
  if curl --insecure --fail --silent "${public_origin}/health/ready" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    echo "relay exited before the HTTPS browser gate became ready" >&2
    sed -n '1,240p' "${server_log}" >&2
    exit 1
  fi
  if ! kill -0 "${caddy_pid}" 2>/dev/null; then
    echo "Caddy exited before the HTTPS browser gate became ready" >&2
    sed -n '1,240p' "${caddy_log}" >&2
    exit 1
  fi
  sleep 0.1
done
curl --insecure --fail --silent "${public_origin}/health/ready" >/dev/null

viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --config "${work_dir}/missing-client.toml" \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --ingest-token "${ingest_token}" \
  --foreground \
  --client-id ignored-after-authentication \
  --display-name "Internet Browser E2E" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 4 \
  --cursor-hz 30 \
  --segment-frames 2 \
  >"${client_log}" 2>&1 &
client_pid="$!"

streams=""
for _ in $(seq 1 200); do
  streams="$(
    curl --insecure --fail --silent \
      -H "Authorization: Bearer ${access_token}" \
      "${public_origin}/api/streams"
  )"
  if [[ "${streams}" == *"Internet Browser E2E"* ]]; then
    break
  fi
  sleep 0.1
done
[[ "${streams}" == *"Internet Browser E2E"* ]] || {
  echo "publisher did not become available through HTTPS" >&2
  sed -n '1,240p' "${client_log}" >&2
  exit 1
}
stream_id="$(
  node -e "const v=JSON.parse(process.argv[1]);console.log(v[0].stream_id)" "${streams}"
)"

browsers="${GLACIALCAST_VERIFY_INTERNET_BROWSERS:-firefox,chromium}"
if [[ -z "${GLACIALCAST_FIREFOX_EXECUTABLE:-}" ]]; then
  playwright_cache="${PLAYWRIGHT_BROWSERS_PATH:-${XDG_CACHE_HOME:-${HOME}/.cache}/ms-playwright}"
  firefox_candidates=("${playwright_cache}"/firefox-*/firefox/firefox)
  for candidate in "${firefox_candidates[@]}"; do
    if [[ -x "${candidate}" ]]; then
      GLACIALCAST_FIREFOX_EXECUTABLE="${candidate}"
    fi
  done
  if [[ -z "${GLACIALCAST_FIREFOX_EXECUTABLE:-}" ]] && command -v firefox >/dev/null 2>&1; then
    GLACIALCAST_FIREFOX_EXECUTABLE="$(command -v firefox)"
  fi
  export GLACIALCAST_FIREFOX_EXECUTABLE
fi
if [[ -z "${GLACIALCAST_CHROMIUM_EXECUTABLE:-}" ]] && command -v google-chrome >/dev/null 2>&1; then
  GLACIALCAST_CHROMIUM_EXECUTABLE="$(command -v google-chrome)"
  export GLACIALCAST_CHROMIUM_EXECUTABLE
fi
IFS=',' read -r -a browser_list <<<"${browsers}"
for browser in "${browser_list[@]}"; do
  GLACIALCAST_VERIFY_ACCESS_TOKEN="${access_token}" \
  GLACIALCAST_VERIFY_IGNORE_HTTPS_ERRORS=1 \
    node scripts/verify-dash-browser.mjs \
      "${public_origin}" \
      "${stream_id}" \
      "${viewer_key}" \
      "${browser}"
done

if grep -Fq "${access_token}" "${server_log}" \
  || grep -Fq "${ingest_token}" "${server_log}" \
  || grep -Fq "${viewer_key}" "${server_log}" \
  || grep -Fq "${access_token}" "${caddy_log}"; then
  echo "a browser-gate credential leaked into service logs" >&2
  exit 1
fi

echo "PASS: ${browsers} authenticated through HTTPS and played E2EE media with the independent live cursor overlay"
