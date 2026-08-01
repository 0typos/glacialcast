#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

control_addr="${GLACIALCAST_SECURITY_CONTROL_ADDR:-127.0.0.1:19499}"
ingest_addr="${GLACIALCAST_SECURITY_INGEST_ADDR:-127.0.0.1:19500}"
local_origin="http://${control_addr}"
public_origin="https://cast.example.test"
work_dir="$(mktemp -d /tmp/glacialcast-security.XXXXXX)"
server_log="${work_dir}/server.log"
client_log="${work_dir}/client.log"
server_pid=""
client_pid=""

ingest_token="ingest-0123456789abcdef0123456789abcdef"
admin_token="admin-0123456789abcdef0123456789abcdef"
viewer_token="viewer-0123456789abcdef0123456789abcdef"
denied_token="denied-0123456789abcdef0123456789abcdef"
managed_token=""

cleanup() {
  for pid in "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

umask 077
cat >"${work_dir}/server.toml" <<TOML
[security]
public_origin = "${public_origin}"
trust_forwarded_for = true
session_ttl_seconds = 3600

[security.limits]
max_http_in_flight = 32
max_websockets = 4
max_websockets_per_principal = 2
max_ingest_connections = 2
max_ingest_connections_per_ip = 1
login_attempts_per_minute = 2
global_login_attempts_per_minute = 20
authenticated_requests_per_minute = 10000
websocket_attempts_per_minute = 20
ingest_attempts_per_minute = 20
http_timeout_seconds = 10
ingest_handshake_timeout_seconds = 2
ingest_idle_timeout_seconds = 30

[ingest]
require_token = true

[[ingest.tokens]]
name = "internet-client"
token = "${ingest_token}"

[[access.tokens]]
name = "operator"
token = "${admin_token}"
role = "admin"

[[access.tokens]]
name = "authorized-viewer"
token = "${viewer_token}"
role = "viewer"
publishers = ["internet-client"]

[[access.tokens]]
name = "denied-viewer"
token = "${denied_token}"
role = "viewer"
publishers = ["another-client"]
TOML

cargo build -p glacialcast-server -p glacialcast-client -p glacialcast-offline

ingest_server_key="$(
  target/debug/glacialcast-server \
    --config "${work_dir}/server.toml" \
    --control-addr "${control_addr}" \
    --ingest-addr "${ingest_addr}" \
    --data-dir "${work_dir}/data" \
    --print-ingest-server-key
)"

target/debug/glacialcast-server \
  --config "${work_dir}/server.toml" \
  --control-addr "${control_addr}" \
  --ingest-addr "${ingest_addr}" \
  --data-dir "${work_dir}/data" \
  --retention-seconds 60 \
  --retention-bytes-per-stream 32MiB \
  >"${server_log}" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  if curl -fsS "${local_origin}/health/ready" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    echo "security relay exited before becoming ready" >&2
    sed -n '1,240p' "${server_log}" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "${local_origin}/health/live" >/dev/null
curl -fsS "${local_origin}/health/ready" >/dev/null

status="$(
  curl -sS -o /dev/null -w '%{http_code}' "${local_origin}/api/streams"
)"
[[ "${status}" == "401" ]] || {
  echo "anonymous stream listing returned ${status}, expected 401" >&2
  exit 1
}

for page in "/" "/streams"; do
  status="$(
    curl -sS -o /dev/null -w '%{http_code}' "${local_origin}${page}"
  )"
  [[ "${status}" == "303" ]] || {
    echo "anonymous ${page} returned ${status}, expected 303" >&2
    exit 1
  }
done
curl -fsS "${local_origin}/login" >/dev/null

security_headers="$(
  curl -sS -D - -o /dev/null "${local_origin}/health/live" | tr -d '\r'
)"
for expected in \
  "strict-transport-security: max-age=31536000; includeSubDomains" \
  "content-security-policy: default-src 'none'" \
  "x-content-type-options: nosniff" \
  "x-frame-options: DENY" \
  "referrer-policy: no-referrer" \
  "permissions-policy: camera=()"; do
  grep -Fiq "${expected}" <<<"${security_headers}" || {
    echo "missing security response header: ${expected}" >&2
    exit 1
  }
done

status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Origin: https://evil.example" \
    -H 'Content-Type: application/json' \
    --data "{\"token\":\"${admin_token}\"}" \
    "${local_origin}/api/auth/login"
)"
[[ "${status}" == "403" ]] || {
  echo "cross-origin login returned ${status}, expected 403" >&2
  exit 1
}

for attempt in 1 2; do
  status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -X POST \
      -H "Origin: ${public_origin}" \
      -H 'X-Forwarded-For: 203.0.113.10' \
      -H 'Content-Type: application/json' \
      --data '{"token":"invalid-0123456789abcdef0123456789"}' \
      "${local_origin}/api/auth/login"
  )"
  [[ "${status}" == "401" ]] || {
    echo "invalid login ${attempt} returned ${status}, expected 401" >&2
    exit 1
  }
done
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Origin: ${public_origin}" \
    -H 'X-Forwarded-For: 203.0.113.10' \
    -H 'Content-Type: application/json' \
    --data '{"token":"invalid-0123456789abcdef0123456789"}' \
    "${local_origin}/api/auth/login"
)"
[[ "${status}" == "429" ]] || {
  echo "login throttle returned ${status}, expected 429" >&2
  exit 1
}

curl -sS -D "${work_dir}/login.headers" -o "${work_dir}/login.json" \
  -X POST \
  -H "Origin: ${public_origin}" \
  -H 'X-Forwarded-For: 203.0.113.11' \
  -H 'Content-Type: application/json' \
  --data "{\"token\":\"${admin_token}\"}" \
  "${local_origin}/api/auth/login"
admin_cookie="$(
  sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "${work_dir}/login.headers" | tr -d '\r'
)"
csrf_token="$(
  node -e \
    "const fs=require('fs');console.log(JSON.parse(fs.readFileSync(process.argv[1])).csrf_token)" \
    "${work_dir}/login.json"
)"
[[ -n "${admin_cookie}" && -n "${csrf_token}" ]] || {
  echo "login did not issue a session cookie and CSRF token" >&2
  exit 1
}
cookie_headers="$(tr -d '\r' <"${work_dir}/login.headers")"
for attribute in "HttpOnly" "SameSite=Strict" "Secure"; do
  grep -Fq "${attribute}" <<<"${cookie_headers}" || {
    echo "session cookie is missing ${attribute}" >&2
    exit 1
  }
done
curl -fsS -H "Cookie: ${admin_cookie}" "${local_origin}/api/session" \
  | grep -Fq '"role":"admin"'

status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Cookie: ${admin_cookie}" \
    -H "Origin: https://evil.example" \
    -H 'Connection: Upgrade' \
    -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==' \
    "${local_origin}/api/ws"
)"
[[ "${status}" == "403" ]] || {
  echo "cross-origin WebSocket returned ${status}, expected 403" >&2
  exit 1
}

viewer_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
RUST_LOG=glacialcast_client=info target/debug/glacialcast-client \
  --no-config \
  --ingest-addr "${ingest_addr}" \
  "--ingest-server-key=${ingest_server_key}" \
  "--viewer-key=${viewer_key}" \
  --ingest-token "${ingest_token}" \
  --foreground \
  --client-id ignored-after-authentication \
  --display-name "Internet Security E2E" \
  --capture dash-test \
  --dash-encoder openh264 \
  --width 320 \
  --height 180 \
  --fps 2 \
  --cursor-hz 20 \
  --segment-frames 2 \
  >"${client_log}" 2>&1 &
client_pid="$!"

for _ in $(seq 1 200); do
  streams="$(
    curl -fsS -H "Authorization: Bearer ${admin_token}" \
      "${local_origin}/api/streams"
  )"
  if [[ "${streams}" == *"Internet Security E2E"* ]]; then
    break
  fi
  sleep 0.1
done
[[ "${streams}" == *"Internet Security E2E"* ]] || {
  echo "authenticated publisher did not create a stream" >&2
  sed -n '1,240p' "${client_log}" >&2
  exit 1
}
stream_id="$(
  node -e "const v=JSON.parse(process.argv[1]);console.log(v[0].stream_id)" "${streams}"
)"

authorized_streams="$(
  curl -fsS -H "Authorization: Bearer ${viewer_token}" \
    "${local_origin}/api/streams"
)"
denied_streams="$(
  curl -fsS -H "Authorization: Bearer ${denied_token}" \
    "${local_origin}/api/streams"
)"
[[ "${authorized_streams}" == *"${stream_id}"* && "${denied_streams}" == "[]" ]] || {
  echo "publisher-scoped stream listing failed" >&2
  exit 1
}

curl -fsS \
  -H "Authorization: Bearer ${admin_token}" \
  -H "Origin: ${public_origin}" \
  -H 'Content-Type: application/json' \
  --data '{"name":"managed-viewer","publishers":["internet-client"]}' \
  "${local_origin}/api/admin/enrollments" >"${work_dir}/enrollment.json"
managed_token="$(
  node -e \
    "const fs=require('fs');const v=JSON.parse(fs.readFileSync(process.argv[1]));console.log(v.access_token)" \
    "${work_dir}/enrollment.json"
)"
[[ "${managed_token}" == gca_* ]] || {
  echo "managed enrollment did not return a one-time access token" >&2
  exit 1
}
enrollments="$(
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    "${local_origin}/api/admin/enrollments"
)"
[[ "${enrollments}" == *'"name":"managed-viewer"'* \
  && "${enrollments}" != *"${managed_token}"* ]] || {
  echo "managed enrollment listing was missing or exposed the token" >&2
  exit 1
}
managed_streams="$(
  curl -fsS -H "Authorization: Bearer ${managed_token}" \
    "${local_origin}/api/streams"
)"
[[ "${managed_streams}" == *"${stream_id}"* ]] || {
  echo "managed viewer could not access its publisher scope" >&2
  exit 1
}
curl -sS -D "${work_dir}/managed-login.headers" -o "${work_dir}/managed-login.json" \
  -X POST \
  -H "Origin: ${public_origin}" \
  -H 'X-Forwarded-For: 203.0.113.12' \
  -H 'Content-Type: application/json' \
  --data "{\"token\":\"${managed_token}\"}" \
  "${local_origin}/api/auth/login"
managed_cookie="$(
  sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' \
    "${work_dir}/managed-login.headers" | tr -d '\r'
)"
[[ -n "${managed_cookie}" ]] || {
  echo "managed viewer login did not issue a session cookie" >&2
  exit 1
}
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X DELETE \
    -H "Authorization: Bearer ${admin_token}" \
    -H "Origin: ${public_origin}" \
    "${local_origin}/api/admin/enrollments/managed-viewer"
)"
[[ "${status}" == "204" ]] || {
  echo "managed viewer revocation returned ${status}, expected 204" >&2
  exit 1
}
for authority in \
  "Authorization: Bearer ${managed_token}" \
  "Cookie: ${managed_cookie}"; do
  status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "${authority}" \
      "${local_origin}/api/streams"
  )"
  [[ "${status}" == "401" ]] || {
    echo "revoked managed authority returned ${status}, expected 401" >&2
    exit 1
  }
done

curl -fsS -H "Authorization: Bearer ${viewer_token}" \
  "${local_origin}/api/dash/streams/${stream_id}/objects" >/dev/null
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${denied_token}" \
    "${local_origin}/api/dash/streams/${stream_id}/objects"
)"
[[ "${status}" == "404" ]] || {
  echo "out-of-scope object listing returned ${status}, expected hidden 404" >&2
  exit 1
}

target/debug/glacialcast-offline mirror \
  --server "${local_origin}" \
  --access-token "${viewer_token}" \
  --stream-id "${stream_id}" \
  --output "${work_dir}/mirror"
find "${work_dir}/mirror" -maxdepth 1 -name '*.gco' -print -quit | grep -q .

status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X DELETE \
    -H "Authorization: Bearer ${viewer_token}" \
    -H "Origin: ${public_origin}" \
    "${local_origin}/api/streams/${stream_id}"
)"
[[ "${status}" == "403" ]] || {
  echo "viewer deletion returned ${status}, expected 403" >&2
  exit 1
}
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X DELETE \
    -H "Cookie: ${admin_cookie}" \
    -H "Origin: ${public_origin}" \
    "${local_origin}/api/streams/${stream_id}"
)"
[[ "${status}" == "403" ]] || {
  echo "session deletion without CSRF returned ${status}, expected 403" >&2
  exit 1
}
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X DELETE \
    -H "Cookie: ${admin_cookie}" \
    -H "Origin: ${public_origin}" \
    -H "X-GlacialCast-CSRF: ${csrf_token}" \
    "${local_origin}/api/streams/${stream_id}"
)"
[[ "${status}" == "204" ]] || {
  echo "authorized deletion returned ${status}, expected 204" >&2
  exit 1
}

metrics="$(
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    "${local_origin}/api/admin/metrics"
)"
for counter in login_successes login_failures login_rate_limited http_requests; do
  grep -Fq "\"${counter}\":" <<<"${metrics}" || {
    echo "metrics response is missing ${counter}" >&2
    exit 1
  }
done
status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${viewer_token}" \
    "${local_origin}/api/admin/metrics"
)"
[[ "${status}" == "403" ]] || {
  echo "viewer metrics request returned ${status}, expected 403" >&2
  exit 1
}

if grep -Fq "${admin_token}" "${server_log}" \
  || grep -Fq "${viewer_token}" "${server_log}" \
  || grep -Fq "${ingest_token}" "${server_log}" \
  || grep -Fq "${managed_token}" "${server_log}" \
  || grep -Fq "${viewer_key}" "${server_log}"; then
  echo "a configured credential leaked into the relay log" >&2
  exit 1
fi

chmod 0644 "${work_dir}/server.toml"
if target/debug/glacialcast-server \
  --config "${work_dir}/server.toml" \
  --control-addr 127.0.0.1:19699 \
  --ingest-addr 127.0.0.1:19700 \
  --data-dir "${work_dir}/unsafe-data" \
  >"${work_dir}/unsafe.log" 2>&1; then
  echo "Internet mode accepted a publicly readable credential file" >&2
  exit 1
fi
grep -Fq "private regular file with mode 0600" "${work_dir}/unsafe.log"

if target/debug/glacialcast-server \
  --no-config \
  --control-addr 0.0.0.0:19699 \
  --ingest-addr 127.0.0.1:19700 \
  --data-dir "${work_dir}/public-http-data" \
  >"${work_dir}/public-http.log" 2>&1; then
  echo "relay accepted an accidental public plaintext HTTP listener" >&2
  exit 1
fi
grep -Fq "refusing a non-loopback HTTP listener" "${work_dir}/public-http.log"

# A wrong bearer credential must face the same limiter as a wrong login.
#
# Every route other than /api/auth/login reaches request_identity, which
# returns early on an Authorization header, so a guesser who used a bearer
# token instead of the login form met no limiter, no counter, and no delay --
# orders of magnitude more attempts per minute than the login path allows, and
# invisible to the failure metric operators are told to alert on.
bearer_codes=""
for attempt in $(seq 1 6); do
  bearer_codes="${bearer_codes} $(
    curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer wrong-bearer-guess-${attempt}" \
      "${local_origin}/api/streams" || true
  )"
done
if ! grep -q "429" <<<"${bearer_codes}"; then
  echo "a wrong bearer credential was never rate limited: ${bearer_codes}" >&2
  exit 1
fi
if ! grep -q "401" <<<"${bearer_codes}"; then
  echo "a wrong bearer credential was not rejected before limiting: ${bearer_codes}" >&2
  exit 1
fi
echo "a wrong bearer credential is rejected and then rate limited:${bearer_codes}"

echo "PASS: Internet profile enforced authentication, managed enrollment/revocation, publisher authorization, CSRF/origin policy, login throttling, secure cookies, security headers, private configuration, monitoring, and fail-closed binds"
