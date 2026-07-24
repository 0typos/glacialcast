#!/usr/bin/env bash
set -u

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18898}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18897}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-frame-integrity-verify.$$}"
CLIENT_LOG_DIR="${GLACIALCAST_VERIFY_CLIENT_LOG_DIR:-/tmp}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-25}"

SERVER_PID=""
CLIENT_PID=""
CLIENT_LOG=""

cleanup() {
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_cmd cargo
need_cmd curl
need_cmd node

mkdir -p "${DATA_DIR}" "${CLIENT_LOG_DIR}"

echo "building Glacialcast verifier binaries"
cargo build -p glacialcast-server -p glacialcast-client

echo "starting temporary Glacialcast server on ${CONTROL_ADDR} / ${INGEST_ADDR}"
./target/debug/glacialcast-server \
  --control-addr "${CONTROL_ADDR}" \
  --ingest-addr "${INGEST_ADDR}" \
  --data-dir "${DATA_DIR}" \
  --retention-bytes-per-stream 32MiB &
SERVER_PID="$!"

for _ in {1..80}; do
  if curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "server exited before becoming ready" >&2
    wait "${SERVER_PID}" 2>/dev/null || true
    exit 1
  fi
  sleep 0.1
done

if ! curl -fsS "http://${CONTROL_ADDR}/api/streams" >/dev/null 2>&1; then
  echo "server did not become ready on ${CONTROL_ADDR}" >&2
  exit 1
fi

random_viewer_key() {
  node -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'))"
}

run_case() {
  local mode="$1"
  local display_name="$2"
  local client_id="$3"
  local viewer_key="${4:-}"
  local expected_encrypted="$5"

  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi

  CLIENT_LOG="${CLIENT_LOG_DIR}/glacialcast-frame-integrity-${mode}.$$.log"
  local client_args=(
    --config /tmp/glacialcast-missing-client.toml
    --ingest-addr "${INGEST_ADDR}"
    --client-id "${client_id}"
    --display-name "${display_name}"
    --capture test-pattern
    --fps 1
  )
  if [[ -n "${viewer_key}" ]]; then
    client_args+=(--viewer-key "${viewer_key}")
  else
    client_args+=(--no-viewer-key)
  fi

  echo "starting ${mode} test-pattern client"
  ./target/debug/glacialcast-client "${client_args[@]}" >"${CLIENT_LOG}" 2>&1 &
  CLIENT_PID="$!"

  node - "${CONTROL_ADDR}" "${display_name}" "${viewer_key}" "${expected_encrypted}" "${CLIENT_TIMEOUT}" <<'NODE'
const [controlAddr, displayName, viewerKey, expectedEncrypted, timeoutText] = process.argv.slice(2);
const timeoutMs = Number(timeoutText) * 1000;

function b64urlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  return Uint8Array.from(Buffer.from(padded, 'base64'));
}

function fastContentHash(bytes) {
  let hash = 0x811c9dc5;
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

async function decryptFrame(manifest, ciphertext, keyText) {
  const keyBytes = b64urlToBytes(keyText);
  if (keyBytes.length !== 32) throw new Error(`viewer key must decode to 32 bytes, got ${keyBytes.length}`);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(manifest.nonce) },
    key,
    ciphertext,
  );
  return new Uint8Array(plain);
}

async function fetchJson(path) {
  const res = await fetch(`http://${controlAddr}${path}`);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return await res.json();
}

async function fetchBytes(path) {
  const res = await fetch(`http://${controlAddr}${path}`);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function findFrame() {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const streams = await fetchJson('/api/streams');
    const stream = streams.find(candidate => candidate.display_name === displayName);
    if (stream?.stream_id) {
      const frames = await fetchJson(`/api/streams/${stream.stream_id}/frames`);
      if (frames.length > 0) {
        return { stream, manifest: frames[frames.length - 1] };
      }
    }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for frame from ${displayName}`);
}

const { stream, manifest } = await findFrame();
const encrypted = Boolean(manifest.key_id);
if (String(stream.frame_encrypted) !== expectedEncrypted) {
  throw new Error(`stream frame_encrypted=${stream.frame_encrypted}, expected ${expectedEncrypted}`);
}
if (String(encrypted) !== expectedEncrypted) {
  throw new Error(`manifest encrypted=${encrypted}, expected ${expectedEncrypted}`);
}

const payload = await fetchBytes(`/api/streams/${stream.stream_id}/frames/${manifest.seq}`);
const plain = encrypted ? await decryptFrame(manifest, payload, viewerKey) : payload;
const plainHash = fastContentHash(plain);
if (plainHash !== manifest.content_hash) {
  throw new Error(`content_hash mismatch: manifest=${manifest.content_hash}, computed=${plainHash}`);
}
if (encrypted && payload.length !== plain.length + 16) {
  throw new Error(`encrypted payload length ${payload.length} did not include AES-GCM tag over plaintext ${plain.length}`);
}
if (!encrypted && viewerKey) {
  throw new Error('clear stream unexpectedly required a viewer key');
}
console.log(`PASS ${displayName}: seq=${manifest.seq} encrypted=${encrypted} bytes=${plain.length} content_hash=${plainHash}`);
NODE

  local status="$?"
  if [[ "${status}" -ne 0 ]]; then
    echo "FAIL: ${mode} integrity verifier failed; client log: ${CLIENT_LOG}" >&2
    tail -n 80 "${CLIENT_LOG}" >&2 || true
    exit "${status}"
  fi
}

run_case "clear" "Frame Integrity Clear" "frame-integrity-clear" "" "false"
run_case "encrypted" "Frame Integrity Encrypted" "frame-integrity-encrypted" "$(random_viewer_key)" "true"

echo "PASS: clear and encrypted frame payloads match their viewer-side content hashes"
