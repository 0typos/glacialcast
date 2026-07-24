#!/usr/bin/env bash
set -euo pipefail

CONTROL_ADDR="${GLACIALCAST_VERIFY_CONTROL_ADDR:-127.0.0.1:18918}"
INGEST_ADDR="${GLACIALCAST_VERIFY_INGEST_ADDR:-127.0.0.1:18917}"
DATA_DIR="${GLACIALCAST_VERIFY_DATA_DIR:-/tmp/glacialcast-browser-render-verify.$$}"
CLIENT_LOG_DIR="${GLACIALCAST_VERIFY_CLIENT_LOG_DIR:-/tmp}"
CLIENT_TIMEOUT="${GLACIALCAST_VERIFY_CLIENT_TIMEOUT:-25}"
PLAYWRIGHT_DIR_OWNED=0
if [[ -n "${GLACIALCAST_VERIFY_PLAYWRIGHT_DIR:-}" ]]; then
  PLAYWRIGHT_DIR="${GLACIALCAST_VERIFY_PLAYWRIGHT_DIR}"
else
  PLAYWRIGHT_DIR="$(mktemp -d /tmp/glacialcast-playwright-verify.XXXXXX)"
  PLAYWRIGHT_DIR_OWNED=1
fi

SERVER_PID=""
CLIENT_PID=""
CLIENT_LOG=""
SERVER_LOG="${GLACIALCAST_VERIFY_SERVER_LOG:-/tmp/glacialcast-browser-render-server.$$.log}"

cleanup() {
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${PLAYWRIGHT_DIR_OWNED}" == "1" ]]; then
    rm -rf "${PLAYWRIGHT_DIR}"
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
need_cmd npm
need_cmd google-chrome

mkdir -p "${DATA_DIR}" "${CLIENT_LOG_DIR}" "${PLAYWRIGHT_DIR}"
export NPM_CONFIG_CACHE="${PLAYWRIGHT_DIR}/npm-cache"
export PLAYWRIGHT_BROWSERS_PATH="${GLACIALCAST_VERIFY_PLAYWRIGHT_BROWSERS_PATH:-${XDG_CACHE_HOME:-/tmp}/glacialcast-playwright-browsers}"

echo "preparing Playwright browser verifier"
(
  cd "${PLAYWRIGHT_DIR}"
  npm init -y >/dev/null
  npm install @playwright/test@1.54.2 --no-save >/dev/null
  npx playwright install firefox >/dev/null
)

cat >"${PLAYWRIGHT_DIR}/playwright.config.js" <<'NODE'
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  projects: [
    {
      name: 'chrome',
      use: {
        browserName: 'chromium',
        launchOptions: { executablePath: process.env.GLACIALCAST_CHROME_EXECUTABLE },
      },
    },
    { name: 'firefox', use: { browserName: 'firefox' } },
  ],
});
NODE
export GLACIALCAST_CHROME_EXECUTABLE="$(command -v google-chrome)"

cat >"${PLAYWRIGHT_DIR}/dashboard-render.spec.js" <<'NODE'
const { test, expect } = require('@playwright/test');

test('dashboard renders the selected stream frame bytes', async ({ page }) => {
  const controlAddr = process.env.GLACIALCAST_BROWSER_CONTROL_ADDR;
  const streamId = process.env.GLACIALCAST_BROWSER_STREAM_ID;
  const viewerKey = process.env.GLACIALCAST_BROWSER_VIEWER_KEY || '';
  const expectedEncrypted = process.env.GLACIALCAST_BROWSER_EXPECTED_ENCRYPTED === 'true';
  const expectedDisplayName = process.env.GLACIALCAST_BROWSER_DISPLAY_NAME;

  const errors = [];
  page.on('console', message => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', error => errors.push(error.message));

  const fragment = new URLSearchParams({ stream: streamId });
  if (viewerKey) fragment.set('key', viewerKey);
  await page.goto(`http://${controlAddr}/#${fragment.toString()}`);

  const tile = page.locator('[data-slot="0"]');
  await expect(tile.locator('.tile-title strong')).toHaveText(expectedDisplayName, { timeout: 15000 });
  await expect(tile.locator('img.screen-media')).toBeVisible({ timeout: 20000 });
  await page.waitForFunction(() => {
    const img = document.querySelector('[data-slot="0"] img.screen-media');
    return img && img.complete && img.naturalWidth > 0 && img.naturalHeight > 0;
  }, null, { timeout: 20000 });

  const rendered = await page.evaluate(async streamId => {
    const img = document.querySelector('[data-slot="0"] img.screen-media');
    const info = document.querySelector('[data-slot="0"] [data-role="frame-info"]')?.textContent || '';
    const status = document.querySelector('#status')?.textContent || '';
    const stageText = document.querySelector('[data-slot="0"] [data-role="stage"]')?.textContent || '';
    const response = await fetch(img.src);
    const bytes = new Uint8Array(await response.arrayBuffer());
    let hash = 0x811c9dc5;
    for (const byte of bytes) {
      hash ^= byte;
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    const seq = Number(info.match(/seq (\d+)/)?.[1] || 0);
    const manifests = await (await fetch(`/api/streams/${streamId}/frames`)).json();
    const manifest = manifests.find(candidate => candidate.seq === seq);
    return {
      bytes: bytes.length,
      hash: hash >>> 0,
      expectedHash: manifest?.content_hash || 0,
      width: img.naturalWidth,
      height: img.naturalHeight,
      info,
      status,
      stageText,
    };
  }, streamId);

  expect(rendered.bytes).toBeGreaterThan(0);
  expect(rendered.width).toBeGreaterThan(0);
  expect(rendered.height).toBeGreaterThan(0);
  expect(rendered.expectedHash).toBeGreaterThan(0);
  expect(rendered.hash).toBe(rendered.expectedHash);
  expect(rendered.stageText).not.toContain('Unable to decrypt');
  expect(rendered.stageText).not.toContain('Frame failed reconstruction check');
  expect(rendered.status).not.toContain('frame content hash mismatch');
  expect(errors).toEqual([]);

  console.log(
    `PASS ${expectedDisplayName}: encrypted=${expectedEncrypted} ` +
      `rendered=${rendered.width}x${rendered.height} bytes=${rendered.bytes} hash=${rendered.hash} info=${rendered.info}`
  );
});
NODE

cat >"${PLAYWRIGHT_DIR}/dashboard-video.spec.js" <<'NODE'
const { test, expect } = require('@playwright/test');

async function waitForPaintedVideo(page, timeout) {
  await page.waitForFunction(() => {
    const tile = document.querySelector('[data-slot="0"]');
    const video = tile?.querySelector('video.screen-media');
    return Number(tile?.dataset.decodedFrames || 0) > 0 &&
      video && video.videoWidth > 0 && video.videoHeight > 0;
  }, null, { timeout });
}

test('dashboard decodes, paints, and reconnects H.264 video', async ({ page, browserName }) => {
  const controlAddr = process.env.GLACIALCAST_BROWSER_CONTROL_ADDR;
  const streamId = process.env.GLACIALCAST_BROWSER_STREAM_ID;
  const displayName = process.env.GLACIALCAST_BROWSER_DISPLAY_NAME;
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));

  await page.goto(`http://${controlAddr}/#stream=${encodeURIComponent(streamId)}`);
  const tile = page.locator('[data-slot="0"]');
  await expect(tile.locator('.tile-title strong')).toHaveText(displayName, { timeout: 15000 });
  await waitForPaintedVideo(page, 10000);

  const painted = await page.evaluate(() => {
    const video = document.querySelector('[data-slot="0"] video.screen-media');
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const context = canvas.getContext('2d', { willReadFrequently: true });
    context.drawImage(video, 0, 0);
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
    let min = 255;
    let max = 0;
    for (let index = 0; index < pixels.length; index += 64) {
      min = Math.min(min, pixels[index]);
      max = Math.max(max, pixels[index]);
    }
    return {
      width: video.videoWidth,
      height: video.videoHeight,
      variance: max - min,
    };
  });
  expect(painted.width).toBeGreaterThan(0);
  expect(painted.height).toBeGreaterThan(0);
  expect(painted.variance).toBeGreaterThan(8);

  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForPaintedVideo(page, 3000);
  expect(errors).toEqual([]);
  console.log(
    `PASS ${browserName}: painted=${painted.width}x${painted.height} ` +
      `variance=${painted.variance} and recovered after refresh within 3s`
  );
});
NODE

echo "building Glacialcast browser verifier binaries"
cargo build -p glacialcast-server -p glacialcast-client

echo "starting temporary Glacialcast server on ${CONTROL_ADDR} / ${INGEST_ADDR}"
./target/debug/glacialcast-server \
  --control-addr "${CONTROL_ADDR}" \
  --ingest-addr "${INGEST_ADDR}" \
  --data-dir "${DATA_DIR}" \
  --retention-bytes-per-stream 32MiB >"${SERVER_LOG}" 2>&1 &
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

wait_for_frame_metadata() {
  local display_name="$1"
  node - "${CONTROL_ADDR}" "${display_name}" "${CLIENT_TIMEOUT}" <<'NODE'
const [controlAddr, displayName, timeoutText] = process.argv.slice(2);
const timeoutMs = Number(timeoutText) * 1000;

async function fetchJson(path) {
  const res = await fetch(`http://${controlAddr}${path}`);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return await res.json();
}

const deadline = Date.now() + timeoutMs;
while (Date.now() < deadline) {
  const streams = await fetchJson('/api/streams');
  const stream = streams.find(candidate => candidate.display_name === displayName);
  if (stream?.stream_id) {
    const frames = await fetchJson(`/api/streams/${stream.stream_id}/frames`);
    if (frames.length > 0) {
      const frame = frames[frames.length - 1];
      console.log(JSON.stringify({
        streamId: stream.stream_id,
        seq: frame.seq,
        contentHash: frame.content_hash,
        encrypted: Boolean(frame.key_id),
      }));
      process.exit(0);
    }
  }
  await new Promise(resolve => setTimeout(resolve, 250));
}
throw new Error(`timed out waiting for frame from ${displayName}`);
NODE
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

  CLIENT_LOG="${CLIENT_LOG_DIR}/glacialcast-browser-render-${mode}.$$.log"
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

  echo "starting ${mode} browser-render client"
  ./target/debug/glacialcast-client "${client_args[@]}" >"${CLIENT_LOG}" 2>&1 &
  CLIENT_PID="$!"

  local metadata
  if ! metadata="$(wait_for_frame_metadata "${display_name}")"; then
    echo "FAIL: timed out waiting for ${mode} frame; client log: ${CLIENT_LOG}" >&2
    tail -n 80 "${CLIENT_LOG}" >&2 || true
    exit 1
  fi

  local stream_id content_hash encrypted
  stream_id="$(node -e "console.log(JSON.parse(process.argv[1]).streamId)" "${metadata}")"
  content_hash="$(node -e "console.log(JSON.parse(process.argv[1]).contentHash)" "${metadata}")"
  encrypted="$(node -e "console.log(JSON.parse(process.argv[1]).encrypted)" "${metadata}")"

  if [[ "${encrypted}" != "${expected_encrypted}" ]]; then
    echo "FAIL: ${mode} frame encrypted=${encrypted}, expected ${expected_encrypted}" >&2
    exit 1
  fi

  echo "verifying ${mode} frame in a real browser"
  (
    cd "${PLAYWRIGHT_DIR}"
    GLACIALCAST_BROWSER_CONTROL_ADDR="${CONTROL_ADDR}" \
      GLACIALCAST_BROWSER_STREAM_ID="${stream_id}" \
      GLACIALCAST_BROWSER_VIEWER_KEY="${viewer_key}" \
      GLACIALCAST_BROWSER_EXPECTED_ENCRYPTED="${expected_encrypted}" \
      GLACIALCAST_BROWSER_CONTENT_HASH="${content_hash}" \
      GLACIALCAST_BROWSER_DISPLAY_NAME="${display_name}" \
      npx playwright test dashboard-render.spec.js --reporter=line --project=chrome
  )
}

run_case "clear" "Browser Render Clear" "browser-render-clear" "" "false"
run_case "encrypted" "Browser Render Encrypted" "browser-render-encrypted" "$(random_viewer_key)" "true"

if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
  kill "${CLIENT_PID}" 2>/dev/null || true
  wait "${CLIENT_PID}" 2>/dev/null || true
fi

CLIENT_LOG="${CLIENT_LOG_DIR}/glacialcast-browser-render-video.$$.log"
echo "starting generated H.264 browser-render client"
./target/debug/glacialcast-client \
  --config /tmp/glacialcast-missing-client.toml \
  --ingest-addr "${INGEST_ADDR}" \
  --client-id browser-render-video \
  --display-name "Browser Render Video" \
  --capture test-video \
  --fps 5 \
  --no-viewer-key >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

VIDEO_STREAM_ID=""
deadline=$((SECONDS + CLIENT_TIMEOUT))
while (( SECONDS < deadline )); do
  VIDEO_STREAM_ID="$(
    curl -fsS "http://${CONTROL_ADDR}/api/streams" 2>/dev/null | node -e '
      let raw = "";
      process.stdin.on("data", chunk => raw += chunk);
      process.stdin.on("end", () => {
        const stream = JSON.parse(raw).find(candidate =>
          candidate.display_name === "Browser Render Video" && candidate.last_frame_seq > 0);
        if (stream) process.stdout.write(stream.stream_id);
      });
    ' 2>/dev/null
  )"
  [[ -n "${VIDEO_STREAM_ID}" ]] && break
  sleep 0.25
done

if [[ -z "${VIDEO_STREAM_ID}" ]]; then
  echo "FAIL: generated H.264 stream did not become ready; client log: ${CLIENT_LOG}" >&2
  tail -n 100 "${CLIENT_LOG}" >&2 || true
  echo "server log: ${SERVER_LOG}" >&2
  tail -n 100 "${SERVER_LOG}" >&2 || true
  exit 1
fi

for browser in chrome firefox; do
  echo "verifying decoded H.264 video in ${browser}"
  (
    cd "${PLAYWRIGHT_DIR}"
    GLACIALCAST_BROWSER_CONTROL_ADDR="${CONTROL_ADDR}" \
      GLACIALCAST_BROWSER_STREAM_ID="${VIDEO_STREAM_ID}" \
      GLACIALCAST_BROWSER_DISPLAY_NAME="Browser Render Video" \
      npx playwright test dashboard-video.spec.js --reporter=line --project="${browser}"
  )
done

echo "PASS: image integrity and Chromium/Firefox H.264 decode, paint, and refresh recovery verified"
