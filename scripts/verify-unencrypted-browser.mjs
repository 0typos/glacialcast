#!/usr/bin/env node

// Drives a browser against a stream published with --no-encryption.
//
// The encrypted gates all begin by typing a viewing key, so none of them can
// reach this path: the whole point of it is that there is no key to type. What
// is checked here is that the absence is handled deliberately rather than by
// accident -- the stream unlocks itself, the player skips Encrypted Media
// Extensions instead of failing at them, the cursor overlay decodes batches
// that were never sealed, and the viewer says out loud that none of it is
// encrypted.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const [origin, streamId, browserName = 'firefox'] = process.argv.slice(2);
if (!origin || !streamId || !['firefox', 'chromium'].includes(browserName)) {
  console.error(
    'usage: verify-unencrypted-browser.mjs ORIGIN STREAM_ID [firefox|chromium]',
  );
  process.exit(2);
}

const READY_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 500;

const browserType = browserName === 'firefox' ? firefox : chromium;
const executablePath = browserName === 'firefox'
  ? process.env.GLACIALCAST_FIREFOX_EXECUTABLE
  : process.env.GLACIALCAST_CHROMIUM_EXECUTABLE;

console.log(`launching ${browserName} for ${origin}/watch`);
const browser = await browserType.launch({
  headless: true,
  executablePath: executablePath || undefined,
  // No EME preferences here on purpose. A stream published in the clear must
  // play in a browser that has no ClearKey at all, because the reason this mode
  // exists is iOS, where it never will.
  firefoxUserPrefs: browserName === 'firefox' ? { 'media.autoplay.default': 0 } : undefined,
});

const failures = [];
const check = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else failures.push(message);
};

async function until(page, describe) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = null;
  while (Date.now() < deadline) {
    last = await page.evaluate(describe);
    if (last?.ready) return last;
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return last;
}

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
  page.on('console', message => {
    if (
      message.type() === 'error'
      && !message.text().includes("frame-ancestors' is ignored")
    ) {
      errors.push(`console: ${message.text()}`);
    }
  });

  await page.goto(`${origin}/watch`, { waitUntil: 'domcontentloaded' });

  // Nothing is typed anywhere below. The stream has to arrive on screen on its
  // own or this gate fails.
  const watching = await until(page, () => {
    const watch = globalThis.GlacialCastWatch;
    if (!watch) return { ready: false, reason: 'the watch page has not loaded' };
    const tiles = watch.tiles();
    const playing = tiles.find(tile => tile.metrics?.appendedMedia > 0);
    return {
      ready: Boolean(playing),
      tiles,
      openStreams: watch.openStreams(),
      metrics: playing?.metrics ?? null,
    };
  });
  check(watching?.ready, `a tile played with no key entered (${JSON.stringify(watching?.tiles)})`);
  check(
    watching?.openStreams?.includes(streamId),
    `${streamId} unlocked without a key (open: ${JSON.stringify(watching?.openStreams)})`,
  );
  check(
    watching?.metrics?.encrypted === false,
    `the player reports the stream as unencrypted (encrypted=${watching?.metrics?.encrypted})`,
  );
  check(
    watching?.metrics?.cursorEvents > 0,
    `cursor events decoded from unsealed batches (${watching?.metrics?.cursorEvents})`,
  );

  // Appending is not decoding. Only readyState says a frame came out.
  const decoded = await until(page, () => {
    const video = document.querySelector('[data-role="video"]');
    return {
      ready: Boolean(video) && video.readyState >= 2,
      readyState: video?.readyState ?? null,
      width: video?.videoWidth ?? 0,
      height: video?.videoHeight ?? 0,
    };
  });
  check(
    decoded?.ready,
    `decoded a ${decoded?.width}x${decoded?.height} frame (readyState ${decoded?.readyState})`,
  );

  const hint = await page.evaluate(
    () => document.querySelector('#stream-list .stream-hint')?.textContent ?? '',
  );
  check(hint.includes('not encrypted'), `the stream list says so: "${hint}"`);

  // The deep-link page has its own start path and must also need no key.
  const solo = await browser.newPage();
  solo.on('pageerror', error => errors.push(`deep-link pageerror: ${error.message}`));
  await solo.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  const soloState = await until(solo, () => {
    const player = globalThis.GlacialCastActivePlayer;
    const metrics = player?.metrics() ?? null;
    return {
      ready: Boolean(metrics && metrics.appendedMedia > 0),
      metrics,
      formHidden: document.querySelector('[data-role="unlock-form"]')?.hidden ?? null,
    };
  });
  check(
    soloState?.ready,
    `the deep-link page started itself (${JSON.stringify(soloState?.metrics)})`,
  );
  check(soloState?.formHidden === true, 'the deep-link page hid the key field');

  check(errors.length === 0, `no page errors (${JSON.stringify(errors)})`);

  // The viewer-side fence. A relay that strips the encryption from a stream
  // someone holds a key for must not be able to feed them whatever it likes
  // under that key's reputation, so a player started with a key refuses an
  // epoch published in the clear rather than playing it. On its own page,
  // because provoking it logs the refusal the checks above forbid.
  const fence = await browser.newPage();
  await fence.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  const refusal = await fence.evaluate(async id => {
    // A player of its own, so the descriptors the auto-start already loaded
    // are not reused: the refusal happens while loading them.
    globalThis.GlacialCastActivePlayer.destroy();
    const player = globalThis.GlacialCastPlayer.createPlayer(
      document.querySelector('[data-role="player"]'),
      { streamId: id },
    );
    const random = crypto.getRandomValues(new Uint8Array(32));
    const key = btoa(String.fromCharCode(...random))
      .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const keyRejected = await globalThis.GlacialCastPlayer.verifyViewerKey(id, random);
    try {
      await player.start(key);
      return { refused: false, keyRejected };
    } catch (error) {
      return { refused: true, keyRejected, message: error.message };
    }
  }, streamId);
  check(
    refusal.refused && /without encryption/.test(refusal.message ?? ''),
    `a player holding a key refuses a stream served in the clear (${refusal.message ?? 'it played'})`,
  );
  check(
    refusal.keyRejected === false,
    'no key is reported as opening a stream published in the clear',
  );

  // What an iPhone will decide, without an iPhone.
  //
  // No engine a gate can launch exposes ManagedMediaSource, so the branch that
  // uses it cannot be run here -- attaching one and playing through it is
  // verified on a real device or not at all. What can be checked is the
  // decision in front of it, which is where a mistake would be worst: refusing
  // the whole page on a device that can in fact play these streams. So the
  // globals are made to look like an iPhone and the platform gate is asked.
  const asIphone = await fence.evaluate(() => {
    const realMediaSource = globalThis.MediaSource;
    delete globalThis.MediaSource;
    globalThis.ManagedMediaSource = class {};
    try {
      return {
        encrypted: globalThis.GlacialCastPlayer.platformProblem({ encrypted: true }),
        clear: globalThis.GlacialCastPlayer.platformProblem({ encrypted: false }),
      };
    } finally {
      globalThis.MediaSource = realMediaSource;
      delete globalThis.ManagedMediaSource;
    }
  });
  check(
    asIphone.clear === null,
    `an iPhone is not refused a stream published in the clear (${asIphone.clear})`,
  );
  check(
    typeof asIphone.encrypted === 'string' && /ClearKey/.test(asIphone.encrypted),
    `an iPhone is told why an encrypted stream cannot play (${asIphone.encrypted})`,
  );
} finally {
  await browser.close();
}

if (failures.length > 0) {
  console.error(`FAIL ${browserName}:`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`PASS ${browserName}: an unencrypted stream played with no key and no EME`);
