#!/usr/bin/env node
// Proves the viewer asks for a key at most once.
//
// Three properties, in the order a real viewer meets them:
//
//   1. An invitation link unlocks and plays with nothing typed, and the key does
//      not stay in the address bar afterwards.
//   2. A reload with no fragment is still unlocked, because the key is remembered
//      on this browser rather than for the tab.
//   3. "Forget keys" really forgets: a reload after it asks again.
//
// A tile is only counted as playing once its video has decoded a frame, so a page
// that unlocks and then shows a black tile fails here rather than passing.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const playwright = require(playwrightModule);

const origin = process.env.GLACIALCAST_VIEWER_ORIGIN;
const phrase = process.env.GLACIALCAST_VIEWER_PHRASE;
const browserName = process.env.GLACIALCAST_VERIFY_BROWSER || 'firefox';
const readyTimeoutMs = Number(process.env.GLACIALCAST_VIEWER_READY_MS || 60_000);
// Long enough to cover one periodic live reconcile, which is where the fault this
// gate pins actually happens.
const settleMs = Number(process.env.GLACIALCAST_VIEWER_SETTLE_MS || 20_000);

if (!origin || !phrase) {
  console.error('set GLACIALCAST_VIEWER_ORIGIN and GLACIALCAST_VIEWER_PHRASE');
  process.exit(2);
}

const browserType = playwright[browserName];
if (!browserType) {
  console.error(`unknown browser ${browserName}`);
  process.exit(2);
}

function fail(message) {
  console.error(`FAIL ${message}`);
  process.exitCode = 1;
  return false;
}

/** Waits until at least one tile has actually decoded a frame. */
async function waitForPlayingTile(page, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const playing = await page.evaluate(() => [...document.querySelectorAll('video')]
      .filter(video => video.readyState >= 2 && video.videoWidth > 0).length);
    if (playing > 0) return playing;
    if (Date.now() > deadline) return 0;
    await page.waitForTimeout(500);
  }
}

async function unlockedStreamCount(page) {
  return page.evaluate(() => document.querySelectorAll('#stream-list li').length);
}

const browser = await browserType.launch();
// One context for the whole run: local storage has to survive a reload the way it
// does for a real viewer, so a fresh context per step would prove nothing.
const context = await browser.newContext();
const page = await context.newPage();

// Both channels matter, and for different reasons. An uncaught throw arrives as a
// pageerror; a throw the player caught and reported arrives only as a
// console.error, and that is the one that painted an internal message over a
// black tile. Watching pageerror alone let the original fault pass.
const pageErrors = [];
const consoleErrors = [];
page.on('pageerror', error => pageErrors.push(error.message));
page.on('console', message => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});

/** Content Security Policy notices are emitted by the page itself, not by a fault. */
function significant(messages) {
  return messages.filter(text => !/Content.Security.Policy|frame-ancestors/i.test(text));
}

/**
 * Tiles the player has marked as failed, with whatever it put on them.
 *
 * A tile can hold a decoded frame and still be in this state -- the fault that
 * prompted this gate happened after the first frame had been appended, so asking
 * only whether something is playing is not enough.
 */
async function failedTiles(page) {
  return page.evaluate(() => [...document.querySelectorAll('.tile.failed')].map(tile => {
    const stage = tile.querySelector('[data-role="stage-message"]')?.textContent?.trim();
    const status = tile.querySelector('[data-role="status"]')?.textContent?.trim();
    const title = tile.querySelector('.tile-title')?.textContent?.trim() || 'tile';
    return `${title}: ${stage || status || 'marked failed with no message'}`;
  }));
}

let ok = true;
try {
  // 1. The invitation link, with nothing typed.
  await page.goto(`${origin}/#k=${encodeURIComponent(phrase)}`, {
    waitUntil: 'domcontentloaded',
  });
  const playing = await waitForPlayingTile(page, readyTimeoutMs);
  if (playing === 0) {
    ok = fail('an invitation link did not reach a playing tile');
  } else {
    console.log(`invitation link played ${playing} tile(s) with nothing typed`);
  }

  // The fault this gate exists for happens while reconciling the retained
  // history, which is after the first frame is already on screen. Checking for
  // errors as soon as something plays would miss it, so wait for a reconcile
  // pass to have run.
  await page.waitForTimeout(settleMs);

  const failed = await failedTiles(page);
  if (failed.length > 0) {
    ok = fail(`a tile is showing a failure while playing: ${failed.join(' | ')}`);
  } else {
    console.log('no tile reported a failure while reconciling retained history');
  }

  const unlocked = await unlockedStreamCount(page);
  if (unlocked === 0) ok = fail('the invitation link unlocked no streams');

  if (page.url().includes('#k=') || page.url().includes(phrase)) {
    ok = fail(`the key is still in the address bar: ${page.url()}`);
  } else {
    console.log('the key was removed from the address bar');
  }

  // 2. A reload with no fragment must not ask again.
  await page.goto(origin, { waitUntil: 'domcontentloaded' });
  const rememberedPlaying = await waitForPlayingTile(page, readyTimeoutMs);
  if (rememberedPlaying === 0) {
    ok = fail('a reload without the invitation link did not play; the key was not remembered');
  } else {
    console.log(`a plain reload played ${rememberedPlaying} tile(s) with nothing typed`);
  }

  // 3. Forgetting has to actually forget.
  await page.click('#forget-all');
  await page.goto(origin, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(3_000);
  const afterForget = await unlockedStreamCount(page);
  if (afterForget !== 0) {
    ok = fail(`${afterForget} stream(s) stayed unlocked after Forget keys`);
  } else {
    console.log('Forget keys cleared the remembered key');
  }

  if (pageErrors.length > 0) {
    ok = fail(`uncaught page errors: ${pageErrors.join(' | ')}`);
  }
  // The reported fault only ever showed up here: the player caught its own throw
  // and reported it, so nothing reached pageerror.
  const reported = significant(consoleErrors);
  if (reported.length > 0) {
    ok = fail(`the viewer reported errors: ${reported.join(' | ')}`);
  }
} finally {
  await context.close();
  await browser.close();
}

if (ok) console.log(`PASS viewer onboarding (${browserName}): one key interaction, and none after`);
