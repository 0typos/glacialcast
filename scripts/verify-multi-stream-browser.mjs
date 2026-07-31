#!/usr/bin/env node
// Drives the multi-stream viewer: unlocks with one viewing key, fills a
// four-tile layout, full-screens one tile, and requires every tile to keep
// decoding independently.
//
// This is the regression test for the player-factory refactor. A singleton
// player passes every single-stream gate and still fails here.
//
// usage: verify-multi-stream-browser.mjs ORIGIN VIEWER_KEY STREAM_ID... [--browser=firefox]

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const args = process.argv.slice(2);
const browserName = (args.find(arg => arg.startsWith('--browser='))?.split('=')[1]) || 'firefox';
const positional = args.filter(arg => !arg.startsWith('--'));
const [origin, viewerKey, ...streamIds] = positional;
if (!origin || !viewerKey || streamIds.length === 0) {
  console.error(
    'usage: verify-multi-stream-browser.mjs ORIGIN VIEWER_KEY STREAM_ID... [--browser=firefox]',
  );
  process.exit(2);
}
if (!['firefox', 'chromium'].includes(browserName)) {
  console.error(`unsupported browser ${browserName}`);
  process.exit(2);
}

const tileCount = Math.min(4, streamIds.length);
const browserType = browserName === 'firefox' ? firefox : chromium;
const executablePath = browserName === 'firefox'
  ? process.env.GLACIALCAST_FIREFOX_EXECUTABLE
  : process.env.GLACIALCAST_CHROMIUM_EXECUTABLE;

const browser = await browserType.launch({
  headless: true,
  executablePath: executablePath || undefined,
  firefoxUserPrefs: browserName === 'firefox' ? {
    'media.autoplay.default': 0,
    'media.eme.enabled': true,
    'media.clearkey.enabled': true,
    'full-screen-api.allow-trusted-requests-only': false,
  } : undefined,
});

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (
      message.type() === 'error'
      && !message.text().includes("frame-ancestors' is ignored")
    ) {
      errors.push(message.text());
    }
  });

  await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded' });

  // Before a key opens anything there is one thing to do, and the page shows
  // only that. It used to open on a grid of empty tiles inviting a drop the
  // viewer had nothing to make.
  // Which page this is depends on the stream list, so wait for that to have
  // been decided rather than reading the markup's starting point back.
  await page.waitForFunction(
    () => !document.body.classList.contains('deciding'),
    null,
    { timeout: 30_000 },
  );
  const firstRun = await page.evaluate(() => ({
    asking: document.body.classList.contains('empty'),
    unlockVisible: Boolean(document.querySelector('#welcome #unlock')),
    tilesVisible: [...document.querySelectorAll('.tile')]
      .filter(tile => tile.checkVisibility?.() ?? tile.offsetParent !== null).length,
  }));
  if (!firstRun.asking || !firstRun.unlockVisible) {
    throw new Error('the first run did not open on the key prompt');
  }
  if (firstRun.tilesVisible !== 0) {
    throw new Error(`the first run showed ${firstRun.tilesVisible} tile(s) before anything unlocked`);
  }
  console.log('the first run opens on the key prompt, with no empty tiles');

  // A wrong key has to be reported as wrong. Silently unlocking nothing, or
  // unlocking tiles that then fail to decode, is the failure this guards.
  await page.locator('#viewing-key').fill('able-about-acid-acorn-acre-actor-adapt');
  await page.locator('#unlock button[type="submit"]').click();
  await page.locator('#unlock-error').waitFor({ state: 'visible', timeout: 30_000 });
  if (await page.evaluate(() => globalThis.GlacialCastWatch.unlockedStreams().length) !== 0) {
    throw new Error('a wrong viewing key unlocked a stream');
  }

  // One key, entered once, must unlock every stream the publisher casts.
  await page.locator('#viewing-key').fill(viewerKey);
  await page.locator('#unlock button[type="submit"]').click();
  await page.waitForFunction(
    expected => globalThis.GlacialCastWatch.unlockedStreams().length >= expected,
    tileCount,
    { timeout: 30_000 },
  );
  console.log(`one viewing key unlocked ${tileCount} streams`);

  const layout = tileCount > 2 ? 4 : tileCount;
  await page.locator(`[data-layout="${layout}"]`).click();

  for (const streamId of streamIds.slice(0, tileCount)) {
    await page.locator(`#stream-list li[data-stream-id="${streamId}"] button`).first().click();
  }

  // Every tile must reach live media on its own. A shared singleton would
  // leave all but one tile empty here.
  await page.waitForFunction(expected => {
    const tiles = globalThis.GlacialCastWatch.tiles()
      .filter(tile => tile.streamId && tile.metrics?.appendedMedia > 0);
    return tiles.length >= expected;
  }, tileCount, { timeout: 90_000 });
  console.log(`${tileCount} tiles decoded encrypted media concurrently`);

  const before = await page.evaluate(() => globalThis.GlacialCastWatch.tiles());
  const distinct = new Set(before.map(tile => tile.streamId).filter(Boolean));
  if (distinct.size !== tileCount) {
    throw new Error(`tiles are not showing distinct streams: ${JSON.stringify(before)}`);
  }

  // Full-screening one tile must not disturb the others.
  await page.locator('.tile [data-action="fullscreen"]').first().click();
  await page.waitForTimeout(1_000);
  const fullscreened = await page.evaluate(() => Boolean(document.fullscreenElement));
  if (!fullscreened) throw new Error('the tile did not enter full screen');
  await page.evaluate(() => document.exitFullscreen());
  console.log('full-screened one tile independently');

  // Only the tiles that were showing a stream are compared; a four-up layout
  // holding three streams legitimately leaves one tile empty.
  await page.waitForFunction(previous => {
    const tiles = globalThis.GlacialCastWatch.tiles();
    return previous.every((was, index) => {
      if (!was.streamId) return true;
      const tile = tiles[index];
      return tile?.streamId === was.streamId
        && tile.metrics.appendedMedia >= was.metrics.appendedMedia;
    });
  }, before, { timeout: 60_000 });

  // Shrinking the layout must destroy the dropped players, not orphan them.
  await page.locator('[data-layout="1"]').click();
  await page.waitForTimeout(500);
  const afterShrink = await page.evaluate(() => globalThis.GlacialCastWatch.tiles());
  if (afterShrink.length !== 1) {
    throw new Error(`expected one tile after shrinking, saw ${afterShrink.length}`);
  }
  console.log('layout shrink released the other tiles');

  // Collapsing must survive a reload, and must not disturb what is playing:
  // the panel is a control surface, not part of the stream.
  const playingBefore = await page.evaluate(
    () => globalThis.GlacialCastWatch.tiles()[0]?.metrics?.appendedMedia ?? 0,
  );
  await page.locator('#sidebar-toggle').click();
  await page.waitForFunction(() => globalThis.GlacialCastWatch.sidebarCollapsed());
  await page.waitForFunction(
    was => (globalThis.GlacialCastWatch.tiles()[0]?.metrics?.appendedMedia ?? 0) > was,
    playingBefore,
    { timeout: 60_000 },
  );

  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => globalThis.GlacialCastWatch?.sidebarCollapsed?.() === true, null, {
    timeout: 15_000,
  });

  // The key was entered once. A reload must not ask for it again.
  await page.waitForFunction(
    expected => globalThis.GlacialCastWatch.unlockedStreams().length >= expected,
    tileCount,
    { timeout: 15_000 },
  );
  console.log('the viewing key survived a reload without being entered again');
  await page.locator('#sidebar-toggle').click();
  await page.waitForFunction(() => globalThis.GlacialCastWatch.sidebarCollapsed() === false);
  console.log('sidebar collapsed, stayed collapsed across a reload, and reopened');

  // Hiding the list is something done while watching, so it is worth a key as
  // well as a trip to the header.
  await page.locator('.tile').first().click();
  await page.keyboard.press('[');
  await page.waitForFunction(() => globalThis.GlacialCastWatch.sidebarCollapsed() === true, null, {
    timeout: 5_000,
  });
  await page.keyboard.press('[');
  await page.waitForFunction(() => globalThis.GlacialCastWatch.sidebarCollapsed() === false, null, {
    timeout: 5_000,
  });

  // The same key inside the field is a character, not a command: a viewer
  // typing a key must not have the panel toggling under them.
  await page.locator('#viewing-key').fill('');
  await page.locator('#viewing-key').press('[');
  if (await page.evaluate(() => globalThis.GlacialCastWatch.sidebarCollapsed())) {
    throw new Error('typing in the key field collapsed the panel');
  }
  console.log('the shortcut toggles the panel, and is inert while typing a key');

  if (errors.length > 0) {
    throw new Error(`browser reported errors:\n${errors.join('\n')}`);
  }

  const summary = before
    .filter(tile => tile.streamId)
    .map(tile => `${tile.streamId.slice(0, 8)}=${tile.metrics.appendedMedia}`)
    .join(' ');
  console.log(`PASS ${browserName} multi-stream: ${tileCount} tiles [${summary}]`);
} finally {
  await browser.close();
}
