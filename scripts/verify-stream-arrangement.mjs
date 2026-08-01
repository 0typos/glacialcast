#!/usr/bin/env node

// Drives the viewer's stream arrangement: numbering, parking, hiding, naming.
//
// All four are remembered in this browser and nowhere else, so the thing worth
// checking is not that a click changes the page -- it is that the change is
// still there after a reload, and that a numbered stream comes back in the tile
// its number names rather than wherever the grid happens to put it.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const [origin, viewerKey, browserName = 'firefox'] = process.argv.slice(2);
if (!origin || !viewerKey || !['firefox', 'chromium'].includes(browserName)) {
  console.error('usage: verify-stream-arrangement.mjs ORIGIN VIEWER_KEY [firefox|chromium]');
  process.exit(2);
}

const WAIT_MS = 45_000;
const browserType = browserName === 'firefox' ? firefox : chromium;
const executablePath = browserName === 'firefox'
  ? process.env.GLACIALCAST_FIREFOX_EXECUTABLE
  : process.env.GLACIALCAST_CHROMIUM_EXECUTABLE;

const failures = [];
const check = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else failures.push(message);
};

const browser = await browserType.launch({
  headless: true,
  executablePath: executablePath || undefined,
  firefoxUserPrefs: browserName === 'firefox' ? {
    'media.autoplay.default': 0,
    'media.eme.enabled': true,
    'media.clearkey.enabled': true,
  } : undefined,
});

// One context throughout: the whole feature is "this browser remembers", so a
// fresh context per step would prove nothing.
const context = await browser.newContext();
const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));

const tiles = () => page.evaluate(() => globalThis.GlacialCastWatch.tiles());
const placements = () => page.evaluate(() => globalThis.GlacialCastWatch.placements());
const rowIds = group => page.evaluate(
  selector => [...document.querySelectorAll(selector)].map(row => row.dataset.streamId),
  `.stream-group-${group} li[data-stream-id]`,
);

async function reload() {
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForFunction(
    () => globalThis.GlacialCastWatch?.unlockedStreams().length > 0,
    null,
    { timeout: WAIT_MS },
  );
}

try {
  await page.goto(`${origin}/watch`, { waitUntil: 'domcontentloaded' });
  await page.locator('#viewing-key').fill(viewerKey);
  await page.locator('#unlock button[type="submit"]').click();
  await page.waitForFunction(
    () => globalThis.GlacialCastWatch.unlockedStreams().length >= 3,
    null,
    { timeout: WAIT_MS },
  );
  await page.waitForFunction(
    () => globalThis.GlacialCastWatch.tiles().filter(tile => tile.streamId).length >= 3,
    null,
    { timeout: WAIT_MS },
  );

  // Newly seen streams take the free tiles, which is what the viewer did before
  // any of this existed. Numbering them is what makes it survive a reload.
  const initial = await tiles();
  const numbered = await placements();
  check(
    initial.slice(0, 3).every((tile, index) => numbered[tile.streamId]?.slot === index + 1),
    `each stream took the number of its tile (${JSON.stringify(
      initial.map(tile => tile.streamId && numbered[tile.streamId]?.slot),
    )})`,
  );

  // (3) The arrangement has to come back on its own, in the same tiles.
  await reload();
  await page.waitForFunction(
    expected => {
      const restored = globalThis.GlacialCastWatch.tiles().map(tile => tile.streamId);
      return expected.every((streamId, index) => !streamId || restored[index] === streamId);
    },
    initial.map(tile => tile.streamId),
    { timeout: WAIT_MS },
  );
  console.log('  ok   every stream came back in its own tile after a reload');

  const [first, second, third] = initial.map(tile => tile.streamId);

  // (4) A name this viewer typed, over whatever the publisher pushed.
  const published = await page.evaluate(
    streamId => document.querySelector(`li[data-stream-id="${streamId}"] .stream-name`).textContent,
    first,
  );
  await page.locator(`li[data-stream-id="${first}"] .stream-action`).first().click();
  await page.locator(`li[data-stream-id="${first}"] .stream-rename input`).fill('Kitchen Door');
  await page.locator(`li[data-stream-id="${first}"] .stream-rename button`).click();
  await page.waitForFunction(
    streamId => globalThis.GlacialCastWatch.titleOf(streamId) === 'Kitchen Door',
    first,
    { timeout: WAIT_MS },
  );
  const renamedTile = (await tiles()).find(tile => tile.streamId === first);
  check(renamedTile !== undefined, 'renaming did not disturb the tile it was playing in');
  const subtitle = await page.evaluate(
    streamId => document.querySelector(
      `li[data-stream-id="${streamId}"] .stream-published`,
    )?.textContent ?? null,
    first,
  );
  check(
    subtitle === published,
    `the publisher's own name is still shown beneath it (${subtitle} vs ${published})`,
  );

  // (2) Parking: off screen, still listed, ready to be put back.
  await page.locator(`li[data-stream-id="${second}"] .stream-action[aria-label^="Take off"]`).click();
  await page.waitForFunction(
    streamId => !globalThis.GlacialCastWatch.tiles().some(tile => tile.streamId === streamId),
    second,
    { timeout: WAIT_MS },
  );
  check((await rowIds('available')).includes(second), 'a parked stream moved to the available list');
  check(
    (await placements())[second]?.slot === null,
    'a parked stream gave up its number',
  );

  // (1) Hiding: out of the list entirely, and reversible.
  await page.locator(`li[data-stream-id="${third}"] .stream-action[aria-label^="Hide"]`).click();
  await page.waitForFunction(
    streamId => globalThis.GlacialCastWatch.placements()[streamId]?.hidden === true,
    third,
    { timeout: WAIT_MS },
  );
  check(
    !(await rowIds('screen')).includes(third) && !(await rowIds('available')).includes(third),
    'a hidden stream left both visible lists',
  );
  check((await rowIds('hidden')).includes(third), 'a hidden stream is still reachable to undo');
  check(
    !(await tiles()).some(tile => tile.streamId === third),
    'hiding a stream stopped it decoding',
  );

  // Everything above, still true after a reload. This is the whole point.
  await reload();
  // Restoring the grid happens after the keys have opened anything, so waiting
  // on the unlock alone would read the tiles before they had been filled and
  // call an empty grid a pass.
  await page.waitForFunction(
    streamId => globalThis.GlacialCastWatch.tiles().some(tile => tile.streamId === streamId),
    first,
    { timeout: WAIT_MS },
  );
  const remembered = await placements();
  check(
    await page.evaluate(streamId => globalThis.GlacialCastWatch.titleOf(streamId), first) === 'Kitchen Door',
    'the name survived a reload',
  );
  check(remembered[second]?.slot === null && remembered[second]?.hidden === false,
    'the parked stream came back parked, not on screen');
  check(remembered[third]?.hidden === true, 'the hidden stream came back hidden');
  check(
    !(await tiles()).some(tile => tile.streamId === second || tile.streamId === third),
    'neither the parked nor the hidden stream started decoding again',
  );
  check(
    (await tiles()).some(tile => tile.streamId === first),
    'the stream left on screen is still on screen',
  );

  // Putting one back has to work, or hiding is a one-way door.
  await page.locator('.stream-group-hidden summary').click();
  await page.locator(`li[data-stream-id="${third}"] .stream-pick`).click();
  await page.waitForFunction(
    streamId => globalThis.GlacialCastWatch.placements()[streamId]?.hidden === false,
    third,
    { timeout: WAIT_MS },
  );
  check((await rowIds('available')).includes(third), 'an unhidden stream returned to the list');
  await page.locator(`li[data-stream-id="${third}"] .stream-pick`).click();
  await page.waitForFunction(
    streamId => globalThis.GlacialCastWatch.tiles().some(tile => tile.streamId === streamId),
    third,
    { timeout: WAIT_MS },
  );
  check(true, 'and went back on screen from there');

  check(errors.length === 0, `no page errors (${JSON.stringify(errors)})`);
} finally {
  await browser.close();
}

if (failures.length > 0) {
  console.error(`FAIL ${browserName}:`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`PASS ${browserName}: the arrangement is remembered across reloads`);
