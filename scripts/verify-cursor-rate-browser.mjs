#!/usr/bin/env node
// Measures how many cursor updates actually reach a viewer while the pointer
// moves, and how evenly they are painted.
//
// Counting objects at the relay is not enough: a cursor object is a batch, so
// a publisher that batches badly still produces objects at a healthy rate
// while carrying almost no motion. This decrypts in a real browser and counts
// events, then watches the overlay's own selected sample advance, which is the
// number a person actually sees.
//
// usage: verify-cursor-rate-browser.mjs ORIGIN STREAM_ID VIEWER_KEY SECONDS

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { firefox } = require(playwrightModule);

const [origin, streamId, viewerKey, secondsText] = process.argv.slice(2);
if (!origin || !streamId || !viewerKey) {
  console.error('usage: verify-cursor-rate-browser.mjs ORIGIN STREAM_ID VIEWER_KEY SECONDS');
  process.exit(2);
}
const seconds = Number(secondsText || 20);

const browser = await firefox.launch({
  headless: true,
  executablePath: process.env.GLACIALCAST_FIREFOX_EXECUTABLE || undefined,
  firefoxUserPrefs: {
    'media.autoplay.default': 0,
    'media.eme.enabled': true,
    'media.clearkey.enabled': true,
  },
});

try {
  const page = await browser.newPage();
  await page.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-role="viewer-key"]').fill(viewerKey);
  await page.locator('[data-role="unlock-form"] button[type="submit"]').click();
  await page.waitForFunction(
    () => (globalThis.GlacialCastActivePlayer?.metrics()?.cursorEvents ?? 0) > 0,
    null,
    { timeout: 60_000 },
  );

  // Retained history backfills in one burst and would otherwise be counted as
  // live throughput. Wait for the count to stop jumping before measuring.
  let previous = -1;
  let steady = 0;
  for (let i = 0; i < 60 && steady < 3; i += 1) {
    await page.waitForTimeout(500);
    const now = await page.evaluate(
      () => globalThis.GlacialCastActivePlayer.metrics().cursorEvents,
    );
    steady = now === previous ? steady + 1 : 0;
    previous = now;
  }

  // Sample the overlay's own selected timestamp on every animation frame. A
  // change means the viewer moved the pointer on screen; the gaps between
  // changes are what "smooth" actually means.
  const result = await page.evaluate(async ms => {
    const player = globalThis.GlacialCastActivePlayer;
    const startEvents = player.metrics().cursorEvents;
    const startedAt = performance.now();
    const gaps = [];
    // Where in the window each gap fell, so a stall at start-up is
    // distinguishable from one that happens in steady state.
    const gapOffsets = [];
    let lastShown = null;
    let lastChangeAt = startedAt;
    // Separates "the overlay had nothing new to show" from "the page could not
    // run": if the animation callback itself stalls, the stall is main-thread
    // work in the viewer, not missing cursor data.
    let maxFrameDelta = 0;
    let lastFrameAt = startedAt;
    // How far the play-out clock trails the newest sample it holds. A clock
    // that falls behind and cannot catch up looks exactly like a stall.
    let maxLag = 0;
    let minLag = Number.POSITIVE_INFINITY;

    await new Promise(resolve => {
      const step = () => {
        const frameNow = performance.now();
        maxFrameDelta = Math.max(maxFrameDelta, frameNow - lastFrameAt);
        lastFrameAt = frameNow;
        const cursor = player.metrics().cursor;
        if (cursor.shownTimestamp !== null && cursor.newestTimestamp !== null) {
          const lag = cursor.newestTimestamp - cursor.shownTimestamp;
          maxLag = Math.max(maxLag, lag);
          minLag = Math.min(minLag, lag);
        }
        const shown = cursor.shownTimestamp;
        if (shown !== null && shown !== lastShown) {
          const now = performance.now();
          if (lastShown !== null) {
            gaps.push(now - lastChangeAt);
            gapOffsets.push(now - startedAt);
          }
          lastShown = shown;
          lastChangeAt = now;
        }
        if (performance.now() - startedAt < ms) requestAnimationFrame(step);
        else resolve();
      };
      requestAnimationFrame(step);
    });

    const elapsed = (performance.now() - startedAt) / 1000;
    return {
      elapsed,
      events: player.metrics().cursorEvents - startEvents,
      gaps,
      gapOffsets,
      maxFrameDelta,
      maxLag,
      minLag: Number.isFinite(minLag) ? minLag : null,
    };
  }, seconds * 1000);

  const eventsPerSecond = result.events / result.elapsed;
  const gaps = result.gaps.slice().sort((left, right) => left - right);
  let worstIndex = 0;
  for (let i = 1; i < result.gaps.length; i += 1) {
    if (result.gaps[i] > result.gaps[worstIndex]) worstIndex = i;
  }
  const quantile = q => (gaps.length === 0 ? null : gaps[Math.min(gaps.length - 1, Math.floor(q * gaps.length))]);
  const paintedPerSecond = gaps.length / result.elapsed;

  console.log(JSON.stringify({
    elapsed_seconds: Number(result.elapsed.toFixed(2)),
    delivered_events: result.events,
    delivered_events_per_second: Number(eventsPerSecond.toFixed(1)),
    painted_updates_per_second: Number(paintedPerSecond.toFixed(1)),
    painted_gap_ms: {
      p50: quantile(0.5) === null ? null : Number(quantile(0.5).toFixed(1)),
      p90: quantile(0.9) === null ? null : Number(quantile(0.9).toFixed(1)),
      max: gaps.length === 0 ? null : Number(gaps.at(-1).toFixed(1)),
    },
    max_animation_frame_gap_ms: Number(result.maxFrameDelta.toFixed(1)),
    playout_lag_ticks: { min: result.minLag, max: result.maxLag },
    worst_gap_at_second: result.gaps.length === 0
      ? null
      : Number((result.gapOffsets[worstIndex] / 1000).toFixed(1)),
  }));
} finally {
  await browser.close();
}
