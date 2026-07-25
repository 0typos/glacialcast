#!/usr/bin/env node

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const [origin, streamId, viewerKey, output, browserName = 'firefox'] = process.argv.slice(2);
if (
  !origin
  || !streamId
  || !viewerKey
  || !output
  || !['firefox', 'chromium'].includes(browserName)
) {
  console.error(
    'usage: capture-dash-frame.mjs ORIGIN STREAM_ID VIEWER_KEY OUTPUT [firefox|chromium]',
  );
  process.exit(2);
}

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
  } : undefined,
});

try {
  const page = await browser.newPage();
  await page.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  await page.locator('#viewer-key').fill(viewerKey);
  await page.locator('#unlock-form button').click();
  await page.waitForFunction(() => {
    const video = document.querySelector('#video');
    const metrics = document.querySelector('#metrics')?.textContent || '';
    return video?.videoWidth > 0
      && video.videoHeight > 0
      && video.buffered.length > 0
      && /[1-9]\d* media fragments/.test(metrics);
  }, null, { timeout: 30_000 });
  const result = await page.evaluate(async () => {
    const video = document.querySelector('#video');
    const end = video.buffered.end(video.buffered.length - 1);
    video.currentTime = Math.max(video.buffered.start(0), end - 0.25);
    if (video.paused) await video.play();
    if (typeof video.requestVideoFrameCallback === 'function') {
      await Promise.race([
        new Promise(resolve => video.requestVideoFrameCallback(resolve)),
        new Promise(resolve => setTimeout(resolve, 2_000)),
      ]);
    } else {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    return {
      width: video.videoWidth,
      height: video.videoHeight,
      metrics: document.querySelector('#metrics')?.textContent || '',
      status: document.querySelector('#status')?.textContent || '',
    };
  });
  await page.locator('#video').screenshot({ path: output });
  console.log(
    `captured ${browserName} frame ${result.width}x${result.height} to ${output}; `
      + `${result.metrics}; status=${result.status}`,
  );
} finally {
  await browser.close();
}
