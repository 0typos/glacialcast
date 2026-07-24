#!/usr/bin/env node

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const [origin, streamId, viewerKey, browserName = 'firefox'] = process.argv.slice(2);
if (!origin || !streamId || !viewerKey || !['firefox', 'chromium'].includes(browserName)) {
  console.error(
    'usage: verify-dash-browser.mjs ORIGIN STREAM_ID VIEWER_KEY [firefox|chromium]',
  );
  process.exit(2);
}

const browserType = browserName === 'firefox' ? firefox : chromium;
const executablePath = browserName === 'firefox'
  ? process.env.GLACIALCAST_FIREFOX_EXECUTABLE
  : process.env.GLACIALCAST_CHROMIUM_EXECUTABLE;
console.log(`launching ${browserName} for ${origin}/dash/${streamId}`);
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
  const errors = [];
  let resolveNextLiveMedia = null;
  let minimumLiveSequence = Number.MAX_SAFE_INTEGER;
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (
      message.type() === 'error'
      && !message.text().includes("frame-ancestors' is ignored")
    ) {
      errors.push(message.text());
    }
  });
  page.on('websocket', socket => {
    socket.on('framereceived', event => {
      if (!resolveNextLiveMedia || typeof event.payload !== 'string') return;
      try {
        const header = JSON.parse(event.payload);
        if (header.kind !== 'Media' || header.sequence <= minimumLiveSequence) return;
        const resolve = resolveNextLiveMedia;
        resolveNextLiveMedia = null;
        resolve(Date.now());
      } catch {
        // Non-JSON frames are diagnosed by the viewer itself.
      }
    });
  });

  await page.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  console.log('viewer loaded; submitting the viewer key');
  await page.locator('#viewer-key').fill(viewerKey);
  await page.locator('#unlock-form button').click();
  try {
    await page.waitForFunction(() => {
      const video = document.querySelector('#video');
      const metrics = document.querySelector('#metrics')?.textContent || '';
      const status = document.querySelector('#status')?.textContent || '';
      return video?.videoWidth > 0
        && video.videoHeight > 0
        && video.buffered.length > 0
        && /[1-9]\d* media fragments/.test(metrics)
        && /[1-9]\d* cursor events/.test(metrics)
        && (
          status.includes('playback ready')
          || status.includes('Connected to live')
        );
    }, null, { timeout: 30_000 });
  } catch (error) {
    const diagnostic = await page.evaluate(() => {
      const video = document.querySelector('#video');
      return {
        status: document.querySelector('#status')?.textContent || '',
        stage: document.querySelector('#stage-message')?.textContent || '',
        metrics: document.querySelector('#metrics')?.textContent || '',
        videoError: video?.error
          ? { code: video.error.code, message: video.error.message }
          : null,
        videoWidth: video?.videoWidth || 0,
        videoHeight: video?.videoHeight || 0,
        buffered: video?.buffered.length || 0,
      };
    });
    throw new Error(
      `${error.message}\nviewer=${JSON.stringify(diagnostic)}\n`
        + `browser errors=${JSON.stringify(errors)}`,
    );
  }
  console.log('encrypted media and cursor events reached the browser');
  const initialMediaCount = await page.evaluate(() => {
    const match = (document.querySelector('#metrics')?.textContent || '')
      .match(/(\d+) media fragments/);
    return Number(match?.[1] || 0);
  });
  minimumLiveSequence = await page.evaluate(async id => {
    const headers = await fetch(`/api/dash/streams/${id}/objects`, {
      cache: 'no-store',
    }).then(response => response.json());
    return Math.max(0, ...headers.map(header => header.sequence));
  }, streamId);
  const announcedAt = await Promise.race([
    new Promise(resolve => {
      resolveNextLiveMedia = resolve;
    }),
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error('timed out waiting for a live media announcement')), 3_000);
    }),
  ]);
  await page.waitForFunction(
    previous => {
      const match = (document.querySelector('#metrics')?.textContent || '')
        .match(/(\d+) media fragments/);
      return Number(match?.[1] || 0) > previous;
    },
    initialMediaCount,
    { timeout: 3_000 },
  );
  const liveAppendLatencyMs = Date.now() - announcedAt;
  if (liveAppendLatencyMs > 250) {
    throw new Error(
      `live media append took ${liveAppendLatencyMs} ms after its relay announcement`,
    );
  }
  await page.evaluate(async () => {
    const video = document.querySelector('#video');
    const start = video.buffered.start(0);
    const end = video.buffered.end(video.buffered.length - 1);
    video.currentTime = Math.max(start, end - 0.5);
    if (video.paused) await video.play();
    if (typeof video.requestVideoFrameCallback === 'function') {
      await Promise.race([
        new Promise(resolve => video.requestVideoFrameCallback(resolve)),
        new Promise(resolve => setTimeout(resolve, 2_000)),
      ]);
    } else {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  });

  const result = await page.evaluate(() => {
    const video = document.querySelector('#video');
    return {
      width: video.videoWidth,
      height: video.videoHeight,
      bufferedStart: video.buffered.start(0),
      bufferedEnd: video.buffered.end(video.buffered.length - 1),
      currentTime: video.currentTime,
      readyState: video.readyState,
      metrics: document.querySelector('#metrics')?.textContent || '',
      status: document.querySelector('#status')?.textContent || '',
    };
  });
  result.liveAppendLatencyMs = liveAppendLatencyMs;
  const paintedVideo = await page.locator('#video').screenshot();
  result.paintedVideoBytes = paintedVideo.byteLength;
  if (paintedVideo.byteLength < 5_000) {
    const screenshot = process.env.GLACIALCAST_DASH_SCREENSHOT
      || `/tmp/glacialcast-dash-${browserName}.png`;
    await page.screenshot({ path: screenshot });
    throw new Error(`decoded video did not paint: ${JSON.stringify(result)}`);
  }
  if (errors.length > 0) {
    throw new Error(`browser reported errors:\n${errors.join('\n')}`);
  }
  console.log(
    `PASS ${browserName}: ${result.width}x${result.height}, `
      + `buffer=${result.bufferedStart.toFixed(3)}..${result.bufferedEnd.toFixed(3)}, `
      + `live-append=${result.liveAppendLatencyMs}ms, painted=${result.paintedVideoBytes} bytes, `
      + `${result.metrics}, status=${result.status}`,
  );
} finally {
  await browser.close();
}
