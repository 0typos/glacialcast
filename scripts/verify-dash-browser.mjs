#!/usr/bin/env node

import { createRequire } from 'node:module';
import fs from 'node:fs';

const require = createRequire(import.meta.url);
const playwrightModule = process.env.GLACIALCAST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox } = require(playwrightModule);

const [origin, streamId, viewerKey, browserName = 'firefox'] = process.argv.slice(2);
const accessToken = process.env.GLACIALCAST_VERIFY_ACCESS_TOKEN;
const minimumEpochs = Number(process.env.GLACIALCAST_VERIFY_MIN_EPOCHS || 1);
const epochTransitionMarker = process.env.GLACIALCAST_VERIFY_EPOCH_TRANSITION_MARKER;
if (!origin || !streamId || !viewerKey || !['firefox', 'chromium'].includes(browserName)) {
  console.error(
    'usage: verify-dash-browser.mjs ORIGIN STREAM_ID VIEWER_KEY [firefox|chromium]',
  );
  process.exit(2);
}
if (!Number.isSafeInteger(minimumEpochs) || minimumEpochs < 1) {
  throw new Error('GLACIALCAST_VERIFY_MIN_EPOCHS must be a positive integer');
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
  const page = await browser.newPage({
    ignoreHTTPSErrors: process.env.GLACIALCAST_VERIFY_IGNORE_HTTPS_ERRORS === '1',
  });
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

  if (accessToken) {
    await page.goto(`${origin}/login`, { waitUntil: 'domcontentloaded' });
    await page.locator('#access-token').fill(accessToken);
    await page.locator('#login-form button').click();
    await page.waitForURL(`${origin}/`);
  }
  await page.goto(`${origin}/dash/${streamId}`, { waitUntil: 'domcontentloaded' });
  console.log('viewer loaded; submitting the viewer key');
  await page.locator('#viewer-key').fill(viewerKey);
  await page.locator('#unlock-form button').click();
  try {
    await page.waitForFunction(expectedEpochs => {
      const video = document.querySelector('#video');
      const metrics = document.querySelector('#metrics')?.textContent || '';
      const status = document.querySelector('#status')?.textContent || '';
      return video?.videoWidth > 0
        && video.videoHeight > 0
        && video.buffered.length > 0
        && /[1-9]\d* media fragments/.test(metrics)
        && /[1-9]\d* cursor events/.test(metrics)
        && Number(metrics.match(/(\d+) capture epochs?/)?.[1] || 0) >= expectedEpochs
        && (
          status.includes('playback ready')
          || status.includes('Connected to live')
        );
    }, minimumEpochs, { timeout: 30_000 });
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
  if (minimumEpochs > 1) {
    await page.evaluate(async () => {
      const video = document.querySelector('#video');
      video.currentTime = video.buffered.start(0) + 0.01;
      if (video.paused) await video.play();
      if (typeof video.requestVideoFrameCallback === 'function') {
        await Promise.race([
          new Promise(resolve => video.requestVideoFrameCallback(resolve)),
          new Promise((_, reject) => {
            setTimeout(() => reject(new Error('historical epoch did not paint')), 2_000);
          }),
        ]);
      } else {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    });
    const historicalFrame = await page.locator('#video').screenshot();
    if (historicalFrame.byteLength < 5_000) {
      throw new Error('the earliest retained capture epoch did not paint');
    }
    await page.locator('#live-button').click();
  }
  const cursorMotion = await page.evaluate(async () => {
    const canvas = document.querySelector('#cursor-layer');
    const bounds = () => {
      const context = canvas.getContext('2d');
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
      let count = 0;
      let minX = canvas.width;
      let minY = canvas.height;
      let maxX = -1;
      let maxY = -1;
      for (let index = 3; index < pixels.length; index += 4) {
        if (pixels[index] === 0) continue;
        const pixel = (index - 3) / 4;
        const x = pixel % canvas.width;
        const y = Math.floor(pixel / canvas.width);
        count += 1;
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x);
        maxY = Math.max(maxY, y);
      }
      return count === 0
        ? null
        : {
          count,
          centerX: (minX + maxX) / 2,
          centerY: (minY + maxY) / 2,
        };
    };

    const deadline = Date.now() + 3_000;
    let first = bounds();
    while (!first && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
      first = bounds();
    }
    if (!first) throw new Error('the independent cursor overlay did not paint');

    let motion = null;
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
      const current = bounds();
      if (
        current
        && (
          Math.abs(current.centerX - first.centerX) >= 1
          || Math.abs(current.centerY - first.centerY) >= 1
        )
      ) {
        motion = {
          paintedPixels: current.count,
          movedX: current.centerX - first.centerX,
          movedY: current.centerY - first.centerY,
        };
        break;
      }
    }
    if (!motion) {
      throw new Error('the independent cursor overlay painted but did not move');
    }

    const visibilityDeadline = Date.now() + 4_000;
    let hidden = false;
    while (Date.now() < visibilityDeadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
      const current = bounds();
      if (!current) hidden = true;
      else if (hidden) return { ...motion, hidAndReturned: true };
    }
    throw new Error('the independent cursor overlay did not hide and return');
  });
  console.log(
    `cursor overlay painted ${cursorMotion.paintedPixels} pixels and moved `
      + `${cursorMotion.movedX.toFixed(1)},${cursorMotion.movedY.toFixed(1)}`,
  );
  if (epochTransitionMarker) {
    const initialEpochs = await page.evaluate(() => {
      const metrics = document.querySelector('#metrics')?.textContent || '';
      return Number(metrics.match(/(\d+) capture epochs?/)?.[1] || 0);
    });
    fs.writeFileSync(`${epochTransitionMarker}.ready`, `${initialEpochs}\n`);
    const transitionDeadline = Date.now() + 30_000;
    while (!fs.existsSync(`${epochTransitionMarker}.continue`)) {
      if (Date.now() >= transitionDeadline) {
        throw new Error('timed out waiting for the publisher epoch transition');
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    await page.waitForFunction(previousEpochs => {
      const metrics = document.querySelector('#metrics')?.textContent || '';
      const status = document.querySelector('#status')?.textContent || '';
      const epochs = Number(metrics.match(/(\d+) capture epochs?/)?.[1] || 0);
      return epochs > previousEpochs
        && !status.includes('Reloading is required')
        && !document.querySelector('#status')?.classList.contains('error');
    }, initialEpochs, { timeout: 30_000 });
    console.log(`viewer continued live playback across capture epoch ${initialEpochs + 1}`);
  }
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
  result.cursorMotion = cursorMotion;
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
