'use strict';

const TIMESCALE = 90000;
const FORMAT_VERSION = 1;
const LIVE_RECONCILE_INTERVAL_MS = 15_000;
const ViewerCore = globalThis.GlacialCastViewerCore;
if (!ViewerCore) throw new Error('The GlacialCast viewer core failed to load.');
const streamId = location.pathname.split('/').filter(Boolean).at(-1);
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const els = {
  streamLabel: document.querySelector('#stream-label'),
  unlockPanel: document.querySelector('#unlock-panel'),
  unlockForm: document.querySelector('#unlock-form'),
  viewerKey: document.querySelector('#viewer-key'),
  playerPanel: document.querySelector('#player-panel'),
  stage: document.querySelector('#stage'),
  stageMessage: document.querySelector('#stage-message'),
  video: document.querySelector('#video'),
  cursorLayer: document.querySelector('#cursor-layer'),
  liveButton: document.querySelector('#live-button'),
  timeline: document.querySelector('#timeline'),
  timeLabel: document.querySelector('#time-label'),
  status: document.querySelector('#status'),
  metrics: document.querySelector('#metrics'),
};

const state = {
  descriptor: null,
  epochKeys: null,
  headers: [],
  seenSequences: new Set(),
  cursorEvents: [],
  cursorBitmaps: new Map(),
  mediaSource: null,
  sourceBuffer: null,
  mediaQueue: Promise.resolve(),
  liveQueue: Promise.resolve(),
  liveSocket: null,
  liveReconnectTimer: null,
  liveReconcileTimer: null,
  live: true,
  appendedMedia: 0,
  decryptedCursorBatches: 0,
  lastRenderedCursor: undefined,
  lastRenderedBitmap: undefined,
  lastRenderLayout: '',
};

els.streamLabel.textContent = `Stream ${streamId}`;

els.unlockForm.addEventListener('submit', event => {
  event.preventDefault();
  start(els.viewerKey.value.trim()).catch(showError);
});

els.liveButton.addEventListener('click', () => {
  state.live = true;
  seekToLiveEdge();
});

els.timeline.addEventListener('input', () => {
  state.live = false;
  els.video.currentTime = Number(els.timeline.value);
});

els.video.addEventListener('timeupdate', updateTimeline);
els.video.addEventListener('progress', updateTimelineBounds);
els.video.addEventListener('playing', () => {
  els.stageMessage.textContent = '';
});
els.video.addEventListener('error', () => {
  const detail = els.video.error?.message || `media error ${els.video.error?.code || 'unknown'}`;
  showError(new Error(detail));
});

requestAnimationFrame(renderCursor);

async function start(viewerKeyText) {
  setStatus('Loading stream metadata…');
  validatePlatform();
  const headers = await fetchHeaders();
  const epochHeader = [...headers].reverse().find(header => header.kind === 'Epoch');
  if (!epochHeader) throw new Error('The stream has not published an epoch descriptor.');

  const epochPayload = await fetchObject(epochHeader.sequence);
  const epochKeys = await deriveEpochKeys(viewerKeyText, streamId, epochHeader.epoch_id);
  state.epochKeys = epochKeys;
  await verifyObject(epochHeader, epochPayload);

  const descriptor = JSON.parse(decoder.decode(epochPayload));
  validateDescriptor(descriptor, epochHeader);
  state.descriptor = descriptor;
  state.headers = headers;
  els.streamLabel.textContent = `${streamId} · ${descriptor.width}×${descriptor.height} · ${descriptor.codec}`;

  const contentType = `video/mp4; codecs="${descriptor.codec}"`;
  await installClearKey(contentType, epochKeys);
  await initializeMediaSource(contentType, headers);

  els.unlockPanel.hidden = true;
  els.playerPanel.hidden = false;
  await loadHistoricalCursors(headers);
  connectLive();
  setStatus('Live encrypted DASH playback ready.');
  updateMetrics();
}

function validatePlatform() {
  if (!globalThis.isSecureContext) {
    throw new Error('Encrypted playback requires HTTPS or a loopback origin.');
  }
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable.');
  if (!globalThis.MediaSource) throw new Error('Media Source Extensions are unavailable.');
  if (!navigator.requestMediaKeySystemAccess) {
    throw new Error('Encrypted Media Extensions are unavailable.');
  }
}

async function fetchHeaders() {
  const response = await fetch(`/api/dash/streams/${streamId}/objects`, {
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(await response.text() || 'Unable to list DASH objects.');
  const headers = await response.json();
  headers.sort((left, right) => left.sequence - right.sequence);
  return headers;
}

async function fetchObject(sequence) {
  const response = await fetch(`/api/dash/streams/${streamId}/objects/${sequence}`);
  if (!response.ok) throw new Error(await response.text() || `Unable to load object ${sequence}.`);
  return new Uint8Array(await response.arrayBuffer());
}

async function deriveEpochKeys(viewerKeyText, stream, epoch) {
  const viewerKey = base64UrlToBytes(viewerKeyText, 32);
  const saltInput = concatBytes(
    encoder.encode('glacialcast epoch key salt'),
    uuidToBytes(stream),
    uuidToBytes(epoch),
  );
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', saltInput));
  const inputKey = await crypto.subtle.importKey('raw', viewerKey, 'HKDF', false, ['deriveBits']);
  const material = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt,
    info: encoder.encode('glacialcast dash epoch keys v1'),
  }, inputKey, 80 * 8));
  const cencKey = material.slice(0, 16);
  const cursorKeyBytes = material.slice(16, 48);
  const authenticationKeyBytes = material.slice(48, 80);
  return {
    keyId: uuidToBytes(epoch),
    cencKey,
    cursorKey: await crypto.subtle.importKey(
      'raw',
      cursorKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    ),
    authenticationKey: await crypto.subtle.importKey(
      'raw',
      authenticationKeyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    ),
  };
}

async function verifyObject(header, payload) {
  if (header.format_version !== FORMAT_VERSION) {
    throw new Error(`Unsupported DASH object version ${header.format_version}.`);
  }
  if (header.stream_id !== streamId || header.epoch_id !== state.descriptor?.epoch_id && state.descriptor) {
    throw new Error(`Object ${header.sequence} belongs to a different stream epoch.`);
  }
  if (payload.byteLength !== header.payload_len) {
    throw new Error(`Object ${header.sequence} has an invalid payload length.`);
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  if (!equalBytes(digest, new Uint8Array(header.payload_sha256))) {
    throw new Error(`Object ${header.sequence} failed its SHA-256 check.`);
  }
  const authenticated = concatBytes(authenticationBytes(header), payload);
  const valid = await crypto.subtle.verify(
    'HMAC',
    state.epochKeys.authenticationKey,
    new Uint8Array(header.authentication_tag),
    authenticated,
  );
  if (!valid) throw new Error(`Object ${header.sequence} failed authentication.`);
}

function authenticationBytes(header) {
  const mime = encoder.encode(header.mime);
  return concatBytes(
    encoder.encode('glacial-dash-object-v1'),
    unsignedBigEndian(header.format_version, 2),
    uuidToBytes(header.stream_id),
    uuidToBytes(header.epoch_id),
    new Uint8Array([kindCode(header.kind)]),
    unsignedBigEndian(header.sequence, 8),
    unsignedBigEndian(header.segment_number, 8),
    unsignedBigEndian(header.chunk_index, 2),
    unsignedBigEndian(header.timestamp, 8),
    unsignedBigEndian(header.duration, 8),
    new Uint8Array([header.random_access ? 1 : 0]),
    unsignedBigEndian(mime.byteLength, 2),
    mime,
    unsignedBigEndian(header.payload_len, 4),
    new Uint8Array(header.payload_sha256),
  );
}

function kindCode(kind) {
  const code = {
    Epoch: 0,
    Initialization: 1,
    Media: 2,
    Cursor: 3,
    Index: 4,
    End: 5,
  }[kind];
  if (code === undefined) throw new Error(`Unknown DASH object kind ${kind}.`);
  return code;
}

function validateDescriptor(descriptor, header) {
  if (
    descriptor.format_version !== FORMAT_VERSION
    || descriptor.stream_id !== streamId
    || descriptor.epoch_id !== header.epoch_id
    || descriptor.timescale !== TIMESCALE
    || descriptor.width <= 0
    || descriptor.height <= 0
    || !String(descriptor.codec).startsWith('avc1.')
  ) {
    throw new Error('The authenticated epoch descriptor is invalid.');
  }
}

async function installClearKey(contentType, keys) {
  if (!MediaSource.isTypeSupported(contentType)) {
    throw new Error(`This browser cannot play ${contentType}.`);
  }
  const capability = { contentType, robustness: '', encryptionScheme: 'cenc' };
  const configuration = [{
    initDataTypes: ['keyids', 'cenc'],
    distinctiveIdentifier: 'not-allowed',
    persistentState: 'not-allowed',
    sessionTypes: ['temporary'],
    videoCapabilities: [capability],
  }];
  let access;
  try {
    access = await navigator.requestMediaKeySystemAccess('org.w3.clearkey', configuration);
  } catch (error) {
    delete capability.encryptionScheme;
    access = await navigator.requestMediaKeySystemAccess('org.w3.clearkey', configuration)
      .catch(() => { throw error; });
  }
  const mediaKeys = await access.createMediaKeys();
  await els.video.setMediaKeys(mediaKeys);
  const session = mediaKeys.createSession('temporary');
  const message = new Promise((resolve, reject) => {
    session.addEventListener('message', resolve, { once: true });
    session.addEventListener('keystatuseschange', () => {
      for (const status of session.keyStatuses.values()) {
        if (status !== 'usable' && status !== 'status-pending') {
          reject(new Error(`Clear Key status is ${status}.`));
        }
      }
    });
  });
  await session.generateRequest('keyids', encoder.encode(JSON.stringify({
    kids: [bytesToBase64Url(keys.keyId)],
    type: 'temporary',
  })));
  await message;
  await session.update(encoder.encode(JSON.stringify({
    keys: [{
      kty: 'oct',
      kid: bytesToBase64Url(keys.keyId),
      k: bytesToBase64Url(keys.cencKey),
    }],
    type: 'temporary',
  })));
}

async function initializeMediaSource(contentType, headers) {
  const mediaSource = new MediaSource();
  state.mediaSource = mediaSource;
  els.video.src = URL.createObjectURL(mediaSource);
  await once(mediaSource, 'sourceopen');
  const sourceBuffer = mediaSource.addSourceBuffer(contentType);
  sourceBuffer.mode = 'segments';
  state.sourceBuffer = sourceBuffer;

  const epoch = state.descriptor.epoch_id;
  const initHeader = [...headers].reverse().find(header =>
    header.kind === 'Initialization' && header.epoch_id === epoch
  );
  if (!initHeader) throw new Error('The stream has no initialization segment.');
  await fetchVerifyAppend(initHeader);

  const media = headers.filter(header =>
    header.kind === 'Media' && header.epoch_id === epoch
  );
  const firstRandomAccess = media.findIndex(header => header.random_access);
  if (firstRandomAccess < 0) throw new Error('No retained random-access segment is available.');
  for (const header of media.slice(firstRandomAccess)) {
    await fetchVerifyAppend(header);
  }
  updateTimelineBounds();
  seekToLiveEdge();
  await els.video.play().catch(() => {
    setStatus('Playback is ready; use the Live button if autoplay was blocked.');
  });
}

async function fetchVerifyAppend(header) {
  if (state.seenSequences.has(header.sequence)) return;
  const payload = await fetchObject(header.sequence);
  await verifyObject(header, payload);
  await appendMedia(payload);
  state.seenSequences.add(header.sequence);
  if (header.kind === 'Media') state.appendedMedia += 1;
  updateMetrics();
}

function appendMedia(bytes) {
  state.mediaQueue = state.mediaQueue.then(async () => {
    if (!state.sourceBuffer || state.mediaSource?.readyState !== 'open') return;
    if (state.sourceBuffer.updating) await once(state.sourceBuffer, 'updateend');
    state.sourceBuffer.appendBuffer(bytes);
    await once(state.sourceBuffer, 'updateend');
    updateTimelineBounds();
    if (state.live) seekToLiveEdge();
  });
  return state.mediaQueue;
}

async function loadHistoricalCursors(headers) {
  const cursors = headers.filter(header =>
    header.kind === 'Cursor' && header.epoch_id === state.descriptor.epoch_id
  );
  const concurrency = 12;
  for (let index = 0; index < cursors.length; index += concurrency) {
    const decoded = await Promise.all(
      cursors
        .slice(index, index + concurrency)
        .map(async header => [header, await decodeCursorObject(header)]),
    );
    for (const [header, batch] of decoded) commitCursorObject(header, batch);
  }
}

async function decodeCursorObject(header) {
  const payload = await fetchObject(header.sequence);
  await verifyObject(header, payload);
  const encrypted = ViewerCore.parseEncryptedCursorPayload(payload);
  const plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: encrypted.nonce,
    additionalData: cursorAad(header),
    tagLength: 128,
  }, state.epochKeys.cursorKey, encrypted.ciphertext);
  return ViewerCore.parseCursorBatch(new Uint8Array(plaintext), {
    sourceWidth: state.descriptor.width,
    sourceHeight: state.descriptor.height,
    startTimestamp: header.timestamp,
  });
}

function commitCursorObject(header, batch) {
  if (state.seenSequences.has(header.sequence)) return;
  for (const event of batch.events) {
    if (event.bitmap) cacheCursorBitmap(event.bitmap_id, event.bitmap);
  }
  state.cursorEvents = ViewerCore.mergeSortedCursorEvents(state.cursorEvents, batch.events);
  state.seenSequences.add(header.sequence);
  state.decryptedCursorBatches += 1;
  updateMetrics();
}

async function loadCursorObject(header) {
  if (state.seenSequences.has(header.sequence)) return;
  commitCursorObject(header, await decodeCursorObject(header));
}

function cacheCursorBitmap(bitmapId, bitmap) {
  const surface = typeof OffscreenCanvas === 'function'
    ? new OffscreenCanvas(bitmap.width, bitmap.height)
    : Object.assign(document.createElement('canvas'), {
      width: bitmap.width,
      height: bitmap.height,
    });
  const context = surface.getContext('2d');
  if (!context) throw new Error('The browser cannot render the cursor bitmap.');
  const pixels = new Uint8ClampedArray(
    bitmap.rgba.buffer,
    bitmap.rgba.byteOffset,
    bitmap.rgba.byteLength,
  );
  context.putImageData(new ImageData(pixels, bitmap.width, bitmap.height), 0, 0);
  state.cursorBitmaps.set(bitmapId, {
    width: bitmap.width,
    height: bitmap.height,
    hotspot_x: bitmap.hotspot_x,
    hotspot_y: bitmap.hotspot_y,
    surface,
  });
}

function cursorAad(header) {
  return concatBytes(
    encoder.encode('glacial-cursor-v1'),
    uuidToBytes(header.stream_id),
    uuidToBytes(header.epoch_id),
    unsignedBigEndian(header.sequence, 8),
    unsignedBigEndian(header.timestamp, 8),
    unsignedBigEndian(state.descriptor.width, 4),
    unsignedBigEndian(state.descriptor.height, 4),
  );
}

function connectLive() {
  clearTimeout(state.liveReconnectTimer);
  clearInterval(state.liveReconcileTimer);
  state.liveSocket?.close();
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(
    `${scheme}//${location.host}/api/dash/streams/${streamId}/live`
  );
  state.liveSocket = socket;
  socket.addEventListener('open', () => {
    queueLiveTask(async () => {
      await reconcileLiveHeaders();
      if (state.liveSocket === socket) {
        setStatus('Connected to live encrypted stream.');
      }
    });
    state.liveReconcileTimer = setInterval(() => {
      queueLiveTask(reconcileLiveHeaders);
    }, LIVE_RECONCILE_INTERVAL_MS);
  });
  socket.addEventListener('message', event => {
    queueLiveTask(() => handleLiveHeader(JSON.parse(event.data)));
  });
  socket.addEventListener('close', () => {
    if (state.liveSocket !== socket) return;
    clearInterval(state.liveReconcileTimer);
    setStatus('Live connection interrupted; reconnecting…');
    state.liveReconnectTimer = setTimeout(connectLive, 1000);
  });
}

function queueLiveTask(task) {
  state.liveQueue = state.liveQueue.then(task).catch(showError);
  return state.liveQueue;
}

async function reconcileLiveHeaders() {
  const headers = await fetchHeaders();
  const latestEpoch = [...headers].reverse().find(header => header.kind === 'Epoch');
  if (latestEpoch && latestEpoch.epoch_id !== state.descriptor.epoch_id) {
    setStatus('The capture epoch changed. Reloading is required.');
    return;
  }

  const epochHeaders = headers.filter(
    header => header.epoch_id === state.descriptor.epoch_id
  );
  for (const header of epochHeaders) {
    await handleLiveHeader(header);
  }

  const retainedSequences = new Set(epochHeaders.map(header => header.sequence));
  const listedHighWater = headers.at(-1)?.sequence || 0;
  state.seenSequences = new Set(
    [...state.seenSequences].filter(
      sequence => retainedSequences.has(sequence) || sequence > listedHighWater
    )
  );

  const firstRandomAccess = epochHeaders.find(
    header => header.kind === 'Media' && header.random_access
  );
  if (firstRandomAccess) {
    await trimPlaybackHistory(firstRandomAccess.timestamp);
  }
}

async function handleLiveHeader(header) {
  if (header.stream_id !== streamId || state.seenSequences.has(header.sequence)) return;
  if (header.epoch_id !== state.descriptor.epoch_id) {
    setStatus('The capture epoch changed. Reloading is required.');
    return;
  }
  if (header.kind === 'Media') {
    await fetchVerifyAppend(header);
  } else if (header.kind === 'Cursor') {
    await loadCursorObject(header);
  }
}

async function trimPlaybackHistory(cutoffTimestamp) {
  state.cursorEvents = ViewerCore.retainCursorHistory(
    state.cursorEvents,
    cutoffTimestamp,
  );
  const referencedBitmaps = ViewerCore.referencedBitmapIds(state.cursorEvents);
  for (const bitmapId of state.cursorBitmaps.keys()) {
    if (!referencedBitmaps.has(bitmapId)) state.cursorBitmaps.delete(bitmapId);
  }

  const cutoffSeconds = cutoffTimestamp / TIMESCALE;
  state.mediaQueue = state.mediaQueue.then(async () => {
    const sourceBuffer = state.sourceBuffer;
    if (!sourceBuffer || state.mediaSource?.readyState !== 'open' || !sourceBuffer.buffered.length) {
      return;
    }
    if (sourceBuffer.updating) await once(sourceBuffer, 'updateend');
    const bufferedStart = sourceBuffer.buffered.start(0);
    const bufferedEnd = sourceBuffer.buffered.end(sourceBuffer.buffered.length - 1);
    const removeEnd = Math.min(cutoffSeconds, bufferedEnd);
    if (removeEnd <= bufferedStart + 0.001) return;
    if (els.video.currentTime < removeEnd) els.video.currentTime = removeEnd;
    sourceBuffer.remove(0, removeEnd);
    await once(sourceBuffer, 'updateend');
    updateTimelineBounds();
  });
  await state.mediaQueue;
  updateMetrics();
}

function renderCursor() {
  const canvas = els.cursorLayer;
  const ratio = globalThis.devicePixelRatio || 1;
  const width = Math.max(1, els.stage.clientWidth);
  const height = Math.max(1, els.stage.clientHeight);
  const canvasWidth = Math.round(width * ratio);
  const canvasHeight = Math.round(height * ratio);
  const event = currentCursorEvent();
  const bitmap = event?.visible ? state.cursorBitmaps.get(event.bitmap_id) : undefined;
  const layout = `${canvasWidth}:${canvasHeight}:${ratio}`;
  if (
    state.lastRenderedCursor === event
    && state.lastRenderedBitmap === bitmap
    && state.lastRenderLayout === layout
  ) {
    requestAnimationFrame(renderCursor);
    return;
  }
  state.lastRenderedCursor = event;
  state.lastRenderedBitmap = bitmap;
  state.lastRenderLayout = layout;

  if (canvas.width !== canvasWidth || canvas.height !== canvasHeight) {
    canvas.width = canvasWidth;
    canvas.height = canvasHeight;
  }
  const context = canvas.getContext('2d');
  if (!context) {
    showError(new Error('The browser cannot render the cursor overlay.'));
    return;
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);

  if (event?.visible) {
    const rectangle = containedVideoRectangle(width, height);
    const scaleX = rectangle.width / state.descriptor.width;
    const scaleY = rectangle.height / state.descriptor.height;
    const x = rectangle.left + event.x_micropixels / 1_000_000 * scaleX;
    const y = rectangle.top + event.y_micropixels / 1_000_000 * scaleY;
    if (bitmap) {
      context.drawImage(
        bitmap.surface,
        x - bitmap.hotspot_x * scaleX,
        y - bitmap.hotspot_y * scaleY,
        bitmap.width * scaleX,
        bitmap.height * scaleY,
      );
    } else {
      context.fillStyle = '#ffffff';
      context.strokeStyle = '#000000';
      context.lineWidth = 2;
      context.beginPath();
      context.arc(x, y, 5, 0, Math.PI * 2);
      context.fill();
      context.stroke();
    }
  }
  requestAnimationFrame(renderCursor);
}

function currentCursorEvent() {
  if (!state.cursorEvents.length || !state.descriptor) return null;
  return ViewerCore.findCursorEvent(
    state.cursorEvents,
    els.video.currentTime * TIMESCALE,
    state.live,
  );
}

function containedVideoRectangle(width, height) {
  return ViewerCore.containedVideoRectangle(
    width,
    height,
    state.descriptor.width,
    state.descriptor.height,
  );
}

function updateTimelineBounds() {
  if (!els.video.buffered.length) return;
  const start = els.video.buffered.start(0);
  const end = els.video.buffered.end(els.video.buffered.length - 1);
  els.timeline.min = String(start);
  els.timeline.max = String(end);
  if (state.mediaSource?.readyState === 'open' && state.mediaSource.setLiveSeekableRange) {
    state.mediaSource.setLiveSeekableRange(start, end);
  }
  updateTimeline();
}

function updateTimeline() {
  if (!state.live) els.timeline.value = String(els.video.currentTime);
  else if (els.video.buffered.length) {
    els.timeline.value = String(els.video.buffered.end(els.video.buffered.length - 1));
  }
  els.timeLabel.textContent = formatTime(els.video.currentTime);
}

function seekToLiveEdge() {
  if (!els.video.buffered.length) return;
  const end = els.video.buffered.end(els.video.buffered.length - 1);
  els.video.currentTime = Math.max(0, end - 0.05);
  els.video.play().catch(() => {});
  updateTimeline();
}

function updateMetrics() {
  els.metrics.textContent =
    `${state.appendedMedia} media fragments · ${state.cursorEvents.length} cursor events`;
}

function setStatus(message) {
  els.status.classList.remove('error');
  els.status.textContent = message;
}

function showError(error) {
  console.error(error);
  els.status.classList.add('error');
  els.status.textContent = error?.message || String(error);
  els.stageMessage.textContent = error?.message || String(error);
}

function once(target, event) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      target.removeEventListener(event, done);
      target.removeEventListener('error', failed);
    };
    const done = value => {
      cleanup();
      resolve(value);
    };
    const failed = () => {
      cleanup();
      reject(new Error(`${event} failed.`));
    };
    target.addEventListener(event, done, { once: true });
    target.addEventListener('error', failed, { once: true });
  });
}

function uuidToBytes(uuid) {
  const hex = uuid.replaceAll('-', '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`Invalid UUID ${uuid}.`);
  return Uint8Array.from(hex.match(/../g), byte => Number.parseInt(byte, 16));
}

function unsignedBigEndian(value, size) {
  let remaining = BigInt(value);
  const bytes = new Uint8Array(size);
  for (let index = size - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error(`Value ${value} does not fit in ${size} bytes.`);
  return bytes;
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function base64UrlToBytes(value, expectedLength) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  if (bytes.byteLength !== expectedLength) {
    throw new Error(`Viewer key must decode to ${expectedLength} bytes.`);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function equalBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function formatTime(seconds) {
  if (!Number.isFinite(seconds)) return '0:00';
  const whole = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(whole / 60);
  return `${minutes}:${String(whole % 60).padStart(2, '0')}`;
}
