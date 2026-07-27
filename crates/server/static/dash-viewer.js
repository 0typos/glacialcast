'use strict';


const TIMESCALE = 90000;
const FORMAT_VERSION = 1;
const LIVE_RECONCILE_INTERVAL_MS = 15_000;
const ViewerCore = globalThis.GlacialCastViewerCore;
if (!ViewerCore) throw new Error('The GlacialCast viewer core failed to load.');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Mounts one encrypted DASH player inside `root`.
 *
 * Elements are found by `data-role` within `root`, so several players can run
 * on one page. Every element except the stage, video, and cursor layer is
 * optional: a tile in the multi-stream view has no unlock panel or timeline of
 * its own.
 *
 * The returned handle must be destroyed when the player is removed; the live
 * socket, its reconnect timers, and the animation-frame loop all outlive the
 * DOM otherwise.
 */
// Hoisted out of createPlayer so the standalone key check below authenticates
// an object with exactly the same bytes the player does; two copies of this
// layout would be two chances to disagree.
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

function createPlayer(root, options) {
  const streamId = options.streamId;
  const onStatus = options.onStatus || (() => {});
  let destroyed = false;
  let cursorFrame = null;
  let objectUrl = null;

  const els = {
    streamLabel: root.querySelector('[data-role="stream-label"]'),
    unlockPanel: root.querySelector('[data-role="unlock-panel"]'),
    playerPanel: root.querySelector('[data-role="player-panel"]'),
    stage: root.querySelector('[data-role="stage"]'),
    stageMessage: root.querySelector('[data-role="stage-message"]'),
    video: root.querySelector('[data-role="video"]'),
    cursorLayer: root.querySelector('[data-role="cursor-layer"]'),
    liveButton: root.querySelector('[data-role="live-button"]'),
    timeline: root.querySelector('[data-role="timeline"]'),
    timeLabel: root.querySelector('[data-role="time-label"]'),
    status: root.querySelector('[data-role="status"]'),
    metrics: root.querySelector('[data-role="metrics"]'),
  };

  const state = {
    descriptor: null,
    viewerKey: null,
    epochs: new Map(),
    epochOrder: [],
    headers: [],
    seenSequences: new Set(),
    cursorEvents: [],
    cursorBitmaps: new Map(),
    mediaSource: null,
    sourceBuffer: null,
    sourceBufferContentType: null,
    mediaKeys: null,
    keyEpochs: new Set(),
    keySessions: [],
    mediaQueue: Promise.resolve(),
    liveQueue: Promise.resolve(),
    liveSocket: null,
    liveReconnectTimer: null,
    liveReconcileTimer: null,
    live: true,
    appendedMedia: 0,
    decryptedCursorBatches: 0,
    cursorClock: ViewerCore.createCursorClock(),
    lastRenderedCursor: undefined,
    lastRenderedBitmap: undefined,
    lastRenderLayout: '',
  };

  if (els.streamLabel) els.streamLabel.textContent = `Stream ${streamId}`;

  els.liveButton?.addEventListener('click', () => {
    state.live = true;
    state.cursorClock.reset();
    seekToLiveEdge();
  });

  els.timeline?.addEventListener('input', () => {
    state.live = false;
    state.cursorClock.reset();
    els.video.currentTime = Number(els.timeline?.value);
  });

  els.video.addEventListener('timeupdate', updateTimeline);
  els.video.addEventListener('progress', updateTimelineBounds);
  els.video.addEventListener('playing', () => {
    if (els.stageMessage) els.stageMessage.textContent = '';
  });
  els.video.addEventListener('error', () => {
    const detail = els.video.error?.message || `media error ${els.video.error?.code || 'unknown'}`;
    showError(new Error(detail));
  });

  cursorFrame = requestAnimationFrame(renderCursor);

  async function start(viewerKeyText) {
    setStatus('Loading stream metadata…');
    validatePlatform();
    state.viewerKey = base64UrlToBytes(viewerKeyText, 32);
    const headers = await fetchHeaders();
    state.headers = headers;
    await loadEpochDescriptors(headers);
    const timeline = installInitialEpochTimeline(headers);
    if (timeline.length === 0) {
      throw new Error('No retained random-access media is available.');
    }
    state.descriptor = state.epochs.get(timeline.at(-1).epoch_id).descriptor;
    const descriptor = state.descriptor;
    if (els.streamLabel) els.streamLabel.textContent = `${streamId} · ${descriptor.width}×${descriptor.height} · ${descriptor.codec}`;

    await initializeKeySystem();
    for (const epochId of state.epochOrder) {
      await installEpochKey(state.epochs.get(epochId));
    }
    await initializeMediaSource(timeline);

    if (els.unlockPanel) els.unlockPanel.hidden = true;
    if (els.playerPanel) els.playerPanel.hidden = false;
    // Live first: replaying history can take a while on a long retention
    // window, and nothing about it should delay or endanger the live cursor.
    connectLive();
    setStatus('Live encrypted DASH playback ready.');
    updateMetrics();
    await loadHistoricalCursors(headers);
    updateMetrics();
  }

  async function loadEpochDescriptors(headers) {
    const epochHeaders = headers.filter(header => header.kind === 'Epoch');
    if (epochHeaders.length === 0) {
      throw new Error('The stream has not published an epoch descriptor.');
    }
    for (const header of epochHeaders) {
      await loadEpochDescriptor(header);
    }
  }

  async function loadEpochDescriptor(header) {
    if (state.epochs.has(header.epoch_id)) return state.epochs.get(header.epoch_id);
    const keys = await deriveEpochKeys(state.viewerKey, streamId, header.epoch_id);
    const epoch = {
      descriptor: null,
      keys,
      mediaStart: null,
      mediaEnd: null,
      offset: null,
      globalStart: null,
      globalEnd: null,
      initializationAppended: false,
      cursorBoundaryAdded: false,
    };
    state.epochs.set(header.epoch_id, epoch);
    state.epochOrder.push(header.epoch_id);
    try {
      const payload = await fetchObject(header.sequence);
      await verifyObject(header, payload);
      const descriptor = JSON.parse(decoder.decode(payload));
      validateDescriptor(descriptor, header);
      epoch.descriptor = descriptor;
      state.seenSequences.add(header.sequence);
      return epoch;
    } catch (error) {
      state.epochs.delete(header.epoch_id);
      state.epochOrder = state.epochOrder.filter(epochId => epochId !== header.epoch_id);
      throw error;
    }
  }

  function installInitialEpochTimeline(headers) {
    const timeline = ViewerCore.buildEpochTimeline(headers);
    for (const planned of timeline) {
      const epoch = state.epochs.get(planned.epoch_id);
      if (!epoch?.descriptor) {
        throw new Error(`Epoch ${planned.epoch_id} has no authenticated descriptor.`);
      }
      epoch.mediaStart = planned.media_start;
      epoch.mediaEnd = planned.media_end;
      epoch.offset = planned.offset;
      epoch.globalStart = planned.global_start;
      epoch.globalEnd = planned.global_end;
    }
    return timeline;
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

  async function deriveEpochKeys(viewerKey, stream, epoch) {
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
    if (header.stream_id !== streamId) {
      throw new Error(`Object ${header.sequence} belongs to a different stream.`);
    }
    const epoch = state.epochs.get(header.epoch_id);
    if (!epoch) throw new Error(`Object ${header.sequence} belongs to an unknown stream epoch.`);
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
      epoch.keys.authenticationKey,
      new Uint8Array(header.authentication_tag),
      authenticated,
    );
    if (!valid) throw new Error(`Object ${header.sequence} failed authentication.`);
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

  async function initializeKeySystem() {
    const contentTypes = [...new Set(state.epochOrder.map(epochId => {
      const descriptor = state.epochs.get(epochId).descriptor;
      return contentTypeForDescriptor(descriptor);
    }))];
    for (const contentType of contentTypes) {
      if (!MediaSource.isTypeSupported(contentType)) {
        throw new Error(`This browser cannot play ${contentType}.`);
      }
    }
    const capabilities = contentTypes.map(contentType => ({
      contentType,
      robustness: '',
      encryptionScheme: 'cenc',
    }));
    const configuration = [{
      initDataTypes: ['keyids', 'cenc'],
      distinctiveIdentifier: 'not-allowed',
      persistentState: 'not-allowed',
      sessionTypes: ['temporary'],
      videoCapabilities: capabilities,
    }];
    let access;
    try {
      access = await navigator.requestMediaKeySystemAccess('org.w3.clearkey', configuration);
    } catch (error) {
      for (const capability of capabilities) delete capability.encryptionScheme;
      access = await navigator.requestMediaKeySystemAccess('org.w3.clearkey', configuration)
        .catch(() => { throw error; });
    }
    state.mediaKeys = await access.createMediaKeys();
    await els.video.setMediaKeys(state.mediaKeys);
  }

  async function installEpochKey(epoch) {
    const epochId = epoch.descriptor.epoch_id;
    if (state.keyEpochs.has(epochId)) return;
    if (!state.mediaKeys) throw new Error('The Clear Key system is not initialized.');
    const session = state.mediaKeys.createSession('temporary');
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
      kids: [bytesToBase64Url(epoch.keys.keyId)],
      type: 'temporary',
    })));
    await message;
    await session.update(encoder.encode(JSON.stringify({
      keys: [{
        kty: 'oct',
        kid: bytesToBase64Url(epoch.keys.keyId),
        k: bytesToBase64Url(epoch.keys.cencKey),
      }],
      type: 'temporary',
    })));
    state.keySessions.push(session);
    state.keyEpochs.add(epochId);
  }

  function contentTypeForDescriptor(descriptor) {
    return `video/mp4; codecs="${descriptor.codec}"`;
  }

  async function initializeMediaSource(timeline) {
    const mediaSource = new MediaSource();
    state.mediaSource = mediaSource;
    objectUrl = URL.createObjectURL(mediaSource);
    els.video.src = objectUrl;
    await once(mediaSource, 'sourceopen');
    const firstEpoch = state.epochs.get(timeline[0].epoch_id);
    const contentType = contentTypeForDescriptor(firstEpoch.descriptor);
    const sourceBuffer = mediaSource.addSourceBuffer(contentType);
    sourceBuffer.mode = 'segments';
    state.sourceBuffer = sourceBuffer;
    state.sourceBufferContentType = contentType;

    for (const planned of timeline) {
      await appendEpochMedia(state.epochs.get(planned.epoch_id), planned.media);
    }
    updateTimelineBounds();
    seekToLiveEdge();
    await els.video.play().catch(() => {
      setStatus('Playback is ready; use the Live button if autoplay was blocked.');
    });
  }

  async function appendEpochMedia(epoch, allMedia) {
    const firstRandomAccess = allMedia.findIndex(header => header.random_access);
    if (firstRandomAccess < 0) return;
    const media = allMedia.slice(firstRandomAccess);
    if (epoch.offset === null) {
      const previousEnd = Math.max(
        0,
        ...[...state.epochs.values()]
          .map(candidate => candidate.globalEnd)
          .filter(value => value !== null),
      );
      epoch.mediaStart = media[0].timestamp;
      epoch.offset = previousEnd - epoch.mediaStart;
      epoch.globalStart = previousEnd;
    }
    const mediaEnd = media.reduce(
      (end, header) => Math.max(end, header.timestamp + header.duration),
      epoch.mediaStart,
    );
    epoch.mediaEnd = Math.max(epoch.mediaEnd ?? epoch.mediaStart, mediaEnd);
    epoch.globalEnd = epoch.offset + epoch.mediaEnd;
    ensureEpochCursorBoundary(epoch);

    const initHeader = [...state.headers].reverse().find(header =>
      header.kind === 'Initialization' && header.epoch_id === epoch.descriptor.epoch_id
    );
    if (!initHeader) throw new Error(`Epoch ${epoch.descriptor.epoch_id} has no initialization segment.`);
    if (!epoch.initializationAppended) {
      await fetchVerifyAppend(initHeader, epoch);
      epoch.initializationAppended = true;
    }
    for (const header of media) {
      if (header.timestamp < epoch.mediaStart) continue;
      await fetchVerifyAppend(header, epoch);
    }
  }

  async function fetchVerifyAppend(header, epoch) {
    if (state.seenSequences.has(header.sequence)) return;
    const payload = await fetchObject(header.sequence);
    await verifyObject(header, payload);
    await appendMedia(payload, epoch);
    state.seenSequences.add(header.sequence);
    if (header.kind === 'Media') state.appendedMedia += 1;
    updateMetrics();
  }

  function appendMedia(bytes, epoch) {
    state.mediaQueue = state.mediaQueue.then(async () => {
      if (!state.sourceBuffer || state.mediaSource?.readyState !== 'open') return;
      if (state.sourceBuffer.updating) await once(state.sourceBuffer, 'updateend');
      const contentType = contentTypeForDescriptor(epoch.descriptor);
      if (state.sourceBufferContentType !== contentType) {
        if (typeof state.sourceBuffer.changeType !== 'function') {
          throw new Error(`This browser cannot transition playback to ${contentType}.`);
        }
        state.sourceBuffer.changeType(contentType);
        state.sourceBufferContentType = contentType;
      }
      state.sourceBuffer.timestampOffset = epoch.offset / TIMESCALE;
      state.sourceBuffer.appendBuffer(bytes);
      await once(state.sourceBuffer, 'updateend');
      updateTimelineBounds();
      if (state.live) seekToLiveEdge();
    });
    return state.mediaQueue;
  }

  async function loadHistoricalCursors(headers) {
    const cursors = headers.filter(header => {
      const epoch = state.epochs.get(header.epoch_id);
      return header.kind === 'Cursor'
        && epoch?.offset !== null
        && !state.seenSequences.has(header.sequence);
    });
    const concurrency = 12;
    let dropped = 0;
    for (let index = 0; index < cursors.length; index += concurrency) {
      const decoded = await Promise.all(
        cursors.slice(index, index + concurrency).map(async header => {
          try {
            return [header, await decodeCursorObject(header)];
          } catch (error) {
            // Retention evicts the oldest objects while this runs, so a
            // listed object can be gone by the time it is fetched. Replay is
            // best-effort by design: losing part of it must never cost the
            // live stream, which used to be abandoned along with it.
            dropped += 1;
            console.warn(`skipping cursor object ${header.sequence}:`, error);
            return null;
          }
        }),
      );
      for (const entry of decoded) {
        if (entry) commitCursorObject(entry[0], entry[1]);
      }
    }
    if (dropped > 0) {
      console.warn(`${dropped} retained cursor objects were unavailable and were skipped`);
    }
  }

  async function decodeCursorObject(header) {
    const epoch = state.epochs.get(header.epoch_id);
    if (!epoch?.descriptor || epoch.offset === null) {
      throw new Error(`Cursor object ${header.sequence} belongs to an unplayable epoch.`);
    }
    const payload = await fetchObject(header.sequence);
    await verifyObject(header, payload);
    const encrypted = ViewerCore.parseEncryptedCursorPayload(payload);
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: encrypted.nonce,
      additionalData: cursorAad(header, epoch.descriptor),
      tagLength: 128,
    }, epoch.keys.cursorKey, encrypted.ciphertext);
    const batch = ViewerCore.parseCursorBatch(new Uint8Array(plaintext), {
      sourceWidth: epoch.descriptor.width,
      sourceHeight: epoch.descriptor.height,
      startTimestamp: header.timestamp,
    });
    for (const event of batch.events) {
      event.timestamp += epoch.offset;
      event.epoch_id = header.epoch_id;
      event.source_width = epoch.descriptor.width;
      event.source_height = epoch.descriptor.height;
      event.bitmap_key = `${header.epoch_id}:${event.bitmap_id}`;
    }
    return batch;
  }

  function commitCursorObject(header, batch) {
    if (state.seenSequences.has(header.sequence)) return;
    for (const event of batch.events) {
      if (event.bitmap) cacheCursorBitmap(event.bitmap_key, event.bitmap);
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

  function cacheCursorBitmap(bitmapKey, bitmap) {
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
    state.cursorBitmaps.set(bitmapKey, {
      width: bitmap.width,
      height: bitmap.height,
      hotspot_x: bitmap.hotspot_x,
      hotspot_y: bitmap.hotspot_y,
      surface,
    });
  }

  function cursorAad(header, descriptor) {
    return concatBytes(
      encoder.encode('glacial-cursor-v1'),
      uuidToBytes(header.stream_id),
      uuidToBytes(header.epoch_id),
      unsignedBigEndian(header.sequence, 8),
      unsignedBigEndian(header.timestamp, 8),
      unsignedBigEndian(descriptor.width, 4),
      unsignedBigEndian(descriptor.height, 4),
    );
  }

  function connectLive() {
    if (destroyed) return;
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
    state.headers = headers;
    for (const header of headers.filter(header => header.kind === 'Epoch')) {
      const epoch = await loadEpochDescriptor(header);
      await installEpochKey(epoch);
    }

    for (const epochId of state.epochOrder) {
      const epoch = state.epochs.get(epochId);
      const media = headers.filter(
        header => header.kind === 'Media' && header.epoch_id === epochId,
      );
      if (media.length > 0) await appendEpochMedia(epoch, media);
    }
    await loadHistoricalCursors(headers);
    const latestPlayable = [...state.epochOrder]
      .reverse()
      .map(epochId => state.epochs.get(epochId))
      .find(epoch => epoch.offset !== null);
    if (latestPlayable) {
      state.descriptor = latestPlayable.descriptor;
      refreshStreamLabel();
    }

    const retainedSequences = new Set(headers.map(header => header.sequence));
    const listedHighWater = headers.at(-1)?.sequence || 0;
    state.seenSequences = new Set(
      [...state.seenSequences].filter(
        sequence => retainedSequences.has(sequence) || sequence > listedHighWater
      )
    );

    const firstRandomAccess = headers.find(
      header => header.kind === 'Media' && header.random_access
    );
    if (firstRandomAccess) {
      const epoch = state.epochs.get(firstRandomAccess.epoch_id);
      if (epoch?.offset !== null) {
        await trimPlaybackHistory(epoch.offset + firstRandomAccess.timestamp);
      }
    }
  }

  async function handleLiveHeader(header) {
    if (header.stream_id !== streamId || state.seenSequences.has(header.sequence)) return;
    if (!state.headers.some(candidate => candidate.sequence === header.sequence)) {
      state.headers.push(header);
      state.headers.sort((left, right) => left.sequence - right.sequence);
    }
    if (header.kind === 'Epoch') {
      const epoch = await loadEpochDescriptor(header);
      await installEpochKey(epoch);
      state.descriptor = epoch.descriptor;
      refreshStreamLabel();
      setStatus('A new capture epoch is ready.');
      return;
    }
    const epoch = state.epochs.get(header.epoch_id);
    if (!epoch) {
      await reconcileLiveHeaders();
      return;
    }
    if (header.kind === 'Media') {
      const media = state.headers.filter(
        candidate => candidate.kind === 'Media' && candidate.epoch_id === header.epoch_id,
      );
      await appendEpochMedia(epoch, media);
      await loadHistoricalCursors(
        state.headers.filter(candidate => candidate.epoch_id === header.epoch_id),
      );
      state.descriptor = epoch.descriptor;
      refreshStreamLabel();
    } else if (header.kind === 'Cursor') {
      if (epoch.offset !== null) await loadCursorObject(header);
    } else if (header.kind === 'Initialization') {
      const media = state.headers.filter(
        candidate => candidate.kind === 'Media' && candidate.epoch_id === header.epoch_id,
      );
      if (media.length > 0) await appendEpochMedia(epoch, media);
    }
  }

  function ensureEpochCursorBoundary(epoch) {
    if (epoch.cursorBoundaryAdded) return;
    const epochId = epoch.descriptor.epoch_id;
    state.cursorEvents = ViewerCore.mergeSortedCursorEvents(state.cursorEvents, [{
      timestamp: epoch.globalStart,
      x_micropixels: 0,
      y_micropixels: 0,
      visible: false,
      bitmap_id: 0,
      bitmap: null,
      epoch_id: epochId,
      source_width: epoch.descriptor.width,
      source_height: epoch.descriptor.height,
      bitmap_key: `${epochId}:0`,
    }]);
    epoch.cursorBoundaryAdded = true;
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
    if (destroyed) return;
    const canvas = els.cursorLayer;
    const ratio = globalThis.devicePixelRatio || 1;
    const width = Math.max(1, els.stage.clientWidth);
    const height = Math.max(1, els.stage.clientHeight);
    const canvasWidth = Math.round(width * ratio);
    const canvasHeight = Math.round(height * ratio);
    const event = currentCursorEvent();
    const bitmap = event?.visible ? state.cursorBitmaps.get(event.bitmap_key) : undefined;
    const layout = `${canvasWidth}:${canvasHeight}:${ratio}`;
    if (
      state.lastRenderedCursor === event
      && state.lastRenderedBitmap === bitmap
      && state.lastRenderLayout === layout
    ) {
      cursorFrame = requestAnimationFrame(renderCursor);
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
      const rectangle = containedVideoRectangle(
        width,
        height,
        event.source_width,
        event.source_height,
      );
      const scaleX = rectangle.width / event.source_width;
      const scaleY = rectangle.height / event.source_height;
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
    cursorFrame = requestAnimationFrame(renderCursor);
  }

  function currentCursorEvent() {
    if (!state.cursorEvents.length || !state.descriptor) return null;
    if (!state.live) {
      // Scrubbing history: the video clock is authoritative, because the cursor
      // has to line up with the frame the viewer is looking at.
      return ViewerCore.findCursorEvent(
        state.cursorEvents,
        els.video.currentTime * TIMESCALE,
        false,
      );
    }
    // Live: pace the batched samples against a wall clock instead of snapping to
    // the newest one, which would collapse each batch to a single position.
    const newest = state.cursorEvents[state.cursorEvents.length - 1].timestamp;
    const timestamp = state.cursorClock.sample(newest, performance.now());
    if (timestamp === null) return null;
    return ViewerCore.findCursorEvent(state.cursorEvents, timestamp, false);
  }

  function containedVideoRectangle(width, height, videoWidth, videoHeight) {
    return ViewerCore.containedVideoRectangle(
      width,
      height,
      videoWidth,
      videoHeight,
    );
  }

  function updateTimelineBounds() {
    if (!els.video.buffered.length) return;
    const start = els.video.buffered.start(0);
    const end = els.video.buffered.end(els.video.buffered.length - 1);
    if (els.timeline) els.timeline.min = String(start);
    if (els.timeline) els.timeline.max = String(end);
    if (state.mediaSource?.readyState === 'open' && state.mediaSource.setLiveSeekableRange) {
      state.mediaSource.setLiveSeekableRange(start, end);
    }
    updateTimeline();
  }

  function updateTimeline() {
    if (!state.live) if (els.timeline) els.timeline.value = String(els.video.currentTime);
    else if (els.video.buffered.length) {
      if (els.timeline) els.timeline.value = String(els.video.buffered.end(els.video.buffered.length - 1));
    }
    if (els.timeLabel) els.timeLabel.textContent = formatTime(els.video.currentTime);
  }

  function seekToLiveEdge() {
    if (!els.video.buffered.length) return;
    const end = els.video.buffered.end(els.video.buffered.length - 1);
    els.video.currentTime = Math.max(0, end - 0.05);
    els.video.play().catch(() => {});
    updateTimeline();
  }

  function updateMetrics() {
    const playableEpochs = [...state.epochs.values()]
      .filter(epoch => epoch.offset !== null)
      .length;
    if (els.metrics) els.metrics.textContent =
      `${state.appendedMedia} media fragments · ${state.cursorEvents.length} cursor events`
      + ` · ${playableEpochs} capture epoch${playableEpochs === 1 ? '' : 's'}`;
  }

  function refreshStreamLabel() {
    const descriptor = state.descriptor;
    if (!descriptor) return;
    if (els.streamLabel) els.streamLabel.textContent =
      `${streamId} · ${descriptor.width}×${descriptor.height} · ${descriptor.codec}`;
  }

  function setStatus(message) {
    els.status?.classList.remove('error');
    if (els.status) els.status.textContent = message;
    onStatus({ streamId, message, error: false });
  }

  function showError(error) {
    console.error(error);
    const message = error?.message || String(error);
    els.status?.classList.add('error');
    if (els.status) els.status.textContent = message;
    if (els.stageMessage) els.stageMessage.textContent = message;
    onStatus({ streamId, message, error: true });
  }


  return {
    streamId,
    start(viewerKeyText) {
      return start(viewerKeyText).catch(error => {
        showError(error);
        throw error;
      });
    },
    metrics() {
      const newest = state.cursorEvents.at(-1) || null;
      // Report what the last frame drew rather than asking for a fresh
      // decision: the clock advances when sampled, so a caller polling this
      // would otherwise pull the overlay's own playback forward.
      const shown = state.lastRenderedCursor || null;
      return {
        appendedMedia: state.appendedMedia,
        cursorEvents: state.cursorEvents.length,
        epochs: state.epochOrder.length,
        live: state.live,
        // Cursor selection state, which is otherwise invisible from outside
        // and is where overlay problems actually live.
        cursor: {
          newestTimestamp: newest?.timestamp ?? null,
          newestVisible: newest?.visible ?? null,
          shownTimestamp: shown?.timestamp ?? null,
          shownVisible: shown?.visible ?? null,
          shownBitmapKey: shown?.bitmap_key ?? null,
          bitmapsCached: state.cursorBitmaps.size,
        },
      };
    },
    destroy() {
      destroyed = true;
      if (cursorFrame !== null) cancelAnimationFrame(cursorFrame);
      clearTimeout(state.liveReconnectTimer);
      clearInterval(state.liveReconcileTimer);
      const socket = state.liveSocket;
      state.liveSocket = null;
      socket?.close();
      try {
        if (state.mediaSource?.readyState === 'open') state.mediaSource.endOfStream();
      } catch {
        // A MediaSource torn down mid-append rejects endOfStream; the element
        // is being discarded regardless.
      }
      if (els.video) {
        els.video.pause();
        els.video.removeAttribute('src');
        els.video.load();
      }
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      state.cursorBitmaps.clear();
      state.cursorEvents = [];
    },
  };
}

/**
 * Reports whether `viewerKey` really opens `streamId`.
 *
 * A key is right or wrong before any tile is built, so the viewer can say "that
 * key does not open this stream" instead of starting a player that fails
 * halfway through with a decoding error. The check is the same authentication
 * the player performs on every object: derive the epoch keys and verify one
 * epoch descriptor's HMAC. That costs a single small fetch.
 */
async function verifyViewerKey(streamId, viewerKey) {
  const response = await fetch(`/api/dash/streams/${streamId}/objects`, { cache: 'no-store' });
  if (!response.ok) return false;
  const headers = await response.json();
  const epoch = headers
    .filter(header => header.kind === 'Epoch')
    .sort((left, right) => right.sequence - left.sequence)[0];
  // A stream that has not published an epoch yet cannot confirm or deny the
  // key. Treat that as "no reason to reject" rather than as a wrong key.
  if (!epoch) return true;

  const payloadResponse = await fetch(
    `/api/dash/streams/${streamId}/objects/${epoch.sequence}`,
  );
  if (!payloadResponse.ok) return false;
  const payload = new Uint8Array(await payloadResponse.arrayBuffer());

  const saltInput = concatBytes(
    new TextEncoder().encode('glacialcast epoch key salt'),
    uuidToBytes(streamId),
    uuidToBytes(epoch.epoch_id),
  );
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', saltInput));
  const inputKey = await crypto.subtle.importKey('raw', viewerKey, 'HKDF', false, ['deriveBits']);
  const material = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt,
    info: new TextEncoder().encode('glacialcast dash epoch keys v1'),
  }, inputKey, 80 * 8));
  const authenticationKey = await crypto.subtle.importKey(
    'raw',
    material.slice(48, 80),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  return crypto.subtle.verify(
    'HMAC',
    authenticationKey,
    new Uint8Array(epoch.authentication_tag),
    concatBytes(authenticationBytes(epoch), payload),
  );
}

if (typeof globalThis !== 'undefined') {
  globalThis.GlacialCastPlayer = { createPlayer, verifyViewerKey };
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
