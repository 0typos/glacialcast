'use strict';


const TIMESCALE = 90000;
const FORMAT_VERSION = 1;
const LIVE_RECONCILE_INTERVAL_MS = 15_000;
const ViewerCore = globalThis.GlacialCastViewerCore;
if (!ViewerCore) throw new Error('The GlacialCast viewer core failed to load.');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Whether the page has started going away.
 *
 * Navigating cancels every request in flight, and the rejections that produces
 * are the browser tearing the page down rather than any stream failing. They
 * arrive before the tiles are destroyed -- nothing has destroyed them, the page
 * is simply leaving -- so a per-player `destroyed` flag does not cover this and
 * the failures were reported against streams that were fine.
 *
 * Module-level because it is a property of the page, not of one player.
 *
 * `beforeunload` is the one that is early enough. Measured in Firefox against
 * three tiles with requests in flight, it arrives 1ms before the rejections and
 * `pagehide` arrives 9ms after them, so a `pagehide` handler sets this flag
 * only once the errors have already been reported. Both are registered because
 * `beforeunload` is not guaranteed on every path a page can leave by, and the
 * listener only sets a flag -- it neither calls `preventDefault` nor sets
 * `returnValue`, so it does not raise a "leave site?" prompt.
 */
let pageUnloading = false;
for (const event of ['beforeunload', 'pagehide']) {
  globalThis.addEventListener?.(event, () => {
    pageUnloading = true;
  });
}

/**
 * Mounts one DASH player inside `root`.
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

/**
 * A stream the relay knows about that has nothing playable in it yet.
 *
 * This is an ordinary state rather than a fault. The relay registers a stream
 * the moment the publisher connects, and on GNOME and KDE that happens before
 * anyone has accepted the screen-sharing prompt, so the first viewer to arrive
 * finds a live stream with no media behind it. Retention reaching the end of an
 * idle stream looks the same from here.
 *
 * It used to be reported as a hard failure, which left a black tile carrying an
 * internal string until the page was reloaded by hand. Marking it retryable lets
 * the caller wait for the stream to start instead.
 */
function streamNotReadyError() {
  const error = new Error(
    'Waiting for this screen to start sending. If the publisher has just '
    + 'started this clears on its own; on GNOME and KDE it is waiting for the '
    + 'screen-sharing prompt to be accepted on the publisher’s machine.',
  );
  error.retryable = true;
  return error;
}

/**
 * The MediaSource flavour to play a stream of this kind with, or `null`.
 *
 * Ordinary `MediaSource` wherever it exists, which is every desktop browser,
 * Android, and iPad. `ManagedMediaSource` is taken only where there is no
 * ordinary one at all -- that is, on iPhones -- so no platform that already
 * works changes path. It cannot carry an encrypted stream in any case: it
 * arrived with iOS 17.1, and WebKit's Encrypted Media Extensions offer
 * FairPlay and never ClearKey, so an iPhone can play a stream published in the
 * clear and no other kind.
 */
function mediaSourceConstructor(encrypted) {
  if (globalThis.MediaSource) return globalThis.MediaSource;
  if (!encrypted && globalThis.ManagedMediaSource) return globalThis.ManagedMediaSource;
  return null;
}

function isAppleMobile() {
  return 'ManagedMediaSource' in globalThis
    || /iPhone|iPod|iPad/.test(globalThis.navigator?.userAgent ?? '');
}

/**
 * Why this browser cannot play a stream of this kind here, or `null` if it can.
 *
 * `encrypted` says which kind is being asked about, because the answer differs.
 * An end-to-end encrypted stream needs Encrypted Media Extensions and ClearKey
 * inside them; a stream a publisher sent in the clear to a trusted LAN needs
 * neither. That difference is the whole reason an iPhone can play the second
 * kind and can never play the first.
 *
 * Module-level and returning rather than throwing, so the page can ask before
 * it offers to do anything. The order matters: a plaintext origin that is not
 * loopback is not a secure context, and browsers withhold Web Crypto there, so
 * `crypto.subtle` is missing for a reason worth naming. Deriving a key touches
 * `crypto.subtle` before any player exists, so checking only inside the player
 * meant the first thing a viewer saw was `undefined is not an object (reading
 * 'importKey')` -- true, and useless.
 *
 * A secure context is required of both kinds, not only the encrypted one. Every
 * object carries a SHA-256 of its payload and the viewer checks it, which is
 * what catches a truncated or corrupted fragment before it reaches the decoder,
 * and `crypto.subtle.digest` is withheld outside a secure context along with
 * everything else. The relay can serve its own HTTPS, so this costs a flag
 * rather than a second server.
 */
function platformProblem(options = {}) {
  const encrypted = options.encrypted !== false;
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    return 'This page must be reached over HTTPS, or at a loopback address, '
      + 'before it can play a stream. Browsers withhold the cryptography this '
      + 'needs to check what it receives on a plain http:// address that is '
      + 'not localhost. Start the relay with --tls-cert, or forward its port '
      + 'over SSH to your own machine.';
  }
  if (!mediaSourceConstructor(encrypted)) {
    // Every iOS browser is WebKit underneath, whatever its name, so "use
    // Chrome" is not advice that helps there. Say what is actually missing.
    if (isAppleMobile()) {
      return encrypted
        ? 'iPhone and iPad browsers cannot play an end-to-end encrypted '
          + 'stream: WebKit offers FairPlay decryption and never the ClearKey '
          + 'these use, in any browser on the device. A publisher on a trusted '
          + 'LAN can send in the clear with --no-encryption, which does play '
          + 'here; otherwise use a desktop or Android browser.'
        : 'This iPhone is running a version of iOS too old to play a stream '
          + 'this way. The media API it needs, ManagedMediaSource, arrived in '
          + 'iOS 17.1.';
    }
    return 'Media Source Extensions are unavailable.';
  }
  if (encrypted && !globalThis.navigator?.requestMediaKeySystemAccess) {
    return 'Encrypted Media Extensions are unavailable.';
  }
  return null;
}

function createPlayer(root, options) {
  const streamId = options.streamId;
  const onStatus = options.onStatus || (() => {});
  let destroyed = false;
  let cursorFrame = null;
  let objectUrl = null;
  // Aborted when the player is destroyed, so a request still in flight ends
  // with the tile rather than outliving it. Closing the socket was never
  // enough: the reconcile pass fetches over plain HTTP, and a fetch left
  // running past teardown rejects into the live queue's catch and gets
  // reported as if the stream had failed.
  const teardown = new AbortController();

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
    // Which flavour of MediaSource this stream is playing through, settled once
    // `start` knows whether the stream is encrypted.
    mediaSourceClass: null,
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
    cursorBatches: 0,
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

  /**
   * Starts playback, with `viewerKeyText` or with `null` for a stream the
   * publisher sent in the clear.
   *
   * Which of those it is decides almost everything below -- whether keys are
   * derived, whether Encrypted Media Extensions are touched at all, and which
   * MediaSource carries the video -- so it is settled here, once, rather than
   * rediscovered at each step.
   */
  async function start(viewerKeyText) {
    setStatus('Loading stream metadata…');
    const encrypted = viewerKeyText !== null && viewerKeyText !== undefined;
    const problem = platformProblem({ encrypted });
    if (problem) throw new Error(problem);
    state.viewerKey = encrypted ? base64UrlToBytes(viewerKeyText, 32) : null;
    state.mediaSourceClass = mediaSourceConstructor(encrypted);
    const headers = await fetchHeaders();
    state.headers = headers;
    await loadEpochDescriptors(headers);
    const timeline = installInitialEpochTimeline(headers);
    if (timeline.length === 0) {
      throw streamNotReadyError();
    }
    state.descriptor = state.epochs.get(timeline.at(-1).epoch_id).descriptor;
    const descriptor = state.descriptor;
    if (els.streamLabel) els.streamLabel.textContent = `${streamId} · ${descriptor.width}×${descriptor.height} · ${descriptor.codec}`;

    ensureContentTypesSupported();
    if (encrypted) {
      await initializeKeySystem();
      for (const epochId of state.epochOrder) {
        await installEpochKey(state.epochs.get(epochId));
      }
    }
    await initializeMediaSource(timeline);

    if (els.unlockPanel) els.unlockPanel.hidden = true;
    if (els.playerPanel) els.playerPanel.hidden = false;
    // Live first: replaying history can take a while on a long retention
    // window, and nothing about it should delay or endanger the live cursor.
    connectLive();
    setStatus(encrypted
      ? 'Live encrypted DASH playback ready.'
      : 'Live DASH playback ready. This stream is not encrypted.');
    updateMetrics();
    await loadHistoricalCursors(headers);
    updateMetrics();
  }

  async function loadEpochDescriptors(headers) {
    const epochHeaders = headers.filter(header => header.kind === 'Epoch');
    if (epochHeaders.length === 0) {
      throw streamNotReadyError();
    }
    // An epoch this viewer cannot open is skipped rather than fatal. Retained
    // history can outlive a viewer key — rotating one leaves the relay holding
    // objects encrypted to the old key for the rest of the retention window —
    // and a viewer holding the current key must still be able to watch the
    // current stream. Failing the whole load would make a rotated key look
    // broken until the old history aged out. A publisher that switched between
    // encrypted and clear leaves the same kind of unopenable history behind.
    const failures = [];
    for (const header of epochHeaders) {
      try {
        await loadEpochDescriptor(header);
      } catch (error) {
        failures.push(error);
      }
    }
    if (state.epochOrder.length === 0) {
      throw failures[0] ?? new Error('No stream epoch could be opened.');
    }
    if (failures.length > 0) {
      console.info(`Skipped ${failures.length} epoch(s) this viewer cannot open.`);
    }
  }

  /**
   * Loads and opens one epoch descriptor.
   *
   * The order here is forced by what the descriptor is for. An epoch published
   * without a viewer key has no key to derive an authentication tag from, so
   * its objects carry none -- and whether to expect one is a question only the
   * descriptor answers. So the payload is read before it is authenticated.
   *
   * Nothing the parse produces is trusted before that check. The JSON
   * contributes exactly one boolean, which chooses between "verify the tag" and
   * "there is no tag"; every other field is validated and stored only after the
   * chosen verification has passed. A relay that flips the boolean on a stream
   * this viewer holds a key for is caught by `requireMatchingEncryption` before
   * even that much, and one that flips it the other way fails the tag check.
   * The payload's own SHA-256 is checked first either way, so the parser never
   * sees bytes that do not match the header describing them.
   */
  async function loadEpochDescriptor(header) {
    if (state.epochs.has(header.epoch_id)) return state.epochs.get(header.epoch_id);
    const payload = await fetchObject(header.sequence);
    await verifyObjectIntegrity(header, payload);
    const descriptor = JSON.parse(decoder.decode(payload));
    // Absent means encrypted: the only descriptors without the field predate it.
    const encrypted = descriptor.encrypted !== false;
    requireMatchingEncryption(encrypted, header);
    const keys = encrypted
      ? await deriveEpochKeys(state.viewerKey, streamId, header.epoch_id)
      : null;
    await authenticateObject(header, payload, keys);
    validateDescriptor(descriptor, header);
    const epoch = {
      descriptor,
      keys,
      encrypted,
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
    state.seenSequences.add(header.sequence);
    return epoch;
  }

  /**
   * Refuses an epoch whose encryption does not match what this viewer started
   * with.
   *
   * Both directions matter, and the second one is the point. Holding a viewer
   * key and being handed an epoch published in the clear is a relay stripping
   * the encryption from a stream -- serving whatever bytes it likes, with no
   * tag to fail, to a viewer who believes the key is protecting them. Detecting
   * exactly that is what the key is for, so the epoch is refused rather than
   * played with a note. The other direction is only a viewer without the key it
   * needs, which is worth saying plainly.
   *
   * Refusing is per-epoch, not per-stream: a publisher that changed modes
   * leaves retained history of the other kind, and that history must not stop
   * the current epoch from playing.
   */
  function requireMatchingEncryption(encrypted, header) {
    if (encrypted === (state.viewerKey !== null)) return;
    if (encrypted) {
      throw new Error(
        `Epoch ${header.epoch_id} is end-to-end encrypted and needs a viewing key.`,
      );
    }
    throw new Error(
      `Epoch ${header.epoch_id} was published without encryption, but this `
      + 'viewer holds a key for the stream. Refusing it: a relay that can strip '
      + 'the encryption from a stream you hold a key for is what the key is '
      + 'there to catch.',
    );
  }

  function installInitialEpochTimeline(headers) {
    // Only epochs that authenticated get a place on the timeline; objects
    // belonging to a skipped epoch are not playable and must not reserve time.
    const timeline = ViewerCore.buildEpochTimeline(
      headers.filter(header => state.epochs.has(header.epoch_id)),
    );
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

  async function fetchHeaders() {
    const response = await fetch(`/api/dash/streams/${streamId}/objects`, {
      cache: 'no-store',
      signal: teardown.signal,
    });
    if (!response.ok) throw new Error(await response.text() || 'Unable to list DASH objects.');
    const headers = await response.json();
    headers.sort((left, right) => left.sequence - right.sequence);
    return headers;
  }

  async function fetchObject(sequence) {
    const response = await fetch(`/api/dash/streams/${streamId}/objects/${sequence}`, {
      signal: teardown.signal,
    });
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

  /**
   * Checks that a payload is the one its header describes.
   *
   * Everything an object claims about itself that needs no key: the format, the
   * stream, the length, and the payload hash. An epoch published without a
   * viewer key has only this, which catches a truncated or corrupted object but
   * makes no claim about who produced it.
   */
  async function verifyObjectIntegrity(header, payload) {
    if (header.format_version !== FORMAT_VERSION) {
      throw new Error(`Unsupported DASH object version ${header.format_version}.`);
    }
    if (header.stream_id !== streamId) {
      throw new Error(`Object ${header.sequence} belongs to a different stream.`);
    }
    if (payload.byteLength !== header.payload_len) {
      throw new Error(`Object ${header.sequence} has an invalid payload length.`);
    }
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
    if (!equalBytes(digest, new Uint8Array(header.payload_sha256))) {
      throw new Error(`Object ${header.sequence} failed its SHA-256 check.`);
    }
  }

  /**
   * Verifies the keyed claim about who produced an object.
   *
   * `keys` is null for an epoch published in the clear, which carries no tag to
   * check. That is the whole of the difference between the two modes: integrity
   * is checked either way, and only this end-to-end claim is given up.
   */
  async function authenticateObject(header, payload, keys) {
    if (!keys) return;
    const authenticated = concatBytes(authenticationBytes(header), payload);
    const valid = await crypto.subtle.verify(
      'HMAC',
      keys.authenticationKey,
      new Uint8Array(header.authentication_tag),
      authenticated,
    );
    if (!valid) throw new Error(`Object ${header.sequence} failed authentication.`);
  }

  async function verifyObject(header, payload) {
    await verifyObjectIntegrity(header, payload);
    const epoch = state.epochs.get(header.epoch_id);
    if (!epoch) throw new Error(`Object ${header.sequence} belongs to an unknown stream epoch.`);
    await authenticateObject(header, payload, epoch.keys);
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

  function playableContentTypes() {
    return [...new Set(state.epochOrder.map(
      epochId => contentTypeForDescriptor(state.epochs.get(epochId).descriptor),
    ))];
  }

  /**
   * Rejects a codec the browser will not decode, before a MediaSource exists.
   *
   * Asked of whichever MediaSource this stream is playing through, because
   * ManagedMediaSource answers for itself and an iPhone has no other one to
   * ask.
   */
  function ensureContentTypesSupported() {
    for (const contentType of playableContentTypes()) {
      if (!state.mediaSourceClass.isTypeSupported(contentType)) {
        throw new Error(`This browser cannot play ${contentType}.`);
      }
    }
  }

  async function initializeKeySystem() {
    const contentTypes = playableContentTypes();
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
      // Safari passes the capability check -- requestMediaKeySystemAccess
      // exists for FairPlay -- and then refuses ClearKey here, on iPad and on
      // macOS alike. That refusal deserves a sentence, not a bare
      // NotSupportedError.
      access = await navigator.requestMediaKeySystemAccess('org.w3.clearkey', configuration)
        .catch(() => {
          throw new Error(
            'This browser does not offer ClearKey decryption, which these '
            + 'end-to-end encrypted streams need. Safari, and every browser '
            + 'on iOS, offers only FairPlay; use Firefox or a Chromium '
            + `browser instead. (${error.message || error})`,
          );
        });
    }
    state.mediaKeys = await access.createMediaKeys();
    await els.video.setMediaKeys(state.mediaKeys);
  }

  async function installEpochKey(epoch) {
    // An epoch published in the clear has no key to install, and on the
    // platforms that mode exists for there is no key system to install it into.
    if (!epoch.keys) return;
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
    const mediaSource = new state.mediaSourceClass();
    state.mediaSource = mediaSource;
    if (state.mediaSourceClass === globalThis.ManagedMediaSource) {
      // ManagedMediaSource attaches through srcObject, not an object URL, and
      // refuses an element that could hand playback to an AirPlay receiver.
      //
      // It also differs from an ordinary MediaSource in when it opens: it is
      // managed, so it stays closed until the element actually wants data
      // rather than opening as soon as something is attached to it. Nothing
      // below asks for data, so waiting for `sourceopen` on a paused element
      // waits forever. Starting playback is what makes the browser ask. The
      // element is muted and playsinline, so this is allowed without a gesture;
      // if a browser blocks it anyway the Live button is the way back, exactly
      // as it is for the ordinary path.
      els.video.disableRemotePlayback = true;
      els.video.srcObject = mediaSource;
      els.video.play().catch(() => {});
    } else {
      objectUrl = URL.createObjectURL(mediaSource);
      els.video.src = objectUrl;
    }
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
        && ViewerCore.isPlayableEpoch(epoch)
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
    if (!ViewerCore.isPlayableEpoch(epoch) || !epoch.descriptor) {
      throw new Error(`Cursor object ${header.sequence} belongs to an unplayable epoch.`);
    }
    const payload = await fetchObject(header.sequence);
    await verifyObject(header, payload);
    // An epoch with no key carries the encoded batch directly, with none of the
    // GCE1 envelope around it. The batch inside is the same either way, and so
    // is the validation it goes through.
    const encoded = epoch.keys ? await decryptCursorPayload(header, epoch, payload) : payload;
    const batch = ViewerCore.parseCursorBatch(encoded, {
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

  async function decryptCursorPayload(header, epoch, payload) {
    const encrypted = ViewerCore.parseEncryptedCursorPayload(payload);
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: encrypted.nonce,
      additionalData: cursorAad(header, epoch.descriptor),
      tagLength: 128,
    }, epoch.keys.cursorKey, encrypted.ciphertext);
    return new Uint8Array(plaintext);
  }

  function commitCursorObject(header, batch) {
    if (state.seenSequences.has(header.sequence)) return;
    for (const event of batch.events) {
      if (event.bitmap) cacheCursorBitmap(event.bitmap_key, event.bitmap);
    }
    state.cursorEvents = ViewerCore.mergeSortedCursorEvents(state.cursorEvents, batch.events);
    state.seenSequences.add(header.sequence);
    state.cursorBatches += 1;
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
    state.liveQueue = state.liveQueue.then(task).catch(reportUnlessTornDown);
    return state.liveQueue;
  }

  /**
   * Reports a live-queue failure unless the player caused it by shutting down.
   *
   * A tile that is going away aborts its own requests, and the rejection that
   * produces is the teardown working, not the stream failing. Without this it
   * reached `showError`, which paints the message onto the tile and writes it
   * to the console -- so navigating away or pressing "Forget keys" while a
   * reconcile was in flight logged `NetworkError when attempting to fetch
   * resource` against a stream that was fine.
   */
  function reportUnlessTornDown(error) {
    if (pageUnloading || destroyed || teardown.signal.aborted) return;
    if (error?.name === 'AbortError') return;
    showError(error);
  }

  async function reconcileLiveHeaders() {
    const headers = await fetchHeaders();
    state.headers = headers;
    for (const header of headers.filter(header => header.kind === 'Epoch')) {
      // Same reasoning as the initial load: an epoch this key cannot open is
      // skipped, not fatal, so retained history from a rotated key does not
      // stop live playback.
      let epoch;
      try {
        epoch = await loadEpochDescriptor(header);
      } catch {
        continue;
      }
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
      // The oldest retained random-access point can belong to an epoch this key
      // cannot open, which is absent from the epoch map rather than present and
      // empty. Trimming to it is an optimisation; skipping it costs nothing.
      const epoch = state.epochs.get(firstRandomAccess.epoch_id);
      if (ViewerCore.isPlayableEpoch(epoch)) {
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
    const message = error?.message || String(error);
    // The stream and the message both go in the text, not only in the object.
    // A console holding several players' failures is unreadable when every line
    // renders as the word "Error", and that is the view anyone debugging this
    // from a browser actually has.
    console.error(`glacialcast ${streamId}: ${message}`, error);
    els.status?.classList.add('error');
    if (els.status) els.status.textContent = message;
    if (els.stageMessage) els.stageMessage.textContent = message;
    onStatus({ streamId, message, error: true });
  }


  return {
    streamId,
    start(viewerKeyText) {
      return start(viewerKeyText).catch(error => {
        // A start interrupted by teardown is the same non-event as an
        // interrupted reconcile, and the caller's retry path already ignores a
        // tile it has moved on from.
        reportUnlessTornDown(error);
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
        encrypted: state.viewerKey !== null,
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
      teardown.abort();
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
        // The ManagedMediaSource path attaches here instead of through src, so
        // clearing only the attribute would leave the source attached to a
        // tile that is going away.
        els.video.srcObject = null;
        els.video.load();
      }
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      state.cursorBitmaps.clear();
      state.cursorEvents = [];
    },
  };
}

/**
 * Fetches the newest epoch descriptor of `streamId`, or null if it has none.
 *
 * The two questions a page asks before it builds a tile -- is this stream
 * encrypted, and does this key open it -- are both answered by the same
 * object, so they share the two fetches it takes to get it.
 */
async function latestEpochObject(streamId) {
  const response = await fetch(`/api/dash/streams/${streamId}/objects`, { cache: 'no-store' });
  if (!response.ok) return null;
  const headers = await response.json();
  const header = headers
    .filter(candidate => candidate.kind === 'Epoch')
    .sort((left, right) => right.sequence - left.sequence)[0];
  if (!header) return null;
  const payloadResponse = await fetch(
    `/api/dash/streams/${streamId}/objects/${header.sequence}`,
  );
  if (!payloadResponse.ok) return null;
  return { header, payload: new Uint8Array(await payloadResponse.arrayBuffer()) };
}

/**
 * Whether `streamId` is published encrypted: true, false, or null when nothing
 * has been published yet to tell from.
 *
 * Read from the epoch descriptor rather than from the stream listing, because
 * the descriptor is what the publisher wrote and the listing is what the relay
 * says. A relay that answers this dishonestly gains nothing: claiming a stream
 * is in the clear only makes the page skip a key prompt, and the player then
 * refuses every encrypted epoch and says so, while claiming a clear stream is
 * encrypted only produces a key prompt that nothing satisfies. The player, not
 * this, is where the decision is enforced.
 */
async function describeStream(streamId) {
  try {
    const object = await latestEpochObject(streamId);
    if (!object) return { encrypted: null };
    const descriptor = JSON.parse(new TextDecoder().decode(object.payload));
    // Absent means encrypted: the only descriptors without the field predate it.
    return { encrypted: descriptor.encrypted !== false };
  } catch {
    // A stream whose descriptor cannot be read is not one to guess about.
    return { encrypted: null };
  }
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
  const object = await latestEpochObject(streamId);
  // A stream that has not published an epoch yet cannot confirm or deny the
  // key. Treat that as "no reason to reject" rather than as a wrong key.
  if (!object) return true;
  const { header: epoch, payload } = object;

  // A stream published in the clear is not opened by any key, however good the
  // key is. Saying so here is what keeps a viewer who holds a key for some
  // other publisher from claiming this stream and then refusing to play it.
  try {
    if (JSON.parse(new TextDecoder().decode(payload)).encrypted === false) return false;
  } catch {
    // Not readable as a descriptor; let the authentication below answer.
  }

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
  globalThis.GlacialCastPlayer = {
    createPlayer,
    verifyViewerKey,
    describeStream,
    platformProblem,
  };
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
