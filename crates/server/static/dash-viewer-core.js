'use strict';

(function installViewerCore(root, factory) {
  const core = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  } else {
    root.GlacialCastViewerCore = core;
  }
}(typeof globalThis === 'undefined' ? this : globalThis, () => {
  const MAX_CURSOR_PAYLOAD = 4 * 1024 * 1024;
  const ENCRYPTED_CURSOR_HEADER_LENGTH = 16;
  const AES_GCM_TAG_LENGTH = 16;
  const MAX_CURSOR_PLAINTEXT =
    MAX_CURSOR_PAYLOAD - ENCRYPTED_CURSOR_HEADER_LENGTH - AES_GCM_TAG_LENGTH;
  const CURSOR_BATCH_HEADER_LENGTH = 14;
  const CURSOR_EVENT_LENGTH = 33;
  const MAX_CURSOR_BITMAP_SIDE = 512;
  const MAX_SOURCE_EXTENT = 65535;
  const MICROPIXELS_PER_PIXEL = 1_000_000;

  function requireBytes(bytes, label) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError(`${label} must be a Uint8Array.`);
    }
  }

  function hasMagic(bytes, magic) {
    return magic.length === 4
      && bytes[0] === magic.charCodeAt(0)
      && bytes[1] === magic.charCodeAt(1)
      && bytes[2] === magic.charCodeAt(2)
      && bytes[3] === magic.charCodeAt(3);
  }

  function parseEncryptedCursorPayload(bytes) {
    requireBytes(bytes, 'Encrypted cursor payload');
    if (
      bytes.byteLength < ENCRYPTED_CURSOR_HEADER_LENGTH + AES_GCM_TAG_LENGTH
      || bytes.byteLength > MAX_CURSOR_PAYLOAD
      || !hasMagic(bytes, 'GCE1')
    ) {
      throw new Error('The encrypted cursor payload is malformed.');
    }
    return {
      nonce: bytes.subarray(4, ENCRYPTED_CURSOR_HEADER_LENGTH),
      ciphertext: bytes.subarray(ENCRYPTED_CURSOR_HEADER_LENGTH),
    };
  }

  function parseCursorBatch(bytes, expected = null) {
    requireBytes(bytes, 'Decrypted cursor batch');
    if (bytes.byteLength > MAX_CURSOR_PLAINTEXT) {
      throw new Error('The decrypted cursor batch exceeds its size limit.');
    }

    let offset = 0;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ensure = length => {
      if (
        !Number.isSafeInteger(length)
        || length < 0
        || length > bytes.byteLength - offset
      ) {
        throw new Error('The decrypted cursor batch is truncated.');
      }
    };
    const take = length => {
      ensure(length);
      const value = bytes.subarray(offset, offset + length);
      offset += length;
      return value;
    };
    const u8 = () => {
      ensure(1);
      const value = view.getUint8(offset);
      offset += 1;
      return value;
    };
    const u16 = () => {
      ensure(2);
      const value = view.getUint16(offset);
      offset += 2;
      return value;
    };
    const u32 = () => {
      ensure(4);
      const value = view.getUint32(offset);
      offset += 4;
      return value;
    };
    const i32 = () => {
      ensure(4);
      const value = view.getInt32(offset);
      offset += 4;
      return value;
    };
    const safeInteger = (value, field) => {
      const number = Number(value);
      if (!Number.isSafeInteger(number)) {
        throw new Error(`Cursor ${field} exceeds JavaScript's safe integer range.`);
      }
      return number;
    };
    const u64 = field => {
      ensure(8);
      const value = view.getBigUint64(offset);
      offset += 8;
      return safeInteger(value, field);
    };
    const i64 = field => {
      ensure(8);
      const value = view.getBigInt64(offset);
      offset += 8;
      return safeInteger(value, field);
    };

    if (!hasMagic(take(4), 'GCC1')) {
      throw new Error('The decrypted cursor batch has an unknown version.');
    }
    const sourceWidth = u32();
    const sourceHeight = u32();
    const eventCount = u16();
    if (
      sourceWidth < 1
      || sourceHeight < 1
      || sourceWidth > MAX_SOURCE_EXTENT
      || sourceHeight > MAX_SOURCE_EXTENT
      || eventCount < 1
    ) {
      throw new Error('The decrypted cursor batch has invalid dimensions or event count.');
    }
    if (bytes.byteLength - offset < eventCount * CURSOR_EVENT_LENGTH) {
      throw new Error('The decrypted cursor batch is truncated.');
    }

    const maxX = sourceWidth * MICROPIXELS_PER_PIXEL;
    const maxY = sourceHeight * MICROPIXELS_PER_PIXEL;
    let previousTimestamp = null;
    const events = [];
    for (let index = 0; index < eventCount; index += 1) {
      const timestamp = u64('timestamp');
      const xMicropixels = i64('x coordinate');
      const yMicropixels = i64('y coordinate');
      const flags = u8();
      if (flags & ~0b11) throw new Error('The cursor event has unsupported flags.');
      const visible = Boolean(flags & 1);
      const bitmapId = u64('bitmap ID');
      let bitmap = null;
      if (flags & (1 << 1)) {
        const width = u32();
        const height = u32();
        const hotspotX = i32();
        const hotspotY = i32();
        const rgbaLength = u32();
        const expectedLength = width * height * 4;
        if (
          bitmapId === 0
          || width < 1
          || height < 1
          || width > MAX_CURSOR_BITMAP_SIDE
          || height > MAX_CURSOR_BITMAP_SIDE
          || hotspotX < 0
          || hotspotY < 0
          || hotspotX >= width
          || hotspotY >= height
          || !Number.isSafeInteger(expectedLength)
          || rgbaLength !== expectedLength
        ) {
          throw new Error('The cursor bitmap has invalid dimensions or metadata.');
        }
        bitmap = {
          width,
          height,
          hotspot_x: hotspotX,
          hotspot_y: hotspotY,
          rgba: take(rgbaLength),
        };
      }
      if (previousTimestamp !== null && timestamp < previousTimestamp) {
        throw new Error('Cursor event timestamps are not ordered.');
      }
      if (
        visible
        && (
          xMicropixels < 0
          || yMicropixels < 0
          || xMicropixels > maxX
          || yMicropixels > maxY
        )
      ) {
        throw new Error('The cursor event is outside the source dimensions.');
      }
      if (!visible && (xMicropixels !== 0 || yMicropixels !== 0 || bitmap !== null)) {
        throw new Error('A hidden cursor event contains visible cursor state.');
      }
      previousTimestamp = timestamp;
      events.push({
        timestamp,
        x_micropixels: xMicropixels,
        y_micropixels: yMicropixels,
        visible,
        bitmap_id: bitmapId,
        bitmap,
      });
    }
    if (offset !== bytes.byteLength) {
      throw new Error('The decrypted cursor batch has trailing data.');
    }
    if (
      expected
      && (
        sourceWidth !== expected.sourceWidth
        || sourceHeight !== expected.sourceHeight
        || events[0].timestamp !== expected.startTimestamp
      )
    ) {
      throw new Error('The cursor batch does not match its authenticated context.');
    }
    return {
      source_width: sourceWidth,
      source_height: sourceHeight,
      events,
    };
  }

  function mergeSortedCursorEvents(existing, incoming) {
    if (existing.length === 0) return incoming.slice();
    if (incoming.length === 0) return existing;
    if (existing[existing.length - 1].timestamp <= incoming[0].timestamp) {
      existing.push(...incoming);
      return existing;
    }
    const merged = [];
    let left = 0;
    let right = 0;
    while (left < existing.length && right < incoming.length) {
      if (existing[left].timestamp <= incoming[right].timestamp) {
        merged.push(existing[left]);
        left += 1;
      } else {
        merged.push(incoming[right]);
        right += 1;
      }
    }
    merged.push(...existing.slice(left), ...incoming.slice(right));
    return merged;
  }

  function findCursorEvent(events, timestamp, live = false) {
    if (events.length === 0) return null;
    if (live) return events[events.length - 1];
    let low = 0;
    let high = events.length - 1;
    let found = null;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      if (events[middle].timestamp <= timestamp) {
        found = events[middle];
        low = middle + 1;
      } else {
        high = middle - 1;
      }
    }
    return found;
  }

  // Cursor timestamps are carried on the 90 kHz media timescale.
  const CURSOR_TICKS_PER_MS = 90;
  // How far behind the newest sample the live overlay deliberately runs. It
  // buys smoothness with latency, and on a pointer the latency is what a
  // viewer notices first, so it is kept to roughly one publisher flush
  // interval rather than the several it started at.
  const DEFAULT_CURSOR_LAG_MS = 40;
  // Beyond this the overlay is not smoothing, it is simply stale, so it jumps
  // rather than crawling through a backlog.
  const DEFAULT_CURSOR_DRIFT_MS = 600;
  // Play-out rates used to restore the buffer after it runs dry or drain it
  // after a burst. Both are close enough to real time to be invisible: a 10%
  // deviation on pointer motion is well under what anyone can perceive.
  const CURSOR_REBUILD_RATE = 0.9;
  const CURSOR_DRAIN_RATE = 1.1;

  /**
   * Paces live cursor playback against a wall clock.
   *
   * Cursor samples arrive batched: the publisher collects a flush interval of
   * them and sends them together. Rendering only the newest sample of each
   * batch throws away every intermediate position and reduces a 60 Hz cursor to
   * the batch rate, so the overlay instead runs a small fixed distance behind
   * the newest sample and plays the queue out in real time.
   *
   * The clock deliberately does not follow the video element. Video is
   * published around 1 fps with variable-duration samples, so its currentTime
   * stalls between fragments; the cursor timeline must keep advancing anyway.
   */
  function createCursorClock(options = {}) {
    const lagTicks = Math.max(0, Math.round(
      (options.targetLagMs ?? DEFAULT_CURSOR_LAG_MS) * CURSOR_TICKS_PER_MS,
    ));
    const driftTicks = Math.max(lagTicks, Math.round(
      (options.maxDriftMs ?? DEFAULT_CURSOR_DRIFT_MS) * CURSOR_TICKS_PER_MS,
    ));
    let position = null;
    let anchorWall = 0;

    function anchor(media, nowMs) {
      position = media;
      anchorWall = nowMs;
      return media;
    }

    return {
      /** Drops the anchor so the next sample re-synchronises, after a seek. */
      reset() {
        position = null;
      },
      /**
       * Returns the cursor timestamp to display now, given the newest sample
       * available and a monotonic millisecond clock.
       */
      sample(newestTimestamp, nowMs) {
        if (!Number.isFinite(newestTimestamp)) return null;
        if (position === null) return anchor(newestTimestamp - lagTicks, nowMs);

        // Samples arrive a batch at a time, so the overlay plays from a small
        // buffer: the playhead advances with the wall clock while the buffer
        // absorbs late deliveries. `depth` is how much play-out is in hand.
        const depth = newestTimestamp - position;
        if (depth > driftTicks) return anchor(newestTimestamp - lagTicks, nowMs);

        // Running dry once must not cost the buffer permanently. Rebuilding it
        // by rewinding would make the pointer retrace itself, so the playhead
        // instead runs fractionally slow until the cushion is back — far below
        // the threshold where a viewer could see the difference.
        let rate = 1;
        if (depth < lagTicks) rate = CURSOR_REBUILD_RATE;
        else if (depth > lagTicks * 3) rate = CURSOR_DRAIN_RATE;

        // Clamp the elapsed time: a caller handing back a stale clock reading
        // must never make the pointer retrace its path.
        const elapsed = Math.max(0, nowMs - anchorWall);
        const advanced = position + elapsed * CURSOR_TICKS_PER_MS * rate;
        // Nothing left to show: hold at the newest sample. This is also how the
        // overlay comes to rest in the right place when the pointer stops.
        return anchor(Math.max(position, Math.min(advanced, newestTimestamp)), nowMs);
      },
    };
  }

  function retainCursorHistory(events, cutoffTimestamp) {
    if (events.length === 0 || events[0].timestamp >= cutoffTimestamp) return events;
    let low = 0;
    let high = events.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (events[middle].timestamp < cutoffTimestamp) low = middle + 1;
      else high = middle;
    }
    return events.slice(Math.max(0, low - 1));
  }

  function referencedBitmapIds(events) {
    return new Set(
      events
        .filter(event => event.bitmap_id !== 0)
        .map(event => event.bitmap_key || event.bitmap_id),
    );
  }

  function buildEpochTimeline(headers) {
    if (!Array.isArray(headers)) throw new TypeError('DASH headers must be an array.');
    const epochIds = [];
    const seenEpochs = new Set();
    for (const header of headers) {
      if (header.kind !== 'Epoch' || seenEpochs.has(header.epoch_id)) continue;
      seenEpochs.add(header.epoch_id);
      epochIds.push(header.epoch_id);
    }

    let globalEnd = 0;
    const epochs = [];
    for (const epochId of epochIds) {
      const allMedia = headers.filter(
        header => header.kind === 'Media' && header.epoch_id === epochId,
      );
      const firstRandomAccess = allMedia.findIndex(header => header.random_access);
      if (firstRandomAccess < 0) continue;
      const media = allMedia.slice(firstRandomAccess);
      const mediaStart = media[0].timestamp;
      const mediaEnd = media.reduce(
        (end, header) => Math.max(end, header.timestamp + header.duration),
        mediaStart,
      );
      if (
        !Number.isSafeInteger(mediaStart)
        || !Number.isSafeInteger(mediaEnd)
        || mediaStart < 0
        || mediaEnd <= mediaStart
      ) {
        throw new Error(`Epoch ${epochId} has an invalid media timeline.`);
      }
      const offset = globalEnd - mediaStart;
      const globalStart = globalEnd;
      globalEnd += mediaEnd - mediaStart;
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(globalEnd)) {
        throw new Error('The retained media timeline exceeds JavaScript integer limits.');
      }
      epochs.push({
        epoch_id: epochId,
        media_start: mediaStart,
        media_end: mediaEnd,
        offset,
        global_start: globalStart,
        global_end: globalEnd,
        media,
      });
    }
    return epochs;
  }

  function containedVideoRectangle(stageWidth, stageHeight, videoWidth, videoHeight) {
    if (
      !Number.isFinite(stageWidth)
      || !Number.isFinite(stageHeight)
      || !Number.isFinite(videoWidth)
      || !Number.isFinite(videoHeight)
      || stageWidth <= 0
      || stageHeight <= 0
      || videoWidth <= 0
      || videoHeight <= 0
    ) {
      throw new Error('Video and stage dimensions must be positive finite numbers.');
    }
    const videoRatio = videoWidth / videoHeight;
    const stageRatio = stageWidth / stageHeight;
    if (stageRatio > videoRatio) {
      const width = stageHeight * videoRatio;
      return { left: (stageWidth - width) / 2, top: 0, width, height: stageHeight };
    }
    const height = stageWidth / videoRatio;
    return { left: 0, top: (stageHeight - height) / 2, width: stageWidth, height };
  }

  return Object.freeze({
    AES_GCM_TAG_LENGTH,
    CURSOR_BATCH_HEADER_LENGTH,
    CURSOR_EVENT_LENGTH,
    ENCRYPTED_CURSOR_HEADER_LENGTH,
    MAX_CURSOR_BITMAP_SIDE,
    MAX_CURSOR_PAYLOAD,
    MAX_CURSOR_PLAINTEXT,
    CURSOR_TICKS_PER_MS,
    buildEpochTimeline,
    containedVideoRectangle,
    createCursorClock,
    findCursorEvent,
    mergeSortedCursorEvents,
    parseCursorBatch,
    parseEncryptedCursorPayload,
    referencedBitmapIds,
    retainCursorHistory,
  });
}));
