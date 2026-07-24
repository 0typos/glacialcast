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
    return new Set(events.filter(event => event.bitmap_id !== 0).map(event => event.bitmap_id));
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
    containedVideoRectangle,
    findCursorEvent,
    mergeSortedCursorEvents,
    parseCursorBatch,
    parseEncryptedCursorPayload,
    referencedBitmapIds,
    retainCursorHistory,
  });
}));
