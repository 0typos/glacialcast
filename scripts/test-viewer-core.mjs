#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const core = require('../crates/server/static/dash-viewer-core.js');

let tests = 0;

function test(name, body) {
  try {
    body();
    tests += 1;
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

function bytesOf(...parts) {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return bytes;
}

function integer(value, byteLength, signed = false) {
  const bytes = new Uint8Array(byteLength);
  const view = new DataView(bytes.buffer);
  if (byteLength === 1) view.setUint8(0, Number(value));
  else if (byteLength === 2) view.setUint16(0, Number(value));
  else if (byteLength === 4 && signed) view.setInt32(0, Number(value));
  else if (byteLength === 4) view.setUint32(0, Number(value));
  else if (byteLength === 8 && signed) view.setBigInt64(0, BigInt(value));
  else if (byteLength === 8) view.setBigUint64(0, BigInt(value));
  else throw new Error(`unsupported integer size ${byteLength}`);
  return bytes;
}

function encodeBatch({
  sourceWidth = 320,
  sourceHeight = 180,
  events = [{
    timestamp: 100,
    x: 1_500_000,
    y: 250_000,
    visible: true,
    bitmapId: 9,
    bitmap: {
      width: 2,
      height: 1,
      hotspotX: 1,
      hotspotY: 0,
      rgba: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
    },
  }, {
    timestamp: 200,
    x: 0,
    y: 0,
    visible: false,
    bitmapId: 9,
    bitmap: null,
  }],
} = {}) {
  const parts = [
    new TextEncoder().encode('GCC1'),
    integer(sourceWidth, 4),
    integer(sourceHeight, 4),
    integer(events.length, 2),
  ];
  for (const event of events) {
    const flags = Number(event.visible) | (event.bitmap ? 2 : 0);
    parts.push(
      integer(event.timestamp, 8),
      integer(event.x, 8, true),
      integer(event.y, 8, true),
      integer(flags, 1),
      integer(event.bitmapId, 8),
    );
    if (event.bitmap) {
      parts.push(
        integer(event.bitmap.width, 4),
        integer(event.bitmap.height, 4),
        integer(event.bitmap.hotspotX, 4, true),
        integer(event.bitmap.hotspotY, 4, true),
        integer(event.bitmap.rgba.byteLength, 4),
        event.bitmap.rgba,
      );
    }
  }
  return bytesOf(...parts);
}

function assertRejected(bytes, pattern = /cursor/i, expected = null) {
  assert.throws(() => core.parseCursorBatch(bytes, expected), pattern);
}

test('encrypted envelope validates exact framing', () => {
  const valid = new Uint8Array(32);
  valid.set(new TextEncoder().encode('GCE1'));
  const parsed = core.parseEncryptedCursorPayload(valid);
  assert.equal(parsed.nonce.byteLength, 12);
  assert.equal(parsed.ciphertext.byteLength, 16);
  for (let length = 0; length < 32; length += 1) {
    assert.throws(
      () => core.parseEncryptedCursorPayload(valid.subarray(0, length)),
      /malformed/,
    );
  }
  valid[0] = 'X'.charCodeAt(0);
  assert.throws(() => core.parseEncryptedCursorPayload(valid), /malformed/);
  assert.throws(
    () => core.parseEncryptedCursorPayload(new Uint8Array(core.MAX_CURSOR_PAYLOAD + 1)),
    /malformed/,
  );
  assert.throws(() => core.parseEncryptedCursorPayload(new ArrayBuffer(32)), /Uint8Array/);
});

test('cursor batch round trips bitmap, hidden state, and authenticated context', () => {
  const parsed = core.parseCursorBatch(encodeBatch(), {
    sourceWidth: 320,
    sourceHeight: 180,
    startTimestamp: 100,
  });
  assert.equal(parsed.events.length, 2);
  assert.deepEqual([...parsed.events[0].bitmap.rgba], [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(parsed.events[1].visible, false);
});

test('cursor decoder rejects every truncated prefix and trailing data', () => {
  const valid = encodeBatch();
  for (let length = 0; length < valid.byteLength; length += 1) {
    assertRejected(valid.subarray(0, length), /cursor|truncated|version/i);
  }
  assertRejected(bytesOf(valid, Uint8Array.of(0)), /trailing/);
});

test('cursor decoder preflights claimed event storage', () => {
  const claimed = bytesOf(
    new TextEncoder().encode('GCC1'),
    integer(320, 4),
    integer(180, 4),
    integer(65535, 2),
  );
  assertRejected(claimed, /truncated/);
});

test('cursor decoder enforces dimensions and a nonempty batch', () => {
  assertRejected(encodeBatch({ sourceWidth: 0 }), /dimensions/);
  assertRejected(encodeBatch({ sourceHeight: 65536 }), /dimensions/);
  assertRejected(encodeBatch({ events: [] }), /event count/);
});

test('cursor decoder enforces authenticated context', () => {
  const valid = encodeBatch();
  for (const expected of [
    { sourceWidth: 321, sourceHeight: 180, startTimestamp: 100 },
    { sourceWidth: 320, sourceHeight: 181, startTimestamp: 100 },
    { sourceWidth: 320, sourceHeight: 180, startTimestamp: 101 },
  ]) {
    assertRejected(valid, /authenticated context/, expected);
  }
});

test('cursor decoder rejects unknown flags and unsafe integers', () => {
  const flags = encodeBatch();
  flags[core.CURSOR_BATCH_HEADER_LENGTH + 24] = 0x80;
  assertRejected(flags, /flags/);

  const unsafe = encodeBatch();
  unsafe.set(integer(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 8), core.CURSOR_BATCH_HEADER_LENGTH);
  assertRejected(unsafe, /safe integer/);
});

test('cursor decoder enforces timeline and coordinate bounds', () => {
  const base = {
    timestamp: 100,
    x: 0,
    y: 0,
    visible: true,
    bitmapId: 9,
    bitmap: null,
  };
  assertRejected(encodeBatch({
    events: [base, { ...base, timestamp: 99 }],
  }), /timestamps/);
  for (const event of [
    { ...base, x: -1 },
    { ...base, y: -1 },
    { ...base, x: 320_000_001 },
    { ...base, y: 180_000_001 },
  ]) {
    assertRejected(encodeBatch({ events: [event] }), /outside/);
  }
  core.parseCursorBatch(encodeBatch({
    events: [{ ...base, x: 320_000_000, y: 180_000_000 }],
  }));
});

test('hidden cursor state cannot carry coordinates or a bitmap', () => {
  const hidden = {
    timestamp: 100,
    x: 0,
    y: 0,
    visible: false,
    bitmapId: 9,
    bitmap: null,
  };
  assertRejected(encodeBatch({ events: [{ ...hidden, x: 1 }] }), /hidden/);
  assertRejected(encodeBatch({
    events: [{
      ...hidden,
      bitmap: {
        width: 1,
        height: 1,
        hotspotX: 0,
        hotspotY: 0,
        rgba: Uint8Array.of(0, 0, 0, 0),
      },
    }],
  }), /hidden/);
});

test('cursor bitmap dimensions, IDs, hotspots, and lengths are bounded', () => {
  const event = {
    timestamp: 100,
    x: 0,
    y: 0,
    visible: true,
    bitmapId: 9,
    bitmap: {
      width: 1,
      height: 1,
      hotspotX: 0,
      hotspotY: 0,
      rgba: Uint8Array.of(0, 0, 0, 0),
    },
  };
  for (const invalid of [
    { ...event, bitmapId: 0 },
    { ...event, bitmap: { ...event.bitmap, width: 0 } },
    { ...event, bitmap: { ...event.bitmap, height: 513 } },
    { ...event, bitmap: { ...event.bitmap, hotspotX: -1 } },
    { ...event, bitmap: { ...event.bitmap, hotspotY: 1 } },
    { ...event, bitmap: { ...event.bitmap, rgba: Uint8Array.of(0, 0, 0) } },
  ]) {
    assertRejected(encodeBatch({ events: [invalid] }), /bitmap/);
  }
});

test('cursor event selection handles boundaries and live state', () => {
  const events = [{ timestamp: 10 }, { timestamp: 20 }, { timestamp: 30 }];
  assert.equal(core.findCursorEvent(events, 9), null);
  assert.equal(core.findCursorEvent(events, 10), events[0]);
  assert.equal(core.findCursorEvent(events, 29), events[1]);
  assert.equal(core.findCursorEvent(events, 999, true), events[2]);
  assert.equal(core.findCursorEvent([], 999, true), null);
});

test('cursor merge preserves timestamp and sequence order', () => {
  const first = { timestamp: 10, marker: 'first' };
  const second = { timestamp: 10, marker: 'second' };
  const merged = core.mergeSortedCursorEvents(
    [first, { timestamp: 30 }],
    [second, { timestamp: 20 }],
  );
  assert.deepEqual(merged.map(event => event.marker || event.timestamp), [
    'first',
    'second',
    20,
    30,
  ]);
});

test('cursor retention keeps one predecessor and referenced bitmaps', () => {
  const events = [
    { timestamp: 10, bitmap_id: 1 },
    { timestamp: 20, bitmap_id: 2 },
    { timestamp: 30, bitmap_id: 2 },
    { timestamp: 40, bitmap_id: 3 },
  ];
  const retained = core.retainCursorHistory(events, 30);
  assert.deepEqual(retained.map(event => event.timestamp), [20, 30, 40]);
  assert.deepEqual([...core.referencedBitmapIds(retained)], [2, 3]);
  assert.equal(core.retainCursorHistory(events, 0), events);
});

test('epoch timeline joins retained random-access ranges without overlap', () => {
  const headers = [
    { kind: 'Epoch', epoch_id: 'first', sequence: 1 },
    {
      kind: 'Media',
      epoch_id: 'first',
      sequence: 2,
      timestamp: 90_000,
      duration: 90_000,
      random_access: false,
    },
    {
      kind: 'Media',
      epoch_id: 'first',
      sequence: 3,
      timestamp: 180_000,
      duration: 90_000,
      random_access: true,
    },
    {
      kind: 'Media',
      epoch_id: 'first',
      sequence: 4,
      timestamp: 270_000,
      duration: 90_000,
      random_access: false,
    },
    { kind: 'Epoch', epoch_id: 'second', sequence: 5 },
    {
      kind: 'Media',
      epoch_id: 'second',
      sequence: 6,
      timestamp: 0,
      duration: 45_000,
      random_access: true,
    },
  ];
  const timeline = core.buildEpochTimeline(headers);
  assert.deepEqual(
    timeline.map(epoch => ({
      id: epoch.epoch_id,
      mediaStart: epoch.media_start,
      offset: epoch.offset,
      globalStart: epoch.global_start,
      globalEnd: epoch.global_end,
      sequences: epoch.media.map(header => header.sequence),
    })),
    [{
      id: 'first',
      mediaStart: 180_000,
      offset: -180_000,
      globalStart: 0,
      globalEnd: 180_000,
      sequences: [3, 4],
    }, {
      id: 'second',
      mediaStart: 0,
      offset: 180_000,
      globalStart: 180_000,
      globalEnd: 225_000,
      sequences: [6],
    }],
  );
});

test('epoch timeline rejects unusable or unsafe media ranges', () => {
  assert.deepEqual(core.buildEpochTimeline([
    { kind: 'Epoch', epoch_id: 'empty', sequence: 1 },
  ]), []);
  assert.throws(() => core.buildEpochTimeline([
    { kind: 'Epoch', epoch_id: 'bad', sequence: 1 },
    {
      kind: 'Media',
      epoch_id: 'bad',
      sequence: 2,
      timestamp: Number.MAX_SAFE_INTEGER,
      duration: 1,
      random_access: true,
    },
  ]), /invalid media timeline/);
});

test('contained video geometry handles letterboxing and pillarboxing', () => {
  assert.deepEqual(core.containedVideoRectangle(1600, 900, 1920, 1080), {
    left: 0,
    top: 0,
    width: 1600,
    height: 900,
  });
  assert.deepEqual(core.containedVideoRectangle(1000, 1000, 1920, 1080), {
    left: 0,
    top: 218.75,
    width: 1000,
    height: 562.5,
  });
  assert.deepEqual(core.containedVideoRectangle(1600, 900, 1000, 1000), {
    left: 350,
    top: 0,
    width: 900,
    height: 900,
  });
  assert.throws(() => core.containedVideoRectangle(0, 100, 100, 100), /positive/);
});

test('live cursor clock plays batches out instead of snapping to the newest', () => {
  const ticks = core.CURSOR_TICKS_PER_MS;
  const clock = core.createCursorClock({ targetLagMs: 100, maxDriftMs: 500 });
  // A batch of 100 ms of samples lands at once; the newest is 10_000 ticks in.
  const newest = 10_000 * ticks;
  const first = clock.sample(newest, 1_000);
  assert.equal(first, newest - 100 * ticks, 'starts one lag behind the newest');

  // Wall clock advances 40 ms with no new samples: the overlay must advance
  // through the queue rather than sit on one position.
  const later = clock.sample(newest, 1_040);
  assert.equal(later, first + 40 * ticks);
  assert.ok(later < newest, 'still trailing the newest sample');
});

test('live cursor clock holds at the newest sample and does not run ahead', () => {
  const ticks = core.CURSOR_TICKS_PER_MS;
  const clock = core.createCursorClock({ targetLagMs: 100, maxDriftMs: 500 });
  const newest = 5_000 * ticks;
  clock.sample(newest, 0);
  // Far past the queue with nothing new delivered.
  assert.equal(clock.sample(newest, 10_000), newest);
  // Having caught up, it resumes from there rather than replaying the gap.
  const resumed = clock.sample(newest + 30 * ticks, 10_020);
  assert.equal(resumed, newest + 20 * ticks);
});

test('live cursor clock jumps forward instead of crawling through a backlog', () => {
  const ticks = core.CURSOR_TICKS_PER_MS;
  const clock = core.createCursorClock({ targetLagMs: 100, maxDriftMs: 500 });
  clock.sample(1_000 * ticks, 0);
  // A backgrounded tab wakes up to samples far beyond the drift bound.
  const caught = clock.sample(9_000 * ticks, 50);
  assert.equal(caught, (9_000 - 100) * ticks, 'resynchronises to one lag behind');
});

test('live cursor clock resynchronises after a reset', () => {
  const ticks = core.CURSOR_TICKS_PER_MS;
  const clock = core.createCursorClock({ targetLagMs: 100, maxDriftMs: 500 });
  clock.sample(1_000 * ticks, 0);
  clock.reset();
  assert.equal(clock.sample(4_000 * ticks, 5), (4_000 - 100) * ticks);
  assert.equal(clock.sample(Number.NaN, 6), null);
});

console.log(`PASS viewer core: ${tests} tests`);
