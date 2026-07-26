#!/usr/bin/env node
// Self-test for the picture comparator used by the Wayland acceptance gate.
// It builds PNGs covering the encodings `grim` and Playwright emit, then
// asserts that matching screens score high and mismatched screens do not.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, body) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length);
  const typed = Buffer.concat([Buffer.from(type, 'ascii'), body]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typed));
  return Buffer.concat([length, typed, crc]);
}

/**
 * Writes an 8-bit PNG. `shade(x, y)` returns a 0-255 grey level. `channels`
 * selects RGB (3) or RGBA (4), and `filter` selects the per-row PNG filter so
 * the decoder's reconstruction paths are all exercised.
 */
function writePng(path, width, height, shade, { channels = 3, filter = 0 } = {}) {
  const stride = width * channels;
  const rows = [];
  const previous = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const raw = Buffer.alloc(stride);
    for (let x = 0; x < width; x += 1) {
      const value = Math.max(0, Math.min(255, Math.round(shade(x, y))));
      for (let c = 0; c < Math.min(3, channels); c += 1) raw[x * channels + c] = value;
      if (channels === 4) raw[x * channels + 3] = 255;
    }
    const encoded = Buffer.alloc(stride);
    for (let i = 0; i < stride; i += 1) {
      const left = i >= channels ? raw[i - channels] : 0;
      const up = previous[i];
      const upLeft = i >= channels ? previous[i - channels] : 0;
      let predictor;
      switch (filter) {
        case 0: predictor = 0; break;
        case 1: predictor = left; break;
        case 2: predictor = up; break;
        case 3: predictor = (left + up) >> 1; break;
        case 4: {
          const p = left + up - upLeft;
          const dl = Math.abs(p - left);
          const du = Math.abs(p - up);
          const dul = Math.abs(p - upLeft);
          predictor = dl <= du && dl <= dul ? left : du <= dul ? up : upLeft;
          break;
        }
        default: throw new Error(`unsupported test filter ${filter}`);
      }
      encoded[i] = (raw[i] - predictor) & 0xff;
    }
    rows.push(Buffer.concat([Buffer.from([filter]), encoded]));
    raw.copy(previous);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = channels === 4 ? 6 : 2;
  writeFileSync(path, Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

function compare(reference, candidate, minimum) {
  const args = ['scripts/compare-frame.mjs', reference, candidate];
  if (minimum !== undefined) args.push(String(minimum));
  try {
    // Capture stderr instead of inheriting it: the negative cases below make
    // the comparator report a mismatch, which is a pass here, not a failure.
    const out = execFileSync(process.execPath, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { ok: true, score: Number(/correlation=(-?[\d.]+)/.exec(out)[1]) };
  } catch (error) {
    const text = `${error.stdout || ''}${error.stderr || ''}`;
    const match = /correlation=(-?[\d.]+)/.exec(text);
    return { ok: false, score: match ? Number(match[1]) : NaN, text };
  }
}

const failures = [];
function check(name, condition, detail) {
  if (!condition) failures.push(`${name}${detail ? `: ${detail}` : ''}`);
}

const dir = mkdtempSync(join(tmpdir(), 'glacialcast-compare-'));
try {
  // A "screen": diagonal gradient with a bright panel, so structure dominates.
  const screen = (x, y) => (x * 3 + y * 2) % 256 + (x > 40 && y > 20 ? 40 : 0);
  const reference = join(dir, 'screen.png');
  writePng(reference, 96, 54, screen, { channels: 3, filter: 4 });

  // The published frame: smaller, RGBA, dimmed and softened like a low-bitrate
  // H.264 decode, and letterboxed the way the viewer element pads the video.
  const published = join(dir, 'published.png');
  const bars = 12;
  writePng(published, 48 + bars * 2, 27, (x, y) => {
    if (x < bars || x >= 48 + bars) return 0;
    return 16 + screen((x - bars) * 2, y * 2) * 0.8;
  }, { channels: 4, filter: 1 });

  const matched = compare(reference, published, 0.85);
  check('matching screens must pass the gate threshold', matched.ok, matched.text);
  check(
    'matching screens must correlate strongly',
    matched.score > 0.9,
    `score ${matched.score}`,
  );

  // An unrelated screen: same tones, different structure.
  const unrelated = join(dir, 'unrelated.png');
  writePng(unrelated, 96, 54, (x, y) => (y * 7 - x * 5) % 256, { channels: 3, filter: 2 });
  const mismatched = compare(reference, unrelated, 0.85);
  check('an unrelated screen must fail the gate', !mismatched.ok, `score ${mismatched.score}`);
  check(
    'an unrelated screen must not correlate',
    Math.abs(mismatched.score) < 0.5,
    `score ${mismatched.score}`,
  );

  // Every PNG row filter must reconstruct to the same image.
  for (const filter of [0, 1, 2, 3, 4]) {
    const filtered = join(dir, `filter-${filter}.png`);
    writePng(filtered, 96, 54, screen, { channels: 3, filter });
    const identical = compare(reference, filtered, 0.999);
    check(`row filter ${filter} must decode identically`, identical.ok, identical.text);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log('PASS: picture comparator');
