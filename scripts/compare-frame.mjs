#!/usr/bin/env node
// Compares a viewer screenshot against a reference screenshot of the same
// screen and reports how strongly they correlate.
//
// Both inputs are 8-bit non-interlaced PNGs, which is what `grim` and
// Playwright produce. Decoding uses only Node's built-in zlib so the picture
// gate needs no image dependency.
//
// usage: compare-frame.mjs REFERENCE.png CANDIDATE.png [MINIMUM_CORRELATION]

import { readFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
// Grid used for the comparison. It is coarse on purpose: the published stream
// is a downscaled, heavily quantised H.264 frame, so per-pixel equality is not
// a meaningful question, but layout and tone are.
const GRID_WIDTH = 80;
const GRID_HEIGHT = 45;
// Below this the sampled line is treated as viewer letterboxing rather than
// content. Real screen content is never this uniformly black at the edges.
const LETTERBOX_LEVEL = 6;

function decodePng(path) {
  const file = readFileSync(path);
  if (!file.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error(`${path} is not a PNG file`);
  }
  let offset = 8;
  let header = null;
  const idat = [];
  while (offset + 8 <= file.length) {
    const length = file.readUInt32BE(offset);
    const type = file.toString('ascii', offset + 4, offset + 8);
    const body = file.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      header = {
        width: body.readUInt32BE(0),
        height: body.readUInt32BE(4),
        depth: body[8],
        colorType: body[9],
        interlace: body[12],
      };
    } else if (type === 'IDAT') {
      idat.push(body);
    } else if (type === 'IEND') {
      break;
    }
    offset += 12 + length;
  }
  if (!header) throw new Error(`${path} has no IHDR chunk`);
  if (header.depth !== 8 || header.interlace !== 0) {
    throw new Error(`${path} must be 8-bit and non-interlaced`);
  }
  const channels = { 0: 1, 2: 3, 4: 2, 6: 4 }[header.colorType];
  if (!channels) throw new Error(`${path} uses unsupported colour type ${header.colorType}`);

  const raw = inflateSync(Buffer.concat(idat));
  const { width, height } = header;
  const stride = width * channels;
  const pixels = Buffer.alloc(stride * height);
  let source = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = raw[source];
    source += 1;
    const row = y * stride;
    const previous = row - stride;
    for (let x = 0; x < stride; x += 1) {
      const value = raw[source + x];
      const left = x >= channels ? pixels[row + x - channels] : 0;
      const up = y > 0 ? pixels[previous + x] : 0;
      const upLeft = y > 0 && x >= channels ? pixels[previous + x - channels] : 0;
      let restored;
      switch (filter) {
        case 0: restored = value; break;
        case 1: restored = value + left; break;
        case 2: restored = value + up; break;
        case 3: restored = value + ((left + up) >> 1); break;
        case 4: {
          const p = left + up - upLeft;
          const dl = Math.abs(p - left);
          const du = Math.abs(p - up);
          const dul = Math.abs(p - upLeft);
          restored = value + (dl <= du && dl <= dul ? left : du <= dul ? up : upLeft);
          break;
        }
        default: throw new Error(`${path} row ${y} uses unknown filter ${filter}`);
      }
      pixels[row + x] = restored & 0xff;
    }
    source += stride;
  }

  // Collapse to luminance; colour agreement is checked by eye, structure here.
  const luma = new Float64Array(width * height);
  for (let i = 0; i < width * height; i += 1) {
    const at = i * channels;
    if (channels <= 2) {
      luma[i] = pixels[at];
    } else {
      luma[i] = 0.299 * pixels[at] + 0.587 * pixels[at + 1] + 0.114 * pixels[at + 2];
    }
  }
  return { width, height, luma };
}

function contentBox({ width, height, luma }) {
  const columnMean = x => {
    let sum = 0;
    for (let y = 0; y < height; y += 1) sum += luma[y * width + x];
    return sum / height;
  };
  const rowMean = y => {
    let sum = 0;
    for (let x = 0; x < width; x += 1) sum += luma[y * width + x];
    return sum / width;
  };
  let left = 0;
  let right = width - 1;
  let top = 0;
  let bottom = height - 1;
  while (left < right && columnMean(left) < LETTERBOX_LEVEL) left += 1;
  while (right > left && columnMean(right) < LETTERBOX_LEVEL) right -= 1;
  while (top < bottom && rowMean(top) < LETTERBOX_LEVEL) top += 1;
  while (bottom > top && rowMean(bottom) < LETTERBOX_LEVEL) bottom -= 1;
  return { left, top, right, bottom };
}

function grid(image) {
  const { left, top, right, bottom } = contentBox(image);
  const boxWidth = right - left + 1;
  const boxHeight = bottom - top + 1;
  const cells = new Float64Array(GRID_WIDTH * GRID_HEIGHT);
  for (let gy = 0; gy < GRID_HEIGHT; gy += 1) {
    const y0 = top + Math.floor((gy * boxHeight) / GRID_HEIGHT);
    const y1 = Math.max(y0 + 1, top + Math.floor(((gy + 1) * boxHeight) / GRID_HEIGHT));
    for (let gx = 0; gx < GRID_WIDTH; gx += 1) {
      const x0 = left + Math.floor((gx * boxWidth) / GRID_WIDTH);
      const x1 = Math.max(x0 + 1, left + Math.floor(((gx + 1) * boxWidth) / GRID_WIDTH));
      let sum = 0;
      let count = 0;
      for (let y = y0; y < y1; y += 1) {
        for (let x = x0; x < x1; x += 1) {
          sum += image.luma[y * image.width + x];
          count += 1;
        }
      }
      cells[gy * GRID_WIDTH + gx] = sum / count;
    }
  }
  return { cells, box: `${boxWidth}x${boxHeight}` };
}

function correlation(a, b) {
  const n = a.length;
  let meanA = 0;
  let meanB = 0;
  for (let i = 0; i < n; i += 1) {
    meanA += a[i];
    meanB += b[i];
  }
  meanA /= n;
  meanB /= n;
  let numerator = 0;
  let varianceA = 0;
  let varianceB = 0;
  for (let i = 0; i < n; i += 1) {
    const x = a[i] - meanA;
    const y = b[i] - meanB;
    numerator += x * y;
    varianceA += x * x;
    varianceB += y * y;
  }
  const denominator = Math.sqrt(varianceA * varianceB);
  return denominator === 0 ? 0 : numerator / denominator;
}

const [referencePath, candidatePath, minimum] = process.argv.slice(2);
if (!referencePath || !candidatePath) {
  console.error('usage: compare-frame.mjs REFERENCE.png CANDIDATE.png [MINIMUM_CORRELATION]');
  process.exit(2);
}
const reference = grid(decodePng(referencePath));
const candidate = grid(decodePng(candidatePath));
const score = correlation(reference.cells, candidate.cells);
const threshold = minimum === undefined ? null : Number(minimum);
console.log(
  `correlation=${score.toFixed(4)} reference=${reference.box} candidate=${candidate.box}`,
);
if (threshold !== null && !(score >= threshold)) {
  console.error(
    `published picture does not match the screen: ${score.toFixed(4)} < ${threshold}`,
  );
  process.exit(1);
}
