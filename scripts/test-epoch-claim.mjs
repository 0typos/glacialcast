#!/usr/bin/env node

// The browser half of the epoch encryption claim.
//
// The relay decides whether to store an epoch from these bytes; the viewer
// decides whether to demand a viewing key from the same bytes. They do not
// share a JSON parser, and the claim is what turns object authentication on or
// off, so a disagreement between the two is a security hole rather than an
// inconsistency: the relay accepting what it reads as "no claim" while the
// viewer reads "unencrypted" is a plaintext epoch played with no key.
//
// That is not hypothetical. It shipped. `serde_json` rejects a leading
// byte-order mark and a repeated key; `TextDecoder` and `JSON.parse` accept
// both. Three bytes in front of an ordinary descriptor were enough.
//
// crates/stream drives the same vector file over the Rust reader. Neither side
// may be changed alone.

import { readFileSync } from 'node:fs';

const decoder = new TextDecoder();

/**
 * The claim, read exactly as the viewer reads it.
 *
 * This mirrors `dash-viewer.js`: `TextDecoder().decode()` then `JSON.parse`,
 * with the claim taken as `descriptor.encrypted !== false`. Anything that
 * throws carries no claim the viewer could act on.
 */
function claimAsTheViewerReadsIt(bytes) {
  let descriptor;
  try {
    descriptor = JSON.parse(decoder.decode(bytes));
  } catch {
    return 'unreadable';
  }
  // A non-object parses fine but has no field to read; the viewer would fail
  // its descriptor validation rather than treat it as a claim.
  if (descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    return 'unreadable';
  }
  return descriptor.encrypted === false ? 'unencrypted' : 'encrypted';
}

const file = JSON.parse(readFileSync('test-vectors/epoch-claim-vectors.json', 'utf8'));
const failures = [];

for (const vector of file.vectors) {
  const bytes = Buffer.from(vector.payload_base64, 'base64');
  const observed = claimAsTheViewerReadsIt(bytes);
  if (observed !== vector.claim) {
    failures.push(`${vector.name}: expected ${vector.claim}, the browser reader says ${observed}`);
  }
}

if (file.vectors.length < 10) {
  failures.push(`vector file looks truncated: ${file.vectors.length} vectors`);
}

if (failures.length > 0) {
  console.error('FAIL epoch claim: the browser reader disagrees with the shared vectors');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(`PASS epoch claim: ${file.vectors.length} shared vectors read the same way in the browser`);
