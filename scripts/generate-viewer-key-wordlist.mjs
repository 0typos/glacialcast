// Regenerates the wordlist block inside the browser's viewer-key module from
// the canonical list the publisher uses.
//
// The two must agree exactly: a viewer that resolves a word differently from
// the publisher derives a different key and simply cannot decrypt the stream.
// Keeping one source and generating the other removes the chance of drift.
//
// usage: node scripts/generate-viewer-key-wordlist.mjs [--check]

import { readFileSync, writeFileSync } from 'node:fs';

const SOURCE = 'crates/protocol/wordlist.txt';
const TARGET = 'crates/relay/static/viewer-key.js';
const BEGIN = '  // BEGIN GENERATED WORDLIST';
const END = '  // END GENERATED WORDLIST';

const words = readFileSync(SOURCE, 'utf8').split('\n').filter(Boolean);
if (words.length !== 1024) {
  throw new Error(`${SOURCE} must hold 1024 words, found ${words.length}`);
}

// Ten words a line keeps the diff readable when the list ever changes.
const lines = [];
for (let index = 0; index < words.length; index += 10) {
  lines.push(`    ${words.slice(index, index + 10).map(word => `'${word}'`).join(', ')},`);
}
const block = [BEGIN, '  const WORDLIST = [', ...lines, '  ];', END].join('\n');

const current = readFileSync(TARGET, 'utf8');
const start = current.indexOf(BEGIN);
const finish = current.indexOf(END);
if (start < 0 || finish < 0) {
  throw new Error(`${TARGET} is missing its generated wordlist markers`);
}
const updated = current.slice(0, start) + block + current.slice(finish + END.length);

if (process.argv.includes('--check')) {
  if (updated !== current) {
    console.error(
      `${TARGET} is out of date with ${SOURCE}.\n`
      + 'Run: node scripts/generate-viewer-key-wordlist.mjs',
    );
    process.exit(1);
  }
  console.log('PASS: the browser wordlist matches the publisher wordlist');
} else {
  writeFileSync(TARGET, updated);
  console.log(`updated ${TARGET} from ${SOURCE}`);
}
