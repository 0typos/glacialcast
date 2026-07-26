#!/usr/bin/env node
// Tests the passphrase-protected viewer keyring against Node's WebCrypto.

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';

const require = createRequire(import.meta.url);
if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) {
  globalThis.btoa = value => Buffer.from(value, 'binary').toString('base64');
  globalThis.atob = value => Buffer.from(value, 'base64').toString('binary');
}
const keyring = require('../crates/server/static/keyring.js');

let tests = 0;

async function test(name, body) {
  try {
    await body();
    tests += 1;
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

function memoryStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    getItem: key => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => map.set(key, String(value)),
    removeItem: key => map.delete(key),
    get size() {
      return map.size;
    },
    raw: () => Object.fromEntries(map),
  };
}

// Two distinct 32-byte keys in URL-safe base64.
const KEY_A = Buffer.alloc(32, 7).toString('base64url');
const KEY_B = Buffer.alloc(32, 9).toString('base64url');
// A short passphrase keeps the deliberately expensive derivation affordable in
// tests; production cost comes from the iteration count, which is unchanged.
const PASSPHRASE = 'correct horse battery staple';

await test('a remembered key survives a reload under the same passphrase', async () => {
  const storage = memoryStorage();
  const first = await keyring.unlock(PASSPHRASE, storage);
  assert.deepEqual(first.streamIds(), []);
  await first.remember('stream-a', KEY_A);
  assert.equal(first.getEncoded('stream-a'), KEY_A);

  const second = await keyring.unlock(PASSPHRASE, storage);
  assert.deepEqual(second.streamIds(), ['stream-a']);
  assert.equal(second.getEncoded('stream-a'), KEY_A);
  assert.equal(second.get('missing'), null);
});

await test('the stored blob never contains the key material', async () => {
  const storage = memoryStorage();
  const ring = await keyring.unlock(PASSPHRASE, storage);
  await ring.remember('stream-a', KEY_A);
  const serialized = JSON.stringify(storage.raw());
  assert.ok(!serialized.includes(KEY_A), 'the URL-safe key must not appear');
  assert.ok(
    !serialized.includes(Buffer.from(KEY_A, 'base64url').toString('base64')),
    'the standard-base64 key must not appear either',
  );
  assert.ok(!serialized.includes(PASSPHRASE), 'the passphrase must not be stored');
});

await test('a wrong passphrase fails loudly rather than opening empty', async () => {
  const storage = memoryStorage();
  const ring = await keyring.unlock(PASSPHRASE, storage);
  await ring.remember('stream-a', KEY_A);
  await assert.rejects(
    () => keyring.unlock('not the passphrase', storage),
    /does not open this keyring/,
  );
});

await test('forget removes one stream and forgetAll removes the keyring', async () => {
  const storage = memoryStorage();
  const ring = await keyring.unlock(PASSPHRASE, storage);
  await ring.remember('stream-a', KEY_A);
  await ring.remember('stream-b', KEY_B);
  assert.deepEqual(ring.streamIds().sort(), ['stream-a', 'stream-b']);

  ring.forget('stream-a');
  assert.deepEqual(ring.streamIds(), ['stream-b']);
  const reopened = await keyring.unlock(PASSPHRASE, storage);
  assert.deepEqual(reopened.streamIds(), ['stream-b']);

  reopened.forgetAll();
  assert.equal(keyring.exists(storage), false);
  const fresh = await keyring.unlock('a completely different passphrase', storage);
  assert.deepEqual(fresh.streamIds(), []);
});

await test('malformed viewer keys are rejected before they are stored', async () => {
  const storage = memoryStorage();
  const ring = await keyring.unlock(PASSPHRASE, storage);
  await assert.rejects(() => ring.remember('stream-a', 'not base64!!'), /URL-safe base64/);
  await assert.rejects(
    () => ring.remember('stream-a', Buffer.alloc(31, 1).toString('base64url')),
    /32 bytes/,
  );
  assert.deepEqual(ring.streamIds(), []);
});

await test('an unsupported or corrupt store is reported, not silently reset', async () => {
  await assert.rejects(
    () => keyring.unlock(PASSPHRASE, memoryStorage({ [keyring.STORAGE_KEY]: 'nonsense' })),
    /corrupt/,
  );
  await assert.rejects(
    () => keyring.unlock(
      PASSPHRASE,
      memoryStorage({ [keyring.STORAGE_KEY]: JSON.stringify({ version: 99, entries: {} }) }),
    ),
    /unsupported format/,
  );
});

await test('an empty passphrase is refused', async () => {
  await assert.rejects(() => keyring.unlock('', memoryStorage()), /passphrase is required/);
});

console.log(`PASS keyring: ${tests} tests`);
