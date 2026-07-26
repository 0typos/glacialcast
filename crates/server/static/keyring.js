'use strict';

// A passphrase-protected store for viewer keys.
//
// The multi-stream view needs to know which streams the operator holds keys
// for before any of them is unlocked, which means remembering keys between
// page loads. Keys are the whole security boundary of an end-to-end-encrypted
// stream, so they are never written in the clear: each is wrapped with AES-GCM
// under a key derived from a passphrase with PBKDF2, and the passphrase itself
// is never stored. A stolen browser profile therefore yields ciphertext and a
// salt, not streams.
//
// Unwrapped keys live in memory for the session only. Nothing here is ever
// sent to the relay.

(function installKeyring(root, factory) {
  const keyring = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = keyring;
  } else {
    root.GlacialCastKeyring = keyring;
  }
}(typeof globalThis === 'undefined' ? this : globalThis, () => {
  const STORAGE_KEY = 'glacialcast.keyring.v1';
  const FORMAT_VERSION = 1;
  // OWASP's floor for PBKDF2-HMAC-SHA-256 at the time of writing. The cost is
  // paid once per session, not per stream.
  const DEFAULT_ITERATIONS = 600_000;
  const SALT_LENGTH = 16;
  const IV_LENGTH = 12;
  const VIEWER_KEY_LENGTH = 32;

  function bytesToBase64(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(text) {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function base64UrlToBytes(value, expectedLength) {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    const padded = normalized.padEnd(
      normalized.length + ((4 - (normalized.length % 4)) % 4),
      '=',
    );
    let bytes;
    try {
      bytes = base64ToBytes(padded);
    } catch {
      throw new Error('The viewer key is not valid URL-safe base64.');
    }
    if (bytes.length !== expectedLength) {
      throw new Error(`The viewer key must decode to ${expectedLength} bytes.`);
    }
    return bytes;
  }

  function emptyStore() {
    return { version: FORMAT_VERSION, salt: null, iterations: DEFAULT_ITERATIONS, entries: {} };
  }

  function readStore(storage) {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) return emptyStore();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('The stored keyring is corrupt. Forget all streams to start over.');
    }
    if (parsed?.version !== FORMAT_VERSION || typeof parsed.entries !== 'object') {
      throw new Error('The stored keyring has an unsupported format.');
    }
    return parsed;
  }

  function writeStore(storage, store) {
    storage.setItem(STORAGE_KEY, JSON.stringify(store));
  }

  async function deriveWrappingKey(passphrase, salt, iterations) {
    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  /**
   * Opens the keyring for this session.
   *
   * `storage` defaults to `localStorage`; tests pass a stand-in. The returned
   * keyring holds unwrapped keys in memory and never writes them back in the
   * clear.
   */
  async function unlock(passphrase, storage = globalThis.localStorage) {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new Error('A passphrase is required to open the keyring.');
    }
    const store = readStore(storage);
    const salt = store.salt
      ? base64ToBytes(store.salt)
      : crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iterations = store.iterations || DEFAULT_ITERATIONS;
    const wrappingKey = await deriveWrappingKey(passphrase, salt, iterations);
    const keys = new Map();

    // Decrypting every entry up front is what makes a wrong passphrase fail
    // immediately and visibly, rather than silently presenting an empty
    // keyring that the operator would then overwrite.
    for (const [streamId, entry] of Object.entries(store.entries)) {
      let plaintext;
      try {
        plaintext = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: base64ToBytes(entry.iv) },
          wrappingKey,
          base64ToBytes(entry.ciphertext),
        ));
      } catch {
        throw new Error('That passphrase does not open this keyring.');
      }
      if (plaintext.length !== VIEWER_KEY_LENGTH) {
        throw new Error('The stored keyring contains a malformed viewer key.');
      }
      keys.set(streamId, plaintext);
    }

    if (!store.salt) {
      store.salt = bytesToBase64(salt);
      store.iterations = iterations;
      writeStore(storage, store);
    }

    return {
      /** Stream IDs this keyring holds a viewer key for. */
      streamIds() {
        return [...keys.keys()];
      },
      has(streamId) {
        return keys.has(streamId);
      },
      /** Returns the viewer key bytes, or `null` when the stream is unknown. */
      get(streamId) {
        return keys.get(streamId) || null;
      },
      /** Returns the viewer key as the URL-safe base64 the player accepts. */
      getEncoded(streamId) {
        const bytes = keys.get(streamId);
        if (!bytes) return null;
        return bytesToBase64(bytes)
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replaceAll('=', '');
      },
      /** Wraps and stores a viewer key given in URL-safe base64. */
      async remember(streamId, viewerKeyText) {
        const bytes = base64UrlToBytes(viewerKeyText.trim(), VIEWER_KEY_LENGTH);
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          wrappingKey,
          bytes,
        ));
        const current = readStore(storage);
        current.salt = bytesToBase64(salt);
        current.iterations = iterations;
        current.entries[streamId] = {
          iv: bytesToBase64(iv),
          ciphertext: bytesToBase64(ciphertext),
        };
        writeStore(storage, current);
        keys.set(streamId, bytes);
      },
      /** Removes one stream's key from memory and from storage. */
      forget(streamId) {
        keys.delete(streamId);
        const current = readStore(storage);
        delete current.entries[streamId];
        writeStore(storage, current);
      },
      /** Removes every key and the salt, so the next unlock starts fresh. */
      forgetAll() {
        keys.clear();
        storage.removeItem(STORAGE_KEY);
      },
    };
  }

  /** Reports whether a keyring already exists in `storage`. */
  function exists(storage = globalThis.localStorage) {
    return Boolean(storage.getItem(STORAGE_KEY));
  }

  return Object.freeze({
    DEFAULT_ITERATIONS,
    STORAGE_KEY,
    VIEWER_KEY_LENGTH,
    base64UrlToBytes,
    exists,
    unlock,
  });
}));
