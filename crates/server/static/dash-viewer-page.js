'use strict';

// Mounts the single-stream viewer at /dash/<stream-id>. The player itself is
// reusable; this file is only the page around it.

const Player = globalThis.GlacialCastPlayer;
const ViewerKey = globalThis.GlacialCastViewerKey;
if (!Player || !ViewerKey) throw new Error('The GlacialCast player failed to load.');

const streamId = location.pathname.split('/').filter(Boolean).at(-1);
const root = document.querySelector('[data-role="player"]');
const unlockForm = document.querySelector('[data-role="unlock-form"]');
const viewerKeyInput = document.querySelector('[data-role="viewer-key"]');
const label = document.querySelector('[data-role="stream-label"]');

if (label) label.textContent = `Stream ${streamId}`;

const player = Player.createPlayer(root, { streamId });

/**
 * Finds this stream's key-derivation salt.
 *
 * A key phrase means nothing without the publisher's salt, and a deep link
 * lands here with only a stream id. Returns null for a publisher that shares a
 * raw key, which needs no salt.
 */
async function streamSalt() {
  try {
    const response = await fetch('/api/streams', { cache: 'no-store' });
    if (!response.ok) return null;
    const streams = await response.json();
    return streams.find(stream => stream.stream_id === streamId)?.viewer_key_salt ?? null;
  } catch {
    return null;
  }
}

/**
 * Starts straight away when the stream needs no key.
 *
 * A publisher on a trusted LAN can send in the clear, and asking such a stream
 * for a viewing key would be asking for something that does not exist. The
 * player is the authority on this -- it refuses an epoch whose encryption does
 * not match what it started with -- so an unhelpful answer here costs a visible
 * failure, not a silent one.
 */
describeOpenStream();

async function describeOpenStream() {
  try {
    const { encrypted } = await Player.describeStream(streamId);
    if (encrypted !== false) return;
    unlockForm.hidden = true;
    await player.start(null);
  } catch {
    // Put the field back. A keyless start that failed leaves this page with
    // nothing to act on otherwise -- no form, no way to try a key, and only
    // whatever the player managed to print.
    unlockForm.hidden = false;
  }
}

unlockForm.addEventListener('submit', async event => {
  event.preventDefault();
  // Accepts either a key phrase or a raw viewer key, so a link shared with a
  // phrase works the same way the multi-stream view does.
  try {
    const bytes = await ViewerKey.resolveKey(viewerKeyInput.value, await streamSalt());
    // The player renders its own failures; nothing further to do here.
    await player.start(ViewerKey.bytesToBase64Url(bytes));
  } catch {
    // Resolution failures surface through the player's own status line below.
    player.start(viewerKeyInput.value.trim()).catch(() => {});
  }
});

// Exposed so the browser gates can inspect player state without reaching
// into module internals.
globalThis.GlacialCastActivePlayer = player;

globalThis.addEventListener('pagehide', () => player.destroy());
