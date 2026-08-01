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

/** How long this page may sit without a decoded frame before it says so. */
const STREAM_STALL_TIMEOUT_MS = 25_000;
/**
 * What a stalled page says.
 *
 * Kept in step with the multi-stream view's wording deliberately: it describes
 * what was observed rather than guessing why, and offers another browser as a
 * way to tell an engine-specific problem from a stream-specific one rather than
 * as the answer.
 */
const STALLED_MESSAGE =
  'This stream is not starting. Media is arriving, but the browser has not '
  + 'decoded a frame from it. Reloading often clears this. If it keeps '
  + 'happening, opening the same stream in another browser will show whether '
  + 'it is specific to this one.';

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
    watchForFirstFrame();
    await player.start(null);
  } catch {
    // Put the field back. A keyless start that failed leaves this page with
    // nothing to act on otherwise -- no form, no way to try a key, and only
    // whatever the player managed to print.
    unlockForm.hidden = false;
  }
}

/**
 * Says something when the page never produces a picture.
 *
 * The same silence the tiles in the multi-stream view are watched for: starting
 * a player can fail without ever rejecting, because the media element waits for
 * a frame that never arrives and the promise chain simply does not settle. This
 * page had no such watchdog, so it sat on its status line indefinitely -- and it
 * is the page a deep link lands on, where there is no sidebar to suggest
 * anything else is wrong.
 */
function watchForFirstFrame() {
  setTimeout(() => {
    const video = root.querySelector('[data-role="video"]');
    // readyState below HAVE_CURRENT_DATA means no frame was ever decoded.
    if (!video || video.readyState >= 2) return;
    const stage = root.querySelector('[data-role="stage-message"]');
    if (stage) stage.textContent = STALLED_MESSAGE;
  }, STREAM_STALL_TIMEOUT_MS);
}

unlockForm.addEventListener('submit', async event => {
  event.preventDefault();
  watchForFirstFrame();
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
