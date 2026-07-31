'use strict';

// The multi-stream viewer: a side panel of the streams this tab has unlocked,
// and a grid of one, two, or four tiles they can be dragged into.
//
// Each tile owns an independent player instance, so tiles start and stop
// without disturbing one another and each can be full-screened on its own.
//
// A viewing key is entered once, and once only. One key covers every screen a
// publisher casts, so entering it unlocks all of them rather than asking again
// per monitor; it is remembered on this browser, so a reload, a new tab, or a
// restart does not ask again; and a screen the publisher adds later unlocks
// itself. An invitation link carries the key in its fragment, which removes the
// interaction altogether.
//
// Remembering it means it is stored on disk in the browser profile, which is a
// deliberate trade: an earlier version kept it in session storage and viewers
// had to retype it constantly. "Forget keys" erases it.

const Player = globalThis.GlacialCastPlayer;
const ViewerKey = globalThis.GlacialCastViewerKey;
if (!Player || !ViewerKey) throw new Error('The GlacialCast viewer failed to load.');

const els = {
  unlockForm: document.querySelector('#unlock'),
  viewingKey: document.querySelector('#viewing-key'),
  unlockError: document.querySelector('#unlock-error'),
  unlockStatus: document.querySelector('#unlock-status'),
  streamList: document.querySelector('#stream-list'),
  forgetAll: document.querySelector('#forget-all'),
  grid: document.querySelector('#grid'),
  tileTemplate: document.querySelector('#tile-template'),
  main: document.querySelector('main'),
  sidebar: document.querySelector('#sidebar'),
  sidebarToggle: document.querySelector('#sidebar-toggle'),
  welcomeUnlock: document.querySelector('#welcome-unlock'),
  sidebarUnlock: document.querySelector('#sidebar-unlock'),
};

const SIDEBAR_STORAGE_KEY = 'glacialcast.sidebar.collapsed';
/** Toggles the stream list. Named once so the title text cannot drift from it. */
const SIDEBAR_SHORTCUT = '[';
const KEY_STORE = 'glacialcast.keys.v1';
const KEY_STORE_VERSION = 1;

const MAX_TILES = 4;
/** How long to wait before asking a not-yet-sending stream again. */
const STREAM_RETRY_INTERVAL_MS = 3_000;
/** How often to look for screens the publisher added after this page loaded. */
const STREAM_POLL_INTERVAL_MS = 10_000;
/** How long a tile may sit without a decoded frame before it says so. */
const STREAM_STALL_TIMEOUT_MS = 25_000;
/**
 * What a stalled tile says.
 *
 * Deliberately about what was observed rather than why. This message once named
 * Firefox, because at the time every stall was the same one: samples of a
 * second or longer, which Firefox will not decode and Chromium will. The
 * publisher now keeps samples under that, so a tile reaching this is more
 * likely to be something not yet seen than the cause that has been fixed --
 * and sending someone to a different browser for a reason that no longer
 * applies wastes the one clue they have.
 *
 * Another browser is still worth trying, as a way to tell an engine-specific
 * problem from a stream-specific one. It is offered as a diagnostic rather than
 * as the answer.
 */
const STALLED_MESSAGE =
  'This stream is not starting. Media is arriving, but the browser has not '
  + 'decoded a frame from it. Reloading often clears this. If it keeps '
  + 'happening, opening the same stream in another browser will show whether '
  + 'it is specific to this one.';
const state = {
  /** Unlocked viewer keys as URL-safe base64, by stream ID. */
  keys: new Map(),
  /** Secrets entered on this browser: key phrases, or raw viewer keys. */
  secrets: new Set(),
  /** Cache of derived keys as URL-safe base64, by publisher salt. */
  derived: new Map(),
  /**
   * Publisher salts no remembered secret opens.
   *
   * Without this, the poll below would re-derive a key for every publisher this
   * viewer has no business watching, every time it runs -- and each derivation
   * is hundreds of thousands of PBKDF2 iterations by design. Cleared whenever a
   * new secret is entered, so a key added later is still tried.
   */
  rejected: new Set(),
  /** Relay stream metadata by stream ID. */
  streams: new Map(),
  /** One entry per visible tile. */
  tiles: [],
  layout: 1,
  /**
   * Whether the page is showing streams rather than asking for a key.
   *
   * Undefined until the first render so that render decides it, rather than a
   * default here having to agree with one written in the markup.
   */
  watching: undefined,
};

/**
 * Reads the keys remembered on this browser.
 *
 * What is stored is the secret the viewer typed, not the per-stream keys derived
 * from it. Derived keys only open the streams that existed when they were made,
 * so a screen added later, or a publisher that reconnected under a new stream,
 * would ask for the key again -- which is the entire complaint this is meant to
 * answer. The secret opens whatever the publisher casts next.
 *
 * The derived keys are kept beside it only as a cache: deriving one costs
 * hundreds of thousands of PBKDF2 iterations, and doing that for every publisher
 * on every page load is a visible stall. A cached key is still verified against a
 * real object before use, so a publisher that rotated its key falls back to
 * deriving rather than silently failing.
 */
function loadRememberedKeys() {
  try {
    const raw = globalThis.localStorage.getItem(KEY_STORE);
    if (!raw) return;
    const stored = JSON.parse(raw);
    if (stored?.version !== KEY_STORE_VERSION) return;
    for (const secret of stored.secrets ?? []) {
      if (typeof secret === 'string' && secret) state.secrets.add(secret);
    }
    for (const [salt, key] of Object.entries(stored.derived ?? {})) {
      if (typeof key === 'string') state.derived.set(salt, key);
    }
  } catch {
    // A corrupt or unavailable store just means unlocking again.
  }
}

function saveRememberedKeys() {
  try {
    globalThis.localStorage.setItem(KEY_STORE, JSON.stringify({
      version: KEY_STORE_VERSION,
      secrets: [...state.secrets],
      derived: Object.fromEntries(state.derived),
    }));
  } catch {
    // Without storage the key still works for this page; it just has to be
    // entered again next time.
  }
}

function forgetRememberedKeys() {
  state.secrets.clear();
  state.derived.clear();
  state.keys.clear();
  state.rejected.clear();
  try {
    globalThis.localStorage.removeItem(KEY_STORE);
  } catch {
    // Nothing stored means nothing to remove.
  }
}

/**
 * Applies one typed key to every stream it actually opens.
 *
 * Streams are grouped by publisher because a publisher's screens share a key
 * and each publisher has its own salt. Deriving is deliberately expensive, so
 * it happens once per publisher rather than once per screen. Each derived key
 * is then checked against a real object, which is what lets a wrong key be
 * reported as wrong instead of producing tiles that fail later.
 */
function publishersByName() {
  const publishers = new Map();
  for (const stream of state.streams.values()) {
    if (!publishers.has(stream.publisher)) publishers.set(stream.publisher, []);
    publishers.get(stream.publisher).push(stream);
  }
  return publishers;
}

async function unlockWithKey(typed) {
  const secret = typed.trim();
  if (!secret) throw new Error('Enter the viewing key you were given.');
  const publishers = publishersByName();
  if (publishers.size === 0) throw new Error('No streams are published yet.');

  let unlocked = 0;
  const failures = [];
  for (const streams of publishers.values()) {
    let bytes;
    try {
      bytes = await ViewerKey.resolveKey(secret, streams[0].viewer_key_salt);
    } catch (error) {
      failures.push(error);
      continue;
    }
    // One screen answers for the publisher: the key is the same for all of
    // them, so checking every screen would only repeat the same fetch.
    if (!await Player.verifyViewerKey(streams[0].stream_id, bytes)) continue;

    const encoded = ViewerKey.bytesToBase64Url(bytes);
    for (const stream of streams) state.keys.set(stream.stream_id, encoded);
    state.derived.set(streams[0].viewer_key_salt, encoded);
    unlocked += streams.length;
  }

  if (unlocked === 0) {
    // Every publisher rejected the key. If none of them could even parse it,
    // the parse error is the more useful thing to say.
    if (failures.length === publishers.size && failures[0]) throw failures[0];
    throw new Error('That key does not open any stream published here.');
  }
  state.secrets.add(secret);
  // A newly entered key may open a publisher an earlier one could not.
  state.rejected.clear();
  saveRememberedKeys();
  return unlocked;
}

/**
 * Opens everything the remembered secrets can open, without asking.
 *
 * Runs on load and again whenever the stream list changes, so a screen the
 * publisher adds later, or one that comes back under a new stream after a
 * reconnect, appears already unlocked rather than prompting again.
 */
async function applyRememberedKeys() {
  if (state.secrets.size === 0) return 0;
  let unlocked = 0;
  for (const streams of publishersByName().values()) {
    const locked = streams.filter(stream => !state.keys.has(stream.stream_id));
    if (locked.length === 0) continue;
    const salt = streams[0].viewer_key_salt;
    if (state.rejected.has(salt)) continue;

    // The cached key first, then each remembered secret. Either way the key is
    // verified against a real object before it is treated as opening anything.
    const candidates = [];
    const cached = state.derived.get(salt);
    if (cached) candidates.push(ViewerKey.base64UrlToBytes(cached));
    for (const secret of state.secrets) {
      try {
        candidates.push(await ViewerKey.resolveKey(secret, salt));
      } catch {
        // A secret that cannot be parsed against this salt simply is not this
        // publisher's key.
      }
    }

    let opened = false;
    for (const bytes of candidates) {
      if (!await Player.verifyViewerKey(streams[0].stream_id, bytes)) continue;
      const encoded = ViewerKey.bytesToBase64Url(bytes);
      for (const stream of locked) state.keys.set(stream.stream_id, encoded);
      state.derived.set(salt, encoded);
      unlocked += locked.length;
      opened = true;
      break;
    }
    if (!opened) state.rejected.add(salt);
  }
  if (unlocked > 0) saveRememberedKeys();
  return unlocked;
}

els.unlockForm.addEventListener('submit', async event => {
  event.preventDefault();
  showError(els.unlockError, null);
  const typed = els.viewingKey.value;
  const submit = els.unlockForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  els.unlockStatus.textContent = 'Checking the key\u2026';
  try {
    await refreshStreams();
    const unlocked = await unlockWithKey(typed);
    els.viewingKey.value = '';
    els.unlockStatus.textContent = unlocked === 1
      ? 'Unlocked 1 stream.'
      : `Unlocked ${unlocked} streams.`;
    renderStreamList();
    showUnlockedStreams();
  } catch (error) {
    els.unlockStatus.textContent = '';
    showError(els.unlockError, error);
  } finally {
    submit.disabled = false;
  }
});

els.forgetAll.addEventListener('click', () => {
  for (const tile of state.tiles) detachTile(tile);
  forgetRememberedKeys();
  els.unlockStatus.textContent = 'Forgotten. Enter a key to watch again.';
  renderStreamList();
});

for (const button of document.querySelectorAll('[data-layout]')) {
  button.addEventListener('click', () => setLayout(Number(button.dataset.layout)));
}

/**
 * Shows or hides the stream list.
 *
 * The choice is remembered because someone who watches with the panel closed
 * wants it closed every time, not once per page load.
 */
function setSidebarCollapsed(collapsed, { persist = true } = {}) {
  els.main.classList.toggle('sidebar-collapsed', collapsed);
  els.sidebar.inert = collapsed;
  els.sidebarToggle.setAttribute('aria-expanded', String(!collapsed));
  els.sidebarToggle.title = collapsed
    ? `Show the stream list (${SIDEBAR_SHORTCUT})`
    : `Hide the stream list (${SIDEBAR_SHORTCUT})`;
  if (!persist) return;
  try {
    globalThis.localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? '1' : '0');
  } catch {
    // A browser with storage disabled still gets a working toggle, just not a
    // remembered one.
  }
}

function restoreSidebar() {
  let collapsed = false;
  try {
    collapsed = globalThis.localStorage.getItem(SIDEBAR_STORAGE_KEY) === '1';
  } catch {
    collapsed = false;
  }
  setSidebarCollapsed(collapsed, { persist: false });
}

function toggleSidebar() {
  setSidebarCollapsed(!els.main.classList.contains('sidebar-collapsed'));
}

els.sidebarToggle.addEventListener('click', toggleSidebar);

// Getting the list out of the way is something a viewer does while watching,
// with the pointer somewhere over a tile, so it is worth a key as well as a
// trip to the header. Ignored while typing, so it cannot eat a viewing key.
document.addEventListener('keydown', event => {
  if (event.key !== SIDEBAR_SHORTCUT) return;
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  const active = document.activeElement;
  if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) return;
  if (!state.watching) return;
  event.preventDefault();
  toggleSidebar();
});

function showError(element, error) {
  if (!element) return;
  element.hidden = !error;
  element.textContent = error ? (error.message || String(error)) : '';
}

async function refreshStreams() {
  const response = await fetch('/api/streams', { cache: 'no-store' });
  if (!response.ok) throw new Error('Unable to list streams.');
  state.streams = new Map((await response.json()).map(stream => [stream.stream_id, stream]));
  renderStreamList();
}

function streamTitle(streamId) {
  return state.streams.get(streamId)?.display_name || streamId;
}

function renderStreamList() {
  // Ordered by the relay's own ordering rather than by unlock order, so the
  // panel reads the same way every time.
  const known = [...state.streams.keys()].filter(streamId => state.keys.has(streamId));
  els.streamList.textContent = '';
  for (const streamId of known) {
    const item = document.createElement('li');
    item.draggable = true;
    item.dataset.streamId = streamId;
    const live = Boolean(state.streams.get(streamId)?.active);
    item.className = live ? 'live' : 'offline';

    const title = document.createElement('span');
    title.className = 'stream-name';
    title.textContent = streamTitle(streamId);
    const hint = document.createElement('span');
    hint.className = 'stream-hint';
    hint.textContent = live ? 'live' : 'not publishing';

    // The row itself is the control. Dragging is still the way to choose which
    // tile, but it is unavailable to keyboard and touch users, so a plain click
    // on the stream puts it in the first free one.
    const pick = document.createElement('button');
    pick.type = 'button';
    pick.className = 'stream-pick';
    pick.append(title, hint);
    pick.addEventListener('click', () => assignToFirstFreeTile(streamId));

    item.append(pick);
    item.addEventListener('dragstart', event => {
      event.dataTransfer.setData('text/plain', streamId);
      event.dataTransfer.effectAllowed = 'copy';
    });
    els.streamList.append(item);
  }
  els.forgetAll.hidden = known.length === 0;
  markOnScreen();
  setWatching(known.length > 0);
}

/**
 * Marks the streams that already have a tile.
 *
 * Kept apart from rendering the list so that attaching a tile does not rebuild
 * the row whose button is still handling the click that caused it.
 */
function markOnScreen() {
  for (const item of els.streamList.children) {
    item.classList.toggle(
      'on-screen',
      state.tiles.some(tile => tile.streamId === item.dataset.streamId),
    );
  }
}

/**
 * Switches the page between asking for a key and showing streams.
 *
 * These are different pages in everything but the URL: before a key opens
 * anything the only useful act is entering one, and a grid of empty tiles
 * offering to accept a drop is four invitations to do something impossible.
 * The single unlock form moves between the two rather than being written twice,
 * so there is one input to find, one set of listeners, and one error line
 * wherever the viewer is looking.
 */
function setWatching(watching) {
  // The first call settles which page this is, so it always runs even when the
  // answer matches the default.
  document.body.classList.remove('deciding');
  if (state.watching === watching) return;
  state.watching = watching;
  document.body.classList.toggle('empty', !watching);
  const slot = watching ? els.sidebarUnlock : els.welcomeUnlock;
  const vacated = watching ? els.welcomeUnlock : els.sidebarUnlock;
  slot.append(els.unlockForm);
  slot.hidden = false;
  vacated.hidden = true;
  // The status travels with the form, because it is what just happened --
  // "Unlocked 3 streams", or "Forgotten" on the way back. A stale error does
  // not: it describes an attempt the viewer has since moved past.
  showError(els.unlockError, null);
}

function setLayout(count) {
  state.layout = count;
  for (const button of document.querySelectorAll('[data-layout]')) {
    button.setAttribute('aria-pressed', String(Number(button.dataset.layout) === count));
  }
  els.grid.className = `grid layout-${count}`;

  // Shrinking the layout destroys the players it drops, so their sockets and
  // decoders are released rather than left running behind a hidden tile.
  while (state.tiles.length > count) {
    const tile = state.tiles.pop();
    detachTile(tile);
    tile.element.remove();
  }
  while (state.tiles.length < count) {
    state.tiles.push(createTile());
  }
}

function createTile() {
  const element = els.tileTemplate.content.firstElementChild.cloneNode(true);
  const tile = {
    element,
    streamId: null,
    player: null,
    title: element.querySelector('.tile-title'),
    body: element.querySelector('[data-role="player"]'),
    message: element.querySelector('[data-role="stage-message"]'),
  };

  element.addEventListener('dragover', event => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    element.classList.add('drop-target');
  });
  element.addEventListener('dragleave', () => element.classList.remove('drop-target'));
  element.addEventListener('drop', event => {
    event.preventDefault();
    element.classList.remove('drop-target');
    const streamId = event.dataTransfer.getData('text/plain');
    if (streamId) attachTile(tile, streamId);
  });

  element.querySelector('[data-action="remove"]').addEventListener('click', () => {
    detachTile(tile);
  });
  element.querySelector('[data-action="fullscreen"]').addEventListener('click', () => {
    if (document.fullscreenElement === element) document.exitFullscreen();
    else element.requestFullscreen?.();
  });

  els.grid.append(element);
  return tile;
}

function assignToFirstFreeTile(streamId) {
  const existing = state.tiles.find(tile => tile.streamId === streamId);
  if (existing) return;
  const free = state.tiles.find(tile => !tile.streamId);
  if (free) {
    attachTile(free, streamId);
    return;
  }
  if (state.tiles.length < MAX_TILES) {
    setLayout(Math.min(MAX_TILES, state.tiles.length + 1));
    attachTile(state.tiles.at(-1), streamId);
    return;
  }
  attachTile(state.tiles[0], streamId);
}

function attachTile(tile, streamId) {
  const key = state.keys.get(streamId);
  if (!key) {
    tile.message.textContent = 'That stream is not unlocked in this tab.';
    return;
  }
  // Moving a stream that is already on screen swaps the two tiles rather than
  // decoding it twice.
  const occupied = state.tiles.find(other => other !== tile && other.streamId === streamId);
  const displaced = tile.streamId;
  detachTile(tile);
  if (occupied) {
    detachTile(occupied);
    if (displaced) attachTile(occupied, displaced);
  }

  tile.streamId = streamId;
  tile.title.textContent = streamTitle(streamId);
  tile.message.textContent = 'Preparing encrypted media…';
  mountPlayer(tile, streamId, key);
  markOnScreen();
}

/**
 * Starts a player in a tile, waiting rather than giving up when the stream has
 * simply not started sending yet.
 *
 * A publisher on GNOME or KDE registers its stream before the screen-sharing
 * prompt has been accepted, so the first viewer to arrive reliably lands on a
 * stream with no media in it. That used to leave a black tile until the page was
 * reloaded by hand. The player is rebuilt for each attempt rather than restarted,
 * because a failed start leaves a half-built MediaSource behind.
 */
function mountPlayer(tile, streamId, key) {
  tile.player = Player.createPlayer(tile.body, {
    streamId,
    onStatus: update => {
      tile.element.classList.toggle('failed', Boolean(update.error));
    },
  });
  watchForFirstFrame(tile, streamId);
  tile.player.start(key).catch(error => {
    // A tile reassigned or emptied while the start was in flight has already
    // been torn down, and must not be revived here.
    if (!error?.retryable || tile.streamId !== streamId) return;
    tile.player?.destroy();
    tile.player = null;
    tile.element.classList.remove('failed');
    tile.retryTimer = setTimeout(() => {
      tile.retryTimer = null;
      if (tile.streamId !== streamId) return;
      mountPlayer(tile, streamId, key);
    }, STREAM_RETRY_INTERVAL_MS);
  });
}

/**
 * Says something when a tile never produces a picture.
 *
 * Starting a player can fail without ever rejecting: the media element waits
 * for a frame that never arrives, and the promise chain simply does not settle.
 * Nothing downstream of that runs, so the tile kept its "Preparing encrypted
 * media" message for as long as the page stayed open -- no error, no retry, and
 * nothing to act on.
 *
 * This does not diagnose the cause. It converts silence into a sentence, which
 * is worth having whatever the cause turns out to be.
 */
function watchForFirstFrame(tile, streamId) {
  clearTimeout(tile.stallTimer);
  tile.stallTimer = setTimeout(() => {
    tile.stallTimer = null;
    if (tile.streamId !== streamId) return;
    const video = tile.element.querySelector('[data-role="video"]');
    // readyState below HAVE_CURRENT_DATA means no frame was ever decoded.
    if (video && video.readyState >= 2) return;
    tile.element.classList.add('failed');
    tile.message.textContent = STALLED_MESSAGE;
    // A slow start is not a permanent one. If a frame does arrive later the
    // player clears the message itself, so the mark has to go with it rather
    // than leaving a tile flagged for the rest of the session.
    video?.addEventListener('playing', () => {
      tile.element.classList.remove('failed');
    }, { once: true });
  }, STREAM_STALL_TIMEOUT_MS);
}

function detachTile(tile) {
  clearTimeout(tile.retryTimer);
  tile.retryTimer = null;
  clearTimeout(tile.stallTimer);
  tile.stallTimer = null;
  tile.player?.destroy();
  tile.player = null;
  tile.streamId = null;
  tile.title.textContent = 'Empty';
  tile.message.textContent = 'Pick a stream';
  tile.element.classList.remove('failed');
  markOnScreen();
  const status = tile.element.querySelector('[data-role="status"]');
  const metrics = tile.element.querySelector('[data-role="metrics"]');
  if (status) status.textContent = '';
  if (metrics) metrics.textContent = '';
}

globalThis.addEventListener('pagehide', () => {
  for (const tile of state.tiles) detachTile(tile);
});

// Exposed for the browser gate, which needs to inspect tile state without
// reaching into module internals.
globalThis.GlacialCastWatch = {
  tiles: () => state.tiles.map(tile => ({
    streamId: tile.streamId,
    metrics: tile.player?.metrics() || null,
  })),
  layout: () => state.layout,
  sidebarCollapsed: () => els.main.classList.contains('sidebar-collapsed'),
  unlockedStreams: () => [...state.keys.keys()],
};

/**
 * Fills the grid with whatever is already unlocked.
 *
 * Arriving at a viewer that holds your keys and shows an empty grid is a
 * chore: the obvious next action is always "put them on screen". The layout is
 * sized to what there is, so three screens land in a four-up grid and one lands
 * on its own rather than in a mostly empty one.
 */
function showUnlockedStreams() {
  const available = [...state.streams.keys()].filter(streamId => state.keys.has(streamId));
  if (available.length === 0) return;
  const fitted = available.length > 2 ? 4 : available.length;
  if (fitted !== state.layout) setLayout(fitted);
  for (const [index, streamId] of available.slice(0, state.tiles.length).entries()) {
    // Reattaching a tile tears down a working player, so a stream already on
    // screen is left exactly where it is.
    if (state.tiles.some(tile => tile.streamId === streamId)) continue;
    if (state.tiles[index].streamId) continue;
    attachTile(state.tiles[index], streamId);
  }
}

/**
 * Reads a viewing key out of an invitation link.
 *
 * The key travels in the fragment, after the `#`, which browsers never put in a
 * request -- so the relay cannot see the key even though the link that carries it
 * points at the relay. A query parameter would be sent, and logged.
 */
function inviteKeyFromUrl() {
  const fragment = globalThis.location.hash.replace(/^#/, '');
  if (!fragment) return null;
  const key = new URLSearchParams(fragment).get('k');
  return key ? key.trim() : null;
}

/**
 * Takes the key out of the address bar once it has been read.
 *
 * The key is remembered on this browser by then, so leaving it in the URL only
 * creates ways to leak it: the address bar is visible in any screen share, and a
 * copied link hands the stream to whoever receives it.
 */
function stripInviteKeyFromUrl() {
  const { pathname, search } = globalThis.location;
  globalThis.history.replaceState(null, '', `${pathname}${search}`);
}

/**
 * Says why this browser cannot decrypt here, instead of offering a key field
 * that cannot work.
 *
 * Deriving a key is the first thing that touches `crypto.subtle`, and browsers
 * withhold it outside a secure context -- so on a plain `http://` address that
 * is not localhost, typing a correct key produced `undefined is not an object
 * (reading 'importKey')`. That is an accurate description of the third line of
 * a key-derivation routine and no help at all to someone who just wants to
 * know why the page will not play.
 *
 * Asked before the stream list, because nothing below it can succeed and the
 * answer does not depend on what the relay holds.
 */
function refuseUnusablePlatform() {
  const problem = Player.platformProblem();
  if (!problem) return false;
  document.body.classList.remove('deciding');
  document.body.classList.add('empty');
  const lead = document.querySelector('.welcome-lead');
  if (lead) lead.textContent = problem;
  els.unlockForm.hidden = true;
  return true;
}

restoreSidebar();
setLayout(state.layout);
loadRememberedKeys();

// The key arrives in the link before the page can act on it, so it is read and
// erased from the URL immediately, then used once the stream list is known.
const invitedKey = inviteKeyFromUrl();
if (invitedKey) stripInviteKeyFromUrl();

// Nothing below this can work if the browser will not do the cryptography, and
// the reason has nothing to do with the relay, so it is settled first.
if (!refuseUnusablePlatform()) {

// Streams are listed before anything is unlocked so the panel can say whether
// the relay has anything to show at all, and so a key entered a moment later
// has publishers to match against.
refreshStreams()
  .then(async () => {
    if (invitedKey) {
      els.unlockStatus.textContent = 'Opening your invitation…';
      try {
        const unlocked = await unlockWithKey(invitedKey);
        els.unlockStatus.textContent = unlocked === 1
          ? 'Unlocked 1 stream.'
          : `Unlocked ${unlocked} streams.`;
      } catch (error) {
        els.unlockStatus.textContent = '';
        showError(els.unlockError, error);
      }
    }
    await applyRememberedKeys();
    renderStreamList();
    showUnlockedStreams();
  })
  .catch(error => showError(els.unlockError, error));

// A publisher can add a screen, or come back from a restart under a new stream,
// long after this page loaded. Polling for that keeps the promise that the key is
// entered once: the new screen unlocks itself and appears.
//
// The layout is only re-fitted when something actually unlocked, because doing it
// on every poll would keep overriding a layout the viewer chose by hand.
setInterval(async () => {
  try {
    await refreshStreams();
    if (await applyRememberedKeys() > 0) {
      renderStreamList();
      showUnlockedStreams();
    }
  } catch {
    // A failed poll is retried by the next one.
  }
}, STREAM_POLL_INTERVAL_MS);

}
