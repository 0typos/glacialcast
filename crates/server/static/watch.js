'use strict';

// The multi-stream viewer: a side panel of the streams this tab has unlocked,
// and a grid of one, two, or four tiles they can be dragged into.
//
// Each tile owns an independent player instance, so tiles start and stop
// without disturbing one another and each can be full-screened on its own.
//
// A viewing key is entered once. One key covers every screen a publisher
// casts, so entering it unlocks all of them at once rather than asking again
// per monitor, and it is held in session storage so a reload does not ask
// again either. Session storage is deliberate: the key lives as long as the
// tab and no longer, so closing the browser leaves nothing behind on disk.

const Player = globalThis.GlacialCastPlayer;
const ViewerKey = globalThis.GlacialCastViewerKey;
if (!Player || !ViewerKey) throw new Error('The GlacialCast viewer failed to load.');

const els = {
  unlockForm: document.querySelector('#unlock'),
  viewingKey: document.querySelector('#viewing-key'),
  unlockError: document.querySelector('#unlock-error'),
  unlockStatus: document.querySelector('#unlock-status'),
  streamList: document.querySelector('#stream-list'),
  emptyHint: document.querySelector('#empty-hint'),
  forgetAll: document.querySelector('#forget-all'),
  grid: document.querySelector('#grid'),
  headline: document.querySelector('#headline'),
  tileTemplate: document.querySelector('#tile-template'),
  main: document.querySelector('main'),
  sidebar: document.querySelector('#sidebar'),
  sidebarToggle: document.querySelector('#sidebar-toggle'),
};

const SIDEBAR_STORAGE_KEY = 'glacialcast.sidebar.collapsed';
const SESSION_KEY_STORE = 'glacialcast.session.keys.v1';

const MAX_TILES = 4;
const state = {
  /** Unlocked viewer keys as URL-safe base64, by stream ID. */
  keys: new Map(),
  /** Relay stream metadata by stream ID. */
  streams: new Map(),
  /** One entry per visible tile. */
  tiles: [],
  layout: 4,
};

/** Reads the keys this tab already unlocked. */
function loadSessionKeys() {
  try {
    const raw = globalThis.sessionStorage.getItem(SESSION_KEY_STORE);
    if (!raw) return;
    for (const [streamId, key] of Object.entries(JSON.parse(raw))) {
      if (typeof key === 'string') state.keys.set(streamId, key);
    }
  } catch {
    // A corrupt or unavailable store just means unlocking again.
  }
}

function saveSessionKeys() {
  try {
    globalThis.sessionStorage.setItem(
      SESSION_KEY_STORE,
      JSON.stringify(Object.fromEntries(state.keys)),
    );
  } catch {
    // Without session storage the key still works, it just has to be retyped
    // after a reload.
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
async function unlockWithKey(typed) {
  const publishers = new Map();
  for (const stream of state.streams.values()) {
    if (!publishers.has(stream.publisher)) publishers.set(stream.publisher, []);
    publishers.get(stream.publisher).push(stream);
  }
  if (publishers.size === 0) throw new Error('No streams are published yet.');

  let unlocked = 0;
  const failures = [];
  for (const streams of publishers.values()) {
    let bytes;
    try {
      bytes = await ViewerKey.resolveKey(typed, streams[0].viewer_key_salt);
    } catch (error) {
      failures.push(error);
      continue;
    }
    // One screen answers for the publisher: the key is the same for all of
    // them, so checking every screen would only repeat the same fetch.
    if (!await Player.verifyViewerKey(streams[0].stream_id, bytes)) continue;

    const encoded = ViewerKey.bytesToBase64Url(bytes);
    for (const stream of streams) state.keys.set(stream.stream_id, encoded);
    unlocked += streams.length;
  }

  if (unlocked === 0) {
    // Every publisher rejected the key. If none of them could even parse it,
    // the parse error is the more useful thing to say.
    if (failures.length === publishers.size && failures[0]) throw failures[0];
    throw new Error('That key does not open any stream published here.');
  }
  saveSessionKeys();
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
  state.keys.clear();
  try {
    globalThis.sessionStorage.removeItem(SESSION_KEY_STORE);
  } catch {
    // Nothing stored means nothing to remove.
  }
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
  els.sidebarToggle.title = collapsed ? 'Show the stream list' : 'Hide the stream list';
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

els.sidebarToggle.addEventListener('click', () => {
  setSidebarCollapsed(!els.main.classList.contains('sidebar-collapsed'));
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
    item.className = state.streams.get(streamId)?.active ? 'live' : 'offline';

    const title = document.createElement('span');
    title.className = 'stream-name';
    title.textContent = streamTitle(streamId);
    const hint = document.createElement('span');
    hint.className = 'stream-hint';
    hint.textContent = state.streams.get(streamId)?.active ? 'live' : 'not publishing';

    const watch = document.createElement('button');
    watch.type = 'button';
    watch.textContent = 'Watch';
    // Dragging is the primary gesture, but it is unavailable to keyboard and
    // touch users, so every stream is also one click away from a free tile.
    watch.addEventListener('click', () => assignToFirstFreeTile(streamId));

    item.append(title, hint, watch);
    item.addEventListener('dragstart', event => {
      event.dataTransfer.setData('text/plain', streamId);
      event.dataTransfer.effectAllowed = 'copy';
    });
    els.streamList.append(item);
  }
  els.emptyHint.hidden = known.length > 0;
  els.forgetAll.hidden = known.length === 0;
  // Once something is unlocked the form is no longer the point of the panel,
  // but it stays reachable for a second publisher's key.
  els.unlockForm.classList.toggle('secondary', known.length > 0);
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
  tile.player = Player.createPlayer(tile.body, {
    streamId,
    onStatus: update => {
      tile.element.classList.toggle('failed', Boolean(update.error));
    },
  });
  tile.player.start(key).catch(() => {});
}

function detachTile(tile) {
  tile.player?.destroy();
  tile.player = null;
  tile.streamId = null;
  tile.title.textContent = 'Empty';
  tile.message.textContent = 'Drop a stream here';
  tile.element.classList.remove('failed');
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

restoreSidebar();
setLayout(state.layout);
loadSessionKeys();

// Streams are listed before anything is unlocked so the panel can say whether
// the relay has anything to show at all, and so a key entered a moment later
// has publishers to match against.
refreshStreams()
  .then(() => {
    showUnlockedStreams();
    els.headline.textContent = state.keys.size > 0
      ? 'Drag a stream into a tile'
      : 'Enter the viewing key you were given';
  })
  .catch(error => showError(els.unlockError, error));
