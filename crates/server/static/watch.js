'use strict';

// The multi-stream viewer: a side panel of streams this browser holds keys
// for, and a grid of one, two, or four tiles they can be dragged into.
//
// Each tile owns an independent player instance, so tiles start and stop
// without disturbing one another and each can be full-screened on its own.

const Player = globalThis.GlacialCastPlayer;
const Keyring = globalThis.GlacialCastKeyring;
if (!Player || !Keyring) throw new Error('The GlacialCast viewer failed to load.');

const els = {
  unlockForm: document.querySelector('#unlock-keyring'),
  passphrase: document.querySelector('#passphrase'),
  keyringError: document.querySelector('#keyring-error'),
  keyringPanel: document.querySelector('#keyring-panel'),
  streamList: document.querySelector('#stream-list'),
  emptyHint: document.querySelector('#empty-hint'),
  addForm: document.querySelector('#add-key'),
  addStream: document.querySelector('#add-stream'),
  addKey: document.querySelector('#add-key-value'),
  addError: document.querySelector('#add-error'),
  forgetAll: document.querySelector('#forget-all'),
  grid: document.querySelector('#grid'),
  headline: document.querySelector('#headline'),
  tileTemplate: document.querySelector('#tile-template'),
  main: document.querySelector('main'),
  sidebar: document.querySelector('#sidebar'),
  sidebarToggle: document.querySelector('#sidebar-toggle'),
};

const SIDEBAR_STORAGE_KEY = 'glacialcast.sidebar.collapsed';

const MAX_TILES = 4;
const state = {
  keyring: null,
  /** Relay stream metadata by stream ID. */
  streams: new Map(),
  /** One entry per visible tile. */
  tiles: [],
  layout: 1,
};

els.unlockForm.addEventListener('submit', async event => {
  event.preventDefault();
  showError(els.keyringError, null);
  try {
    state.keyring = await Keyring.unlock(els.passphrase.value);
    els.passphrase.value = '';
    els.unlockForm.hidden = true;
    els.keyringPanel.hidden = false;
    await refreshStreams();
    setLayout(state.layout);
  } catch (error) {
    showError(els.keyringError, error);
  }
});

els.addForm.addEventListener('submit', async event => {
  event.preventDefault();
  showError(els.addError, null);
  try {
    await state.keyring.remember(els.addStream.value, els.addKey.value);
    els.addKey.value = '';
    renderStreamList();
  } catch (error) {
    showError(els.addError, error);
  }
});

els.forgetAll.addEventListener('click', () => {
  if (!globalThis.confirm('Forget every stored viewer key in this browser?')) return;
  for (const tile of state.tiles) detachTile(tile);
  state.keyring.forgetAll();
  state.keyring = null;
  els.keyringPanel.hidden = true;
  els.unlockForm.hidden = false;
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
  const known = state.keyring ? state.keyring.streamIds() : [];
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

    const forget = document.createElement('button');
    forget.type = 'button';
    forget.className = 'link';
    forget.textContent = 'Forget';
    forget.addEventListener('click', () => {
      for (const tile of state.tiles) {
        if (tile.streamId === streamId) detachTile(tile);
      }
      state.keyring.forget(streamId);
      renderStreamList();
    });

    item.append(title, hint, watch, forget);
    item.addEventListener('dragstart', event => {
      event.dataTransfer.setData('text/plain', streamId);
      event.dataTransfer.effectAllowed = 'copy';
    });
    els.streamList.append(item);
  }
  els.emptyHint.hidden = known.length > 0;

  els.addStream.textContent = '';
  for (const [streamId, stream] of state.streams) {
    const option = document.createElement('option');
    option.value = streamId;
    option.textContent = `${stream.display_name} — ${streamId.slice(0, 8)}`;
    els.addStream.append(option);
  }
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
  const key = state.keyring?.getEncoded(streamId);
  if (!key) {
    tile.message.textContent = 'No stored key for that stream.';
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
};

restoreSidebar();
setLayout(1);
if (!Keyring.exists()) {
  els.headline.textContent = 'Open a keyring, then add the viewer keys you were given';
}
