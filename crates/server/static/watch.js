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
/**
 * Where the arrangement lives: which streams are on screen and in which tile,
 * which are parked, which are hidden, and what this viewer calls them.
 *
 * Separate from the key store because it answers a different question and has a
 * different lifetime. "Forget keys" gives up access; it does not mean the
 * viewer has changed their mind about what to call their kitchen camera, and
 * re-entering the key puts the arrangement back rather than starting over.
 *
 * Per-browser, like the keys, and never sent to the relay. A name typed here is
 * this viewer's private label -- the relay is not told, and other viewers of
 * the same stream see whatever the publisher called it.
 */
const PLACEMENT_STORE = 'glacialcast.streams.v1';
const PLACEMENT_STORE_VERSION = 1;
/** Longest custom name kept, so one pasted essay cannot fill the store. */
const MAX_STREAM_NAME = 80;
/**
 * How many streams' arrangements to remember.
 *
 * A publisher that reconnects under a new identity leaves its old record
 * behind, so on a long-lived relay this would otherwise only grow. The map
 * keeps insertion order, so the oldest records are the ones dropped.
 */
const MAX_REMEMBERED_PLACEMENTS = 500;

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
/**
 * Why this browser cannot play an end-to-end encrypted stream, or `null`.
 *
 * Asked once, because it cannot change while the page is open. It is not a
 * reason to refuse the page: a relay on a trusted LAN can publish in the clear,
 * and those streams play here even where encrypted ones never will -- which is
 * the whole of what an iPhone can do. So it is used to explain a key that
 * cannot work, not to withhold everything.
 */
const ENCRYPTED_UNSUPPORTED = Player.platformProblem({ encrypted: true });

const state = {
  /**
   * Unlocked streams, by stream ID.
   *
   * The value is the viewer key as URL-safe base64, or `null` for a stream the
   * publisher sent in the clear, which needs none. Membership is what says a
   * stream is unlocked; the value only says how. So every test here asks `has`,
   * never whether the value is truthy.
   */
  keys: new Map(),
  /**
   * The epoch each stream's encryption was last read from, by stream ID.
   *
   * Whether a stream is encrypted is a property of its epoch, so the answer
   * only goes stale when the epoch does. Holding the epoch it was read from
   * turns "should I ask again?" into comparing two values from the relay's own
   * listing, rather than watching a stream go inactive and back and hoping a
   * publisher restart lands between two polls.
   *
   * A stream with no epoch yet maps to null, which never equals the epoch that
   * eventually arrives, so it is re-asked until there is something to read.
   *
   * Each value is `{ epochId, encrypted }`. The mode is kept alongside because
   * the remembered keys are applied first and must not claim a stream already
   * known to need none -- doing so would take it back from the keyless unlock
   * on every poll, forever.
   */
  described: new Map(),
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
  /**
   * This viewer's arrangement, by stream ID.
   *
   * Each record is `{ slot, hidden, name }`. `slot` is a tile number from 1 to
   * MAX_TILES and puts the stream on screen there; null means parked -- in the
   * list, ready to be added, not decoding. `hidden` takes it out of the list
   * altogether, and clears any slot, because a stream cannot be both out of
   * sight and on screen.
   */
  placements: new Map(),
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
  // Clearing the keys also clears the keyless unlocks, which were never keys at
  // all. Forgetting what has been described re-asks for each stream once, which
  // is what puts the streams that need no key straight back.
  state.described.clear();
  try {
    globalThis.localStorage.removeItem(KEY_STORE);
  } catch {
    // Nothing stored means nothing to remove.
  }
}

/** What a stream with no remembered arrangement gets: listed, unnamed, parked. */
const NO_PLACEMENT = Object.freeze({ slot: null, hidden: false, name: '' });

function loadPlacements() {
  try {
    const raw = globalThis.localStorage.getItem(PLACEMENT_STORE);
    if (!raw) return;
    const stored = JSON.parse(raw);
    if (stored?.version !== PLACEMENT_STORE_VERSION) return;
    const taken = new Set();
    for (const [streamId, record] of Object.entries(stored.streams ?? {})) {
      const placement = sanitizePlacement(record);
      // One tile, one stream. A store written by a version that could hand the
      // same number out twice would otherwise keep doing it: whichever stream
      // was restored first took the tile and the other stayed listed as on
      // screen while never appearing. The later record is the one parked, so
      // the arrangement loses a position rather than a stream.
      if (placement.slot !== null) {
        if (taken.has(placement.slot)) placement.slot = null;
        else taken.add(placement.slot);
      }
      state.placements.set(streamId, placement);
    }
  } catch {
    // A corrupt or unavailable store just means arranging again.
  }
}

/**
 * Reads one stored record without trusting it.
 *
 * Local storage is editable by hand and survives across versions, so a slot
 * outside the grid or a name of unbounded length has to be treated as data
 * rather than as something this page wrote.
 */
function sanitizePlacement(record) {
  const hidden = record?.hidden === true;
  const slot = Number(record?.slot);
  const usable = !hidden && Number.isInteger(slot) && slot >= 1 && slot <= MAX_TILES;
  return {
    slot: usable ? slot : null,
    hidden,
    name: typeof record?.name === 'string' ? record.name.trim().slice(0, MAX_STREAM_NAME) : '',
  };
}

function savePlacements() {
  while (state.placements.size > MAX_REMEMBERED_PLACEMENTS) {
    state.placements.delete(state.placements.keys().next().value);
  }
  try {
    globalThis.localStorage.setItem(PLACEMENT_STORE, JSON.stringify({
      version: PLACEMENT_STORE_VERSION,
      streams: Object.fromEntries(state.placements),
    }));
  } catch {
    // Without storage the arrangement still works for this page; it just has to
    // be made again next time.
  }
}

/**
 * Reads a stream's arrangement, without creating one.
 *
 * Non-creating on purpose: this is called while rendering and while labelling
 * tiles, and a read that quietly recorded every stream it was asked about would
 * fill the store with streams the viewer never touched.
 */
function placementOf(streamId) {
  return state.placements.get(streamId) ?? NO_PLACEMENT;
}

function updatePlacement(streamId, changes) {
  const record = { ...placementOf(streamId), ...changes };
  // A hidden stream cannot also be on screen, and this is the one place that
  // has to hold, so it is enforced here rather than at each caller.
  if (record.hidden) record.slot = null;
  state.placements.set(streamId, record);
  savePlacements();
}

/**
 * The stream holding a tile number, whether or not it is unlocked right now.
 *
 * Deliberately not filtered by which streams have keys. A remembered stream
 * that is momentarily locked -- after "Forget keys", before a key is re-entered
 * -- still owns its number, and treating that number as free handed it to a
 * second stream without going through the displacement below. Both then held
 * it, the panel showed two rows badged with the same tile, and only one of them
 * was ever rendered.
 */
function streamInSlot(slot) {
  for (const [streamId, record] of state.placements) {
    if (record.slot === slot) return streamId;
  }
  return null;
}

function firstFreeSlot() {
  for (let slot = 1; slot <= MAX_TILES; slot += 1) {
    if (!streamInSlot(slot)) return slot;
  }
  return null;
}

/** Puts `streamId` in `slot`, turning out whatever held it. */
function assignSlot(streamId, slot) {
  const displaced = streamInSlot(slot);
  if (displaced && displaced !== streamId) updatePlacement(displaced, { slot: null });
  updatePlacement(streamId, { slot, hidden: false });
}

/**
 * Gives a stream nobody has arranged yet a place to be.
 *
 * A free tile if there is one, because a viewer who arrives holding keys and
 * finds an empty grid has to put their own screens on it, and the obvious next
 * action is always the same. Past the fourth it parks instead: a fifth screen
 * turning up and displacing one being watched is the behaviour worth stopping,
 * and it is exactly what "available, but not now" is for.
 *
 * Recorded either way, so the answer is only decided once. A stream parked by
 * hand stays parked when it is seen again.
 */
function placeNewStreams(streamIds) {
  let placed = 0;
  for (const streamId of streamIds) {
    if (state.placements.has(streamId)) continue;
    const slot = firstFreeSlot();
    state.placements.set(streamId, { ...NO_PLACEMENT, slot });
    placed += 1;
  }
  if (placed > 0) savePlacements();
  return placed;
}

/** What the publisher calls this stream. */
function publishedTitle(streamId) {
  return state.streams.get(streamId)?.display_name || streamId;
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
  // A correct key is no use in a browser that cannot decrypt, and finding that
  // out after typing it is worse than being told before.
  if (ENCRYPTED_UNSUPPORTED) throw new Error(ENCRYPTED_UNSUPPORTED);
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
    for (const stream of streams) setStreamKey(stream.stream_id, encoded);
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
 * Records the key a stream is unlocked with, remounting it if it changed.
 *
 * A player is handed its key once, at start, and derives every epoch key from
 * it for the life of the tile. So a stream already on screen under one key --
 * an old one, or the provisional acceptance a stream with no epoch yet gets --
 * went on using it after a new key arrived, failing every object against a key
 * the viewer had already replaced. Nothing put that right short of a reload.
 *
 * Detaching is enough to fix it: the tile keeps its number, so the restore that
 * follows puts the stream back with the key now recorded here.
 */
function setStreamKey(streamId, key) {
  const changed = state.keys.has(streamId) && state.keys.get(streamId) !== key;
  state.keys.set(streamId, key);
  // A key that verified against this stream's newest epoch has already answered
  // the question `unlockOpenStreams` would ask: the epoch is encrypted, because
  // an unencrypted one is opened by no key at all and `verifyViewerKey` says so.
  //
  // Recording it here matters for more than tidiness. Without it, every page
  // load re-described every stream the remembered keys had just unlocked --
  // two fetches each, in series, alongside a WebSocket per tile and against a
  // browser's per-host connection limit. On a loaded machine that was enough to
  // leave a navigation queued behind them.
  if (key !== null) {
    state.described.set(streamId, {
      epochId: state.streams.get(streamId)?.last_epoch_id ?? null,
      encrypted: true,
    });
  }
  if (changed) dropTilesFor(streamId);
}

/**
 * Opens everything the remembered secrets can open, without asking.
 *
 * Runs on load and again whenever the stream list changes, so a screen the
 * publisher adds later, or one that comes back under a new stream after a
 * reconnect, appears already unlocked rather than prompting again.
 */
async function applyRememberedKeys() {
  if (state.secrets.size === 0 || ENCRYPTED_UNSUPPORTED) return 0;
  let unlocked = 0;
  for (const streams of publishersByName().values()) {
    // A stream already known to need no key is not locked, it is open. Trying a
    // key against it would take it back from the keyless unlock every poll.
    const locked = streams.filter(stream => !state.keys.has(stream.stream_id)
      && state.described.get(stream.stream_id)?.encrypted !== false);
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
      for (const stream of locked) setStreamKey(stream.stream_id, encoded);
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

/**
 * Opens the streams that need no key, because the publisher sent them in the
 * clear to a trusted LAN.
 *
 * Runs after the remembered keys, deliberately. A relay that claimed a stream
 * was published in the clear when the publisher encrypts it would otherwise get
 * that stream opened keyless and be free to serve anything as its contents;
 * trying the key first means a stream a key opens is held by that key, and the
 * player refuses a clear epoch on it. So the relay's answer only ever decides
 * streams no key of this viewer's opens anyway.
 *
 * The descriptor, not the stream listing, is what is asked -- see
 * `describeStream`. The listing is trusted for one thing only: which epoch is
 * current, so this can tell when the answer is worth asking for again.
 */
async function unlockOpenStreams() {
  let unlocked = 0;
  for (const [streamId, stream] of state.streams) {
    const epochId = stream.last_epoch_id ?? null;
    if (state.described.get(streamId)?.epochId === epochId) continue;
    // A new epoch is a new answer to every question about this publisher,
    // including one whose key was tried and did not fit. Without this, a
    // publisher that went from clear to encrypted would stay in `rejected`
    // from the attempt made while it had no key at all.
    state.rejected.delete(stream.viewer_key_salt);
    const { encrypted } = await Player.describeStream(streamId);
    // Null means the stream has published nothing to tell from yet. Nothing is
    // remembered and nothing is unlocked: the next poll asks again.
    if (encrypted === null) continue;
    state.described.set(streamId, { epochId, encrypted });
    if (encrypted) {
      // A stream that was open and is now encrypted has to give up its keyless
      // unlock, or every tile showing it fails forever against a key of null
      // with no retry -- the refusal is deliberate, so it is not retryable.
      if (state.keys.get(streamId) === null) {
        state.keys.delete(streamId);
        dropTilesFor(streamId);
      }
      continue;
    }
    // And the reverse: a key held for a stream now published in the clear
    // refuses every epoch. Dropping it lets the keyless unlock below take over.
    if (state.keys.get(streamId)) {
      state.keys.delete(streamId);
      dropTilesFor(streamId);
    }
    if (state.keys.has(streamId)) continue;
    state.keys.set(streamId, null);
    unlocked += 1;
  }
  return unlocked;
}

/**
 * Tears down whatever is showing a stream, without disturbing its arrangement.
 *
 * For when the stream itself changed underneath a running player -- a publisher
 * that restarted into the other encryption mode. The tile keeps its number, so
 * the stream is re-attached under the new mode by the same restore that puts
 * everything else back.
 */
function dropTilesFor(streamId) {
  for (const tile of state.tiles) {
    if (tile.streamId === streamId) detachTile(tile);
  }
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

els.forgetAll.addEventListener('click', async () => {
  for (const tile of state.tiles) detachTile(tile);
  forgetRememberedKeys();
  els.unlockStatus.textContent = 'Forgotten. Enter a key to watch again.';
  renderStreamList();
  // A stream published in the clear was never opened by a key, so there is
  // nothing about it to forget and it stays watchable. Re-opening those here
  // rather than waiting for the next poll keeps them from vanishing for ten
  // seconds and coming back on their own -- and they go back on screen, not
  // merely back in the list, because the tiles were just emptied above and
  // their numbers still say where they belong.
  if (await unlockOpenStreams() > 0) {
    renderStreamList();
    showUnlockedStreams();
  }
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
  state.streams = new Map(
    (await response.json()).map(stream => [stream.stream_id, stream]),
  );
  renderStreamList();
}

/** What to call this stream here: the viewer's own name, or the publisher's. */
function streamTitle(streamId) {
  return placementOf(streamId).name || publishedTitle(streamId);
}

function renderStreamList() {
  // Ordered by the relay's own ordering rather than by unlock order, so the
  // panel reads the same way every time. Within "on screen" the tile number
  // wins, because that is the order on the grid.
  const known = [...state.streams.keys()].filter(streamId => state.keys.has(streamId));
  placeNewStreams(known);

  const onScreen = [];
  const available = [];
  const hidden = [];
  for (const streamId of known) {
    const record = placementOf(streamId);
    if (record.hidden) hidden.push(streamId);
    else if (record.slot) onScreen.push(streamId);
    else available.push(streamId);
  }
  onScreen.sort((left, right) => placementOf(left).slot - placementOf(right).slot);

  els.streamList.textContent = '';
  renderStreamGroup('On screen', onScreen, 'screen');
  renderStreamGroup('Available', available, 'available');
  renderStreamGroup('Hidden', hidden, 'hidden');

  els.forgetAll.hidden = known.length === 0;
  markOnScreen();
  setWatching(known.length > 0);
}

/**
 * Renders one section of the panel.
 *
 * An empty section is not rendered at all: a heading over nothing reads as
 * something having gone wrong, and on the common arrangement -- everything on
 * screen, nothing parked or hidden -- the panel should look exactly as it did
 * before any of this existed.
 */
function renderStreamGroup(title, streamIds, kind) {
  if (streamIds.length === 0) return;
  const group = document.createElement('section');
  group.className = `stream-group stream-group-${kind}`;
  const list = document.createElement('ul');
  list.className = 'stream-list';
  for (const streamId of streamIds) list.append(renderStreamRow(streamId, kind));

  if (kind === 'hidden') {
    // Folded away, because the point of hiding a stream is not to see it. Still
    // present, and still counted, because a removal with no way back is a trap.
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `${title} (${streamIds.length})`;
    details.append(summary, list);
    group.append(details);
  } else {
    const heading = document.createElement('h3');
    heading.textContent = title;
    group.append(heading, list);
  }
  els.streamList.append(group);
}

function renderStreamRow(streamId, kind) {
  const item = document.createElement('li');
  item.dataset.streamId = streamId;
  // Dragging is how a stream is put in a particular tile. A hidden one has no
  // business being dropped anywhere until it is out of hiding.
  item.draggable = kind !== 'hidden';
  const record = placementOf(streamId);
  const live = Boolean(state.streams.get(streamId)?.active);
  item.className = live ? 'live' : 'offline';

  // The whole row is the primary control, and it is deliberately the first
  // button in the row: the obvious gesture is to click the thing you want to
  // watch, and that is also what the browser gates click.
  const pick = document.createElement('button');
  pick.type = 'button';
  pick.className = 'stream-pick';

  if (record.slot) {
    const slot = document.createElement('span');
    slot.className = 'stream-slot';
    slot.textContent = String(record.slot);
    slot.title = `Tile ${record.slot}`;
    pick.append(slot);
  }

  const label = document.createElement('span');
  label.className = 'stream-label';
  const name = document.createElement('span');
  name.className = 'stream-name';
  name.textContent = streamTitle(streamId);
  label.append(name);
  // What the publisher calls it, whenever that is not what is shown. Renaming
  // is for the viewer's convenience and must not make a stream unidentifiable.
  if (record.name) {
    const published = document.createElement('span');
    published.className = 'stream-published';
    published.textContent = publishedTitle(streamId);
    label.append(published);
  }
  pick.append(label);

  const hint = document.createElement('span');
  hint.className = 'stream-hint';
  // A stream nobody needed a key for is not end-to-end encrypted, and a
  // viewer has no other way to tell one from the other once it is on screen.
  hint.textContent = [
    live ? 'live' : 'not publishing',
    state.keys.get(streamId) === null ? 'not encrypted' : null,
  ].filter(Boolean).join(' · ');
  pick.append(hint);

  pick.title = kind === 'hidden'
    ? 'Put this stream back in the list'
    : 'Show this stream on screen';
  pick.addEventListener('click', () => {
    if (kind === 'hidden') {
      updatePlacement(streamId, { hidden: false });
      scheduleStreamList();
      return;
    }
    assignToFirstFreeTile(streamId);
  });
  item.append(pick);

  const actions = document.createElement('span');
  actions.className = 'stream-actions';
  actions.append(rowAction('✎', `Rename ${streamTitle(streamId)}`, () => beginRename(item, streamId)));
  if (record.slot) {
    actions.append(rowAction('−', 'Take off screen, keep in the list', () => {
      takeOffScreen(streamId);
      scheduleStreamList();
    }));
  }
  if (kind !== 'hidden') {
    actions.append(rowAction('✕', 'Hide this stream from the list', () => {
      takeOffScreen(streamId);
      updatePlacement(streamId, { hidden: true });
      scheduleStreamList();
    }));
  }
  item.append(actions);

  if (item.draggable) {
    item.addEventListener('dragstart', event => {
      event.dataTransfer.setData('text/plain', streamId);
      event.dataTransfer.effectAllowed = 'copy';
    });
  }
  return item;
}

function rowAction(glyph, title, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'stream-action';
  button.title = title;
  button.setAttribute('aria-label', title);
  button.textContent = glyph;
  button.addEventListener('click', onClick);
  return button;
}

/** Stops decoding a stream and gives up its tile number, keeping it listed. */
function takeOffScreen(streamId) {
  const tile = state.tiles.find(candidate => candidate.streamId === streamId);
  if (tile) detachTile(tile);
  if (placementOf(streamId).slot) updatePlacement(streamId, { slot: null });
}

/**
 * Rebuilds the panel once the current event has finished.
 *
 * Rendering moves a row between sections, which means destroying the element
 * whose own button is still handling the click that asked for the move. The
 * work is deferred by a turn so the handler returns to a live element, and so
 * that several changes in one gesture render once.
 */
let streamListPending = false;
function scheduleStreamList() {
  if (streamListPending) return;
  streamListPending = true;
  setTimeout(() => {
    streamListPending = false;
    renderStreamList();
  }, 0);
}

/**
 * Swaps a row for a field to rename it in.
 *
 * The name is this viewer's alone: it is stored in this browser, never sent to
 * the relay, and other people watching the same stream see whatever the
 * publisher called it. Submitting an empty field, or the publisher's own name,
 * clears the override rather than storing a duplicate of it -- so there is a
 * way back that does not require remembering what the original was.
 */
function beginRename(item, streamId) {
  if (item.querySelector('.stream-rename')) return;
  const form = document.createElement('form');
  form.className = 'stream-rename';
  const input = document.createElement('input');
  input.type = 'text';
  input.maxLength = MAX_STREAM_NAME;
  input.value = streamTitle(streamId);
  input.setAttribute('aria-label', `Name for ${publishedTitle(streamId)}`);
  const save = document.createElement('button');
  save.type = 'submit';
  save.textContent = 'Save';
  form.append(input, save);

  form.addEventListener('submit', event => {
    event.preventDefault();
    const typed = input.value.trim();
    updatePlacement(streamId, { name: typed === publishedTitle(streamId) ? '' : typed });
    refreshTileTitles();
    scheduleStreamList();
  });
  input.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    scheduleStreamList();
  });

  item.append(form);
  input.focus();
  input.select();
}

/** Carries a rename through to the tiles already showing the stream. */
function refreshTileTitles() {
  for (const tile of state.tiles) {
    if (tile.streamId) tile.title.textContent = streamTitle(tile.streamId);
  }
}

/**
 * Marks the streams that already have a tile.
 *
 * Kept apart from rendering the list so that attaching a tile does not rebuild
 * the row whose button is still handling the click that caused it.
 */
function markOnScreen() {
  for (const item of els.streamList.querySelectorAll('li[data-stream-id]')) {
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
  let parked = false;
  while (state.tiles.length > count) {
    const tile = state.tiles.pop();
    // A stream loses its number along with the tile that number referred to,
    // and moves to the available list. Keeping a slot the grid no longer has
    // would leave the panel promising a position that does not exist.
    if (tile.streamId && placementOf(tile.streamId).slot) {
      updatePlacement(tile.streamId, { slot: null });
      parked = true;
    }
    detachTile(tile);
    tile.element.remove();
  }
  while (state.tiles.length < count) {
    state.tiles.push(createTile());
  }
  // Only when something moved. This also runs during startup, before the stream
  // list has arrived, and rendering then would decide which of the two pages
  // this is before anything is known.
  if (parked) scheduleStreamList();
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
    // Emptying a tile by hand is the viewer saying they do not want this on
    // screen, so the stream gives up its number and moves to the available
    // list. Every other way a tile is emptied -- reassignment, teardown,
    // leaving the page -- deliberately leaves the arrangement alone.
    if (tile.streamId) takeOffScreen(tile.streamId);
    else detachTile(tile);
    scheduleStreamList();
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
    // To the next layout the grid actually has, which is 1, 2, or 4. Growing by
    // one produced a three-tile grid with no rule to lay it out, so the tiles
    // fell into a single column that got narrower with every stream added.
    setLayout(state.tiles.length < 2 ? 2 : MAX_TILES);
    // The first free tile, not the last one. Growing from two adds two tiles at
    // once, so reaching for the end skipped tile 3 -- and since a tile is also
    // a number, that hole was written to the arrangement and faithfully
    // restored on every reload.
    const grown = state.tiles.find(tile => !tile.streamId) ?? state.tiles.at(-1);
    attachTile(grown, streamId);
    return;
  }
  // Every tile is taken. The first one is the one displaced, and its stream
  // keeps its place in the list rather than disappearing from the panel.
  attachTile(state.tiles[0], streamId);
}

function attachTile(tile, streamId) {
  // Membership is what says the stream is unlocked; the value is the key, and
  // null is a real value meaning the stream was published in the clear.
  if (!state.keys.has(streamId)) {
    tile.message.textContent = 'That stream is not unlocked in this tab.';
    return;
  }
  const key = state.keys.get(streamId) ?? null;
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
  tile.message.textContent = key === null ? 'Preparing media…' : 'Preparing encrypted media…';
  mountPlayer(tile, streamId, key);
  // The tile a stream landed in is its number from now on, whether it got there
  // by click, by drag, or by being restored. Recorded here, at the one point
  // every one of those paths goes through.
  assignSlot(streamId, state.tiles.indexOf(tile) + 1);
  markOnScreen();
  scheduleStreamList();
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
  /** Streams unlocked without a key, because they were published in the clear. */
  openStreams: () => [...state.keys].filter(([, key]) => key === null).map(([id]) => id),
  /** This viewer's arrangement, so a gate can check what was remembered. */
  placements: () => Object.fromEntries(state.placements),
  /** What is known about each stream's encryption, and from which epoch. */
  described: () => Object.fromEntries(state.described),
  /** The name shown for a stream, which may be one this viewer typed. */
  titleOf: streamId => streamTitle(streamId),
};

/**
 * Puts the numbered streams on screen, each in the tile its number names.
 *
 * Arriving at a viewer that holds your keys and shows an empty grid is a chore:
 * the obvious next action is always "put them on screen". This does it, and
 * does it the same way every time -- stream 1 in tile 1 -- so the grid a viewer
 * arranged is the grid they come back to, across reloads and restarts.
 *
 * The layout only ever grows to fit. Shrinking it here would keep overriding a
 * layout the viewer chose by hand, and this runs on every poll.
 */
function showUnlockedStreams() {
  const numbered = [...state.placements]
    .filter(([streamId, record]) => record.slot
      && state.keys.has(streamId)
      && state.streams.has(streamId))
    .sort((left, right) => left[1].slot - right[1].slot);
  if (numbered.length === 0) return;

  const highest = numbered.at(-1)[1].slot;
  const fitted = highest > 2 ? 4 : highest;
  if (fitted > state.layout) setLayout(fitted);

  for (const [streamId, record] of numbered) {
    const tile = state.tiles[record.slot - 1];
    // Reattaching a tile tears down a working player, so a stream already on
    // screen is left exactly where it is.
    if (!tile || tile.streamId === streamId) continue;
    if (state.tiles.some(other => other.streamId === streamId)) continue;
    if (tile.streamId) continue;
    attachTile(tile, streamId);
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
 * Says why this browser can play nothing at all here, instead of offering a
 * page that cannot work.
 *
 * Deriving a key is the first thing that touches `crypto.subtle`, and browsers
 * withhold it outside a secure context -- so on a plain `http://` address that
 * is not localhost, typing a correct key produced `undefined is not an object
 * (reading 'importKey')`. That is an accurate description of the third line of
 * a key-derivation routine and no help at all to someone who just wants to
 * know why the page will not play.
 *
 * The question asked is deliberately the weaker one: what stops even a stream
 * published in the clear. A browser that cannot decrypt but can still play is
 * not refused, because on a trusted LAN there may be streams here for it --
 * that is every iPhone. Its narrower problem is explained where a key is
 * actually offered, by `explainEncryptedUnsupported`.
 *
 * Asked before the stream list, because nothing below it can succeed and the
 * answer does not depend on what the relay holds.
 */
function refuseUnusablePlatform() {
  const problem = Player.platformProblem({ encrypted: false });
  if (!problem) return false;
  document.body.classList.remove('deciding');
  document.body.classList.add('empty');
  const lead = document.querySelector('.welcome-lead');
  if (lead) lead.textContent = problem;
  els.unlockForm.hidden = true;
  return true;
}

/**
 * Replaces the invitation to type a key with the reason it would not work.
 *
 * A browser without ClearKey will never open an encrypted stream, so the field
 * is taken away rather than left to disappoint. What remains is whatever the
 * relay publishes in the clear, which unlocks itself.
 */
function explainEncryptedUnsupported() {
  if (!ENCRYPTED_UNSUPPORTED) return;
  els.unlockForm.hidden = true;
  const lead = document.querySelector('.welcome-lead');
  if (lead) lead.textContent = ENCRYPTED_UNSUPPORTED;
}

restoreSidebar();
// Before the layout, because shrinking the grid parks what it drops and that
// has to act on the arrangement being restored, not on an empty one.
loadPlacements();
setLayout(state.layout);
loadRememberedKeys();

// The key arrives in the link before the page can act on it, so it is read and
// erased from the URL immediately, then used once the stream list is known.
const invitedKey = inviteKeyFromUrl();
if (invitedKey) stripInviteKeyFromUrl();

// Nothing below this can work if the browser will not do the cryptography, and
// the reason has nothing to do with the relay, so it is settled first.
if (!refuseUnusablePlatform()) {

explainEncryptedUnsupported();

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
    await unlockOpenStreams();
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
    const unlocked = await applyRememberedKeys() + await unlockOpenStreams();
    if (unlocked > 0) {
      renderStreamList();
      showUnlockedStreams();
    }
  } catch {
    // A failed poll is retried by the next one.
  }
}, STREAM_POLL_INTERVAL_MS);

}
