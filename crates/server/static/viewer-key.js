'use strict';

// Turning what someone was told into the key that decrypts a stream.
//
// A viewer key is 32 bytes, but nobody transfers 32 bytes by hand. What gets
// shared is a key phrase: seven words from a fixed 1024-word list, ten bits
// each. The 32 bytes are derived from the phrase with PBKDF2-HMAC-SHA-256 over
// a per-publisher salt the relay publishes as ordinary stream metadata.
//
// This must match `crates/protocol/src/viewer_key.rs` exactly — a viewer that
// resolves a word or an iteration count differently derives a different key and
// simply cannot decrypt anything. The wordlist below is generated from the same
// file the publisher compiles in, and a gate checks that it still matches.
//
// Raw 32-byte keys in URL-safe base64 are still accepted, because a publisher
// that predates phrases keeps sharing one.

(function installViewerKey(root, factory) {
  const module_ = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = module_;
  } else {
    root.GlacialCastViewerKey = module_;
  }
}(typeof globalThis === 'undefined' ? this : globalThis, () => {
  // BEGIN GENERATED WORDLIST
  const WORDLIST = [
    'able', 'about', 'acid', 'acorn', 'acre', 'actor', 'adapt', 'add', 'adobe', 'adult',
    'afar', 'affix', 'afoot', 'after', 'again', 'agent', 'agile', 'aglow', 'ahead', 'aide',
    'aim', 'air', 'aisle', 'ajar', 'alarm', 'album', 'alert', 'algae', 'alias', 'alley',
    'aloe', 'alpha', 'altar', 'amber', 'amend', 'amid', 'ample', 'amuse', 'angel', 'ankle',
    'annex', 'ant', 'anvil', 'apart', 'apex', 'apple', 'apron', 'aqua', 'arbor', 'arch',
    'area', 'argue', 'arid', 'arm', 'aroma', 'array', 'art', 'ash', 'aside', 'ask',
    'aspen', 'asset', 'atlas', 'atom', 'attic', 'audio', 'auger', 'aunt', 'auto', 'avail',
    'avert', 'avid', 'away', 'awoke', 'axis', 'baby', 'back', 'badge', 'bagel', 'bake',
    'balm', 'band', 'barn', 'bass', 'bath', 'bay', 'bead', 'bee', 'began', 'being',
    'belt', 'bend', 'berry', 'best', 'bet', 'bib', 'bicep', 'bid', 'big', 'bike',
    'bill', 'bin', 'biome', 'bird', 'bison', 'bit', 'black', 'bleak', 'blimp', 'blob',
    'blue', 'boat', 'body', 'bogus', 'boil', 'bold', 'bond', 'book', 'born', 'boss',
    'both', 'bough', 'bow', 'box', 'boy', 'brag', 'brew', 'brim', 'broad', 'brush',
    'bud', 'bugle', 'build', 'bulb', 'bunk', 'burly', 'bus', 'but', 'buy', 'buzz',
    'cabin', 'cacao', 'cadet', 'cage', 'cake', 'calf', 'camp', 'canal', 'cap', 'car',
    'cash', 'catch', 'cause', 'cave', 'cedar', 'cell', 'cent', 'chain', 'chef', 'chin',
    'chop', 'chunk', 'cider', 'cigar', 'cinch', 'city', 'civic', 'clad', 'clean', 'clip',
    'cloak', 'club', 'coal', 'cobra', 'cocoa', 'cod', 'cog', 'coil', 'coke', 'cold',
    'comb', 'cone', 'cook', 'copy', 'cord', 'cost', 'cot', 'couch', 'cove', 'cow',
    'cozy', 'crab', 'crew', 'crib', 'crop', 'crumb', 'cry', 'cube', 'cuff', 'cult',
    'cup', 'curb', 'cut', 'cycle', 'dab', 'daily', 'dam', 'dance', 'dare', 'dash',
    'data', 'dawn', 'day', 'deal', 'debt', 'deck', 'deep', 'defy', 'delay', 'demo',
    'dent', 'depot', 'derby', 'desk', 'deter', 'dew', 'dial', 'dice', 'diet', 'dig',
    'dill', 'dime', 'dine', 'dip', 'dirt', 'disc', 'ditch', 'dive', 'dizzy', 'dock',
    'dodge', 'dog', 'doll', 'dome', 'donor', 'door', 'dose', 'dot', 'dough', 'dove',
    'down', 'dozen', 'drag', 'dream', 'drip', 'drop', 'drum', 'dry', 'duck', 'due',
    'dug', 'duke', 'dull', 'dune', 'dusk', 'duty', 'dwarf', 'dwell', 'dye', 'each',
    'eager', 'ear', 'ease', 'eat', 'echo', 'edge', 'edit', 'eel', 'egg', 'eight',
    'elbow', 'elder', 'elect', 'elf', 'elk', 'elm', 'else', 'elude', 'ember', 'emit',
    'empty', 'enact', 'end', 'enjoy', 'enter', 'envoy', 'epic', 'equal', 'era', 'error',
    'erupt', 'essay', 'etch', 'ethic', 'evade', 'even', 'evict', 'evoke', 'exam', 'excel',
    'exit', 'expel', 'extra', 'fable', 'face', 'fade', 'fair', 'fake', 'fall', 'fame',
    'fan', 'far', 'fast', 'fate', 'fault', 'favor', 'fawn', 'fax', 'feast', 'fee',
    'felt', 'fence', 'fern', 'fetch', 'fever', 'few', 'fiber', 'field', 'fifty', 'fig',
    'file', 'find', 'fire', 'fish', 'fit', 'five', 'fix', 'flag', 'fled', 'flip',
    'flow', 'flu', 'fly', 'foam', 'focus', 'fog', 'foil', 'fold', 'fond', 'food',
    'for', 'four', 'fox', 'frame', 'free', 'frog', 'fruit', 'fudge', 'fuel', 'full',
    'fun', 'fur', 'fuse', 'fuzzy', 'gain', 'gala', 'game', 'gap', 'gas', 'gate',
    'gauge', 'gave', 'gaze', 'gear', 'gecko', 'gem', 'germ', 'get', 'ghost', 'giant',
    'gift', 'gill', 'girl', 'give', 'glad', 'gleam', 'glide', 'glow', 'glue', 'glyph',
    'gnome', 'goal', 'gold', 'gone', 'good', 'gorge', 'got', 'gourd', 'gown', 'grab',
    'grew', 'grid', 'grow', 'grub', 'guard', 'guess', 'guide', 'gulf', 'gum', 'gust',
    'gut', 'guy', 'gym', 'habit', 'hail', 'half', 'ham', 'hand', 'happy', 'hard',
    'hash', 'hat', 'haul', 'have', 'hawk', 'hay', 'haze', 'head', 'hedge', 'heel',
    'held', 'hem', 'hen', 'herb', 'hex', 'hid', 'high', 'hike', 'hill', 'hint',
    'hip', 'hire', 'hiss', 'hive', 'hoax', 'hobby', 'hoist', 'hold', 'home', 'honk',
    'hood', 'hope', 'horn', 'hose', 'hot', 'hour', 'hover', 'howl', 'hub', 'hue',
    'huge', 'hull', 'hump', 'hunt', 'hurl', 'husk', 'hut', 'hydra', 'hymn', 'ice',
    'icon', 'idea', 'idle', 'igloo', 'ill', 'image', 'imply', 'inch', 'index', 'ingot',
    'ink', 'inlet', 'inn', 'input', 'into', 'iris', 'iron', 'issue', 'item', 'ivory',
    'ivy', 'jade', 'jail', 'jam', 'jar', 'jaw', 'jazz', 'jeans', 'jelly', 'jet',
    'jewel', 'job', 'jog', 'join', 'joke', 'jolt', 'joy', 'judge', 'jug', 'juice',
    'july', 'jump', 'june', 'jury', 'just', 'kale', 'kayak', 'keen', 'kelp', 'kept',
    'key', 'kick', 'kid', 'kilt', 'kind', 'kiosk', 'kiss', 'kit', 'kiwi', 'knack',
    'knee', 'knit', 'knob', 'koala', 'lab', 'lace', 'lady', 'lake', 'lamb', 'land',
    'lap', 'lark', 'last', 'late', 'laugh', 'lava', 'law', 'layer', 'lazy', 'leaf',
    'ledge', 'leek', 'left', 'leg', 'lemon', 'lend', 'less', 'let', 'level', 'liar',
    'libel', 'lid', 'life', 'light', 'like', 'lily', 'limb', 'line', 'lion', 'lip',
    'list', 'liter', 'live', 'llama', 'load', 'lobby', 'lock', 'lodge', 'loft', 'log',
    'long', 'look', 'lord', 'lose', 'lot', 'loud', 'love', 'low', 'loyal', 'luck',
    'lull', 'lump', 'lung', 'lure', 'lush', 'lute', 'lyric', 'macaw', 'mad', 'magic',
    'maid', 'major', 'make', 'malt', 'man', 'map', 'mare', 'mask', 'mate', 'maze',
    'meal', 'medal', 'meet', 'melt', 'memo', 'mend', 'mercy', 'mesa', 'metal', 'micro',
    'midst', 'might', 'mild', 'mimic', 'mind', 'mist', 'mix', 'moat', 'mock', 'model',
    'moist', 'mold', 'money', 'mood', 'mop', 'more', 'moss', 'moth', 'mound', 'move',
    'much', 'mud', 'mug', 'mule', 'mural', 'muse', 'mute', 'myrrh', 'myth', 'nacho',
    'nail', 'name', 'nap', 'nasal', 'navy', 'near', 'neck', 'need', 'neon', 'nerve',
    'nest', 'net', 'never', 'new', 'next', 'nice', 'niece', 'night', 'nine', 'noble',
    'node', 'noise', 'nomad', 'none', 'nook', 'north', 'nose', 'note', 'novel', 'now',
    'numb', 'nurse', 'nut', 'nylon', 'oak', 'oar', 'oasis', 'oat', 'obey', 'oboe',
    'odd', 'ode', 'odor', 'ogre', 'oil', 'okay', 'old', 'omit', 'once', 'one',
    'only', 'onto', 'onyx', 'opal', 'open', 'our', 'out', 'oval', 'oven', 'owl',
    'own', 'pace', 'pad', 'page', 'paid', 'pale', 'pan', 'park', 'pass', 'path',
    'pave', 'paw', 'pay', 'peak', 'peck', 'peel', 'pen', 'perk', 'pest', 'pick',
    'pie', 'pike', 'pile', 'pin', 'pipe', 'pit', 'plan', 'plot', 'plug', 'pod',
    'poem', 'pole', 'pond', 'pool', 'pork', 'pose', 'pot', 'pour', 'pray', 'prey',
    'prod', 'puck', 'puff', 'pull', 'puma', 'pure', 'push', 'put', 'quit', 'race',
    'raft', 'rag', 'raid', 'rake', 'ramp', 'rank', 'rare', 'rash', 'rate', 'raw',
    'ray', 'read', 'red', 'reed', 'rely', 'rent', 'rest', 'rib', 'rice', 'ride',
    'rim', 'ring', 'riot', 'ripe', 'rise', 'road', 'robe', 'rock', 'rod', 'role',
    'roof', 'rope', 'rose', 'row', 'ruby', 'rug', 'ruin', 'rule', 'run', 'rush',
    'rye', 'sack', 'sad', 'safe', 'sage', 'said', 'salt', 'same', 'sand', 'sash',
    'save', 'saw', 'say', 'scan', 'sea', 'seed', 'self', 'send', 'set', 'sew',
    'shed', 'ship', 'shoe', 'shut', 'shy', 'sick', 'side', 'sift', 'sigh', 'silk',
    'sing', 'sip', 'sit', 'six', 'size', 'ski', 'sky', 'slab', 'sled', 'slim',
    'slot', 'slug', 'snap', 'snow', 'snug', 'soak', 'sock', 'soda', 'sofa', 'soil',
    'sold', 'some', 'song', 'soon', 'sort', 'soul', 'span', 'spin', 'spot', 'spur',
    'spy', 'star', 'stem', 'stir', 'stop', 'stub', 'such', 'suit', 'sum', 'sun',
    'sure', 'swan', 'swim', 'tack', 'tag', 'tail', 'take', 'tale', 'tame', 'tan',
    'tape', 'tarp', 'task', 'tax', 'tea', 'tech', 'tell', 'ten', 'term', 'test',
    'text', 'that', 'then', 'thin', 'thus', 'tide', 'tie', 'tile', 'time', 'tin',
    'tip', 'toad', 'toe', 'tofu', 'toga', 'toil', 'told', 'tomb', 'tone', 'took',
    'top', 'torn', 'toss', 'tote', 'tour', 'tow', 'toy', 'tram', 'tree', 'trim',
    'trot', 'true', 'try', 'tub', 'tuck', 'tuft', 'tuna', 'turf', 'tusk', 'twig',
    'two', 'type', 'ugly', 'undo', 'unit', 'upon', 'urge', 'use', 'van', 'vary',
    'vase', 'veal', 'veer', 'veil', 'vent', 'verb', 'vest', 'vet', 'via', 'view',
    'vine', 'visa', 'void', 'volt', 'vote', 'wade', 'wag', 'wait', 'wake', 'walk',
    'want', 'ward', 'wash', 'watt', 'wave', 'wax', 'way', 'weak', 'web', 'weed',
    'weld', 'went', 'were', 'west', 'wet', 'what', 'when', 'whim', 'whom', 'why',
    'wick', 'wide', 'wife', 'wig', 'wild', 'win', 'wipe', 'wire', 'wise', 'with',
    'woke', 'wolf', 'wood', 'word', 'wrap', 'wren', 'yak', 'yam', 'yard', 'yawn',
    'year', 'yell', 'yes', 'yet', 'yoga', 'yolk', 'your', 'zeal', 'zero', 'zest',
    'zinc', 'zip', 'zone', 'zoo',
  ];
  // END GENERATED WORDLIST

  const PHRASE_WORDS = 7;
  const PBKDF2_ITERATIONS = 600_000;
  const SALT_LENGTH = 16;
  const VIEWER_KEY_LENGTH = 32;
  const PREFIX_LENGTH = 3;
  const DERIVATION_CONTEXT = 'glacialcast-viewer-key-v1:';

  /** Words indexed by their unique three-letter prefix. */
  const BY_PREFIX = new Map(WORDLIST.map(word => [word.slice(0, PREFIX_LENGTH), word]));

  function base64UrlToBytes(value) {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    const padded = normalized.padEnd(
      normalized.length + ((4 - (normalized.length % 4)) % 4),
      '=',
    );
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function bytesToBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  }

  /**
   * Reduces a typed phrase to its canonical hyphenated form.
   *
   * Words may be separated by spaces or hyphens, typed in any case, and
   * abbreviated to their first three letters, because a key gets retyped from a
   * chat message far more often than it gets pasted.
   */
  function normalizePhrase(input) {
    const tokens = String(input).split(/[^A-Za-z]+/).filter(Boolean);
    if (tokens.length !== PHRASE_WORDS) {
      throw new Error(`A viewing key is ${PHRASE_WORDS} words, but ${tokens.length} were given.`);
    }
    return tokens.map(token => {
      const lowered = token.toLowerCase();
      const word = lowered.length >= PREFIX_LENGTH
        ? BY_PREFIX.get(lowered.slice(0, PREFIX_LENGTH))
        : undefined;
      if (!word) throw new Error(`"${token}" is not a GlacialCast viewing-key word.`);
      return word;
    }).join('-');
  }

  /** Reports whether `input` parses as a key phrase. */
  function looksLikePhrase(input) {
    try {
      normalizePhrase(input);
      return true;
    } catch {
      return false;
    }
  }

  /** Decodes a per-publisher salt from its wire form. */
  function decodeSalt(encoded) {
    const bytes = base64UrlToBytes(encoded);
    if (bytes.length !== SALT_LENGTH) {
      throw new Error(`A viewer key salt must decode to ${SALT_LENGTH} bytes.`);
    }
    return bytes;
  }

  /** Derives the 32 key bytes a phrase stands for under one publisher's salt. */
  async function deriveFromPhrase(phrase, saltBytes) {
    const canonical = normalizePhrase(phrase);
    const salted = new Uint8Array(DERIVATION_CONTEXT.length + saltBytes.length);
    salted.set(new TextEncoder().encode(DERIVATION_CONTEXT), 0);
    salted.set(saltBytes, DERIVATION_CONTEXT.length);

    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(canonical),
      'PBKDF2',
      false,
      ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salted, iterations: PBKDF2_ITERATIONS },
      material,
      VIEWER_KEY_LENGTH * 8,
    );
    return new Uint8Array(bits);
  }

  /**
   * Resolves whatever the operator was given into 32 key bytes.
   *
   * `salt` is the publisher's `viewer_key_salt` from `/api/streams`, and is
   * required only for a phrase. A raw base64 key needs no derivation.
   */
  async function resolveKey(input, salt) {
    const trimmed = String(input).trim();
    if (!trimmed) throw new Error('Enter the viewing key you were given.');
    if (looksLikePhrase(trimmed)) {
      if (!salt) {
        throw new Error('This stream does not accept a key phrase; paste its viewer key instead.');
      }
      return deriveFromPhrase(trimmed, decodeSalt(salt));
    }
    let bytes;
    try {
      bytes = base64UrlToBytes(trimmed);
    } catch {
      throw new Error('That is neither a key phrase nor a valid viewer key.');
    }
    if (bytes.length !== VIEWER_KEY_LENGTH) {
      throw new Error(`A viewer key must decode to ${VIEWER_KEY_LENGTH} bytes.`);
    }
    return bytes;
  }

  return Object.freeze({
    PBKDF2_ITERATIONS,
    PHRASE_WORDS,
    SALT_LENGTH,
    VIEWER_KEY_LENGTH,
    WORDLIST,
    base64UrlToBytes,
    bytesToBase64Url,
    decodeSalt,
    deriveFromPhrase,
    looksLikePhrase,
    normalizePhrase,
    resolveKey,
  });
}));
