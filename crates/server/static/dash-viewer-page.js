'use strict';

// Mounts the single-stream viewer at /dash/<stream-id>. The player itself is
// reusable; this file is only the page around it.

const Player = globalThis.GlacialCastPlayer;
if (!Player) throw new Error('The GlacialCast player failed to load.');

const streamId = location.pathname.split('/').filter(Boolean).at(-1);
const root = document.querySelector('[data-role="player"]');
const unlockForm = document.querySelector('[data-role="unlock-form"]');
const viewerKeyInput = document.querySelector('[data-role="viewer-key"]');
const label = document.querySelector('[data-role="stream-label"]');

if (label) label.textContent = `Stream ${streamId}`;

const player = Player.createPlayer(root, { streamId });

unlockForm.addEventListener('submit', event => {
  event.preventDefault();
  // The player renders its own failures; nothing further to do here.
  player.start(viewerKeyInput.value.trim()).catch(() => {});
});

globalThis.addEventListener('pagehide', () => player.destroy());
