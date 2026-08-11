#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

function element() {
  return {
    children: [],
    hidden: true,
    textContent: '',
    value: '',
    append(...children) {
      this.children.push(...children);
    },
    replaceChildren(...children) {
      this.children = children;
    },
    addEventListener() {},
    reset() {},
  };
}

const selected = new Map();
const context = {
  console,
  document: {
    querySelector(selector) {
      if (!selected.has(selector)) selected.set(selector, element());
      return selected.get(selector);
    },
    createElement: element,
    createTextNode(value) {
      return { textContent: value };
    },
  },
  fetch: async () => {
    throw new Error('initial fetch intentionally disabled by unit test');
  },
  location: { assign() {}, protocol: 'http:', host: '127.0.0.1' },
  WebSocket: class {},
  setTimeout() {},
  confirm: () => false,
};
vm.createContext(context);
vm.runInContext(
  fs.readFileSync(new URL('../crates/relay/static/index.js', import.meta.url), 'utf8'),
  context,
);

assert.equal(context.formatBytes(0), '0 B');
assert.equal(context.formatBytes(1536), '1.5 KiB');
assert.equal(context.formatRate(1024, 60), '1.0 KiB/min');
assert.equal(context.formatRate(1024, 30), '2.0 KiB/min');
assert.equal(context.formatDuration(1800), '30 min');
assert.deepEqual(
  JSON.parse(JSON.stringify(context.parsePublisherScopes('workstation, laptop, workstation'))),
  ['workstation', 'laptop'],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.trafficTotal({
    media: { objects: 2, bytes: 400 },
    cursor: { objects: 3, bytes: 50 },
  }))),
  { objects: 5, bytes: 450 },
);

context.renderMetrics({
  traffic: {
    window_seconds: 60,
    lifetime: {
      epoch: { objects: 1, bytes: 10 },
      media: { objects: 2, bytes: 400 },
      cursor: { objects: 3, bytes: 50 },
    },
    last_minute: {
      epoch: { objects: 0, bytes: 0 },
      media: { objects: 2, bytes: 400 },
      cursor: { objects: 3, bytes: 50 },
    },
    streams: [],
  },
  active_ingest_connections: 1,
  active_websockets: 2,
  ingest_rejected: 3,
  websocket_rejected: 4,
  http_requests: 5,
  http_overloaded: 6,
  http_timed_out: 7,
  retention_seconds: 1800,
  retention_bytes_per_stream: 536870912,
  managed_viewers: 2,
});
assert.equal(selected.get('#operations').hidden, false);
assert.equal(selected.get('#metric-cards').children.length, 8);

console.log('PASS: operations dashboard helpers');
