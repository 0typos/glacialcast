'use strict';

const streamsElement = document.querySelector('#streams');
const countElement = document.querySelector('#count');
const connectionElement = document.querySelector('#connection');
const identityElement = document.querySelector('#identity');
const operationsElement = document.querySelector('#operations');
const metricCardsElement = document.querySelector('#metric-cards');
let session = null;
let traffic = null;

function formatBytes(bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = Number(bytes || 0);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function appendText(parent, className, value) {
  const element = document.createElement('div');
  element.className = className;
  element.textContent = value;
  parent.append(element);
  return element;
}

function trafficTotal(counters) {
  return Object.values(counters || {}).reduce(
    (total, item) => ({
      objects: total.objects + Number(item?.objects || 0),
      bytes: total.bytes + Number(item?.bytes || 0),
    }),
    { objects: 0, bytes: 0 },
  );
}

function formatRate(bytes, windowSeconds = 60) {
  const perMinute = Number(bytes || 0) * (60 / Math.max(1, Number(windowSeconds || 60)));
  return `${formatBytes(perMinute)}/min`;
}

function streamTraffic(streamId) {
  return traffic?.streams?.find(item => item.stream_id === streamId) || null;
}

function renderStream(stream) {
  const article = document.createElement('article');
  article.className = 'stream';
  const details = document.createElement('div');
  const title = document.createElement('h3');
  title.textContent = stream.display_name || stream.stream_id;
  details.append(title);

  const status = stream.active ? 'live' : 'offline';
  const metadata = appendText(details, 'meta', '');
  const badge = document.createElement('span');
  badge.className = `badge${stream.active ? '' : ' offline'}`;
  badge.textContent = status;
  metadata.append(
    badge,
    document.createTextNode(`encrypted DASH · ${formatBytes(stream.retained_bytes)} retained`),
  );
  const streamRate = streamTraffic(stream.stream_id);
  if (streamRate) {
    metadata.append(
      document.createTextNode(
        ` · ${formatRate(trafficTotal(streamRate.last_minute).bytes, traffic.window_seconds)} ingress`,
      ),
    );
  }
  appendText(
    details,
    'source',
    `${stream.source?.description || 'Unknown source'} · ${stream.stream_id}`,
  );

  const actions = document.createElement('div');
  actions.className = 'actions';
  const open = document.createElement('a');
  open.className = 'action';
  open.href = `/dash/${encodeURIComponent(stream.stream_id)}`;
  open.textContent = 'Open viewer';
  actions.append(open);
  if (session.role === 'admin') {
    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.type = 'button';
    remove.textContent = 'Delete';
    remove.addEventListener('click', async () => {
      if (!confirm(`Delete ${title.textContent} and all retained data?`)) return;
      const response = await fetch(`/api/streams/${encodeURIComponent(stream.stream_id)}`, {
        method: 'DELETE',
        headers: { 'X-GlacialCast-CSRF': session.csrf_token || '' },
      });
      if (!response.ok && response.status !== 404) {
        alert(await response.text());
        return;
      }
      await refresh();
    });
    actions.append(remove);
  }
  article.append(details, actions);
  return article;
}

function metricCard(label, value, detail) {
  const card = document.createElement('article');
  card.className = 'metric-card';
  appendText(card, 'metric-label', label);
  appendText(card, 'metric-value', value);
  appendText(card, 'metric-detail', detail);
  return card;
}

function renderMetrics(metrics) {
  traffic = metrics.traffic;
  const recent = trafficTotal(traffic.last_minute);
  const lifetime = trafficTotal(traffic.lifetime);
  metricCardsElement.replaceChildren(
    metricCard(
      'Ingress',
      formatRate(recent.bytes, traffic.window_seconds),
      `${recent.objects} objects in the rolling window`,
    ),
    metricCard(
      'Media',
      formatRate(traffic.last_minute.media.bytes, traffic.window_seconds),
      `${traffic.last_minute.media.objects} encrypted fragments`,
    ),
    metricCard(
      'Cursor',
      formatRate(traffic.last_minute.cursor.bytes, traffic.window_seconds),
      `${traffic.last_minute.cursor.objects} encrypted batches`,
    ),
    metricCard(
      'Process total',
      formatBytes(lifetime.bytes),
      `${lifetime.objects} accepted objects`,
    ),
    metricCard(
      'Connections',
      `${metrics.active_ingest_connections} ingest · ${metrics.active_websockets} viewer`,
      `${metrics.ingest_rejected + metrics.websocket_rejected} rejected`,
    ),
    metricCard(
      'HTTP',
      `${metrics.http_requests} requests`,
      `${metrics.http_overloaded} overloaded · ${metrics.http_timed_out} timed out`,
    ),
  );
  operationsElement.hidden = false;
}

async function authenticatedFetch(path, options) {
  const response = await fetch(path, options);
  if (response.status === 401) {
    location.assign('/login');
    throw new Error('Session expired.');
  }
  return response;
}

async function refresh() {
  if (session.role === 'admin') {
    const metricsResponse = await authenticatedFetch('/api/admin/metrics', { cache: 'no-store' });
    if (!metricsResponse.ok) throw new Error(await metricsResponse.text());
    renderMetrics(await metricsResponse.json());
  }
  const response = await authenticatedFetch('/api/streams', { cache: 'no-store' });
  if (!response.ok) throw new Error(await response.text());
  const streams = await response.json();
  streams.sort((left, right) =>
    Number(right.active) - Number(left.active)
    || String(left.display_name).localeCompare(String(right.display_name)));
  countElement.textContent = `${streams.length} stream${streams.length === 1 ? '' : 's'}`;
  streamsElement.replaceChildren();
  if (!streams.length) {
    appendText(streamsElement, 'empty', 'No authorized streams are available.');
    return;
  }
  streams.forEach(stream => streamsElement.append(renderStream(stream)));
}

function connectEvents() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const socket = new WebSocket(`${scheme}://${location.host}/api/ws`);
  socket.addEventListener('open', () => {
    connectionElement.textContent = 'live updates connected';
  });
  socket.addEventListener('message', () => refresh().catch(showError));
  socket.addEventListener('close', event => {
    if (event.code === 1008) {
      location.assign('/login');
      return;
    }
    connectionElement.textContent = 'reconnecting';
    setTimeout(connectEvents, 1000);
  });
  socket.addEventListener('error', () => socket.close());
}

function showError(error) {
  connectionElement.textContent = error.message || String(error);
}

async function initialize() {
  const response = await authenticatedFetch('/api/session', { cache: 'no-store' });
  if (!response.ok) throw new Error(await response.text());
  session = await response.json();
  identityElement.textContent = `${session.name} · ${session.role}`;
  await refresh();
  connectEvents();
}

document.querySelector('#refresh').addEventListener('click', () => refresh().catch(showError));
document.querySelector('#logout').addEventListener('click', async () => {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'X-GlacialCast-CSRF': session?.csrf_token || '' },
  });
  location.assign('/login');
});
initialize().catch(showError);
