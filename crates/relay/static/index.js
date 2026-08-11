'use strict';

const streamsElement = document.querySelector('#streams');
const countElement = document.querySelector('#count');
const connectionElement = document.querySelector('#connection');
const identityElement = document.querySelector('#identity');
const operationsElement = document.querySelector('#operations');
const metricCardsElement = document.querySelector('#metric-cards');
const enrollmentForm = document.querySelector('#enrollment-form');
const enrollmentNameElement = document.querySelector('#enrollment-name');
const enrollmentPublishersElement = document.querySelector('#enrollment-publishers');
const enrollmentResultElement = document.querySelector('#enrollment-result');
const enrollmentTokenElement = document.querySelector('#enrollment-token');
const enrollmentsElement = document.querySelector('#enrollments');
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

function formatDuration(seconds) {
  const value = Number(seconds || 0);
  if (value >= 3600 && value % 3600 === 0) return `${value / 3600} h`;
  if (value >= 60 && value % 60 === 0) return `${value / 60} min`;
  return `${value} s`;
}

function formatAge(timestampMs) {
  if (!timestampMs) return 'never';
  const seconds = Math.max(0, Math.round((Date.now() - Number(timestampMs)) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
}

function parsePublisherScopes(value) {
  return [...new Set(String(value || '')
    .split(',')
    .map(scope => scope.trim())
    .filter(Boolean))];
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
    `${stream.source?.description || 'Unknown source'} · ${stream.source?.width || '?'}×${stream.source?.height || '?'} · last seen ${formatAge(stream.last_seen_at_ms)} · sequence ${stream.last_object_sequence || 0} · ${stream.stream_id}`,
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
      const response = await authenticatedFetch(`/api/streams/${encodeURIComponent(stream.stream_id)}`, {
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
    metricCard(
      'Retention',
      formatDuration(metrics.retention_seconds),
      `${formatBytes(metrics.retention_bytes_per_stream)} per stream ceiling`,
    ),
    metricCard(
      'Managed access',
      `${metrics.managed_viewers} viewer${metrics.managed_viewers === 1 ? '' : 's'}`,
      'access tokens only · E2EE keys stay off relay',
    ),
  );
  operationsElement.hidden = false;
}

function renderEnrollments(enrollments) {
  enrollmentsElement.replaceChildren();
  if (!enrollments.length) {
    appendText(enrollmentsElement, 'empty compact', 'No dashboard-managed viewers.');
    return;
  }
  for (const viewer of enrollments) {
    const row = document.createElement('div');
    row.className = 'enrollment';
    const details = document.createElement('div');
    appendText(details, 'enrollment-name', viewer.name);
    appendText(
      details,
      'meta',
      `${viewer.publishers.join(', ')} · created ${formatAge(viewer.created_at_ms)}`,
    );
    const revoke = document.createElement('button');
    revoke.className = 'danger';
    revoke.type = 'button';
    revoke.textContent = 'Revoke';
    revoke.addEventListener('click', async () => {
      if (!confirm(`Revoke relay access for ${viewer.name}?`)) return;
      const response = await authenticatedFetch(
        `/api/admin/enrollments/${encodeURIComponent(viewer.name)}`,
        {
          method: 'DELETE',
          headers: { 'X-GlacialCast-CSRF': session.csrf_token || '' },
        },
      );
      if (!response.ok && response.status !== 404) {
        alert(await response.text());
        return;
      }
      enrollmentResultElement.hidden = true;
      enrollmentTokenElement.textContent = '';
      await refreshEnrollments();
      await refresh();
    });
    row.append(details, revoke);
    enrollmentsElement.append(row);
  }
}

async function refreshEnrollments() {
  const response = await authenticatedFetch('/api/admin/enrollments', { cache: 'no-store' });
  if (!response.ok) throw new Error(await response.text());
  renderEnrollments(await response.json());
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
    await refreshEnrollments();
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
enrollmentForm.addEventListener('submit', async event => {
  event.preventDefault();
  enrollmentResultElement.hidden = true;
  enrollmentTokenElement.textContent = '';
  const response = await authenticatedFetch('/api/admin/enrollments', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-GlacialCast-CSRF': session.csrf_token || '',
    },
    body: JSON.stringify({
      name: enrollmentNameElement.value.trim(),
      publishers: parsePublisherScopes(enrollmentPublishersElement.value),
    }),
  });
  if (!response.ok) {
    showError(new Error(await response.text()));
    return;
  }
  const enrollment = await response.json();
  enrollmentTokenElement.textContent = enrollment.access_token;
  enrollmentResultElement.hidden = false;
  enrollmentForm.reset();
  await refresh();
});
document.querySelector('#copy-enrollment-token').addEventListener('click', async () => {
  const token = enrollmentTokenElement.textContent;
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    connectionElement.textContent = 'access token copied';
  } catch {
    connectionElement.textContent = 'copy failed; select the access token manually';
  }
});
document.querySelector('#logout').addEventListener('click', async () => {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'X-GlacialCast-CSRF': session?.csrf_token || '' },
  });
  location.assign('/login');
});
initialize().catch(showError);
