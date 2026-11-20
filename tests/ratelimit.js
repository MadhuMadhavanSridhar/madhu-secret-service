// Rate-limit conformance check (benchmark standard, requirement 7).
// Black-box: works against any build that follows the shared wire contract.
//
// What it proves, from ONE source IP:
//   1. Create: the first MUST_ALLOW creates succeed (201), a burst of
//      CREATE_BURST creates inside WINDOW_S seconds gets at least one 429.
//   2. Create, spoofed: the same burst with a random X-Forwarded-For,
//      X-Real-IP, Forwarded (and friends) on every request still gets a 429.
//   3. Read: the first MUST_ALLOW reads of unknown ids get 404 (not 429), a
//      burst of READ_BURST reads inside WINDOW_S seconds gets at least one 429.
//   4. Read, spoofed: same as 3 with spoofed client-IP headers.
//   5. Every 429 carries a Retry-After header.
//
// The app must NOT exempt the generator (RATE_LIMIT_EXEMPT_CIDRS empty).
// Run from inside the compose network so the TCP peer is a real client:
//
//   docker run --rm --network <project>_default -v "$PWD/tests:/t:ro" \
//     -e BASE_URL=http://app:8080 grafana/k6:1.3.0 run /t/ratelimit.js
//
// Tunables (env): BASE_URL, CREATE_BURST (200), READ_BURST (500),
// WINDOW_S (10), MUST_ALLOW (10), COOLDOWN_S (65), BATCH (25).
// Exit code is non-zero if any check fails.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { randomBytes } from 'k6/crypto';
import encoding from 'k6/encoding';

const BASE = (__ENV.BASE_URL || 'http://localhost:8080').replace(/\/$/, '');
const CREATE_BURST = Number(__ENV.CREATE_BURST || 200);
const READ_BURST = Number(__ENV.READ_BURST || 500);
const WINDOW_S = Number(__ENV.WINDOW_S || 10);
const MUST_ALLOW = Number(__ENV.MUST_ALLOW || 10);
// Pause between the create and read phases, for builds that share one
// bucket across endpoints. Create and spoofed-create run back to back on
// purpose: a limiter keyed on the peer IP is already drained and must 429,
// a limiter keyed on a spoofable header sees a fresh client every request.
const COOLDOWN_S = Number(__ENV.COOLDOWN_S || 65);
const BATCH = Number(__ENV.BATCH || 25);

export const options = {
  scenarios: {
    ratelimit: { executor: 'per-vu-iterations', vus: 1, iterations: 1, maxDuration: '10m' },
  },
  batchPerHost: BATCH,
  thresholds: { checks: ['rate==1'] },
  summaryTrendStats: ['med', 'p(99)', 'max'],
};

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const CREATE_BODY = JSON.stringify({ content: 'rate-limit-probe', ttl_seconds: 60, max_views: 1 });

function octet() {
  return Math.floor(Math.random() * 254) + 1;
}

function randomIP() {
  return `${octet()}.${octet()}.${octet()}.${octet()}`;
}

function spoofHeaders() {
  const ip = randomIP();
  return {
    'X-Forwarded-For': `${ip}, ${randomIP()}`,
    'X-Real-IP': ip,
    Forwarded: `for=${ip}`,
    'True-Client-IP': ip,
    'CF-Connecting-IP': ip,
    'X-Client-IP': ip,
    'X-Cluster-Client-IP': ip,
  };
}

function randomId() {
  return encoding.b64encode(randomBytes(32), 'rawurl');
}

function createReq(spoof) {
  return {
    method: 'POST',
    url: `${BASE}/secrets`,
    body: CREATE_BODY,
    params: { headers: Object.assign({}, JSON_HEADERS, spoof ? spoofHeaders() : {}), tags: { name: 'create' } },
  };
}

function readReq(spoof) {
  return {
    method: 'GET',
    url: `${BASE}/s/${randomId()}`,
    params: { headers: spoof ? spoofHeaders() : {}, tags: { name: 'read' } },
  };
}

// Sends `total` requests built by `make`. The first `sequential` go one at
// a time so their order is known; the rest go in parallel batches so the
// burst really lands inside the window even on a slow build.
function burst(make, total, sequential) {
  const res = { statuses: {}, first429: 0, early: [], missingRetryAfter: 0, sent: 0, inWindow: 0 };
  const start = Date.now();
  const record = (r) => {
    res.sent++;
    if ((Date.now() - start) / 1000 <= WINDOW_S) res.inWindow++;
    res.statuses[r.status] = (res.statuses[r.status] || 0) + 1;
    if (r.status === 429) {
      if (!res.first429) res.first429 = res.sent;
      if (!r.headers['Retry-After']) res.missingRetryAfter++;
    }
  };
  for (let i = 0; i < sequential && res.sent < total; i++) {
    const q = make();
    const r = http.request(q.method, q.url, q.body || null, q.params);
    res.early.push(r.status);
    record(r);
  }
  while (res.sent < total) {
    const n = Math.min(BATCH, total - res.sent);
    const reqs = [];
    for (let i = 0; i < n; i++) {
      const q = make();
      reqs.push([q.method, q.url, q.body || null, q.params]);
    }
    http.batch(reqs).forEach(record);
  }
  res.seconds = (Date.now() - start) / 1000;
  return res;
}

function describe(label, r) {
  const codes = Object.keys(r.statuses).map((k) => `${k}x${r.statuses[k]}`).join(' ');
  const hit = r.first429 ? `first 429 at #${r.first429}` : 'no 429';
  console.log(`${label}: ${r.sent} sent in ${r.seconds.toFixed(1)}s (${r.inWindow} inside ${WINDOW_S}s) | ${codes} | ${hit}`);
}

export default function () {
  const health = http.get(`${BASE}/healthz`);
  if (!check(health, { 'stack is healthy (GET /healthz 200)': (r) => r.status === 200 })) return;

  const create = burst(() => createReq(false), CREATE_BURST, MUST_ALLOW);
  describe('create        ', create);
  const createSpoof = burst(() => createReq(true), CREATE_BURST, 0);
  describe('create spoofed', createSpoof);

  console.log(`cooling down ${COOLDOWN_S}s before the read phase`);
  sleep(COOLDOWN_S);

  const read = burst(() => readReq(false), READ_BURST, MUST_ALLOW);
  describe('read          ', read);
  const readSpoof = burst(() => readReq(true), READ_BURST, 0);
  describe('read spoofed  ', readSpoof);

  const missingRA = create.missingRetryAfter + createSpoof.missingRetryAfter + read.missingRetryAfter + readSpoof.missingRetryAfter;

  check(null, {
    [`create: first ${MUST_ALLOW} creates return 201`]: () => create.early.every((s) => s === 201),
    [`create: burst of ${CREATE_BURST} gets a 429`]: () => create.first429 > 0 && create.first429 <= create.inWindow,
    'create: spoofed client-IP headers do not bypass the limit': () => createSpoof.first429 > 0,
    [`read: first ${MUST_ALLOW} reads are not rate limited`]: () => read.early.every((s) => s !== 429 && s < 500),
    [`read: burst of ${READ_BURST} gets a 429`]: () => read.first429 > 0 && read.first429 <= read.inWindow,
    'read: spoofed client-IP headers do not bypass the limit': () => readSpoof.first429 > 0,
    'every 429 carries Retry-After': () => missingRA === 0,
  });
}
