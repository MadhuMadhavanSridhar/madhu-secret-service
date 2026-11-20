// k6 load profile matching the scoring table: 200 requests/s for 60 s.
// Each iteration is one create followed by one read, so 100 iterations/s.
//
//   k6 run tests/load.js
//   BASE_URL=http://host:8080 k6 run tests/load.js
//
// The generator must be exempt from the per-IP limiter or the run measures
// 429s. Set RATE_LIMIT_EXEMPT_CIDRS on the app to the generator's address.
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '60s',
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.001'],
    'http_req_duration{name:create}': ['p(99)<50'],
    'http_req_duration{name:read}': ['p(99)<50'],
  },
};

export default function () {
  const created = http.post(
    `${BASE}/secrets`,
    JSON.stringify({ content: 'load-' + __VU + '-' + __ITER, ttl_seconds: 120 }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'create' } },
  );
  if (!check(created, { 'created 201': (r) => r.status === 201 })) {
    return;
  }
  const id = created.json('id');
  const read = http.get(`${BASE}/s/${id}`, { tags: { name: 'read' } });
  check(read, { 'read 200': (r) => r.status === 200 });
}
