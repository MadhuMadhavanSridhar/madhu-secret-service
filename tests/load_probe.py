"""Fallback load probe when k6 is unavailable. Standard library only.

    python tests/load_probe.py [seconds] [workers]

Each worker loops create+read over a keep-alive connection. Prints achieved
requests per second and latency percentiles. Exempt the generator address from
the limiter first (RATE_LIMIT_EXEMPT_CIDRS), otherwise you measure 429s.
"""

import http.client
import json
import os
import statistics
import sys
import threading
import time
from urllib.parse import urlparse

BASE = urlparse(os.environ.get("BASE_URL", "http://localhost:8080"))
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 32

lock = threading.Lock()
latencies = {"create": [], "read": []}
statuses = {}


def record(kind, dt, status):
    with lock:
        latencies[kind].append(dt)
        statuses[status] = statuses.get(status, 0) + 1


def worker(stop_at):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port or 80, timeout=10)
    body = json.dumps({"content": "load-probe", "ttl_seconds": 120})
    while time.perf_counter() < stop_at:
        t0 = time.perf_counter()
        conn.request("POST", "/secrets", body=body, headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        data = r.read()
        record("create", time.perf_counter() - t0, r.status)
        if r.status != 201:
            continue
        sid = json.loads(data)["id"]
        t0 = time.perf_counter()
        conn.request("GET", "/s/" + sid)
        r = conn.getresponse()
        r.read()
        record("read", time.perf_counter() - t0, r.status)
    conn.close()


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * len(values))))] * 1000


start = time.perf_counter()
threads = [threading.Thread(target=worker, args=(start + DURATION,)) for _ in range(WORKERS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.perf_counter() - start
total = sum(len(v) for v in latencies.values())

print(f"requests: {total} in {elapsed:.1f}s  ->  {total / elapsed:.0f} req/s  (workers={WORKERS})")
print(f"statuses: {dict(sorted(statuses.items()))}")
for kind, vals in latencies.items():
    if vals:
        print(
            f"{kind:6s} p50={pct(vals, 50):.1f}ms  p95={pct(vals, 95):.1f}ms  "
            f"p99={pct(vals, 99):.1f}ms  max={max(vals) * 1000:.1f}ms  mean={statistics.mean(vals) * 1000:.1f}ms"
        )
