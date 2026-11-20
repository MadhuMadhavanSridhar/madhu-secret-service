"""Black-box checks mirroring the Build & Break scoring table.

Runs against a live service (default http://localhost:8080). Works under pytest
or as a plain script:

    python tests/test_service.py            # all checks
    BASE_URL=http://host:8080 pytest tests  # under pytest

Checks marked "docker" shell out to `docker compose` and are skipped when that
is not available. Uses only the standard library.
"""

import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("BASE_URL", "http://localhost:8080").rstrip("/")
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "CANARY-" + os.urandom(8).hex() + "-do-not-leak"
PASSPHRASE = "PASS-" + os.urandom(6).hex()


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body or "{}")


def call(method, path, body=None, headers=None, timeout=10):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return Resp(r.status, dict(r.headers), r.read().decode())
    except urllib.error.HTTPError as e:
        return Resp(e.code, dict(e.headers), e.read().decode())


def create(content="hello", **kw):
    r = call("POST", "/secrets", {"content": content, **kw})
    assert r.status == 201, (r.status, r.body)
    return r.json()


def path_of(c):
    return "/s/" + c["id"]


# ---- correctness --------------------------------------------------------------

def test_health():
    assert call("GET", "/healthz").status == 200


def test_view_once():
    c = create("once")
    first = call("GET", path_of(c))
    assert first.status == 200 and first.json()["content"] == "once"
    assert call("GET", path_of(c)).status == 404


def test_max_views():
    c = create("thrice", max_views=3)
    assert [call("GET", path_of(c)).status for _ in range(4)] == [200, 200, 200, 404]


def test_ttl_expiry():
    c = create("brief", ttl_seconds=2)
    time.sleep(3.2)
    assert call("GET", path_of(c)).status == 404


def test_revoke_with_deletion_token():
    c = create("revoke")
    assert call("DELETE", path_of(c)).status == 401
    assert call("DELETE", path_of(c), headers={"X-Deletion-Token": "wrong"}).status == 404
    assert call("DELETE", path_of(c), headers={"X-Deletion-Token": c["deletion_token"]}).status == 204
    assert call("GET", path_of(c)).status == 404


def test_passphrase():
    c = create("guarded", passphrase="open sesame")
    assert call("GET", path_of(c)).status == 401
    wrong = call("GET", path_of(c), headers={"X-Passphrase": "nope"})
    missing = call("GET", "/s/" + "A" * 43)
    assert wrong.status == 404 and wrong.body == missing.body
    assert call("GET", path_of(c), headers={"X-Passphrase": "open sesame"}).status == 200


# ---- timing (before the race test, which spends most of the read bucket) ------

def test_timing_not_found_vs_wrong_passphrase():
    c = create("timed", passphrase="right")
    bogus = "/s/" + os.urandom(32).hex()[:43]

    def median(path):
        samples = []
        for _ in range(8):
            t0 = time.perf_counter()
            r = call("GET", path, headers={"X-Passphrase": "wrong"})
            samples.append(time.perf_counter() - t0)
            assert r.status == 404, (path, r.status)
        return statistics.median(samples)

    wrong, missing = median(path_of(c)), median(bogus)
    ratio = wrong / missing
    assert 0.5 < ratio < 2, (wrong, missing)


# ---- view-once race -----------------------------------------------------------

def test_race_50_concurrent_gets():
    c = create("race")
    with ThreadPoolExecutor(max_workers=50) as ex:
        codes = list(ex.map(lambda _: call("GET", path_of(c)).status, range(50)))
    assert codes.count(200) == 1, codes
    assert all(code in (200, 404) for code in codes), codes


# ---- enumeration and timing ---------------------------------------------------

def test_ids_are_long_and_random():
    ids = [create("x")["id"] for _ in range(3)]
    assert all(len(i) >= 32 for i in ids)
    assert len(set(ids)) == 3
    assert not any(i.isdigit() for i in ids)


# ---- headers ------------------------------------------------------------------

def test_security_headers():
    c = create("hdr")
    for path in (path_of(c), "/s/missing", "/healthz"):
        r = call("GET", path)
        assert r.headers.get("Cache-Control") == "no-store", path
        assert r.headers.get("Referrer-Policy") == "no-referrer", path
        assert r.headers.get("X-Content-Type-Options") == "nosniff", path
        assert "Content-Security-Policy" in r.headers, path


# ---- leaks: metrics, logs, data at rest (docker) ------------------------------

class _Result:
    def __init__(self, proc):
        self.returncode = proc.returncode
        # Output may contain raw ciphertext bytes; never let decoding fail.
        self.stdout = proc.stdout.decode("utf-8", errors="replace")
        self.stderr = proc.stderr.decode("utf-8", errors="replace")


def _compose(*args):
    try:
        proc = subprocess.run(["docker", "compose", *args], cwd=PROJECT_DIR, capture_output=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return _Result(proc)


def test_metrics_do_not_leak():
    c = create(CANARY, passphrase=PASSPHRASE)
    m = call("GET", "/metrics")
    assert m.status == 200
    for s in (CANARY, PASSPHRASE, c["id"], c["deletion_token"]):
        assert s not in m.body


def test_no_plaintext_at_rest_docker():
    c = create(CANARY, passphrase=PASSPHRASE, max_views=2)
    call("GET", path_of(c), headers={"X-Passphrase": "wrong"})
    call("GET", path_of(c), headers={"X-Passphrase": PASSPHRASE})

    pw = os.environ.get("REDIS_PASSWORD", "ots-internal-only-change-me")
    dump = _compose(
        "exec", "-T", "redis", "sh", "-c",
        "ls -la /data; cat /data/* 2>/dev/null; "
        f"for k in $(redis-cli --user app --pass '{pw}' --no-auth-warning --scan); do "
        f"redis-cli --user app --pass '{pw}' --no-auth-warning hgetall \"$k\"; done",
    )
    if dump is None or dump.returncode != 0:
        print("skip: docker compose exec unavailable", dump and dump.stderr)
        return
    for s in (CANARY, PASSPHRASE, c["id"], c["deletion_token"]):
        assert s not in dump.stdout, s


def test_logs_are_clean_docker():
    c = create(CANARY, passphrase=PASSPHRASE)
    call("GET", path_of(c), headers={"X-Passphrase": PASSPHRASE})
    logs = _compose("logs", "--no-color")
    if logs is None or logs.returncode != 0:
        print("skip: docker compose logs unavailable")
        return
    out = logs.stdout + logs.stderr
    for s in (CANARY, PASSPHRASE, c["id"], c["deletion_token"]):
        assert s not in out, s
    assert "secret.viewed" in out


# ---- rate limiting (last: it exhausts this client's create bucket) -----------

def test_create_burst_gets_429_even_with_spoofed_xff():
    codes = []
    for i in range(80):
        r = call("POST", "/secrets", {"content": "burst"}, headers={"X-Forwarded-For": f"10.{i}.{i}.{i}"})
        codes.append(r.status)
        if r.status == 429:
            assert r.headers.get("Retry-After")
            break
    assert 429 in codes, codes


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):  # definition order, same as pytest
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:  # noqa: BLE001
                failures += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failures else 0)
