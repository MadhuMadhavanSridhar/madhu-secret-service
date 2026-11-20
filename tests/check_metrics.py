#!/usr/bin/env python3
"""/metrics check (benchmark standard, requirement 12).

Black-box, stdlib only, works against any build on the shared wire contract.

Checks:
  1. GET /metrics returns 200 with a non-empty text body.
  2. Metrics are live: the body changes after traffic.
  3. No secret content, passphrase, deletion token, full id, share URL or
     URL fragment appears, in raw, URL-encoded, base64 or hex form.
  4. No client IP addresses as label values.
  5. No per-secret series: creating 25 secrets adds fewer than 25 series.
     Per-secret labels leak ids and let anyone grow memory without bound.

Usage:  python tests/check_metrics.py [BASE_URL]   (default http://localhost:8080,
        or the BASE_URL environment variable)
Exit code 0 when every check passes.
"""
import base64
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", "http://localhost:8080")).rstrip("/")
IP_LABEL = re.compile(r'="(?:\d{1,3}\.){3}\d{1,3}"|="[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}"', re.I)
PER_SECRET = 25


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def forms(value):
    b = value.encode()
    out = {value, quote(value, safe=""), b.hex(),
           base64.b64encode(b).decode().rstrip("="), base64.urlsafe_b64encode(b).decode().rstrip("=")}
    return {f for f in out if len(f) >= 8}


def series(body):
    return {line.split(" ")[0] for line in body.splitlines() if line and not line.startswith("#")}


def create(content, pw):
    st, raw = call("POST", "/secrets", {"content": content, "ttl_seconds": 300, "max_views": 1, "passphrase": pw})
    if st != 201:
        raise SystemExit(f"cannot create a secret: POST /secrets returned {st} {raw[:200]!r}")
    doc = json.loads(raw)
    u = urlparse(doc["url"])
    return u.path or f"/s/{doc['id']}", doc


def main():
    results = []

    def report(name, ok, detail=""):
        results.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))

    st, before = call("GET", "/metrics")
    report("GET /metrics returns 200 with a body", st == 200 and before.strip() != "", f"got {st}, {len(before)} bytes")
    if st != 200:
        return 1

    tag = secrets.token_hex(6)
    canary, pw = f"CANARY-{tag}", f"PW-{tag}-{secrets.token_hex(4)}"
    wrong_pw, wrong_tok = f"WRONGPW-{tag}", f"WRONGTOK-{tag}-{secrets.token_hex(8)}"
    sensitive = [canary, pw, wrong_pw, wrong_tok]

    _, mid = call("GET", "/metrics")
    base_series = series(mid)
    for i in range(PER_SECRET):
        path, doc = create(f"{canary}-{i}", pw)
        sensitive += [f"{canary}-{i}", doc["id"], doc["url"], doc["deletion_token"]]
        if urlparse(doc["url"]).fragment:
            sensitive.append(urlparse(doc["url"]).fragment)
        if i % 5 == 0:
            call("GET", path, headers={"X-Passphrase": wrong_pw})
            call("GET", path, headers={"X-Passphrase": pw})
            call("GET", path, headers={"X-Passphrase": pw})
            call("DELETE", path, headers={"X-Deletion-Token": wrong_tok})
        elif i % 5 == 1:
            call("DELETE", path, headers={"X-Deletion-Token": doc["deletion_token"]})
    call("GET", "/s/" + secrets.token_urlsafe(32))

    _, after = call("GET", "/metrics")
    report("metrics change after traffic", after != before, "body identical before and after 25 creates")

    hits = sorted({v[:24] for v in sensitive for f in forms(v) if f in after})
    report("no content, passphrase, token, id or URL in /metrics", not hits, f"found {hits[:3]}")

    ips = sorted(set(IP_LABEL.findall(after)))
    report("no client IP addresses as label values", not ips, f"found {ips[:3]}")

    grown = len(series(after) - base_series)
    report(f"no per-secret series ({PER_SECRET} creates)", grown < PER_SECRET, f"{grown} new series")

    failed = results.count(False)
    print(f"\n{results.count(True)} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
