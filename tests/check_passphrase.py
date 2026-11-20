#!/usr/bin/env python3
"""Passphrase-path check (benchmark standard, requirement 3b).

Black-box, stdlib only, works against any build that follows the shared
wire contract (passphrase sent in the X-Passphrase header).

Checks:
  1. Right passphrase returns 200 with the exact content.
  2. Missing passphrase is refused (401 or 404) and does not use up a view.
  3. Wrong passphrase returns 404 with the same body as an unknown id.
  4. Wrong passphrases do not use up views: three wrong tries, then the
     right one still reads a max_views=1 secret.
  5. The passphrase is case-sensitive and exact (no prefix match, no
     dropped characters).
  6. max_views still applies with a passphrase: two reads, then 404.
  7. A passphrase-protected secret is gone after its last view, even with
     the right passphrase.
  8. The passphrase never appears in any response body or header.

Usage:  python tests/check_passphrase.py [BASE_URL]   (default http://localhost:8080,
        or the BASE_URL environment variable)
Exit code 0 when every check passes.
"""
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", "http://localhost:8080")).rstrip("/")
seen_passphrases = []
leaks = []


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, raw, hdrs = r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        status, raw, hdrs = e.code, e.read(), e.headers
    blob = raw.decode("utf-8", "replace") + "\n" + str(hdrs)
    for p in seen_passphrases:
        if p in blob:
            leaks.append(f"{method} {path} -> {status}")
    return status, raw


def create(content, passphrase, max_views=1):
    seen_passphrases.append(passphrase)
    status, raw = call("POST", "/secrets", {"content": content, "ttl_seconds": 300,
                                            "max_views": max_views, "passphrase": passphrase})
    if status != 201:
        raise SystemExit(f"cannot create a secret: POST /secrets returned {status} {raw[:200]!r}")
    doc = json.loads(raw)
    return urlparse(doc["url"]).path or f"/s/{doc['id']}"


def get(path, passphrase=None):
    return call("GET", path, headers={"X-Passphrase": passphrase} if passphrase is not None else {})


def content_of(raw):
    try:
        return json.loads(raw).get("content")
    except (ValueError, AttributeError):
        return None


def main():
    results = []

    def report(name, ok, detail=""):
        results.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))

    status, _ = call("GET", "/healthz")
    if status != 200:
        print(f"[FAIL] stack is healthy: GET /healthz returned {status}")
        return 1

    pw = "Pass " + secrets.token_hex(8) + " !#"

    # 1 + 2: missing first (must not burn), then right passphrase reads it.
    content = "pp-" + secrets.token_hex(8)
    path = create(content, pw)
    missing, _ = get(path)
    report("missing passphrase is refused (401 or 404)", missing in (401, 404), f"got {missing}")
    st, raw = get(path, pw)
    report("right passphrase returns the exact content", st == 200 and content_of(raw) == content,
           f"got {st} {raw[:120]!r}")
    report("missing passphrase does not use up a view", st == 200, "secret was gone after a request without passphrase")

    # 3: wrong passphrase looks exactly like an unknown id.
    path = create("pp-" + secrets.token_hex(8), pw)
    st_wrong, body_wrong = get(path, "wrong-" + secrets.token_hex(4))
    st_unknown, body_unknown = get("/s/" + secrets.token_urlsafe(32), "wrong-" + secrets.token_hex(4))
    report("wrong passphrase returns 404", st_wrong == 404, f"got {st_wrong}")
    report("wrong passphrase body matches unknown-id body", body_wrong == body_unknown,
           f"{body_wrong[:80]!r} vs {body_unknown[:80]!r}")

    # 4: wrong tries do not burn views.
    content = "pp-" + secrets.token_hex(8)
    path = create(content, pw)
    for _ in range(3):
        get(path, "nope-" + secrets.token_hex(4))
    st, raw = get(path, pw)
    report("three wrong passphrases do not use up the view", st == 200 and content_of(raw) == content, f"got {st}")

    # 5: exact and case-sensitive.
    content = "pp-" + secrets.token_hex(8)
    path = create(content, pw)
    # No leading/trailing-space variants: HTTP strips header whitespace in transit.
    variants = [pw.lower(), pw.upper(), pw[:-1], pw + "x", pw.replace(" ", "")]
    accepted = [v for v in variants if v != pw and get(path, v)[0] == 200]
    report("passphrase is exact and case-sensitive", not accepted, f"also accepted {accepted!r}")

    # 6 + 7: max_views with a passphrase, gone afterwards.
    content = "pp-" + secrets.token_hex(8)
    path = create(content, pw, max_views=2)
    first, second, third = get(path, pw)[0], get(path, pw)[0], get(path, pw)[0]
    report("max_views=2 allows two reads with the passphrase", (first, second) == (200, 200), f"got {first}, {second}")
    report("protected secret is gone after its last view", third == 404, f"third read got {third}")

    # 8: never echoed.
    unique = sorted(set(leaks))
    report("passphrase never appears in a response", not leaks,
           f"{len(leaks)} responses, e.g. " + "; ".join(unique[:3]))

    failed = results.count(False)
    print(f"\n{results.count(True)} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
