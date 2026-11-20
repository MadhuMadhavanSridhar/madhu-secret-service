#!/usr/bin/env python3
"""Log-hygiene check (benchmark standard, requirement 9).

Black-box, stdlib only. Drives a build through the normal and the error
paths with marked values, then greps every service's logs for them.

Never allowed in any log, in raw, URL-encoded, base64 or hex form:
  - secret content (a canary)
  - the passphrase, right or wrong
  - the deletion token, right or wrong
  - the full share URL, the full id and any URL fragment. The id is a bearer
    capability: whoever reads it from a log can read the live secret. A
    short prefix or a hash is fine for correlating audit lines.

Must be present (heuristic, the matching line is printed):
  - an audit line for create, read and delete, each with a timestamp and a
    client IP written by the app itself.

Usage:
  python tests/check_logs.py [--base-url URL] [--project-dir DIR]
  python tests/check_logs.py --base-url URL --log-file app.log   # non-docker builds
Exit code 0 when every check passes.
"""
import argparse
import base64
import json
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\"(ts|time|timestamp)\"\s*:\s*\d{9,}")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
NOISE = re.compile(r"healthz|/metrics", re.I)
ACTIONS = {
    "create": re.compile(r"creat|POST", re.I),
    "read": re.compile(r"\bread\b|\bviewed\b|\bview\b|consum|\bGET\b|retriev", re.I),
    "delete": re.compile(r"delet|revok|DELETE", re.I),
}


def call(base, method, path, body=None, headers=None, raw_body=None):
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def forms(value):
    b = value.encode()
    out = {value, quote(value, safe=""), b.hex(),
           base64.b64encode(b).decode().rstrip("="), base64.urlsafe_b64encode(b).decode().rstrip("=")}
    return {f for f in out if len(f) >= 8}


def drive(base):
    """Exercise every path and return {label: [sensitive values]}."""
    tag = secrets.token_hex(6)
    canary = f"CANARY-{tag}-{secrets.token_hex(8)}"
    pw = f"PW-{tag}-{secrets.token_hex(6)}"
    wrong_pw = f"WRONGPW-{tag}-{secrets.token_hex(6)}"
    wrong_tok = f"WRONGTOK-{tag}-{secrets.token_hex(12)}"
    marks = {"content": [canary], "passphrase": [pw, wrong_pw], "deletion token": [wrong_tok],
             "share URL / id / fragment": []}

    made = []
    for i in range(3):
        st, raw = call(base, "POST", "/secrets", {"content": f"{canary}-{i}", "ttl_seconds": 300,
                                                  "max_views": 2, "passphrase": pw})
        if st != 201:
            raise SystemExit(f"cannot create a secret: POST /secrets returned {st} {raw[:200]!r}")
        doc = json.loads(raw)
        u = urlparse(doc["url"])
        made.append((u.path or f"/s/{doc['id']}", doc["deletion_token"]))
        marks["content"].append(f"{canary}-{i}")
        marks["deletion token"].append(doc["deletion_token"])
        marks["share URL / id / fragment"] += [doc["url"], doc["id"]] + ([u.fragment] if u.fragment else [])

    (p0, t0), (p1, t1), (p2, t2) = made
    call(base, "GET", p0, headers={"X-Passphrase": pw})            # good read
    call(base, "GET", p0, headers={"X-Passphrase": wrong_pw})      # wrong passphrase
    call(base, "GET", p0)                                          # missing passphrase
    call(base, "GET", p1, headers={"X-Passphrase": pw})
    call(base, "GET", p1, headers={"X-Passphrase": pw})            # last view
    call(base, "GET", p1, headers={"X-Passphrase": pw})            # already gone
    call(base, "DELETE", p2, headers={"X-Deletion-Token": wrong_tok})  # wrong token
    call(base, "DELETE", p2, headers={"X-Deletion-Token": t2})         # revoke
    call(base, "DELETE", p0, headers={"Authorization": f"Bearer {t0}"})
    # Error paths that tempt a build into logging the request body.
    call(base, "POST", "/secrets", {"content": canary, "ttl_seconds": -1, "max_views": 1, "passphrase": pw})
    call(base, "POST", "/secrets", raw_body=f'{{"content": "{canary}", "passphrase": "{pw}"'.encode())
    return marks


def read_logs(project_dir, since, log_file):
    if log_file:
        with open(log_file, encoding="utf-8", errors="replace") as f:
            return f.read()
    r = subprocess.run(["docker", "compose", "--project-directory", project_dir, "logs", "--no-color",
                        "--no-log-prefix", "--since", since], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise SystemExit(f"docker compose logs failed: {r.stderr.strip()}")
    return r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--log-file", help="read logs from this file instead of docker compose")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    results = []

    def report(name, ok, detail=""):
        results.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))

    st, _ = call(base, "GET", "/healthz")
    if st != 200:
        print(f"[FAIL] stack is healthy: GET /healthz returned {st}")
        return 1

    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    time.sleep(1)
    marks = drive(base)
    time.sleep(2)  # let log drivers flush
    logs = read_logs(args.project_dir, since, args.log_file)
    lines = logs.splitlines()
    print(f"read {len(lines)} log lines\n")

    for label, values in marks.items():
        hits = []
        for v in values:
            for f in forms(v):
                for line in lines:
                    if f in line:
                        hits.append(line.strip()[:160])
                        break
        report(f"no {label} in logs", not hits, f"{len(hits)} hit(s), e.g. {hits[0]!r}" if hits else "")

    for action, pattern in ACTIONS.items():
        line = next((l for l in lines if pattern.search(l) and TS.search(l) and IP.search(l)
                     and not NOISE.search(l)), None)
        report(f"audit line for {action} with time and IP", line is not None,
               repr(line.strip()[:160]) if line else "no line has the action, a timestamp and an IP")

    failed = results.count(False)
    print(f"\n{results.count(True)} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
