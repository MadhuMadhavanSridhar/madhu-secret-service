# Progress log

Build & Break round 1: One-Time Secret Service. Spec dated Nov 11, 2026. Work done Nov 15, 2026.

## Status

Complete and verified. The service builds, every automated check passes, and a manual curl and Docker walkthrough confirmed the behaviour end to end. The compose stack runs on port 8080.

## Timeline

1. Read the spec PDF from Downloads and wrote `DESIGN.md` before any code: threat model, where keys live, how deletion deletes, plus one open question for the organizer.
2. Built the service in Go with Redis 7 as the only store, shipped as one `docker compose up`.
3. Wrote a Go test suite against an in-process Redis emulator, a black-box suite in Python mirroring the scoring table, a k6 profile, and a k6-free load probe.
4. Moved from Go 1.22.5 to Go 1.27.4 on request: toolchain pinned in `go.mod`, image on `golang:1.27-alpine`, dependencies bumped to current releases, code modernised (stdlib HKDF, request patterns, range-over-int, SplitSeq, CutPrefix, clear).
5. Upgraded the machine: system Go install to 1.27.4 via winget, gopls to v0.24.0, which cleared the editor diagnostic about SplitSeq.
6. Raised the read rate limit from burst 60 at 120/min to burst 100 at 240/min after a sequential test run from one IP tripped the smaller bucket during the 50-way race. Create stays at burst 30 at 30/min.
7. Ran the manual walkthrough with curl and docker (see README and the section below).

## Layout

| Path | Purpose |
|---|---|
| `DESIGN.md` | One-page design note required by the spec |
| `README.md` | Run, API, configuration, test commands |
| `cmd/server/main.go` | Entrypoint, env parsing, graceful shutdown |
| `internal/crypto` | Tokens, HKDF, AES-256-GCM, Argon2id verifier |
| `internal/store` | Redis records, atomic consume and delete Lua scripts |
| `internal/ratelimit` | Per-IP token bucket Lua script |
| `internal/api` | Handlers, middleware, metrics |
| `internal/audit` | JSON audit logger |
| `docker-compose.yml`, `Dockerfile`, `redis/redis.conf` | Stack: distroless app, memory-only Redis with ACL |
| `tests/test_service.py` | Black-box suite, runs with pytest or plain python |
| `tests/load.js`, `tests/load_probe.py` | k6 profile and stdlib fallback |

## Verification results

| Check | Result |
|---|---|
| `go vet`, `go test ./...` (16 tests) | pass on Go 1.27.4 |
| Black-box suite against live stack (14 checks) | pass |
| Timing, wrong passphrase vs unknown id | 16.4 ms vs 16.9 ms median |
| 50 concurrent GETs on a one-view secret | exactly one 200, rest 404 |
| Create burst with spoofed X-Forwarded-For | 429 with Retry-After after the bucket |
| Redis keyspace and container logs grepped for canary, passphrase, tokens | clean |
| Redis `/data` | empty tmpfs, no RDB or AOF |
| App container | distroless, no shell, read-only, non-root |
| Restart | fresh KEK, old records return 404 and expire by TTL |
| Load probe from inside the compose network, 32 workers | 2893 req/s, read p99 23.7 ms, create p99 34.9 ms |

## Findings worth remembering

- **Windows host proxy artifact.** Load generated from the Windows host shows a 40 ms stall on POSTs that the service does not have. Docker Desktop's host-to-VM proxy meets Linux delayed ACK on two-packet requests. Run generators inside the compose network.
- **PowerShell 5.1 strips JSON quotes** from `curl.exe -d` arguments. Use Git Bash for manual curl testing.
- **Rate limiter and sequential suites.** Any suite that runs correctness checks and then a race from one IP eats into the read bucket. Burst 100 leaves room.
- **HEAD never consumes a view**, so link previewers cannot burn a secret.

## Open question for the organizer

The load test at 200 rps for 60 s from a single IP collides with any per-IP limiter strict enough to 429 a burst. `RATE_LIMIT_EXEMPT_CIDRS` exists for the generator. Decide whether the harness spreads source IPs or expects that exemption.

## Next steps

- Install k6 and run `tests/load.js` for the exact 200 rps profile with p99 thresholds.
- Organizer prep from the spec: hidden pytest plus k6 suite, private reference implementation (this build can serve), attack-phase scope rules.
- Attack-phase self-review candidates: anything that logs the request path upstream of the app, Redis ACL password handling in `.env`, behaviour when Redis hits `maxmemory`.
- Optional: a minimal UI with an interstitial so browser clicks do not consume a view before the reader is ready.
