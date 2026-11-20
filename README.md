# One-Time Secret Service

Build & Break round 1. Design decisions and threat model are in [DESIGN.md](DESIGN.md).

## Run

```sh
cp .env.example .env     # optional: set REDIS_PASSWORD
docker compose up --build
```

The API listens on port 8080. Redis runs on the internal compose network only, memory only, with no persistence.

## API

| Call | Request | Response |
|---|---|---|
| `POST /secrets` | `{"content": "...", "ttl_seconds": 3600, "max_views": 1, "passphrase": "optional"}` | `201` `{"id", "url", "deletion_token", "expires_at", "max_views", "passphrase_protected"}` |
| `GET /s/{id}` | header `X-Passphrase` when protected | `200` `{"content", "views", "max_views", "remaining"}`; `401 passphrase_required`; `404 not_found` |
| `DELETE /s/{id}` | header `X-Deletion-Token` or `Authorization: Bearer <token>` | `204`; `401`; `404` |
| `GET /healthz` | | `200` or `503` when Redis is unreachable |
| `GET /metrics` | | Prometheus text |

Defaults and limits: `ttl_seconds` 1 to 604800 (default 3600), `max_views` 1 to 100 (default 1), content up to 64 KiB, passphrase up to 256 bytes. A wrong passphrase returns the same `404` body as an unknown id. Ten wrong passphrases burn the secret. `HEAD /s/{id}` always returns `200` and never consumes a view, so link previewers cannot burn a secret.

Rate limits are per client IP: create 30 per minute (burst 30), read and delete 240 per minute (burst 100). Limited requests get `429` with `Retry-After`. The read burst is sized so a test run that does its correctness checks and then a 50-way race from one address does not trip it.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_PASSWORD` | dev value in compose | Password for the `app` ACL user. Set it in `.env`. |
| `RATE_CREATE_PER_MIN`, `RATE_READ_PER_MIN` | 30, 240 | Sustained per-IP rates. |
| `RATE_CREATE_BURST`, `RATE_READ_BURST` | 30, 100 | Bucket capacity. |
| `RATE_LIMIT_EXEMPT_CIDRS` | empty | Comma-separated CIDRs never limited, for the load generator. |
| `TRUSTED_PROXY_CIDRS` | empty | Peers allowed to set `X-Forwarded-For`. Empty means the TCP peer is always the client. |
| `PUBLIC_BASE_URL` | derived from `Host` | Prefix for returned share URLs. |
| `MAX_CONTENT_BYTES` | 65536 | Content size limit. |
| `MAX_PASSPHRASE_FAILURES` | 10 | Wrong passphrases before the secret is burned. |
| `DEFAULT_TTL_SECONDS`, `MIN_TTL_SECONDS`, `MAX_TTL_SECONDS` | 3600, 1, 604800 | TTL bounds. |

## Tests

```sh
go test ./...                       # unit and integration tests against an in-process Redis emulator
python tests/test_service.py        # black-box checks against a running stack (pytest also works)
k6 run tests/load.js                # 200 rps for 60 s; exempt the generator IP first
python tests/load_probe.py 20 32    # k6-free fallback: 32 keep-alive workers for 20 s
```

On Docker Desktop for Windows, run the load generator from inside the compose network rather than from the host. The host port proxy adds a 40 ms stall to two-packet POSTs that the service does not have:

```sh
docker run --rm --network madhu-secret-service_default -v "${PWD}/tests:/t:ro" \
  -e BASE_URL=http://app:8080 python:3-alpine python -I /t/load_probe.py 20 32
```

The black-box suite covers every row of the scoring table: correctness, the 50-way race, enumeration and timing, rate limiting with spoofed `X-Forwarded-For`, plaintext at rest via `docker compose exec`, log hygiene, and headers.

## Operational notes

- The key-encryption key is generated in process memory at start. A restart gives a fresh key and, because Redis holds nothing on disk, an empty store. Live secrets do not survive a restart by design.
- The share URL path is the key. Do not put the service behind anything that logs full request paths.
- The app container is distroless, read-only, non-root, with all capabilities dropped. There is no shell inside it.
