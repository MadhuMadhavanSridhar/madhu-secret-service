# One-Time Secret Service: design note

Build & Break round 1 · spec dated Nov 11, 2026 · Go + Redis 7, one `docker compose up`, port 8080.

## Decisions in one breath

- **Server-side encryption, key carried in the URL.** The API contract hands the server plaintext on `POST /secrets`, so client-side crypto would protect only a browser path that curl and the hidden suite never use. Instead the server generates a per-secret key, encrypts, and returns the key inside the share URL. The server stores nothing that decrypts, which is the property a fragment key gives, and `GET /s/{id}` still works from curl.
- **Redis 7, persistence off, as the only store.** `save ""`, `appendonly no`, `maxmemory` with `noeviction`, no published port, ACL user limited to the commands the app needs. Nothing ever touches a disk, so there are no dumps, WAL, backups or soft deletes to recover from.
- **Atomic consume in one Lua script.** Check expiry, compare `views < max_views`, increment, and `DEL` when exhausted, all in one Redis call. Redis executes scripts serially, so 50 racing GETs yield exactly one success with no lock in the app.
- **Go `net/http`.** Static binary, hardware AES-GCM, no deserialization magic, no template engine, no UI, no outbound requests, no filesystem access from input. There is deliberately no extra feature for SSRF or traversal to live in.

## Threat model

Assets: secret content, passphrases, share-URL tokens, deletion tokens, the in-process key-encryption key (KEK), and audit-log integrity.

| Actor | What they try | Control |
|---|---|---|
| Network attacker without a URL | Enumerate IDs, bypass rate limits, use timing to learn which IDs exist | 256-bit random tokens; per-IP token bucket from the TCP peer address; identical 404 and identical work for not-found and wrong-passphrase |
| URL holder beyond intended use | Race the view count, replay, brute-force a passphrase | Atomic Lua consume; Argon2id passphrase verifier; secret burned after 10 failed passphrases |
| Infrastructure reader | Dump Redis or a volume, read container logs, scrape `/metrics`, restore a backup | Ciphertext only in Redis, key never stored; no disk; logs carry hashed references only; metrics have no per-secret or per-IP labels |
| Peer attacker in the attack phase | SSRF, traversal, reversible deletion tokens, recovery after delete | No outbound fetches, no paths from input, random deletion tokens stored only as SHA-256, nothing on disk to recover |

Out of scope: a compromised recipient device, the host itself, and an operator who reads process memory. TLS is assumed at the edge. The lab runs plain HTTP on 8080, so the URL token is visible to anyone on the path there.

## Where keys live

- **Share token.** 32 bytes from `crypto/rand`, base64url, 43 characters. It is the `{id}` in the URL and the only copy exists in the URL.
- **Lookup ID.** `HKDF(token, info="lookup")`, 16 bytes. This is the Redis key. It is one-way, so a Redis dump cannot yield tokens.
- **Content key.** `HKDF(ikm=token, salt=KEK, info="key")`, 32 bytes, AES-256-GCM with a random nonce. Each key encrypts exactly one message.
- **KEK.** Generated in process memory at app start. It is not in env, compose, a file or Redis. Its purpose is defense in depth: an old memory snapshot plus a URL leaked later from chat history still decrypts nothing without the running process. Redis keys are prefixed with a KEK fingerprint, so after an app restart stale records are unreachable and expire on their own.
- **Passphrase.** Argon2id (16 MiB, t=2) over a per-secret salt, then an HMAC under the content key becomes the stored verifier. A dump offers nothing to crack offline because the HMAC key lives only in the URL. Verification happens before consume, so a wrong passphrase never burns a view. Argon2 runs whenever the `X-Passphrase` header is present, against a dummy salt when the record is missing, so request shape alone decides the cost.
- **Deletion token.** 32 random bytes, returned once, stored as SHA-256. `DELETE /s/{id}` needs both the URL token and the deletion token.
- **Never logged.** Access logs record the route template `/s/{id}` and the first 8 hex of the lookup ID, never the path, because the path is the key. Responses carry `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and a `default-src 'none'` CSP.

## How deletion actually deletes

A view that reaches `max_views`, a revoke, or a passphrase lockout all end in a Redis `DEL` inside the same script that decided the outcome. With persistence disabled the bytes exist only in freed Redis heap until reuse, and they are ciphertext whose key was never stored. TTL expiry is Redis `EXPIRE`, and the consume script re-checks `expires_at` so a lazily expired key cannot be read in the gap. The app zeroes plaintext buffers after responding, as best effort in Go. The trade-off is explicit: a restart loses every live secret. A secret that survives a restart is a secret on disk, and that is the harder promise to keep.

## Open question for the organizer

The load test at 200 rps for 60 s from a single IP will collide with any per-IP limiter strict enough to 429 a burst. Defaults ship as create 30/min (burst 30) and read 240/min (burst 100) per IP, tunable by env, with a `RATE_LIMIT_EXEMPT_CIDRS` knob for the load generator. The read burst leaves room for a suite that runs its correctness checks and then the 50-way race from one address. Please confirm whether the harness spreads source IPs or expects an exemption.
