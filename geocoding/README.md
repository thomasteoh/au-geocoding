# au-geocoder

The public geocoding service. It owns **auth, rate limits, quotas, abuse
guards, `ErrOutOfScope` handling** and the public API surface — everything
Step 5 of au-system. It does **not** own the geocoding data: it calls
**au-places** through the split-service contract (`shared/contract`).

It lives in the au-system monorepo beside `places/` and `shared/`, but it is
its own Go module and its own deployable, so the public surface (keys, quotas,
rate limits) lives where it belongs and the geocoding DBs stay read-only and
unauthenticated behind the contract.

## Layout

| Path | Owns |
|------|------|
| `cmd/augeo` | HTTP server: /search, /geocode, /reverse, /poi, /parse, /batch, /suggest, /healthz, /readyz, /metrics |
| `cmd/keygen` | Operator key issuance (no HTTP endpoint — T6) |
| `cmd/mockplaces` | Test resolver implementing the contract /resolve |
| `internal/ladder` | Parse ladder rungs 1–5; LLM admission/breaker/singleflight |
| `internal/ranking` | Two-phase ranking: FTS5 cap, then Go composite |
| `internal/publicapi` | app.db: api_keys, usage, request_log; pepper, quota, token bucket |
| `internal/placesclient` | Split-mode resolver over HTTP |
| `internal/config` | D-020: flag > env > file > default, AUGEO_ prefix, fail fast |
| `../shared/contract` | The geocoder↔places contract (single-binary + split mode) |
| `../shared/normalise` | Free text → tokens; FTS5-injection guard (T3) |
| `../shared/slog` | Structured logging (INV-1: event + k/v only) |

## Build

```sh
go build ./...
go test ./...
```

## Run (split mode)

```sh
go run ./cmd/augeo \
  -addr :8080 \
  -app-db data/app.db \
  -places-url http://localhost:8090
```

Requires a running au-places instance exposing `POST /resolve`
(the contract endpoint). Without `AUGEO_PLACES_URL` the server refuses to boot —
split mode is the default deployment.

## Keys

Issue via keygen (no HTTP issuance endpoint — keys are an operator workflow):

```sh
go run ./cmd/keygen -app-db data/app.db -label "my-key" -tier standard
```

Send with `X-Api-Key: <key>`. Anonymous (no header) is rate-limited per IP and
quota-capped at the anonymous tier. Invalid/revoked/disabled keys all return a
uniform 401 (T6) — the API never confirms which keys exist.

## Batch geocoding (`POST /batch`)

Batch geocoding is a **keyed, batch-scoped, batch-tier** endpoint — it is
never anonymous. The caller needs the `batch` scope *and* the batch quota
tier; a `search`-only key, or a key on any other tier, gets 403. Moving an
org off the batch tier also strips `batch` from its keys.

Request: `{"items":[{"query":"12 high st"},{"query":"woolworths near doncaster"},{"kind":"reverse","lat":-38.19,"lon":144.32}]}`

- Each item is one geocode: free-text `query`, or `kind:"reverse"` with
  `lat`/`lon`, or `kind:"poi"`. Unknown kinds default to `search`.
- Caps: `Batch.MaxRows` items (default 100000) — over-cap → 400 `batch too
  large`. Per-item `query` length is capped at `MaxQueryLen` (256).
- Processing is parallel over `Batch.Workers` (default 4); response order
  always matches request order (results written by item index).
- Runtime is bounded by `Batch.MaxDuration` (600s), not the single-query
  `RequestTimeout`.
- One caller runs at most `Batch.MaxConcurrentPerKey` (default 1) batches at
  a time; another is 429 `too many concurrent batches`.
- A batch with more items than the rows left in today's quota is refused
  up front (429 `quota exceeded`), before any item runs.

Response: `{"items":[{"index":0,"status":200,"strategy":"address","candidates":[...]},...]}`

- **Per-item status** — one bad item does not fail the batch. Each item carries
  its own `status`, `strategy`, `candidates`, or `error` (e.g. `no candidates`,
  `query too long`, `reverse needs lat/lon`). The envelope is HTTP 200 when
  items succeed; an item's status is the one the single endpoint would give
  (400, 404, 429, 500, ...). Item errors are fixed messages; a server-side
  failure is `internal error`, with the reason code in the server log.
- Quota is charged per **result row** across all items (D-034); a batch that
  would exceed the key's daily ceiling is refused wholesale (429 `quota
  exceeded`) — the caller retries.
- Attribution (ODbL) is returned on OSM-touching batches (D-018).

## Config

All env vars use the `AUGEO_` prefix (D-020), precedence flag > env > file >
default, validated at boot (fail fast). See `internal/config` for the full set.
Secrets support the `_FILE` convention (`AUGEO_LLM_API_KEY_FILE`,
`AUGEO_CTRL_TOKEN_FILE`, `AUGEO_SECRET_KEY_FILE`, `AUGEO_SMTP_PASSWORD_FILE`);
a `_FILE` that is set but unreadable fails boot.

## Security notes

- Keys are SHA-256(key ‖ pepper); the pepper is persisted in app.db (all
  processes share it); raw keys are never stored or logged (T6).
- No raw query text is ever logged or persisted (INV-1/D-015/T9).
- Quotas are per **result row**, not per request (D-034). A caller already
  at its ceiling is refused before any work. An LLM-rung answer costs at
  least one row, even with no candidates.
- LLM-rung calls have their own daily caps: anonymous callers
  `AUGEO_ANON_LLM_DAILY_PER_IP` (10) and `AUGEO_ANON_LLM_DAILY_GLOBAL`
  (1000) per replica, 0 turns anonymous LLM off; keyed callers 50 (demo),
  1000 (standard) or 5000 (batch) per org or operator key, counted in
  `usage_principal.llm_calls`. Each caller holds at most
  `AUGEO_QUEUE_PER_KEY_INFLIGHT` (2) LLM requests at once. Calls are
  counted before the provider is called.
- The client IP for rate limits and anonymous quota is the TCP peer, unless
  the peer is in `AUGEO_TRUSTED_PROXY` (comma-separated IPs/CIDRs): then
  `X-Forwarded-For` is read from the right and the first untrusted address
  is the client. IPv6 clients are keyed by /64. The anonymous per-IP table
  holds at most 100000 addresses a day; past that, new addresses are refused.
- Error responses carry fixed messages. Internal error text (upstream
  addresses, model output) goes to the log only as a reason code.
- `ErrOutOfScope` propagates as a 400 — it never becomes an empty result
  (T4/D-032).
- Attribution is returned on OSM-touching responses (D-018).

## Docker

`Dockerfile` builds the serving binary (`augeo`) and the operator tool
(`keygen`). The geocoder never mounts geocoding data — it reads au-places
through the contract. Build from the repository root
(`docker build -f geocoding/Dockerfile .`) so `shared/` is in the context. See
[docs/release.md](docs/release.md) and the root `docker-compose.yml`.

## CI

Root `.github/workflows/ci.yml` runs on every push and PR. Releases are
triggered by `geocoding/v*` tags, fixture-only (never downloads real data), smoke test against the
mock resolver (`cmd/mockplaces`) — the geocoder never touches real geocoding
data, so CI exercises the contract end to end with canned candidates. Actions
pinned by commit SHA (P9). See [docs/release.md](docs/release.md).

## License

Apache-2.0. `ATTRIBUTION.md` covers G-NAF (CC BY 4.0 + use restriction), OSM
(ODbL), Geoscape (CC BY 4.0).
