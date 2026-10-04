# au-geocoder

The public geocoding service. It owns **auth, rate limits, quotas, abuse
guards, `ErrOutOfScope` handling** and the public API surface — everything
Step 5 of au-system. It does **not** own the geocoding data: it calls
**au-places** through the split-service contract (`internal/contract`).

The repo is deliberately separate from au-places so the public surface (keys,
quotas, rate limits) lives where it belongs and the geocoding DBs stay
read-only and unauthenticated behind the contract.

## Layout

| Path | Owns |
|------|------|
| `cmd/augeo` | HTTP server: /search, /geocode, /reverse, /poi, /parse, /batch, /suggest, /healthz, /readyz, /metrics |
| `cmd/keygen` | Operator key issuance (no HTTP endpoint — T6) |
| `cmd/mockplaces` | Test resolver implementing the contract /resolve |
| `internal/contract` | The geocoder↔places contract (single-binary + split mode) |
| `internal/normalise` | Free text → tokens; FTS5-injection guard (T3) |
| `internal/ladder` | Parse ladder rungs 1–5; LLM admission/breaker/singleflight |
| `internal/ranking` | Two-phase ranking: FTS5 cap, then Go composite |
| `internal/publicapi` | app.db: api_keys, usage, request_log; pepper, quota, token bucket |
| `internal/placesclient` | Split-mode resolver over HTTP |
| `internal/slog` | Structured logging (INV-1: event + k/v only) |
| `internal/config` | D-020: flag > env > file > default, AUGEO_ prefix, fail fast |

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

Batch geocoding is a **keyed, batch-scoped** endpoint — it is never anonymous.
A key issued with the `batch` scope (or a key with `search`+`batch` scopes)
can call it; a `search`-only key gets 403.

Request: `{"items":[{"query":"12 high st"},{"query":"woolworths near doncaster"},{"kind":"reverse","lat":-38.19,"lon":144.32}]}`

- Each item is one geocode: free-text `query`, or `kind:"reverse"` with
  `lat`/`lon`, or `kind:"poi"`. Unknown kinds default to `search`.
- Caps: `Batch.MaxRows` items (default 100000) — over-cap → 400 `batch too
  large`. Per-item `query` length is capped at `MaxQueryLen` (256).
- Processing is parallel over `Batch.Workers` (default 4); response order
  always matches request order (results written by item index).
- Runtime is bounded by `Batch.MaxDuration` (600s), not the single-query
  `RequestTimeout`.

Response: `{"items":[{"index":0,"status":200,"strategy":"address","candidates":[...]},...]}`

- **Per-item status** — one bad item does not fail the batch. Each item carries
  its own `status`, `strategy`, `candidates`, or `error` (e.g. `no candidates`,
  `query too long`, `reverse needs lat/lon`). The envelope is HTTP 200 when
  items succeed; item-level errors are 400 in the item, not the response.
- Quota is charged per **result row** across all items (D-034); a batch that
  would exceed the key's daily ceiling is refused wholesale (429 `quota
  exceeded`) — the caller retries.
- Attribution (ODbL) is returned on OSM-touching batches (D-018).

## Config

All env vars use the `AUGEO_` prefix (D-020), precedence flag > env > file >
default, validated at boot (fail fast). See `internal/config` for the full set.
Secrets support the `_FILE` convention (e.g. `AUGEO_LLM_API_KEY_FILE`).

## Security notes

- Keys are SHA-256(key ‖ pepper); the pepper is persisted in app.db (all
  processes share it); raw keys are never stored or logged (T6).
- No raw query text is ever logged or persisted (INV-1/D-015/T9).
- Quotas are per **result row**, not per request (D-034).
- `ErrOutOfScope` propagates as a 400 — it never becomes an empty result
  (T4/D-032).
- Attribution is returned on OSM-touching responses (D-018).

## Docker

`Dockerfile` builds the serving binary (`augeo`) and the operator tool
(`keygen`). The geocoder never mounts geocoding data — it reads au-places
through the contract. See [docs/release.md](docs/release.md) and the compose
example.

## CI

Tag-triggered, fixture-only (never downloads real data), smoke test against the
mock resolver (`cmd/mockplaces`) — the geocoder never touches real geocoding
data, so CI exercises the contract end to end with canned candidates. Actions
pinned by commit SHA (P9). See [docs/release.md](docs/release.md).

## License

Apache-2.0. `ATTRIBUTION.md` covers G-NAF (CC BY 4.0 + use restriction), OSM
(ODbL), Geoscape (CC BY 4.0).
