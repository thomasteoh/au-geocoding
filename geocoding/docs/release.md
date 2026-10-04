# Release runbook (Step 5 — public API)

The geocoder is the public-facing API service. It owns auth, rate limits,
quotas, abuse guards and the parse ladder; it **never touches geocoding data
directly** — it calls au-places through the `/resolve` contract (split mode is
the default deployment).

## What's shipped

- `augeo` — serving binary (public API, read-only against the contract).
- `keygen` — operator key issuance into app.db (no HTTP issuance endpoint).
- `Dockerfile` — multi-stage build producing both binaries; build context is
  the repository root.
- `../docker-compose.yml` — the whole stack (geocoder, places resolver,
  loader, Prometheus).
- `../.github/workflows/release-geocoding.yml` — CI triggered by
  `geocoding/v*` tags (P9).
- `LICENSE` (Apache-2.0), `ATTRIBUTION.md` (data licences, D-018).

## Build

```
CGO_ENABLED=0 go build -trimpath -o augeo ./cmd/augeo
CGO_ENABLED=0 go build -trimpath -o keygen ./cmd/keygen
```

Both are statically linked (CGO-free, modernc.org/sqlite). Verify with `file`:
```
file augeo   # statically linked
```

## Run (split mode — default)

```
./augeo -addr :8080 -app-db data/app.db -places-url http://localhost:8090
```

Requires a running au-places instance exposing `POST /resolve`. Without
`AUGEO_PLACES_URL` the server refuses to boot (split mode is the default
deployment). The geocoder never writes the geocoding DBs — au-places owns
those and mounts them read-only.

## app.db — keys & quota

The geocoder's service tables (api_keys, usage, request_log) live in `app.db`,
separate from the geocoding DBs. **Issue a key before first boot** (the server
refuses to boot without an initialized app.db):

```
./keygen -app-db data/app.db -label "my-key" -tier standard
```

Send with `X-Api-Key: <key>`. Anonymous (no header) is rate-limited per IP and
quota-capped at the anonymous tier. Invalid/revoked/disabled keys return a
uniform 401 (T6).

## Run (Docker)

```
# from the repository root
docker build -f geocoding/Dockerfile -t augeocoding:latest .
docker run --rm -v "$(pwd)/data:/data" -p 8099:8080 \
  -e AUGEO_PLACES_URL=http://host.docker.internal:8090 augeocoding:latest
```

Or compose from the repository root (split mode — geocoder + places resolver):

```
docker compose run --rm --entrypoint keygen augeo -app-db /data/app.db -label my-key
docker compose up -d places augeo prometheus
```

## Config (D-020)

Precedence: flag > env > file > default. Env prefix `AUGEO_`. Validated at
boot; a misconfigured server fails fast (exit 1). See `internal/config` for the
full set. Secrets support the `_FILE` convention (e.g. `AUGEO_LLM_API_KEY_FILE`).

| Group | Keys |
|-------|------|
| Server | `ADDR`, `READ_TIMEOUT`, `WRITE_TIMEOUT`, `IDLE_TIMEOUT`, `SHUTDOWN_GRACE` |
| Data | `DATA_DIR`, `GNAF_DB`, `POIS_DB`, `APP_DB`, `STATES` |
| Limits | `MAX_QUERY_LEN`, `MAX_RESULTS`, `MAX_RADIUS_M`, `MAX_BODY_BYTES`, `REQUEST_TIMEOUT` |
| Rate | `ANON_RPS`, `ANON_BURST`, `ANON_DAILY`, `KEY_DEFAULT_RPS`, `KEY_DEFAULT_BURST`, `KEY_DEFAULT_DAILY` |
| Anon LLM | `ANON_LLM_DAILY_PER_IP`, `ANON_LLM_DAILY_GLOBAL` |
| LLM | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_TIMEOUT`, `LLM_MAX_TOKENS` |
| Queue | `QUEUE_DEPTH`, `QUEUE_WORKERS`, `QUEUE_PER_KEY_INFLIGHT`, `BREAKER_THRESHOLD`, `BREAKER_COOLDOWN` |
| Cache | `CACHE_ENTRIES`, `CACHE_TTL` |
| Batch | `BATCH_MAX_ROWS`, `BATCH_WORKERS`, `BATCH_MAX_CONCURRENT_PER_KEY`, `BATCH_MAX_DURATION` |
| Cluster | `STATE_MODE` (single\|cluster), `STATE_DSN` |
| Web | `DEMO_ENABLED`, `DEMO_MAP_ENABLED`, `CORS_ORIGINS` |
| Log | `LOG_LEVEL`, `LOG_FORMAT` |

The effective config is logged at boot with secrets redacted.

## Health

- `GET /healthz` — liveness only.
- `GET /readyz` — readiness: loaded G-NAF/OSM state + dataset version.
- `GET /metrics` — Prometheus text format, counters/histograms only (no
  query-derived labels).

## API

The geocoder exposes the public endpoints; the resolver (au-places) owns the
data. All POSTs require an `X-Api-Key` (anonymous is rate-limited per IP) and
the scope `search`.

- `POST /search` — free-text/structured address search (ladder).
- `POST /geocode` — resolve structured components (ladder bypassed).
- `POST /reverse` — reverse geocode (lat/lon → nearest).
- `POST /parse` — parse-only (return components, no resolution).
- `POST /batch` — multi-row batch (bounded).
- `POST /suggest` — keystroke autocomplete (Step 7 / S-13). Proxies to the
  resolver's `/suggest`; prefix-matches the FTS5 street+locality index. Each
  entry is self-disambiguating and carries resolvable handles. The prefix is
  never logged (INV-1) — only the suggestion count is recorded. Quota is
  charged per suggestion row (D-034).

## Control plane

`/ctrl/llm` (GET/POST) is the runtime LLM config interface. It is **token-gated**
via `AUGEO_CTRL_TOKEN` — empty disables the endpoint (fail closed). GET returns
the config with the API key redacted; POST updates a subset and keeps the rest.
**The POST body is bounded** (1 MiB) — a misconfigured or oversized body is
rejected. `AUGEO_CTRL_TOKEN` is a secret — never pass it as a flag.

## CI (P9)

Tag-triggered (`v*`), fixture-only (never downloads real data), smoke test
against the mock resolver (`cmd/mockplaces`) — the geocoder never touches real
geocoding data, so CI exercises the contract end to end with canned candidates.
Actions pinned by commit SHA. Release notes state the contract version tested.

**GHCR publish (R9.7)**: the docker job logs in to `ghcr.io` and pushes per-arch
images; a `manifest` job merges them into a single multi-arch tag
(`ghcr.io/<repo>:<tag>`). `packages: write` permission is set. Push requires a
git remote — once the repo is pushed to GitHub, a `v*` tag triggers the full
pipeline. No cosign (see below).

**Cosign signing**: the keyless cosign step is NOT enabled in the shipped
workflow (its action SHA needs pinning from upstream). Enable it before
production use with a verified SHA.

**Runner**: the workflow is defined but **not yet connected to a hosted
runner** — neither repo has a git remote. Push to a GitHub repo and the
tag-triggered workflow becomes active. Until then, CI is a definition, not an
execution.

## Licence compliance (D-018)

Code is Apache-2.0. The data (G-NAF, OSM, Geoscape) is separately licensed —
read [ATTRIBUTION.md](ATTRIBUTION.md) before running or redistributing an
instance. OSM-touching responses carry an `attribution` field.
