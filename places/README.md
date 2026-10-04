# auplaces

Deterministic geocoding/resolution service for Australian places (Victoria dataset).
Serves addresses, POIs, locality boundaries and reverse geocoding from a read-only
SQLite dataset. This is the self-host release (Step 4).

## What it does

- `POST /search` — parse-ladder resolution: coordinate, address, POI-near-anchor,
  bare POI. Deterministic, no LLM (rung 5 deferred). Query string capped at
  `MaxQueryLen=256` before normalisation (400 `query too long`) — the body limit
  alone isn't enough, a huge query can OOM the server.
- `POST /reverse` — nearest addresses to a point, distance-ranked, expanding bbox.
- `POST /suggest` — keystroke autocomplete (Step 7 / S-13). Prefix-matches the
  `suggest_idx` FTS5 street+locality index; self-disambiguating entries with
  resolvable handles. Built by `auplaces-suggest`.
- `POST /locality` — boundary containment (geopoly) for a point.
- `POST /resolve` — the split-service contract endpoint. Structured resolution
  request (kind, generate/score tokens, anchor, within, limit) dispatched by
  `Kind` to the internal resolvers; exposes G-NAF quality axes (confidence,
  geocode reliability) and `match_score`. The au-geocoding public API calls this
  in split mode. Versioned via `X-Augeo-Contract-Version`.
- `GET /readyz` — per-dataset loaded state + dataset version, with the reason when
  not ready (P8).
- `GET /healthz` — liveness only; stays green during load (P8).
- `GET /metrics` — Prometheus text format (counters per endpoint/status, latency
  histogram, no query-derived labels — INV-1).

Every response names the dataset version that produced it (INV-5). No raw query
text is ever logged or emitted as telemetry (INV-1). The serving dataset is
read-only at runtime — only the loader writes (INV-4, D-019).

## Build

```
go build -o auplaces-server ./cmd/server
go build -o auplaces-load ./cmd/buildaddr
```

The server is a single static binary (CGO-free, `modernc.org/sqlite`). It embeds
the demo UI and docs.

## Run (self-host)

```
./auplaces-server -db data/vic.db -addr :8080
```

The DB is opened read-only (`PRAGMA query_only=ON`). Bootstrap/refresh is a
separate loader binary (`auplaces-load`), the only writer. See the au-system
operations runbook (`~/wiki/projects/au-system/operations.md`) for the
refresh/activate runbook.

## Config (D-020)

Precedence: flag > env > file > default. Env vars are prefixed `AUGEO_`. Validated
at boot; a misconfigured server refuses to start (fail fast).

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `-db` | `AUGEO_DB` | `data/vic.db` | serving DB path (read-only) |
| `-addr` | `AUGEO_ADDR` | `:8080` | listen address |
| (none) | `AUGEO_CTRL_TOKEN` | empty (disabled) | secret for `POST /ctrl/activate`; empty disables the swap endpoint |

Effective config is logged at startup with secrets redacted (there are none here —
no secrets in this service, except the optional `AUGEO_CTRL_TOKEN`).

## Licence & attribution

Code is Apache-2.0. The data (G-NAF, OSM, Geoscape) is separately licensed and
operator-facing obligations are documented in [ATTRIBUTION.md](ATTRIBUTION.md).
**The repo ships no data.** Read ATTRIBUTION.md before running or redistributing
an instance.

OSM-touching responses carry an `attribution` field (D-018).

## Docker

`Dockerfile` builds the server binary; the data volume is mounted read-only
(`:ro`). See [release.md](docs/release.md) and the compose example.

## CI

Tag-triggered, multi-arch (amd64/arm64), fixture-only (never downloads real data),
corpus-subset smoke test, SBOM + signature per image, actions pinned by commit SHA
(P9). See [release.md](docs/release.md).
