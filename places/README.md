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

## Aliases, levels and postcodes

`buildaddr` carries each address's level (`level_number`, digits, set only for
a plain LEVEL or FLOOR; `level_type` names the type), so "Level 2, 12 Collins
St" picks the row on level 2. It also builds `alias_locality` and
`alias_street` from G-NAF's alias tables (`loadreal` loads them; on an
existing dataset `go run ./cmd/loadreal -aliases-only -db ... -base ...`
adds just those): an alias such as JOLIMONT (EAST MELBOURNE) or LITTLE
LATROBE STREET (LITTLE LA TROBE STREET) is answered as the official name.
Aliases that are official names themselves, or that name several places, are
left out.

`go run ./cmd/loadpostcode -db ... -shp POA_2021_AUST_GDA2020.shp -dbf
POA_2021_AUST_GDA2020.dbf` loads ABS Postal Areas: postcode answers stay at
the centre of the postcode's addresses unless that point falls outside the
postal area, when the area's representative point (inside it) is used.
PO-box-only postcodes (3001, 8001) have neither addresses nor an area;
`internal/postbox/pobox_postcodes.tsv` maps the ones checked against
Australia Post to their delivery locality. Add a row only with the URL it was
read from.

## Accuracy checks

`testdata/golden.tsv` holds real Victorian addresses as people type them
(units, "St" as Saint, 4-digit street numbers, multi-word localities,
misspellings), streets and localities with no number, and text /resolve must
decline. `go test ./...` runs it in CI against `testdata/golden_fixture.tsv.gz`,
about 25K real rows around those addresses. Before changing the parser,
generation or scoring, also run it against a full dataset:

```
# golden set through /search and /resolve
AUPLACES_GOLDEN_DB=/path/to/vic.db go test ./internal/api -run Golden -v

# 500 misspelt addresses; reports the match rate
go run ./cmd/gen -real -db /path/to/vic.db -corpus testdata/corpus_real.tsv -cap 200

# both services end to end, golden set through augeo's /geocode
../scripts/smoke-real.sh /path/to/vic.db
```

After adding a street or locality to the golden set, rebuild the fixture:
`go run ./cmd/goldenfixture -db /path/to/vic.db`.

Full-dataset checks open the dataset read-only. A dataset built before
`idx_addr_pid` was added to `buildaddr` needs
`CREATE UNIQUE INDEX idx_addr_pid ON address(gnaf_pid)`, or every address query
scans the whole table. One built before `flat_number` and `lot_number` were
added still serves street addresses, but cannot tell units or lots apart
("7/12 Collins St" is any row at 12 Collins St; "Lot 14 Old Sydney Rd" is any
address on the street): rebuild `address` with `buildaddr`.

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
(`:ro`). Build from the repository root (`docker build -f places/Dockerfile .`)
so `shared/` is in the context. See [release.md](docs/release.md) and the root
`docker-compose.yml`.

## CI

Root `.github/workflows/ci.yml` runs on every push and PR. Releases are
triggered by `places/v*` tags, multi-arch (amd64/arm64), fixture-only (never downloads real data),
corpus-subset smoke test, SBOM + signature per image, actions pinned by commit SHA
(P9). See [release.md](docs/release.md).
