# Release runbook (Step 4)

Self-host release: single static binary, Docker, CI, licence compliance. The
serving binary is CGO-free (modernc.org/sqlite), statically linked, no runtime
deps — copy it and run. The loader binary is the only writer (INV-4, D-019).

## What's shipped

- `auplaces-server` — serving binary (read-only, single static binary).
- `auplaces-load` — loader binary (only writer; builds/refreshes the dataset).
- `Dockerfile` — multi-stage build producing both binaries (D-019); build
  context is the repository root.
- `../docker-compose.yml` — `places` mounts data `:ro`; `loader` is a one-shot.
- `../.github/workflows/release-places.yml` — CI triggered by `places/v*`
  tags (P9).
- `LICENSE` (Apache-2.0), `ATTRIBUTION.md` (data licences, D-018).

## Build

```
CGO_ENABLED=0 go build -trimpath -o auplaces-server ./cmd/server
CGO_ENABLED=0 go build -trimpath -o auplaces-load ./cmd/buildaddr
```

Both are statically linked. Verify with `file`:
```
file auplaces-server   # statically linked
```

## Run (bare metal)

```
./auplaces-server -db data/vic.db -addr :8080
```

The DB must already exist (built by `auplaces-load`). The server opens it
read-only (`mode=ro` and `query_only` on every pooled connection) and refuses to start if the `address` table
is missing (D-020 fail-fast).

## Run (Docker)

```
# from the repository root
docker build -f places/Dockerfile -t auplaces:latest .
docker run --rm -v "$(pwd)/data:/data:ro" -p 8080:8080 auplaces:latest
```

Or compose, from the repository root:

```
docker compose run --rm loader   # build/refresh dataset into the volume
docker compose up -d places      # serve it (read-only mount)
```

The server mounts the data volume `:ro` (D-019, INV-4). Only the loader writes.

## Config (D-020)

Precedence: flag > env > file > default. Env prefix `AUGEO_`. Validated at boot;
a misconfigured server fails fast (exit 1).

| Flag | Env | Default |
|------|-----|---------|
| `-db` | `AUGEO_DB` | `data/vic.db` |
| `-addr` | `AUGEO_ADDR` | `:8080` |

Config file: `AUGEO_CONFIG` (JSON, `{"db": "...", "addr": "..."}`). The server
logs the effective config at boot with secrets redacted (none here).

## Health

- `GET /healthz` — liveness only; stays green during load (P8).
- `GET /readyz` — readiness: per-dataset loaded state + dataset version. Reports
  `not_ready` with a reason while loading (P8/R8.2).
- `GET /metrics` — Prometheus text format. Counters per endpoint/status and a
  latency histogram; no query-derived labels (INV-1). Mirrors au-geocoding's
  collector so both services are scrapable.

## API

- `POST /search` — address/structured search over the serving dataset.
- `POST /reverse` — reverse geocode (lat/lon → nearest).
- `POST /suggest` — keystroke autocomplete (Step 7 / S-13). Prefix-matches over
  the `suggest_idx` FTS5 street+locality index; each entry is self-disambiguating
  (street + street_type + locality + postcode + state) and carries resolvable
  handles (`street_locality_pid` / `locality_pid`) so selection is an exact
  lookup, never a re-parse (PR-7.6). The prefix is never logged (INV-1).
  Requires the `suggest_idx` table — built by `auplaces-suggest` (see loader).

## CI (P9)

Tag-triggered (`v*`), multi-arch (amd64/arm64), fixture-only (never downloads
real data), corpus-subset smoke, SBOM per image. Actions pinned by commit SHA.
Release notes state contract version + dataset versions tested.

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

## Refresh/swap

The dataset is built/refreshed out-of-band by `auplaces-load`. The serving
server is swapped via `cmd/activate` (`/ctrl/activate`) after `cmd/verify` (P1
integrity gate) passes. See the au-system operations runbook
(`~/wiki/projects/au-system/operations.md`).

**The swap endpoint is gated.** `/ctrl/activate` requires the `AUGEO_CTRL_TOKEN`
secret (same value on both the server and the `activate` tool). Without it the
endpoint returns 401 and no swap happens. Set it before starting the server:

```sh
AUGEO_CTRL_TOKEN=$(openssl rand -hex 32) ./auplaces-server -db data/vic.db -addr :8080
```

Then signal the swap with the same token (the tool reads it from the env var):

```sh
AUGEO_CTRL_TOKEN=$TOKEN ./cmd/activate -db data/vic.db.new -version gnaf-aug26+osm-vic-260914
```

The token is a secret — never pass it as a flag (it would leak into shell
history); the tool reads it from `AUGEO_CTRL_TOKEN`. The server also refuses
arbitrary DB paths: the requested file (relative to the server's working
directory, symlinks resolved) must be a regular file inside the directory
holding the boot dataset, and it is opened by that resolved path, read-only.

Activation also requires a passing `cmd/verify` report beside the file
(`<db>.verify.json`, `"ok": true`) whose `sha256` matches the file as it is
now; otherwise it returns 409 and the old dataset keeps serving. The served
`dataset_version` is the file's own `address.dataset_version` (set by
`buildaddr -version`, default `gnaf-YYYY-MM` from the G-NAF release); a
`version` in the request is optional and must match it. The replaced pool is
closed after a drain delay (longer than the server's write timeout).

### Loaders never write a served file

The server holds a shared advisory lock (`flock`) on every dataset it serves;
`buildaddr`, `assertapply`, `loadboundary`, `loadoscdiff` and `oscchain` take
an exclusive one and refuse to start while a server holds the file. Build into
a staging copy (`data/vic.db.new`), run `cmd/verify` on it, then activate it.
Loaders set `busy_timeout`; WAL is deliberately not enabled, since a WAL file
opened `mode=ro` needs write access to its `-shm` file, which the server's
read-only mount does not give it.

`buildaddr`, `assertapply` and `loadboundary` each replace their tables in a
single transaction, so an interrupted run leaves the previous tables intact.

## Licence compliance (D-018)

Code is Apache-2.0. The data (G-NAF, OSM, Geoscape) is separately licensed —
read [ATTRIBUTION.md](ATTRIBUTION.md) before running or redistributing an
instance. OSM-touching responses carry an `attribution` field.
