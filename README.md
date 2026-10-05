# au-system

Australian geocoding, split into two services that share one contract.

| Path | Module | What it is |
|------|--------|------------|
| [`geocoding/`](geocoding/README.md) | `augeocoding` | au-geocoder: the public API. Input handling, the parse ladder, ranking, auth, quotas. Owns no geo data. |
| [`places/`](places/README.md) | `auplaces` | au-places: the resolver. Loaders, the G-NAF/OSM datasets, the `/resolve` contract endpoint. |
| [`shared/`](shared/) | `ausystem/shared` | Code both services compile against: `contract`, `normalise`, `streettype`, `slog`, `metrics`. |
| `deploy/` | | Prometheus scrape config for the compose stack. |
| `scripts/` | | CI helpers (`smoke-geocoding.sh`). |

Each service is its own Go module and its own image. `go.work` ties them
together for local development; each service's `go.mod` also carries
`replace ausystem/shared => ../shared` so it builds standalone (`GOWORK=off`),
which is how CI and the Dockerfiles build it.

## Develop

```sh
go build ./shared/... ./geocoding/... ./places/...
(cd geocoding && go test ./...)
(cd places && go test ./...)
```

## Run

```sh
docker compose run --rm loader                     # build the dataset (one-shot)
docker compose run --rm --entrypoint keygen augeo -app-db /data/app.db -label my-key
docker compose up -d places augeo prometheus
```

Images build from the repository root so `shared/` is in the context:
`docker build -f geocoding/Dockerfile .` and `docker build -f places/Dockerfile .`.

## CI and releases

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request: gofmt, build, vet and `go test -race` per module, the INV-1 logging
check, the places corpus-subset smoke, the geocoding contract smoke and both
image builds. It never downloads real data.

Releases are per service. Tag `geocoding/vX.Y.Z` or `places/vX.Y.Z`; the
matching release workflow reruns CI, then publishes a multi-arch image to
`ghcr.io/<repo>/augeo` or `ghcr.io/<repo>/auplaces` with the version tag.

## Data

The repository ships no data. G-NAF, OSM and Geoscape are separately licensed;
see each service's `ATTRIBUTION.md`.
