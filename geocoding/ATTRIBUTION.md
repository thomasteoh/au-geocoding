# Attribution & data licences

**This repository ships no data and never loads it.** The geocoder reads
geocoding results through the `/resolve` contract from au-places, which owns
the dataset and its licences. Code in this repo is Apache-2.0 (see
[LICENSE](LICENSE)); the data licences are separate and are NOT covered by the
code licence.

Because the geocoder serves results derived from third-party data, the
**operator-facing** attribution obligations below still apply — whoever runs an
instance is responsible for complying with them, even though the data itself is
never in this repo.

## G-NAF (Geocoded National Address File) — CC BY 4.0 + use restriction

- **Licence:** CC BY 4.0 (data.gov.au `isopen: true` release). Published by
  Geoscape Australia / PSMA.
- **Use restriction:** G-NAF is published under the *"Fact Sheet — Open G-NAF
  Use Restriction"*. Narrowly: it forbids **generating or compiling addresses
  for the sending of mail** without secondary verification. This service
  resolves queries to coordinates/PIDs — it does not generate mailing lists —
  so it is outside that restriction. It **does** constrain any future
  mailing-list output.
- **Attribution:** when G-NAF-derived data is redistributed or served, credit
  Geoscape Australia / PSMA and link the source. Responses carrying a G-NAF
  address (`source: "gnaf"`) should note G-NAF provenance where the consumer may
  redistribute.

## OSM (OpenStreetMap) — ODbL 1.0

- **Licence:** Open Database Licence (ODbL) 1.0.
- **Attribution:** OSM-derived POIs require attribution on produced works. The
  geocoder's responses carrying an OSM POI (`source: "osm"`) include an
  `attribution` field naming OpenStreetMap and the licence. See the OSM licence
  page for the required form (© OpenStreetMap contributors, ODbL).
- **Note:** OSM ids are not durable identifiers — a way is renumbered when
  someone redraws it. Treat an OSM id as a fetch handle, never a key to store.

## Geoscape Administrative Boundaries — CC BY 4.0

- **Licence:** CC BY 4.0, per-state Suburb/Locality Boundaries (data.gov.au,
  44 packages), AUG26 release.
- **Attribution:** credit Geoscape Australia when boundary polygons are
  redistributed or rendered.

## Summary

| Source | Licence | Attribution required |
|--------|---------|----------------------|
| G-NAF | CC BY 4.0 + use restriction | credit Geoscape/PSMA; no mailing-list use |
| OSM | ODbL 1.0 | `attribution` field on OSM responses |
| Geoscape boundaries | CC BY 4.0 | credit Geoscape on boundary redistribution |

**The Apache-2.0 code licence does not imply the data is Apache-2.0.** The data
is loaded and served by [au-places](../au-places/README.md); this service only
carries the attribution through the contract. Read au-places'
[ATTRIBUTION.md](../au-places/ATTRIBUTION.md) for the data-side obligations.
