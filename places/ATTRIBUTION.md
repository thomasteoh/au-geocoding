# Attribution & data licences

**This repository ships no data.** The dataset is built at load time from
third-party sources. Each source has its own licence; the obligations below are
**operator-facing** — whoever runs an instance is responsible for complying with
them. Code in this repo is Apache-2.0 (see [LICENSE](LICENSE)); the data licences
are separate and are NOT covered by the code licence.

## G-NAF (Geocoded National Address File) — CC BY 4.0 + use restriction

- **Licence:** CC BY 4.0 (data.gov.au tags `isopen: true` for the CC BY 4.0
  release). Published by Geoscape Australia / PSMA.
- **Use restriction:** G-NAF is published under the *"Fact Sheet — Open G-NAF Use
  Restriction"*. Narrowly: the restriction forbids **generating or compiling
  addresses for the sending of mail** without secondary verification. This
  service resolves queries to coordinates/PIDs — it does not generate mailing
  lists — so it is outside that restriction. It **does** constrain any future
  mailing-list output.
- **Attribution:** when G-NAF-derived data is redistributed or served, credit
  Geoscape Australia / PSMA and link the source. Responses carrying a G-NAF
  address (`source: "gnaf"`) should note G-NAF provenance where the consumer may
  redistribute.
- **Source:** data.gov.au G-NAF August 2026 release.

## OSM (OpenStreetMap) — ODbL 1.0

- **Licence:** Open Database Licence (ODbL) 1.0.
- **Attribution:** OSM-derived POIs require attribution on produced works. The
  `/search` responses carrying an OSM POI (`source: "osm"`) include an
  `attribution` field naming OpenStreetMap and the licence. See the OSM licence
  page for the required form (© OpenStreetMap contributors, ODbL).
- **Note:** OSM ids are not durable identifiers — a way is renumbered when someone
  redraws it. Treat an OSM id as a fetch handle, never a key to store
  ([compatibility](../au-system/compatibility.md)).

## Geoscape Administrative Boundaries — CC BY 4.0

- **Licence:** CC BY 4.0, per-state Suburb/Locality Boundaries (data.gov.au,
  44 packages), AUG26 release.
- **Attribution:** credit Geoscape Australia when boundary polygons are
  redistributed or rendered.

## Overture (not currently used)

Overture themes do not share one licence — some are ODbL (OSM-derived), others
CDLA-Permissive. Not taken yet; if adopted, verify the licence for `places`
specifically before shipping ([sources](../au-geocoding/sources.md)).

## Summary

| Source | Licence | Attribution required |
|--------|---------|----------------------|
| G-NAF | CC BY 4.0 + use restriction | credit Geoscape/PSMA; no mailing-list use |
| OSM | ODbL 1.0 | `attribution` field on OSM responses |
| Geoscape boundaries | CC BY 4.0 | credit Geoscape on boundary redistribution |

**The Apache-2.0 code licence does not imply the data is Apache-2.0.** Redistributing
the dataset (or a derived dataset) requires complying with each source's terms,
independently.
