---
project: au-geocoding
title: AU Geocoding — public API service
status: active
created: 2026-09-17
updated: 2026-09-17
tags: [geocoding, public-api, go, au-places]
---

# au-geocoding — project scope

The **interpretation** half of the split. Owns the public API surface (auth,
rate limits, quotas, abuse guards), the parse ladder (rungs 1–5), normalisation,
ranking, and the LLM parser. It never touches G-NAF schema or geo data — it calls
[au-places](../au-places/README.md) via the resolution contract.

## What it is NOT

- Not the resolution service. au-places owns the data and the query primitives.
- Not a data loader. au-places builds the dataset; this service only reads it
  through the contract.
- Not a framework app. stdlib-first, no ORM, interfaces only at seams.

## Build order (this repo)

1. Contract client — the Go interface + HTTP client for au-places (split mode),
   shared types with the contract package.
2. Normalisation — case-fold, punctuation, street-type abbreviations, unit/level
   prefixes, state/postcode anchors.
3. Parse ladder — rungs 1–4 deterministic (coord, address, poi_anchor, poi),
   rung 5 LLM (queued, gated on config).
4. Ranking — two-phase: cap candidates in places, score in Go (match_score,
   gnaf_confidence, geocode_reliability, distance-to-anchor).
5. Public API — auth (SHA-256+pepper keys), token-bucket rate limiter, daily
   quotas (D-034 per-row), abuse guards (T1–T7), ErrOutOfScope handling.
6. app.db — service tables (api_keys, usage, request_log) separate from the
   geocoding DBs.
7. HTTP server — endpoints: /search, /geocode, /reverse, /poi, /parse, /batch,
   /healthz, /readyz, /metrics.
8. Frontend — single-input demo, no framework, attribution surface.
9. OpenAPI 3.1 + docs, README, ATTRIBUTION.md, LICENSE, CI/CD.

## Verified facts (carried from the wiki)

- Go 1.26, modernc.org/sqlite v1.58.0 (pure Go, CGO_ENABLED=0, FTS5+RTree+geopoly).
- Two-phase ranking beats ORDER BY rank (D-010): cap in FTS5, score in Go.
- Token-bucket per key (D-006); quota per result row (D-034).
- No query retention (D-015): queries never logged, never metric labels, never
  persisted; caches in-memory only.
- FTS5 MATCH never receives raw user text (T3) — tokenise, whitelist, AND-join.
