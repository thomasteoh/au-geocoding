# au-places — presentation forms, rendered as docs

This is the static counterpart of the animation. The animation renders the
motion; these pages render the code. Both derive from `presentations.md` and
must agree with the live server (`POST /search` on :8080).

## Forms

### Intersection (`poi_anchor`, two streets crossing)
- [A AND B ROAD (shared suffix)](intersection.md#a-and-b-road--shared-suffix)
- [A ROAD AND B ROAD (both suffixes)](intersection.md#a-road-and-b-road--both-explicit-suffixes)
- [A AND B (no suffix)](intersection.md#a-and-b--no-suffix-at-all)
- [A ROAD B ROAD (no AND, both suffixes)](intersection.md#a-road-b-road--no-and-both-suffixes)
- [A B ROAD (no AND, shared suffix)](intersection.md#a-b-road--no-and-shared-suffix)
- [CORNER OF A AND B](intersection.md#corner-of-a-and-b--connector-prefix)
- [CNR A AND B](intersection.md#cnr-a-and-b--abbreviation)
- [RD abbreviations](intersection.md#rd-abbreviations)
- [Locality that is ALSO a street](intersection.md#locality-that-is-also-a-street--a-east-and-b-road)

### Locality (`poi_anchor`, locality centroid)
- [Single-word locality](locality.md#single-word-locality)
- [Multi-word locality](locality.md#multi-word-locality)
- [Locality as the anchor, no in/near](locality.md#locality-as-the-anchor-no-in-near)
- [Connector-first — target is the anchor (known limitation)](locality.md#connector-first--target-is-the-anchor)

### Address (rung 2, `looksAddress` gate)
- [Full address](address.md#full-address)
- [Street only, no number](address.md#street-only-no-number)
- [Unit / format number](address.md#unit--format-number)
- [Commercial prefix](address.md#commercial-prefix)

### Coordinate
- [Coordinate string](coord.md)

### Bare POI
- [POI name alone, no anchor](bare-poi.md)

---

## How the docs relate to the live server

Each page's **verified output** was confirmed against `POST /search` on the
running server. The animation's scenes render the same resolution paths; the
docs render the code that implements them.
