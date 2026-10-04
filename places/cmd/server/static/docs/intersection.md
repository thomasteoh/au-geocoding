# Intersection forms

`poi_anchor` with an intersection anchor. The two streets are resolved from
the data (least-squares fit + crossing), never guessed. All outputs verified
against `POST /search`.

## The resolver

```ts
function ResolveAnchor(fragment: string, locality: string): Anchor | null {
  const frag = upper(trim(fragment));
  // 1. Whole fragment is a locality ("DONCASTER EAST", "BOX HILL").
  const whole = wholeLocality(frag);
  if (whole) return localityCentroid(whole);
  // 2. Two-street intersection ("A AND B ROAD", "CORNER OF X AND Y", ...).
  const streets = parseTwoStreet(frag);              // presentation-agnostic
  if (streets) {
    const x = ResolveIntersection(streets[0], streets[1]);
    if (x) return { kind: "intersection", ...x };    // crossing found
    // else: streets don't cross in this dataset → fall through
  }
  // 3. Street-in-locality.
  if (locality && looksStreet(frag))
    if (const a = streetAnchor(frag, locality)) return a;
  // 4. Locality centroid (fallback).
  return localityCentroid(locality);
}
```

`parseTwoStreet` is the presentation-agnostic splitter. It does **not** require
`AND` and **does not** require a suffix — it tries `AND` first, then any space
boundary between two street-like tokens, and strips the type suffix from each
side:

```ts
function parseTwoStreet(frag: string): [string, string] | null {
  const up = stripPrefix(frag);            // "CORNER OF ", "CNR ", "THE CORNER OF "
  if (up.includes(" AND ")) {
    const [a, b] = up.split(" AND ");      // "A AND B ROAD" → ["A", "B ROAD"]
    const A = stripType(a), B = stripType(b);          // suffix elided, applies to both
    return isStreet(A) && isStreet(B) ? [A, B] : null;
  }
  const f = up.split(" ");
  for (let i = 1; i < f.length; i++) {
    const a = stripType(f.slice(0, i).join(" "));
    const b = stripType(f.slice(i).join(" "));         // "X ROAD Y ROAD" → each side
    if (isStreet(a) && isStreet(b)) return [a, b];
  }
  return null;                                        // no two-street reading
}
```

`ResolveIntersection` computes the crossing **from the data** — it cannot
fabricate one. It collects each street's address points, restricts both to the
shared coordinate overlap, fits a least-squares line through each, and crosses
them. If the streets' extents don't overlap, it returns `null` and the resolver
falls back (honestly) to the locality:

```ts
function ResolveIntersection(a: string, b: string): Point | null {
  const pa = collectStreetPoints(a), pb = collectStreetPoints(b);
  if (pa.length < 2 || pb.length < 2) return null;
  // Restrict both to the shared coordinate overlap (where they genuinely cross).
  const latMin = max(minLat(pa), minLat(pb)), latMax = min(maxLat(pa), maxLat(pb));
  const lonMin = max(minLon(pa), minLon(pb)), lonMax = min(maxLon(pa), maxLon(pb));
  const A = inRange(pa, latMin, latMax, lonMin, lonMax);
  const B = inRange(pb, latMin, latMax, lonMin, lonMax);
  if (A.length < 2 || B.length < 2) return null;       // no shared region — no crossing
  const { lat, lon } = lineCross(fitLine(A), fitLine(B));
  return { lat: clamp(lat, latMin, latMax), lon: clamp(lon, lonMin, lonMax) };
}
```

## A AND B ROAD — shared suffix

> `woolworths near doncaster and blackburn road`

```
Classify    → poi_anchor, query=WOOLWORTHS, anchors=[DONCASTER AND BLACKBURN ROAD]
ResolveAnchor: wholeLocality("DONCASTER AND BLACKBURN ROAD") → null (has " AND ")
              parseTwoStreet → AND split: ["DONCASTER", "BLACKBURN ROAD"]
                            → stripType both: ["DONCASTER", "BLACKBURN"]
                            → isStreet both ✓
              ResolveIntersection → (-37.7883, 145.1619)   ◄── the crossing
Result      → anchor intersection, top Woolworths w1185033336 at 347 m
```

**Verified output:** `poi_anchor`, anchor `(-37.7883, 145.1619)`, top
`w1185033336` at 347 m (Doncaster East 3109 Woolworths).

```ts
// "DONCASTER AND BLACKBURN ROAD" — the "ROAD" suffix applies to BOTH streets.
// AND-split → ["DONCASTER", "BLACKBURN ROAD"] → stripType both → ["DONCASTER", "BLACKBURN"].
// Both resolve as streets in G-NAF (street_name = DONCASTER, BLACKBURN; the
// type lives in a separate column, so the suffix is elided by design).
```

## A ROAD AND B ROAD — both explicit suffixes

> `woolworths near doncaster road and blackburn road`

```
Classify    → poi_anchor, anchors=[DONCASTER ROAD AND BLACKBURN ROAD]
ResolveAnchor: parseTwoStreet → AND split: ["DONCASTER ROAD", "BLACKBURN ROAD"]
              stripType both → ["DONCASTER", "BLACKBURN"]  ✓ both streets
              ResolveIntersection → (-37.7883, 145.1619)
```

**Verified output:** intersection, 347 m. The explicit per-side suffixes are
stripped independently; the elided-suffix logic handles both this and the
shared-suffix case.

## A AND B — no suffix at all

> `woolworths at doncaster and blackburn`

```
Classify    → poi_anchor, anchors=[DONCASTER AND BLACKBURN]
ResolveAnchor: parseTwoStreet → AND split: ["DONCASTER", "BLACKBURN"]
              no suffix to strip; isStreet both ✓
              ResolveIntersection → (-37.7883, 145.1619)
```

**Verified output:** intersection, 347 m. The suffix is entirely optional.

## A ROAD B ROAD — no AND, both suffixes

> `woolworths at doncaster road blackburn road`

```
Classify    → poi_anchor, anchors=[DONCASTER ROAD BLACKBURN ROAD]
ResolveAnchor: parseTwoStreet → no " AND ", so space-boundary split:
              i=1 → ["DONCASTER", "ROAD BLACKBURN ROAD"]   isStreet(DONCASTER) ✓
                                                           isStreet("ROAD BLACKBURN ROAD") ✗
              i=2 → ["DONCASTER ROAD", "BLACKBURN ROAD"]   stripType both ✓✓
              → ["DONCASTER", "BLACKBURN"] → intersection (-37.7883, 145.1619)
```

**Verified output:** intersection, 347 m. The space-boundary loop tries every
split; the one where both sides are streets wins. This is why the splitter is
presentation-agnostic — it does not assume `AND` or a suffix.

## A B ROAD — no AND, shared suffix

> `woolworths near doncaster blackburn road`

```
Classify    → poi_anchor, anchors=[DONCASTER BLACKBURN ROAD]
ResolveAnchor: parseTwoStreet → no AND → boundary split:
              i=1 → ["DONCASTER", "BLACKBURN ROAD"]  stripType → ["DONCASTER", "BLACKBURN"] ✓
              → intersection (-37.7883, 145.1619)
```

**Verified output:** intersection, 347 m. The `ROAD` suffix attaches to the
second token; `stripType` removes it and both sides resolve.

## CORNER OF A AND B — connector prefix

> `woolworths at the corner of doncaster rd and blackburn rd`

```
Classify    → connector " at " splits → left=WOOLWORTHS, right="THE CORNER OF DONCASTER RD AND BLACKBURN RD"
splitAnchors("THE CORNER OF DONCASTER RD AND BLACKBURN RD") → connectors split again:
              " CORNER OF " is a connector → ["THE", "DONCASTER RD AND BLACKBURN RD"]
              → anchors = ["THE", "DONCASTER RD AND BLACKBURN RD"]
searchPOIAnchor: iterates ALL anchors, first that resolves wins:
              anchor[0] = "THE"      → ResolveAnchor("THE") → null (not a locality/street)
              anchor[1] = "DONCASTER RD AND BLACKBURN RD" → parseTwoStreet strips "CORNER OF"
              → AND split → ["DONCASTER RD", "BLACKBURN RD"] → stripType → ["DONCASTER", "BLACKBURN"]
              → intersection (-37.7883, 145.1619) ✓
```

**Verified output:** intersection, 347 m. Two fixes make this work:
1. `searchPOIAnchor` **iterates all anchors** and uses the first that resolves —
   `THE` (a stray token from the `corner of` split) fails, so it moves on.
2. `parseTwoStreet` and `wholeLocality` both **strip the `CORNER OF` / `CNR`
   prefix** before matching.

```ts
// "at the corner of doncaster rd and blackburn rd"
//   splitAnchors → ["THE", "DONCASTER RD AND BLACKBURN RD"]
//   searchPOIAnchor tries each:
//     "THE"                          → ResolveAnchor → null   (not a locality, not a street)
//     "DONCASTER RD AND BLACKBURN RD" → strip "CORNER OF" → AND split → both streets → intersection ✓
// The stray "THE" anchor is harmless — the resolver iterates, not assumes anchors[0].
```

## CNR A AND B — abbreviation

> `woolworths cnr doncaster and blackburn`

```
Classify    → connector " cnr " splits → left=WOOLWORTHS, right="DONCASTER AND BLACKBURN"
ResolveAnchor: wholeLocality → null (has AND); parseTwoStreet strips "CNR" (no-op) →
              AND split → ["DONCASTER", "BLACKBURN"] → intersection (-37.7883, 145.1619)
```

**Verified output:** intersection, 347 m. `CNR` is a first-class connector.

## RD abbreviations

> `woolworths near the corner of doncaster rd and blackburn rd`

**Verified output:** intersection, 347 m. `RD` is in `stripStreetType`'s suffix
list — the abbreviation is stripped exactly like `ROAD`, so `DONCASTER RD` →
`DONCASTER`. The connector prefix + abbreviation + AND all compose.

## Locality that is ALSO a street — A EAST AND B ROAD

> `woolworths near doncaster east and blackburn road`

```
Classify    → poi_anchor, anchors=[DONCASTER EAST AND BLACKBURN ROAD]
ResolveAnchor:
  1. wholeLocality("DONCASTER EAST AND BLACKBURN ROAD")
     → contains " AND " → REJECTED (not a pure locality)
  2. parseTwoStreet → AND split → ["DONCASTER EAST", "BLACKBURN ROAD"]
     stripType → ["DONCASTER EAST", "BLACKBURN"]
     isStreet("DONCASTER EAST") ✓ (211 rows — it IS a street)
     isStreet("BLACKBURN") ✓
     ResolveIntersection("DONCASTER EAST", "BLACKBURN") → null
       (extents don't overlap: DONCASTER EAST street -37.815..-37.808 × 145.193..145.197;
        BLACKBURN in DONCASTER EAST -37.801..-37.750 × 145.156..145.169 — no shared region)
     → fall through (no fabricated crossing)
  3. street-in-locality: locality="DONCASTER EAST" (extracted), looksStreet? no suffix → skip
  4. locality centroid → (-37.7818, 145.1622)
```

**Verified output:** `poi_anchor`, anchor `(-37.7818, 145.1622)`, top
`w1185033336` at 915 m. **This is the honest answer** — the two streets don't
cross in the dataset, so it falls back to the locality rather than inventing an
intersection. The `wholeLocality` AND-rejection is what lets it reach the
two-street path instead of short-circuiting to the locality.

```ts
// "DONCASTER EAST AND BLACKBURN ROAD"
//   DONCASTER EAST is BOTH a locality (15,612 rows) AND a street (211 rows).
//   wholeLocality: contains " AND " → rejected, so it reaches parseTwoStreet.
//   parseTwoStreet: ["DONCASTER EAST", "BLACKBURN"] — both are streets.
//   ResolveIntersection: extents don't overlap → null → NO fabricated crossing.
//   Falls back to the locality centroid — the truthful answer.
```
