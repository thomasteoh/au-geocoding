# Locality forms

`poi_anchor` with a locality centroid. The locality is matched as a whole
fragment, never a prefix. All outputs verified against `POST /search`.

## The whole-fragment rule

```ts
function wholeLocality(frag: string): string | null {
  const clean = stripPrefix(frag);
  if (clean.includes(" AND ")) return null;            // a second street — not pure
  if (stripType(clean) !== clean) return null;         // trailing street suffix — not pure
  return isKnownLocality(clean) ? clean : null;        // WHOLE fragment, exact match
}
```

## Single-word locality

> `woolworths in box hill` → locality `BOX HILL` (-37.8195, 145.1231), top
> `n4578704404` at 157 m. **Verified.**

```
Classify    → poi_anchor, anchors=[BOX HILL]
ResolveAnchor: wholeLocality("BOX HILL") → BOX HILL is a known locality (exact match)
              → locality centroid (-37.8195, 145.1231)
```

## Multi-word locality

> `woolworths in doncaster east` → locality `DONCASTER EAST` (-37.7818,
> 145.1622), top `w1185033336` at 915 m. **Verified.**

```
Classify    → poi_anchor, anchors=[DONCASTER EAST]
ResolveAnchor: wholeLocality("DONCASTER EAST") → exact-match locality (no AND, no suffix)
              → locality centroid (-37.7818, 145.1622)
extractLocality("DONCASTER EAST") → longest-prefix match → "DONCASTER EAST", not "DONCASTER"
```

Two fixes are load-bearing here:
1. **`wholeLocality` requires the ENTIRE fragment** to be a locality. A
   leading-prefix match (`DONCASTER` inside `DONCASTER EAST`) must NOT qualify
   — otherwise `DONCASTER AND BLACKBURN ROAD` would short-circuit to the
   DONCASTER locality and never reach the intersection path.
2. **`extractLocality` matches the LONGEST prefix** — it tries 4 tokens down to
   1, so `DONCASTER EAST` (2 tokens) wins over `DONCASTER` (1 token). Greedy
   first-match returned the wrong locality.

```ts
// Multi-word localities must not be mis-split.
// "DONCASTER EAST" → wholeLocality exact-match → locality centroid.
// Without the whole-fragment requirement, "DONCASTER" (a prefix) would match
// and the two-street path would never run.
```

## Locality as the anchor, no in/near

> `woolworths near doncaster` → locality `DONCASTER` (-37.7855, 145.1243), top
> `n465186446` at 223 m. **Verified.**

```
Classify    → connector " near " → left=WOOLWORTHS, right=DONCASTER → anchors=[DONCASTER]
ResolveAnchor: wholeLocality("DONCASTER") → exact-match locality → centroid (-37.7855, 145.1243)
```

`DONCASTER` is a locality here (15,158 rows) — the whole fragment is a locality
so step 1 fires. **This is the correct reading** when only one place-name is
given: it's a locality, not an intersection (there's no second street).

## Connector-first — target is the anchor

> `near doncaster and blackburn road` → `poi`, no anchor, 0 results. **Verified.**

```
Classify    → connector " near " is first → left = "" (empty)
              → return { poi_anchor, query: anchors[0]="DONCASTER", anchors: ["AND BLACKBURN ROAD"] }
              → query "DONCASTER" (a locality, not a POI) → POI lookup finds nothing → 0
```

**This is a known limitation, not a bug.** Connector-first input (`near <X>`
with nothing before the connector) treats the first anchor as the POI target.
For `near doncaster and blackburn road` the target is a locality, not a named
POI, so it returns 0. The design intent is `POI near anchor`; connector-first
`near anchor` alone is out of the demo scope. Spec'd here so the rendered docs
state it explicitly rather than implying it works.
