# Bare POI form

`poi` — a POI name alone, no anchor. Verified against `POST /search`.

## The form

> `woolworths` → `poi`, no anchor, all Woolworths ranked.

```
Classify    → poi: the whole query is a POI name, no anchor
              → POI lookup across the whole dataset (no anchor restriction)
              → rank by confidence/reliability, not distance
```

## Notes

- The **bare-POI** rung fires when nothing looks like an anchor (no locality,
  no address, no coordinate, no street).
- With no anchor, the trigram match is **capped** (a set cap applies — the
  full set would be unbounded). The cap is lifted only when an anchor
  restricts the search (the `poi_anchor` path).
- Ranking is by **confidence/reliability**, not distance — there's no anchor
  to measure distance from.
- This is the **fallback rung** — cheapest to reason about, least specific.

## The cap-after-order rule (INV-6)

Even when the set is capped, the cap applies **after** ordering, and
`truncated` + `total_matched` are always reported:

```ts
function LookupPOI(query: string, anchor?: Anchor): Candidate[] {
  const set = anchor ? matchByAnchor(query, anchor)   // anchored: no cap
                     : matchByTrigram(query);         // bare: capped
  const ordered = order(set);                          // lexical + distance + confidence
  return ordered.slice(0, CAP);                        // cap AFTER ordering
  // truncated = ordered.length > CAP, total_matched = ordered.length
}
```

The top candidate is trustworthy because ranking happens over the full,
ordered set — never a truncated one.
