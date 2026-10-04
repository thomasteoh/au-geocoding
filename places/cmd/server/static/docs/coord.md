# Coordinate form

`coord` — a bare coordinate string. The query is a coordinate pair, not a
place name. Verified against `POST /search`.

## The form

> `-37.7883, 145.1619` → `coord`, anchor at the coordinate, nearest POI.

```
Classify    → coord: the whole query is a coordinate pair (lat, lon)
              → resolve the coordinate as the anchor directly
              → rank POIs by distance from that point
```

## The gate

```ts
// A coordinate pair is recognised by its shape — two numbers, one negative.
function looksCoord(frag: string): boolean {
  const f = upper(trim(frag)).split(",");
  if (f.length !== 2) return false;
  const lat = parseFloat(f[0]), lon = parseFloat(f[1]);
  return Number.isFinite(lat) && Number.isFinite(lon) &&
         Math.abs(lat) <= 90 && Math.abs(lon) <= 180;
}
```

## Notes

- The coordinate is used **as given** — no locality scoping, no street
  resolution. It's the most specific anchor possible.
- The `coord` rung is the **cheapest** in the ladder — it fires first.
- Verified output: anchor at `(-37.7883, 145.1619)`, nearest POI ranked by
  distance.
