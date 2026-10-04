# Address forms

The address rung (rung 2) fires when the left fragment looks like an address.
`looksAddress` has **four independent signals** (any one fires). All outputs
verified against `POST /search`.

## The address gate

```ts
// The address gate — any ONE signal fires.
function looksAddress(frag: string): boolean {
  const up = upper(frag);
  if (/\b(VIC|NSW|QLD|SA|WA|TAS|NT|ACT)\b/.test(up)) return true;      // 1. state
  const f = up.split(" ");
  if (startsNumeric(f[0]) && f.slice(1).some(w => w.length > 1 && !startsNumeric(w)))
    return true;                                                       // 2. digit-led + word
  if (PREFIX.has(f[0]) && startsNumeric(f[1])) return true;           // 3. commercial prefix
  for (let i = 0; i < f.length; i++)
    if (STREET_SUFFIX.has(f[i])) return i > 0 && i + 1 < f.length;     // 4. street + locality
  return false;
}
```

`startsNumeric` accepts **any digit-led token** — not just pure digits. This is
what makes unit/format numbers work:

```ts
function startsNumeric(s: string): boolean {
  if (!s) return false;
  for (const c of s) {
    if (c >= "0" && c <= "9") return true;   // "12", "12/45", "12-45", "12A"
    if (!"/-ABCDEFGH".includes(c)) return false;  // a non-numeric char kills it
  }
  return s[0] >= "0" && s[0] <= "9";
}
```

## Full address

> `12 collins st melbourne vic 3000` → `GAVIC423448192`. **Verified.**

```
Classify    → address rung: left = "12 collins st melbourne vic 3000"
looksAddress: state signal (VIC) → true
              → resolve to GAVIC423448192 (full address)
```

## Street only, no number

> `collins st melbourne` → `GAVIC721916550`. **Verified.**

```
Classify    → address rung: left = "collins st melbourne"
looksAddress: street-suffix (ST) followed by a token (MELBOURNE) → true
              → resolve to GAVIC721916550 (street anchor, no number)
```

## Unit / format number

> `12/45 collins st melbourne` → `GAVIC423448192`. **Verified.**

```
Classify    → address rung: left = "12/45 collins st melbourne"
looksAddress: digit-led token (12/45) followed by a word → true
              → resolve to GAVIC423448192 (unit/format number, same building)
```

## Commercial prefix

> `shop 12 collins st melbourne` → `GAVIC720522072`. **Verified.**

```
Classify    → address rung: left = "shop 12 collins st melbourne"
looksAddress: commercial prefix (SHOP) + digit (12) → true
              → resolve to GAVIC720522072 (shop entry)
```

## Notes on the gate

- The four signals are **independent** — any one fires. A full address (state +
  number + street) fires on the state signal; a street-only fires on the
  suffix; a unit/format fires on the digit-led token; a shop fires on the
  commercial prefix.
- `startsNumeric` deliberately accepts `12/45`, `12-45`, `12A` — unit and
  format numbers are digit-led, not pure digits.
