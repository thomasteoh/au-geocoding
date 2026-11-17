#!/usr/bin/env bash
# End-to-end smoke against a real dataset: builds and boots au-places and augeo,
# then sends places/testdata/golden.tsv through augeo's public /geocode and
# checks each answer, plus /reverse, POI search and an invalid key. Unlike
# smoke-geocoding.sh (mock resolver, CI) this exercises real matching, so it
# needs a dataset with the gnaf_pid index; it is a manual pre-release check.
#
#   scripts/smoke-real.sh /path/to/vic.db
#
# Needs curl, jq and sqlite3. The dataset is opened read-only.
set -uo pipefail
db="${1:?usage: smoke-real.sh /path/to/vic.db}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
places_port="${SMOKE_PLACES_PORT:-18092}"
augeo_port="${SMOKE_AUGEO_PORT:-18099}"
base="http://127.0.0.1:$augeo_port"

for port in "$places_port" "$augeo_port"; do
  if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
    echo "FAIL port $port is already in use (set SMOKE_PLACES_PORT / SMOKE_AUGEO_PORT)"; exit 1
  fi
done

work="$(mktemp -d)"; pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$work"; }
trap cleanup EXIT
export GOWORK=off
(cd "$repo/places" && go build -o "$work/places" ./cmd/server) || exit 1
(cd "$repo/geocoding" && go build -o "$work/augeo" ./cmd/augeo && go build -o "$work/keygen" ./cmd/keygen) || exit 1

export AUGEO_APP_DB="$work/app.db"
key="$("$work/keygen" -app-db "$AUGEO_APP_DB" -label smoke -tier standard | sed -n 's/^key=//p')"
[ -n "$key" ] || { echo "FAIL keygen printed no key"; exit 1; }
(cd "$work" && AUGEO_DB= exec "$work/places" -db "$db" -addr "127.0.0.1:$places_port" >"$work/places.log" 2>&1) & pids+=($!)
"$work/augeo" -addr "127.0.0.1:$augeo_port" -places-url "http://127.0.0.1:$places_port" >"$work/augeo.log" 2>&1 & pids+=($!)

t0=$(date +%s)
for _ in $(seq 1 600); do
  curl -fsS "http://127.0.0.1:$places_port/readyz" 2>/dev/null | grep -q '"ready"' && break; sleep 0.5
done
echo "places ready after $(( $(date +%s) - t0 ))s"
curl -fsS "$base/readyz" >/dev/null || { echo "FAIL augeo not ready"; tail -5 "$work/augeo.log"; exit 1; }

pass=0; fail=0
while IFS=$'\t' read -r q want; do
  case "$q" in ''|\#*) continue;; esac
  start=$(date +%s%N)
  resp=$(curl -sS -X POST -H 'content-type: application/json' -H "X-Api-Key: $key" \
    -d "$(jq -nc --arg q "$q" '{query:$q}')" "$base/geocode")
  ms=$(( ($(date +%s%N) - start) / 1000000 ))
  precision=$(jq -r '.candidates[0].precision // empty' <<<"$resp" 2>/dev/null)
  got="(none)"
  if [ "$precision" = address ]; then
    # Key forms as in golden.tsv: a fifth part names the unit, lot or level row.
    pid=$(jq -r '.candidates[0].gnaf_pid' <<<"$resp")
    row="street_number||'|'||street_name||'|'||ifnull(street_type,'')||'|'||locality_name"
    if [ "$(tr -cd '|' <<<"$want" | wc -c)" -ge 4 ]; then
      row="$row||'|'||CASE WHEN flat_number<>'' THEN 'unit '||flat_number
        WHEN lot_number<>'' AND street_number='' THEN 'lot '||lot_number
        WHEN level_number<>'' THEN 'level '||level_number ELSE '' END"
    fi
    got=$(sqlite3 -readonly "file:$db?mode=ro" "SELECT $row FROM address WHERE gnaf_pid='${pid//\'/}'")
  elif [ -n "$precision" ]; then
    got=$(jq -r '(.candidates[0].postal_delivery // "" | if . == "" then . else . + "@" end) + .candidates[0].id.pid' <<<"$resp")
  fi
  if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok   %5dms  %s\n' "$ms" "$q"
  else fail=$((fail+1)); printf 'FAIL %5dms  %-40s got %s want %s\n' "$ms" "$q" "$got" "$want"; fi
done < "$repo/places/testdata/golden.tsv"
echo "geocode: $pass passed, $fail failed"

post() { curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' "$@"; }
check() { if [ "$2" = "$1" ]; then echo "ok   $3 ($2)"; else echo "FAIL $3: got $2, want $1"; fail=$((fail+1)); fi; }
check 200 "$(post -H "X-Api-Key: $key" -d '{"lat":-37.8136,"lon":144.9631}' "$base/reverse")" "reverse"
check 200 "$(post -H "X-Api-Key: $key" -d '{"query":"woolworths near doncaster"}' "$base/search")" "poi search"
check 401 "$(post -H 'X-Api-Key: not-a-key' -d '{"query":"12 high st"}' "$base/search")" "invalid key"
if grep -qiE '"level":"error"|panic' "$work/places.log" "$work/augeo.log"; then
  echo "FAIL errors logged:"; grep -iE '"level":"error"|panic' "$work/places.log" "$work/augeo.log" | head -5; fail=$((fail+1))
fi
[ "$fail" -eq 0 ]
