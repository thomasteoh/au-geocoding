#!/usr/bin/env bash
# Contract smoke: boots the mock resolver and augeo, then exercises the public
# API end to end (anonymous search, keyed search, uniform 401). Run from the
# geocoding/ directory. Fixture-only — never touches real data (R9.2).
set -euo pipefail

# Ports are overridable so the smoke can run beside live services.
places_port="${SMOKE_PLACES_PORT:-18092}"
augeo_port="${SMOKE_AUGEO_PORT:-18099}"
base="http://127.0.0.1:$augeo_port"

work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$work/mockplaces" ./cmd/mockplaces
go build -o "$work/augeo" ./cmd/augeo
go build -o "$work/keygen" ./cmd/keygen

export AUGEO_APP_DB="$work/app.db"
key="$("$work/keygen" -app-db "$AUGEO_APP_DB" -label smoke -tier standard | sed -n 's/^key=//p')"

"$work/mockplaces" -addr "127.0.0.1:$places_port" & pids+=($!)
"$work/augeo" -addr "127.0.0.1:$augeo_port" -places-url "http://127.0.0.1:$places_port" & pids+=($!)

for _ in $(seq 1 50); do
  curl -fsS $base/readyz >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS $base/readyz; echo

post() { curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' "$@"; }
expect() {
  local want="$1" got="$2" what="$3"
  if [ "$got" != "$want" ]; then echo "FAIL $what: got $got, want $want"; exit 1; fi
  echo "ok   $what ($got)"
}

expect 200 "$(post -d '{"query":"12 high st"}' $base/search)" "anonymous search"
expect 200 "$(post -H "X-Api-Key: $key" -d '{"query":"woolworths near doncaster"}' $base/search)" "keyed search"
expect 401 "$(post -H 'X-Api-Key: not-a-key' -d '{"query":"12 high st"}' $base/search)" "invalid key"
