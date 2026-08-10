#!/bin/bash
# End-to-end check of the subscription entitlement, against a running `wrangler dev`.
#
#   Terminal 1:  npx wrangler d1 migrations apply mushroom-files --local --persist-to ../.wrangler-dev-state
#                npx wrangler dev --local --persist-to ../.wrangler-dev-state
#   Terminal 2:  ./test-entitlement.sh
#
# Separate from test.sh on purpose: that file is also the on-prem conformance suite and runs
# against a self-hosted box, where entitlement is deliberately switched off (cutover 0). This
# one is about our hosted deployment's behaviour and seeds `entitled_until` directly, which is
# the only way to reach a lapsed state without waiting a week for a real membership to expire.
set -uo pipefail

BASE="${BASE:-http://localhost:8787}"
STATE="${STATE:-../.wrangler-dev-state}"
PASS=0
FAIL=0

d1() { npx wrangler d1 execute mushroom-files --local --persist-to "$STATE" --command "$1"; }
ok()  { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s (%s)\n' "$1" "$2"; }
want() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected $2, got $3"; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "==> entitlement matrix against $BASE"

TOKEN="ent-token-$$"
HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
NOW=$(date +%s)
LIC="entlicensehash$$"
AUTH=(-H "authorization: Bearer $TOKEN")

seed() { # seed <entitled_until SQL literal>
  d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
      VALUES ('$LIC', 'active', $NOW, $NOW, $1);
      INSERT OR REPLACE INTO devices (id, license_hash, token_hash, name, created_at, last_seen_at)
      VALUES ('ent-device-$$', '$LIC', '$HASH', 'test', $NOW, $NOW);" >/dev/null 2>&1
}

# ---------------------------------------------------------------- the grandfathered case
# NULL is what every row got from the migration, so this is what EVERY existing user looks
# like. If this ever 401s, the release has taken paid features away from people who already
# bought, which is the one outcome guideline 3.1.2(a) forbids outright.
seed "NULL"
want "NULL entitled_until is entitled forever" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- a live membership
seed "$((NOW + 86400))"
want "a horizon in the future works" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- a lapsed membership
# 401 and not 403, deliberately: 401 is what the client maps to `.reactivate`, which makes it
# delete its token and re-activate, and re-activation is a real Gumroad call that either
# extends the horizon or answers an honest 403. A 403 here would strand the Mac instead.
seed "$((NOW - 1))"
want "a horizon in the past is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/files")"
want "  and every other authed route too" 401 \
  "$(status -X DELETE "${AUTH[@]}" "$BASE/v1/files/whatever")"

# Boundary: the clause is `entitled_until > now`, so "exactly now" is expired, not live.
seed "$NOW"
want "a horizon of exactly now is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- ONCE FOREVER, ALWAYS FOREVER
# The upsert's CASE is monotonic in BOTH directions. Kept character-for-character in step with
# files-worker/worker.js: this file used to carry the pre-fix TWO-clause version, so the middle
# clause below (a NULL must not wipe a live horizon) had no coverage here at all and deleting it
# from the worker left this suite green. Same three clauses as messaging-worker/test-entitlement.sh.
UPSERT_CASE="entitled_until = CASE
        WHEN licenses.entitled_until IS NULL THEN NULL
        WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until
        ELSE excluded.entitled_until END"

# First clause: a horizon must never replace a NULL. The safety net under grandfathering, so even
# a build that computes the wrong horizon cannot demote an existing user.
seed "NULL"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW - 1)))
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
want "a horizon cannot demote a grandfathered row" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# Second clause: a NULL must never wipe a live horizon either. This is the half that made an
# ordinary config slip irreversible: `appStoreEntitlement()` answers NULL whenever
# ENTITLEMENT_CUTOVER is absent, and `vars` are replaced wholesale on every `wrangler deploy`.
seed "$((NOW + 86400))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, NULL)
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -o "$((NOW + 86400))")
[ -n "$GOT" ] && ok "a NULL cannot promote a horizon to permanent" \
              || bad "a NULL cannot promote a horizon to permanent" "horizon was replaced by NULL"

# Third clause: a row that already HAS a horizon must still be movable, or a renewal could never
# extend one.
seed "$((NOW + 10))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW + 86400)))
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -o "$((NOW + 86400))")
[ -n "$GOT" ] && ok "a renewal can still extend an existing horizon" \
              || bad "a renewal can still extend an existing horizon" "value did not move"

# ---------------------------------------------------------------- activation refusals
# No credential at all still fails the way it always did: entitlement must not have loosened
# anything on the unauthenticated path.
want "activate with neither credential is still 400" 400 \
  "$(status -X POST -H 'content-type: application/json' --data '{"device_name":"x"}' "$BASE/v1/devices/activate")"
# An entitlement proof is NOT a credential, so a subscription on its own is still nothing.
want "a subscription alone is not a credential" 400 \
  "$(status -X POST -H 'content-type: application/json' \
     --data '{"device_name":"x","app_subscription":"a.b.c"}' "$BASE/v1/devices/activate")"
# Oversized redeem key is rejected on shape before any Gumroad round trip.
BIG=$(python3 -c "print('k'*101)")
want "an oversized redeem key is 400" 400 \
  "$(status -X POST -H 'content-type: application/json' \
     --data "{\"device_name\":\"x\",\"app_transaction\":\"a.b.c\",\"redeem_license_key\":\"$BIG\"}" \
     "$BASE/v1/devices/activate")"

d1 "DELETE FROM devices WHERE license_hash = '$LIC'; DELETE FROM licenses WHERE license_hash = '$LIC';" >/dev/null 2>&1

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
