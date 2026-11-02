#!/bin/bash
# End-to-end check of the subscription entitlement, against a running `wrangler dev`.
#
#   Terminal 1:  npx wrangler d1 migrations apply mushroom-files --local --persist-to ../.wrangler-dev-state
#                npx wrangler dev --local --persist-to ../.wrangler-dev-state \
#                  --var ACTIVATIONS_PER_HOUR_PER_IP:1000
#   Terminal 2:  ./test-entitlement.sh
#
# Separate from test.sh on purpose: that's also the on-prem conformance suite, run against a
# self-hosted box with entitlement off (cutover 0). This one tests our hosted deployment and
# seeds `entitled_until` directly, the only way to reach a lapsed state without waiting a week.
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
# Every row got NULL from the migration, so this is every existing user. If it ever 401s, the
# release took paid features from people who already bought, which guideline 3.1.2(a) forbids.
seed "NULL"
want "NULL entitled_until is entitled forever" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- a live membership
seed "$((NOW + 86400))"
want "a horizon in the future works" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- a lapsed membership
# 401, not 403: the client maps 401 to `.reactivate`, deleting its token and re-activating, a
# real Gumroad call that either extends the horizon or answers an honest 403. A 403 here would
# strand the Mac.
seed "$((NOW - 1))"
want "a horizon in the past is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/files")"
want "  and every other authed route too" 401 \
  "$(status -X DELETE "${AUTH[@]}" "$BASE/v1/files/whatever")"

# Boundary: the clause is `entitled_until > now`, so "exactly now" is expired, not live.
seed "$NOW"
want "a horizon of exactly now is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# ---------------------------------------------------------------- monotonic horizon
# The upsert's CASE is monotonic both ways. Keep these in step with files-worker/worker.js, one
# check per clause, or deleting a clause from the worker leaves this suite green. Same three
# clauses as messaging-worker/test-entitlement.sh.
UPSERT_CASE="entitled_until = CASE
        WHEN licenses.entitled_until IS NULL THEN NULL
        WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until
        ELSE excluded.entitled_until END"

# First clause: a horizon must never replace a NULL. The safety net under grandfathering, so even
# a build computing the wrong horizon can't demote an existing user.
seed "NULL"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW - 1)))
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
want "a horizon cannot demote a grandfathered row" 200 "$(status "${AUTH[@]}" "$BASE/v1/files")"

# Second clause: a NULL must never wipe a live horizon, or an ordinary config slip becomes
# irreversible: `appStoreEntitlement()` answers NULL whenever ENTITLEMENT_CUTOVER is absent, and
# `wrangler deploy` replaces `vars` wholesale.
seed "$((NOW + 86400))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, NULL)
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -o "$((NOW + 86400))")
[ -n "$GOT" ] && ok "a NULL cannot promote a horizon to permanent" \
              || bad "a NULL cannot promote a horizon to permanent" "horizon was replaced by NULL"

# Third clause: a row that already has a horizon must still move, or a renewal could never
# extend it.
seed "$((NOW + 10))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW + 86400)))
    ON CONFLICT(license_hash) DO UPDATE SET $UPSERT_CASE;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -o "$((NOW + 86400))")
[ -n "$GOT" ] && ok "a renewal can still extend an existing horizon" \
              || bad "a renewal can still extend an existing horizon" "value did not move"

# ---------------------------------------------------------------- activation refusals
# No credential at all still fails: entitlement must not loosen the unauthenticated path.
want "activate with neither credential is still 400" 400 \
  "$(status -X POST -H 'content-type: application/json' --data '{"device_name":"x"}' "$BASE/v1/devices/activate")"
# An entitlement proof isn't a credential, so a subscription alone is still nothing.
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
