#!/bin/bash
# End-to-end check of the subscription entitlement, against a running `wrangler dev`.
#
#   Terminal 1:  npx wrangler d1 migrations apply mushroom-messaging --local --persist-to ../.wrangler-dev-state-msg
#                npx wrangler dev --port 8788 --persist-to ../.wrangler-dev-state-msg \
#                  --var ACTIVATIONS_PER_HOUR_PER_IP:1000
#   Terminal 2:  ./test-entitlement.sh
#
# The sibling of files-worker/test-entitlement.sh, and it exists for one assertion that worker
# cannot make. Every HTTP route re-reads `entitled_until` on each request, so a curl matrix here
# would only repeat what the files-worker suite already proves. A WebSocket does not: it is
# authenticated ONCE at the upgrade and is hibernation-backed, so it outlives the process that
# checked it. `UserInbox.stillAuthorized` is the only thing that can notice a horizon passing
# underneath a live connection, and without it a lapsed subscriber who simply never quit the app
# kept messages, acks, typing and presence flowing indefinitely while every curl below correctly
# 401'd. That is exactly the shape of bug a green HTTP suite hides, which is why the socket half
# is the last and most important section of this file.
#
# Separate from test.sh on purpose: that file is also the on-prem conformance suite and runs
# against a self-hosted box, where entitlement is deliberately switched off (cutover 0). This one
# is about our hosted deployment's behaviour and seeds `entitled_until` directly, which is the
# only way to reach a lapsed state without waiting a week for a real membership to expire.
#
# Same logging rule as the Worker: ids and status codes, never a token.
set -uo pipefail

BASE="${BASE:-http://localhost:8788}"
STATE="${STATE:-../.wrangler-dev-state-msg}"
DB="mushroom-messaging"
PASS=0
FAIL=0

d1() { npx wrangler d1 execute "$DB" --local --persist-to "$STATE" --command "$1"; }
ok()  { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s (%s)\n' "$1" "$2"; }
want() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected $2, got $3"; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
sha() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

echo "==> entitlement matrix against $BASE"

TOKEN="ent-token-$$"
HASH=$(sha "$TOKEN")
NOW=$(date +%s)
LIC="entlicensehash$$"
KEY="RU5UX18zMl9ieXRlX3B1YmxpY19rZXlfX19fX18B"
IDENT=$(sha "$KEY")
AUTH=(-H "authorization: Bearer $TOKEN")

# A SECOND device, for the lapse test alone, and it is not tidiness. `stillAuthorized` records
# `checked:<device>` and then trusts it for SOCKET_RECHECK_SECONDS (300), so the control run's
# ping stamps the device and a lapse run moments later on the SAME device short-circuits before
# it ever reads the row: the socket answers normally and the suite reports the bug it exists to
# catch. Two devices on the one licence, which is also just an ordinary two-Mac member.
TOKEN2="ent-token2-$$"
HASH2=$(sha "$TOKEN2")

seed() { # seed <entitled_until SQL literal>
  d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
      VALUES ('$LIC', 'active', $NOW, $NOW, $1);
      INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at)
      VALUES ('$IDENT', '$KEY', '$LIC', $NOW);
      INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at)
      VALUES ('ent-device-$$', '$IDENT', '$LIC', '$HASH', 'test', $NOW, $NOW),
             ('ent-device2-$$', '$IDENT', '$LIC', '$HASH2', 'test2', $NOW, $NOW);" >/dev/null 2>&1
}

# ---------------------------------------------------------------- the grandfathered case
# NULL is what every row got from the migration, so this is what EVERY existing user looks
# like. If this ever 401s, the release has taken paid features away from people who already
# bought, which is the one outcome guideline 3.1.2(a) forbids outright.
seed "NULL"
want "NULL entitled_until is entitled forever" 200 "$(status "${AUTH[@]}" "$BASE/v1/friends")"

# ---------------------------------------------------------------- a live membership
seed "$((NOW + 86400))"
want "a horizon in the future works" 200 "$(status "${AUTH[@]}" "$BASE/v1/friends")"

# ---------------------------------------------------------------- a lapsed membership
# 401 and not 403, deliberately: 401 is what the client maps to `.reactivate`, which makes it
# delete its token and re-activate, and re-activation is a real Gumroad call that either
# extends the horizon or answers an honest 403. A 403 here would strand the Mac instead.
seed "$((NOW - 1))"
want "a horizon in the past is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/friends")"
want "  and the sync route too" 401 "$(status "${AUTH[@]}" "$BASE/v1/sync?after=0")"
want "  and posting an invite too" 401 \
  "$(status -X POST "${AUTH[@]}" "$BASE/v1/invites")"

# Boundary: the clause is `entitled_until > now`, so "exactly now" is expired, not live.
seed "$NOW"
want "a horizon of exactly now is refused" 401 "$(status "${AUTH[@]}" "$BASE/v1/friends")"

# ---------------------------------------------------------------- ONCE FOREVER, ALWAYS FOREVER
# The upsert's CASE must never replace a NULL with a horizon. This is the safety net under
# grandfathering: even a build that computes the wrong horizon cannot demote an existing user.
seed "NULL"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW - 1)))
    ON CONFLICT(license_hash) DO UPDATE SET
      entitled_until = CASE
        WHEN licenses.entitled_until IS NULL THEN NULL
        WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until
        ELSE excluded.entitled_until END;" >/dev/null 2>&1
want "a horizon cannot demote a grandfathered row" 200 "$(status "${AUTH[@]}" "$BASE/v1/friends")"

# ...and the other direction, which is the newer half of the CASE. A NULL arriving from a
# misconfigured deploy (ENTITLEMENT_CUTOVER absent, 0 or unparseable) must not promote a paying
# subscriber to permanent, because the clause above would then lock them there forever with
# hand-written production SQL as the only way back.
seed "$((NOW + 10))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, NULL)
    ON CONFLICT(license_hash) DO UPDATE SET
      entitled_until = CASE
        WHEN licenses.entitled_until IS NULL THEN NULL
        WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until
        ELSE excluded.entitled_until END;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -c "$((NOW + 10))")
[ "$GOT" -ge 1 ] && ok "a NULL cannot promote a horizon to permanent" \
                 || bad "a NULL cannot promote a horizon to permanent" "the horizon was erased"

# ...but a row that already HAS a horizon must still be movable, or a renewal could never
# extend one.
seed "$((NOW + 10))"
d1 "INSERT INTO licenses (license_hash, status, checked_at, created_at, entitled_until)
    VALUES ('$LIC', 'active', $NOW, $NOW, $((NOW + 86400)))
    ON CONFLICT(license_hash) DO UPDATE SET
      entitled_until = CASE
        WHEN licenses.entitled_until IS NULL THEN NULL
        WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until
        ELSE excluded.entitled_until END;" >/dev/null 2>&1
GOT=$(d1 "SELECT entitled_until FROM licenses WHERE license_hash = '$LIC'" 2>/dev/null | grep -c "$((NOW + 86400))")
[ "$GOT" -ge 1 ] && ok "a renewal can still extend an existing horizon" \
                 || bad "a renewal can still extend an existing horizon" "value did not move"

# ---------------------------------------------------------------- activation refusals
# No credential at all still fails the way it always did: entitlement must not have loosened
# anything on the unauthenticated path.
want "activate with neither credential is still 400" 400 \
  "$(status -X POST -H 'content-type: application/json' \
     --data "{\"device_name\":\"x\",\"public_key\":\"$KEY\"}" "$BASE/v1/devices/activate")"
# An entitlement proof is NOT a credential, so a subscription on its own is still nothing.
want "a subscription alone is not a credential" 400 \
  "$(status -X POST -H 'content-type: application/json' \
     --data "{\"device_name\":\"x\",\"public_key\":\"$KEY\",\"app_subscription\":\"a.b.c\"}" \
     "$BASE/v1/devices/activate")"
# Oversized redeem key is rejected on shape before any Gumroad round trip.
BIG=$(python3 -c "print('k'*101)")
want "an oversized redeem key is 400" 400 \
  "$(status -X POST -H 'content-type: application/json' \
     --data "{\"device_name\":\"x\",\"public_key\":\"$KEY\",\"app_transaction\":\"a.b.c\",\"redeem_license_key\":\"$BIG\"}" \
     "$BASE/v1/devices/activate")"

# ---------------------------------------------------------------- the socket, the whole point
# Everything above is an HTTP route re-reading the row on every request. The socket is the one
# place that does not, and it is where messages, acks, typing and presence actually flow.
#
# The control first, or a "lapses" pass could mean nothing more than a broken server.
seed "NULL"
BASE="$BASE" node entitlement-socket.mjs "$TOKEN" alive
[ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

# A horizon a few seconds out, so it passes while the socket sits there already authenticated.
# `stillAuthorized` runs on the first frame after that, which is the frame the script sends.
#
# EVERY guarded frame, not just ping. The guard covered ping alone until this change, which is
# how a lapsed subscriber kept sending and acking for as long as the app stayed open, and a probe
# that only pings cannot tell that case from a fixed one. One fresh horizon per frame, because
# the first refused frame closes the socket.
for FRAME in ping typing ack send; do
  seed "$(( $(date +%s) + 3 ))"
  # A device of its OWN per frame, and for exactly the reason TOKEN2 exists at all. The stamp is
  # keyed on the DEVICE, so one device shared across the four runs meant the ping run recorded
  # `checked:ent-device2` and the three after it short-circuited before ever reading the row: they
  # answered normally and the suite reported three failures against a worker that was correct.
  # Separating the control from the lapse runs was only half the fix; the lapse runs also have to
  # be separated from each other.
  FTOKEN="ent-token2-$FRAME-$$"
  d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at)
      VALUES ('ent-device2-$FRAME-$$', '$IDENT', '$LIC', '$(sha "$FTOKEN")', 'test2', $NOW, $NOW);" >/dev/null 2>&1
  BASE="$BASE" node entitlement-socket.mjs "$FTOKEN" lapses "$FRAME"
  [ $? -eq 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
done

d1 "DELETE FROM devices WHERE license_hash = '$LIC';
    DELETE FROM identities WHERE license_hash = '$LIC';
    DELETE FROM licenses WHERE license_hash = '$LIC';" >/dev/null 2>&1

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
