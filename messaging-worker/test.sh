#!/bin/bash
# Smoke matrix for mushroom-messaging against a local `wrangler dev`.
#
#   npx wrangler dev --port 8788 --persist-to ../.wrangler-dev-state \
#     --var ACTIVATIONS_PER_HOUR_PER_IP:1000
#   ./test.sh
#
# The --var is not optional. Every assertion about the activation branch is a POST to
# /v1/devices/activate, there are now more than a dozen of them, and the real budget is 10 an
# hour per IP. Without it the suite spends the budget on itself and everything after it fails
# as rate_limited, which --persist-to then carries into the next run too. Nothing sets that
# var in production.
#
# Runs with NO credentials: it seeds a license and two devices straight into local D1, so
# everything past the activation phase is identical whether or not Gumroad is reachable.
# Set MUSHROOM_TEST_LICENSE to also exercise the real activation path.
#
# Same logging rule as the Worker: this script prints ids and status codes, never a token.
set -uo pipefail

BASE="${BASE:-http://localhost:8788}"
STATE="${STATE:-../.wrangler-dev-state}"
DB="mushroom-messaging"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s%s\n' "$1" "${2:+ — $2}"; }
want() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected $2, got $3"; fi
}

status() { curl -s -o "$BODY" -w '%{http_code}' "$@"; }
code()   { python3 -c 'import json,sys; print(json.load(sys.stdin).get("code",""))' < "$BODY" 2>/dev/null; }
field()  { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))" < "$BODY" 2>/dev/null; }

# Database access, with two backends, because this suite is also the on-prem conformance suite.
#
#   ADMIN_SOCK unset -> `wrangler dev`, the hosted reference environment.
#   ADMIN_SOCK set   -> a self-hosted workerd box (see selfhost/), which has no wrangler and no
#                       account to reach. Same SQL, posted to the unix-socket admin route.
#
# Deliberately the ONLY difference between the two runs. Every assertion below is shared, so a
# behaviour that differs between hosted and on-prem shows up as a diff in the pass list rather
# than as a second suite nobody keeps up to date.
ADMIN_SOCK="${ADMIN_SOCK:-}"

selfhost_sql() {
  python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1], "params": []}))' "$1" |
    curl -s --unix-socket "$ADMIN_SOCK" -X POST http://local/_selfhost/sql \
         -H 'content-type: application/json' --data-binary @-
}

d1() {
  if [ -n "$ADMIN_SOCK" ]; then selfhost_sql "$1" >/dev/null 2>&1
  else npx wrangler d1 execute "$DB" --local --persist-to "$STATE" --command "$1" >/dev/null 2>&1; fi
}

# Rows back as a JSON array, for the few assertions that read the database rather than write it.
d1_json() {
  if [ -n "$ADMIN_SOCK" ]; then
    selfhost_sql "$1" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["results"]))'
  else
    npx wrangler d1 execute "$DB" --local --persist-to "$STATE" --command "$1" --json 2>/dev/null |
      python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]["results"]))'
  fi
}

sha() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

# ---------------------------------------------------------------- preflight

if ! curl -sf -o /dev/null "$BASE/" --max-time 5 --max-redirs 0 -w '' 2>/dev/null; then
  if [ "$(status "$BASE/")" = "000" ]; then
    echo "No server at $BASE. Start it with:"
    echo "  npx wrangler dev --port 8788 --persist-to $STATE"
    exit 1
  fi
fi

# Is there a schema? A database with no tables answers 500 to roughly twenty assertions below
# and says nothing about why, which is exactly what a deleted state directory looks like.
# `licenses` comes from the first migration, so its absence means none of them have run.
if ! d1_json "SELECT 1 FROM licenses LIMIT 1" >/dev/null 2>&1; then
  echo "The local database has no tables. Apply the migrations first:"
  if [ -n "$ADMIN_SOCK" ]; then
    echo "  (a self-hosted box applies them itself on first request; is workerd running?)"
  else
    echo "  npx wrangler d1 migrations apply $DB --local --persist-to $STATE"
  fi
  exit 1
fi

echo
echo "unauthenticated"
want "root redirects to the website"        "302" "$(status -o /dev/null "$BASE/")"
want "an unknown path is not found"         "401" "$(status "$BASE/v1/nope")"
want "no token is a 401"                    "401" "$(status -X POST "$BASE/v1/invites")"
want "a junk token is a 401"                "401" "$(status -X POST -H 'authorization: Bearer nope' "$BASE/v1/invites")"

echo
echo "activation"
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' -d '{}' >/dev/null
want "no license is refused"                "bad_request" "$(code)"
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
  -d '{"license_key":"ABC","public_key":"short"}' >/dev/null
want "a malformed public key is refused"    "bad_public_key" "$(code)"
# The public key is validated BEFORE Gumroad is called, so this costs no round trip.
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
  -d '{"license_key":"'"$(printf 'x%.0s' {1..200})"'","public_key":"short"}' >/dev/null
want "an over-long license is refused"      "bad_request" "$(code)"

# The App Store credential. No real AppTransaction JWS exists outside a TestFlight or App
# Store install, so these pin the SHAPE of the branch: what is refused, and with which code.
# Here rather than at the end of the file on purpose: activation is throttled per IP
# (ACTIVATIONS_PER_HOUR_PER_IP) and the seed phase below spends that budget, which would turn
# every one of these into a 429.
PK=$(head -c 32 /dev/urandom | base64)
A="$BASE/v1/devices/activate"
post() { status -X POST "$A" -H 'content-type: application/json' -d "$1" >/dev/null; }

post "{\"public_key\":\"$PK\"}"
want "neither credential is refused"        "bad_request" "$(code)"
post "{\"license_key\":\"K\",\"app_transaction\":\"aaa.bbb.ccc\",\"public_key\":\"$PK\"}"
want "both credentials at once is refused"  "bad_request" "$(code)"
post "{\"app_transaction\":\"$(head -c 13000 /dev/zero | tr '\0' 'a').b.c\",\"public_key\":\"$PK\"}"
want "an over-long app_transaction refused" "bad_request" "$(code)"
# `JSON.parse("null")` succeeds, so the try/catch around request.json() never fires and the
# property reads used to throw a 500.
post 'null'
want "a null body is refused"               "bad_request" "$(code)"
post '[]'
want "an array body is refused"             "bad_request" "$(code)"
# These two reach the verifier. bad_license means it ran and refused;
# appstore_unconfigured would mean APPSTORE_APP_APPLE_ID is unset and the path is dark.
post "{\"app_transaction\":\"not a jws\",\"public_key\":\"$PK\"}"
want "a malformed app_transaction refused"  "bad_license" "$(code)"
post "{\"app_transaction\":\"aaa.bbb.ccc\",\"public_key\":\"$PK\"}"
want "a forged app_transaction refused"     "bad_license" "$(code)"

# The migration fields never authenticate anything on their own: they only prove, to an
# identity that is already bound to the OTHER channel's hash, that the caller holds the
# credential owning it. A request that carries them but no valid primary credential must be
# refused exactly as it would be without them, or they are a second way in.
post "{\"migrate_license_key\":\"K\",\"public_key\":\"$PK\"}"
want "a migration field alone is refused"   "bad_request" "$(code)"
post "{\"app_transaction\":\"aaa.bbb.ccc\",\"migrate_license_key\":\"K\",\"migrate_app_transaction\":\"a.b.c\",\"public_key\":\"$PK\"}"
want "both migration fields still refused"  "bad_license" "$(code)"
post "{\"app_transaction\":\"aaa.bbb.ccc\",\"migrate_license_key\":\"$(printf 'x%.0s' {1..200})\",\"public_key\":\"$PK\"}"
want "an over-long migration key refused"   "bad_license" "$(code)"

if [ -n "${MUSHROOM_TEST_LICENSE:-}" ]; then
  REAL_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  s=$(status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
    -d "{\"license_key\":\"$MUSHROOM_TEST_LICENSE\",\"public_key\":\"$REAL_KEY\"}")
  want "a real license activates" "201" "$s"
fi

# ---------------------------------------------------------------- seed
#
# Two identities on one license, which is also the shape of "three Macs per license".
# Public keys are 44 base64 characters because that is what 32 raw bytes encode to and the
# Worker checks the length; the bytes themselves are never used by the server.

ALICE_KEY="QUxJQ0VfXzMyX2J5dGVfcHVibGljX2tleV9fX19fX18="
BOB_KEY="Qk9CX19fXzMyX2J5dGVfcHVibGljX2tleV9fX19fX18B"
ALICE_ID="$(sha "$ALICE_KEY")"
BOB_ID="$(sha "$BOB_KEY")"
ALICE_TOKEN="alice-test-token-do-not-use-in-production"
BOB_TOKEN="bob-test-token-do-not-use-in-production"
LICENSE="$(sha 'TEST-LICENSE')"
NOW="$(date +%s)"

d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at)
    VALUES ('$LICENSE', 'active', $NOW, $NOW);"
# `license_hash` INCLUDED. `INSERT OR REPLACE` rewrites the whole row, so seeding without it
# reset the column to NULL on every run and recreated exactly the state migrations 0002/0003
# exist to eliminate: `activateDevice`'s first-claim-wins check is
# `if (claimed && claimed.license_hash && ...)`, which a NULL passes, so the check was skipped
# locally whether or not the code was there to run.
d1 "INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at) VALUES
    ('$ALICE_ID', '$ALICE_KEY', '$LICENSE', $NOW), ('$BOB_ID', '$BOB_KEY', '$LICENSE', $NOW);"
d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) VALUES
    ('dev-alice', '$ALICE_ID', '$LICENSE', '$(sha "$ALICE_TOKEN")', 'Alice Mac', $NOW, $NOW),
    ('dev-bob',   '$BOB_ID',   '$LICENSE', '$(sha "$BOB_TOKEN")',   'Bob Mac',   $NOW, $NOW);"

A=(-H "authorization: Bearer $ALICE_TOKEN")
B=(-H "authorization: Bearer $BOB_TOKEN")

echo
echo "channel migration"

# A Mac that moves between the direct download and the App Store keeps its Keychain, so the
# identity key survives while the licence hash under it does not. `migrateIdentity` lets the
# identity follow its owner, but ONLY to someone who can produce the credential it is bound
# to. The happy path needs two real credentials at once (a Gumroad key AND an AppTransaction
# JWS, which only exists inside a TestFlight or App Store install), so it is verified by hand
# on a TestFlight build. What is pinned here is the half that must never give way: an
# unprovable migration leaves the binding exactly where it was.
# 44 base64 characters, because that is what 32 raw bytes encode to and the Worker checks the
# length before anything else. A 43 character key never reaches the claim check at all: it is
# refused as bad_public_key, which looks like the migration assertions passing for the wrong
# reason if you are not watching the code.
MIG_KEY="TUlHUkFURV8zMl9ieXRlX3B1YmxpY19rZXlfX19fX18="
MIG_ID="$(sha "$MIG_KEY")"
OTHER="$(sha 'SOME-OTHER-CHANNEL')"
d1 "INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at)
    VALUES ('$MIG_ID', '$MIG_KEY', '$OTHER', $NOW);"

owner() { d1_json "SELECT license_hash FROM identities WHERE id = '$MIG_ID';" |
  python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["license_hash"] if r else "")'; }

# No migration field at all: the original refusal, unchanged.
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
  -d "{\"app_transaction\":\"aaa.bbb.ccc\",\"public_key\":\"$MIG_KEY\"}" >/dev/null
want "a claimed identity is still refused"  "bad_license" "$(code)"
want "and its owner did not move"           "$OTHER" "$(owner)"

# A migration credential that does not verify proves nothing, so the binding holds.
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
  -d "{\"app_transaction\":\"aaa.bbb.ccc\",\"migrate_license_key\":\"NOT-A-REAL-KEY\",\"public_key\":\"$MIG_KEY\"}" >/dev/null
want "an unprovable migration is refused"   "bad_license" "$(code)"
want "and the owner still did not move"     "$OTHER" "$(owner)"

echo
echo "invites"
want "a seeded token authenticates"         "201" "$(status -X POST "${A[@]}" "$BASE/v1/invites")"
CODE="$(field code)"
want "the code is 8 characters"             "8" "${#CODE}"
if [[ "$CODE" =~ ^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$ ]]; then
  ok "the code avoids I, L, O and U"
else
  bad "the code avoids I, L, O and U" "$CODE"
fi

status -X POST "${A[@]}" -H 'content-type: application/json' \
  -d "{\"code\":\"$CODE\"}" "$BASE/v1/invites/accept" >/dev/null
want "you cannot accept your own invite"    "self_invite" "$(code)"

status -X POST "${B[@]}" -H 'content-type: application/json' \
  -d '{"code":"ZZZZZZZZ"}' "$BASE/v1/invites/accept" >/dev/null
want "an unissued code is not found"        "invite_not_found" "$(code)"

status -X POST "${B[@]}" -H 'content-type: application/json' \
  -d '{"code":"nonsense!"}' "$BASE/v1/invites/accept" >/dev/null
want "a malformed code is not found"        "invite_not_found" "$(code)"

# Pasted the way people actually paste them.
LOWER="$(printf '%s' "$CODE" | tr 'A-Z' 'a-z')"
SPACED="${LOWER:0:4}-${LOWER:4:4}"
s=$(status -X POST "${B[@]}" -H 'content-type: application/json' \
  -d "{\"code\":\"$SPACED\"}" "$BASE/v1/invites/accept")
want "lowercase and dashes still accept"    "201" "$s"
want "the accepter learns who invited them" "$ALICE_ID" "$(field peer_id)"

status -X POST "${B[@]}" -H 'content-type: application/json' \
  -d "{\"code\":\"$CODE\"}" "$BASE/v1/invites/accept" >/dev/null
want "a code is single use"                 "invite_used" "$(code)"

# Expiry beats used, so an old code reads as expired rather than as someone else's.
# NB the code has to be spellable in the alphabet: "EXPIRED0" is not, it contains an I.
d1 "INSERT OR REPLACE INTO invites (code, identity_id, expires_at, created_at)
    VALUES ('EXPRED00', '$ALICE_ID', $((NOW - 10)), $((NOW - 100)));"
status -X POST "${B[@]}" -H 'content-type: application/json' \
  -d '{"code":"EXPRED00"}' "$BASE/v1/invites/accept" >/dev/null
want "an expired code says so"              "invite_expired" "$(code)"

echo
echo "history and push"
want "sync starts from a cursor"            "200" "$(status "${B[@]}" "$BASE/v1/sync?after=0")"
want "an empty inbox has no more pages"     "False" "$(field has_more)"
want "a bad push token is refused"          "400" "$(status -X POST "${B[@]}" \
  -H 'content-type: application/json' -d '{"token":"nothex"}' "$BASE/v1/push")"
want "a real-shaped push token is stored"   "200" "$(status -X POST "${B[@]}" \
  -H 'content-type: application/json' \
  -d '{"token":"'"$(printf 'a%.0s' {1..64})"'","environment":"sandbox"}' "$BASE/v1/push")"

echo
echo "friends"
want "blocking a stranger is not found"     "404" "$(status -X POST "${A[@]}" \
  "$BASE/v1/friends/$(printf '0%.0s' {1..64})/block")"
want "a malformed peer id is not a route"   "404" "$(status -X POST "${A[@]}" \
  "$BASE/v1/friends/notanidentity/block")"

# ---------------------------------------------------------------- sockets
#
# Before the rate-limit phase, which deliberately exhausts Alice's invite budget for the
# day and would otherwise leave the socket suite unable to make a friendship.

if command -v node >/dev/null 2>&1; then
  BASE="$BASE" BOB_IDENTITY="$BOB_ID" node socket-test.mjs "$ALICE_TOKEN" "$BOB_TOKEN"
  SOCKET_STATUS=$?
  # RE-SEED. The socket suite ends by releasing Bob's device to prove that revocation closes
  # a live socket, which revokes the token with it. Everything after this point, and the
  # Swift wire suite that runs against the same seeded tokens, would otherwise get a 401.
  d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) VALUES
      ('dev-alice', '$ALICE_ID', '$LICENSE', '$(sha "$ALICE_TOKEN")', 'Alice Mac', $NOW, $NOW),
      ('dev-bob',   '$BOB_ID',   '$LICENSE', '$(sha "$BOB_TOKEN")',   'Bob Mac',   $NOW, $NOW);"
else
  echo
  echo "  (skipping socket tests: node not found)"
  SOCKET_STATUS=0
fi

echo
echo "rate limits (exhausting, kept last)"
for _ in $(seq 1 20); do status -X POST "${A[@]}" "$BASE/v1/invites" >/dev/null; done
want "invites are capped per day"           "429" "$(status -X POST "${A[@]}" "$BASE/v1/invites")"
want "and it says when to retry"            "rate_limited" "$(code)"

echo

printf '%d passed, %d failed (plus the socket suite above)\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && [ "$SOCKET_STATUS" -eq 0 ]
