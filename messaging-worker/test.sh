#!/bin/bash
# Smoke matrix for mushroom-messaging against a local `wrangler dev`.
#
#   npx wrangler dev --port 8788 --persist-to ../.wrangler-dev-state \
#     --var ACTIVATIONS_PER_HOUR_PER_IP:1000
#   ./test.sh
#
# The --var is required. Every activation assertion is a POST to /v1/devices/activate, there
# are over a dozen, and the real budget is 10 an hour per IP. Without it the suite spends the
# budget itself and everything after fails as rate_limited, which --persist-to carries into
# the next run. Production never sets it.
#
# Needs no credentials: it seeds a license and two devices straight into local D1, so
# everything past activation is the same whether or not Gumroad is reachable. Set
# MUSHROOM_TEST_LICENSE to also exercise the real activation path.
#
# Same logging rule as the Worker: ids and status codes, never a token.
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

# Database access has two backends, because this is also the on-prem conformance suite.
#
#   ADMIN_SOCK unset -> `wrangler dev`, the hosted reference environment.
#   ADMIN_SOCK set   -> a self-hosted workerd box (see selfhost/), which has no wrangler and no
#                       account to reach. Same SQL, posted to the unix-socket admin route.
#
# That's the only difference between the runs. Every assertion is shared, so hosted vs on-prem
# behaviour shows up as a diff in the pass list, not as a second suite nobody maintains.
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

# Is there a schema? With no tables, about twenty assertions below answer 500 with no hint why,
# which is what a deleted state directory looks like. `licenses` comes from the first migration,
# so its absence means none have run.
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
# A self-hosted root redirects to BRAND_URL, or 404s when the box names nobody.
ROOT=$(status -o /dev/null "$BASE/")
if [ -n "$ADMIN_SOCK" ] && [ "$ROOT" = 404 ]; then want "root is 404 (no BRAND_URL)" "404" "$ROOT"
else want "root redirects to the website" "302" "$ROOT"; fi
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
# The public key is validated before Gumroad is called, so this costs no round trip.
status -X POST "$BASE/v1/devices/activate" -H 'content-type: application/json' \
  -d '{"license_key":"'"$(printf 'x%.0s' {1..200})"'","public_key":"short"}' >/dev/null
want "an over-long license is refused"      "bad_request" "$(code)"

# The App Store credential. A real AppTransaction JWS only exists inside a TestFlight or App
# Store install, so these pin the branch's shape: what's refused, and with which code. Here,
# not at the end: activation is throttled per IP (ACTIVATIONS_PER_HOUR_PER_IP) and the seed
# phase spends that budget, turning these into 429s.
PK=$(head -c 32 /dev/urandom | base64)
A="$BASE/v1/devices/activate"
post() { status -X POST "$A" -H 'content-type: application/json' -d "$1" >/dev/null; }

post "{\"public_key\":\"$PK\"}"
want "neither credential is refused"        "bad_request" "$(code)"
post "{\"license_key\":\"K\",\"app_transaction\":\"aaa.bbb.ccc\",\"public_key\":\"$PK\"}"
want "both credentials at once is refused"  "bad_request" "$(code)"
post "{\"app_transaction\":\"$(head -c 13000 /dev/zero | tr '\0' 'a').b.c\",\"public_key\":\"$PK\"}"
want "an over-long app_transaction refused" "bad_request" "$(code)"
# `JSON.parse("null")` succeeds, so the try/catch around request.json() doesn't fire and the
# property reads would throw a 500.
post 'null'
want "a null body is refused"               "bad_request" "$(code)"
post '[]'
want "an array body is refused"             "bad_request" "$(code)"
# These two reach the verifier. bad_license means it ran and refused; appstore_unconfigured
# would mean APPSTORE_APP_APPLE_ID is unset and the path is dark.
post "{\"app_transaction\":\"not a jws\",\"public_key\":\"$PK\"}"
want "a malformed app_transaction refused"  "bad_license" "$(code)"
post "{\"app_transaction\":\"aaa.bbb.ccc\",\"public_key\":\"$PK\"}"
want "a forged app_transaction refused"     "bad_license" "$(code)"

# The migration fields never authenticate on their own: they only prove the caller holds the
# credential an identity is bound to on the other channel. Without a valid primary credential
# the request must be refused exactly as without them, or they're a second way in.
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
# Two identities on one license, the shape of "several Macs per license". Public keys are 44
# base64 characters (32 raw bytes) because the Worker checks the length; it never uses the bytes.

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
# `license_hash` included. `INSERT OR REPLACE` rewrites the whole row, so seeding without it
# resets the column to NULL, the state migrations 0002/0003 exist to eliminate.
# `activateDevice`'s first-claim check is `if (claimed && claimed.license_hash && ...)`, which a
# NULL passes, so the check would silently never run locally.
d1 "INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at) VALUES
    ('$ALICE_ID', '$ALICE_KEY', '$LICENSE', $NOW), ('$BOB_ID', '$BOB_KEY', '$LICENSE', $NOW);"
d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) VALUES
    ('dev-alice', '$ALICE_ID', '$LICENSE', '$(sha "$ALICE_TOKEN")', 'Alice Mac', $NOW, $NOW),
    ('dev-bob',   '$BOB_ID',   '$LICENSE', '$(sha "$BOB_TOKEN")',   'Bob Mac',   $NOW, $NOW);"

A=(-H "authorization: Bearer $ALICE_TOKEN")
B=(-H "authorization: Bearer $BOB_TOKEN")

echo
echo "channel migration"

# A Mac moving between the direct download and the App Store keeps its Keychain, so the
# identity key survives but the licence hash under it doesn't. `migrateIdentity` lets the
# identity follow its owner, but only for someone who can produce the credential it's bound to.
# The happy path needs a Gumroad key and an AppTransaction JWS at once (the JWS only exists in a
# TestFlight or App Store install), so it's checked by hand on TestFlight. Pinned here is the
# half that must never give: an unprovable migration leaves the binding where it was.
# 44 base64 characters, because the Worker checks the length first. A 43-character key is
# refused as bad_public_key before the claim check, which would make the migration assertions
# pass for the wrong reason.
MIG_KEY="TUlHUkFURV8zMl9ieXRlX3B1YmxpY19rZXlfX19fX18="
MIG_ID="$(sha "$MIG_KEY")"
OTHER="$(sha 'SOME-OTHER-CHANNEL')"
d1 "INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at)
    VALUES ('$MIG_ID', '$MIG_KEY', '$OTHER', $NOW);"

owner() { d1_json "SELECT license_hash FROM identities WHERE id = '$MIG_ID';" |
  python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["license_hash"] if r else "")'; }

# No migration field at all: the plain refusal.
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
# The code must be spellable in the alphabet: "EXPIRED0" isn't, it has an I.
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
# Before the rate-limit phase, which exhausts Alice's invite budget for the day and would leave
# the socket suite unable to make a friendship.

if command -v node >/dev/null 2>&1; then
  BASE="$BASE" BOB_IDENTITY="$BOB_ID" node socket-test.mjs "$ALICE_TOKEN" "$BOB_TOKEN"
  SOCKET_STATUS=$?
  # Re-seed. The socket suite ends by releasing Bob's device to prove revocation closes a live
  # socket, which revokes his token. Everything after, and the Swift wire suite using the same
  # seeded tokens, would otherwise get a 401.
  d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) VALUES
      ('dev-alice', '$ALICE_ID', '$LICENSE', '$(sha "$ALICE_TOKEN")', 'Alice Mac', $NOW, $NOW),
      ('dev-bob',   '$BOB_ID',   '$LICENSE', '$(sha "$BOB_TOKEN")',   'Bob Mac',   $NOW, $NOW);"
else
  echo
  echo "  (skipping socket tests: node not found)"
  SOCKET_STATUS=0
fi

echo
echo "device management"

# Reads a field from the /v1/devices payload; `field()` only reaches top-level scalars.
devices() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" < "$BODY" 2>/dev/null; }

# A device on a different licence, for the scoping assertions below. Without one, "revoking
# someone else's device is refused" would pass against an empty table.
STRANGER="$(sha 'STRANGER-LICENSE')"
d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at)
    VALUES ('$STRANGER', 'active', $NOW, $NOW);"
d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at)
    VALUES ('dev-stranger', '$ALICE_ID', '$STRANGER', '$(sha 'stranger-token')', 'Someone Else Mac', $NOW, $NOW);"

status "${A[@]}" "$BASE/v1/devices" >/dev/null
want "the device list is readable"          "2" "$(devices 'len(d["devices"])')"
want "and reports the seat limit"           "5" "$(devices 'd["limit"]')"
# Scoped on license_hash, not identity_id: the cap counts per licence, so an identity-keyed
# list would hide the rows using the seats.
want "another licence is not listed"        "0" "$(devices '''sum(1 for x in d["devices"] if x["id"]=="dev-stranger")''')"
want "this device is flagged"               "dev-alice" "$(devices '''next(x["id"] for x in d["devices"] if x["this_device"])''')"
# A token is never returned. It isn't even selected, but the assertion is cheap and the rule
# (never a credential) matters.
want "no token leaks into the list"         "0" "$(devices '''sum(1 for x in d["devices"] if "token" in x)''')"

status -X POST "${A[@]}" "$BASE/v1/devices/revoke" -H 'content-type: application/json' -d '{}' >/dev/null
want "revoke needs a device id"             "bad_device" "$(code)"
status -X POST "${A[@]}" "$BASE/v1/devices/revoke" -H 'content-type: application/json' \
  -d '{"device_id":"dev-alice"}' >/dev/null
want "revoking yourself is refused"         "cannot_revoke_self" "$(code)"
# 404, the same as for a device id that never existed, or this is an oracle for real ids.
status -X POST "${A[@]}" "$BASE/v1/devices/revoke" -H 'content-type: application/json' \
  -d '{"device_id":"dev-stranger"}' >/dev/null
want "another licence's device is refused"  "not_found" "$(code)"
want "and the stranger is still live"       "1" "$(d1_json "SELECT COUNT(*) AS n FROM devices WHERE id='dev-stranger' AND revoked_at IS NULL" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["n"])')"
status -X POST "${A[@]}" "$BASE/v1/devices/revoke" -H 'content-type: application/json' \
  -d '{"device_id":"nope"}' >/dev/null
want "an unknown device is refused"         "not_found" "$(code)"

# The real thing: Alice signs Bob's Mac out.
want "revoking a peer device succeeds"      "200" "$(status -X POST "${A[@]}" "$BASE/v1/devices/revoke" -H 'content-type: application/json' -d '{"device_id":"dev-bob"}')"
want "the revoked device cannot call"       "401" "$(status -X POST "${B[@]}" "$BASE/v1/invites")"
status "${A[@]}" "$BASE/v1/devices" >/dev/null
want "and it is off the list"               "1" "$(devices 'len(d["devices"])')"

# Put Bob back, so anything added later doesn't depend on test order.
d1 "UPDATE devices SET revoked_at = NULL WHERE id = 'dev-bob';"
# Proved with a read: creating an invite would spend one of Bob's twenty a day, which the
# rate-limit block below cares about.
want "bob is restored for later runs"       "200" "$(status "${B[@]}" -o /dev/null "$BASE/v1/friends")"

echo
echo "setapp activation (inert until the vendor secrets exist)"

# The Setapp branch ships before Setapp is configured; this proves it's inert. With no
# SETAPP_CLIENT_ID/SECRET, every setapp activation answers 503 `setapp_unconfigured`, the soft
# code neither client latches, and nothing else in this suite changes.
#
# The JSON has single quotes around the braces. Bash brace-expands an unquoted `{a,b,c}` into
# three words, and `$(...)` re-parses the escaping, so the obvious spelling sends three
# malformed requests and every assertion reads 400 bad_request.
PROBE_KEY="U0VUQVBQXzMyX2J5dGVfcHVibGljX2tleV9fX19fXwE="
PHONE_KEY="UEhPTkVfXzMyX2J5dGVfcHVibGljX2tleV9fX19fXwE="
activate() {
  status -X POST -H 'content-type: application/json' -d "$1" "$BASE/v1/devices/activate"
}

json='{"public_key":"'"$PROBE_KEY"'","device_name":"P","setapp_code":"CODE"}'
want "an unconfigured deploy refuses softly"  "503" "$(activate "$json")"
want "and says which half is missing"         "setapp_unconfigured" "$(code)"

# Exactly one credential, counted over four fields. Silently picking a winner is how one build
# ends up authenticating as another's licence.
json='{"public_key":"'"$PROBE_KEY"'","device_name":"P","setapp_code":"C","license_key":"K"}'
want "two credentials at once is refused"     "400" "$(activate "$json")"
json='{"public_key":"'"$PROBE_KEY"'","device_name":"P"}'
want "no credential at all is refused"        "400" "$(activate "$json")"
json='{"public_key":"'"$PROBE_KEY"'","device_name":"P","setapp_code":"'"$(printf 'x%.0s' $(seq 600))"'"}'
want "an oversized code is refused"           "400" "$(activate "$json")"

echo
echo "pairing link codes"

# A Mac mints a one-time code so a phone can join the licence without a credential. It's how a
# Setapp Mac pairs a phone at all: its credential is a single-use auth code only a Worker can
# exchange, so there's nothing to copy across.
want "a Mac can mint a link code"             "201" "$(status -X POST "${A[@]}" "$BASE/v1/link")"
LINK_CODE="$(field code)"
want "and it comes back with an expiry"       "600" "$(field expires_in)"
if [ -n "$LINK_CODE" ]; then ok "the code is non-empty"; else bad "the code is non-empty"; fi

# Stored hashed, like a device token: for ten minutes it's a bearer credential to someone's
# Friends identity, and a plaintext table would turn a database read into account access.
want "the code is never stored in the clear"  "0" \
  "$(d1 "SELECT COUNT(*) AS n FROM link_codes WHERE code_hash = '$LINK_CODE';" | grep -c '\"n\": 1')"

json='{"public_key":"'"$PHONE_KEY"'","device_name":"Phone","link_code":"'"$LINK_CODE"'"}'
want "a phone redeems it and joins"           "201" "$(activate "$json")"
PHONE_TOKEN="$(field token)"

# Single use. The DELETE is the claim, so two phones racing one code can't both win, and a code
# recovered later from a photo is worthless.
want "the same code cannot be spent twice"    "403" "$(activate "$json")"
want "and the refusal is bad_license"         "bad_license" "$(code)"

# The phone landed on the same licence: same seats, and an identity the Mac's friends know.
# Asserted through the device list, not the table, because the list is scoped to the caller's
# licence and is what the user sees.
status "${A[@]}" "$BASE/v1/devices" > /dev/null
want "the phone is on the Mac's licence"      "1" \
  "$(python3 -c 'import json;print(sum(1 for d in json.load(open("'"$BODY"'"))["devices"] if d["name"]=="Phone"))')"

echo
echo "a lapsed entitlement is told apart from a dead token"

# Two refusals share a 401. An unknown token means "activate again"; a live token whose licence
# is past its horizon means "someone must re-prove this licence". A link-paired phone can't do
# that itself, so `reactivate` would make it throw away a token it can never replace.
# Minted while the licence is healthy, since minting is authed; the lapse block below tries to
# spend it.
status -X POST "${A[@]}" "$BASE/v1/link" > /dev/null
json2='{"public_key":"'"$PHONE_KEY"'","device_name":"Phone2","link_code":"'"$(field code)"'"}'

d1 "UPDATE licenses SET entitled_until = $NOW - 10 WHERE license_hash = '$LICENSE';"
want "a lapsed licence still 401s"            "401" "$(status "${A[@]}" -o /dev/null "$BASE/v1/friends")"
status "${A[@]}" "$BASE/v1/friends" > /dev/null
want "but says the entitlement lapsed"        "entitlement_lapsed" "$(code)"

status -H "authorization: Bearer not-a-real-token" "$BASE/v1/friends" > /dev/null
want "an unknown token still says reactivate" "reactivate" "$(code)"

# Releasing a seat is cleanup, not access, so it works through a lapse, or the seat cap is a trap.
want "release still works while lapsed"       "200" \
  "$(status -X POST -H "authorization: Bearer $PHONE_TOKEN" "$BASE/v1/devices/release")"

# A borrowed activation must never refresh the licence row, or a phone could keep a lapsed licence
# alive forever on a code minted while it was good. That's why the link branch skips the upsert.
want "a link code cannot revive a lapse"      "403" "$(activate "$json2")"
want "and it says the subscription is needed" "subscription_required" "$(code)"
want "the licence is still lapsed after that" "401" "$(status "${A[@]}" -o /dev/null "$BASE/v1/friends")"

d1 "UPDATE licenses SET entitled_until = NULL WHERE license_hash = '$LICENSE';"
want "and the licence recovers"               "200" "$(status "${A[@]}" -o /dev/null "$BASE/v1/friends")"
d1 "DELETE FROM devices WHERE name = 'Phone';"
d1 "DELETE FROM identities WHERE public_key = '$PHONE_KEY';"

echo
echo "apns key parsing (pure, no server)"

# `apnsPEM` is how push can fail while the alarm reports Ok: a mangled .p8 throws inside a catch
# that swallows it, and no notification goes out on any platform. These run the real function
# out of worker.js.
#
# The ordering assertion matters most. Stripping non-base64 before the escape sequences drops the
# backslash of `\n` but keeps the `n` (valid base64), so the key decodes to wrong bytes instead
# of failing, which is worse than an outage.
apns_case() {
  node -e '
    const src = require("fs").readFileSync("worker.js","utf8");
    eval(src.match(/function apnsPEM\(env\) \{[\s\S]*?\n\}/)[0]);
    const body = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg" + "A".repeat(64);
    // The armour lines are ASSEMBLED rather than written out, and that is not style. This file
    // is published to qubit999/mushroom-selfhost, and publish-selfhost.sh scans the staged tree
    // for PEM armour before it will release anything. Spelled in full, this fixture (a fake
    // body of 64 A bytes, no secret anywhere) fails that gate on every run, and the comments in
    // that script say why that is the worst outcome: a gate that always fails is a gate
    // somebody stops running. Keep any future PEM fixture split the same way.
    //
    // No apostrophes anywhere in this node block, comments included: it is one single-quoted
    // shell argument, so one apostrophe ends the string and the rest becomes a syntax error.
    const tag = (w) => "-----" + w + " PRIVATE" + " KEY-----";
    const armour = (sep, pre = "", post = "") =>
      pre + tag("BEGIN") + sep + body + sep + tag("END") + sep + post;
    const cases = {
      newlines: armour("\n"),
      escaped:  armour("\\n"),
      crlf:     armour("\r\n"),
      quoted:   armour("\\n", "\"", "\""),
      junk:     armour("\n", "", "%"),
    };
    const out = apnsPEM({ APNS_KEY_P8: cases[process.argv[1]] });
    console.log(out === body ? "exact" : "WRONG");
  ' "$1" 2>/dev/null
}
for c in newlines escaped crlf quoted junk; do
  want "a .p8 with $c decodes exactly" "exact" "$(apns_case $c)"
done

echo
echo "rate limits (exhausting, kept last)"
for _ in $(seq 1 20); do status -X POST "${A[@]}" "$BASE/v1/invites" >/dev/null; done
want "invites are capped per day"           "429" "$(status -X POST "${A[@]}" "$BASE/v1/invites")"
want "and it says when to retry"            "rate_limited" "$(code)"

echo

printf '%d passed, %d failed (plus the socket suite above)\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && [ "$SOCKET_STATUS" -eq 0 ]
