#!/bin/bash
# Does an undelivered message arm a push alarm when APNs is not configured?
#
# It must not, and nothing else in the suite can see this. No APNs key is normal for anyone
# running this Worker but us: only our .p8 signs for com.qubit.shroomy.app. `apnsKey` throws
# the same for an absent key as a broken one, and re-arming on both would wake every inbox with
# an unacked message forever: a quiet bill on someone else's account for a push that can't send.
#
# This owns its own server, in both modes.
#
#   ./alarm-test.sh                 # against `wrangler dev`, the hosted reference environment
#   SELFHOST=1 ./alarm-test.sh      # against a workerd box, the way a customer runs it
#
# A third question, with SELF=1 BOGUS_KEY=1: does a message the user sent to their own inbox
# arm one? It must not. The app copies every sent message to itself so the user's other Macs
# can show it; if that armed a push, a Mac asleep in another room would announce what its owner
# just typed, once per message. BOGUS_KEY is required there: with APNs unconfigured the branch
# is skipped for every message and the answer means nothing.
#
# In wrangler mode the answer is in workerd's `_cf_ALARM` table, readable only once the process
# lets go of the file, hence waiting and then killing the server.
#
# In SELFHOST mode it asks the inbox object over the unix-socket admin route. The file probe has
# to sum across inboxes it can't tell apart; the route answers for one named identity, so
# "stored" means stored in the addressed inbox. It also survives a workerd storage-layout change,
# which the `v3/do/` path below won't.
#
# Same logging rule as the Worker: ids and status codes, never a token.
set -uo pipefail

PORT="${PORT:-8799}"
BASE="http://localhost:$PORT"
STATE="${STATE:-$(mktemp -d)}"
DB="mushroom-messaging"
SELFHOST="${SELFHOST:-0}"
SOCK="$STATE/admin.sock"
cd "$(dirname "$0")"

sha() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

selfhost_sql() {
  python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1], "params": []}))' "$1" |
    curl -s --unix-socket "$SOCK" -X POST http://local/_selfhost/sql \
         -H 'content-type: application/json' --data-binary @- >/dev/null 2>&1
}
d1() {
  if [ "$SELFHOST" = "1" ]; then selfhost_sql "$1"
  else npx wrangler d1 execute "$DB" --local --persist-to "$STATE" --command "$1" >/dev/null 2>&1; fi
}

rm -rf "$STATE"; mkdir -p "$STATE"

if [ "$SELFHOST" = "1" ]; then
  WORKERD="${WORKERD:-../node_modules/.bin/workerd}"
  if [ ! -x "$WORKERD" ]; then
    echo "  FAIL  no workerd at $WORKERD. Run: (cd .. && npm install && ./build.sh)"; exit 1
  fi
  if [ ! -f ../dist/messaging/entry.js ]; then
    echo "  FAIL  no bundle. Run: (cd .. && ./build.sh)"; exit 1
  fi
  # The SqlStore constructor applies migrations on first use, so there's no apply step.
  #
  # The config must live in selfhost/, not the state dir: capnp resolves `import` relative to the
  # importing file, and it imports dist/messaging/modules.capnp. In $STATE it loads nothing and
  # only reports "server never came up".
  CONFIG="../.test-$$.capnp"
  STATE="$STATE" SOCK="$SOCK" PORT="$PORT" TEST_SQL=1 BOGUS_APNS="${BOGUS_KEY:-0}" \
    ../dev-config.sh > "$CONFIG"
  "$WORKERD" serve "$CONFIG" > "$STATE/dev.log" 2>&1 &
  DEV=$!
  trap 'kill $DEV 2>/dev/null; rm -f "$CONFIG"; rm -rf "$STATE"' EXIT
else
  npx wrangler d1 migrations apply "$DB" --local --persist-to "$STATE" >/dev/null 2>&1

  # APNS_KEY_P8 comes from the caller or stays unset (the default case). BOGUS_KEY=1 sets a key
  # that's present but can't sign, the other failure the retry budget exists for.
  APNS_ARG=()
  if [ "${BOGUS_KEY:-0}" = "1" ]; then
    APNS_ARG=(--var "APNS_KEY_P8:not-a-real-key" --var "APNS_KEY_ID:AAAA" --var "APNS_TEAM_ID:BBBB")
  fi

  npx wrangler dev --port "$PORT" --persist-to "$STATE" \
    --var ACTIVATIONS_PER_HOUR_PER_IP:1000 \
    ${APNS_ARG[@]+"${APNS_ARG[@]}"} > "$STATE/dev.log" 2>&1 &
  DEV=$!
fi
trap 'kill $DEV 2>/dev/null; rm -rf "$STATE"' EXIT

# Any HTTP answer means it's up: a self-hosted root with no BRAND_URL is a 404, not a redirect.
up() { [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/")" != "000" ]; }
for _ in $(seq 1 90); do up && break; sleep 1; done
if ! up; then
  echo "  FAIL  server never came up; see $STATE/dev.log"; exit 1
fi

# Same seed shape as test.sh: two identities on one licence.
ALICE_KEY="QUxJQ0VfXzMyX2J5dGVfcHVibGljX2tleV9fX19fX18="
BOB_KEY="Qk9CX19fXzMyX2J5dGVfcHVibGljX2tleV9fX19fX18B"
ALICE_ID="$(sha "$ALICE_KEY")"; BOB_ID="$(sha "$BOB_KEY")"
ALICE_TOKEN="alice-test-token-do-not-use-in-production"
BOB_TOKEN="bob-test-token-do-not-use-in-production"
LICENSE="$(sha 'TEST-LICENSE')"; NOW="$(date +%s)"

d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at)
    VALUES ('$LICENSE','active',$NOW,$NOW);"
d1 "INSERT OR REPLACE INTO identities (id, public_key, license_hash, created_at) VALUES
    ('$ALICE_ID','$ALICE_KEY','$LICENSE',$NOW), ('$BOB_ID','$BOB_KEY','$LICENSE',$NOW);"
d1 "INSERT OR REPLACE INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) VALUES
    ('dev-alice','$ALICE_ID','$LICENSE','$(sha "$ALICE_TOKEN")','Alice Mac',$NOW,$NOW),
    ('dev-bob','$BOB_ID','$LICENSE','$(sha "$BOB_TOKEN")','Bob Mac',$NOW,$NOW);"

A=(-H "authorization: Bearer $ALICE_TOKEN"); B=(-H "authorization: Bearer $BOB_TOKEN")

CODE=$(curl -s -X POST "${A[@]}" "$BASE/v1/invites" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("code",""))')
curl -s -o /dev/null -X POST "${B[@]}" -H 'content-type: application/json' \
  -d "{\"code\":\"$CODE\"}" "$BASE/v1/invites/accept"

# SELF=1 sends to Alice's own inbox instead of Bob's, so the push token goes there too:
# `alarm()` reads the tokens of the inbox holding the message.
if [ "${SELF:-0}" = "1" ] && [ "${BOGUS_KEY:-0}" != "1" ]; then
  printf '  \033[31mFAIL\033[0m SELF=1 needs BOGUS_KEY=1, or the branch under test is skipped for every message\n'
  exit 1
fi
if [ "${SELF:-0}" = "1" ]; then TARGET_ID="$ALICE_ID"; PUSH=("${A[@]}"); else TARGET_ID="$BOB_ID"; PUSH=("${B[@]}"); fi

# The recipient needs a push token, or `alarm()` returns on an empty target list and looks fixed
# for the wrong reason.
curl -s -o /dev/null -X POST "${PUSH[@]}" -H 'content-type: application/json' \
  -d "{\"token\":\"$(printf 'a%.0s' {1..64})\",\"environment\":\"sandbox\"}" "$BASE/v1/push"

BASE="$BASE" node alarm-test.mjs "$ALICE_TOKEN" "$TARGET_ID" || {
  echo "  FAIL  the message was not accepted, so this proves nothing"; exit 1; }

sleep 20   # PUSH_GRACE_MS is 10s, so an armed alarm has fired and re-armed by now
NOW_MS=$(( $(date +%s) * 1000 ))

if [ "$SELFHOST" = "1" ]; then
  # No kill needed: the object answers while running, which is why we ask it instead of reading
  # files. Same "never pass vacuously" rule: no answer, or the wrong shape, is a failure, not 0.
  PROBE="$STATE/probe.json"
  if ! curl -sf --unix-socket "$SOCK" -m 10 -o "$PROBE" \
       "http://local/_selfhost/inbox?identity=$BOB_ID" 2>/dev/null; then
    printf '  \033[31mFAIL\033[0m the inbox probe did not answer: this suite would pass vacuously\n'
    exit 1
  fi
  if ! READ=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
now = int(sys.argv[2])
alarm = d["alarm"]                      # KeyError here is a failure, deliberately
print(0 if alarm is None else 1,
      d["push_tokens"],
      d["messages"],
      0 if d["push_attempt"] is None else 1,
      "?" if alarm is None else int((alarm - now) / 1000))
' "$PROBE" "$NOW_MS" 2>/dev/null); then
    printf '  \033[31mFAIL\033[0m the inbox probe answered the wrong shape: this suite would pass vacuously\n'
    exit 1
  fi
  read -r ALARMS TOKENS STORED ATTEMPTS NEXT_IN <<< "$READ"
  [ "${KEEP:-0}" = "1" ] && { trap 'kill $DEV 2>/dev/null' EXIT; echo "  (state kept at $STATE)"; }
else
kill $DEV 2>/dev/null; wait $DEV 2>/dev/null; sleep 2
# KEEP=1 leaves the state dir behind for poking at.
if [ "${KEEP:-0}" = "1" ]; then trap - EXIT; echo "  (state kept at $STATE)"
else trap 'rm -rf "$STATE"' EXIT; fi

META="$STATE/v3/do/mushroom-messaging-UserInbox/metadata.sqlite"
# Assert the table is readable before trusting its count. Otherwise a workerd layout bump
# (v3 -> v4), a renamed table or a moved namespace makes sqlite3 fail, `${ALARMS:-0}` becomes 0,
# and this file's scenario reports ok forever while asserting nothing.
if ! sqlite3 "$META" "SELECT COUNT(*) FROM _cf_ALARM;" >/dev/null 2>&1; then
  printf '  \033[31mFAIL\033[0m cannot read _cf_ALARM at %s: this suite would pass vacuously\n' "$META"
  exit 1
fi
ALARMS=$(sqlite3 "$META" "SELECT COUNT(*) FROM _cf_ALARM;" 2>/dev/null)
# Same readability rule as above: an unexpanded glob, renamed table or missing sqlite3 gives an
# empty count, `${c:-0}` makes it zero, and "no push token stored" would check nothing.
TOKENS=0
INBOXES=0
for f in "$STATE"/v3/do/mushroom-messaging-UserInbox/*.sqlite; do
  [ -f "$f" ] || continue
  [ "$(basename "$f")" = "metadata.sqlite" ] && continue
  INBOXES=$((INBOXES + 1))
  if ! c=$(sqlite3 "$f" "SELECT COUNT(*) FROM devices WHERE apns_token IS NOT NULL;" 2>/dev/null); then
    printf '  \033[31mFAIL\033[0m cannot read devices in %s: this check would pass vacuously\n' "$(basename "$f")"
    exit 1
  fi
  TOKENS=$((TOKENS + ${c:-0}))
done
if [ "$INBOXES" -eq 0 ]; then
  printf '  \033[31mFAIL\033[0m no inbox databases found under %s\n' "$STATE/v3/do/mushroom-messaging-UserInbox"
  exit 1
fi
# scheduled_time is nanoseconds. How far out the next attempt is, in seconds.
NEXT_IN=$(sqlite3 "$META" \
  "SELECT CAST((MAX(scheduled_time)/1000000 - $NOW_MS)/1000 AS INT) FROM _cf_ALARM;" 2>/dev/null)
STORED=0
for f in "$STATE"/v3/do/mushroom-messaging-UserInbox/*.sqlite; do
  [ "$(basename "$f")" = "metadata.sqlite" ] && continue
  c=$(sqlite3 "$f" "SELECT COUNT(*) FROM messages;" 2>/dev/null); STORED=$((STORED + ${c:-0}))
done
fi

echo
if [ "$STORED" -lt 1 ]; then
  printf '  \033[31mFAIL\033[0m the message was never stored, so the alarm count means nothing\n'
  exit 1
fi
printf '  \033[32mok\033[0m   the message was stored (%s)\n' "$STORED"

if [ "${SELF:-0}" = "1" ]; then
  # The control against passing for the wrong reason: APNs is configured and a token is stored
  # in the message's inbox, so only the sender being the recipient keeps the alarm unarmed.
  if [ "${TOKENS:-0}" -lt 1 ]; then
    printf '  \033[31mFAIL\033[0m no push token stored, so nothing could have been pushed at anyway\n'
    exit 1
  fi
  printf '  \033[32mok\033[0m   a push token is stored, so the target list is not empty\n'
  if [ "${ALARMS:-0}" -eq 0 ]; then
    printf '  \033[32mok\033[0m   the user'"'"'s own message armed no push alarm\n'
    exit 0
  fi
  printf '  \033[31mFAIL\033[0m %s push alarm(s) armed for the user'"'"'s own message: their other Mac will be told about it\n' "$ALARMS"
  exit 1
fi

if [ "${BOGUS_KEY:-0}" = "1" ]; then
  # A key that can't sign should retry: the failures retry is for (a throttled provider token,
  # a 5xx) look identical here and do recover.
  if [ "${ALARMS:-0}" -eq 0 ]; then
    printf '  \033[31mFAIL\033[0m a signing failure gave up immediately; transient APNs errors would never retry\n'
    exit 1
  fi
  printf '  \033[32mok\033[0m   a failing key still retries (next attempt in ~%ss)\n' "${NEXT_IN:-?}"

  # The assertion with teeth. A flat re-arm and a counted one look the same on the first retry
  # (both wait PUSH_RETRY_MS); only the counted one persists an attempt number, which is what
  # lets it stop. No counter, no budget, an unbounded loop.
  if [ "$SELFHOST" != "1" ]; then
    ATTEMPTS=0
    for f in "$STATE"/v3/do/mushroom-messaging-UserInbox/*.sqlite; do
      [ "$(basename "$f")" = "metadata.sqlite" ] && continue
      c=$(sqlite3 "$f" "SELECT COUNT(*) FROM _cf_KV WHERE key = 'push_attempt';" 2>/dev/null)
      ATTEMPTS=$((ATTEMPTS + ${c:-0}))
    done
  fi   # SELFHOST already read it straight out of the object's storage.
  if [ "$ATTEMPTS" -ge 1 ]; then
    printf '  \033[32mok\033[0m   the attempt is counted, so the retry has a budget it can exhaust\n'
    exit 0
  fi
  printf '  \033[31mFAIL\033[0m nothing counted the attempt: this retries every %ss forever\n' "$((60))"
  exit 1
fi

# The token is refused upstream, so `alarm`'s target list is provably empty and the two guards
# are backup. Assert that directly: the alarm assertion below rests on it.
if [ "$TOKENS" -ne 0 ]; then
  printf '  \033[31mFAIL\033[0m %s push token(s) stored on a deployment that cannot push\n' "$TOKENS"
  exit 1
fi
printf '  \033[32mok\033[0m   no push token stored without an APNs key\n'

if [ "${ALARMS:-0}" -eq 0 ]; then
  printf '  \033[32mok\033[0m   no push alarm armed without an APNs key\n'
  exit 0
fi
printf '  \033[31mFAIL\033[0m %s push alarm(s) armed without an APNs key: it will re-arm forever\n' "$ALARMS"
exit 1
