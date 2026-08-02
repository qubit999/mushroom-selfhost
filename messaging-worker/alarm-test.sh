#!/bin/bash
# Does an undelivered message arm a push alarm when APNs is NOT configured?
#
# It must not, and nothing else in the suite can see this. A deployment with no APNs key is
# the normal state for anyone running this Worker who is not us: only our own .p8 signs for
# com.qubit.shroomy.app. `apnsKey` throws for an absent key exactly as it does for a broken
# one, and `alarm()` used to answer both by re-arming at PUSH_RETRY_MS, so every inbox holding
# an unacked message woke on a timer forever. On someone else's Cloudflare account that is a
# bill, charged quietly, for a notification that could never have been sent.
#
# This owns its own server, in both modes.
#
#   ./alarm-test.sh                 # against `wrangler dev`, the hosted reference environment
#   SELFHOST=1 ./alarm-test.sh      # against a workerd box, the way a customer runs it
#
# In wrangler mode the answer lives in workerd's `_cf_ALARM` table, which can only be read once
# the process has let go of the file, which is why this waits and then kills the server.
#
# In SELFHOST mode it asks the inbox object instead, over the unix-socket admin route. That is
# not merely a port: the file probe has to sum across every inbox because it cannot tell them
# apart, while the route answers for ONE named identity, so "the message was stored" means
# stored in the inbox it was addressed to. It also survives a workerd storage-layout change,
# which the `v3/do/` path below will not.
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
  # Migrations are applied by the SqlStore constructor on first use, so there is no apply step.
  #
  # The config has to live in selfhost/, not in the state dir: capnp resolves `import` relative
  # to the importing file and the config imports dist/messaging/modules.capnp. Writing it to
  # $STATE loads nothing and reports only "server never came up".
  CONFIG="../.test-$$.capnp"
  STATE="$STATE" SOCK="$SOCK" PORT="$PORT" TEST_SQL=1 BOGUS_APNS="${BOGUS_KEY:-0}" \
    ../dev-config.sh > "$CONFIG"
  "$WORKERD" serve "$CONFIG" > "$STATE/dev.log" 2>&1 &
  DEV=$!
  trap 'kill $DEV 2>/dev/null; rm -f "$CONFIG"; rm -rf "$STATE"' EXIT
else
  npx wrangler d1 migrations apply "$DB" --local --persist-to "$STATE" >/dev/null 2>&1

  # APNS_KEY_P8 is passed in by the caller, or left unset. Unset is the default case this suite
  # was written for; BOGUS_KEY=1 sets a key that is present but cannot sign, which is the other
  # failure the retry budget exists for.
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

for _ in $(seq 1 90); do curl -sf -o /dev/null --max-time 2 "$BASE/" && break; sleep 1; done
if ! curl -sf -o /dev/null --max-time 2 "$BASE/"; then
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

# Bob needs a push token, or `alarm()` returns on an empty target list and would look fixed
# for the wrong reason.
curl -s -o /dev/null -X POST "${B[@]}" -H 'content-type: application/json' \
  -d "{\"token\":\"$(printf 'a%.0s' {1..64})\",\"environment\":\"sandbox\"}" "$BASE/v1/push"

BASE="$BASE" node alarm-test.mjs "$ALICE_TOKEN" "$BOB_ID" || {
  echo "  FAIL  the message was not accepted, so this proves nothing"; exit 1; }

sleep 20   # PUSH_GRACE_MS is 10s, so an armed alarm has fired and re-armed by now
NOW_MS=$(( $(date +%s) * 1000 ))

if [ "$SELFHOST" = "1" ]; then
  # No kill needed: the object answers while it is running, which is the point of asking it
  # rather than reading its files. The same "refuse to pass vacuously" rule applies, so a probe
  # that does not answer, or answers something the wrong shape, is a failure and not a zero.
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
# Assert the table is READABLE before trusting a count from it. Without this, a workerd storage
# layout bump (v3 -> v4), a renamed table or a moved namespace directory makes sqlite3 fail,
# `${ALARMS:-0}` becomes 0, and the scenario this file is named for reports ok forever while
# asserting nothing.
if ! sqlite3 "$META" "SELECT COUNT(*) FROM _cf_ALARM;" >/dev/null 2>&1; then
  printf '  \033[31mFAIL\033[0m cannot read _cf_ALARM at %s: this suite would pass vacuously\n' "$META"
  exit 1
fi
ALARMS=$(sqlite3 "$META" "SELECT COUNT(*) FROM _cf_ALARM;" 2>/dev/null)
# Same readability rule as the _cf_ALARM probe above, and for the same reason: an unexpanded
# glob, a renamed table or a missing sqlite3 all yield an empty count, `${c:-0}` turns that into
# a zero, and "no push token stored" would be reported having checked nothing.
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
# scheduled_time is nanoseconds. How far out the NEXT attempt is, in seconds.
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

if [ "${BOGUS_KEY:-0}" = "1" ]; then
  # A key that cannot sign SHOULD retry: the failures this retry was written for (a throttled
  # provider token, a 5xx) look identical here and do come back.
  if [ "${ALARMS:-0}" -eq 0 ]; then
    printf '  \033[31mFAIL\033[0m a signing failure gave up immediately; transient APNs errors would never retry\n'
    exit 1
  fi
  printf '  \033[32mok\033[0m   a failing key still retries (next attempt in ~%ss)\n' "${NEXT_IN:-?}"

  # The assertion with teeth. A flat re-arm and a counted one are indistinguishable on the
  # FIRST retry, because the first backoff is PUSH_RETRY_MS either way. What separates them is
  # that the counted one persisted an attempt number, which is the only reason it can ever
  # stop. No counter means no budget means the loop is unbounded again.
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

# The token is refused upstream now, which is what makes the two guards belt-and-braces rather
# than the mechanism: with nothing stored, `alarm`'s target list is provably empty. Assert that
# directly, because it is the invariant the alarm assertion below now rests on.
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
