#!/bin/bash
# Smoke matrix for mushroom-files against a running `wrangler dev`.
#
#   Terminal 1:  npx wrangler d1 migrations apply mushroom-files --local
#                npx wrangler dev --persist-to ../.wrangler-dev-state \
#                  --var ACTIVATIONS_PER_HOUR_PER_IP:1000
#
# The --var is required, as for mushroom-messaging: the default is 20 activations an hour, and a
# second run within the hour would hit 429.
#   Terminal 2:  ./test.sh
#
# By default this seeds a licence and a device straight into the local D1, so it runs with no
# Gumroad key and touches nothing of the user's. Set MUSHROOM_TEST_LICENSE to a real key to also
# exercise live activation (increment_uses_count=false, so it costs no seat).
set -uo pipefail

BASE="${BASE:-http://localhost:8787}"
STATE="${STATE:-../.wrangler-dev-state}"
LICENSE="${MUSHROOM_TEST_LICENSE:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-local-test-admin-token}"
PASS=0
FAIL=0

# Database access has two backends, because this is also the on-prem conformance suite.
#
#   ADMIN_SOCK unset -> `wrangler dev`, the hosted reference environment.
#   ADMIN_SOCK set   -> a self-hosted workerd box (see selfhost/), which has no wrangler and no
#                       account to reach. Same SQL, posted to the unix-socket admin route.
#
# The self-hosted branch prints `[{"results": [...]}]` exactly as `wrangler d1 execute --json`
# does, indent and all, because callers below grep it for things like '"n": 5'. That keeps every
# assertion identical between the two runs.
ADMIN_SOCK="${ADMIN_SOCK:-}"

d1() {
  if [ -n "$ADMIN_SOCK" ]; then
    python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1], "params": []}))' "$1" |
      curl -s --unix-socket "$ADMIN_SOCK" -X POST http://local/_selfhost/sql \
           -H 'content-type: application/json' --data-binary @- |
      python3 -c 'import json,sys; print(json.dumps([{"results": json.load(sys.stdin)["results"]}], indent=2))'
  else
    npx wrangler d1 execute mushroom-files --local --persist-to "$STATE" --command "$1" "${@:2}"
  fi
}

ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s (%s)\n' "$1" "$2"; }
want() { # want <label> <expected-status> <actual-status>
  [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected $2, got $3"
}

status() { # status <curl args...>  -> prints http status
  curl -s -o /tmp/mf-body -w '%{http_code}' "$@"
}

echo "==> mushroom-files smoke matrix against $BASE"

# Is there a schema? With no tables, most of what follows answers 500 with no hint why, which is
# what a deleted state directory looks like. `licenses` comes from the first migration, so its
# absence means none have run.
if ! d1 "SELECT 1 FROM licenses LIMIT 1" >/dev/null 2>&1; then
  echo "The local database has no tables. Apply the migrations first:"
  if [ -n "$ADMIN_SOCK" ]; then
    echo "  (a self-hosted box applies them itself on first request; is workerd running?)"
  else
    echo "  npx wrangler d1 migrations apply mushroom-files --local --persist-to $STATE"
  fi
  exit 1
fi

# ---------------------------------------------------------------- unauthenticated
# A self-hosted root redirects to BRAND_URL, or 404s when the box names nobody.
ROOT=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")
if [ -n "$ADMIN_SOCK" ] && [ "$ROOT" = 404 ]; then want "GET / is 404 (no BRAND_URL)" 404 "$ROOT"
else want "GET / redirects" 302 "$ROOT"; fi
want "unknown path is 404"            404 "$(status "$BASE/nope")"
want "unknown share token is 404"     404 "$(status "$BASE/f/doesnotexist")"
want "list without a token is 401"    401 "$(status "$BASE/v1/files")"
want "create without a token is 401"  401 "$(status -X POST "$BASE/v1/files")"
want "activate with junk body is 400" 400 "$(status -X POST -H 'content-type: application/json' -d 'not json' "$BASE/v1/devices/activate")"
# With ENROLLMENT_HASHES="*" there's no such thing as a bad key: the box takes any string. A 403
# there would test the opposite of the configuration, so say so and move on.
if [ "${OPEN_ENROLLMENT:-0}" = "1" ]; then
  printf '  \033[33mskip\033[0m bad-key rejection: this box enrols any key (ENROLLMENT_HASHES=*)\n'
else
want "activate with bad key is 403"   403 "$(status -X POST -H 'content-type: application/json' -d '{"license_key":"NOT-A-REAL-KEY"}' "$BASE/v1/devices/activate")"
fi

# ---------------------------------------------------------------- get a device token
if [ -n "$LICENSE" ]; then
  ACT=$(curl -s -X POST -H 'content-type: application/json' \
    -d "{\"license_key\":\"$LICENSE\",\"device_name\":\"test.sh\"}" "$BASE/v1/devices/activate")
  TOKEN=$(printf '%s' "$ACT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
  if [ -z "$TOKEN" ]; then bad "activate returns a token" "$ACT"; echo "  $PASS passed, $FAIL failed"; exit 1; fi
  ok "activate returns a token (live Gumroad)"
  want "a second activation also works" 201 \
    "$(status -X POST -H 'content-type: application/json' -d "{\"license_key\":\"$LICENSE\"}" "$BASE/v1/devices/activate")"
else
  # No real key: seed the rows the activation path would have written. Everything after
  # this point is identical either way, which is the point.
  TOKEN="test-token-$$"
  HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
  NOW=$(date +%s)
  d1 "INSERT OR REPLACE INTO licenses (license_hash, status, checked_at, created_at)
      VALUES ('testlicensehash', 'active', $NOW, $NOW);
      INSERT OR REPLACE INTO devices (id, license_hash, token_hash, name, created_at, last_seen_at)
      VALUES ('test-device', 'testlicensehash', '$HASH', 'test.sh', $NOW, $NOW);" >/dev/null 2>&1
  ok "seeded a local licence and device (set MUSHROOM_TEST_LICENSE to test activation too)"
fi

AUTH=(-H "authorization: Bearer $TOKEN")
want "a bogus bearer token is 401" 401 \
  "$(status -H 'authorization: Bearer nonsense' "$BASE/v1/files")"

# ---------------------------------------------------------------- validation
# Archives and disk images are allowed since 1.26.0. Created and deleted again rather than
# left behind: a pending row holds a file slot and its declared bytes for an hour.
for PAIR in 'x.zip application/zip' 'x.dmg application/x-apple-diskimage'; do
  set -- $PAIR
  MADE=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"name\":\"$1\",\"size\":10,\"content_type\":\"$2\"}" "$BASE/v1/files")
  MADE_ID=$(printf '%s' "$MADE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
  [ -n "$MADE_ID" ] && ok "create accepts $2" || bad "create accepts $2" "$MADE"
  [ -n "$MADE_ID" ] && curl -s -o /dev/null -X DELETE "${AUTH[@]}" "$BASE/v1/files/$MADE_ID"
done
want "create with a malformed content_type is 400" 400 \
  "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' \
     -d '{"name":"x.bin","size":10,"content_type":"not a mime type"}' "$BASE/v1/files")"
# An interior newline is what the type regex really guards: this value reaches the plain-text
# abuse-report email, and .trim() only touches the ends.
want "create with a newline in content_type is 400" 400 \
  "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' \
     -d '{"name":"x.bin","size":10,"content_type":"application/x\nType: forged"}' "$BASE/v1/files")"
want "create with a JSON null body is 400, not 500" 400 \
  "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' -d 'null' "$BASE/v1/files")"
want "create over the size cap is 413" 413 \
  "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' \
     -d '{"name":"big.pdf","size":999999999,"content_type":"application/pdf"}' "$BASE/v1/files")"
want "create with size 0 is 400" 400 \
  "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' \
     -d '{"name":"e.pdf","size":0,"content_type":"application/pdf"}' "$BASE/v1/files")"

# ---------------------------------------------------------------- happy path
printf '%%PDF-1.4\n%s\n' "$(head -c 200 /dev/zero | tr '\0' 'x')" > /tmp/mf-test.pdf
SIZE=$(wc -c < /tmp/mf-test.pdf | tr -d ' ')
CREATE=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"name\":\"report.pdf\",\"size\":$SIZE,\"content_type\":\"application/pdf\"}" "$BASE/v1/files")
ID=$(printf '%s' "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
STOKEN=$(printf '%s' "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
[ -n "$ID" ] && ok "create returns an id and token" || bad "create" "$CREATE"

want "download before upload is 404" 404 "$(status "$BASE/f/$STOKEN")"

# Send a body of a different length rather than forging the header: curl computes
# content-length itself, and a hand-set one that disagrees with the body stalls the connection
# (and can take the dev server down).
printf '%%PDF-1.4\n%s\n' "$(head -c 400 /dev/zero | tr '\0' 'y')" > /tmp/mf-wrong.pdf
want "upload of the wrong length is 400" 400 \
  "$(status -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-wrong.pdf "$BASE/v1/files/$ID/content")"
want "chunked upload with no content-length is 411" 411 \
  "$(status -X PUT "${AUTH[@]}" -H 'transfer-encoding: chunked' --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID/content")"

want "upload succeeds" 200 \
  "$(status -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID/content")"
want "second upload is 409" 409 \
  "$(status -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID/content")"

# ---------------------------------------------------------------- download
want "download works" 200 "$(status "$BASE/f/$STOKEN")"
HEADERS=$(curl -s -D - -o /dev/null "$BASE/f/$STOKEN")
grep -qi 'content-type: application/octet-stream' <<<"$HEADERS" \
  && ok "served as octet-stream" || bad "served as octet-stream" "$(grep -i '^content-type' <<<"$HEADERS")"
grep -qi 'content-disposition: attachment' <<<"$HEADERS" \
  && ok "served as an attachment" || bad "served as an attachment" "missing"
grep -qi 'x-content-type-options: nosniff' <<<"$HEADERS" \
  && ok "nosniff is set" || bad "nosniff is set" "missing"
cmp -s /tmp/mf-body /tmp/mf-test.pdf && ok "bytes round-trip intact" || bad "bytes round-trip" "differ"
want "range request is 206" 206 "$(status -H 'range: bytes=0-15' "$BASE/f/$STOKEN")"

# ---------------------------------------------------------------- the receive page
# One URL, two answers. A navigating browser gets the page that can decrypt; the page's own
# fetch, curl and everything else send */* and get the bytes. Backwards, recipients download
# ciphertext they can't open, or the page fetches itself.
PAGE=$(curl -s -H 'accept: text/html,application/xhtml+xml' "$BASE/f/$STOKEN")
grep -q 'crypto.subtle.decrypt' <<<"$PAGE" \
  && ok "a browser gets the receive page" || bad "a browser gets the receive page" "no decrypt in body"
PAGE_HEADERS=$(curl -s -D - -o /dev/null -H 'accept: text/html' "$BASE/f/$STOKEN")
grep -qi 'content-type: text/html' <<<"$PAGE_HEADERS" \
  && ok "the page is served as html" || bad "the page is served as html" "$(grep -i '^content-type' <<<"$PAGE_HEADERS")"
grep -qi "connect-src 'self'" <<<"$PAGE_HEADERS" \
  && ok "the page cannot talk to anywhere else" || bad "connect-src is locked down" "missing"
curl -s -o /tmp/mf-plain -H 'accept: */*' "$BASE/f/$STOKEN"
cmp -s /tmp/mf-plain /tmp/mf-test.pdf \
  && ok "curl still gets the bytes" || bad "curl still gets the bytes" "differ"
want "HEAD is unaffected by accept" 200 "$(status -I -H 'accept: text/html' "$BASE/f/$STOKEN")"

# The format the page and the Mac have to agree on, byte for byte.
if node "$(dirname "$0")/vector.mjs" > /tmp/mf-vector 2>&1; then
  ok "the sealed-file vector matches CryptoKit"
else
  bad "the sealed-file vector matches CryptoKit" "$(tail -3 /tmp/mf-vector | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- magic bytes
CREATE2=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d '{"name":"fake.png","size":20,"content_type":"image/png"}' "$BASE/v1/files")
ID2=$(printf '%s' "$CREATE2" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
head -c 20 /dev/zero | tr '\0' 'M' > /tmp/mf-fake.png
want "a non-PNG claiming image/png is 415" 415 \
  "$(status -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-fake.png "$BASE/v1/files/$ID2/content")"

# Sealed bytes match no signature, so the sniff must stand down for them or every sealed upload
# is refused. Same body, same declared type, one header.
CREATE2B=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d '{"name":"sealed.png","size":20,"content_type":"image/png"}' "$BASE/v1/files")
ID2B=$(printf '%s' "$CREATE2B" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
want "the same bytes are accepted when sealed" 200 \
  "$(status -X PUT "${AUTH[@]}" -H 'x-mushroom-encrypted: 1' --data-binary @/tmp/mf-fake.png "$BASE/v1/files/$ID2B/content")"

# ---------------------------------------------------------------- list and delete
LIST=$(curl -s "${AUTH[@]}" "$BASE/v1/files")
grep -q 'report.pdf' <<<"$LIST" && ok "list shows the file" || bad "list shows the file" "$LIST"
grep -q 'license_hash\|token_hash\|object_key' <<<"$LIST" \
  && bad "list leaks internals" "$LIST" || ok "list leaks no internals"

want "delete works"        200 "$(status -X DELETE "${AUTH[@]}" "$BASE/v1/files/$ID")"
want "delete is idempotent" 200 "$(status -X DELETE "${AUTH[@]}" "$BASE/v1/files/$ID")"
want "deleted link is 410"  410 "$(status "$BASE/f/$STOKEN")"
want "delete of an unknown id is 404" 404 "$(status -X DELETE "${AUTH[@]}" "$BASE/v1/files/00000000-0000-0000-0000-000000000000")"

# ---------------------------------------------------------------- expiry and cron
CREATE3=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"name\":\"old.pdf\",\"size\":$SIZE,\"content_type\":\"application/pdf\"}" "$BASE/v1/files")
ID3=$(printf '%s' "$CREATE3" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
STOKEN3=$(printf '%s' "$CREATE3" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
curl -s -o /dev/null -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID3/content"
# Backdating the row is the only practical way to test a 24-hour rule. Backdate by a minute,
# not to the epoch: that's also past the 7-day tombstone cutoff, so the sweep would expire and
# then delete the row, and the check below would read a correct sweep as broken.
d1 "UPDATE files SET expires_at = $(( $(date +%s) - 60 )) WHERE id = '$ID3'" >/dev/null 2>&1
want "an expired link is 410" 410 "$(status "$BASE/f/$STOKEN3")"

# The handler works in ctx.waitUntil, so the response returns before the D1 writes land;
# reading at once would race them and report a working sweep as broken.
#
# workerd has no cron, so on a self-hosted box a systemd timer calls the admin route, which
# awaits the waitUntil promises before answering. The sleep is harmless there, and one code path
# is worth more.
if [ -n "$ADMIN_SOCK" ]; then
  curl -s -o /dev/null --unix-socket "$ADMIN_SOCK" -X POST http://local/_selfhost/cron
else
  curl -s -o /dev/null "$BASE/cdn-cgi/handler/scheduled"
fi
sleep 2
LEFT=$(d1 "SELECT state FROM files WHERE id = '$ID3'" --json 2>/dev/null | grep -c '"expired"')
[ "$LEFT" -ge 1 ] && ok "cron marked the row expired" || bad "cron marked the row expired" "still not expired"

# ---------------------------------------------------------------- abuse reports
#
# Needs TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA (Cloudflare's documented
# always-passes test secret) in .dev.vars, and any dummy-shaped token. The always-fails secret
# is 2x00...AA, for checking the rejection path by hand.
#
# Skipped on a self-hosted box, a real absence: abuse reporting needs Turnstile and an email
# binding, and a box with no outbound network has neither (every report answers 403 bot_check,
# as `turnstileOK` can't reach Cloudflare). deploy/README.md tells self-hosters it won't work.
#
# Reported as skipped rather than failing, for the same reason APPSTORE_APP_APPLE_ID is set in
# the on-prem config: thirteen permanently red assertions is a differential people stop reading.
#
# The body below isn't re-indented, to keep the skip a two-line diff.
ORIGIN='origin: https://www.getmushroom.app'
REPORT=$BASE/v1/abuse-reports
DUMMY=XXXX.DUMMY.TOKEN.XXXX

# A file to report, uploaded so it's 'ready' and findable by token.
#
# Created outside the skip below: the owner-actions section deletes this same file and asserts
# its link then 410s, so skipping it would break two unrelated assertions.
CREATE4=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"name\":\"reported.pdf\",\"size\":$SIZE,\"content_type\":\"application/pdf\"}" "$BASE/v1/files")
ID4=$(printf '%s' "$CREATE4" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
STOKEN4=$(printf '%s' "$CREATE4" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
curl -s -o /dev/null -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID4/content"
SHARE="https://files.getmushroom.app/f/$STOKEN4"

if [ -n "$ADMIN_SOCK" ]; then
  printf '  \033[33mskip\033[0m abuse reporting: needs Turnstile and email, which a self-hosted box has neither of\n'
else

# Every field is passed explicitly. A second -F for the same name doesn't override the first:
# multipart keeps both and form.get() returns the earlier, so "invalid input" cases would send
# valid input.
# --form-string, not -F: -F reads a value starting with "<" from a file and "@" as an upload,
# so -F 'name=<script>...' sends nothing and the XSS case tests nothing.
report() { # report <share_url> [reason] [name] [email] [details]
  curl -s -o /tmp/mf-body -w '%{http_code}' -X POST -H "$ORIGIN" \
    --form-string "share_url=$1" --form-string "reason=${2-malware}" \
    --form-string "name=${3-Reporter}" --form-string "email=${4-r@example.com}" \
    --form-string "details=${5-please look}" \
    --form-string "cf-turnstile-response=$DUMMY" "$REPORT"
}

want "report from a foreign origin is 403" 403 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'origin: https://evil.example' \
     -F "share_url=$SHARE" -F reason=malware -F name=x -F email=x@y.z \
     -F "cf-turnstile-response=$DUMMY" "$REPORT")"
want "report with no turnstile token is 403" 403 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$ORIGIN" \
     -F "share_url=$SHARE" -F reason=malware -F name=x -F email=x@y.z "$REPORT")"
want "report with a junk share url is 400" 400 "$(report 'https://example.com/f/nope')"
# Every link the app hands out ends in #key; the form must take it as pasted. An unissued token,
# so no row lands on $SHARE's file and the counts below stay exact: 200 here (not 400) is the parse.
want "report of a link with its #key is accepted" 200 \
  "$(report "https://files.getmushroom.app/f/BBBBBBBBBBBBBBBBBBBBBB#c2VjcmV0LWtleQ")"
want "an oversized report is refused before parsing" 413 \
  "$(report "$SHARE" malware Reporter r@example.com "$(head -c 20000 /dev/zero | tr '\0' x)")"
want "report with a bad reason is 400"     400 "$(report "$SHARE" nonsense)"
want "report with no name is 400"          400 "$(report "$SHARE" malware "")"
want "report with no email is 400"         400 "$(report "$SHARE" malware Reporter "")"

want "a valid report is accepted" 200 "$(report "$SHARE")"
grep -q 'reviewed' /tmp/mf-body && ok "report reply is the generic one" || bad "report reply" "$(cat /tmp/mf-body)"
REAL_BODY=$(cat /tmp/mf-body)

# The point: a link that doesn't exist must be indistinguishable from one that does.
FAKE="https://files.getmushroom.app/f/AAAAAAAAAAAAAAAAAAAAAA"

# A delta across the report, not an absolute row count: `--persist-to` keeps state between
# runs, so an absolute count fails on a second run and looks like a security regression. The
# two checks below scope to a file id created this run.
reports_now() {
  d1 "SELECT COUNT(*) AS n FROM abuse_reports" --json 2>/dev/null | grep -o '"n": [0-9]*' | grep -o '[0-9]*'
}
BEFORE_FAKE=$(reports_now)
want "an unknown share link is also 200" 200 "$(report "$FAKE")"
[ "$(cat /tmp/mf-body)" = "$REAL_BODY" ] \
  && ok "unknown link is byte-identical to a real one" \
  || bad "unknown link reveals existence" "$(cat /tmp/mf-body)"
AFTER_FAKE=$(reports_now)
[ "$AFTER_FAKE" = "$BEFORE_FAKE" ] && ok "the unknown link stored nothing" \
  || bad "unknown link stored a row" "rows went $BEFORE_FAKE to $AFTER_FAKE"

want "a duplicate report is accepted" 200 "$(report "$SHARE")"
DUPES=$(d1 "SELECT COUNT(*) AS n FROM abuse_reports WHERE file_id = '$ID4'" --json 2>/dev/null | grep -o '"n": [0-9]*' | grep -o '[0-9]*')
[ "$DUPES" = "1" ] && ok "the duplicate stored nothing" || bad "duplicate stored a second row" "rows=$DUPES"

# A different reason on the same file is new information and should store.
want "a different reason on the same file is accepted" 200 "$(report "$SHARE" phishing)"
TWO=$(d1 "SELECT COUNT(*) AS n FROM abuse_reports WHERE file_id = '$ID4'" --json 2>/dev/null | grep -o '"n": [0-9]*' | grep -o '[0-9]*')
[ "$TWO" = "2" ] && ok "a new reason does store" || bad "new reason not stored" "rows=$TWO"

# Reporter text is stored raw and escaped at render time; assert it isn't executable anywhere
# it's echoed.
report "$SHARE" copyright '<script>alert(1)</script>' x@y.z >/dev/null
grep -q "script" <<<"$(d1 "SELECT reporter_name FROM abuse_reports WHERE reason='copyright'" --json 2>/dev/null)" \
  && ok "reporter text stored verbatim (escaped on render)" || bad "reporter text" "not stored"
fi

# ---------------------------------------------------------------- owner actions
# A self-hosted box answers admin only on its socket, so the same requests go there.
# `${AS[@]+...}` because bash 3.2 calls an empty array unbound under `set -u`.
if [ -n "$ADMIN_SOCK" ]; then
  ABASE=http://local; AS=(--unix-socket "$ADMIN_SOCK")
  want "admin over http is 404 on a self-hosted box, even with the token" 404 \
    "$(status -X POST -H "authorization: Bearer $ADMIN_TOKEN" -d '{}' "$BASE/admin/files/delete")"
else
  ABASE=$BASE; AS=()
fi
want "admin without a token is 401"   401 "$(status ${AS[@]+"${AS[@]}"} -X POST -H 'content-type: application/json' -d '{}' "$ABASE/admin/files/delete")"
want "admin with a wrong token is 401" 401 "$(status ${AS[@]+"${AS[@]}"} -X POST -H 'authorization: Bearer wrong' -d '{}' "$ABASE/admin/files/delete")"
want "GET on an admin path never acts" 405 "$(status ${AS[@]+"${AS[@]}"} "$ABASE/admin/files/delete")"
want "unknown admin path is 404"       404 "$(status ${AS[@]+"${AS[@]}"} -X POST -H "authorization: Bearer $ADMIN_TOKEN" -d '{}' "$ABASE/admin/nope")"

ADMIN=(-H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json')
want "admin delete of an unknown file is 404" 404 \
  "$(status ${AS[@]+"${AS[@]}"} -X POST "${ADMIN[@]}" -d '{"file_id":"00000000-0000-0000-0000-000000000000"}' "$ABASE/admin/files/delete")"
want "admin deletes the reported file" 200 \
  "$(status ${AS[@]+"${AS[@]}"} -X POST "${ADMIN[@]}" -d "{\"file_id\":\"$ID4\"}" "$ABASE/admin/files/delete")"
want "the reported link is now 410" 410 "$(status "$BASE/f/$STOKEN4")"

# Block: one more live file, then block the licence and confirm it is gone and uploads stop.
CREATE5=$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"name\":\"survivor.pdf\",\"size\":$SIZE,\"content_type\":\"application/pdf\"}" "$BASE/v1/files")
ID5=$(printf '%s' "$CREATE5" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
curl -s -o /dev/null -X PUT "${AUTH[@]}" --data-binary @/tmp/mf-test.pdf "$BASE/v1/files/$ID5/content"
LICHASH=$(d1 "SELECT license_hash FROM files WHERE id = '$ID5'" --json 2>/dev/null | grep -o '"license_hash": "[^"]*"' | cut -d'"' -f4)

want "admin blocks the licence" 200 \
  "$(status ${AS[@]+"${AS[@]}"} -X POST "${ADMIN[@]}" -d "{\"license_hash\":\"$LICHASH\"}" "$ABASE/admin/licenses/block")"
GONE=$(d1 "SELECT state FROM files WHERE id = '$ID5'" --json 2>/dev/null | grep -c '"deleted"')
[ "$GONE" -ge 1 ] && ok "block deleted the licence's live files" || bad "block left files live" "state not deleted"
# The device token was revoked with the licence, so the app is locked out at the door.
want "a blocked licence's token is dead" 401 "$(status "${AUTH[@]}" "$BASE/v1/files")"


# ---------------------------------------------------------------- app store credential
# No real AppTransaction JWS is obtainable outside a TestFlight or App Store install, so
# these pin the SHAPE of the credential branch: which inputs are refused, and with which
# code. The happy path is only reachable from TestFlight.
want "activate with neither credential is 400" 400 \
  "$(status -X POST -H 'content-type: application/json' -d "{\"device_name\":\"t\"}" "$BASE/v1/devices/activate")"
want "activate with BOTH credentials is 400"   400 \
  "$(status -X POST -H 'content-type: application/json' -d "{\"license_key\":\"K\",\"app_transaction\":\"aaa.bbb.ccc\"}" "$BASE/v1/devices/activate")"
want "malformed app_transaction is 403"        403 \
  "$(status -X POST -H 'content-type: application/json' -d "{\"app_transaction\":\"not a jws\"}" "$BASE/v1/devices/activate")"
want "oversize app_transaction is 400"         400 \
  "$(status -X POST -H 'content-type: application/json' -d "{\"app_transaction\":\"$(head -c 13000 /dev/zero | tr '\0' 'a').b.c\"}" "$BASE/v1/devices/activate")"
# A body of literal `null` parses fine, so the try/catch around request.json() never fires.
want "activate with a null body is 400"        400 \
  "$(status -X POST -H 'content-type: application/json' -d 'null' "$BASE/v1/devices/activate")"
want "activate with an array body is 400"      400 \
  "$(status -X POST -H 'content-type: application/json' -d '[]' "$BASE/v1/devices/activate")"
# A well-formed JWS reaches the verifier and is refused on the signature, NOT on config.
# 503 here means APPSTORE_APP_APPLE_ID is unset and the whole path is dark.
want "forged but well-formed JWS is 403"       403 \
  "$(status -X POST -H 'content-type: application/json' -d "{\"app_transaction\":\"aaa.bbb.ccc\"}" "$BASE/v1/devices/activate")"

# The Setapp branch ships BEFORE Setapp is configured, and these are the proof it is inert: with
# no SETAPP_CLIENT_ID/SECRET set every setapp activation answers 503 `setapp_unconfigured`, the
# soft code neither client latches. Must agree with mushroom-messaging's copy of this block, or a
# Setapp subscriber keeps one hosted feature and loses the other.
#
# The JSON is assembled with SINGLE quotes around the braces. Bash brace-expands an unquoted
# `{a,b}` into two words, and inside a `$(...)` the escaping is re-parsed, so the obvious spelling
# sends a malformed body and every assertion here reads 400 for the wrong reason.
setapp_json='{"setapp_code":"CODE","device_name":"t"}'
want "setapp with no secrets is 503"           503 \
  "$(status -X POST -H 'content-type: application/json' -d "$setapp_json" "$BASE/v1/devices/activate")"
want "and it says setapp_unconfigured"         "setapp_unconfigured" \
  "$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("code",""))' < /tmp/mf-body 2>/dev/null)"

# Exactly one of the three, counted rather than compared: picking a winner silently is how one
# build ends up authenticating as another's licence.
both_json='{"setapp_code":"C","license_key":"K","device_name":"t"}'
want "setapp plus a key is 400"                400 \
  "$(status -X POST -H 'content-type: application/json' -d "$both_json" "$BASE/v1/devices/activate")"
big_json='{"setapp_code":"'"$(head -c 600 /dev/zero | tr '\0' 'x')"'","device_name":"t"}'
want "oversize setapp_code is 400"             400 \
  "$(status -X POST -H 'content-type: application/json' -d "$big_json" "$BASE/v1/devices/activate")"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
