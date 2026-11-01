#!/bin/bash
# Print a config.capnp for a throwaway test box, on stdout.
#
# Derived from config.capnp.example with sed, not written out again: a second copy is a second
# thing to keep in step, and the differential run exists to prove on-prem isn't quietly different
# from what we ship. A binding missing here is missing in the example too, which we want to know.
#
# Also the container's config generator (see docker-entrypoint.sh), for the same reason. Variables
# only the container needs default to reproducing the test output byte for byte, so `test.sh` is
# unaffected.
#
# Write the output inside this directory, not the state dir or /tmp: capnp resolves `import`
# relative to the importing file, and the config imports dist/*/modules.capnp. Anywhere else it
# fails with a bare "server never came up".
#
#   STATE=/tmp/box SOCK=/tmp/box.sock ./dev-config.sh > .test-$$.capnp
#   workerd serve .test-$$.capnp
set -euo pipefail
cd "$(dirname "$0")"

: "${STATE:?set STATE to a throwaway durable-object directory}"
: "${SOCK:?set SOCK to a throwaway unix socket path}"
PORT="${PORT:-8080}"
FILES_PORT="${FILES_PORT:-$((PORT + 1))}"
FILES_SOCK="${FILES_SOCK:-$STATE/files-admin.sock}"
BLOB_SOCK="${BLOB_SOCK:-$STATE/blobd.sock}"
PUBLIC_BASE="${PUBLIC_BASE:-http://127.0.0.1:$FILES_PORT}"
# Empty is the shipped default, on purpose: the expired and removed pages link nobody and the
# root answers 404, so a box that isn't ours doesn't advertise us.
BRAND_URL="${BRAND_URL:-}"

# The listen address. Loopback suits a test box and systemd, where the proxy is on the same
# machine. A container must set 0.0.0.0: its 127.0.0.1 is its own loopback, so a published port
# would reach nothing.
BIND="${BIND:-127.0.0.1}"

# ADMIN_TOKEN defaults to files-worker/test.sh's, since the workers refuse the example's
# placeholder. UNIQUE_KEY defaults to the example's.
#
# UNIQUE_KEY seeds all three durable-object namespaces. Changing it makes existing data
# unreachable, so anything generating one must persist it (docker-entrypoint.sh does).
ADMIN_TOKEN="${ADMIN_TOKEN:-local-test-admin-token}"
UNIQUE_KEY="${UNIQUE_KEY:-CHANGE-ME-mushroom}"

# An unconfigured box answers 503 to every activation, correct fail-closed behaviour but not what
# the suites measure. So a test box is enrolled by default with the hash of a documented throwaway
# key. Override ENROLL to enrol a real key when testing activation by hand.
#
# One dash, as in docker-entrypoint.sh, and not just for symmetry. An empty ENROLL means an
# operator blanked ENROLLMENT_HASHES, which must reach the Worker empty so `enrolmentAllows`
# refuses everything. With `:-`, empty reads as unset and enrols the hash below, so a blanked
# list would accept exactly one key: the throwaway published in this file. Unset still means
# "a test box", which is what the default is for.
TEST_LICENCE_KEY="${TEST_LICENCE_KEY:-SELFHOST-TEST-LICENCE}"
ENROLL="${ENROLL-$(printf '%s' "$TEST_LICENCE_KEY" | tr '[:lower:]' '[:upper:]' | shasum -a 256 | cut -d' ' -f1)}"

# Test-only bindings, appended after each ADMIN_TOKEN. None are in the shipped example, on
# purpose: a real box has no SQL route and no APNs key.
EXTRA=""
# The direct SQL route the test scripts use in place of `wrangler d1 execute`.
[ "${TEST_SQL:-0}" = "1" ] && EXTRA="$EXTRA (name = \"SELFHOST_TEST_SQL\", text = \"1\"),"
# A key that's present but can't sign, for alarm-test.sh's second scenario: a failing push still
# retries, and the retry has a counted budget it can exhaust.
[ "${BOGUS_APNS:-0}" = "1" ] && EXTRA="$EXTRA (name = \"APNS_KEY_P8\", text = \"not-a-real-key\"), (name = \"APNS_KEY_ID\", text = \"AAAA\"), (name = \"APNS_TEAM_ID\", text = \"BBBB\"),"

# Every value below lands in a sed replacement and then a capnp string, so a stray `"` ends the
# string (and can add a binding) and a `&` or `#` breaks the sed. Hand-typed ones are checked; the
# only one that can reasonably contain `&` is BRAND_URL, so that one is escaped instead.
check() {
  printf '%s\n' "$2" | grep -Eq "$3" && return 0
  echo "dev-config.sh: $1 is not valid here: $2" >&2
  exit 1
}
check PUBLIC_BASE "$PUBLIC_BASE" '^https?://[A-Za-z0-9.-]+(:[0-9]+)?$'
check BRAND_URL "$BRAND_URL" '^(https?://[^"\\[:space:]]+)?$'
check ENROLLMENT_HASHES "$ENROLL" '^(\*|[0-9a-fA-F[:space:],]*)$'
check ADMIN_TOKEN "$ADMIN_TOKEN" '^[A-Za-z0-9_-]+$'
check UNIQUE_KEY "$UNIQUE_KEY" '^[A-Za-z0-9_-]+$'
BRAND_SED=$(printf '%s' "$BRAND_URL" | sed 's/[&#]/\\&/g')

# workerd won't start if a `disk` service path is missing, saying only `Directory named
# "do-messaging" not found`, which callers see as "server never came up". Creating them here
# saves each caller rediscovering that.
mkdir -p "$STATE/do-messaging" "$STATE/do-files" "$STATE/blobs"

# Listen addresses are anchored on `address = `, not the bare host:port, so the tailscale
# examples in the comments above them keep saying what an operator should type.
#
# ADMIN_TOKEN and EXTRA are one substitution: as two, the first destroys the literal the second
# anchors on.
sed -e "s#/var/lib/mushroom/do-messaging#$STATE/do-messaging#" \
    -e "s#/var/lib/mushroom/do-files#$STATE/do-files#" \
    -e "s#unix:/run/mushroom/admin.sock#unix:$SOCK#" \
    -e "s#unix:/run/mushroom/files-admin.sock#unix:$FILES_SOCK#" \
    -e "s#unix:/run/mushroom/blobd.sock#unix:$BLOB_SOCK#" \
    -e "s#address = \"127.0.0.1:8080\"#address = \"$BIND:$PORT\"#" \
    -e "s#address = \"127.0.0.1:8081\"#address = \"$BIND:$FILES_PORT\"#" \
    -e "s#https://CHANGE-ME.example.ts.net#$PUBLIC_BASE#" \
    -e "s#(name = \"BRAND_URL\", text = \"\")#(name = \"BRAND_URL\", text = \"$BRAND_SED\")#g" \
    -e "s#CHANGE-ME-mushroom-inbox#$UNIQUE_KEY-inbox#" \
    -e "s#CHANGE-ME-mushroom-files-sql#$UNIQUE_KEY-files-sql#" \
    -e "s#CHANGE-ME-mushroom-sql#$UNIQUE_KEY-sql#" \
    -e "s#(name = \"ENROLLMENT_HASHES\", text = \"[^\"]*\")#(name = \"ENROLLMENT_HASHES\", text = \"$ENROLL\")#g" \
    -e "s#(name = \"ADMIN_TOKEN\", text = \"CHANGE-ME\"),#(name = \"ADMIN_TOKEN\", text = \"$ADMIN_TOKEN\"),$EXTRA#g" \
    config.capnp.example
