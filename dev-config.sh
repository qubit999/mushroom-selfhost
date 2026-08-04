#!/bin/bash
# Print a config.capnp for a throwaway test box, on stdout.
#
# Derived from config.capnp.example with sed rather than written out again, deliberately: a
# second copy of the config is a second thing to keep in step, and the whole point of the
# differential run is that on-prem behaviour is not quietly different from what we ship. If a
# binding is missing here, it was missing in the example too, which is what we want to find out.
#
# Also the container's config generator (see docker-entrypoint.sh), for the same reason: a second
# deriver would be a second thing to keep in step. Every variable it needs and the test scripts do
# not is defaulted to reproduce today's output byte for byte, so `test.sh` is unaffected.
#
# The output MUST be written inside this directory, not into the state dir or /tmp: capnp
# resolves `import` relative to the importing file, and the config imports
# dist/*/modules.capnp. A config anywhere else fails to load with a bare
# "server never came up".
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
# Empty is the shipped default, and it is meaningful: the expired and removed pages then link
# nobody and the root answers 404, rather than a box that is not ours advertising us.
BRAND_URL="${BRAND_URL:-}"

# The listen address. Loopback is right for a test box and for systemd, where the proxy in front
# is on the same machine. A CONTAINER must set 0.0.0.0: 127.0.0.1 inside a container is the
# container's own loopback, and a published port then reaches nothing at all.
BIND="${BIND:-127.0.0.1}"

# Both default to exactly what config.capnp.example already says, so an unset caller gets the
# file unchanged in these two respects.
#
# UNIQUE_KEY seeds all three durable-object namespaces. Changing it makes existing data
# unreachable, so anything generating one has to persist it (docker-entrypoint.sh does).
ADMIN_TOKEN="${ADMIN_TOKEN:-CHANGE-ME}"
UNIQUE_KEY="${UNIQUE_KEY:-CHANGE-ME-mushroom}"

# A configured box has enrolled licences; an unconfigured one answers 503 to every activation,
# which is correct fail-closed behaviour but is not what the suites are trying to measure. So a
# test box is enrolled by default, with the hash of a documented throwaway key. Override ENROLL
# to enrol a real key when exercising activation by hand.
#
# ONE dash, matching docker-entrypoint.sh, and for a sharper reason than symmetry. An empty
# ENROLL means an operator deliberately blanked ENROLLMENT_HASHES, which has to reach the Worker
# as empty so `enrolmentAllows` refuses every activation. With `:-` it did not: empty read as
# unset and this line quietly enrolled the hash below, so blanking the list produced a box that
# accepted exactly one key, the throwaway one written in this file and published with it.
# Unset still means "nobody set this, it is a test box", which is what the default is for.
TEST_LICENCE_KEY="${TEST_LICENCE_KEY:-SELFHOST-TEST-LICENCE}"
ENROLL="${ENROLL-$(printf '%s' "$TEST_LICENCE_KEY" | tr '[:lower:]' '[:upper:]' | shasum -a 256 | cut -d' ' -f1)}"

# Test-only bindings, appended after each ADMIN_TOKEN. None of these are in the shipped example,
# and that is the point: a real box has no SQL route and no APNs key.
EXTRA=""
# The direct SQL route the test scripts use in place of `wrangler d1 execute`.
[ "${TEST_SQL:-0}" = "1" ] && EXTRA="$EXTRA (name = \"SELFHOST_TEST_SQL\", text = \"1\"),"
# A key that is present but cannot sign, which is alarm-test.sh's second scenario: it proves a
# failing push still retries AND that the retry has a counted budget it can exhaust.
[ "${BOGUS_APNS:-0}" = "1" ] && EXTRA="$EXTRA (name = \"APNS_KEY_P8\", text = \"not-a-real-key\"), (name = \"APNS_KEY_ID\", text = \"AAAA\"), (name = \"APNS_TEAM_ID\", text = \"BBBB\"),"

# workerd refuses to start if a `disk` service path does not exist, and says only
# `Directory named "do-messaging" not found`, which reaches the caller as "server never came
# up". Creating them here rather than in each caller keeps that failure from being rediscovered.
mkdir -p "$STATE/do-messaging" "$STATE/do-files" "$STATE/blobs"

# The listen addresses are anchored on `address = ` rather than on the bare host:port, so the
# tailscale examples in the comments above them are left saying what an operator should type
# rather than being rewritten into whatever this box happens to use.
#
# ADMIN_TOKEN and EXTRA are ONE substitution, not two: as two they fight, because the first one
# to run destroys the literal the second is anchored on. A token containing `#`, `&` or a
# backslash would break this; the generated ones are hex.
sed -e "s#/var/lib/mushroom/do-messaging#$STATE/do-messaging#" \
    -e "s#/var/lib/mushroom/do-files#$STATE/do-files#" \
    -e "s#unix:/run/mushroom/admin.sock#unix:$SOCK#" \
    -e "s#unix:/run/mushroom/files-admin.sock#unix:$FILES_SOCK#" \
    -e "s#unix:/run/mushroom/blobd.sock#unix:$BLOB_SOCK#" \
    -e "s#address = \"127.0.0.1:8080\"#address = \"$BIND:$PORT\"#" \
    -e "s#address = \"127.0.0.1:8081\"#address = \"$BIND:$FILES_PORT\"#" \
    -e "s#https://CHANGE-ME.example.ts.net#$PUBLIC_BASE#" \
    -e "s#(name = \"BRAND_URL\", text = \"\")#(name = \"BRAND_URL\", text = \"$BRAND_URL\")#" \
    -e "s#CHANGE-ME-mushroom-inbox#$UNIQUE_KEY-inbox#" \
    -e "s#CHANGE-ME-mushroom-files-sql#$UNIQUE_KEY-files-sql#" \
    -e "s#CHANGE-ME-mushroom-sql#$UNIQUE_KEY-sql#" \
    -e "s#(name = \"ENROLLMENT_HASHES\", text = \"[^\"]*\")#(name = \"ENROLLMENT_HASHES\", text = \"$ENROLL\")#g" \
    -e "s#(name = \"ADMIN_TOKEN\", text = \"CHANGE-ME\"),#(name = \"ADMIN_TOKEN\", text = \"$ADMIN_TOKEN\"),$EXTRA#g" \
    config.capnp.example
