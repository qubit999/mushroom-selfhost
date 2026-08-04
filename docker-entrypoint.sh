#!/bin/sh
# Derive config.capnp, then hand off to workerd.
#
# Set as `entrypoint:` on the workerd service ONLY. The other three containers do not need a
# config and must not race this one writing the file.
#
# The config is derived by dev-config.sh rather than by a second sed block here, for the reason
# that script already gives: a second copy of the config is a second thing to keep in step, and
# a binding missing from config.capnp.example should go missing HERE too, where it gets noticed.
set -eu

cd /opt/mushroom

# ADMIN_TOKEN and the durable-object uniqueKeys are generated once and kept on the state volume.
#
# The uniqueKeys are why this file exists rather than the values being generated per start:
# changing a uniqueKey makes every existing durable object unreachable, so a fresh one on each
# restart would throw away the box's data every time it was restarted, silently, with the
# databases still sitting on disk.
#
# Generating them also removes three of the four CHANGE ME values from the operator's job, and
# removes the chance of a box running with ADMIN_TOKEN literally set to CHANGE-ME.
SECRETS=/var/lib/mushroom/secrets.env
if [ ! -f "$SECRETS" ]; then
  hex() { node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))'; }
  umask 077
  { echo "ADMIN_TOKEN=$(hex)"; echo "UNIQUE_KEY=$(hex)"; } > "$SECRETS"
  echo "mushroom: generated $SECRETS (admin token and durable-object keys). Back this up."
fi
. "$SECRETS"

# `${ENROLLMENT_HASHES-*}` below, with ONE dash and not two, and the difference is the whole
# enrolment posture of the box.
#
# Unset still means `*`, which is what .env.example ships and what shared/gumroad.js argues for:
# the Mac verified the key against Gumroad before it ever reached the Keychain, so a box that
# cannot reach Gumroad gains nothing by checking a list a human maintains by hand.
#
# But an operator who BLANKS the line, which is how somebody says "I have not decided yet" or
# "nobody", was getting `*` too, because `:-` cannot tell empty from unset. That is the opposite
# of what `enrolmentAllows` promises for an empty list (a 403, fail closed) and the opposite of
# what the person typing it meant. gumroad.js says "the container never gets there"; it did, and
# this is what makes that sentence true. An empty value now reaches the Worker as empty and the
# box refuses every activation until the operator finishes setting it up.

# The only value with no sensible default. It is baked into every share link the box hands out,
# so a box that guessed would hand out links to somewhere else. Refusing to start is a much
# better failure than serving links nobody can open.
if [ -z "${PUBLIC_BASE:-}" ]; then
  echo "mushroom: PUBLIC_BASE is not set. Copy .env.example to .env and fill it in." >&2
  exit 1
fi

# BIND=0.0.0.0 is not a loosening. 127.0.0.1 inside a container is the CONTAINER's loopback, so
# a published port would reach nothing; compose publishes these on the host's 127.0.0.1, and the
# network namespace is the boundary that the bind address was providing before.
#
# The sockets go in /run/mushroom rather than under the state dir (which is what dev-config.sh
# would default to), because the cron container reaches the two admin sockets through that shared
# volume and the blobd container serves its own from there.
# workerd does NOT unlink its unix sockets when it exits, and it does not replace a stale one on
# startup either: it dies with `Address already in use` and, under any restart policy, crash-loops
# on that forever. The sockets outlive the process because /run/mushroom is a shared volume, so
# this bites on the SECOND start and never the first, which is the worst way for it to show up.
#
# blobd.mjs already does this for its own socket. Doing it here is the same fix for the two
# workerd owns. Safe because exactly one workerd container owns these.
rm -f /run/mushroom/admin.sock /run/mushroom/files-admin.sock

STATE=/var/lib/mushroom \
SOCK=/run/mushroom/admin.sock \
FILES_SOCK=/run/mushroom/files-admin.sock \
BLOB_SOCK=/run/mushroom/blobd.sock \
BIND=0.0.0.0 \
ADMIN_TOKEN="$ADMIN_TOKEN" \
UNIQUE_KEY="$UNIQUE_KEY" \
PUBLIC_BASE="$PUBLIC_BASE" \
BRAND_URL="${BRAND_URL:-}" \
ENROLL="${ENROLLMENT_HASHES-*}" \
TEST_SQL="${SELFHOST_TEST_SQL:-0}" \
  ./dev-config.sh > config.capnp

exec "$@"
