#!/bin/sh
# Derive config.capnp, then hand off to workerd.
#
# The `entrypoint:` of the workerd service only. The other three containers need no config and
# must not race this one writing it.
#
# dev-config.sh derives the config rather than a second sed block here, for the reason it gives:
# a second copy is a second thing to keep in step, and a binding missing from
# config.capnp.example should go missing here too, where it gets noticed.
set -eu

cd /opt/mushroom

# ADMIN_TOKEN and the durable-object uniqueKeys are generated once and kept on the state volume.
#
# The uniqueKeys are why: changing one makes every existing durable object unreachable, so fresh
# values per start would silently lose the box's data on every restart, databases still on disk.
#
# Generating them also takes three of the four CHANGE ME values off the operator, and rules out a
# box running with ADMIN_TOKEN literally CHANGE-ME.
SECRETS=/var/lib/mushroom/secrets.env
if [ ! -f "$SECRETS" ]; then
  hex() { node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))'; }
  umask 077
  { echo "ADMIN_TOKEN=$(hex)"; echo "UNIQUE_KEY=$(hex)"; } > "$SECRETS"
  echo "mushroom: generated $SECRETS (admin token and durable-object keys). Back this up."
fi
# Read as data, not sourced: anything that could write this file would otherwise get a shell here
# on the next start. Hex only, which is all this script ever writes.
secret() { sed -n "s/^$1=\([0-9a-f]\{64\}\)\$/\1/p" "$SECRETS"; }
ADMIN_TOKEN=$(secret ADMIN_TOKEN)
UNIQUE_KEY=$(secret UNIQUE_KEY)
if [ -z "$ADMIN_TOKEN" ] || [ -z "$UNIQUE_KEY" ]; then
  echo "mushroom: $SECRETS is not in the expected form. Restore it from your backup." >&2
  exit 1
fi

# No default for either: a guessed PUBLIC_BASE hands out links to somewhere else, and a guessed
# enrolment list either locks everyone out or lets anyone who can reach the box in.
if [ -z "${ENROLLMENT_HASHES:-}" ]; then
  echo "mushroom: ENROLLMENT_HASHES is not set. List your users' licence hashes in .env (see .env.example)." >&2
  exit 1
fi

if [ -z "${PUBLIC_BASE:-}" ]; then
  echo "mushroom: PUBLIC_BASE is not set. Copy .env.example to .env and fill it in." >&2
  exit 1
fi

# BIND=0.0.0.0 isn't a loosening. A container's 127.0.0.1 is its own loopback, so a published
# port would reach nothing; compose publishes on the host's 127.0.0.1, and the network namespace
# is now the boundary.
#
# Sockets go in /run/mushroom, not the state dir (dev-config.sh's default): the cron container
# reaches the two admin sockets through that shared volume. blobd serves its own from /run/blobd,
# a volume of its own, so it can't reach the admin sockets.
# workerd neither unlinks its unix sockets on exit nor replaces a stale one on startup: it dies
# with `Address already in use` and crash-loops under any restart policy. The shared volume
# outlives the process, so this bites on the second start, never the first.
#
# blobd.mjs does the same for its socket. Safe because exactly one workerd container owns these.
rm -f /run/mushroom/admin.sock /run/mushroom/files-admin.sock

STATE=/var/lib/mushroom \
SOCK=/run/mushroom/admin.sock \
FILES_SOCK=/run/mushroom/files-admin.sock \
BLOB_SOCK=/run/blobd/blobd.sock \
BIND=0.0.0.0 \
ADMIN_TOKEN="$ADMIN_TOKEN" \
UNIQUE_KEY="$UNIQUE_KEY" \
PUBLIC_BASE="$PUBLIC_BASE" \
BRAND_URL="${BRAND_URL:-}" \
ENROLL="$ENROLLMENT_HASHES" \
TEST_SQL="${SELFHOST_TEST_SQL:-0}" \
  ./dev-config.sh > config.capnp

exec "$@"
