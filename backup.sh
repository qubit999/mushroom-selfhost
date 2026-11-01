#!/bin/bash
# Nightly backup of the databases.
#
# The SQLite trees only, not the blobs. Shared files expire within a day, so restoring them is
# pointless, and rows without bytes show the "this link has expired" page, which is correct.
#
# `sqlite3 .backup`, never `cp`: these files are live with a WAL beside them, and a mid-write copy
# restores corrupt. `.backup` takes a consistent online snapshot without stopping workerd, the
# same rule as the app's BackupService (CLAUDE.md section 9, VACUUM INTO).
#
# Retention only removes directories this script created, matched by name. The destination is
# the operator's own folder and may hold anything.
set -uo pipefail

# Before anything is created. `sqlite3 .backup` writes 0644 under the default umask, and these
# databases aren't all ciphertext: bodies are sealed and device tokens hashed, but `invites.code`
# is the live invite code in clear and `devices.apns_token` a real push token. Anyone else with a
# shell could read both. This applies the intent of the `chmod 600` on secrets.env below to the
# whole backup.
umask 077

STATE_ROOT="${STATE_ROOT:-/var/lib/mushroom}"
DEST="${DEST:-/var/backups/mushroom}"
KEEP="${KEEP:-3}"
# Overridable so a run is reproducible and the caller can label a restore point. systemd passes
# nothing and gets the current time.
STAMP="${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "mushroom-backup: sqlite3 not found" >&2
  exit 1
fi

OUT="$DEST/mushroom-backup-$STAMP"
mkdir -p "$OUT" || exit 1

count=0
failed=0
# Both durable-object directories: they hold the databases and the message ciphertext, so these
# two trees are the whole backup.
while IFS= read -r db; do
  rel="${db#"$STATE_ROOT"/}"
  target="$OUT/$rel"
  mkdir -p "$(dirname "$target")"
  if sqlite3 "$db" ".backup '$target'" 2>/dev/null; then
    count=$((count + 1))
  else
    echo "mushroom-backup: could not back up $db" >&2
    failed=1
  fi
done < <(find "$STATE_ROOT" -type f -name '*.sqlite' 2>/dev/null)

# The Docker deployment generates the durable-object uniqueKeys and admin token once and keeps
# them here (docker-entrypoint.sh). The loop above doesn't see them, and without them a restore is
# useless: a fresh box generates new keys, and a new uniqueKey makes every restored durable
# object unreachable, intact but unaddressable.
#
# Absent under systemd, where the keys are hand-written in config.capnp. Hence the test.
if [ -f "$STATE_ROOT/secrets.env" ]; then
  cp "$STATE_ROOT/secrets.env" "$OUT/secrets.env"
  chmod 600 "$OUT/secrets.env"
fi

if [ "$count" -eq 0 ]; then
  # An empty backup is worse than none because it looks like one. Don't keep it, and don't let
  # it count towards retention and push a real one out.
  echo "mushroom-backup: found no databases under $STATE_ROOT, refusing to keep an empty backup" >&2
  rm -rf "$OUT"
  exit 1
fi

# Retention: only directories with this script's name prefix, newest KEEP kept. Globbed by that
# prefix rather than `find -delete`, so nothing else in the operator's folder can be reached.
#
# No `mapfile` (bash 4+) or `head -n -N` (GNU-only), so this runs wherever someone needs it.
total=$(ls -1d "$DEST"/mushroom-backup-* 2>/dev/null | wc -l | tr -d ' ')
if [ "$total" -gt "$KEEP" ]; then
  ls -1d "$DEST"/mushroom-backup-* 2>/dev/null | sort | sed -n "1,$((total - KEEP))p" |
    while IFS= read -r old; do rm -rf "$old"; done
fi

echo "mushroom-backup: $count database(s) to $OUT"
exit "$failed"
