#!/bin/bash
# Nightly backup of the databases.
#
# The SQLite trees only, NOT the blobs. Every shared file expires within a day, so restoring one
# is pointless, and a restore that has rows but no bytes degrades to the "this link has expired"
# page, which is the correct thing for it to say.
#
# `sqlite3 .backup` and never `cp`: these files are live, with a WAL beside them, and a copy
# taken mid-write restores as a corrupt database. `.backup` is an online backup that takes a
# consistent snapshot without stopping workerd. This is the same rule the app's own BackupService
# follows (CLAUDE.md section 9), which uses VACUUM INTO for the same reason.
#
# Retention only ever removes directories THIS script created, matched by name. The destination
# is the operator's own folder and may hold anything else.
set -uo pipefail

# Before anything is created. `sqlite3 .backup` writes 0644 under the default umask, and these
# databases are not as opaque as "it is all ciphertext anyway" suggests: message bodies are
# sealed and device tokens are stored as hashes, but `invites.code` is the live invite code in
# clear and `devices.apns_token` is a real push token. On a box where anyone else has a shell
# that is a readable copy of both. The `chmod 600` on secrets.env below already says what the
# intent is; this applies it to the directory and to every database in it.
umask 077

STATE_ROOT="${STATE_ROOT:-/var/lib/mushroom}"
DEST="${DEST:-/var/backups/mushroom}"
KEEP="${KEEP:-3}"
# Passed in rather than computed, so a run is reproducible and so the caller can label a restore
# point. systemd passes nothing and gets the current time.
STAMP="${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "mushroom-backup: sqlite3 not found" >&2
  exit 1
fi

OUT="$DEST/mushroom-backup-$STAMP"
mkdir -p "$OUT" || exit 1

count=0
failed=0
# Both durable-object directories: they hold the databases AND the message ciphertext, which is
# why the whole backup story is these two trees.
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

# The Docker deployment generates the durable-object uniqueKeys and the admin token once and
# keeps them here (docker-entrypoint.sh). They are not a database, so the loop above does not see
# them, and WITHOUT THEM A RESTORE IS USELESS: a fresh box generates new keys, and a new uniqueKey
# makes every durable object in the databases we just restored unreachable. The data would be
# sitting there, intact and unaddressable.
#
# Absent under systemd, where the keys are hand-written in config.capnp instead. Hence the test.
if [ -f "$STATE_ROOT/secrets.env" ]; then
  cp "$STATE_ROOT/secrets.env" "$OUT/secrets.env"
  chmod 600 "$OUT/secrets.env"
fi

if [ "$count" -eq 0 ]; then
  # An empty backup is worse than no backup, because it looks like one. Refuse to leave it
  # behind, and refuse to let it count towards retention and push a real one out.
  echo "mushroom-backup: found no databases under $STATE_ROOT, refusing to keep an empty backup" >&2
  rm -rf "$OUT"
  exit 1
fi

# Retention. Only directories matching the name this script writes, newest KEEP kept.
# Globbed by that exact prefix rather than `find -delete`, so nothing outside the pattern can be
# reached even though the destination is a folder the operator may keep other things in.
#
# No `mapfile` and no `head -n -N`: the first is bash 4+ and the second is GNU-only, and this
# should stay runnable wherever someone needs to check it.
total=$(ls -1d "$DEST"/mushroom-backup-* 2>/dev/null | wc -l | tr -d ' ')
if [ "$total" -gt "$KEEP" ]; then
  ls -1d "$DEST"/mushroom-backup-* 2>/dev/null | sort | sed -n "1,$((total - KEEP))p" |
    while IFS= read -r old; do rm -rf "$old"; done
fi

echo "mushroom-backup: $count database(s) to $OUT"
exit "$failed"
