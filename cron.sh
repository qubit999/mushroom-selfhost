#!/bin/bash
# The sweeps, driven by a systemd timer.
#
# workerd has no cron. `triggers.crons` is a Cloudflare platform feature and `scheduled()` never
# fires on its own here, so both Workers' sweeps have to be called in. A timer was chosen over a
# self-arming Durable Object alarm because `systemctl list-timers` makes a sweep that stopped
# running visible, and a silently-not-running sweep is exactly the class of bug this codebase
# keeps paying for.
#
# The admin routes await the promises `scheduled()` hands to `ctx.waitUntil`, so a 200 here means
# the sweep finished, not that it started.
set -uo pipefail

ADMIN_SOCK="${ADMIN_SOCK:-/run/mushroom/admin.sock}"
FILES_ADMIN_SOCK="${FILES_ADMIN_SOCK:-/run/mushroom/files-admin.sock}"
BLOB_ROOT="${BLOB_ROOT:-/var/lib/mushroom/blobs}"

# The expiry backstop, below, deletes blobs older than TWICE the share lifetime.
#
# DERIVED, never hardcoded. Phase A leans on an R2 lifecycle rule as the guarantee that holds
# even when the Worker is down; on-prem there is no such thing, so this is it. An operator who
# raises the share lifetime and leaves a hardcoded 2880 minutes gets a backstop that deletes live
# bytes out from under rows the database still calls `ready`, and the failure looks like random
# corruption. TTL_HOURS must match TTL_SECONDS in files-worker/worker.js.
TTL_HOURS="${TTL_HOURS:-24}"
BACKSTOP_MINUTES=$(( TTL_HOURS * 60 * 2 ))

fail=0

sweep() {
  local name="$1" sock="$2"
  if [ ! -S "$sock" ]; then
    echo "mushroom-cron: no socket at $sock, is workerd running?" >&2
    fail=1
    return
  fi
  if ! curl -sf --unix-socket "$sock" -m 120 -X POST http://local/_selfhost/cron >/dev/null; then
    echo "mushroom-cron: $name sweep failed" >&2
    fail=1
  fi
}

sweep messaging "$ADMIN_SOCK"
sweep files "$FILES_ADMIN_SOCK"

# The backstop. The Worker's own sweep is what normally removes expired blobs; this catches
# anything it missed, including everything it could not reach while the box was off.
#
# Two times the lifetime rather than one, for the same reason the hosted R2 lifecycle rule uses
# two days rather than one: a blob is only garbage once nothing can legitimately still be
# serving it, and one lifetime is exactly the boundary.
if [ -d "$BLOB_ROOT" ]; then
  find "$BLOB_ROOT" -type f -mmin +"$BACKSTOP_MINUTES" -delete 2>/dev/null
fi

exit "$fail"
