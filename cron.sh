#!/bin/bash
# The sweeps, driven by a systemd timer.
#
# workerd has no cron (`triggers.crons` is a Cloudflare platform feature), so both Workers'
# sweeps are called in. A timer rather than a self-arming Durable Object alarm, because
# `systemctl list-timers` shows a sweep that stopped running; silently stopped sweeps are a bug
# class this codebase keeps paying for.
#
# The admin routes await what `scheduled()` hands to `ctx.waitUntil`, so a 200 means the sweep
# finished, not just started.
set -uo pipefail

ADMIN_SOCK="${ADMIN_SOCK:-/run/mushroom/admin.sock}"
FILES_ADMIN_SOCK="${FILES_ADMIN_SOCK:-/run/mushroom/files-admin.sock}"
BLOB_ROOT="${BLOB_ROOT:-/var/lib/mushroom/blobs}"

# The expiry backstop below deletes blobs older than twice the share lifetime.
#
# Derived, never hardcoded. Phase A relies on an R2 lifecycle rule that holds even when the Worker
# is down; on-prem this is that guarantee. Raise the lifetime against a hardcoded 2880 minutes and
# the backstop deletes live bytes under rows still marked `ready`, which looks like random
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

# The backstop. The Worker's sweep normally removes expired blobs; this catches anything it
# missed, including while the box was off.
#
# Twice the lifetime, like the hosted R2 lifecycle rule's two days: a blob is only garbage once
# nothing could still legitimately serve it, and one lifetime is exactly the boundary.
if [ -d "$BLOB_ROOT" ]; then
  find "$BLOB_ROOT" -type f -mmin +"$BACKSTOP_MINUTES" -delete 2>/dev/null
fi

exit "$fail"
