-- Finish what 0003 could not.
--
-- 0003 backfills `identities.license_hash` from the identity's own device rows, which is the
-- right source: `activateDevice` writes both in one request, so the first device IS the
-- license that first claimed the identity. But the daily cron hard-deletes device rows 30
-- days after they are revoked:
--
--   DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < ?
--
-- so a pre-0002 identity whose devices were all revoked (seat eviction, or "Start Over") and
-- then swept has nothing left to backfill FROM. The correlated subquery matches nothing,
-- evaluates to NULL, and the row keeps `license_hash IS NULL`. 0003's own stated
-- post-condition (`SELECT COUNT(*) FROM identities WHERE license_hash IS NULL` returns 0)
-- therefore does not hold, and the hole it was written to close stays open for those rows:
-- `activateDevice`'s guard is
--
--   if (claimed && claimed.license_hash && claimed.license_hash !== hash)
--
-- which a NULL passes, so anyone holding any valid Gumroad key could post that identity's
-- public key (not a secret: /v1/friends hands it to every friend, friend_added pushes it,
-- and accepting an invite returns the inviter's) and be issued a token for it.
--
-- DELETING those rows closes it, and costs nothing that matters. An identity with no license
-- and no device is unreachable: nothing can authenticate as it, and the only thing the row
-- still does is answer the claim check. The identity id is `sha256(public_key)`, so an owner
-- who comes back re-activates, the row is recreated with their license bound, and their
-- Durable Object inbox (friends, messages, push tokens) is untouched throughout, because it
-- is keyed by identity id and lives outside D1 entirely.
--
-- Scoped to rows with NO devices at all, not merely NULL ones: an identity that still has a
-- device row is reachable, and 0003 already bound it if there was anything to bind from.
--
-- Idempotent, and a no-op once no NULLs remain. After applying, this must return 0:
--   SELECT COUNT(*) FROM identities WHERE license_hash IS NULL;
DELETE FROM identities
WHERE license_hash IS NULL
  AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.identity_id = identities.id);

-- Anything still NULL here has a device row that 0003 could not read a license from, which
-- should be impossible: every device is inserted with one. Bind it rather than leave the
-- claim check open, using the license of whichever device is oldest.
UPDATE identities SET license_hash = (
  SELECT d.license_hash FROM devices d
  WHERE d.identity_id = identities.id AND d.license_hash IS NOT NULL
  ORDER BY d.created_at ASC LIMIT 1
) WHERE license_hash IS NULL;
