-- Finish what 0003 could not.
--
-- 0003 backfills `identities.license_hash` from the identity's own device rows, the right
-- source: `activateDevice` writes both in one request. But the daily cron hard-deletes device
-- rows 30 days after they're revoked:
--
--   DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < ?
--
-- so a pre-0002 identity whose devices were all revoked (seat eviction, "Start Over") and swept
-- has nothing to backfill from. The subquery yields NULL, 0003's post-condition
-- (`SELECT COUNT(*) FROM identities WHERE license_hash IS NULL` returns 0) fails, and the hole
-- stays open for those rows, because `activateDevice`'s guard is
--
--   if (claimed && claimed.license_hash && claimed.license_hash !== hash)
--
-- which a NULL passes, so anyone with a valid Gumroad key could post that identity's public key
-- (not secret: /v1/friends, friend_added and invite acceptance all hand it out) and get a token.
--
-- Deleting those rows closes it at no real cost. An identity with no license and no device is
-- unreachable; the row only answers the claim check. The id is `sha256(public_key)`, so a
-- returning owner re-activates and the row is recreated with their license bound, while their
-- Durable Object inbox (friends, messages, push tokens), keyed by identity id outside D1, is
-- untouched.
--
-- Only rows with no devices at all: an identity with a device row is reachable, and 0003 already
-- bound it if there was anything to bind from.
--
-- Idempotent, and a no-op once no NULLs remain. After applying, this must return 0:
--   SELECT COUNT(*) FROM identities WHERE license_hash IS NULL;
DELETE FROM identities
WHERE license_hash IS NULL
  AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.identity_id = identities.id);

-- Anything still NULL has a device row 0003 couldn't read a license from, which should be
-- impossible (every device is inserted with one). Bind it to the oldest device's license
-- rather than leave the claim check open.
UPDATE identities SET license_hash = (
  SELECT d.license_hash FROM devices d
  WHERE d.identity_id = identities.id AND d.license_hash IS NOT NULL
  ORDER BY d.created_at ASC LIMIT 1
) WHERE license_hash IS NULL;
