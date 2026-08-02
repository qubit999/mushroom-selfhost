-- Close the claim window 0002 deliberately left open.
--
-- 0002 added `license_hash` nullable so that identities written before it would bind to
-- whoever activated them next, "rather than locking out the Mac that already owns them".
-- That reasoning is right about the goal and wrong about the only way to reach it: the
-- owner is already recorded. Every `identities` row is written by `activateDevice`, which
-- inserts a `devices` row carrying the same license in the same request, so the first
-- device is exactly the license that first claimed the identity. Backfilling from it binds
-- each old row to its real owner instead of to the next stranger who guesses it.
--
-- Why it mattered: a public key is not a secret (`/v1/friends` hands it to every friend,
-- `friend_added` pushes it, accepting an invite returns the inviter's), and `activateDevice`
-- skips the first-claim-wins check whenever the stored hash is NULL. Anyone holding their
-- own valid Gumroad key could post somebody else's public key, be issued a token for that
-- identity, and then read their friend list and stored ciphertext, register their own push
-- token, and `remove` every friendship, which deletes the messages with it. The bodies stay
-- sealed; everything around them did not.
--
-- Idempotent, and a no-op once no NULLs remain. After applying, this must return 0:
--   SELECT COUNT(*) FROM identities WHERE license_hash IS NULL;
UPDATE identities SET license_hash = (
  SELECT d.license_hash FROM devices d
  WHERE d.identity_id = identities.id AND d.license_hash IS NOT NULL
  ORDER BY d.created_at ASC LIMIT 1
) WHERE license_hash IS NULL;
