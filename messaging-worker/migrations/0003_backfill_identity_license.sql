-- Close the claim window 0002 left open.
--
-- 0002 made `license_hash` nullable so older identities bind to whoever activates them next.
-- But the owner is already recorded: `activateDevice` writes the `identities` row and a
-- `devices` row with the same license in one request, so the first device is the license that
-- first claimed the identity. Backfilling from it binds each old row to its real owner, not to
-- the next stranger who guesses it.
--
-- Why it matters: public keys aren't secret (`/v1/friends` hands them out, `friend_added` pushes
-- them, accepting an invite returns the inviter's), and `activateDevice` skips the first-claim
-- check when the stored hash is NULL. Anyone with a valid Gumroad key could post someone else's
-- public key, get a token for that identity, read their friend list and stored ciphertext,
-- register a push token, and `remove` every friendship and its messages. Bodies stay sealed;
-- nothing around them does.
--
-- Idempotent, and a no-op once no NULLs remain. After applying, this must return 0:
--   SELECT COUNT(*) FROM identities WHERE license_hash IS NULL;
UPDATE identities SET license_hash = (
  SELECT d.license_hash FROM devices d
  WHERE d.identity_id = identities.id AND d.license_hash IS NOT NULL
  ORDER BY d.created_at ASC LIMIT 1
) WHERE license_hash IS NULL;
