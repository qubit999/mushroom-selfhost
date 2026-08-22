-- One-time codes that let a phone join a licence its Mac already proved.
--
-- This exists for the Setapp build, which has nothing to hand over. The other two channels give
-- the phone a durable credential to re-present forever: a Gumroad key travels by QR
-- (`LicenseHandoff`), and an App Store phone can mint its own AppTransaction. A Setapp Mac's
-- credential is a 20-minute single-use authorization code that only a Worker can exchange, so
-- there is nothing to copy across. The Mac asks for one of these instead.
--
-- `code_hash`, never the code, exactly like `devices.token_hash`: for its ten minutes this row is
-- a bearer credential to somebody's Friends identity, and a table that stores it in the clear
-- turns a read-only database leak into account access.
--
-- No `identity_id` column, deliberately. Which identity the phone ends up on is decided by the
-- first-claim guard on `identities` the same way it is for every other activation; recording an
-- intent here as well would be a second answer to a question that already has one, and the two
-- could disagree.
CREATE TABLE link_codes (
  code_hash    TEXT PRIMARY KEY,
  license_hash TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

-- Redemption is `DELETE ... RETURNING` by primary key, so it needs no index of its own. This one
-- is for the sweep: without it, deleting expired rows is a full scan of a table that only ever
-- grows by a row per pairing.
CREATE INDEX idx_link_codes_expiry ON link_codes(expires_at);
