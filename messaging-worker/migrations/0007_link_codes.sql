-- One-time codes that let a phone join a licence its Mac already proved.
--
-- For the Setapp build, which has nothing to hand over. The other channels give the phone a
-- durable credential: a Gumroad key travels by QR (`LicenseHandoff`), and an App Store phone
-- mints its own AppTransaction. A Setapp Mac's credential is a 20-minute single-use auth code
-- only a Worker can exchange, so the Mac asks for one of these instead.
--
-- `code_hash`, never the code, like `devices.token_hash`: for ten minutes the row is a bearer
-- credential to someone's Friends identity, and storing it in the clear would turn a read-only
-- leak into account access.
--
-- No `identity_id` column: the first-claim guard on `identities` decides the phone's identity,
-- as for every activation, and a second answer here could disagree.
CREATE TABLE link_codes (
  code_hash    TEXT PRIMARY KEY,
  license_hash TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

-- Redemption is `DELETE ... RETURNING` by primary key and needs no index. This one is for the
-- sweep, which would otherwise full-scan.
CREATE INDEX idx_link_codes_expiry ON link_codes(expires_at);
