-- mushroom-messaging: the parts that need a GLOBAL lookup.
--
-- Everything addressed by identity (messages, friends, push tokens, sockets) lives in that
-- identity's Durable Object instead. D1 holds only the three things a request has to
-- resolve before it knows which DO to talk to: a bearer token, a license, an invite code.
--
-- No message body, no friend name and no public key of ours appears in this file. There is
-- deliberately nothing here that a dump of this database could turn into a conversation.

-- A Gumroad license, stored only as a hash. We never hold the key itself, and a hash cannot
-- be reversed, but it is still enough to block a license that is being abused.
CREATE TABLE licenses (
  license_hash    TEXT PRIMARY KEY,
  status          TEXT NOT NULL DEFAULT 'active',   -- active | revoked | blocked
  gumroad_sale_id TEXT,
  checked_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);

-- One Mac. `identity_id` is sha256(public_key), so the SAME Mac re-activating with the same
-- Keychain key lands on the same identity and the same inbox, while a Mac that generated a
-- fresh key is a genuinely new person. That is the whole of "per-Mac identity, recovery
-- later": the recovery flow, when it exists, adds a row here pointing at an existing
-- identity, and needs no schema change to do it.
CREATE TABLE devices (
  id           TEXT PRIMARY KEY,
  identity_id  TEXT NOT NULL,
  license_hash TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  name         TEXT,
  revoked_at   INTEGER,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX idx_devices_identity ON devices(identity_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_devices_license  ON devices(license_hash) WHERE revoked_at IS NULL;

-- The public half of an identity, so an invite can hand the accepter a key to encrypt to.
-- Public keys are public; this table is the only reason the invite flow needs no directory
-- and no username.
CREATE TABLE identities (
  id           TEXT PRIMARY KEY,
  public_key   TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

-- A pending invite. Single use and short lived, which is what lets the code be eight
-- characters instead of a uuid: a guess has to land inside the window AND before the real
-- recipient uses it.
CREATE TABLE invites (
  code        TEXT PRIMARY KEY,          -- normalized: uppercase, no separators
  identity_id TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_invites_identity ON invites(identity_id, created_at);
