-- mushroom-messaging: the parts that need a global lookup.
--
-- Everything addressed by identity (messages, friends, push tokens, sockets) lives in that
-- identity's Durable Object. D1 holds only what a request must resolve before it knows which DO
-- to talk to: a bearer token, a license, an invite code.
--
-- No message body, friend name or public key of ours appears here, so a dump of this database
-- can't be turned into a conversation.

-- A Gumroad license, stored only as a hash. We never hold the key, but the hash is enough to
-- block an abused license.
CREATE TABLE licenses (
  license_hash    TEXT PRIMARY KEY,
  status          TEXT NOT NULL DEFAULT 'active',   -- active | revoked | blocked
  gumroad_sale_id TEXT,
  checked_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);

-- One Mac. `identity_id` is sha256(public_key), so a Mac re-activating with the same Keychain
-- key lands on the same identity and inbox, while a fresh key is a new person. A recovery flow
-- would just add a row here pointing at an existing identity, with no schema change.
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
-- This table is why the invite flow needs no directory or username.
CREATE TABLE identities (
  id           TEXT PRIMARY KEY,
  public_key   TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

-- A pending invite. Single use and short lived, which lets the code be eight characters
-- instead of a uuid: a guess has to land inside the window and before the real recipient.
CREATE TABLE invites (
  code        TEXT PRIMARY KEY,          -- normalized: uppercase, no separators
  identity_id TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_invites_identity ON invites(identity_id, created_at);
