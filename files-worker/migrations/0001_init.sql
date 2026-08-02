-- Temporary file sharing: licenses, devices, files.
--
-- Identity is the LICENSE, never the raw key. We store sha256(key) only, so a database
-- dump cannot be replayed against Gumroad and cannot be traced back to a purchase
-- without the key already in hand.

CREATE TABLE licenses (
  license_hash TEXT PRIMARY KEY,          -- sha256 hex of the trimmed, uppercased key
  status       TEXT NOT NULL DEFAULT 'active',   -- active | revoked
  checked_at   INTEGER NOT NULL,          -- unix seconds, last successful Gumroad verify
  created_at   INTEGER NOT NULL
);

-- One row per Mac. The bearer token is a password, so only its hash is stored.
CREATE TABLE devices (
  id           TEXT PRIMARY KEY,          -- uuid, issued here
  license_hash TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,      -- sha256 hex of the bearer token
  name         TEXT,                      -- Mac name, display only, clamped on write
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked_at   INTEGER
);

-- Eviction picks the least-recently-seen device, so this index is the eviction query.
CREATE INDEX idx_devices_license ON devices(license_hash, last_seen_at);

-- The share token is stored in PLAINTEXT, deliberately. The Shared Files window has to
-- re-display the link on the user's other Macs, so it cannot be one-way. The object
-- bytes in R2 are exactly as sensitive as the token that fetches them, so hashing it
-- would protect nothing while breaking the feature.
CREATE TABLE files (
  id           TEXT PRIMARY KEY,          -- uuid; the R2 key is 'f/' || id
  license_hash TEXT NOT NULL,
  device_id    TEXT NOT NULL,
  token        TEXT NOT NULL UNIQUE,      -- 22 chars, base64url of 16 random bytes
  name         TEXT,                      -- sanitized display name; NULLed at expiry
  size         INTEGER NOT NULL,          -- declared at create, corrected from R2 on upload
  content_type TEXT NOT NULL,             -- recorded, never echoed back on download
  state        TEXT NOT NULL,             -- pending | ready | expired | deleted
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  uploaded_at  INTEGER,
  deleted_at   INTEGER
);

-- The list and the quota check both read (license, state, expiry).
CREATE INDEX idx_files_owner ON files(license_hash, state, expires_at);
-- The hourly sweep reads (state, expiry) across every license.
CREATE INDEX idx_files_sweep ON files(state, expires_at);
