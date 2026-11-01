-- Per-IP request counters, for /v1/devices/activate.
--
-- mushroom-messaging throttles the same endpoint in its Durable Object; this Worker has no DO,
-- so the counter lives here. The endpoint is unauthenticated, and each call walks an
-- attacker-supplied X.509 chain through jsrsasign twice (Production, then Sandbox), by far the
-- most expensive thing this Worker does without a bearer token.
--
-- Not Cloudflare's Rate Limiting binding: measured on this account, it let 139 requests from one
-- IP through in a minute against 30 per 60 seconds, all answered `{"success":true}`. A limiter
-- that allows everything is worse than none, because the endpoint looks protected. Don't swap it
-- back without firing a burst at the deployed Worker and watching for 429s.
--
-- Verified on the deployed Worker: 60 requests at 30/60s gave exactly 30 x 403 and 30 x 429,
-- sequentially over one connection and from 60 parallel threads. The upsert is atomic under
-- concurrency; no increments are lost.
--
-- Fixed windows, not sliding: a burst straddling a boundary can get twice the limit, which is
-- fine for bounding an amplification rather than metering a quota (and why a slow test burst can
-- look unlimited). One row per (key, window), so at most a window's worth of distinct IPs, and
-- the cron drops them once expired.
CREATE TABLE throttle (
  bucket_key TEXT PRIMARY KEY,      -- "<name>:<key>:<window start>"
  count      INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- The sweep deletes by expiry.
CREATE INDEX idx_throttle_expires ON throttle(expires_at);
