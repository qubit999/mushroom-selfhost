-- Per-IP request counters, for /v1/devices/activate.
--
-- mushroom-messaging throttles the same endpoint inside its Durable Object. This Worker has
-- no DO, so the counter lives here instead. That endpoint is UNAUTHENTICATED by nature, and
-- since the App Store branch arrived a single call walks an attacker-supplied X.509
-- certificate chain through jsrsasign, twice (PRODUCTION then SANDBOX), which is by a wide
-- margin the most expensive thing this Worker can be made to do without a bearer token.
--
-- This replaces Cloudflare's own Rate Limiting binding, which was tried first and MEASURED
-- NOT TO WORK for this account: 139 requests from one IP inside a minute, against a
-- configured 30 per 60 seconds, every one of them answered `{"success":true}`. A limiter
-- that silently allows everything is worse than none, because the endpoint reads as
-- protected. Do not swap this back without firing a burst at the deployed Worker and
-- watching for 429s.
--
-- Verified against the deployed Worker, because the thing it replaced looked fine and did
-- nothing: 60 requests at 30/60s answered exactly 30 x 403 and 30 x 429, both sequentially
-- over one connection and from 60 parallel threads. The upsert is atomic under concurrency;
-- no increments are lost.
--
-- Fixed windows, not a sliding one: a burst can straddle a boundary and get up to twice the
-- limit, which does not matter when the point is bounding an amplification rather than
-- metering a quota. Expect that while testing, it is what makes a slow burst look unlimited. One row per (key, window), so a window's worth of distinct IPs is the
-- most this can ever hold, and the cron drops them once they expire.
CREATE TABLE throttle (
  bucket_key TEXT PRIMARY KEY,      -- "<name>:<key>:<window start>"
  count      INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- The sweep deletes by expiry, so that is what it needs to find rows by.
CREATE INDEX idx_throttle_expires ON throttle(expires_at);
