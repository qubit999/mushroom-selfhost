-- Abuse reports, and the pointer that makes one actionable beyond file sharing.
--
-- No `status` or `resolved_at`: there's no console to resolve a report from, and a state
-- machine nobody drives would only be wrong. Retention keys off `created_at`.

CREATE TABLE abuse_reports (
  id             TEXT PRIMARY KEY,
  file_id        TEXT NOT NULL,
  reason         TEXT NOT NULL,      -- malware|phishing|copyright|illegal|privacy|other
  details        TEXT,
  -- Volunteered by the reporter so we can follow up. NULLed after 30 days by the sweep.
  reporter_name  TEXT,
  reporter_email TEXT,
  notified       TEXT NOT NULL,      -- sent | failed
  created_at     INTEGER NOT NULL
);

-- Both the 24 hour dedupe and the per-file daily cap read (file, time).
CREATE INDEX abuse_reports_file ON abuse_reports(file_id, created_at);
-- The cron's retry pass reads (notified, time).
CREATE INDEX abuse_reports_retry ON abuse_reports(notified, created_at);

-- We store sha256(licence key), never the key, and a hash can't be reversed, so without this
-- a report can't be connected to its purchase. Blocking file sharing doesn't need it;
-- refunding or disabling the sale in Gumroad does.
ALTER TABLE licenses ADD COLUMN gumroad_sale_id TEXT;
