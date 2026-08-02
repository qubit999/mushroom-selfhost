-- Abuse reports, and the pointer that makes one actionable beyond file sharing.
--
-- No `status` or `resolved_at` column: there is no console to mark a report resolved
-- from, so a state machine nobody drives would only ever be wrong. Retention keys off
-- `created_at` instead.

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

-- We store sha256(licence key) and never the key, which is right but is also a dead end:
-- a hash cannot be reversed, so without this there is no way to connect a report to the
-- purchase behind it. Blocking file sharing never needed it; refunding or disabling the
-- sale in Gumroad does.
ALTER TABLE licenses ADD COLUMN gumroad_sale_id TEXT;
