-- Which sales channel a licence row came from.
--
-- Not used for any decision: activation routes on which credential the request carried, and
-- the Worker never re-verifies on its own (it holds only sha256, see requireLicense). This
-- exists so support can tell the two apart, because an App Store row has a NULL
-- gumroad_sale_id and so does a Gumroad row whose verify happened to omit one. Ambiguous
-- either way without this.
--
-- DEFAULT 'gumroad' backfills every existing row correctly: App Store activation did not
-- exist before this migration.
ALTER TABLE licenses ADD COLUMN source TEXT NOT NULL DEFAULT 'gumroad';

-- 'blocked' joins 'active' and 'revoked' as a status value. No schema change is needed for
-- it (status is free text), but the split matters: 'revoked' is Gumroad's answer and can
-- legitimately clear when a refund is reversed, while 'blocked' is our own abuse decision
-- and must survive re-activation. Mirrors mushroom-messaging, which has had it from 0001.
-- Existing rows blocked by an admin before this migration are 'revoked'; promote any that
-- were an abuse decision by hand, there is no way to tell them apart automatically.
