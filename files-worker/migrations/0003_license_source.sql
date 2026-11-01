-- Which sales channel a licence row came from.
--
-- Not used for any decision: activation routes on the credential the request carried, and the
-- Worker never re-verifies on its own (it holds only sha256, see requireLicense). It lets support
-- tell the two apart, since an App Store row and a Gumroad row whose verify omitted a sale id
-- both have a NULL gumroad_sale_id.
--
-- DEFAULT 'gumroad' backfills every existing row correctly: App Store activation did not
-- exist before this migration.
ALTER TABLE licenses ADD COLUMN source TEXT NOT NULL DEFAULT 'gumroad';

-- 'blocked' joins 'active' and 'revoked' as a status (free text, so no schema change). The split
-- matters: 'revoked' is Gumroad's answer and clears if a refund is reversed, while 'blocked' is
-- our abuse decision and must survive re-activation. Mirrors mushroom-messaging. Rows an admin
-- blocked before this migration read 'revoked'; promote abuse cases by hand, since nothing can
-- tell them apart automatically.
