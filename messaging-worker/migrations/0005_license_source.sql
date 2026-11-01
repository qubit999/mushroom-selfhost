-- Which sales channel a licence row came from. Same column as
-- files-worker/migrations/0003_license_source.sql.
--
-- Not used for any decision: activation routes on the credential the request carried, and the
-- Worker never re-verifies on its own (it holds only sha256). It lets support tell an App Store
-- row from a Gumroad row whose verify omitted a sale id, which otherwise look identical.
--
-- DEFAULT 'gumroad' backfills every existing row correctly: App Store activation did not
-- exist before this migration.
ALTER TABLE licenses ADD COLUMN source TEXT NOT NULL DEFAULT 'gumroad';
