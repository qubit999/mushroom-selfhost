-- When a licence's access to Friends runs out. NULL means never.
--
-- Grandfathering is the absence of a DEFAULT: every existing row gets NULL, so everyone who ever
-- activated keeps Friends permanently, with no backfill, purchase dates or date math to get
-- wrong. App Store Review Guideline 3.1.2(a) ("you should not take away the primary functionality
-- existing users have already paid for"), satisfied by the schema rather than by code.
--
-- Unix seconds, like every timestamp here. Read by the auth JOIN in `authenticateToken` (except
-- on the release route, where cleanup must keep working), by `stillAuthorized` on the hibernating
-- socket and by `entitledDevices` in the push alarm; written by the upsert in `activateDevice`,
-- whose CASE is monotonic both ways: NULL never becomes a horizon, a horizon never becomes NULL.
-- Only horizon -> horizon moves, which is a renewal.
--
-- Same column as files-worker/migrations/0005_entitlement.sql. Both workers must agree or a
-- subscriber would keep one feature and lose the other.
ALTER TABLE licenses ADD COLUMN entitled_until INTEGER;

-- The seat cap counts rows by sale (`SELECT COUNT(*) FROM licenses WHERE gumroad_sale_id = ?`).
-- Without an index every such activation full-scans the table, on the unauthenticated
-- /v1/devices/activate path the rate limiter is sized around. Partial, because a row with no
-- sale id isn't worth a slot.
CREATE INDEX idx_licenses_sale ON licenses(gumroad_sale_id) WHERE gumroad_sale_id IS NOT NULL;
