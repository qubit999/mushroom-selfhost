-- When a licence's access to Friends runs out. NULL means never.
--
-- The whole grandfathering story is the absence of a DEFAULT here. Every row that exists when
-- this runs gets NULL, so every user who has ever activated keeps Friends permanently, with no
-- backfill script, no purchase dates and no date arithmetic that could be wrong. That is App
-- Store Review Guideline 3.1.2(a) ("you should not take away the primary functionality existing
-- users have already paid for") satisfied by a schema default rather than by code.
--
-- Unix seconds, matching every other timestamp in this database. Read by the auth JOIN in
-- `authenticateToken` (except on the release route, where cleanup has to keep working), by
-- `stillAuthorized` on the hibernating socket and by `entitledDevices` in the push alarm; written
-- by the upsert in `activateDevice`, whose CASE is monotonic in BOTH directions: a NULL can never
-- become a horizon and a horizon can never become NULL. Only horizon -> horizon moves, which is
-- what a renewal is.
--
-- Same column, same reasoning, as files-worker/migrations/0005_entitlement.sql. Both workers
-- have to agree or a subscriber would keep one feature and lose the other.
ALTER TABLE licenses ADD COLUMN entitled_until INTEGER;

-- The seat cap on the App Store redeem path counts rows by sale (`SELECT COUNT(*) FROM licenses
-- WHERE gumroad_sale_id = ?`), and until it existed this column was only ever read back by
-- primary key, so nothing indexed it. Without this every redeem activation full-scans the table,
-- on the unauthenticated /v1/devices/activate path the rate limiter is already sized around.
-- Partial, because an App Store row that never redeemed has no sale id and is not worth a slot.
CREATE INDEX idx_licenses_sale ON licenses(gumroad_sale_id) WHERE gumroad_sale_id IS NOT NULL;
