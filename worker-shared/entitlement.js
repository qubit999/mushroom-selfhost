// The entitlement rules both Workers must agree on, in one place.
//
// mushroom-files gates Spore Storage and mushroom-messaging gates Friends on the same
// membership, so a rule that differs by one character keeps one feature and drops the other.
// Hand-copied, nothing in either test.sh would notice a one-sided edit, and the
// `appTransactionId` binding below is exactly the kind of line that must never be fixed in
// only one place. Same pattern as ./apple-roots.js.
//
// No bare imports. `appStoreVerifiers` stays in each worker and is passed in as
// `verifiersFor`, because its `import("@apple/app-store-server-library")` must resolve against
// each worker's package.json; from this directory it would resolve from the wrong place (see
// apple-roots.js). The logic is what drifts, so that's what lives here.

const now = () => Math.floor(Date.now() / 1000);

/// How long a live membership lasts before the app must prove it again. Shorter than a billing
/// period, so a lapse is noticed within a week, and it doubles as a grace period for a failed
/// card.
///
/// One declaration for both Workers: two schedules would make a Mac re-activate twice as often.
export const LICENSE_RECHECK_SECONDS = 7 * 24 * 60 * 60;

/// When an App Store buyer's entitlement runs out: `null` for forever, or "lapsed" for "not
/// grandfathered". "lapsed" isn't a refusal by itself: `activateDevice` then looks for a live
/// StoreKit subscription or a redeemed website membership.
///
/// Buyers before ENTITLEMENT_CUTOVER are grandfathered forever, as App Store Review Guideline
/// 3.1.2(a) requires: "you should not take away the primary functionality existing users have
/// already paid for."
///
/// Cutover 0 (the default) grandfathers everyone. That makes deploying this a provable no-op,
/// lets the switch be a later config edit, and gives self-hosters (who set nothing) an install
/// that never expires.
///
/// A missing `originalPurchaseMs` counts as pre-cutover. Apple marks it optional, and reading
/// absence as "bought recently" would lock an old buyer out, exactly what 3.1.2(a) forbids.
export function appStoreEntitlement(originalPurchaseMs, env) {
  const cutover = Number(env.ENTITLEMENT_CUTOVER ?? 0);
  if (!Number.isFinite(cutover) || cutover <= 0) return null;
  // `Number.isFinite`, not `=== null`: a caller forwarding Apple's optional
  // `originalPurchaseDate` as `undefined` would get NaN, `NaN < cutover` is false, and the answer
  // would be "lapsed", the 3.1.2(a) outcome above. Anything not a real number is pre-cutover.
  if (!Number.isFinite(originalPurchaseMs)) return null;
  return Math.floor(originalPurchaseMs / 1000) < cutover ? null : "lapsed";
}

/// Whether this deployment means to gate on the cutover but has lost the var.
///
/// `wrangler deploy` replaces `vars` wholesale and `ENTITLEMENT_CUTOVER` ships commented out, so
/// one deploy from a stale config makes both rules answer NULL for everyone. Existing rows are
/// safe (the upsert's CASE only moves horizon to horizon), but a new row is permanent: the INSERT
/// writes NULL and the CASE pins it, free hosting forever unless someone hand-edits production.
/// The CASE can't catch it; it only sees the conflict path.
///
/// A self-hosted box sets neither var, so the pair is the signal: a subscription product with
/// no cutover is a misconfiguration, and the caller answers 503 rather than minting a permanent
/// grandfather. 503 because both clients treat it as soft and never latch it, unlike the 403
/// `subscription_required` §12 forbids handing a paying user.
export function entitlementMisconfigured(env) {
  const cutover = Number(env.ENTITLEMENT_CUTOVER ?? 0);
  if (Number.isFinite(cutover) && cutover > 0) return false;
  return String(env.APPSTORE_SUBSCRIPTION_PRODUCT_IDS ?? "").split(/[\s,]+/).filter(Boolean).length > 0;
}

/// Verify the JWS for an auto-renewable subscription transaction.
/// Returns `{ status, entitledUntil }` where status is "active" | "invalid" | "unconfigured".
///
/// Same verifier, roots and Production-then-Sandbox loop as each worker's
/// `verifyAppTransaction`; only the payload differs. Sandbox must work: App Review tests in-app
/// purchases there, with accelerated renewals (a month is minutes).
///
/// `verifiersFor` is the caller's own `appStoreVerifiers` (see the top of this file).
///
/// `expectedAppTransactionID` binds the subscription to the same Apple Account as the
/// credential, and it's required. Apple marks `appTransactionId` optional, but waiving the check
/// when absent makes a subscription JWS a bearer token anyone could present. Every transaction we
/// see is freshly signed and `verifyAppTransaction` already requires it, so this costs nothing.
export async function verifyAppSubscription(jws, env, expectedAppTransactionID, verifiersFor) {
  const verdict = (status, entitledUntil = null) => ({ status, entitledUntil });

  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jws)) return verdict("invalid");

  const appAppleID = Number(env.APPSTORE_APP_APPLE_ID ?? 0);
  if (!Number.isFinite(appAppleID) || appAppleID <= 0) return verdict("unconfigured");

  // A var, so renaming a product in App Store Connect is a config edit, not a deploy. Empty
  // means not configured, which a self-hosted box never needs: its cutover is 0, so nothing asks.
  const wanted = String(env.APPSTORE_SUBSCRIPTION_PRODUCT_IDS ?? "").split(/[\s,]+/).filter(Boolean);
  if (!wanted.length) return verdict("unconfigured");

  let verifiers;
  try {
    verifiers = await verifiersFor(appAppleID);
  } catch (error) {
    console.error("appstore: verifier construction failed", error?.message ?? error);
    return verdict("unconfigured");
  }

  for (const verifier of verifiers) {
    let tx;
    try {
      tx = await verifier.verifyAndDecodeTransaction(jws);
    } catch {
      continue;   // wrong environment, or not ours; try the next verifier
    }
    // "unconfigured", not "invalid". The app only sends a JWS whose product id matched
    // `StoreEntitlement.productIDMonthly` or `.productIDYearly`, so a verified transaction
    // missing from this list means our list is wrong (a typo, a renamed product). "invalid"
    // becomes a 403 `subscription_required`, which both clients latch (`markNotEntitled` /
    // `markNoServerFeatures`), so one bad config character would revoke a paid feature from
    // every subscriber, which §12 forbids. An empty var already fails soft with 503; a wrong one
    // must too.
    if (!wanted.includes(tx.productId)) return verdict("unconfigured");
    if (tx.revocationDate) return verdict("invalid");
    // Required, not "checked when present", or a subscription JWS is a bearer token: anyone
    // could present a published one beside their own app transaction for as long as it lived.
    // `verifyAppTransaction` already requires it; this path has no reason to be more generous.
    if (typeof tx.appTransactionId !== "string" || !tx.appTransactionId) return verdict("invalid");
    if (tx.appTransactionId !== expectedAppTransactionID) return verdict("invalid");
    // One recheck window of slack past the raw expiry, and not out of generosity.
    //
    // Apple leaves `expiresDate` in the past during a billing grace period, while it's still
    // collecting and `Transaction.currentEntitlements` still hands the app the transaction.
    // Refusing on the raw date answers 403 `subscription_required` to a subscriber mid-retry,
    // which both clients latch and persist (`markNotEntitled` / `markNoServerFeatures`, plus
    // `activationBlocked`). CLAUDE.md §12: "never lock a paying user out".
    const expires = typeof tx.expiresDate === "number" ? tx.expiresDate : 0;
    if (expires <= Date.now() - LICENSE_RECHECK_SECONDS * 1000) return verdict("invalid");
    // The same horizon a Gumroad membership gets, never Apple's own expiry. Apple refunds are
    // invisible here (that needs App Store Server Notifications V2 and a webhook), so a yearly
    // transaction's `expiresDate` would be a horizon up to 365 days out that nothing could take
    // back. The client re-activates when it lapses and presents whatever
    // `Transaction.currentEntitlements` holds then: the renewal, or nothing.
    return verdict("active", now() + LICENSE_RECHECK_SECONDS);
  }
  return verdict("invalid");
}

// MARK: Setapp

/// How long a verified Setapp subscription buys before the app has to prove it again.
///
/// Exactly 24 hours, shorter than `LICENSE_RECHECK_SECONDS` on purpose. Setapp's terms ask for
/// an access check "every session or at minimum once per 24 hours", and this horizon expiring is
/// the only re-check trigger, so the horizon is the cadence. Longer quietly breaks that.
///
/// Its own constant: two vendors' rules, and one number serving both would drift into breaking
/// whichever it wasn't chosen for.
export const SETAPP_RECHECK_SECONDS = 24 * 60 * 60;

/// Whether this deployment can talk to Setapp at all.
///
/// Both halves: the client id names the app and the secret proves we're it. Same idea and same
/// soft 503 as `entitlementMisconfigured` above.
///
/// This keeps the Setapp branch inert until configured: the code and migrations can ship
/// without affecting anything. A self-hosted box sets neither and is refused here rather than at
/// a network boundary it can't cross anyway (`globalOutbound = no-internet`).
export function setappMisconfigured(env) {
  return !env.SETAPP_CLIENT_ID || !env.SETAPP_CLIENT_SECRET;
}

/// Exchange a Setapp authorization code for the answer to one question: may this person use our
/// app right now?
///
/// Returns `{ status, userID }` where status is:
///   "active"      - Setapp says yes. `userID` is the stable account id to key the licence on.
///   "refused"     - Setapp says no (lapsed, cancelled, refunded). A real answer, not an error.
///   "invalid"     - the code was rejected: expired, already spent, or not ours.
///   "unreachable" - Setapp could not be asked. Transient, and the caller answers 503.
///
/// The code is single-use and short-lived (20 minutes). It's exchanged inline and the tokens
/// thrown away: nothing stored, no refresh token, no background job. The next check comes when
/// the licence horizon expires and the client activates with a fresh code. So the app must never
/// cache a code: each Worker spends its own, and a reused one comes back "invalid".
///
/// `SETAPP_API_BASE` is only for pointing the test harness at a stub; production sets nothing.
export async function verifySetappAccess(code, env, fetchImpl = fetch) {
  const base = env.SETAPP_API_BASE ?? "https://vendor-api.setapp.com";
  const verdict = (status, userID = null) => ({ status, userID });

  let token;
  try {
    const response = await fetchImpl(`${base}/auth/v1/token`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: env.SETAPP_CLIENT_ID,
        client_secret: env.SETAPP_CLIENT_SECRET,
      }),
    });
    // 4xx means a bad code, which retrying won't fix; 5xx and 429 are Setapp having a moment.
    // The client latches one and not the other.
    if (response.status === 429 || response.status >= 500) return verdict("unreachable");
    if (!response.ok) return verdict("invalid");
    const body = await response.json();
    token = body?.access_token;
    if (typeof token !== "string" || !token) return verdict("invalid");
  } catch {
    return verdict("unreachable");
  }

  const authed = (path) => fetchImpl(`${base}/resource/v1${path}`, {
    method: path === "/userinfo" ? "GET" : "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
  });

  let userID;
  try {
    const response = await authed("/userinfo");
    if (response.status === 429 || response.status >= 500) return verdict("unreachable");
    // As in `/application/access` below: the token was just minted from our client id and
    // secret (so the code is good), and a 401 or 403 is our scope or deploy. `invalid` would
    // answer 403 `bad_license` and tell a paying subscriber their licence is bad, which §12
    // forbids.
    if (response.status === 401 || response.status === 403) return verdict("unreachable");
    if (!response.ok) return verdict("invalid");
    const body = await response.json();
    userID = setappUserID(body?.data?.id);
    if (!userID) return verdict("invalid");
  } catch {
    return verdict("unreachable");
  }

  try {
    const response = await authed("/application/access");
    if (response.status === 429 || response.status >= 500) return verdict("unreachable");
    // A 403 is our scope problem, not the user's. Unreachable, not a refusal, so a misconfigured
    // deploy can't tell a paying subscriber they've lapsed (§12).
    if (response.status === 401 || response.status === 403) return verdict("unreachable");
    if (!response.ok) return verdict("invalid");
    const body = await response.json();
    return body?.data?.granted === true ? verdict("active", userID) : verdict("refused");
  } catch {
    return verdict("unreachable");
  }
}

/// The user id, canonicalised to a decimal string.
///
/// The licence hash is `sha256("setapp:" + this)`, so the string matters, not the value: if
/// Setapp sent `12345` one day and `"12345"` the next, a naive read gives one person two hashes
/// and their Friends identity is refused as someone else's. A number is accepted only as a safe
/// integer, written back in the one spelling this function produces.
///
/// Anything else (float, huge number, object, empty string) is rejected: a hash is forever, and
/// guessing at an unseen shape is how the wrong one gets baked in.
export function setappUserID(raw) {
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    return /^[0-9]+$/.test(trimmed) ? String(BigInt(trimmed)) : null;
  }
  if (typeof raw === "number") {
    return Number.isSafeInteger(raw) && raw >= 0 ? String(raw) : null;
  }
  return null;
}
