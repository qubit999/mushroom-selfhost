// The entitlement rules both Workers have to agree on, in ONE place.
//
// mushroom-files gates Spore Storage and mushroom-messaging gates Friends, but they gate them
// on the same membership, so a rule that differs by one character between the two means a
// subscriber keeps one feature and loses the other. Both new migrations say so in as many words
// ("Both workers have to agree or a subscriber would keep one feature and lose the other"), and
// hand-copying was how that promise was kept until this file existed: `verifyAppSubscription` and
// `appStoreEntitlement` were byte-for-byte identical in the two worker.js files, with nothing in
// either test.sh able to notice a one-sided edit. The security-critical `appTransactionId`
// binding below is exactly the kind of line that must never be fixed in only one of them.
//
// Same pattern, and the same reasoning, as ./apple-roots.js next door.
//
// Deliberately free of bare imports. `appStoreVerifiers` stays in each worker and is passed in as
// `verifiersFor`, because it does `await import("@apple/app-store-server-library")` and that
// package is declared in the two worker package.json files, not here: a bare specifier resolved
// from this directory would be resolved from the wrong place, which is the hazard apple-roots.js
// warns about. What travels is the LOGIC, which is what drifts; the module loading stays put.

const now = () => Math.floor(Date.now() / 1000);

/// How long a live membership buys before the app has to prove it again. Shorter than a billing
/// period on purpose: a lapse is noticed within a week rather than a month, and it doubles as a
/// grace period, because a subscriber whose card failed keeps working until it expires.
///
/// One declaration for both Workers. Two separate literals could drift, and a Mac that had to
/// re-prove itself to one service on a different schedule from the other would re-activate twice
/// as often for no reason.
export const LICENSE_RECHECK_SECONDS = 7 * 24 * 60 * 60;

/// When an App Store buyer's entitlement runs out: `null` for forever, or the string "lapsed" for
/// "not grandfathered". "lapsed" is NOT a refusal on its own: `activateDevice` then looks for a
/// live StoreKit subscription and a redeemed website membership before refusing anything.
///
/// Everyone who bought before ENTITLEMENT_CUTOVER is grandfathered forever, which is not
/// generosity but App Store Review Guideline 3.1.2(a): "you should not take away the primary
/// functionality existing users have already paid for."
///
/// CUTOVER 0 MEANS GRANDFATHER EVERYONE, and it is the default. That is what lets this whole
/// change deploy as a provable no-op, lets the switch be thrown later with a config edit and no
/// code deploy, and gives self-hosters (who set nothing) an install that never expires.
///
/// A missing `originalPurchaseMs` is treated as pre-cutover. Apple marks the field optional, and
/// the failure modes are not symmetric: reading an absent date as "bought recently" would lock a
/// legitimate old buyer out of features they paid for, which is the exact thing 3.1.2(a) forbids.
export function appStoreEntitlement(originalPurchaseMs, env) {
  const cutover = Number(env.ENTITLEMENT_CUTOVER ?? 0);
  if (!Number.isFinite(cutover) || cutover <= 0) return null;
  // `Number.isFinite`, not `=== null`. Both current callers normalise a missing date to null, but
  // this is the exported rule both Workers are meant to call, and a caller that forwarded Apple's
  // optional `originalPurchaseDate` straight through would hand in `undefined`: `Math.floor(
  // undefined / 1000)` is NaN, `NaN < cutover` is false, and the answer came back "lapsed", which
  // is precisely the 3.1.2(a) outcome the paragraph above promises against. Anything that is not
  // a real number is treated as pre-cutover.
  if (!Number.isFinite(originalPurchaseMs)) return null;
  return Math.floor(originalPurchaseMs / 1000) < cutover ? null : "lapsed";
}

/// Whether this deployment means to gate on the cutover but has lost the var.
///
/// `vars` are replaced wholesale on every `wrangler deploy` and `ENTITLEMENT_CUTOVER` ships
/// commented out, so one deploy from a stale config makes both entitlement rules answer NULL for
/// everybody. That is harmless for a licence row that already exists, because the upsert's CASE
/// only ever moves a horizon to another horizon, but it is PERMANENT for a row that does not: the
/// INSERT writes NULL and the CASE's first clause then pins it, which is free hosting forever with
/// hand-written SQL against production the only recovery. The monotonic CASE cannot catch this; it
/// only ever sees the conflict path.
///
/// A self-hosted box sets NEITHER var and must stay unaffected, which is what makes the PAIR the
/// signal rather than the cutover alone: a subscription product configured with no cutover behind
/// it is a misconfiguration, and the caller answers 503 rather than minting a permanent
/// grandfather. 503 is deliberate: it is the code both clients treat as soft and neither latches,
/// unlike the 403 `subscription_required` §12 forbids handing a paying user.
export function entitlementMisconfigured(env) {
  const cutover = Number(env.ENTITLEMENT_CUTOVER ?? 0);
  if (Number.isFinite(cutover) && cutover > 0) return false;
  return String(env.APPSTORE_SUBSCRIPTION_PRODUCT_IDS ?? "").split(/[\s,]+/).filter(Boolean).length > 0;
}

/// Verify the JWS for an auto-renewable subscription transaction.
/// Returns `{ status, entitledUntil }` where status is "active" | "invalid" | "unconfigured".
///
/// Same verifier, same pinned Apple roots, same Production-then-Sandbox loop as each worker's
/// `verifyAppTransaction`; only the payload type differs. Sandbox has to keep working, because
/// App Review tests in-app purchases there and its renewals are accelerated (a month is minutes).
///
/// `verifiersFor` is the caller's own `appStoreVerifiers`, passed in rather than imported: see
/// the note at the top of this file.
///
/// `expectedAppTransactionID` binds the subscription to the SAME Apple Account as the credential
/// it arrived with, and the binding is REQUIRED. Apple marks `appTransactionId` optional on the
/// payload, but waiving the check when it is absent turned a subscription JWS into a bearer
/// token: one subscriber could publish theirs and every other account could present it. Every
/// transaction we see is freshly signed, and `verifyAppTransaction` already treats the same field
/// as fatal, so requiring it costs nothing real.
export async function verifyAppSubscription(jws, env, expectedAppTransactionID, verifiersFor) {
  const verdict = (status, entitledUntil = null) => ({ status, entitledUntil });

  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jws)) return verdict("invalid");

  const appAppleID = Number(env.APPSTORE_APP_APPLE_ID ?? 0);
  if (!Number.isFinite(appAppleID) || appAppleID <= 0) return verdict("unconfigured");

  // A var, so renaming a product in App Store Connect is a config edit rather than a deploy.
  // Empty means the subscription is not configured here at all, which a self-hosted box should
  // never need: its cutover is 0, so nothing ever asks for a subscription in the first place.
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
    // "unconfigured", NOT "invalid". The app only ever sends a JWS whose product id already
    // matched `StoreEntitlement.productIDMonthly` or `.productIDYearly`, so a verified
    // transaction that is not in this list means OUR list is wrong (a typo, or a product renamed
    // in App Store Connect), not that the customer has no membership. "invalid" fell through to
    // a 403 `subscription_required`, which both clients treat as final and LATCH
    // (`markNotEntitled` / `markNoServerFeatures`), so one bad config character revoked a paid
    // feature from every subscriber at once. §12 forbids exactly that. An EMPTY var already
    // fails soft with 503; a WRONG one has to as well.
    if (!wanted.includes(tx.productId)) return verdict("unconfigured");
    if (tx.revocationDate) return verdict("invalid");
    // REQUIRED, not "checked when present". Waiving the binding on an absent id made a
    // subscription JWS a bearer token: one subscriber could publish theirs and every other
    // account could present it alongside their own app transaction and be entitled for as long
    // as that one subscription lived. `verifyAppTransaction` already treats a missing
    // appTransactionId as fatal, and this path has no reason to be more generous.
    if (typeof tx.appTransactionId !== "string" || !tx.appTransactionId) return verdict("invalid");
    if (tx.appTransactionId !== expectedAppTransactionID) return verdict("invalid");
    // ONE RECHECK WINDOW OF SLACK, not the raw expiry, and this is not generosity.
    //
    // Apple leaves `expiresDate` in the PAST for the whole of a billing grace period, while it
    // is still trying to collect and while `Transaction.currentEntitlements` still hands the app
    // the transaction. Refusing on the raw date therefore answered 403 `subscription_required`
    // to a subscriber mid-retry, and BOTH clients latch that answer and persist it
    // (`markNotEntitled` / `markNoServerFeatures`, plus `activationBlocked`). CLAUDE.md §12
    // forbids exactly that: "never lock a paying user out".
    const expires = typeof tx.expiresDate === "number" ? tx.expiresDate : 0;
    if (expires <= Date.now() - LICENSE_RECHECK_SECONDS * 1000) return verdict("invalid");
    // The horizon is the SAME one a Gumroad membership gets, deliberately, and never Apple's own
    // expiry. An Apple refund is invisible from here (catching one needs App Store Server
    // Notifications V2 and a webhook), so handing back a yearly transaction's own `expiresDate`
    // wrote a horizon up to 365 days out that nothing could take back. The client re-activates
    // when it lapses and presents whatever `Transaction.currentEntitlements` holds by then: the
    // renewed transaction, or nothing.
    return verdict("active", now() + LICENSE_RECHECK_SECONDS);
  }
  return verdict("invalid");
}
