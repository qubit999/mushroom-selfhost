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

// MARK: Setapp

/// How long a verified Setapp subscription buys before the app has to prove it again.
///
/// EXACTLY 24 hours, and shorter than `LICENSE_RECHECK_SECONDS` on purpose. Setapp's integration
/// terms ask for an access check "every session or at minimum once per 24 hours", and because the
/// only thing that triggers a re-check is this horizon expiring, the horizon IS the cadence.
/// Anything longer than a day quietly breaks that promise; there is no second timer behind it.
///
/// Its own constant rather than the shared one for the same reason the shared one exists: these
/// are two different vendors' rules, and a single number serving both would drift into breaking
/// whichever one it was not chosen for.
export const SETAPP_RECHECK_SECONDS = 24 * 60 * 60;

/// Whether this deployment can talk to Setapp at all.
///
/// Both halves, because neither is any use alone: the client id names the app and the secret
/// proves we are it. Same shape and the same reasoning as `entitlementMisconfigured` above, and
/// the same 503 answer, which is the code both clients treat as soft and neither latches.
///
/// This is what makes the whole Setapp branch inert until the day it is configured: the code can
/// ship, the migrations can run, and a build that has never heard of Setapp is unaffected.
/// A self-hosted box sets neither and is refused here rather than at a network boundary it cannot
/// cross anyway (`globalOutbound = no-internet`).
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
/// THE CODE IS SINGLE USE AND SHORT LIVED (20 minutes). It is exchanged here, inline, and the
/// tokens are thrown away: nothing is stored, no refresh token is kept, and there is no
/// background job. The next check happens because the licence horizon expires and the client
/// activates again with a code it fetched a moment earlier. That is why the app must never cache
/// a code: the two Workers each spend their own, and a reused one comes back "invalid".
///
/// `SETAPP_API_BASE` exists so the test harness can point this at a stub. It is not a
/// configuration knob: production sets nothing and gets Setapp.
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
    // 4xx here is the CODE being bad, which no amount of retrying fixes; 5xx and 429 are Setapp
    // having a moment. Told apart because the client latches one and not the other.
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
    // Same rule as `/application/access` below, and for the same reason: the token was just
    // minted from OUR client id and secret, so a 401 or 403 here is our scope or our deploy, not
    // the user's licence. Mapping it to `invalid` answered 403 `bad_license` and told a paying
    // subscriber their licence was bad, which is the one answer §12 forbids handing a paying
    // user. The CODE is already known good by this point: the token exchange accepted it.
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
    // 403 here is a scope problem, which is ours, not the user's. Treated as unreachable rather
    // than as a refusal so a misconfigured deploy cannot tell a paying subscriber they have
    // lapsed, which is the one answer §12 forbids handing a paying user.
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
/// The licence hash is `sha256("setapp:" + this)`, so the STRING matters, not the value: if
/// Setapp sends `12345` today and `"12345"` after some JSON library change, a naive read produces
/// two different hashes for one person and their Friends identity is refused as claimed by
/// somebody else. JSON numbers are the hazard, so a number is accepted only when it is a safe
/// integer and is written back out in the one spelling this function can produce.
///
/// Anything else (a float, a huge number, an object, an empty string) is rejected outright: a
/// hash is forever, and guessing at a shape we have not seen is how the wrong one gets baked in.
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
