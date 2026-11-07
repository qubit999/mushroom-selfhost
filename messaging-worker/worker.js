// mushroom-messaging: invite-only one-to-one messaging for Mushroom.
//
// A licensed Mac trades its Gumroad key plus an X25519 public key for a device token, then
// opens a WebSocket to its own inbox. Messages are sealed and opened on the Macs; this Worker
// only moves and stores opaque blobs it can't read.
//
// Logging rule, not negotiable: logs are retained, so never log a message body, ciphertext,
// invite code, license key or bearer token. Ids and status codes only (mushroom-files too).
//
// What the server can see (the privacy copy has to match): that identity A sent something to
// identity B at a time, its size, and which Macs were connected. Not the text, not friend
// names, not who anybody is.

// Not secrets; both match LicenseManager.productIDs. Membership first because new keys are the
// common case. Old one-time keys must verify forever, so the second entry can never go.
const GUMROAD_PRODUCT_IDS = [
  "O8DPu_83HyipF99edOojUQ==",  // Mushroom Membership (subscription)
  "59Bhmk7nBsjAqKhst9Bf9g==",  // Mushroom macOS app (one-time, pre-subscription)
];


const MAX_MESSAGE_CHARACTERS = 4000;
// A sealed box is base64 of nonce + ciphertext + tag: base64 costs 4/3, AES-GCM adds 28 bytes,
// and a character can be four UTF-8 bytes. Rounded up. It bounds the stored blob, not the text.
const MAX_CIPHERTEXT_CHARS = Math.ceil((MAX_MESSAGE_CHARACTERS * 4 + 28) * 4 / 3) + 64;
const MAX_FRIENDS = 50;
// Must equal `LicenseVerifier.seatCap` and files-worker's copy. The app spends five activations
// on Gumroad and the server keeps five device rows: one allowance, and `saleSeatBudget` counts
// it across every row sharing a sale. A mismatch fails silently, because
// `verifyLicenseAgainst` sends `increment_uses_count: "false"` and registering here never
// spends a Gumroad use.
//
// 5, not 3, because the cap evicts the least-recently-seen device rather than refusing: at 3, a
// phone joining a desk Mac and a laptop signed one Mac out mid-conversation.
//
// Changing it is a copy change too: the number is across Mushroom_www (index, faq and its
// JSON-LD, terms, help, llms.txt), the marketing/ Gumroad descriptions and the app's strings in
// all five languages. Both Workers and the app move together. Say "devices", not "Macs".
const MAX_DEVICES_PER_LICENSE = 5;
const MAX_DEVICE_NAME_CHARS = 60;
// A UUID is 36. The id is stored and rebroadcast, so unbounded it's a way past the ciphertext
// cap into a friend's storage quota (see `handleSend`).
const MAX_MSG_ID_CHARS = 64;
// How far `sent_at` may sit from the server clock. The sender picks it and the AEAD binding
// doesn't cover it, and it's the sort key on the other side, so a sender's wrong clock (a fresh
// Windows install with the zone left on US time and the hour fixed by hand runs hours off)
// reordered the conversation. A message written offline is dated when it reached us instead.
const SENT_AT_PAST_SECONDS = 60;
const SENT_AT_FUTURE_SECONDS = 60;
// Our clock at the moment a message frame leaves, so the receiver can move `sent_at` onto its
// own clock (`Messaging.localTime`). Fractional: whole seconds tie a quick exchange.
const serverNow = () => Date.now() / 1000;
const RETENTION_SECONDS = 30 * 24 * 60 * 60;    // then the sweep drops it
// Stored ciphertext per sender, a few thousand full-length messages. Generous for a person,
// and the whole friend list at this size still fits a Durable Object.
const MAX_STORED_CHARS_PER_PEER = 64 * 1024 * 1024;
const INVITE_TTL_SECONDS = 24 * 60 * 60;
const INVITES_PER_DAY = 20;
const MESSAGES_PER_MINUTE = 60;
const TYPING_PER_SECOND = 1;
const SYNC_PAGE = 200;

// Activations per hour per IP, and invite redemptions per hour per identity: generous for a
// person, useless for a script. Activation answers before authentication, so without a limit
// `403 bad_license` vs `201` makes this Worker a free Gumroad key checker, each try costing us
// a verify call. And `activateDevice` fails closed on a Gumroad 429, so a flood would lock real
// Macs out. Overridable only for test.sh, whose dozen activation POSTs plus a re-run within the
// hour would hit 429; `wrangler dev --var` raises it locally, production keeps the default.
const activationsPerHourPerIP = (env) => Number(env.ACTIVATIONS_PER_HOUR_PER_IP ?? 10) || 10;
const ACCEPTS_PER_HOUR = 30;
const LINKS_PER_HOUR = 10;

// How long after delivering on a socket we wait for the ack before pushing. An awake Mac always
// beats it, and a notification still feels immediate.
const PUSH_GRACE_MS = 10_000;
// Delay before retrying a failed push. Longer than the grace window: the failures worth
// retrying (APNs 5xx, a throttled provider token) need more than a moment, and the alarm is a
// single slot, so a short retry would keep overwriting a live conversation's grace alarm.
const PUSH_RETRY_MS = 60_000;
// Attempts, doubling from PUSH_RETRY_MS, before giving up: about an hour. Without a cap an
// expired or revoked .p8 fails every minute forever and one unread message keeps its inbox
// awake for good. Six still outlasts any APNs incident worth waiting out.
const PUSH_MAX_ATTEMPTS = 6;
// In DO storage, not an instance field: the count must survive eviction between alarms, or it
// resets on every wake and the loop is unbounded again.
const PUSH_ATTEMPT_KEY = "push_attempt";
// How long APNs keeps trying to deliver. A day covers a Mac shut overnight without a pile of
// stale banners after a holiday for messages the app already fetched.
const PUSH_EXPIRY_SECONDS = 24 * 60 * 60;

// Presence
const HEARTBEAT_SECONDS = 30;
const PRESENCE_STALE_SECONDS = 90;              // three missed Presence.heartbeatInterval beats
// Twice per staleness window, so a live Mac stays inside it without a fan-out per heartbeat.
// Keep it well below PRESENCE_STALE_SECONDS (see `refreshPresence`).
const PRESENCE_REFRESH_SECONDS = 40;
// Cap on one connect's fan-out. The subrequest budget is far larger than MAX_FRIENDS, so this
// only binds if MAX_FRIENDS grows, making that a decision rather than an outage.
const MAX_PRESENCE_FANOUT = 50;
// How often a live socket re-proves its device may still be here. A socket is authenticated
// once, at the upgrade, and hibernation lets it outlive that check, so without this a revoked
// device (seat eviction, "Start Over"), a blocked license or a refund never touched an open
// connection; the client only reconnects on error. One D1 read per socket per five minutes.
const SOCKET_RECHECK_SECONDS = 300;
// Connect and close each fan out to every friend. A reconnecting Mac needs a handful a minute; a
// connect loop would otherwise wake every friend's inbox per cycle, without limit.
const PRESENCE_ANNOUNCES_PER_MINUTE = 12;

const INVITE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // no I, L, O, U; matches Messaging.inviteAlphabet
const INVITE_CODE_LENGTH = 8;

// ---------------------------------------------------------------- helpers

const now = () => Math.floor(Date.now() / 1000);

function reply(status, body) {
  return new Response(JSON.stringify({ ok: status < 400, ...body }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

const fail = (status, code, extra) => reply(status, { code, ...extra });

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/// Trimmed and uppercased before hashing on both sides, so a key pasted with a stray space
/// is still the same license. Mirrors `FileShare.normalizedLicenseKey` in the app.
const licenseHash = (key) => sha256Hex(key.trim().toUpperCase());

const randomToken = () =>
  [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

/// 256 is a multiple of 32, so `byte % 32` is unbiased. Over a 36-character alphabet the same
/// line would quietly favour the first four.
function inviteCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(INVITE_CODE_LENGTH));
  return [...bytes].map((b) => INVITE_ALPHABET[b % INVITE_ALPHABET.length]).join("");
}

/// Strips separators only, not everything outside the alphabet (mirrors
/// `Messaging.normalizedInviteCode`): filtering by alphabet turns a typo into a different
/// well-formed code nobody issued.
const normalizeInvite = (raw) => String(raw ?? "").toUpperCase().replace(/[\s\-_]/g, "");

const wellFormedInvite = (code) =>
  code.length === INVITE_CODE_LENGTH && [...code].every((c) => INVITE_ALPHABET.includes(c));

const isBase64 = (s, maxBytes) =>
  typeof s === "string" && s.length > 0 && s.length <= maxBytes && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

/// An X25519 public key is 32 bytes, exactly 44 base64 characters with one pad. Refused here,
/// a malformed key can't get stored and then fail to encrypt for everyone who adds this person.
const isPublicKey = (s) => typeof s === "string" && s.length === 44 && /^[A-Za-z0-9+/]{43}=$/.test(s);

const identityFor = (publicKey) => sha256Hex(publicKey);

const limits = () => ({
  // The wire contract this server speaks, for the app to compare against its minimum.
  //
  // Nobody reads it yet, on purpose: a self-hosted copy stops moving when ours does, and the
  // app has no other way to tell an old server from a current one. Absent means "older than 1",
  // so it has to exist before there's a 2. Bump only for changes an older app can't survive;
  // additive ones need none, since unknown frames are ignored and every limit has a fallback.
  protocol: 1,
  max_message_characters: MAX_MESSAGE_CHARACTERS,
  max_friends: MAX_FRIENDS,
  invites_per_day: INVITES_PER_DAY,
  retention_days: RETENTION_SECONDS / 86400,
});

const inbox = (env, identityID) => env.INBOX.get(env.INBOX.idFromName(identityID));

/// Call another identity's inbox. A plain fetch with a made-up origin is the documented way to
/// talk to a DO, and keeps every handler a normal request handler.
function inboxCall(env, identityID, path, body) {
  return inbox(env, identityID).fetch(`https://inbox${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
}

/// A counter for a route that has no inbox of its own yet.
///
/// Reuses `UserInbox.allow`: a Durable Object named after the key is a per-key lock, which is
/// why the counter is exact. The `rate:…` prefix can't collide with an identity id (64 hex).
async function throttle(env, key, bucket, limit, windowSeconds) {
  const response = await inboxCall(env, `rate:${key}`, "/rate",
                                   { bucket, limit, window: windowSeconds });
  return response.ok;
}

/// A JSON body that is an object, or a throw the caller's catch turns into 400. `null`, a number
/// or an array parse fine, and the next `body.x` would be an uncaught 500.
function objectBody(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  throw new TypeError("body is not an object");
}

// ---------------------------------------------------------------- license

/// Ask Gumroad whether a key is real and still paid for.
///
/// increment_uses_count is false, as in mushroom-files: the app spends a seat once at
/// activation, and counting here would spend the user's seats on our bookkeeping.
/// Tries each product and returns the first real answer. "invalid" from one product only means
/// "not that product", so it falls through; anything else (active, lapsed, revoked,
/// unreachable) is an answer about this key. Invalid everywhere means invalid.
async function verifyLicense(key, env) {
  let last = { status: "invalid", saleID: null, entitledUntil: null };
  for (const productID of GUMROAD_PRODUCT_IDS) {
    last = await verifyLicenseAgainst(key, productID, env);
    if (last.status !== "invalid") return last;
  }
  return last;
}

async function verifyLicenseAgainst(key, productID, env) {
  const verdict = (status, saleID = null, entitledUntil = null) => ({ status, saleID, entitledUntil });

  let response;
  try {
    response = await fetch("https://api.gumroad.com/v2/licenses/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        product_id: productID,
        license_key: key,
        increment_uses_count: "false",
      }),
    });
  } catch {
    return verdict("unreachable");
  }
  // 429 is Gumroad rate-limiting us, not a bad license.
  if (response.status === 429 || response.status >= 500) return verdict("unreachable");

  let body;
  try {
    body = await response.json();
  } catch {
    return verdict("unreachable");
  }
  if (!body || body.success !== true) return verdict("invalid");

  const purchase = body.purchase ?? {};
  if (purchase.refunded || purchase.disputed || purchase.chargebacked) return verdict("revoked");

  const saleID = typeof purchase.sale_id === "string" ? purchase.sale_id : null;

  // Entitlement: a one-time purchase has no `subscription_id`; a membership always does (both
  // shapes captured from the live API and pinned in Tests/MushroomPetKitTests/KitTests.swift).
  // "No subscription_id" is necessary but not sufficient: the one-time product is still on sale,
  // so the branch below dates it against the cutover. Don't collapse the two.
  //
  // This also grandfathers a self-hosted box on purpose: `installOfflineGumroad` synthesises a
  // purchase with no subscription_id, so an air-gapped install needs no ENTITLEMENT_CUTOVER.
  if (typeof purchase.subscription_id !== "string") {
    // One-time purchase: entitled forever only if it predates the cutover. Otherwise anyone
    // could buy the app once and keep Friends for less than four months of membership, and the
    // one-time listing itself says "File sharing and Friends stay off in that version".
    //
    // Same cutover and 0-means-grandfather-everyone default as the App Store path. A missing or
    // unparseable date counts as pre-cutover: wrongly refusing an old buyer breaks something
    // they paid for, wrongly admitting one costs a little hosting.
    const cutover = Number(env.ENTITLEMENT_CUTOVER ?? 0);
    if (!Number.isFinite(cutover) || cutover <= 0) return verdict("active", saleID, null);
    const soldMs = Date.parse(purchase.sale_timestamp ?? purchase.created_at ?? "");
    if (!Number.isFinite(soldMs)) return verdict("active", saleID, null);
    return Math.floor(soldMs / 1000) < cutover
      ? verdict("active", saleID, null)
      : verdict("lapsed", saleID);
  }

  // Membership. `subscription_cancelled_at` is ignored on purpose: Gumroad sets it on cancel
  // while the paid period still runs; `subscription_ended_at` marks the real stop. Treating
  // cancelled as lapsed would take away time already paid for.
  if (purchase.subscription_ended_at || purchase.subscription_failed_at) {
    return verdict("lapsed", saleID);
  }
  return verdict("active", saleID, now() + LICENSE_RECHECK_SECONDS);
}

// ---------------------------------------------------------------- app store purchases

// The App Store build has no Gumroad key (`LicenseManager`'s APPSTORE stub never writes one),
// so it sends `AppTransaction`'s JWS, which Apple signs for exactly this. The identity lands in
// the same `licenses.license_hash` column as a Gumroad key hash, so nothing downstream changes.
//
// Trust anchors live in one place, ../worker-shared/apple-roots.js, shared by both workers so
// they rotate in lockstep; nothing here would catch a one-sided edit.
import { APPSTORE_BUNDLE_ID, APPLE_ROOT_CA_G3, APPLE_ROOT_CA_G2 } from "../worker-shared/apple-roots.js";
// The entitlement rules are shared for the same reason: the workers gate different features on
// one membership, so a rule that differs between them keeps one feature and drops the other.
import { clientBucket } from "../worker-shared/client-bucket.js";
import { LICENSE_RECHECK_SECONDS, appStoreEntitlement, verifyAppSubscription,
         entitlementMisconfigured,
         SETAPP_RECHECK_SECONDS, setappMisconfigured, verifySetappAccess }
  from "../worker-shared/entitlement.js";

// A real JWS is a few KB. Bounded so a megabyte of junk never reaches the verifier.
const MAX_APP_TRANSACTION_CHARS = 12000;

// Namespaced so it can't collide with Gumroad hashes in the one `licenses` table. Apple issues
// `appTransactionId` per Apple Account and per family member, so Family Sharing members get
// their own seats.
const appStoreHash = (appTransactionID) => sha256Hex(`appstore:${appTransactionID}`);

// Third identity space, namespaced the same way. Setapp's user id is per account and Setapp
// decides how many Macs it may use, so these seats are only a backstop.
//
// Input must be `setappUserID`'s canonical decimal string: every Setapp user's Friends identity
// is bound to this hash, and a second spelling is a second person to the first-claim guard.
const setappHash = (userID) => sha256Hex(`setapp:${userID}`);

// MARK: Link codes
//
// A one-time code a Mac mints for a phone. A Setapp Mac has nothing else to hand over: its
// credential is a 20-minute single-use auth code only a Worker can exchange.
//
// Stored as sha256, like a device token, so reading the table gives nothing away. Deleted on
// redemption (works once); expired rows are swept lazily by the next lookup.
const LINK_CODE_TTL_SECONDS = 10 * 60;

/// Spend a code, returning the licence it was minted against, or null.
///
/// Delete-then-check: the DELETE is the claim, so two phones racing one code can't both win.
/// RETURNING makes it one statement, with no window between a select and a delete.
async function redeemLinkCode(env, code) {
  const row = await env.DB.prepare(
    "DELETE FROM link_codes WHERE code_hash = ? RETURNING license_hash, expires_at"
  ).bind(await sha256Hex(code)).first();
  if (!row) return null;
  // An expired code is dead anyway; deleting it here is the sweep.
  if (row.expires_at <= now()) return null;
  return row;
}

/// How many Macs this licence row may keep, counted across every row sharing the sale.
///
/// One sale means five devices in total, not per row. Rows multiply: a redeeming App Store
/// account gets its own row keyed on its app transaction, while a direct-build Mac hashes the
/// key. Bounding only the redeem branch let one sale keep twice its Macs here and again on
/// mushroom-files, and nothing else catches it since `verifyLicenseAgainst` sends
/// `increment_uses_count: "false"`.
///
/// Counted in Macs, not rows: counting rows capped Apple Accounts while each kept five devices,
/// and the client's "already set up on five devices" would name a unit nothing counted.
///
/// Excludes this hash, so re-activating an already-counted Mac is free. No sale id can't be
/// counted, so it's let through (§12 fail-open); the live API always sends one. Returns null
/// when the seats are spent; the caller answers `seat_limit`, never `subscription_required`,
/// which both clients persist as a final entitlement refusal.
///
/// Must match mushroom-files' copy, or Friends and Spore Storage allow different Mac counts.
async function saleSeatBudget(env, saleID, hash) {
  if (!saleID) return MAX_DEVICES_PER_LICENSE;
  const seats = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM devices d " +
    "JOIN licenses l ON l.license_hash = d.license_hash " +
    "WHERE l.gumroad_sale_id = ? AND l.license_hash != ? AND d.revoked_at IS NULL"
  ).bind(saleID, hash).first();
  const taken = seats?.n ?? 0;
  return taken >= MAX_DEVICES_PER_LICENSE ? null : MAX_DEVICES_PER_LICENSE - taken;
}

/// May a credential that verified as this hash enrol on this box?
///
/// Self-hosted only. Hosted, Gumroad decides and every paying customer is welcome, so with
/// `SELFHOST` unset this answers yes.
///
/// The offline Gumroad shim (selfhost/shared/gumroad.js) wraps `fetch`, so it only sees the
/// Gumroad branch. An App Store credential verifies offline against the pinned Apple roots and
/// never calls `fetch`, so relying on the shim let any App Store copy enrol on a box
/// restricted to named keys, over an unauthenticated endpoint.
///
/// Deciding on the derived hash, whichever branch produced it, closes the whole class rather
/// than refusing App Store credentials on-prem: an operator enrols an App Store user by hash
/// like anyone else. Gumroad keys pass through here too, redundant with the shim on purpose:
/// the security boundary shouldn't rest on a `fetch` wrapper.
function enrolmentAllows(hash, env) {
  if (env.SELFHOST !== "1") return true;
  const configured = String(env.ENROLLMENT_HASHES ?? "").trim();
  // Exactly "*", as in the shim: a stray asterisk inside a list is a typo, not "let everyone in".
  if (configured === "*") return true;
  // Unset is a half-configured box and fails closed. The Gumroad branch already 503s there (no
  // shim, the call escapes to a network that refuses it); this stops the App Store branch being
  // the one credential such a box still accepts.
  return configured.split(/[\s,]+/).filter(Boolean).some((h) => h.toLowerCase() === hash);
}

// One verifier per environment, built once per isolate and reused.
//
// Beyond skipping the DER parse: `SignedDataVerifier` has a per-instance verified-key cache
// (15 min, 32 entries). A fresh one per request throws it away and redoes the chain walk on
// every activation, though one Apple leaf signs everybody's JWS in a given window.
let verifierCache = null;

async function appStoreVerifiers(appAppleID) {
  if (verifierCache) return verifierCache;
  // Imported here, not at the top, and that's load-bearing: jsrsasign generates random values
  // in its module body, which workerd forbids in global scope ("Disallowed operation called
  // within global scope"), so a top-level import stops the Worker booting. The evaluation is
  // cached, so it costs ~80 ms once per cold isolate.
  const lib = await import("@apple/app-store-server-library");
  const roots = [APPLE_ROOT_CA_G3, APPLE_ROOT_CA_G2].map((b64) => Buffer.from(b64, "base64"));
  // Production, then Sandbox: TestFlight and App Review builds carry Sandbox transactions, and
  // refusing them would fail review. `enableOnlineChecks` is off so activation never waits on
  // OCSP; the chain is still verified to the root. Xcode and LocalTesting are left out because
  // the library skips signature checks for them, which would make this endpoint forgeable.
  verifierCache = [
    new lib.SignedDataVerifier(roots, false, lib.Environment.PRODUCTION, APPSTORE_BUNDLE_ID, appAppleID),
    new lib.SignedDataVerifier(roots, false, lib.Environment.SANDBOX, APPSTORE_BUNDLE_ID, undefined),
  ];
  return verifierCache;
}

/// Verify an AppTransaction JWS.
/// Returns `{ status, appTransactionID, originalPurchaseMs }` where status is
/// "active" | "invalid" | "unconfigured".
///
/// `originalPurchaseMs` is when this Apple Account first bought the app (ms since epoch); it
/// grandfathers buyers from before the subscription. Preferred over
/// `originalApplicationVersion`, a macOS build-number string that would need a parser. It can
/// be null, and null must never read as "bought recently" (see activateDevice's cutover check).
///
/// No "unreachable": the JWS carries its own chain, checked against a pinned root, so there's
/// no third party to be down. "unconfigured" is our missing app id, not the user's problem.
async function verifyAppTransaction(jws, env) {
  const verdict = (status, appTransactionID = null, originalPurchaseMs = null) =>
    ({ status, appTransactionID, originalPurchaseMs });

  // Shape before crypto: verification is the expensive part of an unauthenticated endpoint, so
  // anything obviously not a JWS is rejected for free.
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jws)) return verdict("invalid");

  // Apple's verifier needs the numeric App Store id for Production. It's a var because it only
  // exists once the App Store Connect record does; refuse loudly while it's missing rather
  // than verify against the wrong app.
  const appAppleID = Number(env.APPSTORE_APP_APPLE_ID ?? 0);
  if (!Number.isFinite(appAppleID) || appAppleID <= 0) return verdict("unconfigured");

  let verifiers;
  try {
    verifiers = await appStoreVerifiers(appAppleID);
  } catch (error) {
    console.error("appstore: verifier construction failed", error?.message ?? error);
    return verdict("unconfigured");
  }

  const failures = [];
  for (const [index, verifier] of verifiers.entries()) {
    try {
      const tx = await verifier.verifyAndDecodeAppTransaction(jws);
      // The verifier already checked bundleId. `appTransactionId` is what we need and it's
      // optional in the model; without it there's no identity.
      if (typeof tx.appTransactionId === "string" && tx.appTransactionId) {
        // A sandbox AppTransaction (verifier 1) is never grandfathered: TestFlight hands them out
        // free, and one dated before the cutover would otherwise be a lifetime entitlement.
        // App Review is unaffected; it already buys after the cutover.
        const bought = index > 0 ? Date.now()
          : typeof tx.originalPurchaseDate === "number" ? tx.originalPurchaseDate : null;
        return verdict("active", tx.appTransactionId, bought);
      }
      failures.push("no_app_transaction_id");
    } catch (error) {
      // Wrong environment is normal (every Sandbox JWS fails Production first). Logged anyway,
      // because a wrong but numeric APPSTORE_APP_APPLE_ID would fail every customer with
      // nothing to tell a total outage from junk traffic.
      failures.push(error?.status ?? error?.name ?? "unknown");
    }
  }
  console.warn("appstore: rejected app_transaction", JSON.stringify(failures));
  return verdict("invalid");
}

// ---------------------------------------------------------------- channel migration

/// The licence hash a second, older credential resolves to, or null.
///
/// Only proves the activator also holds the credential an identity is bound to. It doesn't
/// touch `licenses`: this is proof of possession, not activation, and the row that matters is
/// written from the primary credential further down.
///
/// A `revoked` Gumroad key still counts: someone refunded (or their card bounced) and bought
/// again on the other channel is exactly who this migration is for. `invalid` and
/// `unreachable` don't, so making Gumroad unreachable can't wave a migration through.
async function credentialHash(env, { key, jws }) {
  if (jws) {
    const { status, appTransactionID } = await verifyAppTransaction(jws, env);
    return status === "active" ? await appStoreHash(appTransactionID) : null;
  }
  if (key) {
    const { status } = await verifyLicense(key, env);
    // "lapsed" counts too: a membership that stopped paying still proves the holder owned the
    // licence, the standard the original claim was made to. It's the main case, since the only
    // reason to migrate off a Gumroad key is that it stopped working. Refusing it strands the
    // identity on a dead licence, with only Start Over (which deletes every friendship) left.
    return (status === "active" || status === "revoked" || status === "lapsed")
      ? await licenseHash(key) : null;
  }
  return null;
}

/// Move an identity from the licence that claimed it to the one activating now.
///
/// Both targets ship bundle id com.qubit.shroomy.app under one team, so a Mac switching between
/// the direct download and the App Store keeps its Keychain and X25519 identity key. The
/// licence hash doesn't survive (Gumroad's is sha256(licence key), the App Store's
/// sha256("appstore:" + appTransactionId)), so the first-claim guard would refuse the same
/// person forever, leaving only Start Over, which deletes every friendship and message.
///
/// The proof is holding the old credential as well as the new one, the same standard as the
/// original claim, so nothing new opens: an attacker with someone's public key still needs the
/// licence that owns it.
///
/// Returns true when the identity now belongs to `newHash`.
async function migrateIdentity(env, identityID, oldHash, newHash, body, stamp) {
  const key = typeof body.migrate_license_key === "string" ? body.migrate_license_key.trim() : "";
  const jws = typeof body.migrate_app_transaction === "string" ? body.migrate_app_transaction.trim() : "";
  // At least one, and both are allowed. A Mac moving to Setapp may hold a Gumroad key and an App
  // Store transaction, and can't tell which one claimed the identity (only the server knows), so
  // it sends what it has and each is tried.
  //
  // This only proves possession. The only outcome below is moving the identity to a hash the
  // caller already authenticated as, and only if a proof resolves to the hash that owns it now.
  if (!key && !jws) return false;
  if (key && key.length > 100) return false;
  if (jws && jws.length > MAX_APP_TRANSACTION_CHARS) return false;

  // Order doesn't matter: the test is equality with `oldHash`, and any other hash just isn't it.
  let provenHash = key ? await credentialHash(env, { key, jws: "" }) : null;
  if (provenHash !== oldHash && jws) {
    provenHash = await credentialHash(env, { key: "", jws });
  }
  if (!provenHash || provenHash !== oldHash) return false;

  // Guarded on the old value, so two Macs racing one migration can't half-move the identity: the
  // second UPDATE matches nothing and it re-reads the new state next time.
  //
  // RETURNING rather than `meta.changes` because it says what moved, not how many, which suits a
  // guarded conditional update.
  const moved = await env.DB.prepare(
    "UPDATE identities SET license_hash = ? WHERE id = ? AND license_hash = ? RETURNING id"
  ).bind(newHash, identityID, oldHash).first();
  if (!moved) return false;

  // The seat cap counts devices per licence. Old rows left behind would hold seats on a licence
  // the identity no longer belongs to, and their tokens would still authenticate.
  const stale = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE identity_id = ? AND license_hash = ? AND revoked_at IS NULL " +
    "RETURNING id"
  ).bind(stamp, identityID, oldHash).all();
  for (const device of stale.results ?? []) {
    // Out of the inbox too, or `alarm()` keeps pushing to a device that can't connect. Same as
    // the seat eviction below.
    await inboxCall(env, identityID, "/devices/remove", { device: device.id }).catch(() => {});
  }

  console.log(`identity migrated devices=${(stale.results ?? []).length}`);
  return true;
}

// ---------------------------------------------------------------- auth

async function authenticate(request, env, ctx, opts) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  return authenticateToken(header.slice(7).trim(), env, ctx, opts);
}

/// Split out for the WebSocket upgrade, which reaches the token a second way.
///
/// `MessagingClient.openSocket` sends an Authorization header, and that's the path to keep:
/// with `observability` on, Workers Logs records the URL verbatim, so a query-string token is a
/// never-expiring credential in a searchable index. The `?token=` fallback is only for builds
/// from before the header; drop it once none are left.
/// `allowExpired` drops only the entitlement clause, never the device, revocation or
/// license-status checks.
///
/// It's for `releaseDevice`: releasing your own Mac is cleanup, not access. Without it a lapsed
/// member gets 401 on the one call that hands their seat back, and the seat stays taken until
/// LRU eviction. Same exemption as files-worker's `authenticate`.
async function authenticateToken(token, env, ctx, { allowExpired = false, touch = true } = {}) {
  if (!token) return null;
  const tokenHash = await sha256Hex(token);

  // One round trip: the INNER JOIN yields no row for a revoked device or a missing license.
  //
  // The entitlement clause is what makes a subscription recur, with no timer: an expired row
  // gives no auth row, so a 401, so the client re-activates (MessagingService.swift, the
  // .reactivate branch). Re-activation is a real Gumroad or Apple call that either extends the
  // horizon or answers 403 subscription_required. Nothing polls.
  //
  // NULL passes forever: `entitled_until IS NULL` is the grandfathered case.
  const row = await env.DB.prepare(
    "SELECT d.id AS device_id, d.identity_id, d.license_hash, l.status " +
    "FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
    "WHERE d.token_hash = ? AND d.revoked_at IS NULL " +
    (allowExpired ? "" : "AND (l.entitled_until IS NULL OR l.entitled_until > ?)")
  ).bind(...(allowExpired ? [tokenHash] : [tokenHash, now()])).first();
  if (!row) return null;
  // A blocked license keeps its token but loses the service. Revoked is Gumroad's word (refund,
  // chargeback); blocked is ours (abuse).
  if (row.status !== "active") return null;

  // Not when the caller only asks why a request failed (`refusal`). Seat eviction orders by
  // `last_seen_at`, so bumping it for a request we're about to 401 keeps a lapsed device that
  // keeps polling at the top of the LRU, evicting a healthy quieter Mac. And it would cost a D1
  // write per refused request.
  if (touch) {
    ctx.waitUntil(
      env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?")
        .bind(now(), row.device_id).run()
    );
  }
  return { deviceID: row.device_id, identityID: row.identity_id, licenseHash: row.license_hash };
}

/// The 401 to send, once `authenticate` has already said no.
///
/// Two refusals share this status. An unknown or revoked token means "activate again". A live
/// token whose licence is past its horizon means "someone must re-prove this licence", and for
/// a phone that isn't itself: its one-time link code was spent at pairing, so dropping its
/// token to re-activate would end its Friends access for good.
///
/// One extra read, only on a path that already failed. `touch: false` so a device that only
/// ever 401s doesn't sit at the head of the eviction LRU. Older clients read any 401 as
/// `reactivate`, which is what they always did.
async function refusal(token, env, ctx) {
  if (!token) return fail(401, "reactivate");
  const stillValid = await authenticateToken(token, env, ctx, { allowExpired: true, touch: false });
  return stillValid ? fail(401, "entitlement_lapsed") : fail(401, "reactivate");
}

// ---------------------------------------------------------------- routes

async function activateDevice(request, env) {
  let body;
  try {
    body = objectBody(await request.json());
  } catch {
    return fail(400, "bad_request");
  }
  // `JSON.parse("null")` succeeds, so the catch misses a `null` body and the reads below would
  // throw a 500. Same for a bare string or array.
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(400, "bad_request");
  const key = typeof body.license_key === "string" ? body.license_key.trim() : "";
  const jws = typeof body.app_transaction === "string" ? body.app_transaction.trim() : "";
  // An entitlement proof, not a credential (like migrate_app_transaction), so it's left out of
  // the one-credential check. It decides how long, never who.
  const subJWS = typeof body.app_subscription === "string" ? body.app_subscription.trim() : "";
  // A Gumroad membership key entered in the App Store build under "Already subscribed
  // elsewhere?". Also only an entitlement proof; `hash` is never derived from it, or every
  // redeeming Mac would go through migration on each activation and move its friendships to a
  // different licence.
  const redeemKey = typeof body.redeem_license_key === "string" ? body.redeem_license_key.trim() : "";
  // The Setapp build's single-use authorization code, exchanged with Setapp's Vendor API below.
  // A credential, since the licence hash is derived from what it resolves to.
  const setappCode = typeof body.setapp_code === "string" ? body.setapp_code.trim() : "";
  // A one-time code a Mac minted for a phone (`POST /v1/link`). A borrowed credential: it
  // resolves to a licence hash someone else proved, verifies nothing with any vendor, and can
  // never create a licence row.
  const linkCode = typeof body.link_code === "string" ? body.link_code.trim() : "";
  // Exactly one of the four. Silently picking a winner is how one build ends up authenticating
  // as somebody else's licence.
  if ([key, jws, setappCode, linkCode].filter(Boolean).length !== 1) return fail(400, "bad_request");
  if (key && key.length > 100) return fail(400, "bad_request");
  if (setappCode && setappCode.length > 512) return fail(400, "bad_request");
  if (linkCode && linkCode.length > 128) return fail(400, "bad_request");
  if (jws && jws.length > MAX_APP_TRANSACTION_CHARS) return fail(400, "bad_request");
  if (subJWS && subJWS.length > MAX_APP_TRANSACTION_CHARS) return fail(400, "bad_request");
  if (redeemKey && redeemKey.length > 100) return fail(400, "bad_request");
  if (!isPublicKey(body.public_key)) return fail(400, "bad_public_key");

  const stamp = now();
  let hash;
  let saleID = null;
  let source;
  // NULL means entitled forever: any path that doesn't set a horizon is grandfathered.
  let entitledUntil = null;
  // How many Macs this row may keep once written. Every branch that can add a device lowers it,
  // so one sale means five devices in total, not five per Apple Account (see `saleSeatBudget`
  // and the eviction). Setapp is the exception: it counts devices itself, per purchase.
  let deviceBudget = MAX_DEVICES_PER_LICENSE;
  // True when riding a licence someone else proved (a phone spending a link code). It may add a
  // device but must never write the `licenses` row (see the link branch and the skipped upsert).
  let borrowed = false;

  // Before either credential branch, because the hazard is what gets written, not which door it
  // came through. Both entitlement rules answer NULL when the cutover is missing, and NULL on a
  // new row is permanent: the INSERT writes it and the upsert's first CASE pins it. So 503
  // instead. See `entitlementMisconfigured`; a self-hoster sets neither var and never hits it.
  if (entitlementMisconfigured(env)) return fail(503, "appstore_unconfigured");

  if (jws) {
    const { status, appTransactionID, originalPurchaseMs } = await verifyAppTransaction(jws, env);
    if (status === "unconfigured") return fail(503, "appstore_unconfigured");
    if (status !== "active") return fail(403, "bad_license");
    hash = await appStoreHash(appTransactionID);
    source = "appstore";
    entitledUntil = appStoreEntitlement(originalPurchaseMs, env);
    // "lapsed" here only means "bought after the cutover", not yet a refusal: a live
    // subscription is the other way in. Grandfathered buyers never get here.
    if (entitledUntil === "lapsed") {
      const sub = subJWS
        // `appStoreVerifiers` is passed in because its dynamic import of
        // @apple/app-store-server-library resolves against this worker's package.json. See
        // worker-shared/entitlement.js.
        ? await verifyAppSubscription(subJWS, env, appTransactionID, appStoreVerifiers)
        : { status: "invalid", entitledUntil: null };
      if (sub.status !== "active") {
        // No StoreKit subscription. A website membership is the other way in (guideline
        // 3.1.3(b), allowed because the same membership is also an in-app purchase). Verified
        // with the ordinary Gumroad path and rule, and used only for the horizon.
        const redeemed = redeemKey ? await verifyLicense(redeemKey, env) : { status: "unset" };
        // "unreachable" is Gumroad down, not this person unentitled. A 403 here would let a
        // third-party rate limit revoke a paid feature, which the client then latches
        // (markNotEntitled / markNoServerFeatures). §12 forbids that.
        if (redeemed.status === "unreachable") return fail(503, "gumroad_down");
        // A membership, not any key. `verifyLicense` tries both products, so a one-time key comes
        // back `active` with a null horizon, which the upsert's once-forever CASE would pin as
        // permanent, on unlimited App Store accounts, spending no seat. Null here means "not a
        // membership".
        if (redeemed.status !== "active" || redeemed.entitledUntil === null) {
          // Only now is missing product-id config fatal: it must not preempt a good website
          // membership.
          if (sub.status === "unconfigured") return fail(503, "appstore_unconfigured");
          return fail(403, "subscription_required");
        }
        // Seat cap. Nothing else bounds this path: it spends no Gumroad seat and each Apple
        // Account gets its own `licenses` row, so one key posted publicly would entitle unlimited
        // accounts. `saleSeatBudget` is shared with the Gumroad branch so the same sale can't
        // take a fresh allowance through the other door.
        const budget = await saleSeatBudget(env, redeemed.saleID, hash);
        if (budget === null) return fail(403, "seat_limit");
        deviceBudget = budget;
        entitledUntil = redeemed.entitledUntil;
        // Recorded so the next redeemer counts against this sale; anonymous rows are invisible
        // to the cap.
        saleID = redeemed.saleID;
      } else {
        entitledUntil = sub.entitledUntil;
      }
    }
    // No revoked branch: Apple refunds aren't visible here. That needs App Store Server
    // Notifications V2 and a webhook, and §14 says fail open, no DRM until piracy is real.
    // `blocked` below still works; that's our abuse decision, on either channel.
  } else if (setappCode) {
    // Setapp, verified inline and forgotten. The code becomes an access token, which answers two
    // questions; neither it nor its refresh token is stored. The next check happens when
    // `entitled_until` expires and the client activates with a fresh code. No cron, no token
    // table, no refresh rotation.
    //
    // `setappMisconfigured` is this branch's `entitlementMisconfigured`: a deploy that can't ask
    // Setapp must say so, not mint a permanent grandfathered row.
    if (setappMisconfigured(env)) return fail(503, "setapp_unconfigured");
    const { status, userID } = await verifySetappAccess(setappCode, env);
    // Fail closed, as in the Gumroad branch: existing tokens keep working while Setapp is down,
    // but a new one without an answer would make "vendor down" a free pass.
    if (status === "unreachable") return fail(503, "setapp_down");
    // Expired, spent, or not ours. The client doesn't latch it: a fresh code is one launch away,
    // and the usual cause is a slow hand between the two Workers.
    if (status === "invalid") return fail(403, "bad_license");
    // Setapp says no. Their launch agent usually stops a lapsed subscriber first, so this is a
    // subscription that ended between launch and now.
    if (status === "refused") return fail(403, "subscription_required");

    hash = await setappHash(userID);
    source = "setapp";
    // Never null: a null horizon is permanent (the upsert's CASE pins it), and a cancellable
    // Setapp subscription must never be written as entitled forever.
    entitledUntil = stamp + SETAPP_RECHECK_SECONDS;
    // No `saleSeatBudget`: Setapp counts devices itself, per purchase, chosen at checkout. The
    // per-hash LRU below is the backstop.
  } else if (linkCode) {
    // A phone joining a licence its Mac already proved.
    //
    // Nothing to verify with a vendor: the code is the Worker's own word, minted at
    // `POST /v1/link` for an authenticated device. So it must never create or refresh a licence;
    // it reads the row, refuses if it can't take another device, and leaves `entitled_until`
    // alone. Extending it would let a phone keep a lapsed licence alive on an old code.
    const redeemed = await redeemLinkCode(env, linkCode);
    if (!redeemed) return fail(403, "bad_license");
    hash = redeemed.license_hash;
    borrowed = true;

    const row = await env.DB.prepare(
      "SELECT status, entitled_until, gumroad_sale_id FROM licenses WHERE license_hash = ?"
    ).bind(hash).first();
    if (!row) return fail(403, "bad_license");
    if (row.status !== "active") return fail(403, "revoked");
    if (row.entitled_until !== null && row.entitled_until <= stamp) {
      return fail(403, "subscription_required");
    }
    // The sale's budget, as in the credential branches. Not Setapp-only: `POST /v1/link` is open
    // to any authenticated device, so without this a link on a Gumroad membership would get the
    // full `MAX_DEVICES_PER_LICENSE` after the sale's other hashes spent it, and the eviction
    // (scoped to `license_hash`) can't see that. A borrowed activation spends a seat like any
    // other; it just must not write the licence row, which `borrowed` governs.
    const budget = await saleSeatBudget(env, row.gumroad_sale_id, hash);
    if (budget === null) return fail(403, "seat_limit");
    deviceBudget = budget;
  } else {
    const { status: verdict, saleID: gumroadSaleID, entitledUntil: until } = await verifyLicense(key, env);
    // Fail closed here, and only here. The app's license gate fails open (CLAUDE.md §12) and an
    // issued token keeps working while Gumroad is down, but a new token without a check would
    // make "Gumroad is unreachable" a free pass.
    if (verdict === "unreachable") return fail(503, "gumroad_down");
    if (verdict === "invalid") return fail(403, "bad_license");

    hash = await licenseHash(key);
    saleID = gumroadSaleID;
    source = "gumroad";
    entitledUntil = until;

    // A real key whose membership stopped. Not "revoked": nothing was refunded, so the row keeps
    // its status and the app its key, and paying again makes the next activation just work.
    if (verdict === "lapsed") return fail(403, "subscription_required");

    if (verdict === "revoked") {
      await env.DB.prepare(
        // Same CASE as the active upsert below. Writing 'revoked' unconditionally would launder
        // an admin block: 'blocked' becomes 'revoked', and a reversed refund then lets the next
        // activation promote it to 'active', since that CASE only protects 'blocked'. Mirrors
        // mushroom-files.
        "INSERT INTO licenses (license_hash, status, checked_at, created_at) VALUES (?, 'revoked', ?, ?) " +
        "ON CONFLICT(license_hash) DO UPDATE SET " +
        "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'revoked' END, " +
        "checked_at = excluded.checked_at"
      ).bind(hash, stamp, stamp).run();
      return fail(403, "revoked");
    }

    // The same cap as the redeem branch. The eviction below is scoped to `license_hash`, and a
    // direct-build Mac hashes the key while a redeeming Apple Account hashes its transaction, so
    // without this one sale gets a full allowance per door. After the revoked branch so a refused
    // key costs no query.
    const budget = await saleSeatBudget(env, saleID, hash);
    if (budget === null) return fail(403, "seat_limit");
    deviceBudget = budget;
  }

  // Every branch, on whichever hash it produced, and before the upsert so a refused credential
  // leaves no `licenses` row. See enrolmentAllows; same 403 the shim gives an unlisted key.
  if (!enrolmentAllows(hash, env)) return fail(403, "bad_license");

  // Never downgrade a blocked license to active on re-activation: blocking is our abuse
  // decision, and neither Gumroad nor Apple has a say.
  //
  // `entitled_until` is monotonic both ways: NULL never becomes a horizon, and a horizon never
  // becomes NULL. Only horizon -> horizon moves, which is a renewal.
  //
  // One exception: a NULL on a row that isn't active. The revoked INSERT writes NULL because it
  // has no horizon to give, and pinning that would grandfather forever a membership first seen
  // while refunded or disputed, once the refund is reversed.
  //
  // Horizon -> NULL would make a config slip irreversible: `appStoreEntitlement()` answers NULL
  // when ENTITLEMENT_CUTOVER is absent, 0 or unparseable, and `wrangler deploy` replaces `vars`
  // wholesale, so one deploy missing the var (it ships commented out) would make every subscriber
  // activating in that window permanent, with no fix but hand-written SQL in production.
  // Grandfathering a horizon row on purpose is that same manual act, a fair price.
  //
  // NULL -> horizon being impossible is what makes grandfathering stick, even if a later build
  // computes the wrong horizon, someone flips the cutover, or Gumroad briefly omits
  // `subscription_id`. Every row that existed at the migration is NULL, so every earlier user is
  // grandfathered with no backfill or date math.
  //
  // Skipped for a borrowed activation. A phone spending a link code proved nothing to anyone;
  // the upsert would stamp `checked_at` as if a vendor had been asked and carry its null
  // `entitledUntil` into a row with a real horizon. The link branch already vetted the row.
  if (!borrowed) {
    await env.DB.prepare(
      "INSERT INTO licenses (license_hash, status, checked_at, created_at, gumroad_sale_id, source, entitled_until) " +
      "VALUES (?, 'active', ?, ?, ?, ?, ?) " +
      "ON CONFLICT(license_hash) DO UPDATE SET " +
      "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'active' END, " +
      "checked_at = excluded.checked_at, " +
      "gumroad_sale_id = COALESCE(excluded.gumroad_sale_id, licenses.gumroad_sale_id), " +
      "entitled_until = CASE " +
      "WHEN licenses.entitled_until IS NULL AND licenses.status = 'active' THEN NULL " +
      "WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until " +
      "ELSE excluded.entitled_until END"
    ).bind(hash, stamp, stamp, saleID, source, entitledUntil).run();
  }

  const blocked = await env.DB.prepare("SELECT status FROM licenses WHERE license_hash = ?")
    .bind(hash).first();
  if (blocked?.status !== "active") return fail(403, "revoked");

  const identityID = await identityFor(body.public_key);

  // First claim wins, and it's the only thing between a friend and your inbox. Public keys aren't
  // secret (`/v1/friends` hands them out, `friend_added` pushes them, accepting an invite returns
  // the inviter's), and X25519 keys can't sign, so there's no challenge. Without this, anyone
  // with a valid license could post someone else's public key, get a token for that identity,
  // read their friend list, register a push token and `remove` every friendship (and its
  // messages). Binding the identity to the first license that claimed it costs one lookup.
  const claimed = await env.DB.prepare("SELECT license_hash FROM identities WHERE id = ?")
    .bind(identityID).first();
  // No row, but an inbox with friends or messages: an identity whose row migration 0004 deleted
  // (pre-0002, every device swept). Its owner can't be told from a former friend holding the
  // public key, so nobody gets it; the owner's way back is Start Over, a new identity.
  if (!claimed) {
    const response = await inboxCall(env, identityID, "/occupied", {}).catch(() => null);
    if (!response?.ok) return fail(503, "try_again");
    if ((await response.json()).occupied) return fail(403, "identity_claimed");
  }
  if (claimed && claimed.license_hash && claimed.license_hash !== hash) {
    // Before refusing: someone switching between the direct download and the App Store arrives
    // with a good credential on a Mac whose identity is bound to the other channel's hash. If
    // they can also produce that credential, it's a migration, not a theft. See
    // `migrateIdentity`.
    if (!(await migrateIdentity(env, identityID, claimed.license_hash, hash, body, stamp))) {
      // Its own code, not `bad_license`: this is a good key meeting an identity another license
      // owns, the opposite of a key to re-check. Shared, the app told a user with a valid
      // licence "I could not find your license. Try Settings, License", pointed at a pane that
      // already had the key, and stopped retrying for the session.
      return fail(403, "identity_claimed");
    }
  }

  // The id is the key's hash, so an existing row already holds this key. `license_hash` is set
  // on first claim and never moved; COALESCE binds a NULL from before the column existed to
  // whoever activates next.
  await env.DB.prepare(
    "INSERT INTO identities (id, public_key, license_hash, created_at) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET license_hash = COALESCE(identities.license_hash, excluded.license_hash)"
  ).bind(identityID, body.public_key, hash, stamp).run();
  // The check above is a read before this write, so two first claims racing under different
  // licences both pass it. The COALESCE keeps the winner; the loser stops here, before a device.
  const owner = await env.DB.prepare("SELECT license_hash FROM identities WHERE id = ?")
    .bind(identityID).first();
  if (owner?.license_hash !== hash) return fail(403, "identity_claimed");

  // This Mac's previous row goes first, making a re-activation a reclaim, not a second seat. The
  // client sends the device id it holds; otherwise its stale row looks like another Mac's, the
  // eviction counts it as live, and a healthy Mac is evicted on every re-activation. That's
  // routine: the horizon expires every LICENSE_RECHECK_SECONDS.
  //
  // Scoped to this licence hash, so a lifted device id can't revoke another licence's Mac. Out
  // of the inbox as well as D1, like the eviction below: a row left there keeps a live APNs
  // token with a frozen `last_acked_seq` and is pushed to under an id the Mac no longer uses.
  const priorID = typeof body.device_id === "string" ? body.device_id.slice(0, 64) : null;
  if (priorID) {
    const prior = await env.DB.prepare(
      "SELECT identity_id FROM devices WHERE id = ? AND license_hash = ? AND revoked_at IS NULL"
    ).bind(priorID, hash).first();
    if (prior) {
      await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?")
        .bind(stamp, priorID).run();
      await inboxCall(env, prior.identity_id, "/devices/remove", { device: priorID })
        .catch(() => {});
    }
  }

  // Past the cap, evict the least-recently-seen Mac rather than refuse: a 409 would strand
  // someone who reinstalled twice, and the evicted Mac re-activates on its next 401. Scoped to
  // the license, not the identity: five devices, however many keys.
  const live = await env.DB.prepare(
    "SELECT id, identity_id FROM devices WHERE license_hash = ? AND revoked_at IS NULL " +
    "ORDER BY last_seen_at DESC"
  ).bind(hash).all();
  for (const device of (live.results ?? []).slice(deviceBudget - 1)) {
    await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?")
      .bind(stamp, device.id).run();
    // And out of the inbox, where `alarm()` looks. A row left there keeps a live APNs token with
    // a frozen `last_acked_seq`, so every message pushes to it though the Mac is acking under its
    // new id. `identity_id` is selected above only to address the inbox.
    await inboxCall(env, device.identity_id, "/devices/remove", { device: device.id })
      .catch(() => {});
  }

  const token = randomToken() + randomToken();     // 32 bytes of entropy for a bearer token
  const id = crypto.randomUUID();
  const name = typeof body.device_name === "string"
    ? body.device_name.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, MAX_DEVICE_NAME_CHARS)
    : null;

  await env.DB.prepare(
    "INSERT INTO devices (id, identity_id, license_hash, token_hash, name, created_at, last_seen_at) " +
    "VALUES (?,?,?,?,?,?,?)"
  ).bind(id, identityID, hash, await sha256Hex(token), name, stamp, stamp).run();

  return reply(201, { device_id: id, identity_id: identityID, token, limits: limits() });
}

/// Give up this Mac's token, so a seat is freed for another.
async function releaseDevice(env, auth) {
  await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?")
    .bind(now(), auth.deviceID).run();
  // The inbox copy too, or "Start Over" leaves the abandoned identity with this Mac's live APNs
  // token, and friends' messages to it become banners the app can't open.
  await inboxCall(env, auth.identityID, "/devices/remove", { device: auth.deviceID })
    .catch(() => {});
  return reply(200, {});
}

/// Every device this licence pays for, so the user can manage them.
///
/// By `license_hash`, not `identity_id`: the cap counts per licence, so an identity-keyed list
/// would hide exactly the rows using the seats the user is being evicted over.
///
/// Ids, names and timestamps only; no token (`token_hash` isn't selected) and no message.
async function listDevices(env, auth) {
  const rows = await env.DB.prepare(
    "SELECT id, name, created_at, last_seen_at FROM devices " +
    "WHERE license_hash = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC"
  ).bind(auth.licenseHash).all();
  return reply(200, {
    limit: MAX_DEVICES_PER_LICENSE,
    devices: (rows.results ?? []).map((row) => ({
      id: row.id,
      name: row.name,
      created_at: row.created_at,
      last_seen_at: row.last_seen_at,
      // So the app can label the user's own device and not offer to sign it out. Computed here
      // so the client needn't compare device ids itself.
      this_device: row.id === auth.deviceID,
    })),
  });
}

/// Sign another of this licence's devices out.
///
/// Not a cryptographic revocation, and the UI must not claim one: the device keeps the X25519
/// key in its Keychain and can re-activate if it still has the credential. This frees the seat
/// and stops delivery. Really losing a device means Start Over, which mints a new identity.
///
/// Scoped to the caller's `license_hash`, like the reclaim in `activateDevice`, or this would
/// sign out any device whose id you could guess or observe.
async function revokeDevice(request, env, auth) {
  let body;
  try {
    body = objectBody(await request.json());
  } catch {
    return fail(400, "bad_json");
  }
  const target = typeof body.device_id === "string" ? body.device_id.slice(0, 64) : null;
  if (!target) return fail(400, "bad_device");
  // Signing yourself out is `releaseDevice`'s job; doing it here leaves the app holding a token
  // it thinks is good while every call 401s.
  if (target === auth.deviceID) return fail(400, "cannot_revoke_self");

  const row = await env.DB.prepare(
    "SELECT identity_id FROM devices WHERE id = ? AND license_hash = ? AND revoked_at IS NULL"
  ).bind(target, auth.licenseHash).first();
  // Same answer for someone else's row and a missing one, or this is an oracle for device ids.
  if (!row) return fail(404, "not_found");

  await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?")
    .bind(now(), target).run();
  // Out of the inbox as well as D1, like the eviction in `activateDevice`: a row left there keeps
  // a live APNs token and every later message pushes to a device that can't connect.
  await inboxCall(env, row.identity_id, "/devices/remove", { device: target }).catch(() => {});
  console.log(`device revoked by peer device=${target}`);
  return reply(200, {});
}

// ---------------------------------------------------------------- invites

/// Mint a one-time code that lets a phone join this licence.
///
/// The caller is authed, so the Worker vouches for the licence to a second device; that's how a
/// Setapp Mac can pair a phone at all. The code is a bearer secret for ten minutes: stored hashed,
/// returned once, never persisted or logged by `PairPhoneView`.
///
/// No rate limit beyond the general gate: minting is cheap, codes die fast, and someone who
/// scans badly and taps again shouldn't be told to wait.
async function createLink(env, auth) {
  // Each code is a live credential and a D1 row until the daily sweep, so a loop would mint
  // both without bound. A person pairs a phone a few times a year.
  if (!(await throttle(env, auth.identityID, "link", LINKS_PER_HOUR, 3600))) {
    return fail(429, "rate_limited", { retry_after: 3600 });
  }
  const stamp = now();
  // Same entropy as a device token: it's a bearer credential while it lives.
  const code = randomToken();
  await env.DB.prepare(
    "INSERT INTO link_codes (code_hash, license_hash, expires_at, created_at) VALUES (?,?,?,?)"
  ).bind(await sha256Hex(code), auth.licenseHash, stamp + LINK_CODE_TTL_SECONDS, stamp).run();
  return reply(201, { code, expires_in: LINK_CODE_TTL_SECONDS });
}

async function createInvite(env, auth) {
  const stamp = now();
  const since = stamp - 86400;
  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM invites WHERE identity_id = ? AND created_at > ?"
  ).bind(auth.identityID, since).first();
  if ((recent?.n ?? 0) >= INVITES_PER_DAY) {
    return fail(429, "rate_limited", { retry_after: 3600 });
  }

  // Retry on collision rather than trusting 32^8. Three is plenty: only a handful of codes are
  // ever live.
  for (let attempt = 0; attempt < 3; attempt++) {
    const code = inviteCode();
    try {
      await env.DB.prepare(
        "INSERT INTO invites (code, identity_id, expires_at, created_at) VALUES (?,?,?,?)"
      ).bind(code, auth.identityID, stamp + INVITE_TTL_SECONDS, stamp).run();
      return reply(201, { code, expires_at: stamp + INVITE_TTL_SECONDS });
    } catch {
      // PRIMARY KEY conflict. Any other failure will surface on the next attempt too.
    }
  }
  return fail(503, "try_again");
}

async function acceptInvite(request, env, auth) {
  let body;
  try {
    body = objectBody(await request.json());
  } catch {
    return fail(400, "bad_request");
  }
  const code = normalizeInvite(body.code);
  if (!wellFormedInvite(code)) return fail(404, "invite_not_found");

  // 2^40 codes is plenty against a person, nothing against a loop: every distinct answer here
  // (not_found, expired, used) is an existence oracle one account could grind.
  if (!(await throttle(env, auth.identityID, "accept", ACCEPTS_PER_HOUR, 3600))) {
    return fail(429, "rate_limited", { retry_after: 3600 });
  }

  const invite = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(code).first();
  if (!invite) return fail(404, "invite_not_found");
  // Expiry before used, so an old code reads as expired rather than as someone else's.
  if (invite.expires_at <= now()) return fail(410, "invite_expired");
  if (invite.used_at) return fail(409, "invite_used");
  // Its own case: the likeliest mistake while testing, and "not found" would mislead.
  if (invite.identity_id === auth.identityID) return fail(409, "self_invite");

  const inviter = await env.DB.prepare("SELECT * FROM identities WHERE id = ?")
    .bind(invite.identity_id).first();
  const accepter = await env.DB.prepare("SELECT * FROM identities WHERE id = ?")
    .bind(auth.identityID).first();
  if (!inviter || !accepter) return fail(404, "invite_not_found");

  // Burn the code before writing the friendship. The conditional UPDATE handles races: one Mac
  // wins the row, the other gets zero changes and a 409.
  const burnedAt = now();
  const burn = await env.DB.prepare(
    "UPDATE invites SET used_at = ? WHERE code = ? AND used_at IS NULL"
  ).bind(burnedAt, code).run();
  if (!burn.meta.changes) return fail(409, "invite_used");

  // Both directions: an inbox that doesn't know the friendship refuses its messages.
  // `allSettled`, not `all`: a rejected subrequest (an inbox restarting mid-deploy) would throw
  // out of the Worker past the un-burn below, leaving the code spent and the pair incomplete.
  const settled = await Promise.allSettled([
    inboxCall(env, invite.identity_id, "/friends/add",
              { peer: auth.identityID, public_key: accepter.public_key }),
    inboxCall(env, auth.identityID, "/friends/add",
              { peer: invite.identity_id, public_key: inviter.public_key }),
  ]);
  const [inviterHalf, accepterHalf] = settled.map(
    (r) => (r.status === "fulfilled" ? r.value : null));
  // findIndex, not find: a rejected half is `null`, which `find` returns and an `if` reads as
  // "nothing failed".
  const failed = [inviterHalf, accepterHalf].findIndex((r) => !r || !r.ok) !== -1;
  if (failed) {
    // Give the code back. One half can land while the other refuses (accepter at MAX_FRIENDS,
    // an inbox 503s) after the burn committed; otherwise the inviter keeps a friend whose inbox
    // answers `not_friends` and the code is spent. `/friends/add` is an upsert, so a retry
    // finishes the missing half without duplicating the other.
    // Conditional on our own stamp, or it could clear a later accept's burn and hand one code
    // to two people.
    await env.DB.prepare(
      "UPDATE invites SET used_at = NULL WHERE code = ? AND used_at = ?"
    ).bind(code, burnedAt).run();
    // Only the accepter's own half decides "you have reached 50 friends". Otherwise an inviter
    // with no room sends the accepter off deleting their own friends.
    if (accepterHalf && accepterHalf.status === 409) {
      return fail(409, "too_many_friends", { max_friends: MAX_FRIENDS });
    }
    return fail(503, "try_again");
  }

  return reply(201, { peer_id: invite.identity_id, public_key: inviter.public_key });
}

// ---------------------------------------------------------------- friends and history

/// `device` travels with the cursor so the inbox can refuse to skip past its own ack.
const syncMessages = (env, auth, url) =>
  inboxCall(env, auth.identityID, "/sync", {
    after: Number(url.searchParams.get("after") ?? 0) || 0,
    device: auth.deviceID,
  });

async function friendAction(env, auth, peerID, action) {
  const response = await inboxCall(env, auth.identityID, `/friends/${action}`, { peer: peerID });
  if (!response.ok) return fail(response.status === 404 ? 404 : 503, "try_again");
  return reply(200, {});
}

const registerPush = async (request, env, auth) => {
  let body;
  try {
    body = objectBody(await request.json());
  } catch {
    return fail(400, "bad_request");
  }
  // An APNs token is 32 bytes of hex. Sandbox vs production picks the host; the wrong one
  // silently never delivers.
  if (typeof body.token !== "string" || !/^[0-9a-fA-F]{64}$/.test(body.token)) {
    return fail(400, "bad_request");
  }
  const environment = body.environment === "sandbox" ? "sandbox" : "production";
  // Allowlisted: the topic is an APNs header and our .p8 signs only for these bundle ids, so an
  // arbitrary string would let a client aim our push credentials at a topic we didn't choose.
  // Unknown values fall back to the deployment default rather than being refused, so other
  // client versions still get push.
  const topic = PUSH_TOPICS.includes(body.topic) ? body.topic : null;
  const response = await inboxCall(env, auth.identityID, "/push/register", {
    device: auth.deviceID, token: body.token.toLowerCase(), environment, topic,
  });
  return response.ok ? reply(200, {}) : fail(503, "try_again");
};

/// Every bundle id this deployment's APNs key may address.
///
/// Two, because Setapp requires a permanent `-setapp` suffix. `APNS_TOPIC` overrides the default
/// for tokens with no topic; this list is what a client may ask for.
const PUSH_TOPICS = ["com.qubit.shroomy.app", "com.qubit.shroomy.app-setapp"];

// ---------------------------------------------------------------- APNs
//
// Token-based auth: an ES256 JWT signed with the .p8 key, good for an hour. Secrets are
// APNS_KEY_P8, APNS_KEY_ID and APNS_TEAM_ID, set with `wrangler secret put`.

function base64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function apnsPEM(env) {
  return (env.APNS_KEY_P8 ?? "")
    .replace(/-----(BEGIN|END)[^-]*-----/g, "")
    // Escape sequences first, as pairs; the order matters. A .p8 passed through a shell var, CI
    // secret store or JSON arrives with `\n` as two characters. Strip non-base64 first and the
    // backslash goes but the `n` (valid base64) stays, so the key decodes to wrong bytes
    // instead of failing. test.sh pins this ordering.
    .replace(/\\[rnt]/g, "")
    // Then anything else outside the alphabet, instead of listing every way a .p8 arrives
    // mangled.
    //
    // Tolerant on purpose; it decides nothing. `crypto.subtle.importKey` says whether what's left
    // is a valid PKCS#8 key. Being strict here only caused a silent outage: `atob()` complaining
    // inside a catch that swallowed it.
    .replace(/[^A-Za-z0-9+/=]/g, "");
}



/// Whether this deployment can send push at all, as opposed to right now.
///
/// `apnsKey` throws the same for "never set" and "malformed", and retrying is right only for
/// the second. A customer running this Worker in their own account can't have push (only our
/// .p8 signs for `com.qubit.shroomy.app`), so retrying an absent key wakes every inbox with an
/// unacked message forever and bills them for it. Malformed retries; absent stops.
/// All three, not just the key: `mintAPNsToken` puts `APNS_KEY_ID` in the JWT header and
/// `APNS_TEAM_ID` in the payload, unchecked elsewhere. With the key alone the token ships
/// `kid: undefined` / `iss: undefined`, APNs answers 403 InvalidProviderToken, which isn't 410,
/// so the retry ladder runs for every message forever.
function apnsConfigured(env) {
  return apnsPEM(env) !== "" && Boolean(env.APNS_KEY_ID) && Boolean(env.APNS_TEAM_ID);
}

async function apnsKey(env) {
  const pem = apnsPEM(env);
  if (!pem) throw new Error("no apns key");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der,
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

// The provider token, cached for the isolate's life.
//
// Apple answers `429 TooManyProviderTokenUpdates` to refreshes faster than about every 20
// minutes, and `deliver` arms an alarm every 10 seconds, so minting per alarm fails under
// exactly the load that needs push, and notifications stop silently. The documented lifetime
// is an hour; 50 minutes leaves room for a slow send.
let cachedAPNsToken = null;
const APNS_TOKEN_TTL_SECONDS = 50 * 60;

async function apnsToken(env) {
  if (cachedAPNsToken && now() - cachedAPNsToken.issued < APNS_TOKEN_TTL_SECONDS) {
    return cachedAPNsToken;
  }
  cachedAPNsToken = await mintAPNsToken(env);
  return cachedAPNsToken;
}

async function mintAPNsToken(env) {
  const issued = now();
  const header = base64url(new TextEncoder().encode(
    JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID })));
  const payload = base64url(new TextEncoder().encode(
    JSON.stringify({ iss: env.APNS_TEAM_ID, iat: issued })));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, await apnsKey(env),
    new TextEncoder().encode(`${header}.${payload}`));
  return { jwt: `${header}.${payload}.${base64url(signature)}`, issued };
}

/// No content and no names in the payload; the server holds neither. `loc-key` is localized on
/// the Mac from the app's catalogs, so nothing readable crosses Apple's servers.
async function sendPush(env, jwt, token, environment, threadID, topic) {
  const host = environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  return fetch(`https://${host}/3/device/${token}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      // Per device: the topic must equal the token's bundle id, and the Setapp build is
      // `com.qubit.shroomy.app-setapp`. A wrong topic gets a 400 and no banner, with nothing
      // logged here. The env var is the fallback for tokens registered without a topic.
      "apns-topic": topic ?? env.APNS_TOPIC ?? "com.qubit.shroomy.app",
      "apns-push-type": "alert",
      "apns-priority": "10",
      // Explicit, because absent means 0, "try once, don't store". Every push here targets a
      // Mac that didn't ack (asleep or app closed), exactly what one attempt throws away. Nothing
      // else retries: APNs answers 200 even when it can't deliver yet.
      "apns-expiration": String(now() + PUSH_EXPIRY_SECONDS),
    },
    body: JSON.stringify({
      aps: {
        alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_BODY" },
        sound: "default",
        "thread-id": threadID,
      },
      // The peer id again, outside `aps`, so it reaches the app as `userInfo` and a tapped
      // banner knows what to open (`thread-id` isn't handed to the delegate). Leaks nothing the
      // thread id didn't.
      friendPeerID: threadID,
    }),
  });
}

// ---------------------------------------------------------------- the inbox

export class UserInbox {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;

    // `msg_id` UNIQUE plus INSERT OR IGNORE is the dedup: a retried send never becomes a
    // second message.
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages(
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        msg_id     TEXT NOT NULL UNIQUE,
        peer       TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        sent_at    INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer);
      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
      CREATE TABLE IF NOT EXISTS friends(
        peer       TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        blocked    INTEGER NOT NULL DEFAULT 0,
        added_at   INTEGER NOT NULL,
        -- Who we last heard was online, and when. Kept HERE rather than asked for on
        -- demand: querying every friend's inbox at connect time is what made two Macs
        -- connecting at once deadlock, each awaiting the other. See announcePresence.
        online_at  INTEGER
      );
      CREATE TABLE IF NOT EXISTS devices(
        device_id      TEXT PRIMARY KEY,
        apns_token     TEXT,
        apns_env       TEXT,
        last_acked_seq INTEGER NOT NULL DEFAULT 0,
        updated_at     INTEGER NOT NULL
      );
    `);
    // An older object already has its tables, so CREATE TABLE IF NOT EXISTS won't add columns,
    // and there's no way to enumerate objects to migrate them. So: try each ALTER and ignore
    // the "duplicate column" from objects that already have it.
    for (const alter of [
      "ALTER TABLE friends ADD COLUMN online_at INTEGER",
      "ALTER TABLE devices ADD COLUMN last_pushed_seq INTEGER NOT NULL DEFAULT 0",
      // NULL for clients that don't send a topic; `sendPush` then uses the deployment default.
      "ALTER TABLE devices ADD COLUMN apns_topic TEXT",
    ]) {
      try { this.sql.exec(alter); } catch { /* already has it */ }
    }
  }

  // -------------------------------------------------------------- small helpers

  rows(query, ...bindings) { return this.sql.exec(query, ...bindings).toArray(); }
  one(query, ...bindings) { return this.rows(query, ...bindings)[0] ?? null; }

  friend(peer) { return this.one("SELECT * FROM friends WHERE peer = ?", peer); }

  /// Every live socket, or only those belonging to one device.
  sockets() { return this.ctx.getWebSockets(); }

  async send(frame) {
    const text = JSON.stringify(frame);
    for (const socket of this.sockets()) {
      // Outbound too. A client that never sends a frame never meets the inbound check, and would
      // keep receiving after its device is revoked or its licence blocked or lapsed.
      if (!(await this.stillAuthorized(socket))) continue;
      try {
        socket.send(text);
      } catch {
        // A socket still being torn down. Drop the frame; catch-up on reconnect recovers it.
      }
    }
  }

  async sharePresence() {
    return (await this.ctx.storage.get("sharePresence")) !== false;
  }

  // -------------------------------------------------------------- HTTP

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/connect") return this.connect(request, url);

    let body = {};
    try {
      body = objectBody(await request.json());
    } catch { /* the internal callers below all tolerate an empty body */ }

    switch (path) {
      case "/friends/add": return this.addFriend(body);
      case "/friends/list": return this.listFriends();
      case "/friends/block": return this.setBlocked(body.peer, 1);
      case "/friends/unblock": return this.setBlocked(body.peer, 0);
      case "/friends/remove": return this.removeFriend(body.peer);
      case "/sync": return this.syncFrom(Number(body.after) || 0, body.device);
      case "/deliver": return this.deliver(body);
      case "/delivered": return this.markDelivered(body);
      case "/typing": return this.relayTyping(body);
      case "/presence": return this.peerPresence(body);
      case "/push/register": return this.savePushToken(body);
      // A device that lost its seat. Revoking in D1 isn't enough: `alarm()` reads this table,
      // and a stale row's `last_acked_seq` can never advance (acks are keyed on the live
      // socket's device id), so it would push every message to a Mac that's acking normally.
      case "/devices/remove": return this.removeDevice(body.device);
      case "/occupied": return reply(200, {
        occupied: !!(this.one("SELECT 1 AS x FROM friends LIMIT 1")
                     || this.one("SELECT 1 AS x FROM messages LIMIT 1")),
      });
      // Counter only, for `throttle` on routes with no inbox; touches nothing else here.
      case "/rate":
        return (await this.allow(body.bucket, body.limit, body.window))
          ? reply(200, {}) : fail(429, "rate_limited");
      default: return fail(404, "not_found");
    }
  }

  async addFriend({ peer, public_key: publicKey }) {
    if (!peer || !publicKey) return fail(400, "bad_request");
    const count = this.one("SELECT COUNT(*) AS n FROM friends WHERE blocked = 0");
    if ((count?.n ?? 0) >= MAX_FRIENDS && !this.friend(peer)) {
      return fail(409, "too_many_friends");
    }
    // Don't reset `blocked` on re-accept, or a blocked person gets back in with a fresh invite.
    this.sql.exec(
      "INSERT INTO friends (peer, public_key, blocked, added_at) VALUES (?, ?, 0, ?) " +
      "ON CONFLICT(peer) DO UPDATE SET public_key = excluded.public_key",
      peer, publicKey, now());
    // Tell this Mac about a friendship it didn't ask for. The accepter learns from the HTTP
    // reply; without this frame the code's creator learns nothing and drops every message from
    // the unknown friend. `/friends/list` covers the offline case; this covers the live one.
    await this.send({ t: "friend_added", peer_id: peer, public_key: publicKey });
    return reply(200, {});
  }

  /// Every friendship this inbox holds, for a client that may have missed one.
  ///
  /// Read on every connect, not just after an invite: a Mac asleep when its code was accepted
  /// has no other way to learn, and an unknown friendship silently swallows messages.
  listFriends() {
    return reply(200, {
      friends: this.rows("SELECT peer, public_key, blocked FROM friends").map((f) => ({
        peer_id: f.peer, public_key: f.public_key, blocked: !!f.blocked,
      })),
    });
  }

  setBlocked(peer, blocked) {
    if (!this.friend(peer)) return fail(404, "not_found");
    this.sql.exec("UPDATE friends SET blocked = ? WHERE peer = ?", blocked, peer);
    return reply(200, {});
  }

  /// Deleting a conversation drops the stored ciphertext too: "delete" means gone, not hidden.
  removeFriend(peer) {
    this.sql.exec("DELETE FROM messages WHERE peer = ?", peer);
    this.sql.exec("DELETE FROM friends WHERE peer = ?", peer);
    return reply(200, {});
  }

  /// Clamped to the device's own `last_acked_seq`, not just the cursor the client sends.
  ///
  /// The client's cursor is `MAX(seq)` of what it stored, not the highest contiguous seq: a
  /// failed page or an undecryptable message leaves a hole below it. Its ack correctly stays
  /// below the hole, so we still have the message, but asking from the MAX would skip it
  /// forever. Taking the lower makes the ack the one cursor.
  syncFrom(after, device) {
    if (device) {
      const row = this.one("SELECT last_acked_seq FROM devices WHERE device_id = ?", device);
      if (row) after = Math.min(after, row.last_acked_seq ?? 0);
    }
    const messages = this.rows(
      "SELECT seq, msg_id, peer, ciphertext, sent_at FROM messages WHERE seq > ? " +
      "ORDER BY seq LIMIT ?", after, SYNC_PAGE + 1);
    const page = messages.slice(0, SYNC_PAGE);
    return reply(200, {
      messages: page.map((m) => ({
        msg_id: m.msg_id, peer_id: m.peer, ciphertext: m.ciphertext,
        sent_at: m.sent_at, seq: m.seq, server_now: serverNow(),
      })),
      // The client keeps paging until this is false.
      has_more: messages.length > SYNC_PAGE,
    });
  }

  /// Store a message sent to us, and get it in front of the user.
  async deliver({ msg_id: msgID, from, ciphertext, sent_at: sentAt }) {
    if (!msgID || !from || !ciphertext) return fail(400, "bad_request");

    // The same self exception as `handleSend`, which calls this: writing to our own inbox is how
    // the user's other Macs learn what was sent, what people are called and what's been read.
    const mine = from === this.identity();
    const friend = this.friend(from);
    // Both 403s name their reason; the sender's app shows `blocked` as `not_friends` anyway.
    if (!mine && !friend) return fail(403, "not_friends");
    if (!mine && friend.blocked) return fail(403, "blocked");

    const stamp = now();
    // A ceiling per sender on what sits here. The send rate alone lets one friend store ~1.8 GB
    // a day for 30 days, past the object's storage limit, and then nobody's messages land.
    const held = this.one("SELECT COALESCE(SUM(length(ciphertext)), 0) AS n FROM messages WHERE peer = ?", from);
    if ((held?.n ?? 0) + String(ciphertext).length > MAX_STORED_CHARS_PER_PEER) {
      return fail(507, "inbox_full");
    }
    // Retention runs here, not on a cron: Durable Objects can't be listed, so a cron couldn't
    // reach them. On the write path, "we keep messages 30 days" is structurally true. Indexed,
    // and bounded by this same delete, so it stays cheap.
    this.sql.exec("DELETE FROM messages WHERE created_at < ?", stamp - RETENTION_SECONDS);
    // Clamped around our clock, once for both the row and the frame. The sender picks it and
    // `MessageCrypto.binding` covers only `msgID|senderID`, yet it's the sole sort key on the
    // other side (`Messaging.ordered`, `conversationOrder`). Unclamped, a message dated 2100
    // pins its conversation to the top forever, and one dated far back sinks below the
    // 500-row read window: stored, counted unread, never visible.
    const claimed = Number(sentAt);
    const sent = Number.isFinite(claimed)
      ? Math.min(Math.max(claimed, stamp - SENT_AT_PAST_SECONDS), stamp + SENT_AT_FUTURE_SECONDS)
      : stamp;
    this.sql.exec(
      "INSERT OR IGNORE INTO messages (msg_id, peer, ciphertext, sent_at, created_at) " +
      "VALUES (?,?,?,?,?)", msgID, from, ciphertext, sent, stamp);

    // New or duplicate, answer with its seq, so a retry gets the original's number rather than
    // an error and sending is idempotent for the sender too.
    const row = this.one("SELECT seq FROM messages WHERE msg_id = ?", msgID);
    if (!row) return fail(500, "not_stored");

    await this.send({
      t: "message",
      message: { msg_id: msgID, peer_id: from, ciphertext, sent_at: sent, seq: row.seq, server_now: serverNow() },
    });

    // Arm the push even when a socket took it: connected isn't received, and a sleeping Mac's
    // TCP outlives its ability to act. The ack cancels it.
    //
    // Not without an APNs key: `alarm()` does nothing else, so it would wake per message for
    // nothing.
    //
    // And never for the user's own messages. The banner says a friend wrote, so a Mac asleep in
    // another room would announce what its owner just typed. Next connect picks them up anyway.
    if (apnsConfigured(this.env) && !mine) {
      // The pending-alarm check does two jobs.
      //
      // A busy conversation can't reset the retry budget: clearing the counter per message
      // keeps the ladder at attempt one against a dead key, one wake per message forever, the
      // billing failure the budget exists to stop.
      //
      // And a new message doesn't get stuck behind a retry. The alarm is one slot: overwriting a
      // retry's alarm with a grace window lets `retryPush` overwrite it back with its backoff,
      // delaying the new notification by the full ladder. A pending alarm covers every message
      // below `MAX(seq)`, since `alarm` reads the table, not a message.
      const pending = await this.ctx.storage.getAlarm();
      const grace = Date.now() + PUSH_GRACE_MS;
      if (pending === null) {
        // Idle: a fresh message gets a fresh budget.
        await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
        await this.ctx.storage.setAlarm(grace);
      } else if (pending > grace) {
        // A retry ladder's next rung is further out than the grace window. Pull the alarm
        // forward but keep the counter. Skipping would make this message wait the whole backoff,
        // and if the ladder then runs out it gets no notification at all (`retryPush` arms
        // nothing when it gives up). Keeping the counter stops a busy chat resetting the budget.
        await this.ctx.storage.setAlarm(grace);
      }
    }
    return reply(200, { seq: row.seq });
  }

  async relayTyping({ from }) {
    const friend = this.friend(from);
    // Dropped when nobody's there to see it; a typing indicator is worthless later.
    if (!friend || friend.blocked || !this.sockets().length) return reply(200, {});
    // Symmetric: Settings promises "with it off, you will not see theirs either", so hiding
    // your presence also hides friends' typing dots and online state.
    if (!(await this.sharePresence())) return reply(200, {});
    await this.send({ t: "typing", peer_id: from });
    return reply(200, {});
  }

  /// Lands on the sender's inbox: their message reached the other Mac's disk.
  async markDelivered({ ids }) {
    for (const id of Array.isArray(ids) ? ids : []) await this.send({ t: "delivered", msg_id: id });
    return reply(200, {});
  }

  /// A friend telling us they came or went.
  ///
  /// Answers immediately and never awaits a call, which keeps presence deadlock-free. With
  /// `reply_to` we fire our state back once, without a reply flag, so a hello can't ping-pong.
  async peerPresence({ peer, online, reply_to: replyTo }) {
    // Same guard as `relayTyping` and `deliver`. `announcePresence` skips blocked peers, but
    // without this they could still tell us, and the `reply_to` bounce would leak our presence
    // back to them.
    const friend = this.friend(peer);
    if (!friend || friend.blocked) return reply(200, {});

    // Recorded either way, so turning presence back on shows something at once; whether it
    // reaches this Mac is the symmetry check below.
    this.sql.exec("UPDATE friends SET online_at = ? WHERE peer = ?",
                  online ? now() : null, peer);
    const sharing = await this.sharePresence();
    if (sharing && this.sockets().length) {
      await this.send({ t: "presence", peer_id: peer, online: !!online });
    }

    if (replyTo && this.sockets().length && sharing) {
      this.ctx.waitUntil(
        inboxCall(this.env, peer, "/presence",
                  { peer: this.identity(), online: true }).catch(() => {}));
    }
    return reply(200, {});
  }

  async removeDevice(device) {
    if (!device) return fail(400, "bad_request");
    this.sql.exec("DELETE FROM devices WHERE device_id = ?", device);
    // And the socket: eviction and "Start Over" come through here, and a connection that keeps
    // sending after its device is removed means the revocation didn't happen.
    this.dropSockets(device);
    // And the recheck stamp, which nothing else deletes. Otherwise it's kept forever, and a
    // re-added device id would get up to SOCKET_RECHECK_SECONDS of unchecked frames.
    await this.ctx.storage.delete(`checked:${device}`);
    return reply(200, {});
  }

  savePushToken({ device, token, environment, topic }) {
    if (!device) return fail(400, "bad_request");
    // A deployment that can't push shouldn't hold push tokens. Only our .p8 signs for
    // com.qubit.shroomy.app, so elsewhere the token is just a stable per-Mac identifier piling up
    // forever. With none stored, `alarm`'s target list is provably empty, so the guards in
    // `deliver` and `alarm` are backup. 200, since the app did nothing wrong.
    if (!apnsConfigured(this.env)) return reply(200, {});
    this.sql.exec(
      "INSERT INTO devices (device_id, apns_token, apns_env, apns_topic, updated_at) VALUES (?,?,?,?,?) " +
      "ON CONFLICT(device_id) DO UPDATE SET apns_token = excluded.apns_token, " +
      "apns_env = excluded.apns_env, apns_topic = excluded.apns_topic, " +
      "updated_at = excluded.updated_at",
      device, token, environment, topic ?? null, now());
    return reply(200, {});
  }

  // -------------------------------------------------------------- sockets

  async connect(request, url) {
    if (request.headers.get("upgrade") !== "websocket") return fail(426, "upgrade_required");
    const deviceID = url.searchParams.get("device");
    if (!deviceID) return fail(400, "bad_request");

    await this.ctx.storage.put("sharePresence", url.searchParams.get("presence") !== "0");
    this.sql.exec(
      "INSERT INTO devices (device_id, updated_at) VALUES (?, ?) " +
      "ON CONFLICT(device_id) DO UPDATE SET updated_at = excluded.updated_at",
      deviceID, now());

    const wasOffline = this.sockets().length === 0;
    const pair = new WebSocketPair();
    // Hibernation: an idle conversation costs nothing, and the DO can leave memory while the
    // socket stays open.
    this.ctx.acceptWebSocket(pair[1], [deviceID]);

    if (wasOffline && (await this.allow("presence", PRESENCE_ANNOUNCES_PER_MINUTE, 60))) {
      await this.announcePresence(true);
    }
    // Deferred: the client can't receive anything until it has the socket.
    this.ctx.waitUntil(this.sendSnapshot(pair[1]));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(socket, raw) {
    let frame;
    try {
      // `raw` is a string for a text frame and an ArrayBuffer for a binary one, and both happen:
      // URLSessionWebSocketTask.send(.data) is binary, browsers and Node send text. JSON.parse
      // on an ArrayBuffer throws, and the catch would silently drop every message from the Mac
      // app while the socket looks healthy.
      const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
      frame = JSON.parse(text);
    } catch {
      return;   // Never close the socket over one genuinely bad frame.
    }
    // Same rule for valid JSON that isn't a frame: `null` would throw on `.t` below.
    if (!frame || typeof frame !== "object") return;

    // `stillAuthorized` guards every frame that does something, not just the heartbeat, or a
    // lapsed, revoked or blocked client that stops pinging keeps sending, acking and typing
    // while every HTTP route 401s. (`entitlement-socket.mjs` only sends `ping`, so tests
    // wouldn't notice.)
    //
    // Cheap per message: throttled to SOCKET_RECHECK_SECONDS, answered from DO storage between.
    switch (frame.t) {
      case "send":
        if (!(await this.stillAuthorized(socket))) return;
        return this.handleSend(socket, frame);
      case "ack":
        if (!(await this.stillAuthorized(socket))) return;
        return this.handleAck(socket, frame);
      case "typing":
        if (!(await this.stillAuthorized(socket))) return;
        return this.handleTyping(frame);
      case "ping":
        // Before the pong, so a revoked or blocked socket is closed rather than reassured.
        if (!(await this.stillAuthorized(socket))) return;
        socket.send(JSON.stringify({ t: "pong" }));
        // The heartbeat must keep presence fresh, as the Kit's `Presence` promises.
        // `sendSnapshot` reads `online_at` through a 90-second window, so if only connect wrote
        // it, any connection older than 90 seconds would look offline to friends connecting
        // later.
        return this.refreshPresence();
      default: return;   // Forward compatibility: ignore, don't disconnect.
    }
  }

  async handleSend(socket, frame) {
    const { msg_id: msgID, peer_id: peerID, ciphertext } = frame;
    // `msg_id` is bounded like `ciphertext`: it's stored in the recipient's inbox and echoed to
    // every socket. Unbounded, a modified client could put a megabyte in the id at the full
    // send rate and fill a friend's Durable Object until writes fail, and then that person
    // stops receiving from everyone.
    if (typeof msgID !== "string" || !msgID || msgID.length > MAX_MSG_ID_CHARS
        || typeof peerID !== "string" || !peerID || !isBase64(ciphertext, MAX_CIPHERTEXT_CHARS)) {
      return socket.send(JSON.stringify({
        t: "rejected", msg_id: typeof msgID === "string" ? msgID.slice(0, MAX_MSG_ID_CHARS) : "",
        code: "bad_request",
      }));
    }
    // Ourselves is the one exception. An identity can be on several Macs, and a message to its
    // own inbox tells them what the server doesn't hold: what was sent (the outbox is stored
    // nowhere, so another Mac would see only the friend's half), what the user calls people,
    // and how far they've read. Sealed like any message, so we learn nothing.
    if (peerID !== this.identity() && !this.friend(peerID)) {
      return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code: "not_friends" }));
    }
    if (!(await this.allow("send", MESSAGES_PER_MINUTE, 60))) {
      return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code: "rate_limited" }));
    }

    // Wrapped. A DO fetch that rejects rather than answering non-ok (peer inbox restarting,
    // a limit, `.json()` throwing) would escape `webSocketMessage`, and the runtime closes the
    // socket. The sender gets no `rejected`, the message stays `sending`, the reconnect resends,
    // and the sick inbox closes it again: a loop for as long as the peer is unwell.
    // `try_again` is honest, and the client already shows it.
    let response;
    let seq;
    try {
      const payload = {
        msg_id: msgID, from: this.identity(), ciphertext, sent_at: frame.sent_at,
      };
      // Direct for our own inbox. `inboxCall` would re-enter this object from inside
      // `webSocketMessage`, and whether that's delivered while we await it depends on input-gate
      // details the contract doesn't promise. The method call is the same work, and faster.
      response = peerID === this.identity()
        ? await this.deliver(payload)
        : await inboxCall(this.env, peerID, "/deliver", payload);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        // `blocked` is reported as `not_friends`: being blocked isn't ours to reveal.
        const code = body.code === "blocked" ? "not_friends" : (body.code ?? "try_again");
        return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code }));
      }
      ({ seq } = await response.json());
    } catch {
      return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code: "try_again" }));
    }
    socket.send(JSON.stringify({ t: "accepted", msg_id: msgID, seq }));
  }

  /// The recipient telling us how far they have stored.
  ///
  /// It also moves the cursor the push alarm compares against, which is why a connected Mac
  /// never gets a notification.
  async handleAck(socket, frame) {
    const seq = Number(frame.seq) || 0;
    if (!seq) return;
    // The socket's tag from accept time, not the frame, so one Mac can't move another's cursor
    // and suppress its notifications.
    const device = this.ctx.getTags(socket)[0];
    if (!device) return;
    // The baseline is monotonic, kept in storage rather than derived from the device rows.
    //
    // Eviction deletes a device row, and the re-activated Mac inserts one at 0, so if it's the
    // only row `MAX(last_acked_seq)` drops to nothing. Its first ack would then fan
    // `/delivered` out for the entire retained history, one frame per id to every peer, each a
    // database write and conversation reload on someone else's Mac. Storage outlives the rows.
    const devicesMax = this.one("SELECT MAX(last_acked_seq) AS s FROM devices")?.s ?? 0;
    const before = Math.max(devicesMax, (await this.ctx.storage.get("deliveredUpTo")) ?? 0);
    this.sql.exec(
      "UPDATE devices SET last_acked_seq = MAX(last_acked_seq, ?) WHERE device_id = ?",
      seq, device);

    // Tell each sender their messages landed. Only the newly acked range, so re-acking the same
    // cursor doesn't re-notify everyone.
    if (seq > before) {
      await this.ctx.storage.put("deliveredUpTo", seq);
      const landed = this.rows(
        "SELECT msg_id, peer FROM messages WHERE seq > ? AND seq <= ?", before, seq);
      const byPeer = new Map();
      for (const row of landed) {
        if (!byPeer.has(row.peer)) byPeer.set(row.peer, []);
        byPeer.get(row.peer).push(row.msg_id);
      }
      for (const [peer, ids] of byPeer) {
        this.ctx.waitUntil(inboxCall(this.env, peer, "/delivered", { ids }).catch(() => {}));
      }
    }
  }

  async handleTyping(frame) {
    if (!frame.peer_id || !this.friend(frame.peer_id)) return;
    if (!(await this.sharePresence())) return;
    // The client throttles too, but a modified build controls that side.
    if (!(await this.allow("typing", TYPING_PER_SECOND, 1))) return;
    this.ctx.waitUntil(
      inboxCall(this.env, frame.peer_id, "/typing", { from: this.identity() }).catch(() => {}));
  }

  /// Re-prove a live socket's device, at most once per SOCKET_RECHECK_SECONDS.
  ///
  /// The token is only checked at the upgrade, and hibernated sockets outlive that, so without
  /// this a revoked device, evicted seat or blocked license keeps going while the connection
  /// lasts. The client reconnects on close, so a re-activated device returns with its new token.
  ///
  /// Fails open on a D1 error: it's a revocation check, not authentication, and dropping every
  /// live conversation over a D1 blip would be far worse.
  async stillAuthorized(socket) {
    const device = this.ctx.getTags(socket)[0];
    if (!device) return true;
    const key = `checked:${device}`;
    const last = (await this.ctx.storage.get(key)) ?? 0;
    if (now() - last < SOCKET_RECHECK_SECONDS) return true;

    let row;
    try {
      row = await this.env.DB.prepare(
        "SELECT l.status FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
        // The same entitlement clause as `authenticateToken`. This socket outlives its
        // authentication and carries messages, acks, typing and presence, so without it a lapsed
        // subscriber who never quits the app keeps Friends while every HTTP route 401s.
        "WHERE d.id = ? AND d.revoked_at IS NULL " +
        "AND (l.entitled_until IS NULL OR l.entitled_until > ?)"
      ).bind(device, now()).first();
    } catch {
      // Fail open, without refreshing the stamp, so the next frame retries. A stamp here would
      // let one D1 blip buy a possibly lapsed or revoked device SOCKET_RECHECK_SECONDS more.
      return true;
    }
    // Only a real answer resets the throttle.
    await this.ctx.storage.put(key, now());
    if (row && row.status === "active") return true;
    this.dropSockets(device);
    return false;
  }

  /// Which of these device ids still have a live, entitled licence, or `null` if we couldn't
  /// find out. `null` differs from an empty set: the caller fails open on it.
  ///
  /// One D1 round trip for the whole list, since it runs inside the push alarm for every Mac
  /// on this inbox.
  async entitledDevices(ids) {
    if (!ids.length) return new Set();
    try {
      const rows = await this.env.DB.prepare(
        "SELECT d.id AS id FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
        `WHERE d.id IN (${ids.map(() => "?").join(",")}) AND d.revoked_at IS NULL ` +
        "AND l.status = 'active' " +
        "AND (l.entitled_until IS NULL OR l.entitled_until > ?)"
      ).bind(...ids, now()).all();
      return new Set((rows.results ?? []).map((r) => r.id));
    } catch {
      return null;   // fail open, see the caller
    }
  }

  /// Close every socket belonging to one device.
  dropSockets(device) {
    for (const socket of this.ctx.getWebSockets(device)) {
      try { socket.close(1008, "revoked"); } catch { /* already gone */ }
    }
  }

  async webSocketClose(socket) {
    // Ask whether any other socket survives rather than counting. Whether `getWebSockets()`
    // still lists the closing one is a runtime detail, and every reconnect races the close
    // (`connect()` opens the new socket immediately). Counting gets it wrong one way or the
    // other, and announcing offline while the replacement is live leaves the Mac offline to
    // every friend for the session. Excluding it explicitly is right either way.
    if (this.sockets().every((s) => s === socket)
        && (await this.allow("presence", PRESENCE_ANNOUNCES_PER_MINUTE, 60))) {
      await this.announcePresence(false);
    }
  }

  async webSocketError(socket) { return this.webSocketClose(socket); }

  // -------------------------------------------------------------- presence

  /// Tell friends we came or went.
  ///
  /// Fire and forget, and that's load-bearing. Awaiting each friend's inbox deadlocks two Macs
  /// connecting at once: A waits on B while B waits on A. Nothing here awaits a reply.
  ///
  /// `reply_to` asks an online friend to announce themselves back, instead of querying
  /// everyone on connect. The reply carries no flag, so it can't ping-pong.
  async announcePresence(online) {
    if (!(await this.sharePresence())) return;
    const friends = this.rows("SELECT peer FROM friends WHERE blocked = 0 LIMIT ?",
                              MAX_PRESENCE_FANOUT);
    const me = this.identity();
    for (const friend of friends) {
      this.ctx.waitUntil(
        inboxCall(this.env, friend.peer, "/presence",
                  { peer: me, online, reply_to: online }).catch(() => {}));
    }
  }

  /// Re-assert that we are here, often enough that friends never see us go stale.
  ///
  /// Throttled: a fan-out per heartbeat would be 50 subrequests every 30 seconds per Mac. Twice
  /// per staleness window is the fewest announcements that keep `online_at` fresh. The stamp
  /// is in storage so it survives hibernation.
  async refreshPresence() {
    const last = (await this.ctx.storage.get("presenceAnnouncedAt")) ?? 0;
    if (now() - last < PRESENCE_REFRESH_SECONDS) return;
    await this.ctx.storage.put("presenceAnnouncedAt", now());
    await this.announcePresence(true);
  }

  /// Who we believe is online, from our own records.
  ///
  /// No outbound calls (querying friends here can deadlock). A cold inbox sends an empty set
  /// that fills in within a round trip as `reply_to` bounces land.
  async sendSnapshot(socket) {
    if (!(await this.sharePresence())) return;
    const fresh = now() - PRESENCE_STALE_SECONDS;
    const online = this.rows(
      "SELECT peer FROM friends WHERE blocked = 0 AND online_at > ?", fresh).map((f) => f.peer);
    try {
      socket.send(JSON.stringify({ t: "presence_snapshot", online }));
    } catch { /* gone already */ }
  }

  // -------------------------------------------------------------- push

  /// Nothing acked the message in the grace window, so the recipient isn't really here.
  ///
  /// Per device, not a MAX across them: an iMac awake at the office acks instantly, and a
  /// global MAX would let that answer for the MacBook asleep in a bag. `last_pushed_seq` is
  /// per row too, so one device being notified can't suppress another.
  async alarm() {
    // Backstop for an alarm already persisted. `deliver` doesn't arm one without a key, but a
    // DO may still hold an older alarm that would otherwise re-arm itself forever.
    if (!apnsConfigured(this.env)) {
      console.log("push: APNs not configured, alarm is a no-op");
      return;
    }

    const latest = this.one("SELECT MAX(seq) AS s FROM messages")?.s ?? 0;
    if (!latest) return;

    // One push however many are pending: the payload has no content, so a second would say
    // the same thing.
    const newest = this.one("SELECT peer FROM messages WHERE seq = ?", latest);
    let targets = this.rows(
      "SELECT device_id, apns_token, apns_env, apns_topic FROM devices " +
      "WHERE apns_token IS NOT NULL AND last_acked_seq < ? AND last_pushed_seq < ?",
      latest, latest);
    // The same entitlement clause as `authenticateToken` and `stillAuthorized`. This DO table
    // knows nothing about licences, so it asks D1; otherwise push would be the one path that
    // survives a lapse, sending banners for messages the recipient can't open.
    //
    // Fails open on a D1 error, like `stillAuthorized`: silencing everyone's notifications over
    // a D1 blip would be far worse.
    const candidates = targets.length;
    const live = await this.entitledDevices(targets.map((t) => t.device_id));
    if (live) targets = targets.filter((t) => live.has(t.device_id));
    if (!targets.length) {
      // Everyone acked or was pushed, so any retry is done.
      //
      // Logged, because every reason to send nothing (no token, acked, pushed, not entitled)
      // ends here with the alarm reporting Ok, which makes "push doesn't work" undiagnosable.
      // Counts and a seq only, per the logging rule.
      console.log(`push: nothing to send latest=${latest} candidates=${candidates} entitled=0`);
      await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
      return;
    }
    console.log(`push: sending latest=${latest} targets=${targets.length}`);

    let jwt;
    try {
      ({ jwt } = await apnsToken(this.env));
    } catch (error) {
      // Logged: from outside this looks like success (alarm Ok, retries quiet, no push). The
      // error's own message names the problem (malformed .p8, bad key id) and holds no secret.
      console.error(`push: could not mint APNs token: ${error?.message ?? error}`);
      // A bad key or signing failure, not an absent one (the guard at the top handled that).
      // Retry rather than wait for the next message, or the evening's last message never
      // notifies.
      cachedAPNsToken = null;
      await this.retryPush();
      return;
    }

    let retry = false;
    for (const target of targets) {
      try {
        const response = await sendPush(this.env, jwt, target.apns_token, target.apns_env,
                                        newest?.peer ?? "mushroom", target.apns_topic);
        // Never the token: it's a credential.
        console.log(`push ${target.device_id} env=${target.apns_env} -> ${response.status}`);
        // 410: the token is dead. Keeping it pushes into the void and gets us throttled.
        if (response.status === 410) {
          this.sql.exec("UPDATE devices SET apns_token = NULL WHERE device_id = ?",
                        target.device_id);
        } else if (response.ok) {
          this.sql.exec("UPDATE devices SET last_pushed_seq = ? WHERE device_id = ?",
                        latest, target.device_id);
        } else {
          // Anything else (429 on the provider token, a 5xx) didn't deliver; marking it pushed
          // would lose the notification. A 429 drops the cached token so the retry mints anew.
          if (response.status === 429) cachedAPNsToken = null;
          retry = true;
        }
      } catch (error) {
        // Logged: a throwing fetch (DNS, TLS, abort) otherwise looks like a push never tried.
        console.error(`push ${target.device_id} threw: ${error?.message ?? error}`);
        retry = true;
      }
    }
    if (retry) await this.retryPush();
    else await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
  }

  /// Come back and try this push again, but not forever.
  ///
  /// An expired or revoked `.p8` fails the same way every time, so a flat re-arm would wake an
  /// inbox with one unread message every minute forever, silently.
  ///
  /// Doubling from a minute and stopping after `PUSH_MAX_ATTEMPTS` gives about an hour, then
  /// silence: generous for retryable failures (429 on the provider token, 5xx, network blip),
  /// final for the rest.
  ///
  /// The counter is per message, not per inbox: `deliver` clears it when idle, so a new message
  /// gets a fresh budget and a dead key costs a bounded number of wakes per message.
  async retryPush() {
    const attempt = ((await this.ctx.storage.get(PUSH_ATTEMPT_KEY)) ?? 0) + 1;
    if (attempt > PUSH_MAX_ATTEMPTS) {
      // No alarm: asking again won't fix it, and `apns-expiration` already gave Apple a day to
      // deliver whatever we got out.
      await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
      return;
    }
    await this.ctx.storage.put(PUSH_ATTEMPT_KEY, attempt);
    await this.ctx.storage.setAlarm(Date.now() + PUSH_RETRY_MS * 2 ** (attempt - 1));
  }

  // -------------------------------------------------------------- housekeeping

  /// A fixed-window counter in DO storage. Coarse on purpose: it exists to stop a runaway
  /// client, not to be fair at a boundary.
  ///
  /// ponytail: a client that times its bursts to the window edge gets 2x for one instant.
  /// Upgrade to a sliding window if that ever matters; it does not at these limits.
  async allow(bucket, limit, windowSeconds) {
    const key = `rate:${bucket}`;
    const window = Math.floor(Date.now() / 1000 / windowSeconds);
    const state = (await this.ctx.storage.get(key)) ?? { window: 0, count: 0 };
    if (state.window !== window) {
      await this.ctx.storage.put(key, { window, count: 1 });
      return true;
    }
    if (state.count >= limit) return false;
    await this.ctx.storage.put(key, { window, count: state.count + 1 });
    return true;
  }

  /// Our own identity, which is the DO's name. Cached because every send needs it.
  identity() {
    this.cachedIdentity ??= this.ctx.id.name;
    return this.cachedIdentity;
  }
}

// ---------------------------------------------------------------- owner actions

/// Constant-time-ish bearer check, copied from mushroom-files like `verifyLicense` and
/// `sha256Hex`. The token is one shared secret, so there's nothing to enumerate; the loop
/// avoids leaking it via timing. Set it with `wrangler secret put ADMIN_TOKEN`.
function adminOK(request, env) {
  const header = request.headers.get("authorization") ?? "";
  const given = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const want = env.ADMIN_TOKEN ?? "";
  // The placeholder config.capnp.example ships with is public, so it's no secret at all.
  if (!want || want === "CHANGE-ME" || given.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

/// Block a licence from messaging and revoke every device it has.
///
/// `'blocked'` is enforced in `authenticateToken`, `stillAuthorized` and the activate upsert's
/// CASE; this is how it gets set (mushroom-files' endpoint writes a different D1). It's the one
/// control for the App Store channel, whose refunds are invisible here; the alternative is
/// hand-typed SQL in production with no audit line and no device revocation.
///
/// Each device is also removed from its inbox, which closes its live sockets now. Waiting for
/// `stillAuthorized` isn't enough: a client that sends nothing keeps receiving until the
/// next frame goes out to it.
async function adminBlockLicense(request, env) {
  let body;
  try { body = objectBody(await request.json()); } catch { return fail(400, "bad_request"); }
  const hash = String(body.license_hash ?? "");
  if (!hash) return fail(400, "bad_request");

  const row = await env.DB.prepare("SELECT license_hash FROM licenses WHERE license_hash = ?").bind(hash).first();
  if (!row) return fail(404, "not_found");

  await env.DB.prepare("UPDATE licenses SET status = 'blocked' WHERE license_hash = ?").bind(hash).run();
  const devices = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE license_hash = ? AND revoked_at IS NULL RETURNING id, identity_id"
  ).bind(now(), hash).all();
  for (const device of devices.results ?? []) {
    await inboxCall(env, device.identity_id, "/devices/remove", { device: device.id }).catch(() => {});
  }

  const count = (devices.results ?? []).length;
  console.log(`admin blocked license devices=${count}`);
  return reply(200, { blocked: true, devices_revoked: count });
}

// ---------------------------------------------------------------- entry point

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/") {
      // As files-worker's `brandURL`: unset is our deploy, empty names nobody (a self-hosted box
      // shouldn't send its visitors to our site).
      const brand = env.BRAND_URL === undefined ? "https://www.getmushroom.app" : String(env.BRAND_URL).trim();
      return brand ? Response.redirect(brand, 302) : new Response("Not found", { status: 404 });
    }

    if (path === "/v1/devices/activate" && method === "POST") {
      // Before the Gumroad call, which is what a flood spends.
      //
      // Self-hosted, nothing sets or strips cf-connecting-ip, so trusting it lets a client pick
      // a fresh bucket per request, and each bucket is a durable object on disk forever. One
      // bucket for the box; config.capnp.example sizes it.
      const ip = env.SELFHOST === "1" ? "box" : clientBucket(request.headers.get("cf-connecting-ip"));
      if (!(await throttle(env, ip, "activate", activationsPerHourPerIP(env), 3600))) {
        return fail(429, "rate_limited", { retry_after: 600 });
      }
      return activateDevice(request, env);
    }

    // The socket. Header only: every client build sends it there.
    //
    // Never the query string. With `observability` on, Cloudflare records the URL verbatim in
    // Workers Logs, so a URL token puts a live, non-expiring device token in a searchable index
    // any read-only dashboard account or leaked API token can page through. Headers aren't
    // captured that way, and `URLSessionWebSocketTask` built from a `URLRequest` does send the
    // Authorization header in the handshake.
    if (path === "/v1/connect") {
      const header = request.headers.get("authorization") ?? "";
      const bearer = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
      const socketToken = bearer;
      const auth = await authenticateToken(socketToken, env, ctx);
      if (!auth) return refusal(socketToken, env, ctx);
      const target = new URL("https://inbox/connect");
      target.searchParams.set("device", auth.deviceID);
      target.searchParams.set("presence", url.searchParams.get("presence") === "0" ? "0" : "1");
      return inbox(env, auth.identityID).fetch(target, request);
    }

    if (path.startsWith("/admin/")) {
      if (!adminOK(request, env)) return fail(403, "forbidden");
      if (path === "/admin/licenses/block" && method === "POST") return adminBlockLicense(request, env);
      return fail(404, "not_found");
    }

    if (path.startsWith("/v1/")) {
      // Release is cleanup, not access, so it skips the entitlement clause (see
      // `authenticateToken`). Matched first, since the general gate would 401 it.
      const releasing = path === "/v1/devices/release" && method === "POST";
      const auth = await authenticate(request, env, ctx, { allowExpired: releasing });
      if (!auth) {
        const header = request.headers.get("authorization") ?? "";
        return refusal(header.startsWith("Bearer ") ? header.slice(7).trim() : "", env, ctx);
      }

      if (releasing) return releaseDevice(env, auth);
      if (path === "/v1/devices" && method === "GET") return listDevices(env, auth);
      if (path === "/v1/devices/revoke" && method === "POST") {
        return revokeDevice(request, env, auth);
      }
      if (path === "/v1/link" && method === "POST") return createLink(env, auth);
      if (path === "/v1/invites" && method === "POST") return createInvite(env, auth);
      if (path === "/v1/invites/accept" && method === "POST") return acceptInvite(request, env, auth);
      if (path === "/v1/sync" && method === "GET") return syncMessages(env, auth, url);
      if (path === "/v1/friends" && method === "GET") {
        return inboxCall(env, auth.identityID, "/friends/list", {});
      }
      if (path === "/v1/push" && method === "POST") return registerPush(request, env, auth);

      const friend = path.match(/^\/v1\/friends\/([0-9a-f]{64})\/(block|unblock|remove)$/);
      if (friend && method === "POST") return friendAction(env, auth, friend[1], friend[2]);

      return fail(404, "not_found");
    }

    return fail(404, "not_found");
  },

  /// Daily sweep of the global tables only. Durable Objects can't be enumerated, so each inbox
  /// expires its own messages on the write path instead (see `deliver`).
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      // No `LIMIT` on these DELETEs: D1's SQLite lacks SQLITE_ENABLE_UPDATE_DELETE_LIMIT, so
      // `DELETE … LIMIT ?` is a syntax error at execute time and the sweep would fail nightly
      // with only a log line. The tables are small and bounded by these deletes.
      await env.DB.prepare("DELETE FROM invites WHERE expires_at < ?")
        .bind(now() - 7 * 86400).run();
      await env.DB.prepare(
        "DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < ?"
      ).bind(now() - 30 * 86400).run();
      // Collects link codes nobody scanned. An hour of slack so clock skew can't delete a live one.
      await env.DB.prepare("DELETE FROM link_codes WHERE expires_at < ?")
        .bind(now() - 3600).run();
    })());
  },
};
