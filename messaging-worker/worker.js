// mushroom-messaging: invite-only one-to-one messaging for Mushroom.
//
// A licensed Mac exchanges its Gumroad key plus an X25519 public key for a device token,
// then opens a WebSocket to its own inbox. Messages are sealed on the sending Mac and
// opened on the receiving one; this Worker moves and stores opaque blobs and could not read
// one if it wanted to.
//
// LOGGING RULE, and it is not negotiable: observability is on and logs are retained, so
// this file must never log a message body, a ciphertext, an invite code, a license key or a
// bearer token. Ids and status codes only. (mushroom-files takes the same line.)
//
// WHAT THE SERVER CAN SEE, stated plainly because the privacy copy has to match it:
// that identity A sent something to identity B at a time, how big it was, and which Macs
// were connected. Not the text, not the friend names, not who anybody is.

const GUMROAD_PRODUCT_ID = "59Bhmk7nBsjAqKhst9Bf9g==";  // not a secret; matches LicenseManager.productID

const MAX_MESSAGE_CHARACTERS = 4000;
// A sealed box is base64 of nonce + ciphertext + tag. Base64 costs 4/3, AES-GCM adds 28
// bytes, and a character can be four bytes of UTF-8. This is that, rounded up, and it is a
// bound on the STORED blob rather than a second opinion about the text.
const MAX_CIPHERTEXT_CHARS = Math.ceil((MAX_MESSAGE_CHARACTERS * 4 + 28) * 4 / 3) + 64;
const MAX_FRIENDS = 50;
const MAX_DEVICES_PER_LICENSE = 3;              // matches the license: "up to 3 Macs"
const MAX_DEVICE_NAME_CHARS = 60;
// A UUID is 36. Bounded because the id is stored and rebroadcast, so an unbounded one is a
// way past the ciphertext cap and into a friend's storage quota (see `handleSend`).
const MAX_MSG_ID_CHARS = 64;
// How far `sent_at` may sit from the server's own clock. The sender picks it and it is not
// covered by the AEAD binding, so it is the one field a modified client can use to reorder
// somebody else's conversation. A day back covers a message composed offline and sent on
// reconnect; five minutes forward covers ordinary clock skew.
const SENT_AT_PAST_SECONDS = 86400;
const SENT_AT_FUTURE_SECONDS = 300;
const RETENTION_SECONDS = 30 * 24 * 60 * 60;    // then the sweep drops it
const INVITE_TTL_SECONDS = 24 * 60 * 60;
const INVITES_PER_DAY = 20;
const MESSAGES_PER_MINUTE = 60;
const TYPING_PER_SECOND = 1;
const SYNC_PAGE = 200;

// Activations per hour from one IP, and invite redemptions per hour from one identity.
// Both are generous for a person and useless for a script. Activation is the one route that
// answers before authentication, so it is also the one that can be used as an oracle: a
// distinguishable `403 bad_license` versus `201` turns this Worker into a free Gumroad key
// checker, and the flood costs us a paid verify call each time. Worse, `activateDevice`
// fails CLOSED on a Gumroad 429, so the same flood locks every real Mac out of activating.
// Overridable ONLY so test.sh can run: the shape assertions for the activation branch are
// each a POST to this endpoint, and a dozen of them plus a re-run inside the same hour spend
// the real budget and turn every later assertion into a 429. `wrangler dev --var` raises it
// locally; nothing sets it in production, where the default stands.
const activationsPerHourPerIP = (env) => Number(env.ACTIVATIONS_PER_HOUR_PER_IP ?? 10) || 10;
const ACCEPTS_PER_HOUR = 30;

// How long after delivering on a socket we wait for the recipient's ack before pushing.
// Long enough that an awake Mac always beats it, short enough that a notification still
// feels immediate.
const PUSH_GRACE_MS = 10_000;
// How long to wait before trying a push that failed to send. Longer than the grace window,
// because the failures worth retrying are the ones a moment does not fix (APNs 5xx, a
// throttled provider token) and the alarm is a single slot: a short retry would keep
// overwriting the grace alarm a live conversation is setting.
const PUSH_RETRY_MS = 60_000;
// How many times, doubling from PUSH_RETRY_MS, before giving up on a push entirely: about an
// hour of trying. There used to be no limit at all, which was fine for the failures this
// retry was written for and ruinous for the one it was not. An expired or revoked .p8 fails
// the same way every minute forever, so one unread message pinned its inbox awake for the life
// of the deployment. Six attempts still outlasts any APNs incident worth waiting out.
const PUSH_MAX_ATTEMPTS = 6;
// Where the attempt count lives. DO storage rather than an instance field, because giving up
// has to survive the inbox being evicted between alarms; a field would reset to zero on every
// wake and reinstate exactly the unbounded loop this is here to stop.
const PUSH_ATTEMPT_KEY = "push_attempt";
// How long APNs should keep trying to hand a notification over. A day: long enough for a
// Mac shut for the night, short enough that reopening after a holiday is not a pile of
// banners for messages the app has already fetched and shown itself.
const PUSH_EXPIRY_SECONDS = 24 * 60 * 60;

// Presence
const HEARTBEAT_SECONDS = 30;
const PRESENCE_STALE_SECONDS = 90;              // three missed Presence.heartbeatInterval beats
// Twice per staleness window, so a live Mac is always inside it without a fan-out per
// heartbeat. Must stay comfortably below PRESENCE_STALE_SECONDS (see `refreshPresence`).
const PRESENCE_REFRESH_SECONDS = 40;
// Cap on the fan-out a single connect can cause. MAX_FRIENDS is 50 and the subrequest
// budget is far larger, so this only ever binds if MAX_FRIENDS grows. It is here so that
// growing it is a decision rather than an outage.
const MAX_PRESENCE_FANOUT = 50;
// How often a LIVE socket re-proves its device is still allowed to be here. A socket is
// authenticated once, at the upgrade, and hibernation means it can outlive the process that
// checked it: without this, revoking a device (seat eviction, "Start Over"), blocking a
// license for abuse, or Gumroad reporting a refund had no effect at all on a connection that
// was already open, and the client only reconnects on error. One D1 read per socket per five
// minutes is the smallest price that makes revocation mean something.
const SOCKET_RECHECK_SECONDS = 300;

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

/// 256 is an exact multiple of 32, so `byte % 32` is unbiased and there is nothing to
/// reject-sample. Worth stating, because the same line over a 36-character alphabet would
/// quietly favour the first four.
function inviteCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(INVITE_CODE_LENGTH));
  return [...bytes].map((b) => INVITE_ALPHABET[b % INVITE_ALPHABET.length]).join("");
}

/// Separators only, NOT "anything not in the alphabet". Mirrors
/// `Messaging.normalizedInviteCode`, including the reason: filtering by the alphabet turns
/// a mistyped letter into a different well-formed code that nobody ever issued.
const normalizeInvite = (raw) => String(raw ?? "").toUpperCase().replace(/[\s\-_]/g, "");

const wellFormedInvite = (code) =>
  code.length === INVITE_CODE_LENGTH && [...code].every((c) => INVITE_ALPHABET.includes(c));

const isBase64 = (s, maxBytes) =>
  typeof s === "string" && s.length > 0 && s.length <= maxBytes && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

/// An X25519 public key is 32 raw bytes, which is exactly 44 base64 characters with one
/// pad. Checking the length here means a malformed key is refused at the door rather than
/// stored and then failing to encrypt for everyone who ever adds this person.
const isPublicKey = (s) => typeof s === "string" && s.length === 44 && /^[A-Za-z0-9+/]{43}=$/.test(s);

const identityFor = (publicKey) => sha256Hex(publicKey);

const limits = () => ({
  // Which wire contract this server speaks, for the app to compare against its own minimum.
  //
  // Emitted now and read by nobody yet, deliberately. Once anyone other than us runs this
  // Worker their copy stops moving when ours does, and the app has no other way to tell a
  // pinned old server from a current one: absent means "older than 1", so the field has to
  // exist BEFORE there is a 2 or it can never be used to date anything. Bump it only when the
  // contract actually changes in a way an older app cannot survive. Additive changes need no
  // bump, because unknown frames are already ignored by design and every limit decodes with a
  // fallback.
  protocol: 1,
  max_message_characters: MAX_MESSAGE_CHARACTERS,
  max_friends: MAX_FRIENDS,
  invites_per_day: INVITES_PER_DAY,
  retention_days: RETENTION_SECONDS / 86400,
});

const inbox = (env, identityID) => env.INBOX.get(env.INBOX.idFromName(identityID));

/// Call another identity's inbox. A plain fetch with a made-up origin, which is the
/// documented way to talk to a DO and keeps every handler a normal request handler.
function inboxCall(env, identityID, path, body) {
  return inbox(env, identityID).fetch(`https://inbox${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
}

/// A counter for a route that has no inbox of its own yet.
///
/// Reuses `UserInbox.allow` rather than growing a second limiter: a Durable Object named
/// after the key IS a per-key lock, which is the whole reason the counter is exact. The name
/// is namespaced (`rate:…`) so it can never collide with an identity id, which is always
/// 64 hex characters.
async function throttle(env, key, bucket, limit, windowSeconds) {
  const response = await inboxCall(env, `rate:${key}`, "/rate",
                                   { bucket, limit, window: windowSeconds });
  return response.ok;
}

// ---------------------------------------------------------------- license

/// Ask Gumroad whether a key is real and still paid for.
///
/// increment_uses_count is FALSE on purpose, same as mushroom-files: the app burns a seat
/// once at activation, and counting again here would spend the user's seats on our own
/// bookkeeping.
async function verifyLicense(key) {
  const verdict = (status, saleID = null) => ({ status, saleID });

  let response;
  try {
    response = await fetch("https://api.gumroad.com/v2/licenses/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        product_id: GUMROAD_PRODUCT_ID,
        license_key: key,
        increment_uses_count: "false",
      }),
    });
  } catch {
    return verdict("unreachable");
  }
  // 429 is Gumroad rate limiting US, not the user's license being bad.
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
  return verdict("active", typeof purchase.sale_id === "string" ? purchase.sale_id : null);
}

// ---------------------------------------------------------------- app store purchases

// The App Store build has no Gumroad key to present: `LicenseManager`'s APPSTORE stub never
// writes one. It sends `AppTransaction`'s JWS instead, which Apple signs and documents for
// exactly this. Everything downstream is unchanged, because the identity below lands in the
// same `licenses.license_hash` column as a Gumroad key hash.
//
// The trust anchors live in ONE place, ../worker-shared/apple-roots.js, imported by both
// workers: they must be rotated in lockstep and nothing here would catch a one-sided edit.
import { APPSTORE_BUNDLE_ID, APPLE_ROOT_CA_G3, APPLE_ROOT_CA_G2 } from "../worker-shared/apple-roots.js";

// The JWS is three base64url segments and a signature; a real one is a few KB. Bounded so a
// megabyte of junk cannot reach the verifier.
const MAX_APP_TRANSACTION_CHARS = 12000;

// Namespaced away from Gumroad's hash so the two identity spaces can never collide in the
// one `licenses` table. Apple issues `appTransactionId` per Apple Account AND per family
// group member, so a Family Sharing member gets their own three seats rather than fighting
// over the purchaser's.
const appStoreHash = (appTransactionID) => sha256Hex(`appstore:${appTransactionID}`);

// One verifier per environment, built once per isolate and reused.
//
// Not just to skip re-parsing the two DER roots: `SignedDataVerifier` carries its own
// verified-public-key cache (15 min, 32 entries) that is PER INSTANCE, so constructing a
// fresh one per request threw it away and made every activation redo the whole chain walk,
// even though one Apple leaf signs everybody's JWS in a given window.
let verifierCache = null;

async function appStoreVerifiers(appAppleID) {
  if (verifierCache) return verifierCache;
  // Imported HERE rather than at the top of the file, and that is load-bearing: jsrsasign
  // generates random values while its module body runs, and workerd forbids that in global
  // scope, so a top-level import stops the Worker booting outright with "Disallowed
  // operation called within global scope". Inside a handler it is fine. The runtime caches
  // the evaluation, so this costs ~80 ms once per cold isolate and nothing after that.
  const lib = await import("@apple/app-store-server-library");
  const roots = [APPLE_ROOT_CA_G3, APPLE_ROOT_CA_G2].map((b64) => Buffer.from(b64, "base64"));
  // Production first, then Sandbox. A build from TestFlight or from App Review carries a
  // Sandbox transaction, so refusing those would fail review. `enableOnlineChecks` is off so
  // activation never waits on an OCSP round trip; the chain is still verified to the root.
  // Xcode and LocalTesting are deliberately absent: the library skips signature verification
  // entirely for those, so accepting them would make this endpoint forgeable.
  verifierCache = [
    new lib.SignedDataVerifier(roots, false, lib.Environment.PRODUCTION, APPSTORE_BUNDLE_ID, appAppleID),
    new lib.SignedDataVerifier(roots, false, lib.Environment.SANDBOX, APPSTORE_BUNDLE_ID, undefined),
  ];
  return verifierCache;
}

/// Verify an AppTransaction JWS.
/// Returns `{ status, appTransactionID }` where status is
/// "active" | "invalid" | "unconfigured".
///
/// There is deliberately no "unreachable": the JWS carries its own certificate chain and is
/// checked against a pinned root, so unlike the Gumroad path there is no third party who can
/// be down. "unconfigured" is our own missing app id, not the user's problem.
async function verifyAppTransaction(jws, env) {
  const verdict = (status, appTransactionID = null) => ({ status, appTransactionID });

  // Shape first, crypto second. Verification is the expensive part of this endpoint, and it
  // is unauthenticated by nature, so anything obviously not a JWS is rejected before it can
  // cost anything.
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jws)) return verdict("invalid");

  // Apple's verifier requires the numeric App Store id for PRODUCTION. It only exists once
  // the App Store Connect record does, so it lives in a var: refuse loudly while it is
  // missing rather than quietly verify against the wrong app.
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
  for (const verifier of verifiers) {
    try {
      const tx = await verifier.verifyAndDecodeAppTransaction(jws);
      // The verifier already rejected a mismatched bundleId. `appTransactionId` is the part
      // we actually need, and it is optional in the model, so an answer without one is no
      // use to us as an identity.
      if (typeof tx.appTransactionId === "string" && tx.appTransactionId) {
        return verdict("active", tx.appTransactionId);
      }
      failures.push("no_app_transaction_id");
    } catch (error) {
      // Wrong environment is the ordinary case (every Sandbox JWS fails Production first),
      // so this is not an error on its own. Logged because the alternative is that a wrong
      // but numeric APPSTORE_APP_APPLE_ID fails EVERY customer with nothing in the logs to
      // tell a total outage apart from ordinary junk traffic.
      failures.push(error?.status ?? error?.name ?? "unknown");
    }
  }
  console.warn("appstore: rejected app_transaction", JSON.stringify(failures));
  return verdict("invalid");
}

// ---------------------------------------------------------------- channel migration

/// The licence hash a SECOND, older credential resolves to, or null if it does not resolve.
///
/// Only ever used to prove that whoever is activating also holds the credential an identity
/// is already bound to. It deliberately does NOT touch the `licenses` table: this is a proof
/// of possession, not an activation, and the row that matters is written from the primary
/// credential further down.
///
/// A Gumroad key that verifies as `revoked` still counts. The person refunded, or their card
/// bounced, and they have since bought the app again on the other channel: that is precisely
/// the migration this exists for, and refusing it would strand the exact user it is meant to
/// help. `invalid` and `unreachable` do not count, so a migration cannot be waved through by
/// making Gumroad unreachable.
async function credentialHash(env, { key, jws }) {
  if (jws) {
    const { status, appTransactionID } = await verifyAppTransaction(jws, env);
    return status === "active" ? await appStoreHash(appTransactionID) : null;
  }
  if (key) {
    const { status } = await verifyLicense(key);
    return (status === "active" || status === "revoked") ? await licenseHash(key) : null;
  }
  return null;
}

/// Move an identity from the licence that claimed it to the one activating now.
///
/// Both targets ship bundle id com.qubit.shroomy.app under one team, so a Mac that switches
/// between the direct download and the App Store keeps its Keychain, and with it the X25519
/// identity key. The licence hash underneath it does NOT survive: Gumroad's is
/// sha256(licence key) and the App Store's is sha256("appstore:" + appTransactionId). The
/// first-claim guard then refuses the same person on the same Mac, forever, and the only
/// escape was Start Over, which deletes every friendship and every message.
///
/// The proof is holding the OLD credential as well as the new one. That is exactly the
/// standard the original claim was made to, so this opens nothing that was closed: whoever
/// could claim the identity in the first place is whoever can move it. An attacker who has
/// somebody's public key still has to produce the licence that owns it.
///
/// Returns true when the identity now belongs to `newHash`.
async function migrateIdentity(env, identityID, oldHash, newHash, body, stamp) {
  const key = typeof body.migrate_license_key === "string" ? body.migrate_license_key.trim() : "";
  const jws = typeof body.migrate_app_transaction === "string" ? body.migrate_app_transaction.trim() : "";
  // Exactly one, same rule as the primary credential, and bounded the same way.
  if (!key === !jws) return false;
  if (key && key.length > 100) return false;
  if (jws && jws.length > MAX_APP_TRANSACTION_CHARS) return false;

  const provenHash = await credentialHash(env, { key, jws });
  if (!provenHash || provenHash !== oldHash) return false;

  // Guarded on the old value, so two Macs racing the same migration cannot interleave into a
  // half-moved identity: the second one's UPDATE matches nothing and it re-reads the new
  // state on its next attempt.
  //
  // RETURNING rather than `meta.changes`. Still the right call, but NOT for the reason this
  // comment used to give: it claimed `changes` is unpopulated by the local emulator, which is
  // false in both directions and had already sent one reviewer hunting a bug that does not
  // exist. Miniflare computes it from `total_changes()` (`d1/database.worker.js`), and
  // `acceptInvite` has always gated single-use invites on it, green locally and verified
  // against real D1 on a throwaway deployment: two identities, one invite, burned exactly once.
  // The honest reason to keep RETURNING here is that it says what moved rather than how many,
  // which is what a guarded conditional update wants.
  const moved = await env.DB.prepare(
    "UPDATE identities SET license_hash = ? WHERE id = ? AND license_hash = ? RETURNING id"
  ).bind(newHash, identityID, oldHash).first();
  if (!moved) return false;

  // The seat cap counts devices per licence. Leaving this identity's old rows behind would
  // hold seats on a licence it no longer belongs to, and those tokens would still
  // authenticate until something else revoked them.
  const stale = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE identity_id = ? AND license_hash = ? AND revoked_at IS NULL " +
    "RETURNING id"
  ).bind(stamp, identityID, oldHash).all();
  for (const device of stale.results ?? []) {
    // Out of the inbox too, or `alarm()` keeps pushing at a device id that can no longer
    // connect. Same cleanup the seat eviction below does, for the same reason.
    await inboxCall(env, identityID, "/devices/remove", { device: device.id }).catch(() => {});
  }

  console.log(`identity migrated devices=${(stale.results ?? []).length}`);
  return true;
}

// ---------------------------------------------------------------- auth

async function authenticate(request, env, ctx) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  return authenticateToken(header.slice(7).trim(), env, ctx);
}

/// Split out for the WebSocket upgrade, which reaches the token a second way.
///
/// `MessagingClient.openSocket` sends an Authorization HEADER and that is the path to keep:
/// this Worker runs with `observability` on, so Cloudflare records the request URL verbatim
/// in Workers Logs, and a token in the query string is a live, never-expiring credential
/// written into a searchable index. The `?token=` fallback below exists only for builds that
/// shipped before the header, and should be dropped once none are left.
async function authenticateToken(token, env, ctx) {
  if (!token) return null;
  const tokenHash = await sha256Hex(token);

  // One round trip, not two: an INNER JOIN gives the same answer as the two lookups it
  // replaces (no row when the device is revoked, no row when the license is missing).
  const row = await env.DB.prepare(
    "SELECT d.id AS device_id, d.identity_id, d.license_hash, l.status " +
    "FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
    "WHERE d.token_hash = ? AND d.revoked_at IS NULL"
  ).bind(tokenHash).first();
  if (!row) return null;
  // A blocked license keeps its token but loses the service. Distinct from revoked, which
  // is Gumroad's word (refund, chargeback); blocked is ours (abuse).
  if (row.status !== "active") return null;

  ctx.waitUntil(
    env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?")
      .bind(now(), row.device_id).run()
  );
  return { deviceID: row.device_id, identityID: row.identity_id, licenseHash: row.license_hash };
}

// ---------------------------------------------------------------- routes

async function activateDevice(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return fail(400, "bad_request");
  }
  // `JSON.parse("null")` SUCCEEDS, so the catch above never fires for a body of `null` and
  // the property reads below would throw a 500. Same for a bare string or array.
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(400, "bad_request");
  // Exactly one credential. Both set is a client bug, and silently picking a winner is how
  // an App Store build ends up authenticating as somebody else's Gumroad licence.
  const key = typeof body.license_key === "string" ? body.license_key.trim() : "";
  const jws = typeof body.app_transaction === "string" ? body.app_transaction.trim() : "";
  if (!key === !jws) return fail(400, "bad_request");
  if (key && key.length > 100) return fail(400, "bad_request");
  if (jws && jws.length > MAX_APP_TRANSACTION_CHARS) return fail(400, "bad_request");
  if (!isPublicKey(body.public_key)) return fail(400, "bad_public_key");

  const stamp = now();
  let hash;
  let saleID = null;
  let source;

  if (jws) {
    const { status, appTransactionID } = await verifyAppTransaction(jws, env);
    if (status === "unconfigured") return fail(503, "appstore_unconfigured");
    if (status !== "active") return fail(403, "bad_license");
    hash = await appStoreHash(appTransactionID);
    source = "appstore";
    // No revoked branch: an Apple refund is not visible from here. Catching one needs App
    // Store Server Notifications V2 and a webhook, and §14 says fail open and do not build
    // DRM until piracy is a real problem. `blocked` below still works, because that is our
    // own abuse decision and applies to either channel.
  } else {
    const { status: verdict, saleID: gumroadSaleID } = await verifyLicense(key);
    // FAIL CLOSED here, and only here. The app's own license gate fails OPEN by design
    // (CLAUDE.md §12: never lock a paying user out for being offline) and an already issued
    // token keeps working while Gumroad is down. But handing out a NEW token without checking
    // would make "Gumroad is unreachable" a free pass.
    if (verdict === "unreachable") return fail(503, "gumroad_down");
    if (verdict === "invalid") return fail(403, "bad_license");

    hash = await licenseHash(key);
    saleID = gumroadSaleID;
    source = "gumroad";

    if (verdict === "revoked") {
      await env.DB.prepare(
        // Same CASE as the active upsert below, and for the same reason. Writing 'revoked'
        // unconditionally LAUNDERED an admin block: 'blocked' became 'revoked', and then a
        // reversed refund let the next activation promote that row all the way back to
        // 'active', because the CASE below only ever protected 'blocked'. That was the only
        // way a block ever cleared, by accident. Mirrors mushroom-files.
        "INSERT INTO licenses (license_hash, status, checked_at, created_at) VALUES (?, 'revoked', ?, ?) " +
        "ON CONFLICT(license_hash) DO UPDATE SET " +
        "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'revoked' END, " +
        "checked_at = excluded.checked_at"
      ).bind(hash, stamp, stamp).run();
      return fail(403, "revoked");
    }
  }

  // Never downgrade a BLOCKED license back to active on re-activation: blocked is our
  // decision about abuse, and neither Gumroad nor Apple has an opinion on it.
  await env.DB.prepare(
    "INSERT INTO licenses (license_hash, status, checked_at, created_at, gumroad_sale_id, source) " +
    "VALUES (?, 'active', ?, ?, ?, ?) " +
    "ON CONFLICT(license_hash) DO UPDATE SET " +
    "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'active' END, " +
    "checked_at = excluded.checked_at, " +
    "gumroad_sale_id = COALESCE(excluded.gumroad_sale_id, licenses.gumroad_sale_id)"
  ).bind(hash, stamp, stamp, saleID, source).run();

  const blocked = await env.DB.prepare("SELECT status FROM licenses WHERE license_hash = ?")
    .bind(hash).first();
  if (blocked?.status !== "active") return fail(403, "revoked");

  const identityID = await identityFor(body.public_key);

  // FIRST CLAIM WINS, and this is the only thing standing between a friend and your inbox.
  // A public key is not a secret: `/v1/friends` hands it to every friend, `friend_added`
  // pushes it, and accepting an invite returns the inviter's. X25519 keys cannot sign, so
  // there is no challenge to answer, and without this check anyone holding their own valid
  // license could post SOMEBODY ELSE'S public key and be issued a token for that identity,
  // then read their friend list, register their own push token, and `remove` every
  // friendship (which drops the messages with it). Binding the identity to the license that
  // first claimed it costs one lookup and closes that door; the bodies were always safe,
  // everything around them was not.
  const claimed = await env.DB.prepare("SELECT license_hash FROM identities WHERE id = ?")
    .bind(identityID).first();
  if (claimed && claimed.license_hash && claimed.license_hash !== hash) {
    // Before refusing: the same person moving between the direct download and the App Store
    // lands here with a perfectly good credential on a Mac whose identity is bound to the
    // OTHER channel's hash. If they can also produce the credential that owns it, this is a
    // migration rather than a theft, and the identity moves. See `migrateIdentity`.
    if (!(await migrateIdentity(env, identityID, claimed.license_hash, hash, body, stamp))) {
      // Its OWN code, not the `bad_license` this used to share with a genuinely invalid key.
      // The two are opposite problems: one is a key the app should ask the user to check, the
      // other is a perfectly good key meeting an identity somebody else's license already
      // owns. Reported as the same thing, the app told a user with a valid replacement
      // licence "I could not find your license. Try Settings, License", sent them to a pane
      // where that key was already entered, and refused to try again for the rest of the
      // session.
      return fail(403, "identity_claimed");
    }
  }

  // The public key is the identity, so this is an upsert on a value that cannot change for
  // a given id: sha256 collisions aside, a row that exists already holds this same key.
  // `license_hash` is filled in on first claim and never moved, including for rows written
  // before the column existed (COALESCE, so an old NULL binds to whoever activates next).
  await env.DB.prepare(
    "INSERT INTO identities (id, public_key, license_hash, created_at) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET license_hash = COALESCE(identities.license_hash, excluded.license_hash)"
  ).bind(identityID, body.public_key, hash, stamp).run();

  // Past the cap, evict the least-recently-seen Mac rather than refusing. A 409 would
  // strand someone who reinstalled twice, and the evicted Mac silently re-activates on its
  // next 401. Scoped to the license, not the identity: three Macs, however many keys.
  const live = await env.DB.prepare(
    "SELECT id, identity_id FROM devices WHERE license_hash = ? AND revoked_at IS NULL " +
    "ORDER BY last_seen_at DESC"
  ).bind(hash).all();
  for (const device of (live.results ?? []).slice(MAX_DEVICES_PER_LICENSE - 1)) {
    await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?")
      .bind(stamp, device.id).run();
    // And out of the INBOX, which is where `alarm()` looks. Revoking in D1 alone left a row
    // holding this Mac's still-valid APNs token with a frozen `last_acked_seq`, so every
    // later message pushed at it even though the Mac was connected and acking under its new
    // device id. `identity_id` is selected above purely so this line can address the inbox.
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
  // The inbox copy too, or "Start Over" leaves the abandoned identity holding this Mac's live
  // APNs token: friends who were never told keep writing to it, its alarm keeps firing, and
  // the user gets banners for an identity the app has discarded and cannot open.
  await inboxCall(env, auth.identityID, "/devices/remove", { device: auth.deviceID })
    .catch(() => {});
  return reply(200, {});
}

// ---------------------------------------------------------------- invites

async function createInvite(env, auth) {
  const stamp = now();
  const since = stamp - 86400;
  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM invites WHERE identity_id = ? AND created_at > ?"
  ).bind(auth.identityID, since).first();
  if ((recent?.n ?? 0) >= INVITES_PER_DAY) {
    return fail(429, "rate_limited", { retry_after: 3600 });
  }

  // Retry on collision rather than trusting 32^8 blindly. Three attempts is plenty: a
  // collision needs an unexpired, unused code, and there are only ever a handful live.
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
    body = await request.json();
  } catch {
    return fail(400, "bad_request");
  }
  const code = normalizeInvite(body.code);
  if (!wellFormedInvite(code)) return fail(404, "invite_not_found");

  // Eight characters over a 32 character alphabet is 2^40, which is plenty against a person
  // and nothing against a loop: every distinct answer here (not_found, expired, used) is an
  // existence oracle, and one licensed account could otherwise grind the live code space.
  if (!(await throttle(env, auth.identityID, "accept", ACCEPTS_PER_HOUR, 3600))) {
    return fail(429, "rate_limited", { retry_after: 3600 });
  }

  const invite = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(code).first();
  if (!invite) return fail(404, "invite_not_found");
  // Expiry before used, so an old code reads as expired rather than as someone else's.
  if (invite.expires_at <= now()) return fail(410, "invite_expired");
  if (invite.used_at) return fail(409, "invite_used");
  // Its own case because it is the single most likely mistake while testing, and
  // "not found" would send someone hunting for a code that is right there.
  if (invite.identity_id === auth.identityID) return fail(409, "self_invite");

  const inviter = await env.DB.prepare("SELECT * FROM identities WHERE id = ?")
    .bind(invite.identity_id).first();
  const accepter = await env.DB.prepare("SELECT * FROM identities WHERE id = ?")
    .bind(auth.identityID).first();
  if (!inviter || !accepter) return fail(404, "invite_not_found");

  // Burn the code BEFORE writing the friendship. A conditional UPDATE is the whole
  // concurrency story: two Macs racing on the same code, one wins the row and the other
  // gets zero changes and a 409, so a single-use invite cannot become double-use.
  const burnedAt = now();
  const burn = await env.DB.prepare(
    "UPDATE invites SET used_at = ? WHERE code = ? AND used_at IS NULL"
  ).bind(burnedAt, code).run();
  if (!burn.meta.changes) return fail(409, "invite_used");

  // Both directions, because a friendship one side does not know about is a message the
  // other side's inbox will refuse.
  // `allSettled`, not `all`. A rejected subrequest (an inbox restarting mid-deploy) made
  // `Promise.all` reject, which threw straight out of the Worker and skipped the un-burn
  // below entirely: the code stayed spent forever and the pair was never completed, so the
  // only way back was a brand new invite against the 20/day cap.
  const settled = await Promise.allSettled([
    inboxCall(env, invite.identity_id, "/friends/add",
              { peer: auth.identityID, public_key: accepter.public_key }),
    inboxCall(env, auth.identityID, "/friends/add",
              { peer: invite.identity_id, public_key: inviter.public_key }),
  ]);
  const [inviterHalf, accepterHalf] = settled.map(
    (r) => (r.status === "fulfilled" ? r.value : null));
  // findIndex, not find: a REJECTED half is `null`, and `find` would hand back that null and
  // read as "nothing failed" in an `if`.
  const failed = [inviterHalf, accepterHalf].findIndex((r) => !r || !r.ok) !== -1;
  if (failed) {
    // GIVE THE CODE BACK. One half can land while the other refuses (the accepter is at
    // MAX_FRIENDS, or one inbox 503s), and the burn above has already committed: without
    // this the inviter holds a friend whose inbox answers `not_friends` to every message,
    // and the code that would have completed the pair is spent. `/friends/add` is an
    // upsert, so a retry finishes the half that did not land rather than duplicating the
    // half that did.
    // CONDITIONAL on the stamp this call wrote. Unconditional, it could clear a burn that a
    // LATER accept had legitimately committed in between, handing one code to two people.
    await env.DB.prepare(
      "UPDATE invites SET used_at = NULL WHERE code = ? AND used_at = ?"
    ).bind(code, burnedAt).run();
    // The ACCEPTER's own half decides whether "you have reached 50 friends" is true. Reading
    // it off whichever half happened to fail told the accepter they were full when it was the
    // inviter who had no room, which sends them deleting their own friends to fix somebody
    // else's list.
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
    body = await request.json();
  } catch {
    return fail(400, "bad_request");
  }
  // An APNs device token is 32 bytes of hex, and the sandbox/production split decides which
  // host it can be sent to. A token posted to the wrong one silently never arrives.
  if (typeof body.token !== "string" || !/^[0-9a-fA-F]{64}$/.test(body.token)) {
    return fail(400, "bad_request");
  }
  const environment = body.environment === "sandbox" ? "sandbox" : "production";
  const response = await inboxCall(env, auth.identityID, "/push/register", {
    device: auth.deviceID, token: body.token.toLowerCase(), environment,
  });
  return response.ok ? reply(200, {}) : fail(503, "try_again");
};

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
    .replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s/g, "");
}

/// Whether this deployment can send push AT ALL, as opposed to being able to send it right now.
///
/// The distinction is the whole point, because `apnsKey` throws identically for "no secret was
/// ever set" and "the secret is malformed", and `alarm()` answered both by re-arming at
/// PUSH_RETRY_MS. That is right for a bad key and permanently wrong for an absent one: a
/// customer running this Worker in their own account CANNOT have push, since only our own .p8
/// signs for `com.qubit.shroomy.app`. Every inbox holding an unacked message then woke on a
/// timer forever and billed them for it, invisibly. A malformed key still retries; an absent
/// one now stops.
/// All THREE, not just the key. `mintAPNsToken` puts `APNS_KEY_ID` in the JWT header and
/// `APNS_TEAM_ID` in its payload, and neither is checked anywhere else: with the key alone the
/// token imports fine and ships `kid: undefined` / `iss: undefined`, APNs answers 403
/// InvalidProviderToken, and 403 is neither 410 nor ok, so `retry` is set and the whole ladder
/// runs for every message forever. That is the partially-configured deployment this guard
/// exists to protect, failing in exactly the way it was written to prevent.
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

// The provider token, CACHED for the isolate's life.
//
// Apple rejects a provider token refreshed faster than roughly once per 20 minutes with
// `429 TooManyProviderTokenUpdates`, and `deliver` arms an alarm every 10 seconds, so minting
// a fresh one per alarm earned rejections under exactly the load that needs push to work.
// `sendPush`'s status is only inspected for 410, so a 429 fell through to the else branch and
// marked the message as pushed when it was not: notifications stopped, silently. An hour is
// the documented lifetime; 50 minutes leaves room for a slow send.
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

/// The payload carries NO content and no names, because the server holds neither.
/// `loc-key` resolves against the app bundle, so the alert is localized on the Mac from the
/// catalogs that are already there and nothing readable crosses Apple's servers.
async function sendPush(env, jwt, token, environment, threadID) {
  const host = environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  return fetch(`https://${host}/3/device/${token}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      "apns-topic": env.APNS_TOPIC ?? "com.qubit.shroomy.app",
      "apns-push-type": "alert",
      "apns-priority": "10",
      // EXPLICIT, because the header's absence means 0, and 0 means "try once and do not
      // store it". Every push this Worker sends is aimed at a Mac that did not ack, which
      // is to say one that is asleep or has the app closed: exactly the case a single
      // undeliverable attempt throws away. Nothing retries it either, since APNs answers
      // 200 for an accepted-but-undeliverable push and `alarm()` only re-arms on a failure.
      "apns-expiration": String(now() + PUSH_EXPIRY_SECONDS),
    },
    body: JSON.stringify({
      aps: {
        alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_BODY" },
        sound: "default",
        "thread-id": threadID,
      },
      // The peer id again, OUTSIDE `aps`, because that is the half of the payload that
      // reaches the app as `userInfo`. Without it a tapped banner has nothing to open:
      // `thread-id` groups notifications and is not handed back to the delegate. Still no
      // name and no body, so this leaks nothing the thread id did not already.
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

    // `msg_id` UNIQUE plus INSERT OR IGNORE is the entire dedup story, and it is why a
    // retried send can never become a second message.
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
    // A Durable Object created by an older build already has its tables, so CREATE TABLE IF
    // NOT EXISTS above will not add a column to one. There is no migration framework here
    // and no way to enumerate objects to run one, so new columns arrive like this: attempt,
    // ignore the "duplicate column" that every already-migrated object throws.
    for (const alter of [
      "ALTER TABLE friends ADD COLUMN online_at INTEGER",
      "ALTER TABLE devices ADD COLUMN last_pushed_seq INTEGER NOT NULL DEFAULT 0",
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

  send(frame) {
    const text = JSON.stringify(frame);
    for (const socket of this.sockets()) {
      try {
        socket.send(text);
      } catch {
        // A socket the runtime has not finished tearing down yet. Dropping the frame is
        // correct: catch-up on reconnect is what makes this recoverable, not a retry here.
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
      body = await request.json();
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
      // A device the license no longer has a seat for. D1 revoking the row is not enough:
      // `alarm()` reads THIS table, and a stale row keeps a live APNs token beside a
      // `last_acked_seq` that can never advance (acks are written `WHERE device_id = ?` from
      // the live socket's tag), so it matched `last_acked_seq < latest` for every message
      // thereafter and pushed at a Mac that was sitting there acking normally.
      case "/devices/remove": return this.removeDevice(body.device);
      // Counter-only. Used by `throttle` for routes with no inbox of their own, which is
      // why it touches nothing else in this object.
      case "/rate":
        return (await this.allow(body.bucket, body.limit, body.window))
          ? reply(200, {}) : fail(429, "rate_limited");
      default: return fail(404, "not_found");
    }
  }

  addFriend({ peer, public_key: publicKey }) {
    if (!peer || !publicKey) return fail(400, "bad_request");
    const count = this.one("SELECT COUNT(*) AS n FROM friends WHERE blocked = 0");
    if ((count?.n ?? 0) >= MAX_FRIENDS && !this.friend(peer)) {
      return fail(409, "too_many_friends");
    }
    // Re-accepting an invite from someone already here must not reset `blocked`: it would
    // let a blocked person talk their way back in by sending a fresh invite.
    this.sql.exec(
      "INSERT INTO friends (peer, public_key, blocked, added_at) VALUES (?, ?, 0, ?) " +
      "ON CONFLICT(peer) DO UPDATE SET public_key = excluded.public_key",
      peer, publicKey, now());
    // Tell this Mac about the friendship it did not ask for. Accepting an invite tells the
    // ACCEPTER who they added, in the HTTP reply; the person who created the code learns
    // nothing at all without this frame, and their app then drops every message from the
    // friend it has never heard of. `/friends/list` covers the offline case; this covers
    // the ordinary one, where the two of them are sitting next to each other.
    this.send({ t: "friend_added", peer_id: peer, public_key: publicKey });
    return reply(200, {});
  }

  /// Every friendship this inbox holds, for a client that may have missed one.
  ///
  /// Read on every connect rather than only after an invite: a Mac that was asleep when its
  /// code was accepted has no other way to find out, and a friendship the server knows about
  /// but the client does not is a conversation that silently swallows messages.
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

  /// Deleting a conversation drops the stored copy too. These rows are ciphertext we hold
  /// on the user's behalf; "delete" has to mean gone, not hidden.
  removeFriend(peer) {
    this.sql.exec("DELETE FROM messages WHERE peer = ?", peer);
    this.sql.exec("DELETE FROM friends WHERE peer = ?", peer);
    return reply(200, {});
  }

  /// CLAMPED to the device's own `last_acked_seq`, never the cursor the client sends.
  ///
  /// The client derives its cursor from `MAX(seq)` over the rows it stored, which is not the
  /// highest CONTIGUOUS one: a page it failed to fetch, or one message it could not decrypt,
  /// leaves a hole below a number that keeps climbing. It holds its ACK below the hole
  /// correctly, so we still have the message, and then asked for everything after the MAX
  /// and never saw it again. Taking the lower of the two makes the ack the single cursor:
  /// what we kept for them is what they are offered.
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
        sent_at: m.sent_at, seq: m.seq,
      })),
      // The client keeps calling with the new cursor until this is false, rather than
      // assuming one round trip catches up.
      has_more: messages.length > SYNC_PAGE,
    });
  }

  /// Store a message somebody sent US, and get it in front of them.
  async deliver({ msg_id: msgID, from, ciphertext, sent_at: sentAt }) {
    if (!msgID || !from || !ciphertext) return fail(400, "bad_request");

    const friend = this.friend(from);
    // Both answers are 403 and both name their reason, because the SENDER is not told
    // these apart: the app maps `blocked` to the same sentence as `not_friends`.
    if (!friend) return fail(403, "not_friends");
    if (friend.blocked) return fail(403, "blocked");

    const stamp = now();
    // Retention runs HERE rather than on a cron. A cron would have to enumerate every
    // inbox, and there is no way to list Durable Objects; doing it on the write path makes
    // "we keep messages 30 days" structurally true instead of a promise held up by a
    // scheduler that cannot reach the data. Indexed, and the table is bounded by this very
    // delete, so it stays cheap.
    this.sql.exec("DELETE FROM messages WHERE created_at < ?", stamp - RETENTION_SECONDS);
    // CLAMPED to a window around our own clock, and computed once for both the row and the
    // frame below. The sender chooses this value and `MessageCrypto.binding` covers only
    // `msgID|senderID`, so it is the one field a modified client can forge freely, and it is
    // the SOLE sort key on the other side: `Messaging.ordered` sorts a conversation by it and
    // `conversationOrder` ranks the friend list by it. Unclamped, one message dated 2100
    // pinned that conversation to the top of the list forever and sat below every later reply
    // in the thread, and one dated in the past sank below the 500 row read window, where it
    // was stored and counted as unread but could never be seen.
    const claimed = Number(sentAt);
    const sent = Number.isFinite(claimed)
      ? Math.min(Math.max(claimed, stamp - SENT_AT_PAST_SECONDS), stamp + SENT_AT_FUTURE_SECONDS)
      : stamp;
    this.sql.exec(
      "INSERT OR IGNORE INTO messages (msg_id, peer, ciphertext, sent_at, created_at) " +
      "VALUES (?,?,?,?,?)", msgID, from, ciphertext, sent, stamp);

    // Whether it was new or a duplicate, answer with the sequence it HAS. A retry then gets
    // the same number as the original rather than an error, which is what makes the send
    // path idempotent from the sender's side too.
    const row = this.one("SELECT seq FROM messages WHERE msg_id = ?", msgID);
    if (!row) return fail(500, "not_stored");

    this.send({
      t: "message",
      message: { msg_id: msgID, peer_id: from, ciphertext, sent_at: sent, seq: row.seq },
    });

    // Arm the push even when a socket took it: "connected" is not "received", and a slept
    // Mac's TCP outlives its ability to act. The ack is what cancels this.
    //
    // Unless there is no push to arm. `alarm()` does nothing else, so on a deployment without
    // an APNs key this would wake the inbox once per message to discover that again.
    if (apnsConfigured(this.env)) {
      // ONLY when no alarm is already pending, and that guard is doing two jobs.
      //
      // It stops a busy conversation resetting the retry budget. Clearing the counter on every
      // message meant the ladder never climbed past attempt one against a dead key: each
      // message wiped it and re-armed at the grace window, so a chatty friend restored roughly
      // one wake per message forever, which is the billing failure the budget exists to stop.
      //
      // It also stops the reverse. The alarm is a single slot, so a message arriving while a
      // retry is climbing used to overwrite that retry's alarm with a fresh grace window, and
      // the resuming `retryPush` then overwrote THAT with its own backoff, delaying the new
      // message's notification by the full ladder. A pending alarm already covers every
      // message below `MAX(seq)`, because `alarm` reads the table rather than a message.
      const pending = await this.ctx.storage.getAlarm();
      const grace = Date.now() + PUSH_GRACE_MS;
      if (pending === null) {
        // Idle: a fresh message gets a fresh budget.
        await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
        await this.ctx.storage.setAlarm(grace);
      } else if (pending > grace) {
        // A retry ladder is climbing and its next rung is further out than the grace window.
        // Pull the alarm forward WITHOUT clearing the counter: skipping entirely, which is what
        // this did, meant a message arriving during a long backoff waited the whole backoff for
        // its first attempt, and if the ladder then exhausted it got no notification at all,
        // because `retryPush` deliberately arms nothing when it gives up. Keeping the counter is
        // what stops a busy conversation resetting the budget, which was the point of the guard.
        await this.ctx.storage.setAlarm(grace);
      }
    }
    return reply(200, { seq: row.seq });
  }

  async relayTyping({ from }) {
    const friend = this.friend(from);
    // Dropped on the floor when there is nobody to show it to. A typing indicator has no
    // value later, so there is nothing here to store or retry.
    if (!friend || friend.blocked || !this.sockets().length) return reply(200, {});
    // SYMMETRIC. The Settings copy promises "with it off, you will not see theirs either",
    // and only the outbound half was gated: hiding your own presence still let every
    // friend's typing dots and online state through, which is the half the user can see and
    // check.
    if (!(await this.sharePresence())) return reply(200, {});
    this.send({ t: "typing", peer_id: from });
    return reply(200, {});
  }

  /// Lands on the SENDER's inbox: their message reached the other Mac's disk.
  markDelivered({ ids }) {
    for (const id of ids ?? []) this.send({ t: "delivered", msg_id: id });
    return reply(200, {});
  }

  /// A friend telling us they came or went.
  ///
  /// Answers IMMEDIATELY and never calls anything: that is what makes the whole presence
  /// system deadlock-free. When `reply_to` is set we fire our own state back at them, once,
  /// without a further reply flag, so a hello gets an answer and cannot ping-pong.
  async peerPresence({ peer, online, reply_to: replyTo }) {
    // The guard `relayTyping` and `deliver` both apply, and the one this handler was
    // missing. `announcePresence` only fans out to `blocked = 0`, so blocking stopped US
    // telling THEM; without this it did not stop them telling us, and the `reply_to` bounce
    // below then answered with our own state, leaking presence to the blocked peer.
    const friend = this.friend(peer);
    if (!friend || friend.blocked) return reply(200, {});

    // Recorded either way, so turning presence back on has something to show immediately;
    // whether it REACHES this Mac is the symmetry question below.
    this.sql.exec("UPDATE friends SET online_at = ? WHERE peer = ?",
                  online ? now() : null, peer);
    const sharing = await this.sharePresence();
    if (sharing && this.sockets().length) {
      this.send({ t: "presence", peer_id: peer, online: !!online });
    }

    if (replyTo && this.sockets().length && sharing) {
      this.ctx.waitUntil(
        inboxCall(this.env, peer, "/presence",
                  { peer: this.identity(), online: true }).catch(() => {}));
    }
    return reply(200, {});
  }

  removeDevice(device) {
    if (!device) return fail(400, "bad_request");
    this.sql.exec("DELETE FROM devices WHERE device_id = ?", device);
    // And the SOCKET, which the row deletion on its own left wide open: eviction and "Start
    // Over" both come through here, and a connection that keeps sending and acking after the
    // device it belongs to has been removed is the revocation not happening.
    this.dropSockets(device);
    return reply(200, {});
  }

  savePushToken({ device, token, environment }) {
    if (!device) return fail(400, "bad_request");
    // A deployment that cannot push has no business holding a push token. Only our own .p8
    // signs for com.qubit.shroomy.app, so on anyone else's server this token is a stable
    // per-Mac identifier they collect for free and can never use, and the rows accumulate
    // forever. Refusing it here is also what makes the guards in `deliver` and `alarm`
    // belt-and-braces rather than the mechanism: with no tokens stored, `alarm`'s target list
    // is provably empty. 200, not an error: the app has done nothing wrong and there is
    // nothing for it to retry.
    if (!apnsConfigured(this.env)) return reply(200, {});
    this.sql.exec(
      "INSERT INTO devices (device_id, apns_token, apns_env, updated_at) VALUES (?,?,?,?) " +
      "ON CONFLICT(device_id) DO UPDATE SET apns_token = excluded.apns_token, " +
      "apns_env = excluded.apns_env, updated_at = excluded.updated_at",
      device, token, environment, now());
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
    // Hibernation, not a held reference: an idle conversation should cost nothing, and the
    // DO can be evicted from memory while the socket stays open.
    this.ctx.acceptWebSocket(pair[1], [deviceID]);

    if (wasOffline) await this.announcePresence(true);
    // Deferred, because the client cannot receive anything until it has the socket back.
    this.ctx.waitUntil(this.sendSnapshot(pair[1]));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(socket, raw) {
    let frame;
    try {
      // `raw` is a string for a TEXT frame and an ArrayBuffer for a BINARY one, and both
      // arrive in practice: URLSessionWebSocketTask.send(.data) is binary, a browser or
      // Node sending a string is text. Passing an ArrayBuffer straight to JSON.parse
      // stringifies it to "[object ArrayBuffer]" and throws, which the catch below then
      // swallowed as "one bad frame" — so every message from the Mac app was silently
      // dropped while the socket looked perfectly healthy.
      const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
      frame = JSON.parse(text);
    } catch {
      return;   // Never close the socket over one genuinely bad frame.
    }

    switch (frame.t) {
      case "send": return this.handleSend(socket, frame);
      case "ack": return this.handleAck(socket, frame);
      case "typing": return this.handleTyping(frame);
      case "ping":
        // Still allowed to be here? Throttled, and BEFORE the pong, so a socket whose device
        // was revoked or whose license was blocked is closed rather than reassured.
        if (!(await this.stillAuthorized(socket))) return;
        socket.send(JSON.stringify({ t: "pong" }));
        // The heartbeat has to KEEP presence true, not just prove the socket is alive.
        // `Presence` in the Kit says "the server counts the missed heartbeats
        // (PRESENCE_STALE_SECONDS, three of these) and tells friends", and nothing here did:
        // `online_at` was written once at connect and never again, while `sendSnapshot` reads
        // it through a 90 second window. Every connection older than 90 seconds therefore
        // read as offline to any friend who connected after it, which is most of them, and
        // nothing would ever re-evaluate it.
        return this.refreshPresence();
      default: return;   // Forward compatibility: ignore, do not disconnect.
    }
  }

  async handleSend(socket, frame) {
    const { msg_id: msgID, peer_id: peerID, ciphertext } = frame;
    // `msg_id` is bounded for the same reason `ciphertext` is. It is stored as TEXT in the
    // recipient's inbox and echoed to every socket on it, so an unbounded one turned the
    // carefully derived MAX_CIPHERTEXT_CHARS cap into a suggestion: a modified client could
    // put a megabyte in the id at the full send rate and fill a friend's Durable Object
    // until writes failed, at which point `deliver` returns non-ok and that person stops
    // receiving mail from EVERYONE. A UUID is 36 characters; 64 leaves room without leaving
    // a hole.
    if (typeof msgID !== "string" || !msgID || msgID.length > MAX_MSG_ID_CHARS
        || !peerID || !isBase64(ciphertext, MAX_CIPHERTEXT_CHARS)) {
      return socket.send(JSON.stringify({
        t: "rejected", msg_id: typeof msgID === "string" ? msgID.slice(0, MAX_MSG_ID_CHARS) : "",
        code: "bad_request",
      }));
    }
    if (!this.friend(peerID)) {
      return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code: "not_friends" }));
    }
    if (!(await this.allow("send", MESSAGES_PER_MINUTE, 60))) {
      return socket.send(JSON.stringify({ t: "rejected", msg_id: msgID, code: "rate_limited" }));
    }

    // WRAPPED, like every other frame handler. This was the only one that awaited a raw
    // `inboxCall`: `handleAck` and `handleTyping` both go through
    // `ctx.waitUntil(... .catch(() => {}))`, and a Durable Object fetch that REJECTS rather
    // than answering non-ok (the peer's inbox restarting mid-deploy, hitting a limit, or a
    // malformed body making `.json()` throw) propagated out of `webSocketMessage`, which the
    // runtime treats as a handler failure and closes the socket. The sender then got no
    // `rejected` frame at all, so the message stayed `sending`, the reconnect resent it, and
    // the same unhealthy inbox closed the socket again: a resend/disconnect loop that lasted
    // as long as the peer was unwell. `try_again` is the honest answer, and it is one the
    // client already knows how to show.
    let response;
    let seq;
    try {
      response = await inboxCall(this.env, peerID, "/deliver", {
        msg_id: msgID, from: this.identity(), ciphertext, sent_at: frame.sent_at,
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        // `blocked` is deliberately reported as `not_friends`: telling someone they have been
        // blocked is a feature for the blocker to grant, not for us to leak.
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
  /// Two jobs, and the second is why a connected Mac never gets a notification: it moves the
  /// cursor that the push alarm compares against.
  async handleAck(socket, frame) {
    const seq = Number(frame.seq) || 0;
    if (!seq) return;
    // The socket's tag, set at accept time, not anything the frame claims. One Mac must not
    // be able to move another Mac's cursor and suppress its notifications.
    const device = this.ctx.getTags(socket)[0];
    if (!device) return;
    // The baseline is MONOTONIC, kept beside the device rows rather than derived from them.
    //
    // `MAX(last_acked_seq) FROM devices` looks like the same number and is not: eviction
    // DELETEs a device row (`/devices/remove`), so when the evicted Mac re-activates it
    // inserts a fresh row with `last_acked_seq` defaulting to 0, and if it is now the only
    // row the baseline falls from whatever it was to nothing. Its first ack then made
    // `seq > before` true for the ENTIRE retained history and fanned `/delivered` out with
    // every msg_id to every peer, who each answered with one frame per id: a database write
    // plus a conversation reload apiece, synchronously on the main actor, on somebody else's
    // Mac. Storage outlives the rows, so it cannot be walked backwards this way.
    const devicesMax = this.one("SELECT MAX(last_acked_seq) AS s FROM devices")?.s ?? 0;
    const before = Math.max(devicesMax, (await this.ctx.storage.get("deliveredUpTo")) ?? 0);
    this.sql.exec(
      "UPDATE devices SET last_acked_seq = MAX(last_acked_seq, ?) WHERE device_id = ?",
      seq, device);

    // Tell each sender their messages landed. Only the newly acked range, so an idle client
    // re-acking the same cursor does not re-notify everyone.
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
    // The client throttles too, but that is the side a modified build controls.
    if (!(await this.allow("typing", TYPING_PER_SECOND, 1))) return;
    this.ctx.waitUntil(
      inboxCall(this.env, frame.peer_id, "/typing", { from: this.identity() }).catch(() => {}));
  }

  /// Re-prove a live socket's device, at most once per SOCKET_RECHECK_SECONDS.
  ///
  /// The upgrade is the only place a token is ever checked, and hibernated sockets outlive
  /// the check by design, so without this a revoked device, an evicted seat and a license
  /// blocked for abuse all kept sending, acking and receiving for as long as the connection
  /// happened to stay up. The client reconnects on close, so a legitimate device that was
  /// merely re-activated comes straight back with its new token.
  ///
  /// Fails OPEN on a D1 error, deliberately: this is a revocation check, not the
  /// authentication itself, and taking every live conversation down because D1 blipped would
  /// be the worse failure by far.
  async stillAuthorized(socket) {
    const device = this.ctx.getTags(socket)[0];
    if (!device) return true;
    const key = `checked:${device}`;
    const last = (await this.ctx.storage.get(key)) ?? 0;
    if (now() - last < SOCKET_RECHECK_SECONDS) return true;
    await this.ctx.storage.put(key, now());

    let row;
    try {
      row = await this.env.DB.prepare(
        "SELECT l.status FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
        "WHERE d.id = ? AND d.revoked_at IS NULL"
      ).bind(device).first();
    } catch {
      return true;   // fail open, see above
    }
    if (row && row.status === "active") return true;
    this.dropSockets(device);
    return false;
  }

  /// Close every socket belonging to one device.
  dropSockets(device) {
    for (const socket of this.ctx.getWebSockets(device)) {
      try { socket.close(1008, "revoked"); } catch { /* already gone */ }
    }
  }

  async webSocketClose(socket) {
    // Ask whether any OTHER socket survives, rather than counting and hoping. Whether
    // `getWebSockets()` still lists the closing one is a runtime detail, and both readings of
    // it are wrong in one direction: counted as present, a reconnect that raced the close
    // (which is every reconnect, since `connect()` cancels the old socket and opens the new
    // one immediately) left the count at two and announced nothing; counted as gone, the same
    // race announced OFFLINE while the replacement socket was live, and nothing re-announces,
    // so the Mac showed offline to every friend for the rest of the session. Excluding it
    // explicitly is correct either way.
    if (this.sockets().every((s) => s === socket)) await this.announcePresence(false);
  }

  async webSocketError(socket) { return this.webSocketClose(socket); }

  // -------------------------------------------------------------- presence

  /// Tell friends we came or went.
  ///
  /// FIRE AND FORGET, and that is load bearing. This used to await each friend's inbox, and
  /// two Macs connecting at the same moment then waited on each other forever: A held its
  /// turn while calling B, B held its while calling A, and neither could service the
  /// other's request. Nothing here waits for a reply, so there is no cycle to complete.
  ///
  /// `reply_to` asks a friend who IS online to announce themselves back at us. That single
  /// bounce is what replaces the old query-everyone-on-connect, and it cannot ping-pong
  /// because the reply carries no flag of its own.
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
  /// THROTTLED, and that is the whole design: a fan-out per heartbeat would be 50
  /// subrequests every 30 seconds per connected Mac. Twice per staleness window keeps
  /// `online_at` fresh with the smallest number of announcements that can do it, and the
  /// stamp lives in storage so it survives the hibernation this object is built around.
  async refreshPresence() {
    const last = (await this.ctx.storage.get("presenceAnnouncedAt")) ?? 0;
    if (now() - last < PRESENCE_REFRESH_SECONDS) return;
    await this.ctx.storage.put("presenceAnnouncedAt", now());
    await this.announcePresence(true);
  }

  /// Who we currently believe is online, from our OWN records.
  ///
  /// No outbound calls. A cold inbox sends an empty set and fills in within one round trip
  /// as the `reply_to` bounces land, which is a moment of "nobody is online yet" rather
  /// than the deadlock the querying version could produce.
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

  /// Nothing acked the message in the grace window, so the recipient is not really here.
  ///
  /// PER DEVICE, not a MAX across all of them. "Has this been seen" is a question about one
  /// Mac: an iMac that sits awake at the office acks every message the instant it lands, and
  /// a global MAX let that ack answer for the MacBook asleep in a bag, which then never got
  /// a notification for anything. `last_pushed_seq` moved to the row for the same reason,
  /// so one device having been notified cannot suppress the other.
  async alarm() {
    // The backstop for an alarm that was already persisted. `deliver` no longer arms one
    // without a key, but a DO that armed before this shipped still holds it in storage, and
    // that alarm is exactly the one that would re-arm itself forever.
    if (!apnsConfigured(this.env)) return;

    const latest = this.one("SELECT MAX(seq) AS s FROM messages")?.s ?? 0;
    if (!latest) return;

    // ONE push however many messages are pending. The payload has no content, so a second
    // notification would say exactly the same thing as the first.
    const newest = this.one("SELECT peer FROM messages WHERE seq = ?", latest);
    const targets = this.rows(
      "SELECT device_id, apns_token, apns_env FROM devices " +
      "WHERE apns_token IS NOT NULL AND last_acked_seq < ? AND last_pushed_seq < ?",
      latest, latest);
    if (!targets.length) {
      // Everyone has either acked or been pushed, so whatever we were retrying is done.
      await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
      return;
    }

    let jwt;
    try {
      ({ jwt } = await apnsToken(this.env));
    } catch {
      // A bad key, or a signing failure. NOT an absent one: the guard at the top of `alarm`
      // already returned for that, which is what stops a keyless deployment re-arming forever.
      // Never take the message path down with it, but DO come back: waiting for "the next
      // message" means the last message of the evening is the one that never produces a
      // notification at all.
      cachedAPNsToken = null;
      await this.retryPush();
      return;
    }

    let retry = false;
    for (const target of targets) {
      try {
        const response = await sendPush(this.env, jwt, target.apns_token, target.apns_env,
                                        newest?.peer ?? "mushroom");
        // 410 is Apple saying that token is dead. Keeping it would push into the void
        // forever and eventually get us throttled.
        if (response.status === 410) {
          this.sql.exec("UPDATE devices SET apns_token = NULL WHERE device_id = ?",
                        target.device_id);
        } else if (response.ok) {
          this.sql.exec("UPDATE devices SET last_pushed_seq = ? WHERE device_id = ?",
                        latest, target.device_id);
        } else {
          // Anything else (429 on the provider token, a 5xx) has NOT delivered, so recording
          // it as pushed would lose the notification. Drop the cached token on a 429 so the
          // retry mints a fresh one.
          if (response.status === 429) cachedAPNsToken = null;
          retry = true;
        }
      } catch {
        retry = true;
      }
    }
    if (retry) await this.retryPush();
    else await this.ctx.storage.delete(PUSH_ATTEMPT_KEY);
  }

  /// Come back and try this push again, but not forever.
  ///
  /// The re-arm used to be flat and unconditional: `setAlarm(now + PUSH_RETRY_MS)` on every
  /// failure, with nothing counting. An expired or revoked `.p8` fails identically every time,
  /// so a single unread message woke its inbox once a minute for the life of the deployment,
  /// on our own account as much as anyone else's, and nothing in the product would ever say so.
  ///
  /// Doubling from a minute and giving up after `PUSH_MAX_ATTEMPTS` turns that into about an
  /// hour of trying and then silence. Generous for the failures worth retrying (a 429 on the
  /// provider token, a 5xx, a network blip) and final for the ones that are not.
  ///
  /// The counter is scoped to a message rather than to the inbox: `deliver` clears it, so a
  /// genuinely new message always gets a fresh budget and a dead key costs a bounded number of
  /// wakes per message rather than an unbounded number per inbox.
  async retryPush() {
    const attempt = ((await this.ctx.storage.get(PUSH_ATTEMPT_KEY)) ?? 0) + 1;
    if (attempt > PUSH_MAX_ATTEMPTS) {
      // Deliberately no alarm. Whatever is broken is not going to be fixed by asking again,
      // and `apns-expiration` already gave Apple a day to deliver anything we did get out.
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

/// Constant-time-ish bearer check. Copied from mushroom-files rather than shared, matching
/// how `verifyLicense` and `sha256Hex` already live in both: the token is a shared secret,
/// not a per-user one, so there is nothing to enumerate, and the length guard just avoids
/// leaking it via timing. Set it with `wrangler secret put ADMIN_TOKEN`.
function adminOK(request, env) {
  const header = request.headers.get("authorization") ?? "";
  const given = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const want = env.ADMIN_TOKEN ?? "";
  if (!want || given.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

/// Block a licence from messaging and revoke every device it has.
///
/// This worker enforced `'blocked'` in three places (`authenticateToken`, `stillAuthorized`,
/// and the activate upsert's CASE) while having no way whatsoever to SET it: there was no
/// /admin/ routing here at all, and mushroom-files' identical endpoint writes a different D1
/// instance. So the one control the App Store channel has, since an Apple refund is invisible
/// from here and there is no revoked branch for it, could only be applied by hand-typed SQL
/// against production, with no audit line and no device revocation.
///
/// Live sockets are not closed from here on purpose: `stillAuthorized` re-checks each one
/// within SOCKET_RECHECK_SECONDS and drops it, which needs no fan-out across every inbox.
async function adminBlockLicense(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail(400, "bad_request"); }
  const hash = String(body.license_hash ?? "");
  if (!hash) return fail(400, "bad_request");

  const row = await env.DB.prepare("SELECT license_hash FROM licenses WHERE license_hash = ?").bind(hash).first();
  if (!row) return fail(404, "not_found");

  await env.DB.prepare("UPDATE licenses SET status = 'blocked' WHERE license_hash = ?").bind(hash).run();
  const devices = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE license_hash = ? AND revoked_at IS NULL RETURNING id"
  ).bind(now(), hash).all();

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

    if (path === "/") return Response.redirect("https://www.getmushroom.app", 302);

    if (path === "/v1/devices/activate" && method === "POST") {
      // Before the Gumroad call, because the Gumroad call is what the flood is spending.
      const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
      if (!(await throttle(env, ip, "activate", activationsPerHourPerIP(env), 3600))) {
        return fail(429, "rate_limited", { retry_after: 600 });
      }
      return activateDevice(request, env);
    }

    // The socket. Authenticated by query parameter rather than a header, because the
    // HEADER FIRST, query string only as a fallback for a client that cannot send one.
    //
    // The query string was the original scheme, on the reasoning that a token in a URL is
    // "no more exposed than a header would be" inside TLS. That is true of the wire and
    // false of us: `observability` is enabled in wrangler.jsonc, and Cloudflare records the
    // request URL verbatim in Workers Logs, so every upgrade wrote a live, non-expiring
    // device token into a searchable index that a read-only dashboard account or a leaked
    // API token can page through. Headers are not captured that way, which is the whole
    // point. `URLSessionWebSocketTask` created from a `URLRequest` does carry an
    // Authorization header through the handshake, so the premise was wrong too.
    if (path === "/v1/connect") {
      const header = request.headers.get("authorization") ?? "";
      const bearer = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
      const auth = await authenticateToken(bearer || (url.searchParams.get("token") ?? ""), env, ctx);
      if (!auth) return fail(401, "reactivate");
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
      const auth = await authenticate(request, env, ctx);
      if (!auth) return fail(401, "reactivate");

      if (path === "/v1/invites" && method === "POST") return createInvite(env, auth);
      if (path === "/v1/invites/accept" && method === "POST") return acceptInvite(request, env, auth);
      if (path === "/v1/sync" && method === "GET") return syncMessages(env, auth, url);
      if (path === "/v1/friends" && method === "GET") {
        return inboxCall(env, auth.identityID, "/friends/list", {});
      }
      if (path === "/v1/push" && method === "POST") return registerPush(request, env, auth);
      if (path === "/v1/devices/release" && method === "POST") return releaseDevice(env, auth);

      const friend = path.match(/^\/v1\/friends\/([0-9a-f]{64})\/(block|unblock|remove)$/);
      if (friend && method === "POST") return friendAction(env, auth, friend[1], friend[2]);

      return fail(404, "not_found");
    }

    return fail(404, "not_found");
  },

  /// Daily sweep of the global tables only. Message retention is NOT here on purpose:
  /// there is no way to enumerate Durable Objects, so a cron could never reach the
  /// messages. Each inbox expires its own on the write path instead (see `deliver`).
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      // No `LIMIT` on either DELETE. D1's SQLite is not built with
      // SQLITE_ENABLE_UPDATE_DELETE_LIMIT, so `DELETE … LIMIT ?` is a syntax error at
      // execute time, not a slower query: the sweep threw every night and the only trace
      // was a log line nobody reads. Both tables are small and bounded by these deletes.
      await env.DB.prepare("DELETE FROM invites WHERE expires_at < ?")
        .bind(now() - 7 * 86400).run();
      await env.DB.prepare(
        "DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at < ?"
      ).bind(now() - 30 * 86400).run();
    })());
  },
};
