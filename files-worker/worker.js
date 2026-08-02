// mushroom-files: temporary file sharing for Mushroom.
//
// A licensed Mac exchanges its Gumroad key for a device token once, then uploads files
// that live for 24 hours behind an unguessable link. Storage is a PRIVATE R2 bucket;
// nothing is ever publicly listable and the bucket has no r2.dev domain.
//
// LOGGING RULE, and it is not negotiable: observability is on and logs are retained, so
// this file must never log a filename, a share token, a license key or a bearer token.
// Ids and status codes only. (The app takes the same line: PluginToolbox wraps its
// argument logging in #if DEBUG for exactly this reason.)

const GUMROAD_PRODUCT_ID = "59Bhmk7nBsjAqKhst9Bf9g==";  // not a secret; matches LicenseManager.productID

const MAX_FILE_BYTES = 95 * 1024 * 1024;        // 95 MiB, under Cloudflare's 100 MB body cap
const TTL_SECONDS = 24 * 60 * 60;
const MAX_ACTIVE_FILES_PER_LICENSE = 50;
// 50 files at MAX_FILE_BYTES would be 4.6 GiB, so this binds first at ~32 max-size files.
// Deliberate: the file count is the cap for ordinary drops, this is the cap on the bill.
const MAX_ACTIVE_BYTES_PER_LICENSE = 3 * 1024 * 1024 * 1024;
const MAX_DEVICES_PER_LICENSE = 3;              // matches the license: "up to 3 Macs"
const MAX_NAME_CHARS = 120;
const MAX_DEVICE_NAME_CHARS = 60;
const PENDING_GRACE_SECONDS = 60 * 60;          // abandoned uploads
const TOMBSTONE_SECONDS = 7 * 24 * 60 * 60;     // keep the row so /f/ can say "expired"
const LICENSE_RECHECK_SECONDS = 7 * 24 * 60 * 60;
const CLEANUP_BATCH = 500;

// Abuse reporting.
const REPORT_REASONS = ["malware", "phishing", "copyright", "illegal", "privacy", "other"];
const REPORT_DEDUPE_SECONDS = 24 * 60 * 60;   // same file + same reason inside a day
const MAX_REPORTS_PER_FILE_PER_DAY = 5;
const MAX_DETAILS_CHARS = 1000;
const MAX_REPORTER_NAME_CHARS = 100;
const MAX_REPORTER_EMAIL_CHARS = 200;
const REPORT_CONTACT_SECONDS = 30 * 24 * 60 * 60;    // then name/email are cleared
const REPORT_RETENTION_SECONDS = 180 * 24 * 60 * 60; // then the row goes
const REPORT_RETRY_BATCH = 10;

/// The only origins the report form may be served from. The form is the sole browser
/// caller of this Worker; everything else is the Mac app, which sends no Origin.
const REPORT_ORIGINS = ["https://getmushroom.app", "https://www.getmushroom.app"];
const REPORT_ACTION = "report";
const ABUSE_FROM = "abuse@getmushroom.app";   // send only, there is no such mailbox
const ABUSE_TO = "hello@getmushroom.app";

/// Same reply every well-formed submission gets, whether the link was real, already
/// expired, a duplicate, or never existed. Confirming that a token resolves would turn
/// this endpoint into an oracle for guessing share links.
const REPORT_ACCEPTED = "Thank you. If this is an active Mushroom link, it will be reviewed.";

// Known file signatures. This USED to be an allowlist as well; it is not any more, and
// any type may be shared. What made that safe was never this list: the download path
// serves every file as octet-stream + attachment + nosniff + `default-src 'none'; sandbox`
// unconditionally, so attacker-chosen HTML or SVG cannot execute on the domain either way.
// What the allowlist really bought was bounded malware-hosting exposure, and the takedown
// flow it was waiting on (abuse reports, admin delete, license block) now exists.
//
// The signatures stay because they are free and still true: checked against the real first
// bytes during upload, so a renamed .exe DECLARING image/png is still refused. A type with
// no entry here is simply not checked. Every entry is a list of {at, bytes} clauses that
// must ALL match. `null` means the format has no signature worth checking.
const TYPE_SIGNATURES = {
  "image/jpeg": [{ at: 0, bytes: [0xff, 0xd8, 0xff] }],
  "image/png": [{ at: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] }],
  // "RIFF" alone also matches .wav and .avi, so the "WEBP" tag at byte 8 is what
  // actually decides it.
  "image/webp": [{ at: 0, bytes: [0x52, 0x49, 0x46, 0x46] },
                 { at: 8, bytes: [0x57, 0x45, 0x42, 0x50] }],
  "image/heic": [{ at: 4, bytes: [0x66, 0x74, 0x79, 0x70] }],   // "ftyp" box
  "image/heif": [{ at: 4, bytes: [0x66, 0x74, 0x79, 0x70] }],
  "application/pdf": [{ at: 0, bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }],   // "%PDF-"
  "text/plain": null,
  "text/csv": null,
};

const SNIFF_BYTES = 16;

/// A well-formed `type/subtype`, RFC 6838 restricted-name characters, each half capped so
/// the whole string cannot exceed 127. Replaces the allowlist as the validator of this
/// field: see the call site in createFile.
const TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/;

// ---------------------------------------------------------------- helpers

function reply(status, body) {
  return new Response(JSON.stringify({ ok: status < 400, ...body }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function fail(status, code, extra) {
  return reply(status, { code, ...extra });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The app trims and uppercases before hashing too (Kit: FileShare). Keep them in step or
// the same key produces two different identities.
const licenseHash = (key) => sha256Hex(key.trim().toUpperCase());

function shareToken() {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const now = () => Math.floor(Date.now() / 1000);

/// Mirror of FileShare.sanitize in the Kit. The client sanitizes so the user sees the
/// name it will really have; this exists because the client is not to be trusted.
function sanitizeName(raw) {
  let name = String(raw ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, "")   // bidi overrides: "exe.gnp" tricks
    .replace(/[\/\\:]/g, "-")
    .replace(/\s+/g, " ")
    .replace(/^\.+/, "")
    .trim();
  if (name.length > MAX_NAME_CHARS) {
    const dot = name.lastIndexOf(".");
    // Keep the extension: truncating "report.pdf" to "repo" loses what it IS.
    const ext = dot > 0 && name.length - dot <= 12 ? name.slice(dot) : "";
    name = name.slice(0, MAX_NAME_CHARS - ext.length) + ext;
  }
  return name || "file";
}

/// RFC 6266: an ASCII fallback for old clients plus the real UTF-8 name. Quotes and
/// backslashes are stripped from the fallback so the header cannot be broken out of.
function attachmentHeader(name) {
  const safe = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "");
  return `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/// Own-property lookups only. A plain `TYPE_SIGNATURES[ct]` inherits from Object.prototype,
/// so a declared type of "constructor" or "valueOf" used to return a FUNCTION here and blow
/// up on `.every`. Harmless while the allowlist gated which types could reach this; now
/// that any type can, it would be an uncaught 500 on demand.
function signaturesFor(contentType) {
  return Object.hasOwn(TYPE_SIGNATURES, contentType) ? TYPE_SIGNATURES[contentType] : undefined;
}

function matchesMagic(head, contentType) {
  const clauses = signaturesFor(contentType);
  if (clauses === null || clauses === undefined) return true;   // nothing to check
  return clauses.every(({ at, bytes }) =>
    bytes.every((byte, i) => head[at + i] === byte)
  );
}

/// Read the first bytes back OUT of R2 and check them against the declared type.
///
/// This happens after the write, not during it, and that is not laziness. R2 will only
/// accept a FIXED-LENGTH stream, and `request.body` stops being one the moment it is
/// piped through a TransformStream, so sniffing on the way in costs either the streaming
/// (buffer the whole file in a 128 MB worker) or the check. Reading 16 bytes back is a
/// cheap range GET, and a file that fails is deleted before its link ever works.
async function storedBytesMatchType(env, key, contentType) {
  if (!signaturesFor(contentType)) return true;      // unknown or signature-less type
  const head = await env.FILES.get(key, { range: { offset: 0, length: SNIFF_BYTES } });
  if (!head) return false;
  return matchesMagic(new Uint8Array(await head.arrayBuffer()), contentType);
}

// ---------------------------------------------------------------- Gumroad

/// Returns `{ status, saleID }` where status is
/// "active" | "revoked" | "invalid" | "unreachable".
///
/// `saleID` is set only for an active licence. It is a pointer to a purchase, never the
/// licence key, and it is the only thing that lets an abuse report be traced back to a
/// sale: we store sha256(key), and a hash cannot be reversed.
///
/// increment_uses_count is FALSE on purpose. The app burns a seat once, at activation
/// (LicenseManager.activate), and the license allows three Macs. Counting again here
/// would spend the user's seats on our own bookkeeping.
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
  // 429 is Gumroad rate limiting us, not the user's licence being bad. Treating it as
  // "invalid" would lock out real buyers whenever we get busy.
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

// ---------------------------------------------------------------- throttle

const ACTIVATIONS_PER_MINUTE_PER_IP = 30;

/// True if this request is within the limit, false if it should be refused.
///
/// One statement, using RETURNING, so it costs a single D1 round trip. Deliberately NOT
/// Cloudflare's Rate Limiting binding: that was tried first and measured not to enforce for
/// this account (139 requests from one IP in a minute against a 30/60s limit, every one
/// answered success), and a limiter that always says yes is worse than none because the
/// endpoint reads as protected. See migrations/0004_throttle.sql.
///
/// FAILS OPEN on a D1 error, matching §14 and `requireLicense`: this bounds an abuse cost,
/// it is not an authorization decision, and refusing every activation because D1 blipped
/// would be the worse failure.
async function throttle(env, name, key, limit, windowSeconds) {
  const window = Math.floor(now() / windowSeconds) * windowSeconds;
  try {
    const row = await env.DB.prepare(
      "INSERT INTO throttle (bucket_key, count, expires_at) VALUES (?, 1, ?) " +
      "ON CONFLICT(bucket_key) DO UPDATE SET count = throttle.count + 1 " +
      "RETURNING count"
    ).bind(`${name}:${key}:${window}`, window + windowSeconds * 2).first();
    return (row?.count ?? 1) <= limit;
  } catch (error) {
    console.error("throttle failed open", error?.message ?? error);
    return true;
  }
}

// ---------------------------------------------------------------- auth

async function authenticate(request, env, ctx) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const tokenHash = await sha256Hex(header.slice(7).trim());

  // One round trip, not two. Every /v1/ request pays this, so the second sequential D1
  // query was pure latency on the upload path. An INNER JOIN is the same answer as the two
  // lookups it replaces: no row when the device is missing or revoked, and no row when it
  // has no licence, both of which were already `return null`.
  const row = await env.DB.prepare(
    "SELECT d.id AS device_id, d.license_hash, l.status " +
    "FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
    "WHERE d.token_hash = ? AND d.revoked_at IS NULL"
  ).bind(tokenHash).first();
  if (!row) return null;

  ctx.waitUntil(
    env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").bind(now(), row.device_id).run()
  );
  // Same shape the two queries returned, minus `checked_at`, which no caller reads.
  return {
    device: { id: row.device_id, license_hash: row.license_hash },
    license: { license_hash: row.license_hash, status: row.status },
  };
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
    // DRM until piracy is a real problem. The quotas bound the damage either way.
  } else {
    const { status: verdict, saleID: gumroadSaleID } = await verifyLicense(key);
    // FAIL CLOSED here, and only here. The app's own licence gate fails OPEN by design
    // (CLAUDE.md §12: never lock a paying user out for being offline) and an already
    // issued device token keeps working while Gumroad is down, see requireLicense below.
    // But handing out a NEW token without checking would make "Gumroad is unreachable"
    // a free pass into the bucket for anyone.
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
        // 'active', because the CASE below only ever protected 'blocked'. Neither worker has
        // an unblock endpoint, so that was the only way a block ever cleared, by accident.
        "INSERT INTO licenses (license_hash, status, checked_at, created_at) VALUES (?, 'revoked', ?, ?) " +
        "ON CONFLICT(license_hash) DO UPDATE SET " +
        "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'revoked' END, " +
        "checked_at = excluded.checked_at"
      ).bind(hash, stamp, stamp).run();
      return fail(403, "revoked");
    }
  }

  // COALESCE, not overwrite: a later verify that happens to omit the sale id must not
  // erase one we already recorded.
  await env.DB.prepare(
    "INSERT INTO licenses (license_hash, status, checked_at, created_at, gumroad_sale_id, source) " +
    "VALUES (?, 'active', ?, ?, ?, ?) " +
    "ON CONFLICT(license_hash) DO UPDATE SET " +
    "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'active' END, " +
    "checked_at = excluded.checked_at, " +
    "gumroad_sale_id = COALESCE(excluded.gumroad_sale_id, licenses.gumroad_sale_id)"
  ).bind(hash, stamp, stamp, saleID, source).run();

  // An admin block must not be undone by the next activation. It used to be, because this
  // upsert wrote 'active' unconditionally: the app re-activated and sharing resumed with a
  // fresh token. Survivable for a Gumroad key, where revoking at Gumroad makes
  // `verifyLicense` answer revoked on the next call; for an App Store hash there is no such
  // lever, because this Worker never re-asks Apple.
  const state = await env.DB.prepare("SELECT status FROM licenses WHERE license_hash = ?")
    .bind(hash).first();
  if (state?.status !== "active") return fail(403, "revoked");

  // Past the cap, evict the least-recently-seen Mac rather than refusing. A 409 would
  // strand someone who reinstalled twice, and the evicted Mac silently re-activates the
  // next time it sees a 401.
  const live = await env.DB.prepare(
    "SELECT id FROM devices WHERE license_hash = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC"
  ).bind(hash).all();
  const doomed = (live.results ?? []).slice(MAX_DEVICES_PER_LICENSE - 1);
  for (const device of doomed) {
    await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?").bind(stamp, device.id).run();
  }

  const token = shareToken() + shareToken();       // 32 bytes of entropy for a bearer token
  const id = crypto.randomUUID();
  const name = typeof body.device_name === "string"
    ? body.device_name.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, MAX_DEVICE_NAME_CHARS)
    : null;

  await env.DB.prepare(
    "INSERT INTO devices (id, license_hash, token_hash, name, created_at, last_seen_at) VALUES (?,?,?,?,?,?)"
  ).bind(id, hash, await sha256Hex(token), name, stamp, stamp).run();

  // The limits travel with the token so the app renders "up to 95 MB" from the server's
  // answer. Changing a limit then needs no app release.
  return reply(201, { device_id: id, token, limits: limits() });
}

const limits = () => ({
  // Which wire contract this server speaks. Same rule as mushroom-messaging: emitted now and
  // read by nobody yet, because absent means "older than 1" and the field therefore has to
  // exist before there is a 2 or it can never date a pinned customer server. Bump only for a
  // change an older app cannot survive; additive ones already degrade to unchanged.
  protocol: 1,
  max_file_bytes: MAX_FILE_BYTES,
  max_files: MAX_ACTIVE_FILES_PER_LICENSE,
  max_total_bytes: MAX_ACTIVE_BYTES_PER_LICENSE,
  ttl_seconds: TTL_SECONDS,
  // No allowed_types any more: every type is allowed, so there is nothing to enumerate.
  // Apps from before 1.26 read its absence as "the server did not say" and keep their own
  // hardcoded list, which is exactly the behaviour they had, so they degrade to unchanged.
  // The app holds the licence key and we do not, so re-verification is its job. This is
  // the server telling it how often: re-activate once a token is older than this and a
  // refunded purchase stops working. See requireLicense.
  reverify_after_seconds: LICENSE_RECHECK_SECONDS,
});

/// Revocation check for an already-authenticated device. Unlike activation this fails
/// OPEN: the device proved itself once, and Gumroad being down must not stop someone
/// sharing a file. Only an explicit refund/dispute/chargeback closes the door.
///
/// There is deliberately NO periodic re-verify here. We store sha256(key), never the key,
/// so the Worker physically cannot re-ask Gumroad on its own; pretending to (by stamping
/// `checked_at` forward) would be a check that checks nothing. Re-verification is the
/// app's job, which does hold the key: it re-activates when its token is older than
/// LICENSE_RECHECK_SECONDS, and activation is a real Gumroad call that flips `status` to
/// revoked for a refunded purchase. A pirate who never re-activates keeps a working
/// token, which is the same posture the app's own licence gate already takes (spec §14:
/// keep honest people honest, do not build DRM). The quotas bound the damage.
///
/// Called by EVERY route that reads or writes a licence's files: createFile, uploadContent,
/// listFiles and deleteFile. It used to guard createFile alone, which made a block partial in
/// a way that read as total: the blocked Mac's still valid token kept enumerating every file
/// through GET /v1/files and deleting rows through DELETE /v1/files/<id>. That matters more
/// now that 'blocked' is the ONLY revocation lever the App Store channel has.
///
/// `releaseDevice` is deliberately NOT guarded. Releasing your own Mac is cleanup, not access,
/// and a blocked user who wants to unregister a machine should be able to.
function requireLicense(auth) {
  // 'blocked' is our own abuse decision, 'revoked' is Gumroad's. Both close the door, and
  // an unknown or stale status still works, which is the fail-open posture of §14.
  const status = auth.license.status;
  return status === "revoked" || status === "blocked" ? fail(403, "revoked") : null;
}

async function createFile(request, env, auth) {
  const blocked = requireLicense(auth);
  if (blocked) return blocked;

  let body;
  try {
    body = await request.json();
  } catch {
    return fail(400, "bad_request");
  }

  const size = Number(body.size);
  if (!Number.isInteger(size) || size <= 0) return fail(400, "bad_request");
  if (size > MAX_FILE_BYTES) return fail(413, "too_big", { max_file_bytes: MAX_FILE_BYTES });

  // Any type is allowed, but the string itself still has to be a type. The allowlist was
  // the only thing validating this field, and it is not decoration: content_type is
  // interpolated into the plain-text abuse-report email, where an interior newline (which
  // .trim() does not touch) would forge lines in it. Shape and length, per RFC 6838.
  const contentType = String(body.content_type ?? "").toLowerCase().split(";")[0].trim();
  if (!TYPE_RE.test(contentType)) return fail(400, "bad_type");

  const used = await env.DB.prepare(
    "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM files " +
    "WHERE license_hash = ? AND state IN ('pending','ready') AND expires_at > ?"
  ).bind(auth.license.license_hash, now()).first();

  if (used.n >= MAX_ACTIVE_FILES_PER_LICENSE) {
    return fail(409, "quota_files", { max_files: MAX_ACTIVE_FILES_PER_LICENSE });
  }
  if (used.bytes + size > MAX_ACTIVE_BYTES_PER_LICENSE) {
    return fail(409, "quota_bytes", { max_total_bytes: MAX_ACTIVE_BYTES_PER_LICENSE });
  }

  const id = crypto.randomUUID();
  const token = shareToken();
  const stamp = now();
  const expires = stamp + TTL_SECONDS;

  await env.DB.prepare(
    "INSERT INTO files (id, license_hash, device_id, token, name, size, content_type, state, created_at, expires_at) " +
    "VALUES (?,?,?,?,?,?,?,'pending',?,?)"
  ).bind(id, auth.license.license_hash, auth.device.id, token,
         sanitizeName(body.name), size, contentType, stamp, expires).run();

  return reply(201, {
    id,
    token,
    url: `${env.PUBLIC_BASE}/f/${token}`,
    upload_path: `/v1/files/${id}/content`,
    expires_at: expires,
  });
}

async function uploadContent(request, env, auth, id) {
  const blocked = requireLicense(auth);
  if (blocked) return blocked;

  // Scoped by licence, and a miss is 404 rather than 403: answering 403 would confirm
  // that somebody else's id exists.
  const row = await env.DB.prepare(
    "SELECT id, token, name, size, content_type, state, expires_at FROM files WHERE id = ? AND license_hash = ?"
  ).bind(id, auth.license.license_hash).first();
  if (!row) return fail(404, "not_found");
  if (row.state !== "pending") return fail(409, "already_uploaded");
  if (row.expires_at <= now()) return fail(410, "gone");

  // Required so the body is a fixed-length stream R2 can consume without buffering.
  // Workers cap memory at 128 MB; a chunked 50 MiB upload would be read into it.
  const declared = request.headers.get("content-length");
  if (declared === null) return fail(411, "length_required");
  const length = Number(declared);
  if (!Number.isInteger(length) || length <= 0) return fail(400, "bad_request");
  if (length > MAX_FILE_BYTES) return fail(413, "too_big", { max_file_bytes: MAX_FILE_BYTES });
  if (length !== row.size) return fail(400, "size_mismatch");
  if (!request.body) return fail(400, "bad_request");

  const key = `f/${id}`;
  let object;
  try {
    // request.body goes straight through, unwrapped: R2 only accepts a fixed-length
    // stream, and wrapping it in any way loses that.
    object = await env.FILES.put(key, request.body, {
      httpMetadata: {
        // Recorded for our own bookkeeping only. The download path always serves
        // octet-stream, whatever this says.
        contentType: "application/octet-stream",
        contentDisposition: attachmentHeader(row.name ?? "file"),
      },
    });
  } catch (error) {
    await env.FILES.delete(key).catch(() => {});
    // The message is R2's own and carries the object key at worst, never a filename.
    console.log(`upload failed id=${id} err=${error?.message ?? "unknown"}`);
    // The row stays pending, so retrying this exact PUT is free.
    return fail(500, "upload_failed");
  }

  // The declared type was checked at create time; this is where the actual bytes are
  // checked. A renamed .exe claiming to be a PNG dies here, before its link works.
  if (!(await storedBytesMatchType(env, key, row.content_type))) {
    await env.FILES.delete(key).catch(() => {});
    return fail(415, "type_mismatch");
  }

  await env.DB.prepare(
    "UPDATE files SET state = 'ready', uploaded_at = ?, size = ? WHERE id = ?"
  ).bind(now(), object.size, id).run();

  return reply(200, { url: `${env.PUBLIC_BASE}/f/${row.token}`, expires_at: row.expires_at });
}

function gonePage(message) {
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>Mushroom</title><style>body{font:16px/1.6 -apple-system,system-ui,sans-serif;` +
    `max-width:32rem;margin:20vh auto;padding:0 1.5rem;text-align:center;color:#3d3a37}` +
    `a{color:#c2410c}</style><p style="font-size:3rem">🍄</p><p>${message}</p>` +
    `<p><a href="https://www.getmushroom.app">getmushroom.app</a></p>`,
    { status: 410, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
  );
}

async function download(request, env, ctx, token) {
  const row = await env.DB.prepare(
    "SELECT id, name, size, state, expires_at FROM files WHERE token = ?"
  ).bind(token).first();

  if (!row) return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
  if (row.state === "deleted") return removedPage();
  if (row.state === "expired" || row.expires_at <= now()) return expiredPage();
  // Never finished uploading: indistinguishable from a bad link, and should be.
  if (row.state !== "ready") {
    return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
  }

  const range = request.headers.get("range");
  let object;
  try {
    object = await env.FILES.get(`f/${row.id}`, range ? { range: request.headers } : undefined);
  } catch {
    // R2 throws on an unsatisfiable range rather than returning null. Answer the way the
    // spec says to instead of turning a bad header into a 500.
    return new Response("Range not satisfiable", {
      status: 416,
      headers: { "content-range": `bytes */${row.size}`, "cache-control": "no-store" },
    });
  }
  if (!object) return expiredPage();   // lifecycle rule got there first

  const headers = new Headers();
  // ALWAYS octet-stream, never the declared type. Serving attacker-chosen HTML or SVG
  // from a subdomain of getmushroom.app would be stored XSS against the marketing site.
  headers.set("content-type", "application/octet-stream");
  headers.set("content-disposition", attachmentHeader(row.name ?? "file"));
  headers.set("x-content-type-options", "nosniff");
  headers.set("content-security-policy", "default-src 'none'; sandbox");
  headers.set("cache-control", "private, no-store");
  headers.set("referrer-policy", "no-referrer");
  headers.set("accept-ranges", "bytes");

  // Gated on the REQUEST carrying a Range, not just on object.range existing: R2 fills
  // that in for a plain get too, which turned every ordinary download into a 206.
  if (range && object.range && "offset" in object.range) {
    const start = object.range.offset ?? 0;
    const end = start + (object.range.length ?? object.size) - 1;
    headers.set("content-range", `bytes ${start}-${end}/${row.size}`);
    headers.set("content-length", String(object.range.length ?? object.size));
    return new Response(request.method === "HEAD" ? null : object.body, { status: 206, headers });
  }

  headers.set("content-length", String(object.size));
  return new Response(request.method === "HEAD" ? null : object.body, { status: 200, headers });
}

const removedPage = () => gonePage("This file was removed.");
const expiredPage = () => gonePage("This link has expired. Mushroom links last 24 hours.");

async function listFiles(env, auth) {
  const blocked = requireLicense(auth);
  if (blocked) return blocked;

  const rows = await env.DB.prepare(
    "SELECT id, name, size, content_type, token, created_at, expires_at, device_id FROM files " +
    "WHERE license_hash = ? AND state = 'ready' AND expires_at > ? ORDER BY created_at DESC LIMIT ?"
  ).bind(auth.license.license_hash, now(), MAX_ACTIVE_FILES_PER_LICENSE).all();

  const files = (rows.results ?? []).map((row) => ({
    id: row.id,
    name: row.name,
    size: row.size,
    content_type: row.content_type,
    url: `${env.PUBLIC_BASE}/f/${row.token}`,
    created_at: row.created_at,
    expires_at: row.expires_at,
    mine: row.device_id === auth.device.id,
  }));
  return reply(200, { files, limits: limits() });
}

async function deleteFile(env, auth, id) {
  const blocked = requireLicense(auth);
  if (blocked) return blocked;

  const row = await env.DB.prepare(
    "SELECT id, state FROM files WHERE id = ? AND license_hash = ?"
  ).bind(id, auth.license.license_hash).first();
  if (!row) return fail(404, "not_found");
  if (row.state === "deleted") return reply(200, {});   // idempotent

  // R2 first. A row claiming "deleted" while the bytes are still fetchable is the bad
  // direction to fail in.
  await env.FILES.delete(`f/${id}`);
  await env.DB.prepare("UPDATE files SET state = 'deleted', deleted_at = ?, name = NULL WHERE id = ?")
    .bind(now(), id).run();
  return reply(200, {});
}

async function releaseDevice(env, auth) {
  await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?").bind(now(), auth.device.id).run();
  return reply(200, {});
}

// ---------------------------------------------------------------- abuse reports

const escapeHTML = (text) => String(text ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));

/// Reports come from a browser on the marketing site, which is the only browser caller
/// this Worker has. Every response on this route carries the header, including failures,
/// or the page cannot read its own error.
function reportCORS(origin) {
  const allowed = REPORT_ORIGINS.includes(origin) ? origin : REPORT_ORIGINS[1];
  return { "access-control-allow-origin": allowed, "vary": "Origin" };
}

function reportReply(status, body, origin) {
  return new Response(JSON.stringify({ ok: status < 400, ...body }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...reportCORS(origin) },
  });
}

/// Turnstile, verified server side.
///
/// Unlike the site Worker this checks `hostname` and `action` as well as `success`: a
/// token minted by the same sitekey on some other page, or for the tools form, must not
/// be spendable here. Both fields are only checked when Cloudflare actually returns them,
/// which is safe because they come from Cloudflare and not from the submitter; the
/// documented test secrets omit them.
async function turnstileOK(token, ip, env) {
  if (!token) return false;
  let outcome;
  try {
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET_KEY ?? "",
        response: token,
        remoteip: ip ?? "",
      }),
    });
    outcome = await verify.json();
  } catch {
    return false;
  }
  if (!outcome?.success) return false;

  // Cloudflare's documented testing secrets answer for a fixed dummy hostname
  // ("example.com") and no action, and it flags them itself. Skipping the two checks in
  // that one case is what lets the local suite exercise the whole path; it cannot soften
  // production, because a real secret never produces this flag, and a testing secret
  // accepts literally any token anyway so these checks would be the least of it.
  if (outcome.metadata?.result_with_testing_key === true) return true;

  if (outcome.hostname && !REPORT_ORIGINS.includes(`https://${outcome.hostname}`)) return false;
  if (outcome.action && outcome.action !== REPORT_ACTION) return false;
  return true;
}

async function abuseReport(request, env, ctx) {
  const origin = request.headers.get("origin") ?? "";
  if (!REPORT_ORIGINS.includes(origin)) return reportReply(403, { code: "bad_origin" }, origin);

  let form;
  try {
    form = await request.formData();
  } catch {
    return reportReply(400, { code: "bad_request" }, origin);
  }

  // Honeypot: look successful, store nothing. Same trick as the tools form.
  if (form.get("website")) return reportReply(200, { message: REPORT_ACCEPTED }, origin);

  if (!(await turnstileOK(form.get("cf-turnstile-response"), request.headers.get("CF-Connecting-IP"), env))) {
    return reportReply(403, { code: "bot_check", message: "Bot check failed, please reload and try again." }, origin);
  }

  const shareURL = String(form.get("share_url") ?? "").trim();
  const match = shareURL.match(/^https:\/\/files\.getmushroom\.app\/f\/([A-Za-z0-9_-]{22})$/);
  if (!match) {
    return reportReply(400, { code: "bad_url", message: "That does not look like a Mushroom share link." }, origin);
  }

  const reason = String(form.get("reason") ?? "");
  if (!REPORT_REASONS.includes(reason)) return reportReply(400, { code: "bad_reason" }, origin);

  const name = String(form.get("name") ?? "").trim().slice(0, MAX_REPORTER_NAME_CHARS);
  const email = String(form.get("email") ?? "").trim().slice(0, MAX_REPORTER_EMAIL_CHARS);
  const details = String(form.get("details") ?? "").trim().slice(0, MAX_DETAILS_CHARS);
  if (!name || !email.includes("@")) {
    return reportReply(400, { code: "bad_contact", message: "Please give a name and an email we can reply to." }, origin);
  }

  // Everything from here answers identically whether or not the link resolves. A
  // different status, body, or timing-visible branch would make this an oracle for
  // guessing share tokens.
  const accepted = reportReply(200, { message: REPORT_ACCEPTED }, origin);

  const file = await env.DB.prepare(
    "SELECT id, name, size, content_type, state, device_id, license_hash, created_at, expires_at " +
    "FROM files WHERE token = ?"
  ).bind(match[1]).first();
  if (!file) return accepted;

  const stamp = now();
  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS total, SUM(CASE WHEN reason = ? THEN 1 ELSE 0 END) AS same " +
    "FROM abuse_reports WHERE file_id = ? AND created_at > ?"
  ).bind(reason, file.id, stamp - REPORT_DEDUPE_SECONDS).first();

  // A second report of the same thing, or a pile-on, is not new information.
  if ((recent?.same ?? 0) > 0) return accepted;
  if ((recent?.total ?? 0) >= MAX_REPORTS_PER_FILE_PER_DAY) return accepted;

  const id = crypto.randomUUID();
  const license = await env.DB.prepare(
    "SELECT gumroad_sale_id FROM licenses WHERE license_hash = ?"
  ).bind(file.license_hash).first();

  const sent = await notifyOwner(env, { id, reason, details, name, email, shareURL, file, license, stamp });

  await env.DB.prepare(
    "INSERT INTO abuse_reports (id, file_id, reason, details, reporter_name, reporter_email, notified, created_at) " +
    "VALUES (?,?,?,?,?,?,?,?)"
  ).bind(id, file.id, reason, details || null, name, email, sent ? "sent" : "failed", stamp).run();

  return accepted;
}

/// The two commands that act on a report. Deliberately POST and bearer-authenticated, so
/// a mail client or link scanner following anything in this email cannot take an action.
function adminCommands(env, file) {
  const base = env.PUBLIC_BASE;
  return [
    `# Delete just this file`,
    `curl -X POST ${base}/admin/files/delete \\`,
    `  -H "authorization: Bearer $MUSHROOM_ADMIN_TOKEN" \\`,
    `  -H "content-type: application/json" \\`,
    `  -d '{"file_id":"${file.id}"}'`,
    ``,
    `# Block this licence from sharing, revoke its devices, delete everything it has live`,
    `curl -X POST ${base}/admin/licenses/block \\`,
    `  -H "authorization: Bearer $MUSHROOM_ADMIN_TOKEN" \\`,
    `  -H "content-type: application/json" \\`,
    `  -d '{"license_hash":"${file.license_hash}"}'`,
  ].join("\n");
}

/// Best effort. The row is written either way and the cron retries a failure, which is
/// the same ordering the tools form uses: durable first, notify second.
async function notifyOwner(env, r) {
  const when = new Date(r.stamp * 1000).toISOString();
  const expires = new Date(r.file.expires_at * 1000).toISOString();
  const shortFile = r.file.id.slice(0, 8);

  const lines = [
    `Reason:    ${r.reason}`,
    `Reported:  ${when}`,
    `Reporter:  ${r.name} <${r.email}>`,
    ``,
    `Details:`,
    r.details || "(none given)",
    ``,
    `Reported link (do not click, shown as text):`,
    `  ${r.shareURL}`,
    ``,
    `File:      ${r.file.name ?? "(name cleared)"}`,
    `Type:      ${r.file.content_type}`,
    `Size:      ${r.file.size} bytes`,
    `State:     ${r.file.state}`,
    `Uploaded:  ${new Date(r.file.created_at * 1000).toISOString()}`,
    `Expires:   ${expires}`,
    `File id:   ${r.file.id}`,
    `Device:    ${r.file.device_id}`,
    `Licence:   ${r.file.license_hash.slice(0, 16)}...`,
    `Gumroad:   ${r.license?.gumroad_sale_id ?? "(not recorded)"}`,
    `Report id: ${r.id}`,
    ``,
    adminCommands(env, r.file),
  ];
  const text = lines.join("\n");

  try {
    await env.EMAIL.send({
      to: ABUSE_TO,
      from: { email: ABUSE_FROM, name: "Mushroom reports" },
      // The reason is a fixed enum and the id is a uuid, so neither can carry a newline
      // into the header. The filename never appears here, for exactly that reason.
      subject: `[Mushroom report] ${r.reason}, file ${shortFile}`,
      text,
      html: `<pre style="font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap">${escapeHTML(text)}</pre>`,
    });
    return true;
  } catch (error) {
    console.log(`report email failed id=${r.id} err=${error?.message ?? "unknown"}`);
    return false;
  }
}

// ---------------------------------------------------------------- owner actions

/// Constant-time-ish bearer check. The token is a shared secret, not a per-user one, so
/// there is nothing to enumerate; the length guard just avoids leaking it via timing.
function adminOK(request, env) {
  const header = request.headers.get("authorization") ?? "";
  const given = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const want = env.ADMIN_TOKEN ?? "";
  if (!want || given.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

/// Delete the R2 object first, then the row. A row that says deleted while the bytes are
/// still fetchable is the bad direction to fail in.
async function purgeFile(env, id) {
  await env.FILES.delete(`f/${id}`).catch(() => {});
  await env.DB.prepare(
    "UPDATE files SET state = 'deleted', deleted_at = ?, name = NULL WHERE id = ?"
  ).bind(now(), id).run();
}

async function adminDeleteFile(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail(400, "bad_request"); }
  const id = String(body.file_id ?? "");
  if (!id) return fail(400, "bad_request");

  const row = await env.DB.prepare("SELECT id FROM files WHERE id = ?").bind(id).first();
  if (!row) return fail(404, "not_found");
  await purgeFile(env, id);
  console.log(`admin deleted file id=${id}`);
  return reply(200, { file_id: id });
}

/// Blocks FILE SHARING for this licence, and nothing else. The customer's app keeps
/// working: disabling the actual purchase is a separate, deliberate act in Gumroad using
/// the sale id in the report email.
async function adminBlockLicense(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail(400, "bad_request"); }
  const hash = String(body.license_hash ?? "");
  if (!hash) return fail(400, "bad_request");

  const row = await env.DB.prepare("SELECT license_hash FROM licenses WHERE license_hash = ?").bind(hash).first();
  if (!row) return fail(404, "not_found");

  // 'blocked', not 'revoked': a Gumroad revocation can legitimately clear (a reversed
  // refund re-verifies as active on the next activate), and the upsert in activateDevice
  // lets it. An admin block must survive that, and for an App Store hash it is the ONLY
  // lever, because this Worker never re-asks Apple. Same split mushroom-messaging uses.
  await env.DB.prepare("UPDATE licenses SET status = 'blocked' WHERE license_hash = ?").bind(hash).run();
  await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE license_hash = ? AND revoked_at IS NULL")
    .bind(now(), hash).run();

  const live = await env.DB.prepare(
    "SELECT id FROM files WHERE license_hash = ? AND state IN ('pending','ready')"
  ).bind(hash).all();
  for (const file of live.results ?? []) await purgeFile(env, file.id);

  console.log(`admin blocked license files=${(live.results ?? []).length}`);
  return reply(200, { blocked: true, files_deleted: (live.results ?? []).length });
}

// ---------------------------------------------------------------- cron

async function sweep(env) {
  const stamp = now();

  const doomed = await env.DB.prepare(
    "SELECT id FROM files WHERE (state = 'ready' AND expires_at <= ?) " +
    "OR (state = 'pending' AND created_at <= ?) LIMIT ?"
  ).bind(stamp, stamp - PENDING_GRACE_SECONDS, CLEANUP_BATCH).all();

  const ids = (doomed.results ?? []).map((row) => row.id);
  if (ids.length) {
    await env.FILES.delete(ids.map((id) => `f/${id}`));
    const holes = ids.map(() => "?").join(",");
    // NULL the name at the same time: the tombstone only has to answer "expired", it
    // does not need to remember what was shared.
    await env.DB.prepare(
      `UPDATE files SET state = 'expired', name = NULL WHERE id IN (${holes})`
    ).bind(...ids).run();
  }

  await env.DB.prepare(
    "DELETE FROM files WHERE state IN ('expired','deleted') AND expires_at <= ?"
  ).bind(stamp - TOMBSTONE_SECONDS).run();

  // Spent throttle windows. Nothing reads them once they expire, and without this the table
  // grows by one row per distinct IP per window forever.
  await env.DB.prepare("DELETE FROM throttle WHERE expires_at <= ?").bind(stamp).run();

  await env.DB.prepare(
    "DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at <= ?"
  ).bind(stamp - TOMBSTONE_SECONDS).run();

  // Reports whose email never went out. The row was always durable; this is the retry.
  const unsent = await env.DB.prepare(
    "SELECT id, file_id, reason, details, reporter_name, reporter_email, created_at " +
    "FROM abuse_reports WHERE notified = 'failed' ORDER BY created_at LIMIT ?"
  ).bind(REPORT_RETRY_BATCH).all();

  for (const report of unsent.results ?? []) {
    const file = await env.DB.prepare(
      "SELECT id, name, size, content_type, state, device_id, license_hash, created_at, expires_at " +
      "FROM files WHERE id = ?"
    ).bind(report.file_id).first();
    if (!file) continue;
    const license = await env.DB.prepare(
      "SELECT gumroad_sale_id FROM licenses WHERE license_hash = ?"
    ).bind(file.license_hash).first();
    const sent = await notifyOwner(env, {
      id: report.id, reason: report.reason, details: report.details,
      name: report.reporter_name, email: report.reporter_email,
      shareURL: "(link no longer shown)", file, license, stamp: report.created_at,
    });
    if (sent) {
      await env.DB.prepare("UPDATE abuse_reports SET notified = 'sent' WHERE id = ?").bind(report.id).run();
    }
  }

  // The reporter volunteered a name and an email so we could follow up. Thirty days is
  // long enough to have done that, and holding it longer serves nobody.
  await env.DB.prepare(
    "UPDATE abuse_reports SET reporter_name = NULL, reporter_email = NULL " +
    "WHERE created_at <= ? AND reporter_email IS NOT NULL"
  ).bind(stamp - REPORT_CONTACT_SECONDS).run();

  await env.DB.prepare(
    "DELETE FROM abuse_reports WHERE created_at <= ?"
  ).bind(stamp - REPORT_RETENTION_SECONDS).run();

  console.log(`sweep removed=${ids.length} retried=${(unsent.results ?? []).length}`);
}

// ---------------------------------------------------------------- entry

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/" ) {
      return Response.redirect("https://www.getmushroom.app", 302);
    }

    // Public download. No auth, that is the whole feature.
    if (path.startsWith("/f/") && (method === "GET" || method === "HEAD")) {
      const token = path.slice(3);
      if (!token || token.includes("/")) {
        return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
      }
      return download(request, env, ctx, token);
    }

    if (path === "/v1/devices/activate" && method === "POST") {
      // BEFORE activateDevice, because activateDevice is what a flood is spending: the
      // App Store branch walks an attacker-supplied certificate chain twice per call
      // (PRODUCTION then SANDBOX) on a route with no bearer token in front of it.
      // Same posture as mushroom-messaging, which throttles this endpoint via its DO.
      const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
      if (!(await throttle(env, "activate", ip, ACTIVATIONS_PER_MINUTE_PER_IP, 60))) {
        return fail(429, "rate_limited", { retry_after: 60 });
      }
      return activateDevice(request, env);
    }

    // PUBLIC, and it lives under /v1/, so it has to be matched ABOVE the device-token
    // gate below or the report form gets a 401 from a browser that has no token and
    // never will. No OPTIONS handler: the form posts FormData, which is a simple
    // request, so there is no preflight to answer.
    if (path === "/v1/abuse-reports" && method === "POST") {
      return abuseReport(request, env, ctx);
    }

    // Owner-only. POST only, so a mail client or link scanner that follows something in
    // a report email can never take an action. Not under /v1/, so it misses the device
    // gate cleanly.
    if (path.startsWith("/admin/")) {
      if (method !== "POST") return fail(405, "post_only");
      if (!adminOK(request, env)) return fail(401, "unauthorized");
      if (path === "/admin/files/delete") return adminDeleteFile(request, env);
      if (path === "/admin/licenses/block") return adminBlockLicense(request, env);
      return fail(404, "not_found");
    }

    // Everything below needs a device token.
    if (path.startsWith("/v1/")) {
      const auth = await authenticate(request, env, ctx);
      if (!auth) return fail(401, "reactivate");

      if (path === "/v1/files" && method === "POST") return createFile(request, env, auth);
      if (path === "/v1/files" && method === "GET") return listFiles(env, auth);
      if (path === "/v1/devices/release" && method === "POST") return releaseDevice(env, auth);

      const content = path.match(/^\/v1\/files\/([A-Za-z0-9-]+)\/content$/);
      if (content && method === "PUT") return uploadContent(request, env, auth, content[1]);

      const single = path.match(/^\/v1\/files\/([A-Za-z0-9-]+)$/);
      if (single && method === "DELETE") return deleteFile(env, auth, single[1]);
    }

    return fail(404, "not_found");
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(sweep(env));
  },
};
