// mushroom-files: temporary file sharing for Mushroom.
//
// A licensed Mac trades its Gumroad key for a device token once, then uploads files that live
// 24 hours behind an unguessable link. Storage is a private R2 bucket: nothing is publicly
// listable and there's no r2.dev domain.
//
// Logging rule, not negotiable: logs are retained, so never log a filename, share token,
// license key or bearer token. Ids and status codes only. (The app agrees: PluginToolbox
// wraps its argument logging in #if DEBUG for this reason.)

// Not secrets; both match LicenseManager.productIDs and mushroom-messaging's list. Membership
// first because new keys are the common case. Old one-time keys must verify forever, so the
// second entry can never go.
const GUMROAD_PRODUCT_IDS = [
  "O8DPu_83HyipF99edOojUQ==",  // Mushroom Membership (subscription)
  "59Bhmk7nBsjAqKhst9Bf9g==",  // Mushroom macOS app (one-time, pre-subscription)
];

const MAX_FILE_BYTES = 95 * 1024 * 1024;        // 95 MiB, under Cloudflare's 100 MB body cap
const TTL_SECONDS = 24 * 60 * 60;
const MAX_ACTIVE_FILES_PER_LICENSE = 50;
// 50 max-size files would be 4.6 GiB, so this binds first at ~32. On purpose: the file count
// caps ordinary drops, this caps the bill.
const MAX_ACTIVE_BYTES_PER_LICENSE = 3 * 1024 * 1024 * 1024;
// Must equal mushroom-messaging's copy and `LicenseVerifier.seatCap` (see the note there): the
// app spends five activations on Gumroad and both Workers keep five device rows, one allowance.
const MAX_DEVICES_PER_LICENSE = 5;
const MAX_NAME_CHARS = 120;
const MAX_DEVICE_NAME_CHARS = 60;
const PENDING_GRACE_SECONDS = 60 * 60;          // abandoned uploads
const TOMBSTONE_SECONDS = 7 * 24 * 60 * 60;     // keep the row so /f/ can say "expired"
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

/// The only origins the report form may be served from. It's one of two browser callers (the
/// receive page is served from here, so needs no CORS); everything else is the Mac app, which
/// sends no Origin.
///
/// `REPORT_ORIGINS` (comma separated) lets a self-hosted deployment serve its own form.
/// Defaulted, so our own deploy can't regress by forgetting it.
const DEFAULT_REPORT_ORIGINS = ["https://getmushroom.app", "https://www.getmushroom.app"];

function reportOrigins(env) {
  const configured = String(env.REPORT_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean);
  return configured.length ? configured : DEFAULT_REPORT_ORIGINS;
}

const REPORT_ACTION = "report";
const ABUSE_FROM = "abuse@getmushroom.app";   // send only, there is no such mailbox
const ABUSE_TO = "hello@getmushroom.app";

/// Where a stranger lands with no link: the root, and the footer of the expired and removed
/// pages.
///
/// Those pages are all a self-hoster's recipients ever see, and shouldn't advertise
/// getmushroom.app from a box we have nothing to do with. Empty `BRAND_URL` names nobody: the
/// root 404s and the pages carry no link. Defaulted to ours so our deploy can't regress.
function brandURL(env) {
  return env.BRAND_URL === undefined ? "https://www.getmushroom.app" : String(env.BRAND_URL).trim();
}

/// The reply to every well-formed submission, real link or not. Confirming that a token
/// resolves would make this an oracle for guessing share links.
const REPORT_ACCEPTED = "Thank you. If this is an active Mushroom link, it will be reviewed.";

// Known file signatures. Not an allowlist: any type may be shared. Safety comes from the
// download path, which always serves octet-stream + attachment + nosniff +
// `default-src 'none'; sandbox`, so attacker-chosen HTML or SVG can't execute on the domain.
// Malware hosting is handled by the takedown flow (abuse reports, admin delete, license block).
//
// The signatures are free and still useful: checked against the real first bytes, so a
// renamed .exe declaring image/png is refused. Unlisted types aren't checked. Each entry is
// {at, bytes} clauses that must all match; `null` means no signature worth checking.
const TYPE_SIGNATURES = {
  "image/jpeg": [{ at: 0, bytes: [0xff, 0xd8, 0xff] }],
  "image/png": [{ at: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] }],
  // "RIFF" also matches .wav and .avi; the "WEBP" tag at byte 8 decides it.
  "image/webp": [{ at: 0, bytes: [0x52, 0x49, 0x46, 0x46] },
                 { at: 8, bytes: [0x57, 0x45, 0x42, 0x50] }],
  "image/heic": [{ at: 4, bytes: [0x66, 0x74, 0x79, 0x70] }],   // "ftyp" box
  "image/heif": [{ at: 4, bytes: [0x66, 0x74, 0x79, 0x70] }],
  "application/pdf": [{ at: 0, bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }],   // "%PDF-"
  "text/plain": null,
  "text/csv": null,
};

const SNIFF_BYTES = 16;

/// A well-formed `type/subtype` in RFC 6838 restricted-name characters, each half capped so
/// the whole stays under 127. The validator for this field; see createFile.
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

// The app trims and uppercases too (Kit: FileShare). Keep them in step or one key becomes two
// identities.
const licenseHash = (key) => sha256Hex(key.trim().toUpperCase());

function shareToken() {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const now = () => Math.floor(Date.now() / 1000);

/// Mirrors FileShare.sanitize in the Kit. The client sanitizes so the user sees the real name;
/// this is here because the client isn't trusted.
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
    // Keep the extension: truncating "report.pdf" to "repo" loses what it is.
    const ext = dot > 0 && name.length - dot <= 12 ? name.slice(dot) : "";
    name = name.slice(0, MAX_NAME_CHARS - ext.length) + ext;
  }
  return name || "file";
}

/// RFC 6266: an ASCII fallback for old clients plus the real UTF-8 name. Quotes and
/// backslashes are stripped from the fallback so nothing can break out of the header.
function attachmentHeader(name) {
  const safe = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "");
  return `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/// Own-property lookups only. A plain `TYPE_SIGNATURES[ct]` inherits from Object.prototype,
/// so a declared type of "constructor" or "valueOf" returns a function and blows up on
/// `.every`: any type can reach this, so that's an uncaught 500 on demand.
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
/// accept a fixed-length stream, and `request.body` stops being one the moment it is
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
/// increment_uses_count is false on purpose. The app burns a seat once, at activation
/// (LicenseManager.activate), and the license allows five devices. Counting again here
/// would spend the user's seats on our own bookkeeping.
/// Tries each product in turn and returns the first real answer. "invalid" from the membership
/// only means "not one of ours from that product", so it must fall through to the one-time
/// product rather than being reported; anything else (active, lapsed, revoked, unreachable) is a
/// real answer about this key and stops the loop. If every product says invalid, it is invalid.
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
  // 429 is Gumroad rate-limiting us, not a bad licence. Calling it "invalid" would lock out real
  // buyers whenever we're busy.
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

  // Entitlement. Must match mushroom-messaging's copy, or a subscriber keeps one feature and
  // loses the other.
  //
  // A one-time purchase has no `subscription_id`; a membership always does (both shapes
  // captured from the live API and pinned in Tests/MushroomPetKitTests/KitTests.swift).
  // "No subscription_id" is necessary but not sufficient: the one-time product is still on sale,
  // so the branch below dates it against the cutover. Don't collapse the two.
  //
  // This also grandfathers a self-hosted box on purpose: `installOfflineGumroad` synthesises a
  // purchase with no subscription_id, so an air-gapped install entitles itself.
  if (typeof purchase.subscription_id !== "string") {
    // One-time purchase: entitled forever only if it predates the cutover. Otherwise anyone
    // could buy the app once and keep Spore Storage for less than four months of membership,
    // and the one-time listing itself says "File sharing and Friends stay off in that version".
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

  // `subscription_cancelled_at` is ignored on purpose: Gumroad sets it on cancel while the paid
  // period still runs; `subscription_ended_at` marks the real stop. Treating cancelled as
  // lapsed would take away time already paid for.
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

// Third identity space, namespaced the same way, from `setappUserID`'s canonical decimal string
// so one account never hashes two ways.
//
// Must match messaging-worker's copy exactly, or a Setapp subscriber keeps one hosted feature
// and loses the other.
const setappHash = (userID) => sha256Hex(`setapp:${userID}`);

/// How many Macs this licence row may keep, counted across every row sharing the sale.
///
/// One sale means five devices in total, not per row. Rows multiply: a redeeming App Store
/// account gets its own row keyed on its app transaction, while a direct-build Mac hashes the
/// key. Bounding only the redeem branch let one sale keep twice its Macs here and again on
/// mushroom-messaging, and nothing else catches it since `verifyLicenseAgainst` sends
/// `increment_uses_count: "false"`.
///
/// Counted in Macs, not rows: counting rows capped Apple Accounts while each kept five devices,
/// and the client's "already set up on five devices" would name a unit nothing counted.
///
/// Excludes this hash, so re-activating an already-counted Mac is free. No sale id can't be
/// counted, so it's let through (§12 fail-open); the live API always sends one. Returns null
/// when the seats are spent; the caller answers `seat_limit`, never `subscription_required`,
/// which both clients persist as a final entitlement refusal.
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
  for (const verifier of verifiers) {
    try {
      const tx = await verifier.verifyAndDecodeAppTransaction(jws);
      // The verifier already checked bundleId. `appTransactionId` is what we need and it's
      // optional in the model; without it there's no identity.
      if (typeof tx.appTransactionId === "string" && tx.appTransactionId) {
        // Ms since epoch when this Apple Account first bought the app. Optional, and null must
        // never read as "bought recently": see appStoreEntitlement.
        const bought = typeof tx.originalPurchaseDate === "number" ? tx.originalPurchaseDate : null;
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

// ---------------------------------------------------------------- throttle

// Overridable for self-hosted boxes, where every client shares one bucket (see the activate
// route); hosted keeps the default.
const activationsPerMinutePerIP = (env) => Number(env.ACTIVATIONS_PER_MINUTE_PER_IP ?? 30) || 30;

/// True if this request is within the limit, false if it should be refused.
///
/// One statement with RETURNING, so a single D1 round trip. Not Cloudflare's Rate Limiting
/// binding: measured on this account, it let 139 requests from one IP through in a minute
/// against a 30/60s limit, and a limiter that always says yes is worse than none because the
/// endpoint looks protected. See migrations/0004_throttle.sql.
///
/// Fails open on a D1 error, like §14 and `requireLicense`: it bounds an abuse cost, it isn't
/// authorization, and refusing every activation over a D1 blip would be worse.
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

/// `allowExpired` drops only the entitlement clause, never the device or revocation checks.
///
/// It's for `releaseDevice`: "releasing your own Mac is cleanup, not access" (see
/// `requireLicense`). The entitlement clause sits in front of every /v1/ route, so without this
/// a lapsed member gets 401 on the one call that hands their seat back (`switchServers` can't
/// release) and the seat stays taken until LRU eviction, turning the cap into a trap.
async function authenticate(request, env, ctx, { allowExpired = false, touch = true } = {}) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const tokenHash = await sha256Hex(header.slice(7).trim());

  // One round trip, since every /v1/ request pays it: the INNER JOIN yields no row for a
  // missing or revoked device or a missing licence.
  //
  // The entitlement clause is what makes a subscription recur, with no timer: an expired row
  // gives no auth row, so a 401, so the client re-activates (FileShareService.swift, the
  // .reactivate branch). Re-activation is a real Gumroad or Apple call that either extends the
  // horizon or answers 403 subscription_required. Nothing polls.
  //
  // NULL passes forever: `entitled_until IS NULL` is the grandfathered case.
  const row = await env.DB.prepare(
    "SELECT d.id AS device_id, d.license_hash, l.status " +
    "FROM devices d JOIN licenses l ON l.license_hash = d.license_hash " +
    "WHERE d.token_hash = ? AND d.revoked_at IS NULL " +
    (allowExpired ? "" : "AND (l.entitled_until IS NULL OR l.entitled_until > ?)")
  ).bind(...(allowExpired ? [tokenHash] : [tokenHash, now()])).first();
  if (!row) return null;

  // Not when the caller only asks why a request failed (`refusal`). Seat eviction orders by
  // `last_seen_at`, so bumping it for a request we're about to 401 keeps a device that only
  // 401s at the top of the LRU, evicting a healthy quieter Mac, and costs a D1 write besides.
  if (touch) {
    ctx.waitUntil(
      env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").bind(now(), row.device_id).run()
    );
  }
  // Same shape the two queries returned, minus `checked_at`, which no caller reads.
  return {
    device: { id: row.device_id, license_hash: row.license_hash },
    license: { license_hash: row.license_hash, status: row.status },
  };
}

/// The 401 to send, once `authenticate` has already said no.
///
/// Two refusals share this status: an unknown or revoked token ("activate again"), and a live
/// token whose licence is past its horizon ("someone must re-prove this licence"). A Mac can
/// always do the second itself, but both Workers speak the same vocabulary and
/// `FileShare.classify` reads it. One extra read, only on a path that already failed.
/// `touch: false` so a device that only 401s doesn't sit at the head of the eviction LRU.
/// Older clients read any 401 as `reactivate`. Mirrors mushroom-messaging's `refusal`.
async function refusal(request, env, ctx) {
  const stillValid = await authenticate(request, env, ctx, { allowExpired: true, touch: false });
  return stillValid ? fail(401, "entitlement_lapsed") : fail(401, "reactivate");
}

// ---------------------------------------------------------------- routes

async function activateDevice(request, env) {
  let body;
  try {
    body = await request.json();
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
  // redeeming Mac would move to a different licence on each activation.
  const redeemKey = typeof body.redeem_license_key === "string" ? body.redeem_license_key.trim() : "";
  // The Setapp build's single-use authorization code, exchanged with Setapp's Vendor API below.
  // A credential, since the licence hash comes from it.
  //
  // No `link_code`, unlike mushroom-messaging: that lets a phone join a licence, and the phone
  // has no Spore Storage (no FileShareClient in the iOS target), so nothing could redeem one.
  const setappCode = typeof body.setapp_code === "string" ? body.setapp_code.trim() : "";
  // Exactly one of the three. Silently picking a winner is how one build ends up
  // authenticating as somebody else's licence.
  if ([key, jws, setappCode].filter(Boolean).length !== 1) return fail(400, "bad_request");
  if (setappCode && setappCode.length > 512) return fail(400, "bad_request");
  if (key && key.length > 100) return fail(400, "bad_request");
  if (jws && jws.length > MAX_APP_TRANSACTION_CHARS) return fail(400, "bad_request");
  if (subJWS && subJWS.length > MAX_APP_TRANSACTION_CHARS) return fail(400, "bad_request");
  if (redeemKey && redeemKey.length > 100) return fail(400, "bad_request");

  const stamp = now();
  let hash;
  let saleID = null;
  let source;
  // NULL means entitled forever: any path that doesn't set a horizon is grandfathered.
  let entitledUntil = null;
  // How many Macs this row may keep once written. The redeem and Gumroad branches lower it, so
  // one sale means five devices in total, not five per Apple Account (see `saleSeatBudget` and
  // the eviction). Setapp counts devices itself.
  let deviceBudget = MAX_DEVICES_PER_LICENSE;

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
    // Notifications V2 and a webhook, and §14 says fail open, no DRM until piracy is real. The
    // quotas bound the damage.
  } else if (setappCode) {
    // Setapp, verified inline and forgotten: the answer becomes a horizon and no token is
    // stored. When it expires, the client activates again with a fresh code. Must keep agreeing
    // with the twin branch in mushroom-messaging.
    if (setappMisconfigured(env)) return fail(503, "setapp_unconfigured");
    const { status, userID } = await verifySetappAccess(setappCode, env);
    // Fail closed, as in the Gumroad branch: existing tokens keep working while Setapp is down,
    // but a new one isn't handed out on a shrug.
    if (status === "unreachable") return fail(503, "setapp_down");
    if (status === "invalid") return fail(403, "bad_license");
    if (status === "refused") return fail(403, "subscription_required");

    hash = await setappHash(userID);
    source = "setapp";
    // Never null: a null horizon is permanent (the upsert's CASE pins it), and a cancellable
    // subscription must never be written as entitled forever.
    entitledUntil = stamp + SETAPP_RECHECK_SECONDS;
    // No seat budget: Setapp counts devices itself, per purchase.
  } else {
    const { status: verdict, saleID: gumroadSaleID, entitledUntil: until } = await verifyLicense(key, env);
    // Fail closed here, and only here. The app's licence gate fails open (CLAUDE.md §12) and an
    // issued token keeps working while Gumroad is down (see requireLicense), but a new token
    // without a check would make "Gumroad is unreachable" a free pass into the bucket.
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
        // activation promote it to 'active', since that CASE only protects 'blocked'. With no
        // unblock endpoint, a block must only ever clear on purpose.
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

  // COALESCE, not overwrite: a later verify that omits the sale id mustn't erase ours.
  //
  // `entitled_until` is monotonic both ways: NULL never becomes a horizon, and a horizon never
  // becomes NULL. Only horizon -> horizon moves, which is a renewal.
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
  await env.DB.prepare(
    "INSERT INTO licenses (license_hash, status, checked_at, created_at, gumroad_sale_id, source, entitled_until) " +
    "VALUES (?, 'active', ?, ?, ?, ?, ?) " +
    "ON CONFLICT(license_hash) DO UPDATE SET " +
    "status = CASE WHEN licenses.status = 'blocked' THEN 'blocked' ELSE 'active' END, " +
    "checked_at = excluded.checked_at, " +
    "gumroad_sale_id = COALESCE(excluded.gumroad_sale_id, licenses.gumroad_sale_id), " +
    "entitled_until = CASE " +
    "WHEN licenses.entitled_until IS NULL THEN NULL " +
    "WHEN excluded.entitled_until IS NULL THEN licenses.entitled_until " +
    "ELSE excluded.entitled_until END"
  ).bind(hash, stamp, stamp, saleID, source, entitledUntil).run();

  // The next activation must not undo an admin block, or the app re-activates and sharing
  // resumes with a fresh token. A Gumroad key could be revoked at Gumroad instead; an App
  // Store hash has no such lever, since this Worker never re-asks Apple.
  const state = await env.DB.prepare("SELECT status FROM licenses WHERE license_hash = ?")
    .bind(hash).first();
  if (state?.status !== "active") return fail(403, "revoked");

  // This Mac's previous row goes first, making a re-activation a reclaim, not a second seat. The
  // client sends the device id it holds; otherwise its stale row looks like another Mac's, the
  // eviction counts it as live, and a healthy Mac is evicted on every re-activation. That's
  // routine: the horizon expires every LICENSE_RECHECK_SECONDS.
  //
  // Scoped to this licence hash, so a lifted device id can't revoke another licence's Mac. An
  // unknown id matches nothing.
  const priorID = typeof body.device_id === "string" ? body.device_id.slice(0, 64) : null;
  if (priorID) {
    await env.DB.prepare(
      "UPDATE devices SET revoked_at = ? WHERE id = ? AND license_hash = ? AND revoked_at IS NULL"
    ).bind(stamp, priorID, hash).run();
  }

  // Past the cap, evict the least-recently-seen Mac rather than refuse: a 409 would strand
  // someone who reinstalled twice, and the evicted Mac re-activates on its next 401.
  const live = await env.DB.prepare(
    "SELECT id FROM devices WHERE license_hash = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC"
  ).bind(hash).all();
  const doomed = (live.results ?? []).slice(deviceBudget - 1);
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

  // The limits travel with the token so the app shows "up to 95 MB" from the server's answer,
  // and changing a limit needs no app release.
  return reply(201, { device_id: id, token, limits: limits() });
}

const limits = () => ({
  // The wire contract this server speaks, as in mushroom-messaging. Nobody reads it yet, but
  // absent means "older than 1", so it must exist before there's a 2 to date a pinned customer
  // server. Bump only for changes an older app can't survive.
  protocol: 1,
  max_file_bytes: MAX_FILE_BYTES,
  max_files: MAX_ACTIVE_FILES_PER_LICENSE,
  max_total_bytes: MAX_ACTIVE_BYTES_PER_LICENSE,
  ttl_seconds: TTL_SECONDS,
  // No allowed_types: every type is allowed. Apps before 1.26 read its absence as "the server
  // didn't say" and keep their own hardcoded list, so they behave as before.
  // The app holds the licence key and we don't, so re-verification is its job; this says how
  // often. Re-activating past this age is what makes a refund stop working. See
  // requireLicense.
  reverify_after_seconds: LICENSE_RECHECK_SECONDS,
});

/// Revocation check for an authenticated device. Unlike activation it fails open: the device
/// proved itself once, and Gumroad being down mustn't stop someone sharing a file. Only an
/// explicit refund, dispute or chargeback closes the door.
///
/// No periodic re-verify: we store sha256(key), never the key, so the Worker can't re-ask
/// Gumroad, and stamping `checked_at` forward would check nothing. The app holds the key and
/// re-activates when its token is older than LICENSE_RECHECK_SECONDS; that real Gumroad call
/// flips `status` to revoked after a refund. A pirate who never re-activates keeps a working
/// token, the app's own posture (spec §14: keep honest people honest, no DRM). Quotas bound
/// the damage.
///
/// Every route that reads or writes a licence's files calls it: createFile, uploadContent,
/// listFiles and deleteFile. Guarding only createFile would leave a blocked Mac listing and
/// deleting files with its still-valid token, and 'blocked' is the only revocation lever the
/// App Store channel has.
///
/// `releaseDevice` isn't guarded: releasing your own Mac is cleanup, not access, and a blocked
/// user should still be able to unregister a machine.
function requireLicense(auth) {
  // 'blocked' is our abuse decision, 'revoked' is Gumroad's. Both close the door; an unknown
  // or stale status still works (the fail-open posture of §14).
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

  // Any type is allowed, but it must be shaped like one (RFC 6838): content_type goes into the
  // plain-text abuse-report email, where an interior newline (untouched by .trim()) would forge
  // lines.
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

  // Scoped by licence; a miss is 404, since 403 would confirm someone else's id exists.
  const row = await env.DB.prepare(
    "SELECT id, token, name, size, content_type, state, expires_at FROM files WHERE id = ? AND license_hash = ?"
  ).bind(id, auth.license.license_hash).first();
  if (!row) return fail(404, "not_found");
  if (row.state !== "pending") return fail(409, "already_uploaded");
  if (row.expires_at <= now()) return fail(410, "gone");

  // Required so the body is a fixed-length stream R2 takes without buffering. Workers cap
  // memory at 128 MB, and a chunked upload would be read into it.
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
    // request.body goes through unwrapped: R2 only accepts a fixed-length stream, and any
    // wrapping loses that.
    object = await env.FILES.put(key, request.body, {
      httpMetadata: {
        // Bookkeeping only; downloads are always served as octet-stream.
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

  // The declared type was checked at create time; here the actual bytes are. A renamed .exe
  // claiming to be a PNG dies before its link works.
  //
  // Except for sealed files, which current clients always send: ciphertext matches no
  // signature. That's not a hole a header opens, just the server no longer seeing the file;
  // a client could dodge the sniff anyway by declaring application/octet-stream.
  const sealed = request.headers.get("x-mushroom-encrypted") === "1";
  if (!sealed && !(await storedBytesMatchType(env, key, row.content_type))) {
    await env.FILES.delete(key).catch(() => {});
    return fail(415, "type_mismatch");
  }

  await env.DB.prepare(
    "UPDATE files SET state = 'ready', uploaded_at = ?, size = ? WHERE id = ?"
  ).bind(now(), object.size, id).run();

  return reply(200, { url: `${env.PUBLIC_BASE}/f/${row.token}`, expires_at: row.expires_at });
}

/// The page a browser gets for a live link, and the other half of `SporeCrypto` in the Kit.
///
/// The Mac seals every file with a key carried in the link's fragment. Browsers never send a
/// fragment, so the key can't reach this Worker, even in a log; this page turns it back into a
/// file. Format: `"MSH1" || nonce(12) || AES-GCM-256 ciphertext+tag`. The fixed test vector
/// lives in `vector.mjs` and `SporeCryptoTests.swift`; change one, change all three.
///
/// **Nothing is interpolated into this string.** The page reads the token from its own
/// location, so nothing a stranger controls reaches the markup. That's what makes the inline
/// script safe in the CSP; if you ever need a server value here, put it in an escaped `data-`
/// attribute.
///
/// Served from the same origin as the file bytes, so no CORS, and self-hosters get it free.
/// The bytes are still octet-stream + attachment + nosniff + `default-src 'none'; sandbox`,
/// so nothing shared can execute here whatever this page does.
///
/// The palette is a third copy of `Mushroom_www/tokens.css` (the second is
/// `ds/src/styles.css`), since a Worker response can't link a stylesheet on another origin. If
/// the tokens change, port them.
const RECEIVE_PAGE = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mushroom</title>
<style>
  :root {
    --bg: #f6ecd8; --card: #fffaf0; --ink: #4a3226; --ink2: #7d6252;
    --red: #d0342c; --red-ink: #fff; --line: #dcc9a8;
    --shadow: 0 4px 10px rgba(74,50,38,.09), 0 10px 24px rgba(74,50,38,.11);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #17120f; --card: #241b15; --ink: #f3e7d4; --ink2: #b39f8b;
      --red: #e8524a; --red-ink: #1a0d0b; --line: #3b2d23;
      --shadow: 0 4px 10px rgba(0,0,0,.4), 0 10px 24px rgba(0,0,0,.44);
    }
  }
  * { box-sizing: border-box; }
  body {
    font: 16px/1.6 -apple-system, system-ui, sans-serif;
    background: var(--bg); color: var(--ink);
    margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center; padding: 1.5rem;
  }
  .card {
    background: var(--card); border: 1px solid var(--line); border-radius: 18px;
    box-shadow: var(--shadow); padding: 2rem 1.75rem; text-align: center;
    width: 100%; max-width: 26rem;
  }
  .pet { font-size: 3rem; line-height: 1; margin: 0 0 .75rem; }
  h1 {
    font-size: 1.1rem; font-weight: 600; margin: 0 0 .35rem;
    overflow-wrap: anywhere;
  }
  p { margin: 0; color: var(--ink2); font-size: .9rem; }
  button {
    font: inherit; font-weight: 600; cursor: pointer;
    margin-top: 1.5rem; padding: .7rem 1.6rem; border: 0; border-radius: 999px;
    background: var(--red); color: var(--red-ink);
  }
  button:disabled { opacity: .6; cursor: default; }
  button:focus-visible { outline: 2px solid var(--red); outline-offset: 3px; }
  @media (prefers-reduced-motion: no-preference) { button { transition: opacity .2s; } }
</style>
<div class="card">
  <p class="pet">🍄</p>
  <h1 id="name">Mushroom</h1>
  <p id="note">Looking for this file…</p>
  <button id="go" hidden>Download</button>
</div>
<script>
(function () {
  var MAGIC = "MSH1";
  var nameEl = document.getElementById("name");
  var noteEl = document.getElementById("note");
  var button = document.getElementById("go");
  // The key, and the reason this page exists. Read from the fragment and never put into a
  // request, a header or a URL: that is the whole guarantee.
  //
  // Guarded, because a stray % in a mangled link makes decodeURIComponent throw, and thrown
  // out here it takes the whole script with it: no name, no button, and the page sits on
  // "Looking for this file…" forever with nothing to explain it. A key we cannot decode is a
  // key we do not have, which the "missing its key" message below already says properly.
  var key = "";
  try { key = decodeURIComponent(location.hash.slice(1)); } catch (e) { key = ""; }
  var url = location.pathname;
  var total = 0;
  var filename = "file";
  var sealed = false;

  function say(text) { noteEl.textContent = text; }

  function size(bytes) {
    if (!bytes) return "";
    var units = ["bytes", "KB", "MB", "GB"];
    var i = 0;
    var n = bytes;
    while (n >= 1024 && i < units.length - 1) { n = n / 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
  }

  // RFC 6266. The UTF-8 form is what the server always sends; the quoted one is the ASCII
  // fallback beside it.
  function nameFrom(header) {
    if (!header) return "file";
    var star = /filename\\*=UTF-8''([^;]+)/i.exec(header);
    if (star) { try { return decodeURIComponent(star[1]); } catch (e) { /* fall through */ } }
    var plain = /filename="([^"]*)"/i.exec(header);
    return plain ? plain[1] : "file";
  }

  // One range request tells us everything: the name, the real size, and whether the first
  // four bytes are ours. Four bytes rather than the whole file, so a link that is missing
  // its key costs the recipient nothing to find out about.
  fetch(url, { headers: { "Range": "bytes=0-3" } }).then(function (response) {
    if (!response.ok && response.status !== 206) throw new Error("gone");
    filename = nameFrom(response.headers.get("content-disposition"));
    var range = response.headers.get("content-range");
    var slash = range ? range.lastIndexOf("/") : -1;
    total = slash >= 0 ? parseInt(range.slice(slash + 1), 10) : 0;
    return response.arrayBuffer();
  }).then(function (head) {
    sealed = new TextDecoder().decode(head.slice(0, 4)) === MAGIC;
    nameEl.textContent = filename;
    if (sealed && !key) {
      say("This link is missing its key. Ask whoever sent it for the whole link, including everything after the # sign.");
      return;
    }
    say(size(total) + (sealed ? " · Encrypted, only this link can open it" : ""));
    button.hidden = false;
  }).catch(function () {
    nameEl.textContent = "Mushroom";
    say("That link did not work. It may have expired.");
  });

  button.addEventListener("click", function () {
    button.disabled = true;
    say("Downloading…");
    fetch(url).then(function (response) {
      if (!response.ok) throw new Error("gone");
      var length = parseInt(response.headers.get("content-length") || "0", 10) || total;
      // Read the stream rather than awaiting the blob, so a 95 MB file shows progress
      // instead of looking hung.
      var reader = response.body.getReader();
      var chunks = [];
      var done = 0;
      return (function pump() {
        return reader.read().then(function (step) {
          if (step.done) return chunks;
          chunks.push(step.value);
          done += step.value.length;
          if (length) say("Downloading… " + Math.round(done / length * 100) + "%");
          return pump();
        });
      })();
    }).then(function (chunks) {
      return new Blob(chunks).arrayBuffer();
    }).then(function (blob) {
      if (!sealed) return blob;
      say("Decrypting…");
      var raw = new Uint8Array(blob);
      // MAGIC(4) | nonce(12) | ciphertext+tag. WebCrypto takes the tag on the end of the
      // ciphertext, which is exactly how CryptoKit's combined form lays it out.
      var nonce = raw.slice(4, 16);
      var body = raw.slice(16);
      var bytes = Uint8Array.from(atob(key.replace(/-/g, "+").replace(/_/g, "/")), function (c) {
        return c.charCodeAt(0);
      });
      return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["decrypt"])
        .then(function (imported) {
          return crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, imported, body);
        });
    }).then(function (plaintext) {
      var link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([plaintext]));
      link.download = filename;
      link.click();
      setTimeout(function () { URL.revokeObjectURL(link.href); }, 60000);
      say("Saved. It is in your downloads.");
      button.disabled = false;
      button.textContent = "Download again";
    }).catch(function (error) {
      button.disabled = false;
      say(sealed && error && error.name === "OperationError"
        ? "That key does not open this file. Check you copied the whole link."
        : "That did not finish. Check your connection and try again.");
    });
  });
})();
</script>
`;

function gonePage(message, env) {
  const brand = brandURL(env);
  // No link when this deployment names nobody. `brand` is operator config, never visitor
  // input, so it isn't escaped; `message` is one of the two fixed strings below.
  const footer = brand
    ? `<p><a href="${brand}">${brand.replace(/^https?:\/\//, "")}</a></p>`
    : "";
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>Mushroom</title><style>body{font:16px/1.6 -apple-system,system-ui,sans-serif;` +
    `max-width:32rem;margin:20vh auto;padding:0 1.5rem;text-align:center;color:#3d3a37}` +
    `a{color:#c2410c}</style><p style="font-size:3rem">🍄</p><p>${message}</p>${footer}`,
    { status: 410, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
  );
}

async function download(request, env, ctx, token) {
  const row = await env.DB.prepare(
    "SELECT id, name, size, state, expires_at FROM files WHERE token = ?"
  ).bind(token).first();

  if (!row) return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
  if (row.state === "deleted") return removedPage(env);
  if (row.state === "expired" || row.expires_at <= now()) return expiredPage(env);
  // Never finished uploading: deliberately indistinguishable from a bad link.
  if (row.state !== "ready") {
    return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
  }

  // A browser navigating here gets the page that can decrypt; everything else (the page's own
  // fetch, curl, wget, a download manager) sends */* and gets the bytes. One URL serves both,
  // and range support below is untouched.
  if (request.method === "GET" && (request.headers.get("accept") ?? "").includes("text/html")) {
    return new Response(RECEIVE_PAGE, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        // 'unsafe-inline' is safe here and only here: RECEIVE_PAGE is a constant with no
        // interpolation. connect-src 'self' keeps anything, key included, from going elsewhere.
        "content-security-policy":
          "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
          "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      },
    });
  }

  const range = request.headers.get("range");
  let object;
  try {
    object = await env.FILES.get(`f/${row.id}`, range ? { range: request.headers } : undefined);
  } catch {
    // R2 throws on an unsatisfiable range. Answer 416 as the spec says, not a 500.
    return new Response("Range not satisfiable", {
      status: 416,
      headers: { "content-range": `bytes */${row.size}`, "cache-control": "no-store" },
    });
  }
  if (!object) return expiredPage(env);   // lifecycle rule got there first

  const headers = new Headers();
  // Always octet-stream, never the declared type: attacker-chosen HTML or SVG on a
  // getmushroom.app subdomain would be stored XSS against the marketing site.
  headers.set("content-type", "application/octet-stream");
  headers.set("content-disposition", attachmentHeader(row.name ?? "file"));
  headers.set("x-content-type-options", "nosniff");
  headers.set("content-security-policy", "default-src 'none'; sandbox");
  headers.set("cache-control", "private, no-store");
  headers.set("referrer-policy", "no-referrer");
  headers.set("accept-ranges", "bytes");

  // Gated on the request carrying a Range, not just object.range: R2 fills that in for a
  // plain get too, which would turn every download into a 206.
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

const removedPage = (env) => gonePage("This file was removed.", env);
// Read from TTL_SECONDS, so a self-hoster who shortens it doesn't get a page quoting ours.
const expiredPage = (env) =>
  gonePage(`This link has expired. Mushroom links last ${Math.round(TTL_SECONDS / 3600)} hours.`, env);

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

  // R2 first: a row saying "deleted" while the bytes are still fetchable is the bad way to fail.
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
function reportCORS(origin, env) {
  const origins = reportOrigins(env);
  const allowed = origins.includes(origin) ? origin : origins[origins.length - 1];
  return { "access-control-allow-origin": allowed, "vary": "Origin" };
}

function reportReply(status, body, origin, env) {
  return new Response(JSON.stringify({ ok: status < 400, ...body }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...reportCORS(origin, env) },
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

  // Cloudflare's testing secrets answer with a dummy hostname ("example.com") and no action,
  // and flag themselves. Skipping the checks then lets the local suite run the whole path. It
  // can't soften production: a real secret never sets this flag, and a testing secret accepts
  // any token anyway.
  if (outcome.metadata?.result_with_testing_key === true) return true;

  if (outcome.hostname && !reportOrigins(env).includes(`https://${outcome.hostname}`)) return false;
  if (outcome.action && outcome.action !== REPORT_ACTION) return false;
  return true;
}

async function abuseReport(request, env, ctx) {
  const origin = request.headers.get("origin") ?? "";
  if (!reportOrigins(env).includes(origin)) return reportReply(403, { code: "bad_origin" }, origin, env);

  let form;
  try {
    form = await request.formData();
  } catch {
    return reportReply(400, { code: "bad_request" }, origin, env);
  }

  // Honeypot: look successful, store nothing. Same trick as the tools form.
  if (form.get("website")) return reportReply(200, { message: REPORT_ACCEPTED }, origin, env);

  if (!(await turnstileOK(form.get("cf-turnstile-response"), request.headers.get("CF-Connecting-IP"), env))) {
    return reportReply(403, { code: "bot_check", message: "Bot check failed, please reload and try again." }, origin, env);
  }

  const shareURL = String(form.get("share_url") ?? "").trim();
  const match = shareURL.match(/^https:\/\/files\.getmushroom\.app\/f\/([A-Za-z0-9_-]{22})$/);
  if (!match) {
    return reportReply(400, { code: "bad_url", message: "That does not look like a Mushroom share link." }, origin, env);
  }

  const reason = String(form.get("reason") ?? "");
  if (!REPORT_REASONS.includes(reason)) return reportReply(400, { code: "bad_reason" }, origin, env);

  const name = String(form.get("name") ?? "").trim().slice(0, MAX_REPORTER_NAME_CHARS);
  const email = String(form.get("email") ?? "").trim().slice(0, MAX_REPORTER_EMAIL_CHARS);
  const details = String(form.get("details") ?? "").trim().slice(0, MAX_DETAILS_CHARS);
  if (!name || !email.includes("@")) {
    return reportReply(400, { code: "bad_contact", message: "Please give a name and an email we can reply to." }, origin, env);
  }

  // From here the answer is identical whether or not the link resolves; any difference in
  // status, body or visible timing would make this an oracle for guessing share tokens.
  const accepted = reportReply(200, { message: REPORT_ACCEPTED }, origin, env);

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

  // A repeat report or a pile-on is not new information.
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

/// The two commands that act on a report. POST and bearer-authenticated, so a mail client or
/// link scanner following anything in the email can't take an action.
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

/// Best effort. The row is written either way and the cron retries failures: durable first,
/// notify second, like the tools form.
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
      // Reason is a fixed enum and the id a uuid, so neither can put a newline in the header.
      // That's why the filename never appears here.
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

/// Constant-time-ish bearer check. The token is one shared secret, so there's nothing to
/// enumerate; the loop avoids leaking it via timing.
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

/// R2 object first, then the row: a row saying deleted while the bytes are still fetchable is
/// the bad way to fail.
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

/// Blocks file sharing for this licence, nothing else; the app keeps working. Disabling the
/// purchase is a separate act in Gumroad, using the sale id in the report email.
async function adminBlockLicense(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail(400, "bad_request"); }
  const hash = String(body.license_hash ?? "");
  if (!hash) return fail(400, "bad_request");

  const row = await env.DB.prepare("SELECT license_hash FROM licenses WHERE license_hash = ?").bind(hash).first();
  if (!row) return fail(404, "not_found");

  // 'blocked', not 'revoked': a Gumroad revocation can legitimately clear (a reversed refund
  // re-verifies as active), and the activateDevice upsert allows that. A block must survive
  // it, and for an App Store hash it's the only lever, since this Worker never re-asks Apple.
  // Same split as mushroom-messaging.
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
    // NULL the name too: the tombstone only answers "expired", not what was shared.
    await env.DB.prepare(
      `UPDATE files SET state = 'expired', name = NULL WHERE id IN (${holes})`
    ).bind(...ids).run();
  }

  await env.DB.prepare(
    "DELETE FROM files WHERE state IN ('expired','deleted') AND expires_at <= ?"
  ).bind(stamp - TOMBSTONE_SECONDS).run();

  // Spent throttle windows; otherwise the table grows a row per IP per window forever.
  await env.DB.prepare("DELETE FROM throttle WHERE expires_at <= ?").bind(stamp).run();

  await env.DB.prepare(
    "DELETE FROM devices WHERE revoked_at IS NOT NULL AND revoked_at <= ?"
  ).bind(stamp - TOMBSTONE_SECONDS).run();

  // Retry reports whose email never went out.
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

  // The reporter's name and email are for follow-up; thirty days is enough, longer serves
  // nobody.
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
      const brand = brandURL(env);
      // A deployment that names nobody says nothing; a self-hoster's visitors aren't ours to
      // send to our marketing site.
      if (!brand) return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
      return Response.redirect(brand, 302);
    }

    // Public download. No auth; that's the feature.
    if (path.startsWith("/f/") && (method === "GET" || method === "HEAD")) {
      const token = path.slice(3);
      if (!token || token.includes("/")) {
        return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
      }
      return download(request, env, ctx, token);
    }

    if (path === "/v1/devices/activate" && method === "POST") {
      // Before activateDevice, which is what a flood spends: the App Store branch walks an
      // attacker-supplied certificate chain twice per call (Production, then Sandbox) with no
      // bearer token in front. mushroom-messaging throttles this endpoint via its DO.
      //
      // Self-hosted, nothing sets or strips cf-connecting-ip, so a client could pick a fresh
      // bucket per request. One bucket for the box instead.
      const ip = env.SELFHOST === "1" ? "box" : (request.headers.get("cf-connecting-ip") ?? "unknown");
      if (!(await throttle(env, "activate", ip, activationsPerMinutePerIP(env), 60))) {
        return fail(429, "rate_limited", { retry_after: 60 });
      }
      return activateDevice(request, env);
    }

    // Public but under /v1/, so it's matched above the device-token gate, or the report form
    // gets a 401. No OPTIONS handler: FormData is a simple request, so there's no preflight.
    if (path === "/v1/abuse-reports" && method === "POST") {
      return abuseReport(request, env, ctx);
    }

    // Owner-only. POST only, so a mail client or link scanner following a report email can't
    // take an action. Outside /v1/, so it skips the device gate.
    if (path.startsWith("/admin/")) {
      if (method !== "POST") return fail(405, "post_only");
      if (!adminOK(request, env)) return fail(401, "unauthorized");
      if (path === "/admin/files/delete") return adminDeleteFile(request, env);
      if (path === "/admin/licenses/block") return adminBlockLicense(request, env);
      return fail(404, "not_found");
    }

    // Everything below needs a device token.
    if (path.startsWith("/v1/")) {
      // Release is cleanup, not access, so it skips the entitlement clause (see
      // `authenticate`). Matched first, since the general gate would 401 it.
      const releasing = path === "/v1/devices/release" && method === "POST";
      const auth = await authenticate(request, env, ctx, { allowExpired: releasing });
      if (!auth) return refusal(request, env, ctx);

      if (releasing) return releaseDevice(env, auth);
      if (path === "/v1/files" && method === "POST") return createFile(request, env, auth);
      if (path === "/v1/files" && method === "GET") return listFiles(env, auth);

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
