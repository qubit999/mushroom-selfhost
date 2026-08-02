/// Licence verification for a box that cannot reach Gumroad.
///
/// Phase A needs nothing like this: the customer's Worker has internet, so `verifyLicense`
/// reaches Gumroad and each employee activates their own key. A Phase B box has no outbound
/// network at all, by design, so the same call has to be answered locally.
///
/// The handoff proposed gating inside `verifyLicense`. That cannot be done without editing the
/// file Phase B exists to keep unforked: `verifyLicense(key)` takes no `env` in either worker,
/// and it is also reached through `credentialHash` on the channel-migration path. Wrapping the
/// global `fetch` instead means every byte downstream is the ordinary Gumroad path, including
/// the `licenses` upsert with its blocked-preserving CASE, the seat cap, `source: "gumroad"`,
/// and identity claiming. Nothing in worker.js moves.
///
/// An App Store build cannot point at a custom server at all (ServerBase returns nil under
/// #if APPSTORE), so on-prem is the direct build and therefore Gumroad only. That was a fact
/// about the CLIENT, read as a property of this server, and it was neither: it is a choice to
/// avoid a review conversation, not something Apple forbids, and `/v1/devices/activate` is an
/// unauthenticated POST either way. Its `app_transaction` branch verifies against the pinned
/// Apple roots offline, so it never calls `fetch` and never passed through the wrapper below,
/// and anyone holding an App Store JWS could enrol on a box restricted to named keys.
///
/// The list is now applied by `enrolmentAllows` in both workers, to the hash whichever branch
/// produced, so it covers every credential type and keeps covering them if that client
/// restriction is ever lifted. This wrapper still answers Gumroad, and no longer carries the
/// enrolment decision on its own.
///
/// TWO MODES, and `*` is the default a container ships with.
///
/// `*` accepts any key the app presents. That is not a hole, because THE MAC HAS INTERNET EVEN
/// WHEN THIS BOX DOES NOT: `LicenseManager.activate` requires a Gumroad `success: true` and
/// `uses <= 3` before a key ever reaches the Keychain, so a key arriving here was already
/// verified against Gumroad by the machine that owns it. Checking it twice, against a list a
/// human has to maintain by hand, buys nothing this box can act on: it cannot learn about a
/// refund either way. Everything the hash is actually USED for is unchanged, because it is an
/// identifier and not a permit: the `licenses` row, `MAX_DEVICES_PER_LICENSE`, first-claim
/// identity binding, and `/admin/licenses/block`, which stays the operator's real lever.
///
/// A list of hashes instead restricts the box to named keys, for an operator who wants that. The
/// config holds HASHES, never keys, matching what both Workers already store, so a leaked config
/// file yields nothing usable.
///
/// Neither mode is the empty string. With nothing configured this installs NOTHING and every
/// Gumroad activation is a 503, which is what a half-configured box should do. (`enrolmentAllows`
/// refuses an empty list too, with a 403, so the App Store branch is no longer the one credential
/// a box nobody finished setting up still accepted.) The container never gets there: it refuses
/// to start at all without a `.env`.

const VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify";

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let installed = false;

/// Wrap `globalThis.fetch` so the Gumroad verify URL is answered in process. Everything else
/// passes through untouched, which on a correctly configured box means it fails, because
/// `globalOutbound` allows nothing.
///
/// With no hashes configured this installs NOTHING. The call then escapes to a network that
/// refuses it, `verifyLicense` returns "unreachable", and activation is a 503. Fail closed and
/// loud is the right behaviour for a box whose operator has not finished setting it up.
export function installOfflineGumroad(hashes) {
  if (installed) return;
  const configured = String(hashes ?? "").trim();
  // Exactly "*", not a wildcard anywhere in the value: a list that happens to contain a stray
  // asterisk is a typo, and reading it as "let everybody in" is the wrong way to resolve one.
  const open = configured === "*";
  const enrolled = new Set(
    configured.split(/[\s,]+/).filter(Boolean).map((h) => h.trim().toLowerCase())
  );
  if (!open && enrolled.size === 0) return;
  installed = true;

  const passThrough = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input?.url;
    if (url !== VERIFY_URL) return passThrough(input, init);

    // Same normalisation both Workers use before hashing a key, so an operator computing a
    // hash with the documented one-liner gets a match.
    const key = new URLSearchParams(init?.body ?? "").get("license_key") ?? "";
    const hash = await sha256Hex(key.trim().toUpperCase());

    // `success: false` is what Gumroad sends for a key it does not know, and it lands as
    // `invalid` and then a 403, exactly as it would hosted.
    if (!open && !enrolled.has(hash)) return Response.json({ success: false });

    // No refunded/disputed/chargebacked flags: this box cannot learn about a refund, and
    // inventing one would be worse than the honest answer. Removing someone is removing their
    // hash from the config, which is the control an on-prem operator actually has.
    return Response.json({
      success: true,
      purchase: { sale_id: `selfhost-${hash.slice(0, 16)}` },
    });
  };
}
