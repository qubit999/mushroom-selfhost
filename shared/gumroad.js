/// Licence verification for a box that cannot reach Gumroad.
///
/// Phase A doesn't need this: the customer's Worker has internet, so `verifyLicense` reaches
/// Gumroad and each employee activates their own key. A Phase B box has no outbound network by
/// design, so the same call is answered locally.
///
/// Gating inside `verifyLicense` would fork the file Phase B exists to keep unforked; it's
/// reached from several layers in either worker, including `credentialHash` on the
/// channel-migration path. Wrapping global `fetch` keeps everything downstream on the ordinary
/// Gumroad path: the `licenses` upsert and its blocked-preserving CASE, the seat cap,
/// `source: "gumroad"`, identity claiming. Nothing in worker.js moves.
///
/// App Store Macs reach self-hosted boxes too. Their `app_transaction` branch verifies offline
/// against the pinned Apple roots and never calls `fetch`, so this wrapper alone would let any
/// App Store JWS enrol on a box restricted to named keys. The list is therefore applied by
/// `enrolmentAllows` in both workers, to whichever hash a branch produced; this wrapper only
/// answers Gumroad.
///
/// Two modes, and no default: the operator picks one.
///
/// A list of hashes is the safe one. `*` accepts any string as a key, so anyone who can reach the
/// listener enrols, gets a permanent device token and, on files, a quota under this box's name.
/// The Mac's own Gumroad check doesn't help: the server is the boundary, and a script needs no
/// Mac. `*` therefore fits only a box nobody untrusted can reach (a tailnet of employees), and
/// `/admin/licenses/block` is the lever if it goes wrong.
///
/// A list of hashes restricts the box to named keys. The config holds hashes, never keys (as
/// both Workers store them), so a leaked config yields nothing usable.
///
/// Empty is neither mode: this installs nothing and every Gumroad activation is a 503, right
/// for a half-configured box (`enrolmentAllows` also refuses an empty list, with a 403). The
/// container refuses to start with it empty.

const VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify";

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let installed = false;

/// Wrap `globalThis.fetch` so the Gumroad verify URL is answered in process. Everything else
/// passes through, which on a correctly configured box fails, since `globalOutbound` allows
/// nothing.
///
/// With no hashes this installs nothing: the call escapes to a network that refuses it,
/// `verifyLicense` returns "unreachable", and activation is a 503. Fail closed and loud for an
/// unfinished setup.
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

    // The same normalisation both Workers use, so a hash from the documented one-liner matches.
    const key = new URLSearchParams(init?.body ?? "").get("license_key") ?? "";
    const hash = await sha256Hex(key.trim().toUpperCase());

    // Gumroad's answer for an unknown key; it becomes `invalid` and a 403, as hosted.
    if (!open && !enrolled.has(hash)) return Response.json({ success: false });

    // No refunded/disputed/chargebacked flags: this box can't learn about refunds, and inventing
    // one would be worse. To remove someone, the operator removes their hash from the config.
    return Response.json({
      success: true,
      purchase: { sale_id: `selfhost-${hash.slice(0, 16)}` },
    });
  };
}
