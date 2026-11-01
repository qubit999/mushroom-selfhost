// The Setapp half of entitlement.js, tested against a stubbed vendor API.
//
//   node worker-shared/setapp-test.mjs
//
// Pure functions and one `fetch` seam, so no wrangler, network or secrets, unlike the HTTP suites
// next door. It's the only check on two rules that are permanent if wrong: the licence hash input
// (`setappUserID`), fixed once real identities are keyed on it, and the refusal map, where reading
// our misconfiguration as "your subscription lapsed" is what §12 forbids telling a paying user.

import {
  SETAPP_RECHECK_SECONDS, setappMisconfigured, setappUserID, verifySetappAccess,
} from "./entitlement.js";

let pass = 0;
let fail = 0;
const eq = (actual, expected, label) => {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    pass += 1;
    console.log(`  \x1b[32mok\x1b[0m   ${label}`);
  } else {
    fail += 1;
    console.log(`  \x1b[31mFAIL\x1b[0m ${label} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
};

// A vendor API answering from a table. Anything else throws, which is how a test asserts a later
// call was never reached.
const stub = (routes) => async (url) => {
  const path = url.replace("https://stub", "");
  const route = routes[path];
  if (!route) throw new Error(`unexpected call to ${path}`);
  return {
    ok: route.status >= 200 && route.status < 300,
    status: route.status,
    json: async () => route.body ?? {},
  };
};

const env = { SETAPP_CLIENT_ID: "id", SETAPP_CLIENT_SECRET: "secret", SETAPP_API_BASE: "https://stub" };
const token = { status: 200, body: { access_token: "at" } };
const userinfo = { status: 200, body: { data: { id: 777 } } };

console.log("setapp user id");
// The hash is sha256("setapp:" + this), so the spelling is the contract, not the value. A number
// today and a string tomorrow must not make two identities for one person.
eq(setappUserID("12345"), "12345", "a string id passes through");
eq(setappUserID(12345), "12345", "a JSON number becomes the same string");
eq(setappUserID(" 12345 "), "12345", "whitespace is trimmed");
eq(setappUserID("012345"), "12345", "a leading zero canonicalises to one spelling");
eq(setappUserID("9007199254740993"), "9007199254740993", "an id past 2^53 survives as a string");
eq(setappUserID(1.5), null, "a float is refused rather than rounded");
eq(setappUserID(9007199254740993), null, "an unsafe integer is refused, not silently rounded");
eq(setappUserID(""), null, "empty is refused");
eq(setappUserID("abc"), null, "non-numeric is refused");
eq(setappUserID(null), null, "null is refused");
eq(setappUserID({ id: 1 }), null, "an object is refused");

console.log("configuration");
eq(setappMisconfigured({}), true, "a deploy with neither var is misconfigured");
eq(setappMisconfigured({ SETAPP_CLIENT_ID: "id" }), true, "the id alone is not enough");
eq(setappMisconfigured({ SETAPP_CLIENT_SECRET: "s" }), true, "the secret alone is not enough");
eq(setappMisconfigured(env), false, "both vars is configured");
eq(SETAPP_RECHECK_SECONDS, 86_400, "the horizon is 24h exactly, because the horizon IS the cadence");

console.log("access");
eq(await verifySetappAccess("CODE", env, stub({
  "/auth/v1/token": token,
  "/resource/v1/userinfo": userinfo,
  "/resource/v1/application/access": { status: 200, body: { data: { granted: true } } },
})), { status: "active", userID: "777" }, "granted true is an active subscriber");

eq(await verifySetappAccess("CODE", env, stub({
  "/auth/v1/token": token,
  "/resource/v1/userinfo": userinfo,
  "/resource/v1/application/access": { status: 200, body: { data: { granted: false } } },
})), { status: "refused", userID: null }, "granted false is a real refusal");

// Anything but an explicit `true` is a refusal: an unreadable body is never a yes.
eq(await verifySetappAccess("CODE", env, stub({
  "/auth/v1/token": token,
  "/resource/v1/userinfo": userinfo,
  "/resource/v1/application/access": { status: 200, body: {} },
})), { status: "refused", userID: null }, "a missing granted field is not a yes");

console.log("failure map");
// A spent or expired code. 4xx on the exchange means a bad code that no retry fixes, so the
// client gets `bad_license` and doesn't latch it (a fresh code is one launch away).
eq(await verifySetappAccess("CODE", env, stub({ "/auth/v1/token": { status: 400 } })),
   { status: "invalid", userID: null }, "a consumed code is invalid, not unreachable");

eq(await verifySetappAccess("CODE", env, stub({ "/auth/v1/token": { status: 503 } })),
   { status: "unreachable", userID: null }, "vendor 5xx is transient");
eq(await verifySetappAccess("CODE", env, stub({ "/auth/v1/token": { status: 429 } })),
   { status: "unreachable", userID: null }, "vendor 429 is transient");

// Why `unreachable` and `refused` are different words: a scope mistake in our deployment must
// never reach a paying subscriber as "your subscription lapsed", which both clients latch.
eq(await verifySetappAccess("CODE", env, stub({
  "/auth/v1/token": token,
  "/resource/v1/userinfo": userinfo,
  "/resource/v1/application/access": { status: 403 },
})), { status: "unreachable", userID: null }, "our own scope bug never reads as a lapse");

// The same rule one call earlier. `/userinfo` uses the token we just minted from our own client
// id and secret, so a 401 or 403 there is our scope or deploy too. `invalid` would become 403
// `bad_license`, telling a live subscriber their licence is bad over our misconfiguration.
for (const status of [401, 403]) {
  eq(await verifySetappAccess("CODE", env, stub({
    "/auth/v1/token": token,
    "/resource/v1/userinfo": { status },
  })), { status: "unreachable", userID: null },
     `userinfo ${status} is our problem, not the subscriber's`);
}

eq(await verifySetappAccess("CODE", env, stub({
  "/auth/v1/token": token,
  "/resource/v1/userinfo": { status: 200, body: { data: { id: 1.5 } } },
})), { status: "invalid", userID: null }, "an id we cannot canonicalise stops before the access call");

// A network fault, not an HTTP answer.
eq(await verifySetappAccess("CODE", env, async () => { throw new Error("offline"); }),
   { status: "unreachable", userID: null }, "a thrown fetch is transient");

console.log(fail === 0 ? `\n\x1b[32mall ${pass} passed\x1b[0m` : `\n\x1b[31m${fail} failed\x1b[0m, ${pass} passed`);
process.exit(fail === 0 ? 0 : 1);
