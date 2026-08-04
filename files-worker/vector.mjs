// The shared wire vector for the sealed-file format, asserted from the JS side.
//
//   "MSH1" (4) || nonce (12) || AES-GCM-256 ciphertext || tag (16)
//
// The Mac seals with CryptoKit (Sources/MushroomPetKit/SporeCrypto.swift) and the receive
// page in worker.js opens with WebCrypto. A unit test on either side alone passes happily
// while the two disagree about the layout, and the result of that is a link nobody can open,
// so this file exists to make the two agree in public. The numbers below are the same ones in
// SporeVector in Tests/MushroomPetKitTests/SporeCryptoTests.swift. Change them together or
// not at all.
//
//   node vector.mjs
//
// Run by test.sh, and standalone in a second.

const KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const NONCE = new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                              0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]);
const PLAINTEXT = "mushroom spore";
const SEALED_HEX =
  "4d534831a0a1a2a3a4a5a6a7a8a9aaab8b6d0f4537a46dd24216f7bc751f3d730a7643841d824036d8f0ce6635d8";

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (text) => Uint8Array.from(text.match(/../g).map((b) => parseInt(b, 16)));

// Exactly what the receive page does with the fragment.
const keyBytes = Uint8Array.from(
  atob(KEY.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

let failures = 0;
const check = (label, condition) => {
  console.log(`  ${condition ? "\x1b[32mok\x1b[0m  " : "\x1b[31mFAIL\x1b[0m"} ${label}`);
  if (!condition) failures++;
};

const sealed = fromHex(SEALED_HEX);
check("key is 32 bytes", keyBytes.length === 32);
check("magic is MSH1", new TextDecoder().decode(sealed.slice(0, 4)) === "MSH1");
check("nonce is where Swift put it", hex(sealed.slice(4, 16)) === hex(NONCE));
check("overhead is 32 bytes", sealed.length === PLAINTEXT.length + 32);

// Open it the way the page does.
const imported = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
const opened = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: sealed.slice(4, 16) }, imported, sealed.slice(16));
check("Swift's bytes open under WebCrypto",
      new TextDecoder().decode(opened) === PLAINTEXT);

// And seal it back, to prove the agreement runs both ways: a page that could only read
// would not catch WebCrypto and CryptoKit disagreeing about where the tag goes.
const sealer = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
const resealed = new Uint8Array(await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: NONCE }, sealer, new TextEncoder().encode(PLAINTEXT)));
check("WebCrypto reproduces Swift's bytes",
      "4d534831" + hex(NONCE) + hex(resealed) === SEALED_HEX);

console.log(failures ? `\n  ${failures} failed` : "\n  vector ok");
process.exit(failures ? 1 : 0);
