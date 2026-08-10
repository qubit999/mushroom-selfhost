// The one assertion curl cannot make: a LIVE WebSocket has to stop working when the licence's
// entitlement horizon passes underneath it.
//
// Driven by test-entitlement.sh, which seeds the licence and the device and passes the token in.
// Node's global WebSocket (v22+) is enough; there is no dependency to install.
//
// Two modes, and the pair is the point. "alive" is the control: with no horizon the very same
// ping must come back as a pong, so a "lapses" run that closes for some unrelated reason (a dead
// server, a bad token, a renamed frame) cannot be mistaken for the clause doing its job.
//
//   alive   NULL entitled_until  -> ping answers pong
//   lapses  a horizon seconds away -> the first frame AFTER it passes closes the socket
//
// The lapse probe takes the FRAME TYPE as a third argument, and that is the whole reason this
// file is worth more than a curl. `stillAuthorized` guards send, ack, typing and ping, and it
// used to guard ping ALONE: a lapsed subscriber whose client simply stopped pinging kept sending
// and acking indefinitely. A probe that only ever pings reproduces exactly that blind spot, so
// deleting the guard from `send` would leave this suite green. Drive every guarded frame.
//
// A frame that is not `ping` produces no reply of its own, so "still open" cannot be read off a
// silence. When the probe frame does not close the socket, the script sends a ping afterwards: a
// pong then proves the socket was alive and only THAT frame's guard was missing, which is a far
// more precise failure than "nothing happened".
//
// Same rule as the rest of the repo: never print a token.

const BASE = process.env.BASE ?? "http://localhost:8788";
const [token, mode, frameType = "ping"] = process.argv.slice(2);

// Enough shape for the handler behind each guard; the guard runs first, so these never need to
// be deliverable. `peer` is 64 hex chars because `friendAction` and the typing relay validate it.
const PROBE = {
  ping: { t: "ping" },
  typing: { t: "typing", peer: "0".repeat(64), on: true },
  ack: { t: "ack", seq: 1 },
  send: { t: "send", peer: "0".repeat(64), body: "probe", id: "probe-1" },
}[frameType] ?? { t: frameType };
const LAPSE_WAIT_MS = Number(process.env.LAPSE_WAIT_MS ?? 5000);

const ok = (label) => { console.log(`  \x1b[32mok\x1b[0m   ${label}`); return 0; };
const bad = (label, detail) => {
  console.log(`  \x1b[31mFAIL\x1b[0m ${label}${detail ? ` (${detail})` : ""}`);
  return 1;
};

const socket = new WebSocket(`${BASE.replace(/^http/, "ws")}/v1/connect?token=${token}`);

const settled = (ms) => new Promise((resolve) => {
  let done = false;
  const finish = (value) => { if (!done) { done = true; resolve(value); } };
  socket.addEventListener("message", (event) => {
    // Guarded, and not belt-and-braces: this socket also carries hello, message, ack, typing and
    // presence frames, and a binary one arrives as a Blob rather than a string. An uncaught throw
    // in an EventTarget listener leaves this promise unresolved, so it falls through to the
    // timeout and reports "nothing" - a FAIL on the single assertion this whole file exists for,
    // for a reason that has nothing to do with the entitlement clause.
    let frame;
    try { frame = JSON.parse(event.data); } catch { return; }
    if (frame?.t === "pong") finish("pong");
  });
  socket.addEventListener("close", () => finish("closed"));
  setTimeout(() => finish("nothing"), ms);
});

let exit = 1;
try {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("socket never opened")), { once: true });
    setTimeout(() => reject(new Error("socket never opened")), 5000);
  });

  if (mode === "lapses") {
    // The horizon was seeded a few seconds out, so it passes while this socket sits there
    // authenticated. Nothing pushes that fact at the connection: `stillAuthorized` is the only
    // thing that can notice, and it only runs when a frame arrives.
    await new Promise((resolve) => setTimeout(resolve, LAPSE_WAIT_MS));
    socket.send(JSON.stringify(PROBE));
    const label = `a live socket is dropped once the horizon passes (${frameType})`;
    let what = await settled(4000);
    // Silence from a non-ping probe is ambiguous on its own: the guard may have been skipped, or
    // the server may simply be gone. A ping disambiguates, because ping is guarded too, so on a
    // lapsed licence it must ALSO close rather than pong.
    if (what === "nothing" && frameType !== "ping" && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ t: "ping" }));
      const after = await settled(4000);
      what = after === "closed" ? "alive-then-closed" : after;
    }
    exit = what === "closed"
      ? ok(label)
      : bad(label,
            what === "pong"
              ? "it answered normally: a lapsed member keeps Friends for as long as the app stays open"
              : what === "alive-then-closed"
                ? `the socket was alive and accepted a '${frameType}' frame: stillAuthorized does not guard it`
                : "the socket neither answered nor closed");
  } else {
    socket.send(JSON.stringify({ t: "ping" }));
    const what = await settled(4000);
    exit = what === "pong"
      ? ok("a socket on an unexpired licence still answers")
      : bad("a socket on an unexpired licence still answers",
            `got ${what}: the lapse check below would pass for the wrong reason`);
  }
} catch (error) {
  exit = bad(`socket ${mode}`, error.message);
}

try { socket.close(); } catch { /* already gone */ }
process.exit(exit);
