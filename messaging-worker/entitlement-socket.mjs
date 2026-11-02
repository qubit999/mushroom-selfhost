// The one assertion curl can't make: a live WebSocket must stop working when the licence's
// entitlement horizon passes underneath it.
//
// Driven by test-entitlement.sh, which seeds the licence and device and passes the token in.
// Node's global WebSocket (v22+) is enough; nothing to install.
//
// Two modes, and the pair is the point. "alive" is the control: with no horizon the same ping
// must pong, so a "lapses" run that closes for an unrelated reason (dead server, bad token,
// renamed frame) can't pass for the clause doing its job.
//
//   alive   NULL entitled_until  -> ping answers pong
//   lapses  a horizon seconds away -> the first frame after it passes closes the socket
//
// The lapse probe takes the frame type as a third argument, which is what makes this worth more
// than a curl. `stillAuthorized` guards send, ack, typing and ping. A ping-only probe can't see a
// lapsed client that stops pinging but keeps sending and acking, so removing the guard from
// `send` would leave this green. Drive every guarded frame.
//
// Non-ping frames get no reply, so silence doesn't prove "still open". If the probe frame doesn't
// close the socket, the script pings: a pong proves the socket was alive and only that frame's
// guard is missing, a far more precise failure than "nothing happened".
//
// Same rule as the rest of the repo: never print a token.

const BASE = process.env.BASE ?? "http://localhost:8788";
const [token, mode, frameType = "ping"] = process.argv.slice(2);

// Enough shape for each guarded handler; the guard runs first, so these needn't be deliverable.
// `peer` is 64 hex chars because `friendAction` and the typing relay validate it.
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

const socket = new WebSocket(`${BASE.replace(/^http/, "ws")}/v1/connect`, { headers: { authorization: `Bearer ${token}` } });

const settled = (ms) => new Promise((resolve) => {
  let done = false;
  const finish = (value) => { if (!done) { done = true; resolve(value); } };
  socket.addEventListener("message", (event) => {
    // Guarded for real: this socket also carries other frames, and a binary one arrives as a
    // Blob. A throw in an EventTarget listener leaves the promise unresolved, so it times out and
    // reports "nothing", failing this file's one assertion for an unrelated reason.
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
    // The horizon was seeded seconds out, so it passes while this socket sits authenticated.
    // Only `stillAuthorized` can notice, and only when a frame arrives.
    await new Promise((resolve) => setTimeout(resolve, LAPSE_WAIT_MS));
    socket.send(JSON.stringify(PROBE));
    const label = `a live socket is dropped once the horizon passes (${frameType})`;
    let what = await settled(4000);
    // Silence from a non-ping probe is ambiguous: a skipped guard, or a dead server. A ping
    // settles it, because ping is guarded too, so on a lapsed licence it must also close.
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
