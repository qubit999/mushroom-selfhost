// Does a proxy in front of the box keep a hibernated WebSocket alive?
//
// The existing suites can't answer this: socket-test.mjs finishes within seconds, never reaching
// the idle timeout of whatever terminates TLS. Mushroom's sockets stay open for hours (the inbox
// hibernates them), and a proxy that quietly drops idle connections degrades messaging long after
// a deployment looks fine.
//
// Usage:
//   BASE=https://box ALICE=<token> BOB=<token> BOB_ID=<hex> node idle-socket-probe.mjs [seconds]
//
// Node 22+, global WebSocket, no dependencies. Prints ids and states, never a token.
const BASE = process.env.BASE;
const ALICE = process.env.ALICE;
const BOB = process.env.BOB;
const BOB_ID = process.env.BOB_ID;
const IDLE_SECONDS = Number(process.argv[2] ?? 180);

if (!BASE || !ALICE || !BOB || !BOB_ID) {
  console.error("set BASE, ALICE, BOB, BOB_ID");
  process.exit(2);
}

const wsURL = `${BASE.replace(/^http/, "ws")}/v1/connect`;
const open = (token) =>
  new Promise((resolve, reject) => {
    // The token goes in the header, the way the app sends it.
    const socket = new WebSocket(wsURL, { headers: { authorization: `Bearer ${token}` } });
    socket.addEventListener("open", () => resolve(socket), { once: true });
    socket.addEventListener("error", (e) => reject(new Error(String(e.message ?? "socket error"))), { once: true });
  });

let failures = 0;
const ok = (m) => console.log(`  \x1b[32mok\x1b[0m   ${m}`);
const bad = (m) => { failures++; console.log(`  \x1b[31mFAIL\x1b[0m ${m}`); };

const alice = await open(ALICE);
const bob = await open(BOB);
ok("both sockets opened over the proxy");

// Nothing is sent during the wait, on purpose: any keepalive the proxy needs must come from the
// connection itself, not from this probe's traffic.
console.log(`  ... holding both sockets idle for ${IDLE_SECONDS}s, sending nothing`);
const closes = [];
for (const [name, socket] of [["alice", alice], ["bob", bob]]) {
  socket.addEventListener("close", (e) => closes.push(`${name} closed: code=${e.code}`), { once: true });
}
await new Promise((r) => setTimeout(r, IDLE_SECONDS * 1000));

if (closes.length) {
  for (const c of closes) bad(`a socket did not survive the idle period, ${c}`);
} else {
  ok(`both sockets still open after ${IDLE_SECONDS}s idle`);
}

// Surviving isn't enough; the socket must still work. A half-open connection neither side has
// noticed looks healthy until it drops a message.
const delivered = new Promise((resolve) => {
  bob.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data);
    if (frame.t === "message") resolve({ kind: "message", frame });
  });
  // A malformed frame comes back as `rejected` on the sender's socket. Watching for it turns a
  // probe bug into a clear error instead of a 20-second timeout that looks exactly like a proxy
  // dropping messages.
  alice.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data);
    if (frame.t === "rejected") resolve({ kind: "rejected", frame });
  });
  setTimeout(() => resolve(null), 20000);
});

// Field names must match the wire contract exactly: `peer_id`, not `peer`.
alice.send(JSON.stringify({
  t: "send",
  msg_id: `idle-probe-${IDLE_SECONDS}`,
  peer_id: BOB_ID,
  ciphertext: Buffer.from("idle probe payload").toString("base64"),
  sent_at: Math.floor(Date.now() / 1000),
}));

const got = await delivered;
if (got?.kind === "message") ok("a message still arrives on a socket that has been idle");
else if (got?.kind === "rejected") bad(`the server rejected the frame: ${got.frame.code}`);
else bad("nothing arrived: the connection survived but stopped carrying messages");

alice.close();
bob.close();
console.log(failures ? `\n  ${failures} failed` : "\n  idle socket probe passed");
process.exit(failures ? 1 : 0);
