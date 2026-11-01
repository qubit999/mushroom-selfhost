// The half of the suite curl cannot reach: everything that happens over the WebSocket.
//
// Driven by test.sh, which seeds the licenses and devices and passes the two tokens in. Node's
// global WebSocket (v22+) is enough; nothing to install.
//
// Same rule as the rest of the repo: never print a token or a ciphertext.

const BASE = process.env.BASE ?? "http://localhost:8788";
const [aliceToken, bobToken] = process.argv.slice(2);

let pass = 0, fail = 0;
const ok = (label) => { pass++; console.log(`  \x1b[32mok\x1b[0m   ${label}`); };
const bad = (label, detail) => {
  fail++;
  console.log(`  \x1b[31mFAIL\x1b[0m ${label}${detail ? ` — ${detail}` : ""}`);
};
const want = (label, expected, actual) =>
  JSON.stringify(expected) === JSON.stringify(actual)
    ? ok(label)
    : bad(label, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

/// A socket plus a queue, so a test can await the next frame of a type without racing whatever
/// the server sent first (usually a presence snapshot).
function connect(token, { presence = true } = {}) {
  const url = `${BASE.replace(/^http/, "ws")}/v1/connect?token=${token}` +
              (presence ? "" : "&presence=0");
  const socket = new WebSocket(url);
  // next() consumes pending frames, so a second `next("accepted")` waits for a new one rather
  // than returning the first again; otherwise later assertions pass against stale frames.
  const pending = [];
  const waiters = [];
  // Monotonic per type, never consumed, so none() can ask "did any more arrive" regardless of
  // what next() took.
  const arrivals = new Map();

  socket.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data);
    arrivals.set(frame.t, (arrivals.get(frame.t) ?? 0) + 1);
    const waiting = waiters.findIndex((w) => w.type === frame.t);
    if (waiting >= 0) {
      waiters.splice(waiting, 1)[0].resolve(frame);
    } else {
      pending.push(frame);
    }
  });

  return {
    socket,
    open: () => new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    }),
    send: (frame) => socket.send(JSON.stringify(frame)),
    /// The next unconsumed frame of `type`, waiting for one if none is queued.
    next: (type, ms = 3000) => new Promise((resolve, reject) => {
      const queued = pending.findIndex((f) => f.t === type);
      if (queued >= 0) return resolve(pending.splice(queued, 1)[0]);
      const waiter = { type, resolve };
      waiters.push(waiter);
      setTimeout(() => {
        const at = waiters.indexOf(waiter);
        if (at >= 0) waiters.splice(at, 1);
        reject(new Error(`timed out waiting for "${type}"`));
      }, ms);
    }),
    /// Asserts that no further frame of this type arrives, the shape of most privacy assertions.
    none: async (type, ms = 800) => {
      const before = arrivals.get(type) ?? 0;
      await new Promise((r) => setTimeout(r, ms));
      return (arrivals.get(type) ?? 0) === before;
    },
    close: () => socket.close(),
  };
}

const post = (token, path, body) =>
  fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });

const sealed = (text) => Buffer.from(`sealed:${text}`).toString("base64");

async function main() {
  console.log("\nsockets");

  // ---------------------------------------------------------------- befriend
  //
  // Alice's socket opens before her code is used, because the frame telling her who used it is
  // the point. Accepting returns the inviter's details to the accepter; without this frame the
  // code's creator has no row or public key for the new friend, drops their messages and can't
  // reply, so messaging would work only in the direction the code travelled.
  const inviter = connect(aliceToken);
  await inviter.open();

  const invite = await (await post(aliceToken, "/v1/invites")).json();
  const accepted = await (await post(bobToken, "/v1/invites/accept", { code: invite.code })).json();
  if (!accepted.ok) { bad("bob accepts alice's invite", JSON.stringify(accepted)); return; }
  ok("bob accepts alice's invite");
  const alice = accepted.peer_id;

  try {
    const added = await inviter.next("friend_added");
    want("the inviter is told who accepted", await bobIdentity(), added.peer_id);
    // The key as well as the id: without it there's no shared key, so the friendship would be
    // visible but unusable.
    want("and gets the key to reply with", true,
         typeof added.public_key === "string" && added.public_key.length > 0);
  } catch (error) {
    bad("the inviter is told who accepted", error.message);
  }
  inviter.close();

  // The offline half: a Mac asleep when its code was used has no socket to hear that frame, and
  // this is its only other way to find out.
  for (const [who, token] of [["inviter", aliceToken], ["accepter", bobToken]]) {
    const list = await (await fetch(`${BASE}/v1/friends`, {
      headers: { authorization: `Bearer ${token}` },
    })).json();
    want(`the ${who} can list the friendship`, 1, list.friends?.length);
  }

  // `let`, because the blocking section takes Alice offline and back to make the presence
  // announcement fire.
  let a = connect(aliceToken);
  const b = connect(bobToken);
  await Promise.all([a.open(), b.open()]);
  ok("both sockets open");

  // ---------------------------------------------------------------- delivery
  a.send({ t: "send", msg_id: "m1", peer_id: await bobIdentity(), ciphertext: sealed("hello"),
           sent_at: Math.floor(Date.now() / 1000) });
  const accepted1 = await a.next("accepted");
  want("sender gets a sequence back", "m1", accepted1.msg_id);

  const arrived = await b.next("message");
  want("recipient gets the message", "m1", arrived.message.msg_id);
  want("routed from alice", alice, arrived.message.peer_id);
  // The server stores and forwards the blob unchanged. If this fails, something is re-encoding
  // what it shouldn't be able to read.
  want("ciphertext survives untouched", sealed("hello"), arrived.message.ciphertext);

  // ---------------------------------------------------------------- dedup
  a.send({ t: "send", msg_id: "m1", peer_id: await bobIdentity(), ciphertext: sealed("hello"),
           sent_at: Math.floor(Date.now() / 1000) });
  const accepted2 = await a.next("accepted");
  want("a retry gets the SAME sequence, not a second message",
       accepted1.seq, accepted2.seq);

  const sync = await (await fetch(`${BASE}/v1/sync?after=0`, {
    headers: { authorization: `Bearer ${bobToken}` },
  })).json();
  want("stored exactly once", 1, sync.messages.length);

  // ---------------------------------------------------------------- delivered
  b.send({ t: "ack", seq: accepted1.seq });
  try {
    const delivered = await a.next("delivered");
    want("ack turns into a delivered receipt", "m1", delivered.msg_id);
  } catch (error) {
    bad("ack turns into a delivered receipt", error.message);
  }

  // ---------------------------------------------------------------- our own Macs
  //
  // One identity, several Macs. `deliver` files a message in the recipient's inbox, so our
  // outbox is stored nowhere; the app copies what it sends to its own inbox, or a second Mac
  // shows a friend's messages and none of the replies. Same for names and read state.
  //
  // Alice's second socket stands in for that Mac. It opens first, so a frame arriving before
  // it listens can't make this pass by accident.
  const aliceMac2 = connect(aliceToken);
  await aliceMac2.open();

  a.send({ t: "send", msg_id: "self1", peer_id: alice, ciphertext: sealed("to myself"),
           sent_at: Math.floor(Date.now() / 1000) });
  try {
    const selfAccepted = await a.next("accepted");
    want("a message to our own identity is accepted", "self1", selfAccepted.msg_id);
  } catch (error) {
    bad("a message to our own identity is accepted", error.message);
  }

  // The key assertion; everything else here passes even if the send goes nowhere.
  try {
    const onMac2 = await aliceMac2.next("message");
    want("it reaches the user's other Mac", "self1", onMac2.message.msg_id);
    want("stamped from ourselves, which is what tells the app it is ours",
         alice, onMac2.message.peer_id);
    want("ciphertext survives untouched", sealed("to myself"), onMac2.message.ciphertext);
  } catch (error) {
    bad("it reaches the user's other Mac", error.message);
  }

  // And nobody else's. `send()` fans out to every socket on one inbox, but filing it in the
  // friend's inbox by mistake would look identical from Alice's side.
  want("and never reaches the friend", true, await b.none("message"));

  const selfSync = await (await fetch(`${BASE}/v1/sync?after=0`, {
    headers: { authorization: `Bearer ${aliceToken}` },
  })).json();
  want("stored in our OWN inbox, for a Mac that was not connected", 1, selfSync.messages.length);
  aliceMac2.close();

  // ---------------------------------------------------------------- typing
  a.send({ t: "typing", peer_id: await bobIdentity() });
  try {
    const typing = await b.next("typing");
    want("typing reaches the peer", alice, typing.peer_id);
  } catch (error) {
    bad("typing reaches the peer", error.message);
  }
  // Ephemeral: it must not have become a stored row.
  const afterTyping = await (await fetch(`${BASE}/v1/sync?after=0`, {
    headers: { authorization: `Bearer ${bobToken}` },
  })).json();
  want("typing stored nothing", 1, afterTyping.messages.length);

  // ---------------------------------------------------------------- presence
  const c = connect(bobToken);
  await c.open();
  try {
    const snapshot = await c.next("presence_snapshot");
    want("snapshot lists the online friend", [alice], snapshot.online);
  } catch (error) {
    bad("snapshot lists the online friend", error.message);
  }
  c.close();

  // ---------------------------------------------------------------- blocking
  await post(bobToken, `/v1/friends/${alice}/block`);
  a.send({ t: "send", msg_id: "m2", peer_id: await bobIdentity(), ciphertext: sealed("nope"),
           sent_at: Math.floor(Date.now() / 1000) });
  const rejected = await a.next("rejected");
  // Never "blocked": revealing a block is the blocker's call.
  want("a blocked send is refused as not_friends", "not_friends", rejected.code);
  want("blocked message never arrives", true, await b.none("message"));

  a.send({ t: "typing", peer_id: await bobIdentity() });
  want("blocked typing never arrives", true, await b.none("typing"));

  // Presence too. `announcePresence` skips blocked peers, but without the inbound guard they
  // could still tell us, and the `reply_to` bounce would send our state back to them. Alice
  // goes fully offline and back, since a second socket on an online inbox announces nothing.
  a.close();
  await new Promise((resolve) => setTimeout(resolve, 300));
  a = connect(aliceToken);
  await a.open();
  want("a blocked peer's presence never arrives", true, await b.none("presence"));

  await post(bobToken, `/v1/friends/${alice}/unblock`);
  a.send({ t: "send", msg_id: "m3", peer_id: await bobIdentity(), ciphertext: sealed("again"),
           sent_at: Math.floor(Date.now() / 1000) });
  const accepted3 = await a.next("accepted");
  want("unblock restores delivery", "m3", accepted3.msg_id);

  // ---------------------------------------------------------------- forward compat
  a.send({ t: "reaction", emoji: "🍄" });
  a.send({ t: "ping" });
  try {
    await a.next("pong");
    ok("an unknown frame is ignored, not fatal");
  } catch {
    bad("an unknown frame is ignored, not fatal", "socket stopped answering");
  }

  // ---------------------------------------------------------------- removal
  await post(bobToken, `/v1/friends/${alice}/remove`);
  const afterRemove = await (await fetch(`${BASE}/v1/sync?after=0`, {
    headers: { authorization: `Bearer ${bobToken}` },
  })).json();
  want("removing a friend drops the stored ciphertext", 0, afterRemove.messages.length);

  // ---------------------------------------------------------------- revocation
  //
  // A socket is authenticated once, at the upgrade, and hibernation lets it outlive that.
  // Releasing the device must close it, or an evicted seat, "Start Over" or a blocked license
  // leaves the old connection working while it stays up; the client only reconnects on error.
  //
  // Bob's token, not Alice's, and last: releasing spends the token, and test.sh's rate-limit
  // section runs after this against Alice.
  const closed = new Promise((resolve) => {
    b.socket.addEventListener("close", () => resolve(true), { once: true });
    setTimeout(() => resolve(false), 3000);
  });
  await post(bobToken, "/v1/devices/release");
  want("releasing the device closes its socket", true, await closed);

  a.close();
  b.close();

  async function bobIdentity() {
    // Derived as the Worker does, from the key test.sh seeded.
    return process.env.BOB_IDENTITY;
  }
}

await main().catch((error) => { bad("suite", error.message); });
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
