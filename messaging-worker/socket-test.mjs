// The half of the suite curl cannot reach: everything that happens over the WebSocket.
//
// Driven by test.sh, which seeds the licenses and devices this expects and passes the two
// tokens in. Node's global WebSocket (v22+) is enough; there is no dependency to install.
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

/// A socket plus a queue, so a test can await the next frame of a given type without
/// racing whatever else the server decided to send first (a presence snapshot, usually).
function connect(token, { presence = true } = {}) {
  const url = `${BASE.replace(/^http/, "ws")}/v1/connect?token=${token}` +
              (presence ? "" : "&presence=0");
  const socket = new WebSocket(url);
  // Pending frames are CONSUMED by next(), so a second `next("accepted")` waits for a
  // genuinely new one instead of handing back the first one again. Getting this wrong makes
  // every later assertion pass against a stale frame, which is worse than failing.
  const pending = [];
  const waiters = [];
  // Monotonic per type, never consumed, so none() can ask "did any MORE arrive" without
  // caring what next() has taken off the queue.
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
    /// Asserts that no FURTHER frame of this type arrives, which is the shape most of the
    /// privacy assertions take.
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
  // Alice's socket is opened BEFORE her code is used, because the frame that tells her who
  // used it is the point. Accepting an invite returns the inviter's details to the ACCEPTER
  // and for a long time told the person who CREATED the code nothing at all: their app had
  // no row and no public key for the new friend, so it dropped every message they sent and
  // had nothing to reply with. Messaging worked only in the direction the code travelled.
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
    // The key as well as the id: without it there is nothing to derive a shared key from,
    // so the friendship would be visible and still unusable.
    want("and gets the key to reply with", true,
         typeof added.public_key === "string" && added.public_key.length > 0);
  } catch (error) {
    bad("the inviter is told who accepted", error.message);
  }
  inviter.close();

  // The offline half of the same problem: a Mac asleep when its code was used has no socket
  // to hear that frame on, and this is the only other way it can ever find out.
  for (const [who, token] of [["inviter", aliceToken], ["accepter", bobToken]]) {
    const list = await (await fetch(`${BASE}/v1/friends`, {
      headers: { authorization: `Bearer ${token}` },
    })).json();
    want(`the ${who} can list the friendship`, 1, list.friends?.length);
  }

  // `let`, because the blocking section below has to take Alice offline and bring her back
  // to make the presence announcement fire at all.
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
  // The server stores and forwards the blob unchanged. If this ever fails, something in
  // the path is re-encoding what it should not be able to read.
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
  // Never "blocked": telling someone they have been blocked is the blocker's to give.
  want("a blocked send is refused as not_friends", "not_friends", rejected.code);
  want("blocked message never arrives", true, await b.none("message"));

  a.send({ t: "typing", peer_id: await bobIdentity() });
  want("blocked typing never arrives", true, await b.none("typing"));

  // Presence too, which is the one inbound handler that had no such guard. `announcePresence`
  // only ever fans out to `blocked = 0`, so blocking stopped US telling THEM; nothing stopped
  // them telling us, and the `reply_to` bounce then sent our own state straight back to the
  // person who had been blocked. Alice has to go fully offline and return, because a second
  // socket on an already-online inbox announces nothing.
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
  // A socket is authenticated once, at the upgrade, and hibernation means it can outlive the
  // process that checked it. Releasing the device has to CLOSE it: without that, an evicted
  // seat, a "Start Over", or a license blocked for abuse left the old connection sending,
  // acking and receiving for as long as it happened to stay up, because nothing re-checks
  // and the client only reconnects on error.
  //
  // BOB's token, not alice's, and last: releasing spends the token, and test.sh's rate-limit
  // section runs after this one against alice.
  const closed = new Promise((resolve) => {
    b.socket.addEventListener("close", () => resolve(true), { once: true });
    setTimeout(() => resolve(false), 3000);
  });
  await post(bobToken, "/v1/devices/release");
  want("releasing the device closes its socket", true, await closed);

  a.close();
  b.close();

  async function bobIdentity() {
    // Derived the same way the Worker does it, from the key test.sh seeded.
    return process.env.BOB_IDENTITY;
  }
}

await main().catch((error) => { bad("suite", error.message); });
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
