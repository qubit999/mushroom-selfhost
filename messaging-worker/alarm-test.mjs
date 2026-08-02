// Alice sends Bob one message and leaves. Bob never connects and never acks, which is the
// exact state `deliver` arms the push alarm for. Driven by alarm-test.sh.
//
// Node's global WebSocket (v22+) is enough; there is no dependency to install.
// Same rule as the rest of the repo: never print a token or a ciphertext.

const BASE = process.env.BASE ?? "http://localhost:8799";
const [aliceToken, bobID] = process.argv.slice(2);

const socket = new WebSocket(`${BASE.replace(/^http/, "ws")}/v1/connect?token=${aliceToken}`);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

const settled = new Promise((resolve) => {
  socket.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data);
    if (frame.t === "accepted" || frame.t === "rejected") resolve(frame);
  });
});

socket.send(JSON.stringify({
  t: "send",
  msg_id: "alarm-test-0001",
  peer_id: bobID,
  ciphertext: "Y2lwaGVydGV4dA==",
  sent_at: Math.floor(Date.now() / 1000),
}));

const frame = await settled;
console.log(`  send -> ${frame.t}${frame.code ? ` (${frame.code})` : ""}`);
socket.close();
process.exit(frame.t === "accepted" ? 0 : 1);
