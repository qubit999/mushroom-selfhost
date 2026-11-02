// node worker-shared/client-bucket-test.mjs
import assert from "node:assert/strict";
import { clientBucket } from "./client-bucket.js";

assert.equal(clientBucket("203.0.113.9"), "203.0.113.9");
assert.equal(clientBucket(null), "unknown");
const net = "2001:db8:aa:1::/64";
for (const ip of ["2001:db8:aa:1::1", "2001:0db8:00aa:0001:ffff:1:2:3", "2001:DB8:AA:1:0:0:0:9"]) {
  assert.equal(clientBucket(ip), net, ip);
}
assert.notEqual(clientBucket("2001:db8:aa:2::1"), net);
assert.equal(clientBucket("::1"), "0:0:0:0::/64");
assert.equal(clientBucket("2001:db8::"), "2001:db8:0:0::/64");
console.log("client-bucket: ok");
