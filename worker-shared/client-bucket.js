/// The rate-limit key for a client address.
///
/// IPv4 as is. IPv6 by its /64: one subscriber usually holds a whole /64 (often far more), so
/// keying on the full address hands a script a fresh bucket per request and the limit means
/// nothing. A /64 is the smallest block an ISP routes to one customer.
///
/// `prefixGroups` widens the IPv6 key (3 is a /48) for the coarser second limit on activation:
/// a host with a routed /48 otherwise holds 65,536 buckets. IPv4 is unchanged by it.
export function clientBucket(ip, prefixGroups = 4) {
  const address = String(ip ?? "").trim().toLowerCase();
  if (!address) return "unknown";
  if (!address.includes(":")) return address;
  const [head, tail] = address.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  // An embedded IPv4 tail (::ffff:1.2.3.4) counts as two groups; it's past the /64 either way.
  const width = (parts) => parts.reduce((n, p) => n + (p.includes(".") ? 2 : 1), 0);
  const groups = tail === undefined
    ? left
    : [...left, ...Array(Math.max(0, 8 - width(left) - width(right))).fill("0"), ...right];
  return groups.slice(0, prefixGroups).map((g) => (parseInt(g, 16) || 0).toString(16)).join(":")
    + `::/${prefixGroups * 16}`;
}
