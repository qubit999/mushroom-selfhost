/// An R2 binding, backed by the blob sidecar (selfhost/blobd.mjs) over a unix socket.
///
/// The surface is eight call sites in files-worker and nothing else: `put`, `get`, and `delete`
/// in both its string and array forms. What makes this more than a URL rewrite is that three of
/// R2's behaviours are load-bearing in the download path, and a shim that got them merely close
/// would fail in ways the tests are built to catch:
///
///  1. A missing key returns null, it does not throw. `!head` at files-worker:164 and `!object`
///     at :679 are both real paths (a magic-byte check on a vanished object, and a lifecycle
///     rule that got there first).
///  2. An UNSATISFIABLE RANGE THROWS, it does not return null. :671 catches exactly that and
///     answers 416. A shim returning null there would turn a bad Range header into a 404.
///  3. `.range` is populated even for a NON-ranged get. :694 gates its 206 on the request
///     carrying a Range precisely because R2 fills `.range` in regardless, and an earlier
///     version of that gate turned every ordinary download into a 206.
///
/// `httpMetadata` on put is DISCARDED, deliberately. Nothing ever reads it back: the download
/// path sets `content-type: application/octet-stream` unconditionally (:684) and builds
/// content-disposition from the database row (:685). The blob store holds bytes and nothing
/// else, which is one fewer thing to keep consistent.

const ORIGIN = "http://blob";

/// The sidecar always sends `Content-Range: bytes start-end/total`, on a 200 as well as a 206,
/// so the resolved offsets come back without the shim having to recompute them.
function parseContentRange(header) {
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(header ?? "");
  if (!match) return null;
  const [, start, end, total] = match;
  return { offset: Number(start), length: Number(end) - Number(start) + 1, size: Number(total) };
}

/// R2 accepts a range as either `{offset, length}` (files-worker:163, the magic-byte sniff) or a
/// whole `Headers` object it parses itself (:670, forwarding the client's Range). Normalise both
/// into a Range header for the sidecar, which does the seek.
function rangeHeader(range) {
  if (!range) return null;
  if (typeof range.get === "function") return range.get("range");     // a Headers
  const { offset, length } = range;
  if (typeof offset !== "number") return null;
  return typeof length === "number" ? `bytes=${offset}-${offset + length - 1}` : `bytes=${offset}-`;
}

export function makeR2(binding) {
  return {
    async get(key, options) {
      const header = rangeHeader(options?.range);
      const response = await binding.fetch(`${ORIGIN}/${key}`, {
        headers: header ? { range: header } : {},
      });

      if (response.status === 404) return null;              // (1) missing is null, not a throw
      if (response.status === 416) {
        // (2) R2 throws on an unsatisfiable range. files-worker catches this and answers 416,
        // and that catch is the only reason a malformed Range is not a 500.
        await response.body?.cancel();
        throw new Error("R2 range not satisfiable");
      }
      if (!response.ok) throw new Error(`selfhost R2 get: ${response.status}`);

      const resolved = parseContentRange(response.headers.get("content-range"));
      const size = resolved ? resolved.size : Number(response.headers.get("content-length") ?? 0);
      return {
        // `.size` is the FULL object size even on a ranged read: files-worker writes it into D1
        // at :638 and renders it in the content-range at :697.
        size,
        body: response.body,
        // (3) always present, ranged or not.
        range: resolved
          ? { offset: resolved.offset, length: resolved.length }
          : { offset: 0, length: size },
        arrayBuffer: () => response.arrayBuffer(),
      };
    },

    /// `body` is `request.body` handed straight through, unwrapped. files-worker:611 is explicit
    /// that R2 needs a fixed-length stream and that wrapping it loses that, so nothing here
    /// touches it either.
    async put(key, body, _options) {
      const response = await binding.fetch(`${ORIGIN}/${key}`, { method: "PUT", body });
      if (!response.ok) throw new Error(`selfhost R2 put: ${response.status}`);
      // The exact byte count the sidecar wrote, because it lands in D1 as the file's size.
      return { size: (await response.json()).size };
    },

    /// A string (:622, :632, :743, :969) or an array (:1029, the expiry sweep).
    async delete(key) {
      for (const one of Array.isArray(key) ? key : [key]) {
        const response = await binding.fetch(`${ORIGIN}/${one}`, { method: "DELETE" });
        // 404 is success, same as R2: several call sites delete something that may be gone.
        if (!response.ok && response.status !== 404) {
          throw new Error(`selfhost R2 delete: ${response.status}`);
        }
      }
    },
  };
}
