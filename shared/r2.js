/// An R2 binding, backed by the blob sidecar (selfhost/blobd.mjs) over a unix socket.
///
/// The surface is files-worker's handful of call sites: `put`, `get`, and `delete` in string and
/// array forms. Three R2 behaviours are load-bearing in the download path, and a shim that only
/// got them close would fail the tests:
///
///  1. A missing key returns null, not a throw. `!head` in `storedBytesMatchType` and `!object`
///     in `download` are both real paths (a magic-byte check on a vanished object, a lifecycle
///     rule that got there first).
///  2. An unsatisfiable range throws, not null. `download` catches it and answers 416; null
///     would turn a bad Range header into a 404.
///  3. `.range` is populated even for a non-ranged get. `download` gates its 206 on the request
///     carrying a Range because R2 fills `.range` regardless; otherwise every download is a 206.
///
/// `httpMetadata` on put is discarded on purpose. Nothing reads it back: `download` always sets
/// `content-type: application/octet-stream` and builds content-disposition from the database
/// row. The blob store holds bytes only, one less thing to keep consistent.

const ORIGIN = "http://blob";

/// The sidecar always sends `Content-Range: bytes start-end/total`, on a 200 as well as a 206,
/// so the shim needn't recompute the offsets.
function parseContentRange(header) {
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(header ?? "");
  if (!match) return null;
  const [, start, end, total] = match;
  return { offset: Number(start), length: Number(end) - Number(start) + 1, size: Number(total) };
}

/// R2 accepts a range as `{offset, length}` (the magic-byte sniff in `storedBytesMatchType`) or
/// a whole `Headers` it parses itself (`download`, forwarding the client's Range). Both become a
/// Range header for the sidecar, which does the seek.
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
        // (2) R2 throws on an unsatisfiable range. files-worker catches it and answers 416;
        // that catch is the only reason a malformed Range isn't a 500.
        await response.body?.cancel();
        throw new Error("R2 range not satisfiable");
      }
      if (!response.ok) throw new Error(`selfhost R2 get: ${response.status}`);

      const resolved = parseContentRange(response.headers.get("content-range"));
      const size = resolved ? resolved.size : Number(response.headers.get("content-length") ?? 0);
      return {
        // `.size` is the full object size even on a ranged read: `uploadContent` writes it to D1
        // and `download` renders it in content-range.
        size,
        body: response.body,
        // (3) always present, ranged or not.
        range: resolved
          ? { offset: resolved.offset, length: resolved.length }
          : { offset: 0, length: size },
        arrayBuffer: () => response.arrayBuffer(),
      };
    },

    /// `body` is `request.body`, passed through unwrapped: R2 needs a fixed-length stream and
    /// wrapping loses that (see `uploadContent`).
    async put(key, body, _options) {
      const response = await binding.fetch(`${ORIGIN}/${key}`, { method: "PUT", body });
      if (!response.ok) throw new Error(`selfhost R2 put: ${response.status}`);
      // The exact byte count the sidecar wrote; it lands in D1 as the file's size.
      return { size: (await response.json()).size };
    },

    /// A string (`uploadContent`, `deleteFile`, `purgeFile`) or an array (`sweep`).
    async delete(key) {
      for (const one of Array.isArray(key) ? key : [key]) {
        const response = await binding.fetch(`${ORIGIN}/${one}`, { method: "DELETE" });
        // 404 is success, as in R2: several callers delete things that may be gone.
        if (!response.ok && response.status !== 404) {
          throw new Error(`selfhost R2 delete: ${response.status}`);
        }
      }
    },
  };
}
