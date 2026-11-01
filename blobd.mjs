// The blob store behind `env.FILES`, on local disk.
//
// workerd ships no R2, and its `disk` service can't stand in: GET and HEAD only, no DELETE or
// Range (checked in workerd.capnp and server.c++). Both matter. files-worker deletes on user
// request, on a magic-byte rejection and in the hourly sweep; a filesystem sweep instead would
// leave bytes on disk for up to two days after someone pressed delete. Ranged reads are how the
// app resumes a download.
//
// So: about a hundred lines of node:http and node:fs on a unix socket. No dependencies, no
// network port, and a ranged read is a seek, not a stream-and-discard.
//
// Files reach 95 MiB by default and on-prem may raise that (the 95 is a Cloudflare body cap that
// doesn't apply here), so every path streams. Nothing reads a whole object into memory.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const SOCKET = process.env.BLOB_SOCKET;
if (!process.env.BLOB_ROOT || !SOCKET) {
  console.error("blobd: set BLOB_ROOT and BLOB_SOCKET");
  process.exit(2);
}
// Resolved, not taken as typed. The containment check below compares against it, so a relative
// or trailing-slash BLOB_ROOT would fail every key, and "bad key" for everything reads as
// corruption, not a config typo. Our units set an absolute path, but operators set it by hand.
const ROOT = path.resolve(process.env.BLOB_ROOT);

/// The Worker builds keys as `f/<uuid>`, so this should never reject anything real. But "should
/// never" isn't a security boundary: this turns a string off a socket into a filesystem path,
/// exactly where traversal gets in.
function resolveKey(urlPath) {
  const key = decodeURIComponent(urlPath.replace(/^\/+/, ""));
  if (!key || key.length > 512) return null;
  if (!/^[A-Za-z0-9._/-]+$/.test(key)) return null;
  if (key.split("/").some((part) => part === "" || part === "." || part === "..")) return null;
  const full = path.resolve(ROOT, key);
  // Belt and braces: even with the checks above, refuse anything that escaped the root.
  if (full !== ROOT && !full.startsWith(ROOT + path.sep)) return null;
  return full;
}

/// `bytes=N-M`, `bytes=N-` and `bytes=-N`, resolved against a known size.
/// Returns null for a header we don't understand (no range, as R2 does) and "unsatisfiable"
/// for one we understand but can't serve.
function parseRange(header, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec((header ?? "").trim());
  if (!match) return null;
  const [, rawStart, rawEnd] = match;
  let start;
  let end;
  if (rawStart === "") {
    if (rawEnd === "") return "unsatisfiable";
    const suffix = Number(rawEnd);
    if (suffix === 0) return "unsatisfiable";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(rawStart);
    end = rawEnd === "" ? size - 1 : Math.min(Number(rawEnd), size - 1);
  }
  if (!Number.isInteger(start) || !Number.isInteger(end)) return "unsatisfiable";
  if (start >= size || start > end) return "unsatisfiable";
  return { start, end };
}

const send = (res, status, body = "") => {
  res.writeHead(status, { "content-type": "text/plain" });
  res.end(body);
};

// A throw out of a request listener kills the process, and every transfer in flight with it, so
// one bad request (a malformed %-escape, a key naming a directory) would be a restart loop.
const server = http.createServer((req, res) => {
  try {
    handle(req, res);
  } catch (error) {
    console.error("blobd:", error?.message ?? error);
    if (res.headersSent) res.destroy();
    else send(res, 500, "error\n");
  }
});

function handle(req, res) {
  let file;
  try {
    file = resolveKey(new URL(req.url, "http://blob").pathname);
  } catch {
    file = null;   // decodeURIComponent on a broken escape
  }
  if (!file) return send(res, 400, "bad key\n");

  if (req.method === "PUT") {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // Write to a temp name and rename into place, so a failed or truncated upload is never
    // served as a whole object. rename(2) is atomic within a filesystem.
    const temp = `${file}.${process.pid}.${Date.now()}.part`;
    let written = 0;
    req.on("data", (chunk) => { written += chunk.length; });
    const out = fs.createWriteStream(temp);
    req.pipe(out);
    out.on("error", () => { fs.rmSync(temp, { force: true }); send(res, 500, "write failed\n"); });
    req.on("aborted", () => { out.destroy(); fs.rmSync(temp, { force: true }); });
    out.on("finish", () => {
      try {
        fs.renameSync(temp, file);
      } catch {
        fs.rmSync(temp, { force: true });
        return send(res, 500, "rename failed\n");
      }
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify({ size: written }));
    });
    return undefined;
  }

  if (req.method === "DELETE") {
    // Missing is success: the Worker may delete something already gone, and R2 doesn't complain
    // either. A directory isn't an object, so it's "missing" too, never removed.
    let isFile = false;
    try { isFile = fs.statSync(file).isFile(); } catch {}
    if (isFile) fs.rmSync(file, { force: true });
    return send(res, 204);
  }

  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "method\n");

  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    return send(res, 404, "not found\n");
  }
  if (!stat.isFile()) return send(res, 404, "not found\n");

  const range = parseRange(req.headers.range, stat.size);
  if (range === "unsatisfiable") {
    res.writeHead(416, { "content-range": `bytes */${stat.size}` });
    return res.end();
  }

  const start = range ? range.start : 0;
  const end = range ? range.end : Math.max(0, stat.size - 1);
  const length = stat.size === 0 ? 0 : end - start + 1;

  // Content-Range is always sent, on a 200 as well as a 206: the shim reads the offsets back to
  // populate `.range`, which R2 fills in even for a plain get.
  res.writeHead(range ? 206 : 200, {
    "content-type": "application/octet-stream",
    "content-length": String(length),
    "content-range": `bytes ${start}-${end}/${stat.size}`,
  });
  if (req.method === "HEAD" || stat.size === 0) return res.end();
  // A stream error comes later and outside the try above: end the response rather than crash.
  return fs.createReadStream(file, { start, end }).on("error", () => res.destroy()).pipe(res);
}

fs.mkdirSync(ROOT, { recursive: true });
fs.rmSync(SOCKET, { force: true });
server.listen(SOCKET, () => console.log(`blobd: ${ROOT} on ${SOCKET}`));

// systemd sends SIGTERM. Close the socket file so a restart doesn't trip over it.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => { fs.rmSync(SOCKET, { force: true }); process.exit(0); }));
}
