/// A D1 binding, backed by a SQLite Durable Object inside workerd.
///
/// workerd is production-supported for self-hosting but ships no D1, so on-prem has to supply
/// one. This is the whole of it, because the surface the two Workers actually use is four
/// methods wide: `.prepare().bind()` then `.first()` / `.all()` / `.run()`. Nothing calls
/// `.exec()` on D1 (every `.exec(` in the tree is `ctx.storage.sql`) and nothing calls
/// `.batch()`, so neither is here. Adding an unused method would be a second implementation
/// of D1 semantics that no test covers.
///
/// The DO lives in the same storage directory as `UserInbox`, which already holds message
/// ciphertext, so the durable state of an on-prem box stays one directory to back up.

/// The two things this had to prove before the design was allowed to exist, both verified
/// against workerd 2026-08-01 rather than assumed:
///
///  - `changes()` reports the real count, 1 for a winning conditional UPDATE and 0 for a
///    losing one. `messaging-worker/worker.js:688` gates single-use invites on it, so a shim
///    that always answered 1 would silently make every invite reusable.
///  - `RETURNING` works, including `INSERT … ON CONFLICT DO UPDATE … RETURNING count`, which
///    is the entire upload throttle at `files-worker/worker.js:335`.
///
/// `sqlite_version()` is NOT authorized in workerd, which is a fair warning that the SQL
/// surface is allowlisted. Everything both Workers run is plain DML and is fine.

/// Wire between the binding and the DO. A made-up origin, the documented way to address a
/// Durable Object, same as `inboxCall` in messaging-worker.
const ENDPOINT = "https://sql/query";

class PreparedStatement {
  constructor(stub, sql, params) {
    this.stub = stub;
    this.sql = sql;
    this.params = params;
  }

  /// D1 returns a NEW statement rather than mutating, and `throttle` relies on that by
  /// building the statement separately from binding it.
  bind(...params) {
    return new PreparedStatement(this.stub, this.sql, params);
  }

  async #query() {
    const response = await this.stub.fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sql: this.sql, params: this.params }),
    });
    // A throw here has to look like a D1 throw, because `throttle` catches and fails open
    // and `requireLicense` does not. Swallowing it would turn a broken database into a
    // limiter that always says yes.
    if (!response.ok) throw new Error(`selfhost D1: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /// D1 hands back the first row or null. Callers use it both ways: `if (!row)` and
  /// `row?.count ?? 1`.
  async first() {
    const { results } = await this.#query();
    return results.length ? results[0] : null;
  }

  /// Only ever consumed via `.results` in both Workers, but `success` is what D1 sends and
  /// costs nothing to match.
  async all() {
    const { results, meta } = await this.#query();
    return { success: true, results, meta };
  }

  /// `meta.changes` is read at exactly one place, and it is the single-use invite guarantee.
  async run() {
    const { results, meta } = await this.#query();
    return { success: true, results, meta };
  }
}

export function makeD1(stub) {
  return { prepare: (sql) => new PreparedStatement(stub, sql, []) };
}

/// Apply migrations that have not run yet, in filename order.
///
/// This replaces `wrangler d1 migrations apply`, which needs an account and a network. It runs
/// from the DO constructor, so an upgrade that adds a migration applies it on the first request
/// after restart and there is no ops step to forget. A failure throws out of the constructor
/// and every request 500s, which is the right way for a half-migrated database to behave.
///
/// `migrations/` stays the single source of truth for both environments. Only the applier
/// differs, so a migration cannot land in one environment and not the other.
/// Drop trailing blank and comment-only lines.
///
/// `wrangler d1 migrations apply` tolerates a migration that ends with a comment after its last
/// statement. workerd's `sql.exec` does not: it throws "SQL code did not contain a statement" on
/// the trailing fragment, and files-worker/migrations/0003_license_source.sql ends with exactly
/// that, three lines of explanation after the last semicolon. Without this the on-prem files
/// database could not be created at all, while the identical file applied cleanly hosted.
///
/// Only whole-line comments are dropped, so `CREATE INDEX ...;  -- note` keeps its statement.
function stripTrailingComments(text) {
  const lines = text.split("\n");
  while (lines.length) {
    const last = lines[lines.length - 1].trim();
    if (last === "" || last.startsWith("--")) lines.pop();
    else break;
  }
  return lines.join("\n");
}

export function applyMigrations(sql, scripts) {
  sql.exec("CREATE TABLE IF NOT EXISTS _selfhost_migrations (name TEXT PRIMARY KEY, applied_at INTEGER)");
  const done = new Set(sql.exec("SELECT name FROM _selfhost_migrations").toArray().map((r) => r.name));

  for (const [name, text] of [...scripts].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (done.has(name)) continue;
    // Multi-statement exec, including `--` comments, verified against workerd. This is the
    // same thing `UserInbox`'s constructor already does with its own schema.
    //
    // A migration that is nothing but comments still gets recorded as applied: it has no work
    // to do, and leaving it unrecorded would retry it on every start forever.
    const statements = stripTrailingComments(text);
    if (statements.trim()) sql.exec(statements);
    sql.exec("INSERT INTO _selfhost_migrations (name, applied_at) VALUES (?, ?)",
             name, Math.floor(Date.now() / 1000));
  }
}

/// The Durable Object that owns the database file.
///
/// Subclassed per worker so each gets its own migration set and its own storage, while the
/// query handling stays in one place.
export class SqlStoreBase {
  constructor(ctx, scripts) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    applyMigrations(this.sql, scripts);
  }

  async fetch(request) {
    const { sql, params } = await request.json();

    // A `total_changes()` DELTA, not `changes()`.
    //
    // `changes()` reports the last INSERT/UPDATE/DELETE on the connection, which is correct
    // right after a DML statement but STALE after anything else: a plain SELECT here reported
    // `changes: 1` left over from the migration bookkeeping. Nothing reads `meta.changes` off a
    // SELECT today, so that was latent rather than broken, and it is exactly the kind of latent
    // that a future caller trips over.
    //
    // The delta is right in all three cases: N for a DML that changed N rows, 0 for a DML that
    // changed none (the losing invite burn, which is the whole single-use guarantee), and 0 for
    // a statement that was never DML at all.
    //
    // All three statements run with NO await between them. Without a yield point no other
    // request to this object can interleave and move the counter underneath us.
    const before = this.sql.exec("SELECT total_changes() AS c").one().c;
    const cursor = this.sql.exec(sql, ...(params ?? []));
    const results = cursor.toArray();
    const changes = this.sql.exec("SELECT total_changes() AS c").one().c - before;

    return Response.json({
      results,
      // `last_row_id` and the timings are not read anywhere in either Worker. They are here
      // because `meta` is a D1 shape, and a caller reaching for one should get 0 rather than
      // `undefined` doing something quiet and wrong.
      meta: { changes, last_row_id: 0, rows_read: cursor.rowsRead, rows_written: cursor.rowsWritten, duration: 0 },
    });
  }
}
