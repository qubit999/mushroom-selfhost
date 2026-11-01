/// A D1 binding, backed by a SQLite Durable Object inside workerd.
///
/// workerd supports self-hosting but ships no D1, so on-prem supplies one. The Workers only use
/// `.prepare().bind()` then `.first()` / `.all()` / `.run()`. Nothing calls `.exec()` on D1
/// (every `.exec(` in the tree is `ctx.storage.sql`) or `.batch()`, so neither is here: an
/// unused method would be untested D1 semantics.
///
/// The DO shares `UserInbox`'s storage directory, so an on-prem box's durable state stays one
/// directory to back up.

/// Two things verified against workerd before this design was allowed:
///
///  - `changes()` reports the real count: 1 for a winning conditional UPDATE, 0 for a losing
///    one. `acceptInvite` in messaging-worker gates single-use invites on it, so a shim that
///    always said 1 would make every invite reusable.
///  - `RETURNING` works, including `INSERT … ON CONFLICT DO UPDATE … RETURNING count`, which
///    is the whole of files-worker's `throttle`.
///
/// `sqlite_version()` isn't authorized in workerd, a sign the SQL surface is allowlisted. Both
/// Workers run plain DML, which is fine.

/// Wire between the binding and the DO. A made-up origin is the documented way to address a
/// Durable Object, as in messaging-worker's `inboxCall`.
const ENDPOINT = "https://sql/query";

class PreparedStatement {
  constructor(stub, sql, params) {
    this.stub = stub;
    this.sql = sql;
    this.params = params;
  }

  /// D1 returns a new statement rather than mutating; `throttle` relies on that by building
  /// the statement separately from binding it.
  bind(...params) {
    return new PreparedStatement(this.stub, this.sql, params);
  }

  async #query() {
    const response = await this.stub.fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sql: this.sql, params: this.params }),
    });
    // Must throw like D1 does: `throttle` catches and fails open, `requireLicense` doesn't.
    // Swallowing it would turn a broken database into a limiter that always says yes.
    if (!response.ok) throw new Error(`selfhost D1: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /// The first row or null, as D1 does. Callers rely on both: `if (!row)` and
  /// `row?.count ?? 1`.
  async first() {
    const { results } = await this.#query();
    return results.length ? results[0] : null;
  }

  /// Both Workers only read `.results`, but D1 sends `success` and matching it is free.
  async all() {
    const { results, meta } = await this.#query();
    return { success: true, results, meta };
  }

  /// `meta.changes` is read in one place: the single-use invite guarantee.
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
/// Replaces `wrangler d1 migrations apply`, which needs an account and a network. It runs from
/// the DO constructor, so a new migration applies on the first request after restart with no
/// ops step to forget. A failure throws out of the constructor and every request 500s, the right
/// behaviour for a half-migrated database.
///
/// `migrations/` stays the single source of truth for both environments; only the applier
/// differs, so a migration can't land in one and not the other.
/// Drop trailing blank and comment-only lines.
///
/// `wrangler d1 migrations apply` tolerates a comment after the last statement; workerd's
/// `sql.exec` throws "SQL code did not contain a statement" on it.
/// files-worker/migrations/0003_license_source.sql ends that way, so without this the on-prem
/// files database couldn't be created at all.
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
    // Multi-statement exec with `--` comments works in workerd (verified), as `UserInbox`'s
    // constructor already relies on.
    //
    // A comment-only migration is still recorded as applied, or it would retry on every start.
    const statements = stripTrailingComments(text);
    if (statements.trim()) sql.exec(statements);
    sql.exec("INSERT INTO _selfhost_migrations (name, applied_at) VALUES (?, ?)",
             name, Math.floor(Date.now() / 1000));
  }
}

/// The Durable Object that owns the database file.
///
/// Subclassed per worker, so each has its own migrations and storage and the query handling
/// stays in one place.
export class SqlStoreBase {
  constructor(ctx, scripts) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    applyMigrations(this.sql, scripts);
  }

  async fetch(request) {
    const { sql, params } = await request.json();

    // A `total_changes()` delta, not `changes()`.
    //
    // `changes()` reports the connection's last INSERT/UPDATE/DELETE, so it's stale after
    // anything else: a plain SELECT would report `changes: 1` left over from migration
    // bookkeeping, a trap for a future caller.
    //
    // The delta is right in all cases: N for DML that changed N rows, 0 for DML that changed
    // none (the losing invite burn, the single-use guarantee), 0 for non-DML.
    //
    // No await between the three statements, so no other request can interleave and move the
    // counter.
    const before = this.sql.exec("SELECT total_changes() AS c").one().c;
    const cursor = this.sql.exec(sql, ...(params ?? []));
    const results = cursor.toArray();
    const changes = this.sql.exec("SELECT total_changes() AS c").one().c - before;

    return Response.json({
      results,
      // Neither Worker reads `last_row_id` or the timings. They match D1's `meta` shape so a
      // caller reaching for one gets 0, not a quietly wrong `undefined`.
      meta: { changes, last_row_id: 0, rows_read: cursor.rowsRead, rows_written: cursor.rowsWritten, duration: 0 },
    });
  }
}
