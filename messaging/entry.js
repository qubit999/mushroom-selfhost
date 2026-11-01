/// On-prem entry for messaging-worker.
///
/// `worker.js` isn't forked: it's imported and handed an `env` with a D1-shaped `DB`, so hosted
/// and on-prem run the same bytes from the same bundler. That's the protocol-compatibility
/// argument, and why this is a wrapper, not a copy.
///
/// The env is decorated in two places. A `fetch` wrapper alone never reaches the Durable Object:
/// `UserInbox` reads `env.DB` itself in `stillAuthorized` and `APNS_*` through
/// `apnsConfigured`, and the runtime constructs the DO with the raw env, so it needs a subclass.

import { WorkerEntrypoint } from "cloudflare:workers";
import base, { UserInbox as BaseInbox } from "../messaging-worker/worker.js";
import { makeD1, SqlStoreBase } from "../shared/d1.js";
import { installOfflineGumroad } from "../shared/gumroad.js";

// Bundled as Text modules (see wrangler.build.jsonc). The files stay put, so hosted
// `wrangler d1 migrations apply` and on-prem read the same directory.
import m0001 from "../messaging-worker/migrations/0001_init.sql";
import m0002 from "../messaging-worker/migrations/0002_identity_license.sql";
import m0003 from "../messaging-worker/migrations/0003_backfill_identity_license.sql";
import m0004 from "../messaging-worker/migrations/0004_orphan_identity_cleanup.sql";
import m0005 from "../messaging-worker/migrations/0005_license_source.sql";
import m0006 from "../messaging-worker/migrations/0006_entitlement.sql";
import m0007 from "../messaging-worker/migrations/0007_link_codes.sql";

const MIGRATIONS = [
  ["0001_init.sql", m0001],
  ["0002_identity_license.sql", m0002],
  ["0003_backfill_identity_license.sql", m0003],
  ["0004_orphan_identity_cleanup.sql", m0004],
  ["0005_license_source.sql", m0005],
  // Adds `entitled_until`, which every authenticated query reads. Without it a self-hosted box
  // answers "no such column: entitled_until" to every request.
  ["0006_entitlement.sql", m0006],
  // The hourly sweep deletes from `link_codes`, so without this every sweep fails.
  ["0007_link_codes.sql", m0007],
];

export class SqlStore extends SqlStoreBase {
  constructor(ctx, env) {
    super(ctx, MIGRATIONS);
  }
}

/// One database, one object. `idFromName`, not a fixed id, so the name is readable in the
/// storage directory.
const decorate = (env) => {
  // Installed on first use, not at module scope: the enrolled hashes arrive with env, which only
  // exists once a request does. Idempotent.
  installOfflineGumroad(env.ENROLLMENT_HASHES);
  return {
    ...env,
    // After the spread, so no binding in config.capnp can turn it off. It tells `enrolmentAllows`
    // in worker.js that ENROLLMENT_HASHES applies here; hosted has no such list, and an absent
    // one there must not read as empty. The `fetch` wrapper alone would only cover Gumroad keys.
    SELFHOST: "1",
    DB: makeD1(env.SQL.get(env.SQL.idFromName("db"))),
  };
};

export class UserInbox extends BaseInbox {
  constructor(ctx, env) {
    super(ctx, decorate(env));
  }

  /// One route the hosted worker lacks, for `alarm-test.sh`.
  ///
  /// Hosted, that test reads workerd's own SQLite files in Miniflare's state directory
  /// (`_cf_ALARM`, message counts, APNs tokens, the `_cf_KV` retry counter). That layout is
  /// internal and versioned (`v3/do/`) and won't survive a workerd upgrade; asking the object
  /// is layout-independent.
  ///
  /// It's also less vacuous: the file probe sums across inboxes it can't tell apart, while this
  /// answers for one named identity, so "stored" means stored in the addressed inbox.
  ///
  /// Safe in front of `super.fetch`: `UserInbox.fetch` switches on fixed paths and defaults to
  /// 404, so this can't collide. And it's unreachable from the network; only the unix socket
  /// routes here.
  async fetch(request) {
    if (new URL(request.url).pathname === "/_selfhost/inbox") {
      const count = (sql) => this.ctx.storage.sql.exec(sql).one().n;
      return Response.json({
        // Milliseconds, or null when nothing is armed. Null is the default scenario's
        // assertion: a deployment that can't push must not wake on a timer forever.
        alarm: await this.ctx.storage.getAlarm(),
        messages: count("SELECT COUNT(*) AS n FROM messages"),
        push_tokens: count("SELECT COUNT(*) AS n FROM devices WHERE apns_token IS NOT NULL"),
        // Present only once a push attempt is counted. Absent means the retry has no budget and
        // would re-arm forever.
        push_attempt: (await this.ctx.storage.get("push_attempt")) ?? null,
      });
    }
    return super.fetch(request);
  }
}

/// Everything the operator and the test scripts need, on a separate entrypoint.
///
/// A named entrypoint, not a path prefix on the main worker: the capnp binds only the unix
/// socket to it, and the default export refuses `/admin/*`, so none of this is reachable over
/// http.
export class Admin extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url);

    // workerd has no cron, so a systemd timer calls this, which also makes a stalled sweep
    // visible in `systemctl list-timers`.
    if (url.pathname === "/_selfhost/cron") {
      // `scheduled` works inside `ctx.waitUntil`, so with a real ExecutionContext this would
      // answer before the sweep finished and later assertions would race. Await the promises
      // so the response means "done".
      const pending = [];
      await base.scheduled({ cron: "manual", scheduledTime: Date.now() },
                           decorate(this.env), { waitUntil: (p) => pending.push(p) });
      await Promise.all(pending);
      return new Response("ok\n");
    }

    // Direct SQL, replacing `wrangler d1 execute --local` in the test scripts. Gated as well as
    // socket-scoped: the shipped config never sets it, so production has no SQL route even for
    // someone with the unix socket.
    if (url.pathname === "/_selfhost/sql") {
      if (this.env.SELFHOST_TEST_SQL !== "1") return new Response("not found\n", { status: 404 });
      return this.env.SQL.get(this.env.SQL.idFromName("db"))
        .fetch("https://sql/query", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: await request.text(),
        });
    }

    // What alarm-test.sh asks instead of reading workerd's internal tables.
    if (url.pathname === "/_selfhost/inbox") {
      const identity = url.searchParams.get("identity") ?? "";
      if (!identity) return new Response("identity required\n", { status: 400 });
      return this.env.INBOX.get(this.env.INBOX.idFromName(identity))
        .fetch("https://inbox/_selfhost/inbox");
    }

    // The operator commands in README.md. `/admin/*` lives in the worker's default fetch, which
    // this entrypoint doesn't inherit, so forward it; otherwise the documented
    // `curl --unix-socket` 404s. The socket is scoped by the capnp binding, not a token, so it's
    // the channel an operator on the box should use.
    if (url.pathname.startsWith("/admin/")) {
      return base.fetch(request, decorate(this.env), this.ctx);
    }

    return new Response("not found\n", { status: 404 });
  }
}

export default {
  // The http listener, reachable through the proxy. `/admin/*` answers only on the Admin
  // socket: worker.js serves it here too, where hosted needs it, and a bearer token on a
  // network port is one leaked or unchanged config away from deleting everyone's data.
  fetch: (request, env, ctx) => new URL(request.url).pathname.startsWith("/admin/")
    ? new Response("not found\n", { status: 404 })
    : base.fetch(request, decorate(env), ctx),
  // workerd has no cron (`triggers.crons` is a Cloudflare platform feature), so a systemd timer
  // calls `scheduled()` instead; it stays exported.
  scheduled: (event, env, ctx) => base.scheduled(event, decorate(env), ctx),
};
