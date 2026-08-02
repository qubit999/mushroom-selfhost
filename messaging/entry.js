/// On-prem entry for messaging-worker.
///
/// `worker.js` is NOT forked. It is imported and handed an `env` with a D1-shaped `DB` on it,
/// so the hosted deployment and an on-prem box run the same bytes out of the same bundler.
/// That is the whole protocol-compatibility argument, and it is why this file is a wrapper
/// rather than a copy.
///
/// The env has to be decorated in TWO places. An entry `fetch` wrapper alone never reaches the
/// Durable Object: `UserInbox` reads `env.DB` itself in `stillAuthorized`
/// (messaging-worker/worker.js:1414) and reaches `APNS_*` through `apnsConfigured`. A DO
/// constructed by the runtime gets the raw env, not the decorated one, so it needs its own
/// subclass.

import { WorkerEntrypoint } from "cloudflare:workers";
import base, { UserInbox as BaseInbox } from "../messaging-worker/worker.js";
import { makeD1, SqlStoreBase } from "../shared/d1.js";
import { installOfflineGumroad } from "../shared/gumroad.js";

// Bundled as Text modules (see wrangler.build.jsonc). The files stay where they are, so
// `wrangler d1 migrations apply` hosted and this on-prem read the same directory.
import m0001 from "../messaging-worker/migrations/0001_init.sql";
import m0002 from "../messaging-worker/migrations/0002_identity_license.sql";
import m0003 from "../messaging-worker/migrations/0003_backfill_identity_license.sql";
import m0004 from "../messaging-worker/migrations/0004_orphan_identity_cleanup.sql";
import m0005 from "../messaging-worker/migrations/0005_license_source.sql";

const MIGRATIONS = [
  ["0001_init.sql", m0001],
  ["0002_identity_license.sql", m0002],
  ["0003_backfill_identity_license.sql", m0003],
  ["0004_orphan_identity_cleanup.sql", m0004],
  ["0005_license_source.sql", m0005],
];

export class SqlStore extends SqlStoreBase {
  constructor(ctx, env) {
    super(ctx, MIGRATIONS);
  }
}

/// One database, one object. `idFromName` rather than a fixed id so the name is readable in
/// the storage directory.
const decorate = (env) => {
  // Installed on first use rather than at module scope, because the enrolled hashes arrive with
  // env and there is no env until a request does. It is idempotent.
  installOfflineGumroad(env.ENROLLMENT_HASHES);
  return {
    ...env,
    DB: makeD1(env.SQL.get(env.SQL.idFromName("db"))),
  };
};

export class UserInbox extends BaseInbox {
  constructor(ctx, env) {
    super(ctx, decorate(env));
  }

  /// One route the hosted worker does not have, for `alarm-test.sh`.
  ///
  /// That test reads four things out of workerd's own SQLite files in Miniflare's state
  /// directory: the `_cf_ALARM` table, a per-inbox message count, stored APNs tokens, and the
  /// `_cf_KV` row holding the retry counter. That layout is internal, it is versioned (`v3/do/`)
  /// and it will not survive a workerd upgrade, let alone this deployment. Asking the object
  /// itself is layout-independent and stays true.
  ///
  /// It is also LESS vacuous than the file probe, which sums across every inbox because it
  /// cannot tell them apart. This answers for one named identity, so "the message was stored"
  /// means stored in the inbox it was addressed to.
  ///
  /// Safe to sit in front of `super.fetch`: `UserInbox.fetch` switches on a fixed list of paths
  /// and defaults to 404, so this cannot collide with a real one. It is also unreachable from
  /// the network, because the only socket that routes here is the unix one.
  async fetch(request) {
    if (new URL(request.url).pathname === "/_selfhost/inbox") {
      const count = (sql) => this.ctx.storage.sql.exec(sql).one().n;
      return Response.json({
        // Milliseconds, or null when nothing is armed. Null is the whole assertion in the
        // default scenario: a deployment that cannot push must not wake on a timer forever.
        alarm: await this.ctx.storage.getAlarm(),
        messages: count("SELECT COUNT(*) AS n FROM messages"),
        push_tokens: count("SELECT COUNT(*) AS n FROM devices WHERE apns_token IS NOT NULL"),
        // Present only once a push has been attempted and counted. Its absence is what told us
        // the retry had no budget and would re-arm forever.
        push_attempt: (await this.ctx.storage.get("push_attempt")) ?? null,
      });
    }
    return super.fetch(request);
  }
}

/// Everything the operator and the test scripts need, on a separate entrypoint.
///
/// A named entrypoint rather than a path prefix on the main worker: the capnp binds ONLY the
/// unix socket to it, so none of this is reachable over http even by mistake. That is the
/// difference between a debug route and a debug route with an authentication bug in it.
export class Admin extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url);

    // workerd has no cron. A systemd timer calls this instead, which is also what makes a
    // sweep that stopped running visible in `systemctl list-timers` rather than silent.
    if (url.pathname === "/_selfhost/cron") {
      // `scheduled` does its work inside `ctx.waitUntil`, so a real ExecutionContext would let
      // this respond before the sweep finished and every assertion after it would race.
      // Collect the promises and await them, so the response means "done".
      const pending = [];
      await base.scheduled({ cron: "manual", scheduledTime: Date.now() },
                           decorate(this.env), { waitUntil: (p) => pending.push(p) });
      await Promise.all(pending);
      return new Response("ok\n");
    }

    // Direct SQL, replacing `wrangler d1 execute --local` in the test scripts. Gated as well
    // as socket-scoped: the shipped config never sets this, so a box in production has no SQL
    // route at all even for someone who has the unix socket.
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

    return new Response("not found\n", { status: 404 });
  }
}

export default {
  fetch: (request, env, ctx) => base.fetch(request, decorate(env), ctx),
  // workerd has no cron: `triggers.crons` is a Cloudflare platform feature and `scheduled()`
  // would never fire on its own here. A systemd timer calls it instead, so it stays exported.
  scheduled: (event, env, ctx) => base.scheduled(event, decorate(env), ctx),
};
