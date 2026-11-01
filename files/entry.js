/// On-prem entry for files-worker.
///
/// Same shape as selfhost/messaging/entry.js: `worker.js` is imported, not forked, and handed
/// an `env` with a D1-shaped `DB` and an R2-shaped `FILES`.
///
/// Simpler than messaging: files-worker exports only `default`, with no Durable Object, so the
/// env is decorated in one place.

import { WorkerEntrypoint } from "cloudflare:workers";
import base from "../files-worker/worker.js";
import { makeD1, SqlStoreBase } from "../shared/d1.js";
import { makeR2 } from "../shared/r2.js";
import { installOfflineGumroad } from "../shared/gumroad.js";

import m0001 from "../files-worker/migrations/0001_init.sql";
import m0002 from "../files-worker/migrations/0002_reports.sql";
import m0003 from "../files-worker/migrations/0003_license_source.sql";
import m0004 from "../files-worker/migrations/0004_throttle.sql";
import m0005 from "../files-worker/migrations/0005_entitlement.sql";

const MIGRATIONS = [
  ["0001_init.sql", m0001],
  ["0002_reports.sql", m0002],
  ["0003_license_source.sql", m0003],
  ["0004_throttle.sql", m0004],
  // Adds `entitled_until`, which every authenticated query reads. Without it a self-hosted box
  // answers "no such column: entitled_until" to every request.
  ["0005_entitlement.sql", m0005],
];

export class SqlStore extends SqlStoreBase {
  constructor(ctx, env) {
    super(ctx, MIGRATIONS);
  }
}

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
    FILES: makeR2(env.BLOBS),
  };
};

export default {
  // The http listener, reachable through the proxy. `/admin/*` answers only on the Admin
  // socket: worker.js serves it here too, where hosted needs it, and a bearer token on a
  // network port is one leaked or unchanged config away from deleting everyone's data.
  fetch: (request, env, ctx) => new URL(request.url).pathname.startsWith("/admin/")
    ? new Response("not found\n", { status: 404 })
    : base.fetch(request, decorate(env), ctx),
  // The hourly expiry sweep that keeps the 24-hour promise. workerd has no cron, so a systemd
  // timer drives it through the Admin entrypoint below.
  scheduled: (event, env, ctx) => base.scheduled(event, decorate(env), ctx),
};

export class Admin extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/_selfhost/cron") {
      // Await what `scheduled` hands to waitUntil, or this answers before the sweep runs and the
      // next assertion races it.
      const pending = [];
      await base.scheduled({ cron: "manual", scheduledTime: Date.now() },
                           decorate(this.env), { waitUntil: (p) => pending.push(p) });
      await Promise.all(pending);
      return new Response("ok\n");
    }

    if (url.pathname === "/_selfhost/sql") {
      if (this.env.SELFHOST_TEST_SQL !== "1") return new Response("not found\n", { status: 404 });
      return this.env.SQL.get(this.env.SQL.idFromName("db"))
        .fetch("https://sql/query", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: await request.text(),
        });
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
