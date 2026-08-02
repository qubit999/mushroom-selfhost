/// On-prem entry for files-worker.
///
/// Same shape as selfhost/messaging/entry.js and for the same reason: `worker.js` is imported,
/// not forked, and handed an `env` carrying a D1-shaped `DB` and an R2-shaped `FILES`.
///
/// Simpler than messaging in one way: files-worker exports `default` only, with no Durable
/// Object of its own, so there is no second place the env has to be decorated.

import { WorkerEntrypoint } from "cloudflare:workers";
import base from "../files-worker/worker.js";
import { makeD1, SqlStoreBase } from "../shared/d1.js";
import { makeR2 } from "../shared/r2.js";
import { installOfflineGumroad } from "../shared/gumroad.js";

import m0001 from "../files-worker/migrations/0001_init.sql";
import m0002 from "../files-worker/migrations/0002_reports.sql";
import m0003 from "../files-worker/migrations/0003_license_source.sql";
import m0004 from "../files-worker/migrations/0004_throttle.sql";

const MIGRATIONS = [
  ["0001_init.sql", m0001],
  ["0002_reports.sql", m0002],
  ["0003_license_source.sql", m0003],
  ["0004_throttle.sql", m0004],
];

export class SqlStore extends SqlStoreBase {
  constructor(ctx, env) {
    super(ctx, MIGRATIONS);
  }
}

const decorate = (env) => {
  // Installed on first use rather than at module scope, because the enrolled hashes arrive with
  // env and there is no env until a request does. It is idempotent.
  installOfflineGumroad(env.ENROLLMENT_HASHES);
  return {
    ...env,
    // AFTER the spread, so no binding in config.capnp can turn it off. It is what tells
    // `enrolmentAllows` in worker.js that ENROLLMENT_HASHES exists here at all: hosted has no
    // such list, and an absent one there must not be read as an empty one. Until that check
    // existed the list was enforced only by the `fetch` wrapper below, so it covered Gumroad
    // keys and nothing else.
    SELFHOST: "1",
    DB: makeD1(env.SQL.get(env.SQL.idFromName("db"))),
    FILES: makeR2(env.BLOBS),
  };
};

export default {
  fetch: (request, env, ctx) => base.fetch(request, decorate(env), ctx),
  // The hourly expiry sweep. It is what makes the 24 hour promise true, and workerd has no cron,
  // so a systemd timer drives it through the Admin entrypoint below.
  scheduled: (event, env, ctx) => base.scheduled(event, decorate(env), ctx),
};

export class Admin extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/_selfhost/cron") {
      // Await what `scheduled` hands to waitUntil, or this answers before the sweep has run and
      // the assertion that follows it races.
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
    // this entrypoint does not inherit, so the documented `curl --unix-socket` answered 404 and
    // the only admin channel that actually worked was the http listener. Forward instead: the
    // socket is scoped by the capnp binding rather than by a token, so it is the one an operator
    // on the box should be reaching for.
    if (url.pathname.startsWith("/admin/")) {
      return base.fetch(request, decorate(this.env), this.ctx);
    }

    return new Response("not found\n", { status: 404 });
  }
}
