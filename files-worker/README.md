# mushroom-files

The Worker behind Mushroom's temporary file sharing. A licensed Mac trades its Gumroad key
for a device token, uploads a file, and gets back a link that works for 24 hours.

Separate from the website Worker (`Mushroom_www`, its own git repo) on purpose: that one is
asset-first, serving every repo-root file as a static asset, so a stray filename there
would shadow a route here.

## Layout

| File | |
|---|---|
| `worker.js` | Everything. Routes, Gumroad verification, the sweep. |
| `wrangler.jsonc` | Bindings, cron, custom domain. |
| `migrations/0001_init.sql` | D1 schema. |
| `test.sh` | Smoke matrix against `wrangler dev`. |

## First-time setup

```bash
npx wrangler d1 create mushroom-files      # paste database_id into wrangler.jsonc
npx wrangler r2 bucket create mushroom-files-global --location weur
npx wrangler r2 bucket local-uploads enable mushroom-files-global
npx wrangler d1 migrations apply mushroom-files --remote
npx wrangler deploy                        # creates files.getmushroom.app on first run
```

The bucket must stay **private**: do not enable the `r2.dev` domain and do not attach a
custom domain to it. Every byte is served through the Worker, which is what makes the
24-hour rule and the attachment headers enforceable.

Two secrets, both set once:

```bash
npx wrangler secret put TURNSTILE_SECRET_KEY   # the /report widget's secret
npx wrangler secret put ADMIN_TOKEN            # openssl rand -base64 32
```

Gumroad's verify endpoint needs no API key, which is why nothing sensitive ships in the app
binary either. `.dev.vars` holds local values only and is gitignored; it uses Cloudflare's
documented Turnstile test secret so the suite runs without a browser.

Keep `ADMIN_TOKEN` in your shell as `MUSHROOM_ADMIN_TOKEN`, because that is the variable the
commands in every report email expect.

### The backstop lifecycle rule

The hourly cron is what makes 24 hours true. This rule is what guarantees nothing survives
a Worker outage:

```bash
npx wrangler r2 bucket lifecycle add mushroom-files-global \
  --name expire-shared-files --prefix "f/" --expire-days 2
```

Two days, not one: lifecycle granularity is days, so a one-day rule could race a file
that is still inside its live window.

The rule does not follow a bucket. Check it with `npx wrangler r2 bucket lifecycle list
mushroom-files-global` rather than assuming, because privacy.html promises users this
backstop exists and a bucket without it fails silently and invisibly.

## Local development

`--persist-to` has to be on BOTH lines. `wrangler dev` reads `../.wrangler-dev-state`, and a
migrate without the same flag writes the schema into wrangler's default directory instead, so
the Worker starts against a database with no tables:

```bash
npx wrangler d1 migrations apply mushroom-files --local --persist-to ../.wrangler-dev-state
npx wrangler dev --persist-to ../.wrangler-dev-state
```

Needed again any time `../.wrangler-dev-state` is deleted. Without it the failure is a wall of
500s with nothing saying why; the preflight in `test.sh` catches that and prints the command.

Then, in another terminal:

```bash
MUSHROOM_TEST_LICENSE=<a real Gumroad key> ./test.sh
```

Activation hits the live Gumroad endpoint even locally, with
`increment_uses_count=false`, so it costs no seat. Without the variable the script runs
only the unauthenticated cases.

The Mac app points here with `MUSHROOM_FILES_BASE=http://localhost:8787` in a Debug build.

Fire the sweep by hand:

```bash
curl "http://localhost:8787/__scheduled?cron=17+*+*+*+*"
```

## App Store activation

`/v1/devices/activate` takes **exactly one** of `license_key` or `app_transaction`, and 400s
on both or neither. The second is the App Store build's credential: it has no Gumroad key to
present (`LicenseManager`'s APPSTORE stub never writes one), so it sends `AppTransaction`'s
JWS and the Worker verifies it against a pinned Apple root. The identity is
`sha256("appstore:" + appTransactionId)`, which lands in the same `licenses.license_hash`
column as a Gumroad key hash, so seats, quotas and bearer auth are all unchanged. Apple
issues that id per Apple Account *and* per family group member, so a Family Sharing member
gets their own three seats.

`APPSTORE_APP_APPLE_ID` is `6792833686`, in `wrangler.jsonc` as a plain var rather than a
secret: it is the id in every App Store URL, so hiding it would buy nothing and cost a
setup step. Apple's verifier requires it to check the JWS against the right app. If it is
ever missing the endpoint answers `503 appstore_unconfigured` rather than guessing, and the
Gumroad path is unaffected either way.

Two things that will bite:

- **`npm ci` in this directory before `wrangler deploy`.** The verifier is
  `@apple/app-store-server-library`, pinned exactly in `package.json` AND in a committed
  `package-lock.json`. The lockfile is what pins the 45 transitive packages, including
  `jsrsasign`, which is the code that actually parses the certificate chain. Use `npm ci`,
  which honours it; `npm install` will happily rewrite it.
- **The import of that library lives inside the request handler, not at the top of
  `worker.js`, and must stay there.** `jsrsasign` generates random values while its module
  body runs, and workerd refuses that in global scope: a top-level import stops the Worker
  booting entirely with "Disallowed operation called within global scope". Costs about
  160 KB gzipped and one module evaluation on the first activation after a cold start.

There is deliberately no refund revocation. An Apple refund is invisible from here; catching
one needs App Store Server Notifications V2 and a webhook, and §14 says fail open rather than
build DRM. Quotas bound the damage.

## Deploying

```bash
npm ci               # required: the App Store verifier is an npm dependency
npx wrangler deploy
```

**A migration is a separate step.** `deploy` does not run one:

```bash
npx wrangler d1 migrations apply mushroom-files --remote
```

Run the migration first when it only adds things, and check `test.sh` against
`npx wrangler dev --remote` before deploying: local D1 and R2 emulation is not the same
code path as the real thing.

## Acting on an abuse report

A report from `getmushroom.app/report` is stored, then emailed to `hello@` from
`abuse@getmushroom.app`. The email carries two ready-to-paste commands. They are `curl`
rather than `wrangler d1 execute` on purpose: each action has to touch R2 **and** D1, and a
pair of SQL statements that must not be run half way is a worse tool than one endpoint that
does both.

- **Delete just the reported file.** Removes the object, marks the row deleted, clears the
  filename. Idempotent.
- **Block the licence.** Sets its status to revoked, revokes every device token it has, and
  deletes every file still live under it.

Blocking stops **file sharing only**. The customer's app keeps working, because the app's
own licence gate is Gumroad's, not ours. Disabling the purchase itself is a separate,
deliberate act in Gumroad, using the sale id the email prints.

Both endpoints are POST and bearer-authenticated. Never make them GET: mail clients and
link scanners follow URLs in email on their own.

## Things that will look like bugs but are not

- **The bucket has no jurisdiction, on purpose.** It used to be `mushroom-files` with
  `--jurisdiction eu`. R2 Local Uploads, which is what keeps an upload from Sydney quick,
  is not supported on a bucket that has one, and a jurisdiction cannot be removed after
  creation. So the bucket is `mushroom-files-global` with a `weur` location hint: the data
  still lives in Western Europe, it is just a preference now rather than a guarantee.
  Re-adding a jurisdiction means another whole bucket and gives up Local Uploads again.
- **Two R2 bindings is temporary.** `FILES_OLD` exists only until everything shared before
  the cutover has expired. See the R2 bucket drain block at the top of `worker.js` for the
  teardown, and do it in the order written there.
- **Activation fails closed, everything else fails open.** If Gumroad is unreachable, a
  new device gets a 503 and no token. Once a device holds a token it keeps working
  regardless. Handing out tokens without a check would make "Gumroad is down" a free pass
  into the bucket, while blocking an already-verified Mac would break the app's own rule
  that a paying user is never locked out for being offline.
- **There is no periodic re-verify in the Worker.** It stores `sha256(key)`, never the
  key, so it physically cannot re-ask Gumroad. The app holds the key and re-activates on
  the interval the Worker hands it back in `limits.reverify_after_seconds`.
- **A fourth Mac silently evicts the least-recently-used one** rather than getting a 409.
  The evicted Mac re-activates the next time it sees a 401, so the user never notices.
- **Downloads are always `application/octet-stream`**, whatever was uploaded. Serving
  attacker-chosen HTML or SVG from a subdomain of getmushroom.app would be stored XSS
  against the marketing site. There is no inline preview and there cannot be one on this
  domain.
- **Any file type is accepted, but a declared type still has to be true.** The allowlist
  went away in 1.26.0; `TYPE_SIGNATURES` stayed. A type with an entry there is checked
  against the real first bytes after upload, so a renamed `.exe` claiming `image/png` is
  still refused, while a `.zip` is simply not checked. Safety on the download side never
  came from the allowlist (see the octet-stream bullet above); what it bought was bounded
  malware-hosting exposure, and the takedown flow it was waiting for now exists.
- **`PUT` without `Content-Length` is a 411.** A fixed-length body is what lets R2 stream
  it; a chunked one would be read into the Worker's 128 MB memory budget.
- **Filenames are NULLed when a file expires.** The row survives seven more days only so
  the link can answer "expired" instead of "never existed", and it does not need to
  remember what was shared to do that.
- **Never log a filename, share token, license key or bearer token.** Observability is on
  and logs are retained. Ids and status codes only.
