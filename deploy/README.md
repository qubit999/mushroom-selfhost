# Running Mushroom's servers yourself

Mushroom's Friends messaging and file sharing normally run on our Cloudflare account. If your
organisation will not put files on infrastructure it does not control, you can run both Workers
in **your own Cloudflare account** instead. Your data then lives in your D1 databases, your R2
bucket and your Durable Objects, under your contract with Cloudflare, in the region you pick,
with a delete button only you can press.

We can still see nothing either way. Friend messages are end to end encrypted on the sending
Mac, and since 1.38.0 so are shared files: the Mac seals each one before it leaves, with a key
that lives only in the fragment of the share link, which no browser ever puts in a request. Your
Worker stores ciphertext and holds no key, exactly as ours does. What changes here is **who the
data processor is**, and where the bytes and the filenames sit.

If your organisation needs to go further than that, and run the servers on **hardware it owns**
with no Cloudflare in the path at all, that is a different setup: see `selfhost/README.md`. It is
considerably more work, so be sure you need it. Your own tenancy, your own contract, your own
region and your own delete button is what most security reviews are actually asking for, and this
guide gives you all four.

## Getting the server software

The server software is published at **https://github.com/qubit999/mushroom-selfhost**, under
Apache-2.0. It is not part of the Mushroom download. Clone it and you have `files-worker` and
`messaging-worker`, the two directories every command below assumes you are standing in. They are
small, plain JavaScript, and yours to read before you run anything, which is rather the point.

Each Worker comes with a `wrangler.example.jsonc`. Copy it to `wrangler.jsonc` and fill in your
own values; ours is not included, because it holds the database ids of our hosted deployment.

## What you need

- A Cloudflare account (Workers Paid, for Durable Objects).
- A domain on that account, for two hostnames such as `chat.example.com` and
  `files.example.com`.
- Node 22+ and `npx`.
- A Mushroom licence for each person, bought normally. Running the servers does not replace
  the app licence, and one key must not be shared: each employee activates their own, and the
  three-Mac allowance is then three Macs *per person*, which is what it is meant to be.

## Files server (`files-worker`)

```bash
cd files-worker
npm ci
npx wrangler d1 create mushroom-files
```

**Answer `no` when it offers to add the binding for you.** Wrangler proposes a binding named
after the database (`mushroom_files`), and the Worker reads `env.DB`. Accepting the offer gives
you a config that deploys cleanly and then fails at the first query, with nothing in the error
pointing at the name. It also writes into whichever config file is the directory default, which
may not be the one you meant. Paste the id in by hand instead.

Put the printed `database_id` in your `wrangler.jsonc` (copied from `wrangler.example.jsonc`
above), keeping `"binding": "DB"`
exactly as it is, then set `PUBLIC_BASE` and the route to your hostname:

```jsonc
"vars": {
  "PUBLIC_BASE": "https://files.example.com",
  "BRAND_URL": ""
},
"routes": [{ "pattern": "files.example.com", "custom_domain": true }]
```

`BRAND_URL` is where the "this link has expired" and "this file was removed" pages send a
visitor, and where the bare root redirects. Empty means your deployment names nobody, which is
what you want: left unset it falls back to our marketing site, and your recipients would be sent
to us. Set it to your own intranet page if you would rather it pointed somewhere.

```bash
npx wrangler r2 bucket create mushroom-files --location <eu|wnam|apac>
npx wrangler r2 bucket local-uploads enable mushroom-files
npx wrangler d1 migrations apply mushroom-files --remote
npx wrangler secret put ADMIN_TOKEN        # openssl rand -base64 32
npx wrangler deploy
```

**Keep the bucket private.** Do not enable its `r2.dev` domain and do not attach a custom
domain to it. Every byte is served through the Worker, and that is what makes the 24 hour rule
and the attachment headers enforceable.

**Add the lifecycle backstop.** The hourly cron is what makes 24 hours true; this is what makes
it true even if the Worker is down:

```bash
npx wrangler r2 bucket lifecycle add mushroom-files \
  --name expire-shared-files --prefix "f/" --expire-days 2
```

Two days, not one: lifecycle granularity is days, so a one day rule could race a file still
inside its live window. The rule does not follow a bucket, so check it with
`npx wrangler r2 bucket lifecycle list` rather than assuming.

## Messaging server (`messaging-worker`)

```bash
cd messaging-worker
npm ci
npx wrangler d1 create mushroom-messaging
```

Again, decline the offer to add the binding for you: this Worker reads `env.DB`, and the R2
binding on the files side must stay `FILES`. Put the printed id in your copy of `wrangler.jsonc`
by hand and set the route to your hostname. Then:

```bash
npx wrangler d1 migrations apply mushroom-messaging --remote
npx wrangler secret put ADMIN_TOKEN
npx wrangler deploy
```

Migrations first and separately: `deploy` does not run them.

Do **not** set the `APNS_*` secrets. See below.

## Point Mushroom at it

On each Mac, in Mushroom: **Settings, Data, Servers, Use my own servers**. Both addresses are
required and both must be `https`. Switching hands this Mac's place back to the previous
servers first, so nothing is left holding a seat.

Switching is reversible. Credentials are stored per server, so moving to your servers and back
again returns the Mac to its previous identity with its friendships intact.

This is in the direct download only, not the Mac App Store build.

## What does not work, and will not

- **Background notifications.** A push can only be signed by the key that owns the app's push
  identifier, which is ours and cannot be handed out. Leave `APNS_KEY_P8` unset and the Worker
  will not try.

  **No message is lost.** Anything sent while somebody's Mushroom is closed queues in their inbox
  on your server, and the app drains it with `GET /v1/sync` the next time it connects, before it
  trusts the socket for anything. Server-side retention is 30 days. What is actually lost is only
  the tap on the shoulder: nobody is told while the app is quit or the Mac asleep. While Mushroom
  is running it raises its own notification locally, with a message preview that our own push
  deliberately never carries.
- **Abuse reporting.** The public report form needs Turnstile keys and an onboarded sending
  domain. On a private deployment there is no public link surface to report, so leaving
  `TURNSTILE_SECRET_KEY` unset and the `send_email` binding off is correct. If you do want it,
  serve your own copy of `report.html` and add its origin to `REPORT_ORIGINS` (comma separated),
  or the Worker will refuse your page in favour of ours. Note that you will not be able to look
  at a reported file: it is encrypted and you hold no key, so a takedown is a decision about the
  report, and `/admin/files/delete` removes the file without anybody reading it.
- **Licence checking is still ours.** Both Workers verify each activation against Gumroad, so
  they need outbound internet. Purchases through the Mac App Store verify offline against
  pinned Apple roots and need no reachability at all.

## Running it, and looking after it

Both Workers ship an admin surface, protected by the `ADMIN_TOKEN` you set. It is your
offboarding tool:

```bash
curl -X POST -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"license_hash":"<hash>"}' https://chat.example.com/admin/licenses/block
```

Blocking closes that person's live sockets within the recheck window and refuses new ones.
`files.example.com/admin/files/delete` removes a shared file immediately.

Neither Worker ever logs a filename, a share token, a licence key or a bearer token, and
neither stores a licence key: only a one way hash of it. Keep it that way if you patch them.

## Verifying it actually works

Both Workers carry their own suites. Run them against a local `wrangler dev` before you point
anyone at a fresh deployment:

```bash
./test.sh            # in each worker directory
./alarm-test.sh      # messaging-worker, and see below
```

`alarm-test.sh` is the one that matters most here, because it pins the rule that only bites
deployments like yours: a message nobody has read must not arm a push alarm when APNs is not
configured. Without that, every unread message wakes its inbox on a timer forever and bills you
for a notification that could never have been sent.
