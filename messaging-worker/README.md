# mushroom-messaging

Invite-only one-to-one messaging for Mushroom, on `chat.getmushroom.app`.

A licensed Mac trades its Gumroad key plus an X25519 public key for a device token, then
opens a WebSocket to its own inbox. Messages are sealed on the sending Mac and opened on the
receiving one. **This Worker stores ciphertext and could not read a message if it wanted to.**

Third worker on the `getmushroom.app` zone, after `Mushroom_www` and `files-worker`, on the
same Cloudflare account.

## Shape

```
D1 mushroom-messaging          UserInbox DO (one per identity)
  licenses    a hash, never      messages    seq, msg_id UNIQUE, ciphertext
              the key            friends     peer, public key, blocked
  devices     token -> identity  devices     APNs token, last_acked_seq
  identities  public keys        + hibernating WebSockets, one per Mac
  invites     8 chars, 24h       + alarm: unacked -> APNs, and retention
```

**One DO class, not two.** The inbox is already the only thing that knows a person's
sockets, their friends, their push tokens and their history, so a separate "conversation"
object would only have to ask it. One monotonic sequence per person also makes catch-up a
single `GET /v1/sync?after=<cursor>` with no fan-out.

**The DO stores only messages you RECEIVED.** Your own sent messages live on your Mac and
nowhere else. Half the storage, and no second copy to diverge.

## Endpoints

| | |
|---|---|
| `POST /v1/devices/activate` | `{license_key, public_key, device_name}` -> `{device_id, identity_id, token, limits}` |
| `GET /v1/connect?token=` | WebSocket upgrade. `&presence=0` to stay invisible |
| `POST /v1/invites` | -> `{code, expires_at}` |
| `POST /v1/invites/accept` | `{code}` -> `{peer_id, public_key}` |
| `GET /v1/sync?after=<seq>` | -> `{messages[], has_more}` |
| `POST /v1/push` | `{token, environment}` |
| `POST /v1/friends/<id>/block\|unblock\|remove` | |
| `POST /v1/devices/release` | free a seat |

Socket frames, client to server: `send`, `ack`, `typing`, `ping`.
Server to client: `message`, `accepted`, `rejected`, `delivered`, `presence`,
`presence_snapshot`, `typing`, `pong`.

## Setup

```bash
npx wrangler d1 create mushroom-messaging
```

Put the printed id in `wrangler.jsonc` (it ships as `REPLACE_ME`, deliberately, because a
wrong id deploys fine and fails at the first query). Then:

```bash
npx wrangler d1 migrations apply mushroom-messaging --remote
```

Three secrets, for APNs. Never in `wrangler.jsonc`:

```bash
npx wrangler secret put APNS_KEY_ID
npx wrangler secret put APNS_TEAM_ID
npx wrangler secret put APNS_KEY_P8
```

`APNS_KEY_P8` is the whole `.p8` file including the BEGIN/END lines. The key comes from
Apple Developer -> Keys, with Apple Push Notifications enabled; it is downloadable exactly
once. `APNS_TOPIC` defaults to `com.qubit.shroomy.app` and only needs setting if the bundle
id changes.

## Deploy

Migration first, and separately: `deploy` does not run migrations.

```bash
npx wrangler d1 migrations apply mushroom-messaging --remote
```

```bash
npm ci               # required: the App Store verifier is an npm dependency
npx wrangler deploy
```

`wrangler deploy` creates the custom domain on first run.

## App Store activation

`/v1/devices/activate` takes **exactly one** of `license_key` or `app_transaction`, and 400s
on both or neither. The second is the App Store build's credential: it has no Gumroad key to
present, so it sends `AppTransaction`'s JWS and the Worker verifies it against a pinned Apple
root. The identity is `sha256("appstore:" + appTransactionId)`, which lands in the same
`licenses.license_hash` column as a Gumroad key hash, so seats, the identity first-claim
guard, `blocked`, and bearer auth are all unchanged. Apple issues that id per Apple Account
*and* per family group member, so a Family Sharing member gets their own three seats.

`APPSTORE_APP_APPLE_ID` is `6792833686`, in `wrangler.jsonc` as a plain var rather than a
secret: it is the id in every App Store URL. Apple's verifier requires it to check the JWS
against the right app. If it is ever missing the endpoint answers
`503 appstore_unconfigured` rather than guessing.

Two things that will bite, both the same as `mushroom-files`:

- **`npm ci` here before `wrangler deploy`.** The verifier is
  `@apple/app-store-server-library`, pinned exactly in `package.json` and in a committed
  `package-lock.json`, which is what pins `jsrsasign` and the rest of the chain-parsing
  tree. `npm install` would rewrite the lockfile; `npm ci` honours it.
- **The import of that library lives inside the request handler and must stay there.**
  `jsrsasign` generates random values while its module body runs, and workerd refuses that in
  global scope: a top-level import stops the Worker booting with "Disallowed operation called
  within global scope".

`revoked` still only comes from Gumroad. An Apple refund is invisible from here (that needs
App Store Server Notifications V2), but `blocked` works for either channel, because that is
our own abuse decision rather than the store's.

## Channel migration

Both targets ship bundle id `com.qubit.shroomy.app` under one team, so a Mac that moves from
the direct download to the App Store keeps its Keychain, and with it the X25519 messaging
identity. The licence hash under it does NOT survive: Gumroad's is `sha256(key)`, the App
Store's is `sha256("appstore:" + appTransactionId)`. Without a migration path the first-claim
guard refuses the same person on the same Mac forever, and their only way out is Start Over,
which deletes every friendship and every message they have.

`/v1/devices/activate` therefore takes two OPTIONAL extra fields, `migrate_license_key` and
`migrate_app_transaction` (at most one). They authenticate nothing on their own: they are only
consulted when the identity is already bound to a different hash, and only to prove the caller
also holds the credential that owns it. That is exactly the standard the original claim was
made to, so this opens nothing that was closed. A Gumroad key that verifies as `revoked`
counts, because refunding on one channel and buying on the other is the migration this exists
for. `invalid` and `unreachable` do not, so it cannot be waved through by taking Gumroad down.

The app sends it from `AppEnvironment.migrationCredential()`, App Store build only: proving an
App Store purchase needs StoreKit, which the direct build does not compile in. The Worker
accepts either direction; only the client is one-way.

**The happy path cannot be tested from here.** It needs a valid primary credential AND a valid
old credential in one request, which means a real Gumroad key plus a real `AppTransaction`
JWS, and that JWS only exists inside a TestFlight or App Store install. `test.sh` pins every
half that can be checked without one (an unprovable migration leaves the binding exactly where
it was), and the guarded UPDATE uses `RETURNING` rather than `meta.changes` because the local
emulator does not populate `changes` and reading it would pass locally and fail in production.

Verify by hand, once, on a TestFlight build:

1. On a Mac running the DIRECT build, set up Friends and exchange a message.
2. Note the identity: `SELECT id, license_hash FROM identities WHERE id = '<sha256 of the
   public key>'`. It is bound to the Gumroad hash.
3. Install the TestFlight build over it. Do NOT press Start Over, and do not clear the
   Keychain.
4. Force a re-activation (Settings, Friends, Release This Mac, then switch Friends on).
5. Expect a 201, the friend list intact, and that row's `license_hash` now the `appstore:`
   one. A 403 `identity_claimed` means the migration did not fire; check the Worker logs for
   `identity migrated`.

## Blocking a licence

`blocked` is enforced in three places (`authenticateToken`, `stillAuthorized`, and the
activate upsert's CASE) and for the App Store channel it is the ONLY lever, since this Worker
never re-asks Apple. It needs `ADMIN_TOKEN` set once:

```bash
npx wrangler secret put ADMIN_TOKEN
```

```bash
curl -X POST https://chat.getmushroom.app/admin/licenses/block \
  -H "authorization: Bearer $MUSHROOM_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"license_hash":"<sha256>"}'
```

This sets the status and revokes every device on the licence. Live sockets are deliberately
not closed from the endpoint: `stillAuthorized` re-checks each one within
`SOCKET_RECHECK_SECONDS` (300) and drops it, which needs no fan-out across every inbox.

Note this is a SEPARATE database from `mushroom-files`, which has its own identical endpoint.
Blocking someone on both channels means calling both. The hash is the same value in each.

## Test

Apply the migrations to the LOCAL database first. `--persist-to` has to match what
`wrangler dev` uses, or the schema lands in a different state directory than the one the
Worker reads:

```bash
npx wrangler d1 migrations apply mushroom-messaging --local --persist-to ../.wrangler-dev-state
```

```bash
npx wrangler dev --port 8788 --persist-to ../.wrangler-dev-state
```

```bash
./test.sh
```

Needed again any time `../.wrangler-dev-state` is deleted. Without it the database has no
tables, and the failure is around twenty assertions returning 500 with nothing saying why. The
preflight in `test.sh` catches that case and prints this command.

Runs with no credentials: it seeds a license and two devices straight into local D1, so
everything past the activation phase behaves identically whether or not Gumroad is
reachable. Set `MUSHROOM_TEST_LICENSE` to also exercise real activation.

**Reset local state between runs.** The last phase deliberately exhausts the day's invite
budget, so a second run without a reset fails from the first invite onward:

```bash
rm -rf ../.wrangler-dev-state
```

Then restart `wrangler dev` and re-apply the migration.

`socket-test.mjs` is the half curl cannot reach and `test.sh` invokes it; it needs only
Node 22+ for the global `WebSocket`, no dependency to install. Check against
`wrangler dev --remote` before deploying, because local D1 and DO emulation is not the same
code path as the real thing.

`alarm-test.sh` stands apart from both, and owns its own server, because the thing it asks
about lives in workerd's `_cf_ALARM` table and that can only be read once the process has let
go of the file:

```bash
./alarm-test.sh              # no APNs key at all
BOGUS_KEY=1 ./alarm-test.sh  # a key that is present but cannot sign
KEEP=1 ./alarm-test.sh       # leave the state dir behind to poke at
```

`SELFHOST=1` runs the same two scenarios against a self-hosted workerd box instead
(`../selfhost`, build it first with `npm install && ./build.sh` there). It asks the inbox
object over the unix-socket admin route rather than reading `_cf_ALARM`, which survives a
workerd storage-layout change and answers for one named identity instead of summing across
every inbox:

```bash
SELFHOST=1 ./alarm-test.sh
SELFHOST=1 BOGUS_KEY=1 ./alarm-test.sh
```

Both modes must agree. They are the same assertions, and a difference between them is a
difference between what we host and what a customer runs.

It pins two rules, one per scenario.

**A key that cannot sign must retry, but on a budget.** The re-arm used to be flat and
unconditional, so an expired or revoked `.p8` woke the inbox once a minute for the life of the
deployment, ours included, and nothing in the product would ever have said so. `PUSH_MAX_ATTEMPTS`
doubling from `PUSH_RETRY_MS` gives about an hour and then silence. The scenario asserts the
attempt counter was persisted, not the delay, because the first backoff is `PUSH_RETRY_MS`
either way: the counter is the only thing that distinguishes a bounded retry from the old one.

**An undelivered message must not arm a push alarm when APNs is not
configured.** A deployment with no APNs key is the normal state for anyone running this Worker
who is not us, since only our own `.p8` signs for `com.qubit.shroomy.app`. `apnsKey` throws for
an absent key exactly as it does for a broken one, and `alarm()` used to answer both by
re-arming at `PUSH_RETRY_MS`, so every inbox holding an unacked message woke on a timer
forever. On someone else's Cloudflare account that is a bill, charged quietly, for a
notification that could never have been sent. `apnsConfigured` is what separates the two
cases; delete it and this suite fails.

There is a third suite, on the Swift side, covering the seam neither of these can:

```bash
MUSHROOM_MESSAGING_BASE=http://localhost:8788 swift test --filter Wire
```

`Tests/MushroomPetKitTests/MessagingWireTests.swift` drives this Worker with the app's own
frame encoder and decoder. It is skipped unless that variable is set. It exists because
both sides passed their own suites completely while the app could not deliver a single
message: `URLSessionWebSocketTask.send(.data)` is a BINARY frame, this Worker was parsing
only text, and the failure was silent on both ends.

## Two instances on one Mac

The suites above never run the app's own client against a real inbox. This does, with two
side-by-side Debug builds on one Mac, and by default against the DEPLOYED Worker.

`MUSHROOM_INSTANCE` suffixes the Keychain services (`Keychain.swift`), which is the only
thing that was in the way: those items carry no access group, so without it both processes
read one `identity-private-key` and are one identity to `sha256(public_key)`. It also forces
iCloud sync off, because a same-bundle-id copy inherits the real app's change token from
UserDefaults while owning a throwaway `MUSHROOM_DB`.

It does NOT namespace UserDefaults, and that has a third consequence beyond the sync token and
the server pair. `receivedCursor` is `max(messagingCursor(), flushedThroughSeq)`, and
`flushedThroughSeq` is a UserDefaults key (`friendsFlushedThroughSeq`), so the two instances
share one delivery cursor and each one's value leaks into the other's ack. A two-instance run
will show an inbox recording a `deliveredUpTo` higher than any sequence it ever assigned. That
is the harness, not the product: a single client acking what it received produces a cursor that
matches its stored rows exactly. Do not go hunting it as a delivery bug.

Two REAL Gumroad keys, and ideally not the one on your everyday Mushroom: seats are capped
at 3 per licence and activating past the cap evicts the least-recently-seen device. Write
them into the Keychain rather than typing them into Settings, License, which spends a
`uses` increment per activation and is refused past the seat cap. `-T` puts the app on the
item's ACL so the launch-time read does not prompt.

```bash
security add-generic-password -U -s com.qubit.shroomy.license.a -a gumroad-license-key -w "KEY-ONE" -T "$PWD/debug_build/Mushroom.app"
```

```bash
security add-generic-password -U -s com.qubit.shroomy.license.b -a gumroad-license-key -w "KEY-TWO" -T "$PWD/debug_build/Mushroom.app"
```

Then `./debug_build.sh`, and launch each copy with its own environment. `open -n` for a
second instance, `--env` because the variables have to reach the PROCESS: setting them in
front of `./debug_build.sh` reaches the build only, and that script ends in `open -R`, which
just reveals the bundle in Finder.

```bash
open -n debug_build/Mushroom.app --env MUSHROOM_INSTANCE=a --env MUSHROOM_DB=~/mushroom-test/a/db.sqlite
```

```bash
open -n debug_build/Mushroom.app --env MUSHROOM_INSTANCE=b --env MUSHROOM_DB=~/mushroom-test/b/db.sqlite
```

A directory EACH, not two files in one directory. `Add-ons` and `Tools` are siblings of the
database (`AddOnManager.addOnsDirectory`, `PluginToolbox.toolsDirectory`), so two databases
side by side still share both.

Two menu bar icons, and two pet windows at the same saved position: drag one aside. Turn
Friends on in each (Settings, Friends: `messagingEnabledAt` is a settings row, so it is
per-instance), invite from one and accept in the other. Watch the Worker with
`npx wrangler tail --format pretty`.

Add `--env MUSHROOM_MESSAGING_BASE=http://localhost:8788` to both lines to point the same
pair at `wrangler dev` instead.

### Against a self-hosted box, the keys do not have to be real

Everything above about REAL Gumroad keys applies to the deployed Worker and to `wrangler dev`,
both of which ask Gumroad. A self-hosted box (`selfhost/`) answers that call itself from
`ENROLLMENT_HASHES`, so **two invented keys work**, no seat is spent, nothing can be evicted, and
production is never contacted at all. This is the safer harness, and it is the one to reach for.

Enrol the hashes on the box, write the same invented keys into the Keychain, and point both
instances at it. `MUSHROOM_FILES_BASE` matters as much as the messaging one: without it file
sharing still talks to us while Friends does not.

A Docker box needs no step here at all: `ENROLLMENT_HASHES` defaults to `*` and takes both invented
keys as they are. Only a box restricted to named keys needs their hashes:

```bash
printf '%s' 'MADE-UP-KEY-A' | shasum -a 256 | cut -d' ' -f1   # into ENROLLMENT_HASHES, both workers
```

Note the port split: FILES is the bare address and MESSAGING takes `:8443`, because `PUBLIC_BASE`
travels out in every share link and is the one address a non-user ever sees.

```bash
open -n debug_build/Mushroom.app --env MUSHROOM_INSTANCE=a --env MUSHROOM_DB=~/mushroom-test/a/db.sqlite \
  --env MUSHROOM_MESSAGING_BASE=https://box.example.ts.net:8443 --env MUSHROOM_FILES_BASE=https://box.example.ts.net \
  --env MUSHROOM_DEBUG_LICENSED=1
```

`MUSHROOM_DEBUG_LICENSED=1` because `isLicensed` is `Keychain.licenseKey() != nil` and an invented
key would otherwise fail the app's own 30 day re-verify against Gumroad. The box does not care;
this is only about the local gate.

Note what this does NOT cover. The two base overrides sit ahead of `ServerBase`
(`MessagingClient.base`), so this exercises the wire path and not the confirmed-pair gate, the
per-server Keychain tagging or `switchServers`. Those are Phase A machinery and are reached only
by typing both addresses into Settings, Data, Servers.

Finish by deleting the Keychain items and `rm -rf ~/mushroom-test`. Start Over is not needed here
the way it is against production: the seats are on a throwaway box, and there is no residue of
ours to leave behind.

Finish through Settings, Friends, Start Over in EACH instance, which releases the seat
before forgetting the identity. Deleting the Keychain items by hand instead leaks a seat and
leaves an inbox holding a live APNs token behind a cursor that can never advance. Then
`rm -rf ~/mushroom-test` and `security delete-generic-password -s com.qubit.shroomy.license.a`
(and `.b`).

Two things this does not test cleanly. The `identities` rows and both inbox Durable Objects
survive Start Over, so against production this leaves real residue: keep the test keys
stable rather than minting a fresh identity every session. And one bundle id means ONE APNs
device token for both processes, so both inboxes register the same token and a banner meant
for B can surface in A. The Worker's alarm-to-APNs path still runs for real (a Debug build
reports `sandbox`, which is why the sandbox host is picked), so read `wrangler tail`, not
the banner.

## Things that will look like bugs but are not

- **A retry gets the same sequence number back, not an error.** `msg_id` is UNIQUE and the
  insert is `INSERT OR IGNORE`, then the reply reads back the sequence the row *has*. That
  is what makes a resend after a dropped connection idempotent from both ends.

- **A blocked sender is told `not_friends`.** Deliberate. Telling someone they have been
  blocked is a thing for the blocker to grant, not for us to leak. The DO knows the
  difference, the sender does not.

- **A connected Mac never receives a push.** Delivery arms a 10 second alarm; the recipient's
  `ack` moves a cursor, and the alarm only pushes if the cursor has not caught up. There is
  no separate "is anyone online" check, because a socket being open is not proof a slept Mac
  can act on anything.

- **The push payload has no text in it.** `title-loc-key` / `loc-key` resolve against the
  app bundle, so the alert is localized on the Mac from the catalogs already shipped there
  and nothing readable crosses Apple's servers. Changing the wording is an app release, not
  a Worker deploy.

- **Message retention runs on the write path, not on the cron.** There is no way to
  enumerate Durable Objects, so a scheduled job could never reach the messages. Each inbox
  expires its own on every `deliver`. The cron only sweeps D1.

- **`presence=0` is symmetric.** Turning off "show when I'm online" also stops that Mac
  receiving anyone else's presence and typing. If you hide, you do not get to watch.

- **Presence is fire-and-forget, and the snapshot is served from local records.** It used to
  ask every friend's inbox on connect. Two Macs connecting at the same moment then deadlocked,
  each awaiting the other's object. Nothing in the presence path awaits a reply now: an
  announcement carries `reply_to`, and a friend who is online bounces their state back once.
  A cold inbox therefore reports nobody online for one round trip. That is the trade.

- **Only `/deliver` is an awaited object-to-object call.** Its handler makes no outbound call
  of its own, which is what keeps two friends replying simultaneously from deadlocking. Keep
  it that way: anything new that both awaits another inbox AND can be awaited by one
  reintroduces the cycle.

- **A frame can be text or binary.** The Mac app sends binary, Node and browsers send text.
  `webSocketMessage` decodes both. Parsing only one silently drops every frame from the other.

- **Typing frames vanish when the peer is offline.** They are relay-only: never stored,
  never queued, never acked, never pushed. A typing indicator has no value later.

- **Re-accepting an invite from someone you blocked does not unblock them.** `addFriend`
  updates the public key but never resets `blocked`, or a block would be undoable by the
  blocked party simply sending a fresh invite.

- **Activation fails closed, everything else fails open.** Handing out a *new* token while
  Gumroad is unreachable would make an outage a free pass. An already-issued token keeps
  working, which is CLAUDE.md §12: never lock a paying user out for being offline.

- **A blocked license stays blocked through re-activation.** `blocked` is our decision about
  abuse; Gumroad has no opinion on it, so a successful verify must not clear it.

## Logging rule

Observability is on and logs are retained. This Worker must never log a message body, a
ciphertext, an invite code, a license key or a bearer token. Ids and status codes only.

## What the server can see

Stated here so the privacy copy has something to match: that identity A sent something to
identity B at a time, roughly how large it was, and which Macs were connected. Not the text,
not the friend names (they never leave the Mac that chose them), and not who anybody is.
