# Running Mushroom on your own hardware

Mushroom's two servers, on a Linux box you own, with nothing in the path that belongs to us.

This is the stronger of the two self-hosting options. The other one runs the same servers in your
own Cloudflare account and is described in `deploy/README.md`. Read that first and be sure you need
this one: it already gives you your own tenancy, your own region, your own contract and your own
delete button, and it satisfies most security reviews.

## What you get, and what you give up

The app talks to your box and to nothing else. Messages and files never touch our servers, and we
are not the data processor for either. The servers make no outbound connections.

Three things are unavailable on a self-hosted deployment:

- **Background notifications.** Messages wait on your server and arrive when Mushroom is open.
- **In-app abuse reporting.** Handle misuse through your own policies and the admin commands below.
- **Online licence checks.** Not needed here, see Licences.

## What you need

- A Linux box on x86-64 or arm64, with Docker. Windows is not supported.
- A hostname your Macs can reach over **https**. The app requires https, so a plain-http box on a
  LAN cannot be reached at all. Tailscale is the simplest answer and needs no certificate
  management.
- One Mushroom licence per person. Three Macs per person, as usual.
- The direct download of Mushroom. The Mac App Store version cannot use custom servers.

If you would rather not run Docker, see **Without Docker** at the end.

## Install

Decide your hostname first. It goes in the configuration and the app puts it in every share link.

```bash
cp .env.example .env      # set PUBLIC_BASE to your file sharing address
docker compose up -d
```

That is the install. Check it came up:

```bash
docker compose ps
docker compose logs workerd
```

Four containers, from one image: `workerd` (the two servers), `blobd` (file storage), `cron`
(expiry sweeps) and `backup`. Data lives in three named volumes.

`.env` has two values, and only the first is required:

- **`PUBLIC_BASE`**. **Get this right.** It goes into every share link the box hands out, so a
  wrong value gives people links pointing somewhere else for files that live on yours. The
  deployment refuses to start without it.
- **`ENROLLMENT_HASHES`**, which defaults to `*`. See Licences.

### Keep a copy of your credentials

On first start the deployment generates an admin token and the keys that address your data, and
stores them on the state volume. Read them with:

```bash
docker compose exec workerd cat /var/lib/mushroom/secrets.env
```

**Back this file up somewhere safe.** Restoring a backup onto a deployment with different keys
leaves your data intact and completely unreadable. The nightly backup includes this file for that
reason, but a copy you hold separately is what saves you if you lose the volume and the backups
together.

### Air-gapped installs

Building the image needs the internet once, on whatever machine builds it. The deployment itself
never does. Build elsewhere and move the result:

```bash
docker save mushroom-selfhost | ssh yourbox 'docker load'
```

Set `BASE` in `.env` to build from your own registry mirror. Building on an Apple Silicon Mac for
an x86 box needs `docker build --platform linux/amd64 .`.

## Licences

**Nothing to do.** Everyone activates with the licence key they already have.

If you would rather the deployment only accept keys you have named, replace the `*` in
`ENROLLMENT_HASHES` with a space-separated list of hashes, one per person:

```bash
printf '%s' 'THEIR-LICENCE-KEY' | tr '[:lower:]' '[:upper:]' | sha256sum
```

Use `printf`, never `echo`: a trailing newline produces a hash that never matches. The
configuration holds hashes and never keys, so a leaked configuration file gives up nothing.
Removing someone is removing their hash and running `docker compose up -d` again.

## Put https in front

The containers publish plain http on the host's loopback only. Terminate TLS in front of them.
With Tailscale:

```bash
sudo tailscale serve --bg --https=443  http://127.0.0.1:8081   # file sharing
sudo tailscale serve --bg --https=8443 http://127.0.0.1:8080   # friends
```

**Note the crossing.** File sharing gets the bare `:443` address, because it is the one address
that reaches people who are not running Mushroom: it travels in every share link. Friends takes
the port.

Tailscale renews its own certificate, which is why it beats issuing one yourself. If you have
internal PKI and your own DNS name, terminate with your own proxy instead.

Both addresses must be bare origins with **no path**. A reverse proxy that mounts them under a
subpath such as `/api` will not work.

## Point the app at it

On each Mac, in Mushroom: **Settings, Data, Servers, Use my own servers**. Both addresses are
required, both must be https, and the switch has to be confirmed in the app. Nothing outside the
app can set this, by design.

The file sharing server is your bare `https://box` address; the friends server is the same host on
`:8443`. Getting those two the wrong way round is the easiest mistake to make here, and it appears
as "the server cannot be reached" rather than as anything that names the cause.

A badge on the Friends and Shared Files screens shows which server that Mac is using.

Switching servers deletes every message on that Mac and gives up its place on the previous server,
so do it once, at setup.

## Admin

Both admin surfaces are reachable only from inside the deployment, never over the network.

Block a licence and revoke its devices:

```bash
docker compose exec workerd sh -c '. /var/lib/mushroom/secrets.env; \
  curl --unix-socket /run/mushroom/admin.sock -X POST http://local/admin/licenses/block \
  -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  -d "{\"license_hash\":\"<sha256 of their key>\"}"'
```

Delete a shared file immediately, the same shape, against `/run/mushroom/files-admin.sock` and
`/admin/files/delete` with `{"file_id":"<id>"}`.

## Backups

The `backup` container runs nightly and keeps the newest three, in the `backups` volume.

It captures the databases and your generated credentials, not the shared files themselves. Every
shared file expires within a day, so restoring one is pointless, and a restore without them simply
shows the ordinary "this link has expired" page.

It uses SQLite's online backup rather than copying files, because the databases are live and a
copy taken mid-write restores corrupt. **Do not back these up with `cp`, `rsync` or a file-level
snapshot while the deployment is running**, and do not copy the Docker volume out from underneath
a running deployment either. That is the same mistake in a different form.

To take a backup off the box:

```bash
docker compose cp backup:/var/backups/mushroom ./mushroom-backups
```

To restore: `docker compose down`, put a backup's directory tree back into the `state` volume
including `secrets.env`, then `docker compose up -d`.

The output line says how many databases it captured. On a deployment in use that should be at
least three, and a sudden drop is worth looking into.

## Upgrades

```bash
docker compose pull        # or: git pull, if you build from source
docker compose up -d --build
```

Database migrations apply themselves on the first request after the restart. There is no migration
command to run and none to forget. The volumes and your credentials survive, so the data comes back
with it.

## Checking it works

The servers answer on both addresses:

```bash
curl -si https://your-box/        | head -1   # file sharing
curl -si https://your-box:8443/   | head -1   # friends
```

Both should return a `302`. If they do not, the problem is TLS or the proxy in front, not
Mushroom.

**The check that actually proves a deployment is a message arriving between two Macs.** Point two
Macs at the box, add each other from the Friends screen, and send one message in each direction.
Activation, connecting and sending all succeed even when delivery is broken, so nothing short of
arrival tells you the deployment is healthy. Then share a file from one of them and confirm the
link opens: that exercises the other server and confirms `PUBLIC_BASE`.

## When something is wrong

- **`docker compose logs workerd`** first, then `docker compose ps`.
- **It will not start, saying `PUBLIC_BASE is not set`.** There is no `.env`, or it is not next to
  `compose.yaml`.
- **Every activation fails.** `ENROLLMENT_HASHES` is a list and the key is not in it. Set it to
  `*`, or recompute the hash with `printf` rather than `echo`.
- **The app says the server cannot be reached.** That is https failing, not Mushroom. Check
  `tailscale serve status`, check the address has no path on the end, and check the two addresses
  are not swapped: file sharing is the bare address, friends is `:8443`.
- **Share links point at the wrong place.** `PUBLIC_BASE` is wrong. Fix `.env` and run
  `docker compose up -d`. Links already handed out keep the old address.
- **Activations start failing after a burst.** They are rate limited per source address, and
  everything behind your proxy looks like one address. Wait a minute.

## Without Docker

The same deployment under systemd. You need Node 22 or newer and `sqlite3`.

```bash
sudo useradd --system --home /var/lib/mushroom --shell /usr/sbin/nologin mushroom
sudo mkdir -p /opt/mushroom /var/lib/mushroom /var/backups/mushroom
sudo chown -R mushroom:mushroom /var/lib/mushroom /var/backups/mushroom
```

Unpack the release into `/opt/mushroom`, then build and write a configuration:

```bash
cd /opt/mushroom
npm install
./build.sh
cp config.capnp.example config.capnp
```

Edit `config.capnp`. Every value needing attention is marked `CHANGE ME`: `PUBLIC_BASE`,
`ADMIN_TOKEN`, `ENROLLMENT_HASHES` (`*` or a list, as above), and the `uniqueKey` on each storage
namespace. A `uniqueKey` is any long random string, and it must be set once and never changed:
changing it makes existing data unreachable.

**Do not remove the outbound network restrictions.** They are what keep the deployment from making
any outbound connection, and the configuration file marks them clearly.

```bash
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mushroom-blobd mushroom-workerd
sudo systemctl enable --now mushroom-cron.timer mushroom-backup.timer
systemctl list-timers 'mushroom-*'
```

That last line matters: a sweep that has silently stopped running is worth catching early.

Three differences when troubleshooting. `journalctl -u mushroom-workerd -n 50` replaces
`docker compose logs`. If the service will not start and reports a missing directory, a storage
path in `config.capnp` does not exist yet: create it and `chown mushroom`. If it will not start and
mentions its configuration, run it from `/opt/mushroom`, because the configuration refers to files
by relative path.

Upgrading is `systemctl stop mushroom-workerd`, unpack the new release keeping your `config.capnp`,
`npm install && ./build.sh`, and start it again.
