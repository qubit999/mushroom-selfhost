# The whole box in one image: workerd, the blob sidecar, and the two housekeeping scripts.
#
# One image, four services: all four are the same tree with a different command, and three are a
# `while` loop around an existing shell script. compose.yaml is where they differ.
#
# Paths match the systemd layout exactly (/opt/mushroom, /var/lib/mushroom, /run/mushroom,
# /var/backups/mushroom), so cron.sh, backup.sh and config.capnp.example run here unchanged. Don't
# "tidy" them into /app.
# An ARG, not a literal: an air-gapped install mirrors this image anyway, and pinning by digest is
# sensible when Docker Hub is out of reach:
#   docker compose build --build-arg BASE=your-registry/node:22-slim
# Any Debian-based node 22 works; the image only needs a Node runtime and apt.
ARG BASE=node:22-slim
FROM ${BASE}

# sqlite3 for backup.sh's online backup, curl for cron.sh's unix-socket sweep. Both scripts check
# and say so, but failing at image build beats failing at 3am.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sqlite3 curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mushroom
COPY . .

# The build needs the network, but on whatever machine builds the image, so the box itself never
# needs an outbound route. For an air-gapped install, build elsewhere and move the result with
# `docker save` / `docker load`.
#
# The per-worker node_modules go afterwards: wrangler bundles every dependency into
# dist/<worker>/entry.js, the only thing config.capnp names, so the sources would just carry a
# spare copy of the Apple library. The root node_modules stays, pruned to workerd: wrangler is only
# the bundler.
RUN npm ci \
 && ./build.sh \
 && npm prune --omit=dev \
 && rm -rf /root/.npm /root/.cache messaging-worker/node_modules files-worker/node_modules

# A named volume takes its ownership from the image directory it's first mounted over, so
# creating these as `node` means nothing has to run as root to chown them later. workerd also
# won't start if a `disk` path is missing, which callers see only as "server never came up".
RUN mkdir -p /var/lib/mushroom/do-messaging /var/lib/mushroom/do-files /var/lib/mushroom/blobs \
             /var/backups/mushroom /run/mushroom /run/blobd \
 && chown -R node:node /var/lib/mushroom /var/backups/mushroom /run/mushroom /run/blobd /opt/mushroom

USER node
