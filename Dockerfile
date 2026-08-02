# The whole box in one image: workerd, the blob sidecar, and the two housekeeping scripts.
#
# One image and four services rather than four images, because all four are the same tree with a
# different command, and three of them are a `while` loop around a shell script that already
# exists. compose.yaml is where they differ.
#
# Paths are IDENTICAL to the systemd layout (/opt/mushroom, /var/lib/mushroom, /run/mushroom,
# /var/backups/mushroom), which is what lets cron.sh, backup.sh and config.capnp.example run here
# with no changes at all. Do not "tidy" them into /app.
# An ARG rather than a literal because an air-gapped install has to mirror this image somewhere
# anyway, and pinning it by digest is the reasonable thing to do when you cannot reach Docker Hub:
#   docker compose build --build-arg BASE=your-registry/node:22-slim
# Any Debian-based node 22 works. The image only wants a Node runtime and apt.
ARG BASE=node:22-slim
FROM ${BASE}

# sqlite3 for backup.sh's online backup, curl for cron.sh's unix-socket sweep call. Both scripts
# check for what they need and say so, but failing at image build is better than at 3am.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sqlite3 curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mushroom
COPY . .

# The build needs the network, exactly as it does today. The difference is WHERE: this runs on
# whatever machine builds the image, so the box itself never needs an outbound route. For an
# air-gapped install, build here and move the result with `docker save` / `docker load`.
#
# The per-worker node_modules go afterwards: wrangler bundles every dependency into
# dist/<worker>/entry.js, which is the only thing config.capnp names, so keeping the sources
# around would be carrying a copy of the Apple library for nothing. The ROOT node_modules stays,
# because that is where workerd itself lives.
RUN npm install \
 && ./build.sh \
 && rm -rf /root/.npm /root/.cache messaging-worker/node_modules files-worker/node_modules

# A named volume takes its ownership from the image directory it is first mounted over, so
# creating these as `node` here is what means nothing has to run as root to chown them later.
# workerd also refuses to start if a `disk` path is missing, with a message that reaches the
# caller only as "server never came up".
RUN mkdir -p /var/lib/mushroom/do-messaging /var/lib/mushroom/do-files /var/lib/mushroom/blobs \
             /var/backups/mushroom /run/mushroom \
 && chown -R node:node /var/lib/mushroom /var/backups/mushroom /run/mushroom /opt/mushroom

USER node
