# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- build ----
# Full dependency tree, used only to compile the front end.
FROM node:22-bookworm-slim AS build

WORKDIR /app

# --ignore-scripts: no dependency needs an install script here (see the
# runtime stage), and none gets to run one.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build

# -------------------------------------------------------------- runtime ----
FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app

# Production dependencies only. better-sqlite3 ships prebuilt binaries for each
# platform and libc inside the package and picks one when it loads.
#
# --ignore-scripts because the npm bundled with Node 22 (10.x) ignores the
# package's `"gypfile": false` and compiles it from source anyway, which fails
# here: the slim image has no Python or compiler, and needs neither. No runtime
# dependency has an install script of its own, and CI's smoke test proves the
# bundled binary loads.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=build /app/public/dist ./public/dist
COPY --from=build /app/views       ./views
COPY --from=build /app/src         ./src
COPY --from=build /app/server.js   ./server.js

# SQLite writes here. Without a mounted volume the database — and therefore every
# unread secret — disappears when the container is replaced.
RUN mkdir -p /app/data && chown -R node:node /app
VOLUME ["/app/data"]

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Exec form on purpose: node runs as PID 1 and receives SIGTERM directly, which is
# what the graceful shutdown handler needs. Wrapping this in a shell would swallow
# the signal and every stop would become a hard kill on the database.
CMD ["node", "server.js"]
