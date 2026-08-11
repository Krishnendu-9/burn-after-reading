# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- build ----
# Full dependency tree, used only to compile the front end.
FROM node:22-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# -------------------------------------------------------------- runtime ----
FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app

# Production dependencies only. better-sqlite3 pulls a prebuilt binary for this
# platform, which is why the build and runtime images share a base — a native
# module compiled against one libc will not load on another.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

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
