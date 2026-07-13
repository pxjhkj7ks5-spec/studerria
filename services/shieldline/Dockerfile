FROM node:22-bookworm-slim AS base
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

FROM base AS deps
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

FROM base AS builder
ARG SHIELDLINE_BASE_PATH=/shieldline
ENV SHIELDLINE_BASE_PATH=${SHIELDLINE_BASE_PATH}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN --mount=type=cache,target=/app/node_modules/.vite npm run build

FROM base AS runner
ARG SHIELDLINE_BASE_PATH=/shieldline
ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=8080
ENV SHIELDLINE_BASE_PATH=${SHIELDLINE_BASE_PATH}

RUN groupadd --system --gid 1001 nodejs \
  && useradd --system --uid 1001 --gid nodejs shieldline \
  && mkdir -p /data \
  && chown -R shieldline:nodejs /data

COPY --chown=shieldline:nodejs --from=builder /app/dist ./dist
COPY --chown=shieldline:nodejs --from=deps /app/node_modules ./node_modules
COPY --chown=shieldline:nodejs --from=builder /app/server.mjs ./server.mjs
COPY --chown=shieldline:nodejs --from=builder /app/serverGame.mjs ./serverGame.mjs
COPY --chown=shieldline:nodejs --from=builder /app/serverSecurity.mjs ./serverSecurity.mjs
COPY --chown=shieldline:nodejs --from=builder /app/serverSchemas.mjs ./serverSchemas.mjs
COPY --chown=shieldline:nodejs --from=builder /app/serverTelemetry.mjs ./serverTelemetry.mjs
COPY --chown=shieldline:nodejs --from=builder /app/serverPostgresStore.mjs ./serverPostgresStore.mjs
COPY --chown=shieldline:nodejs --from=builder /app/worker.mjs ./worker.mjs
COPY --chown=shieldline:nodejs --from=builder /app/scripts ./scripts
COPY --chown=shieldline:nodejs --from=builder /app/src/game/simulationCore.mjs ./src/game/simulationCore.mjs
COPY --chown=shieldline:nodejs --from=builder /app/src/game/launchSystem.mjs ./src/game/launchSystem.mjs
COPY --chown=shieldline:nodejs --from=builder /app/src/game/campaignPacing.mjs ./src/game/campaignPacing.mjs
COPY --chown=shieldline:nodejs --from=builder /app/package.json ./package.json

USER shieldline

EXPOSE 8080

CMD ["node", "server.mjs"]
