# A release workflow must build/publish this image by immutable Git tag and
# record its digest. The source Dockerfile pins the Node runtime version so an
# Easypanel Git build is reproducible within that release boundary.
FROM node:22.23.1-bookworm-slim AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --audit=false --fund=false

COPY tsconfig.json tsconfig.test.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:22.23.1-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/Yuhtin/easypanel-mcp" \
      org.opencontainers.image.title="easypanel-mcp" \
      org.opencontainers.image.description="Security-first MCP server for bounded Easypanel operations"

COPY --from=build --chown=node:node /app/package.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
RUN mkdir -p /app/.state && chown node:node /app/.state

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "require('node:http').get('http://127.0.0.1:3000/healthz', (r) => process.exit(r.statusCode === 204 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/index.js"]
