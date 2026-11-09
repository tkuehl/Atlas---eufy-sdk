# Atlas eufy bridge: the SDK built from this fork + atlas-bridge/bridge.mjs. Build context = the repo root.
FROM node:24-bookworm-slim AS build
WORKDIR /sdk
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
RUN npm run build && npm prune --omit=dev

FROM node:24-bookworm-slim
WORKDIR /sdk
COPY --from=build /sdk/package.json ./
COPY --from=build /sdk/node_modules ./node_modules
COPY --from=build /sdk/dist ./dist
COPY atlas-bridge ./atlas-bridge
ENV NODE_ENV=production
EXPOSE 3100
CMD ["node", "atlas-bridge/bridge.mjs"]
