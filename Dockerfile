# syntax=docker/dockerfile:1.18
# Multi-stage minimal image for Fastify API
# Build stage installs deps with caching
FROM node:22-alpine AS deps
WORKDIR /app
# Install only production dependencies (no build step needed)
COPY src/package.json src/yarn.lock* src/package-lock.json* ./
# Prefer yarn if lockfile exists
## Use --frozen-lockfile for reproducibility; if it fails (lock out of sync) fall back to normal install
RUN if [ -f yarn.lock ]; then yarn install --frozen-lockfile --production=false || yarn install --production=false; \
    elif [ -f package-lock.json ]; then npm ci; \
    elif [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install --frozen-lockfile; \
    else yarn install --production=false; fi

# Prune dev dependencies to shrink final size
RUN if [ -f yarn.lock ]; then yarn workspaces focus --production 2>/dev/null || yarn install --production --ignore-scripts --prefer-offline; fi || true \
 && if [ -f package-lock.json ]; then npm prune --production; fi || true \
 && if [ -f pnpm-lock.yaml ]; then pnpm prune --prod; fi || true

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Add non-root user
RUN addgroup -S nodejs && adduser -S nodejs -G nodejs
# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules
# Copy application source (only necessary files)
COPY src/app.js src/config.js ./
COPY src/routes ./routes
COPY src/services ./services
# Optionally copy .env at runtime via docker secrets / env injection, not baked in image
EXPOSE 3000
USER nodejs
# Healthcheck (basic TCP) could be added externally; simple command check here
# HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD node -e 'require("http").get("http://localhost:"+(process.env.PORT||3000)+"/api/stats",res=>{if(res.statusCode<500)process.exit(0);process.exit(1)}).on("error",()=>process.exit(1))'
CMD ["node", "app.js"]
