# ApexMail Billing Service — Node.js (Hono)
#
# Multi-stage build: install → build → runtime

# =============================================================================
# Dependency install
# =============================================================================
FROM node:22-slim AS deps

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app

# Copy workspace root manifests
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/billing/package.json apps/billing/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/lib/package.json packages/lib/package.json

RUN pnpm install --frozen-lockfile --filter @apexmail/billing...

# =============================================================================
# Build
# =============================================================================
FROM deps AS builder

# Copy source for billing and its workspace deps
COPY packages/db packages/db
COPY packages/lib packages/lib
COPY apps/billing apps/billing
COPY tsconfig.base.json ./

RUN pnpm --filter @apexmail/billing... run build

# =============================================================================
# Production runtime
# =============================================================================
FROM node:22-slim AS runtime

RUN corepack enable && corepack prepare pnpm@9 --activate

# Create non-root user
RUN useradd -m -u 10001 -s /sbin/nologin apexmail

WORKDIR /app

# Copy built output and prod deps
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/billing/dist ./apps/billing/dist
COPY --from=builder /app/apps/billing/package.json ./apps/billing/package.json
COPY --from=builder /app/packages/db/dist ./packages/db/dist
COPY --from=builder /app/packages/db/package.json ./packages/db/package.json
COPY --from=builder /app/packages/lib/dist ./packages/lib/dist
COPY --from=builder /app/packages/lib/package.json ./packages/lib/package.json

USER apexmail
EXPOSE 3001

LABEL org.opencontainers.image.title="apexmail-billing" \
    org.opencontainers.image.description="ApexMail billing service" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3001"]

CMD ["node", "apps/billing/dist/index.js"]
