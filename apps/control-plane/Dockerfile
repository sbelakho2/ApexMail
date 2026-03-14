# ApexMail Control Plane — Next.js
#
# Multi-stage build: deps → build → runtime

# =============================================================================
# Dependency Install
# =============================================================================
FROM node:22-slim AS deps

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app

# Copy workspace root manifests
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/control-plane/package.json apps/control-plane/package.json

RUN pnpm install --frozen-lockfile --filter @apexmail/control-plane...

# =============================================================================
# Build
# =============================================================================
FROM deps AS builder

COPY apps/control-plane apps/control-plane
COPY tsconfig.base.json ./

ENV NEXT_TELEMETRY_DISABLED=1

RUN pnpm --filter @apexmail/control-plane run build

# =============================================================================
# Production Runtime
# =============================================================================
FROM node:22-slim AS runtime

# Create non-root user
RUN useradd -m -u 10001 -s /sbin/nologin apexmail

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Copy standalone output
COPY --from=builder --chown=apexmail:apexmail /app/apps/control-plane/.next/standalone ./
COPY --from=builder --chown=apexmail:apexmail /app/apps/control-plane/.next/static ./apps/control-plane/.next/static
COPY --from=builder --chown=apexmail:apexmail /app/apps/control-plane/public ./apps/control-plane/public

USER apexmail
EXPOSE 3002

LABEL org.opencontainers.image.title="apexmail-control-plane" \
    org.opencontainers.image.description="ApexMail control plane admin panel" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:3002/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"]

CMD ["node", "apps/control-plane/server.js"]
