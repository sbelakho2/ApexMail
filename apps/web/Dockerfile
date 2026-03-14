# ApexMail Web Dashboard — Next.js
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
COPY apps/web/package.json apps/web/package.json

RUN pnpm install --frozen-lockfile --filter @apexmail/web...

# =============================================================================
# Build
# =============================================================================
FROM deps AS builder

COPY apps/web apps/web
COPY tsconfig.base.json ./

ENV NEXT_TELEMETRY_DISABLED=1

RUN pnpm --filter @apexmail/web run build

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
COPY --from=builder --chown=apexmail:apexmail /app/apps/web/.next/standalone ./
COPY --from=builder --chown=apexmail:apexmail /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=apexmail:apexmail /app/apps/web/public ./apps/web/public

USER apexmail
EXPOSE 3000

LABEL org.opencontainers.image.title="apexmail-web" \
    org.opencontainers.image.description="ApexMail web dashboard" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"]

CMD ["node", "apps/web/server.js"]
