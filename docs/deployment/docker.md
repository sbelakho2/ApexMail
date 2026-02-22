# Docker Deployment

Complete guide to deploying ApexMail with Docker and Docker Compose.

## Overview

ApexMail is designed for containerized deployment with the following components:

| Service | Container | Port | Description |
|---------|-----------|------|-------------|
| API | `apexmail-api` | 3001 | REST API server |
| Web | `apexmail-web` | 3000 | Next.js dashboard |
| Worker | `apexmail-worker` | - | Background job processor |
| Tracking | `apexmail-tracking` | 3002 | Open/click tracking |
| Analytics | `apexmail-analytics` | 3010 | Analytics engine |
| AI | `apexmail-ai` | 3012 | AI inference service |
| Compliance | `apexmail-compliance` | 3013 | Security & GDPR |
| CRM | `apexmail-crm` | 3014 | Sales Autopilot |
| Ops | `apexmail-ops` | 9090 | Monitoring & SLOs |
| MTA | `apexmail-mta` | 25, 587 | Postfix mail server |
| PostgreSQL | `apexmail-postgres` | 5432 | Primary database |
| Redis | `apexmail-redis` | 6379 | Cache & queues |

---

## Docker Compose Configuration

### Production Compose File

Create `docker-compose.prod.yml`:

```yaml
version: '3.9'

services:
  # ===================
  # Infrastructure
  # ===================
  
  postgres:
    image: postgres:15-alpine
    container_name: apexmail-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-apexmail}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-apexmail}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-apexmail}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - apexmail-network

  redis:
    image: redis:7-alpine
    container_name: apexmail-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - apexmail-network

  # ===================
  # Application Services
  # ===================

  api:
    build:
      context: .
      dockerfile: apps/api/Dockerfile
    container_name: apexmail-api
    restart: unless-stopped
    ports:
      - "3001:3001"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - apexmail-network

  web:
    build:
      context: .
      dockerfile: apps/web/Dockerfile
    container_name: apexmail-web
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      NEXT_PUBLIC_API_URL: ${API_URL:-http://api:3001}
    depends_on:
      - api
    networks:
      - apexmail-network

  worker:
    build:
      context: .
      dockerfile: apps/worker/Dockerfile
    container_name: apexmail-worker
    restart: unless-stopped
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    deploy:
      replicas: 2
    networks:
      - apexmail-network

  tracking:
    build:
      context: .
      dockerfile: Dockerfile.tracking
    container_name: apexmail-tracking
    restart: unless-stopped
    ports:
      - "3002:3002"
    environment:
      TRACKING_SECRET_KEY: ${TRACKING_SECRET_KEY}
      REDIS_HOST: redis
      REDIS_PORT: 6379
      REDIS_PASSWORD: ${REDIS_PASSWORD}
      RUST_LOG: info
    depends_on:
      - postgres
      - redis
    networks:
      - apexmail-network

  analytics:
    build:
      context: .
      dockerfile: apps/analytics/Dockerfile
    container_name: apexmail-analytics
    restart: unless-stopped
    ports:
      - "3010:3010"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
    depends_on:
      - postgres
    networks:
      - apexmail-network

  ai:
    build:
      context: .
      dockerfile: apps/ai/Dockerfile
    container_name: apexmail-ai
    restart: unless-stopped
    ports:
      - "3012:3012"
    environment:
      NODE_ENV: production
      MODEL_PATH: /models
    volumes:
      - ai_models:/models
    networks:
      - apexmail-network

  compliance:
    build:
      context: .
      dockerfile: apps/compliance/Dockerfile
    container_name: apexmail-compliance
    restart: unless-stopped
    ports:
      - "3013:3013"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    depends_on:
      - postgres
    networks:
      - apexmail-network

  crm:
    build:
      context: .
      dockerfile: apps/sales-autopilot/Dockerfile
    container_name: apexmail-crm
    restart: unless-stopped
    ports:
      - "3014:3014"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - postgres
      - redis
    networks:
      - apexmail-network

  ops:
    build:
      context: .
      dockerfile: apps/ops/Dockerfile
    container_name: apexmail-ops
    restart: unless-stopped
    ports:
      - "9090:9090"
    environment:
      NODE_ENV: production
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - redis
    networks:
      - apexmail-network

  # ===================
  # Mail Transfer Agent
  # ===================

  mta:
    build:
      context: .
      dockerfile: apps/mta/Dockerfile
    container_name: apexmail-mta
    restart: unless-stopped
    ports:
      - "25:25"
      - "587:587"
    environment:
      HOSTNAME: ${MTA_HOSTNAME}
      RELAY_NETWORKS: 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
    volumes:
      - mta_spool:/var/spool/postfix
      - mta_certs:/etc/postfix/certs
    cap_add:
      - NET_BIND_SERVICE
    networks:
      - apexmail-network

  # ===================
  # Reverse Proxy
  # ===================

  nginx:
    image: nginx:alpine
    container_name: apexmail-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
      - nginx_cache:/var/cache/nginx
    depends_on:
      - api
      - web
      - tracking
    networks:
      - apexmail-network

volumes:
  postgres_data:
  redis_data:
  ai_models:
  mta_spool:
  mta_certs:
  nginx_cache:

networks:
  apexmail-network:
    driver: bridge
```

---

## Dockerfile Examples

### API Dockerfile

```dockerfile
# apps/api/Dockerfile
FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json ./apps/api/
COPY packages/db/package.json ./packages/db/
COPY packages/lib/package.json ./packages/lib/

RUN corepack enable pnpm && pnpm install --frozen-lockfile

# Build the application
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN corepack enable pnpm && pnpm build --filter @apexmail/api

# Production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 apexmail

COPY --from=builder --chown=apexmail:nodejs /app/apps/api/dist ./dist
COPY --from=builder --chown=apexmail:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=apexmail:nodejs /app/apps/api/package.json ./package.json

USER apexmail

EXPOSE 3001

CMD ["node", "dist/index.js"]
```

### Web Dockerfile

```dockerfile
# apps/web/Dockerfile
FROM node:20-alpine AS base

FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/
COPY packages/lib/package.json ./packages/lib/

RUN corepack enable pnpm && pnpm install --frozen-lockfile

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

RUN corepack enable pnpm && pnpm build --filter @apexmail/web

FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/apps/web/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
```

---

## Nginx Configuration

Create `nginx/nginx.conf`:

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript 
               application/rss+xml application/atom+xml image/svg+xml;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=tracking:10m rate=1000r/s;

    # Upstream definitions
    upstream api_backend {
        server api:3001;
        keepalive 32;
    }

    upstream web_backend {
        server web:3000;
        keepalive 32;
    }

    upstream tracking_backend {
        server tracking:3002;
        keepalive 64;
    }

    # HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main application
    server {
        listen 443 ssl http2;
        server_name app.example.com;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # Web dashboard
        location / {
            proxy_pass http://web_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }
    }

    # API server
    server {
        listen 443 ssl http2;
        server_name api.example.com;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        location / {
            limit_req zone=api burst=50 nodelay;
            
            proxy_pass http://api_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # CORS headers
            add_header Access-Control-Allow-Origin $http_origin always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
            
            if ($request_method = OPTIONS) {
                return 204;
            }
        }
    }

    # Tracking server (high performance)
    server {
        listen 443 ssl http2;
        server_name t.example.com;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        location / {
            limit_req zone=tracking burst=500 nodelay;
            
            proxy_pass http://tracking_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # Caching for tracking pixel
            proxy_cache_valid 200 1m;
        }
    }
}
```

---

## Environment Variables

Create `.env.production`:

```env
# ===================
# Database
# ===================
POSTGRES_USER=apexmail
POSTGRES_PASSWORD=<generate-secure-password>
POSTGRES_DB=apexmail

# ===================
# Redis
# ===================
REDIS_PASSWORD=<generate-secure-password>

# ===================
# Security
# ===================
JWT_SECRET=<generate-with-openssl-rand-base64-64>
ENCRYPTION_KEY=<generate-with-openssl-rand-base64-32>

# ===================
# URLs
# ===================
API_URL=https://api.example.com
WEB_URL=https://app.example.com
TRACKING_URL=https://t.example.com

# ===================
# Mail
# ===================
MTA_HOSTNAME=mail.example.com
DKIM_SELECTOR=apexmail
DKIM_PRIVATE_KEY=<base64-encoded-private-key>

# ===================
# Monitoring (Optional)
# ===================
SENTRY_DSN=<your-sentry-dsn>
```

---

## Deployment Commands

### Initial Deployment

```bash
# Pull latest code
git pull origin main

# Build images
docker compose -f docker-compose.prod.yml build

# Start services
docker compose -f docker-compose.prod.yml up -d

# Run migrations
docker compose -f docker-compose.prod.yml exec api pnpm db:migrate

# Check status
docker compose -f docker-compose.prod.yml ps
```

### Updates

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker compose -f docker-compose.prod.yml up -d --build

# Run any new migrations
docker compose -f docker-compose.prod.yml exec api pnpm db:migrate
```

### Scaling

```bash
# Scale workers
docker compose -f docker-compose.prod.yml up -d --scale worker=4

# Scale API (requires load balancer)
docker compose -f docker-compose.prod.yml up -d --scale api=3
```

### Logs

```bash
# All logs
docker compose -f docker-compose.prod.yml logs -f

# Specific service
docker compose -f docker-compose.prod.yml logs -f api

# Last 100 lines
docker compose -f docker-compose.prod.yml logs --tail=100 api
```

### Backup

```bash
# Database backup
docker compose -f docker-compose.prod.yml exec postgres \
  pg_dump -U apexmail apexmail > backup-$(date +%Y%m%d).sql

# Redis backup
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD BGSAVE
```

---

## Health Monitoring

### Healthcheck Endpoints

| Service | Endpoint | Expected Response |
|---------|----------|-------------------|
| API | `GET /health` | `{"status": "healthy"}` |
| Web | `GET /api/health` | `{"status": "ok"}` |
| Tracking | `GET /health` | `{"status": "healthy"}` |
| Ops | `GET /health` | `{"status": "healthy"}` |

### Docker Healthcheck

```bash
# Check all service health
docker compose -f docker-compose.prod.yml ps

# Detailed health status
docker inspect --format='{{json .State.Health}}' apexmail-api | jq
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose -f docker-compose.prod.yml logs api

# Check configuration
docker compose -f docker-compose.prod.yml config

# Restart single service
docker compose -f docker-compose.prod.yml restart api
```

### Database Connection Issues

```bash
# Test connection
docker compose -f docker-compose.prod.yml exec api \
  node -e "require('@apexmail/db').testConnection()"

# Check postgres logs
docker compose -f docker-compose.prod.yml logs postgres
```

### Out of Memory

```bash
# Check resource usage
docker stats

# Increase limits in compose file
# services:
#   api:
#     deploy:
#       resources:
#         limits:
#           memory: 2G
```
