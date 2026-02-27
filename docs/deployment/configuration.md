# Configuration Reference

Complete reference for all ApexMail configuration options.

## Environment Variables

### Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_ENV` | ✓ | `development` | Environment: `development`, `production`, `test` |
| `PORT` | | `3001` | API server port |
| `HOST` | | `0.0.0.0` | Server bind address |
| `LOG_LEVEL` | | `info` | Logging level: `debug`, `info`, `warn`, `error` |

### Database

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✓ | - | PostgreSQL connection string |
| `DATABASE_POOL_MIN` | | `2` | Minimum pool connections |
| `DATABASE_POOL_MAX` | | `10` | Maximum pool connections |
| `DATABASE_SSL` | | `false` | Enable SSL for database |

```env
# Example
DATABASE_URL="postgresql://user:password@localhost:5432/apexmail?schema=public"
DATABASE_POOL_MAX=20
DATABASE_SSL=true
```

### Redis

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | ✓ | - | Redis connection string |
| `REDIS_CLUSTER` | | `false` | Enable cluster mode |
| `REDIS_TLS` | | `false` | Enable TLS |

```env
# Single instance
REDIS_URL="redis://:password@localhost:6379"

# Cluster mode
REDIS_URL="redis://:password@node1:6379,node2:6379,node3:6379"
REDIS_CLUSTER=true
```

### Authentication

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | ✓ | - | JWT signing secret (min 32 chars) |
| `JWT_ACCESS_TTL` | | `3600` | Access token TTL (seconds) |
| `JWT_REFRESH_TTL` | | `2592000` | Refresh token TTL (30 days) |
| `JWT_ALGORITHM` | | `ES256` | JWT algorithm |

```env
# Generate with: openssl rand -base64 64
JWT_SECRET="your-super-secret-jwt-key-at-least-32-characters-long"
JWT_ACCESS_TTL=3600
JWT_REFRESH_TTL=2592000
```

### Login CAPTCHA (mCaptcha)

Login protection is available for both login surfaces:
- User web login: `apps/web` (`/login`)
- Control-plane login: `apps/control-plane` (`/login`)

Server-side verification variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MCAPTCHA_ENABLED` | | `false` | Enforce CAPTCHA verification in login API routes |
| `MCAPTCHA_SITE_KEY` | ✓ when enabled | - | Site key sent to verification API |
| `MCAPTCHA_SECRET` | ✓ when enabled | - | Secret sent to verification API |
| `MCAPTCHA_VERIFY_URL` | | `https://demo.mcaptcha.org/api/v1/pow/siteverify` | Verification endpoint |

Frontend widget variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXT_PUBLIC_MCAPTCHA_ENABLED` | | `false` | Render mCaptcha widget in login pages |
| `NEXT_PUBLIC_MCAPTCHA_WIDGET_URL` | ✓ when enabled | - | Widget URL used by vanilla glue |
| `NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL` | | `https://unpkg.com/@mcaptcha/vanilla-glue@0.1.0-rc2/dist/index.js` | Optional glue script override |

```env
# Server-side enforcement
MCAPTCHA_ENABLED=true
MCAPTCHA_SITE_KEY=your-site-key
MCAPTCHA_SECRET=your-secret
MCAPTCHA_VERIFY_URL=https://demo.mcaptcha.org/api/v1/pow/siteverify

# Frontend widget rendering
NEXT_PUBLIC_MCAPTCHA_ENABLED=true
NEXT_PUBLIC_MCAPTCHA_WIDGET_URL=https://your-mcaptcha-instance/widget-path
NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL=https://unpkg.com/@mcaptcha/vanilla-glue@0.1.0-rc2/dist/index.js
```

Behavior when enabled:
- Missing token: login is rejected (`MCAPTCHA_REQUIRED`)
- Invalid token: login is rejected (`MCAPTCHA_INVALID`)
- Provider/verification outage: login is rejected (`MCAPTCHA_UNAVAILABLE`)

Important: keep `MCAPTCHA_ENABLED` and `NEXT_PUBLIC_MCAPTCHA_ENABLED` aligned to avoid UX drift between form rendering and API enforcement.

### Encryption

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENCRYPTION_KEY` | ✓ | - | AES-256 encryption key (32 bytes base64) |
| `ENCRYPTION_ALGORITHM` | | `aes-256-gcm` | Encryption algorithm |

```env
# Generate with: openssl rand -base64 32
ENCRYPTION_KEY="base64-encoded-32-byte-key"
```

### Email Sending

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MTA_HOST` | | `localhost` | Postfix host |
| `MTA_PORT` | | `25` | Postfix port |
| `MTA_HOSTNAME` | ✓ | - | HELO/EHLO hostname |
| `DEFAULT_FROM_EMAIL` | | - | Default sender address |
| `DEFAULT_FROM_NAME` | | - | Default sender name |

```env
MTA_HOST=postfix
MTA_PORT=25
MTA_HOSTNAME=mail.example.com
DEFAULT_FROM_EMAIL=noreply@example.com
DEFAULT_FROM_NAME="ApexMail"
```

### DKIM Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DKIM_SELECTOR` | | `apexmail` | DKIM selector |
| `DKIM_PRIVATE_KEY` | | - | DKIM private key (PEM or base64) |
| `DKIM_DOMAIN` | | - | Signing domain |

```env
DKIM_SELECTOR=apexmail
DKIM_DOMAIN=example.com
DKIM_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
```

### Rate Limiting

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | | `true` | Enable rate limiting |
| `RATE_LIMIT_WINDOW` | | `60` | Window size (seconds) |
| `RATE_LIMIT_MAX` | | `100` | Max requests per window |
| `RATE_LIMIT_BURST` | | `50` | Burst allowance |

```env
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW=60
RATE_LIMIT_MAX=1000
RATE_LIMIT_BURST=200
```

### CORS

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CORS_ENABLED` | | `true` | Enable CORS |
| `CORS_ORIGINS` | | `*` | Allowed origins (comma-separated) |
| `CORS_METHODS` | | `GET,POST,PUT,DELETE` | Allowed methods |
| `CORS_CREDENTIALS` | | `true` | Allow credentials |

```env
CORS_ORIGINS=https://app.example.com,https://admin.example.com
CORS_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
CORS_CREDENTIALS=true
```

### Monitoring

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SENTRY_DSN` | | - | Sentry error tracking DSN |
| `SENTRY_ENVIRONMENT` | | `NODE_ENV` | Sentry environment |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | | - | OpenTelemetry collector |
| `PROMETHEUS_ENABLED` | | `true` | Enable Prometheus metrics |
| `PROMETHEUS_PORT` | | `9090` | Metrics port |

```env
SENTRY_DSN=https://xxx@sentry.io/123
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317
PROMETHEUS_ENABLED=true
```

### Feature Flags

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FEATURE_AI_ENABLED` | | `true` | Enable AI features |
| `FEATURE_STO_ENABLED` | | `true` | Send time optimization |
| `FEATURE_AB_TESTING` | | `true` | A/B testing |
| `FEATURE_WEBHOOKS` | | `true` | Webhook delivery |

```env
FEATURE_AI_ENABLED=true
FEATURE_STO_ENABLED=true
FEATURE_AB_TESTING=true
```

---

## Domain Verification

### DNS Records

To send emails from your domain, configure these DNS records:

#### SPF Record

```dns
Type: TXT
Host: @
Value: v=spf1 include:_spf.apexmail.ee ~all
```

#### DKIM Record

```dns
Type: TXT
Host: apexmail._domainkey
Value: v=DKIM1; k=rsa; p=MIIBIjAN...
```

Generate DKIM keys:
```bash
openssl genrsa -out dkim.private 2048
openssl rsa -in dkim.private -pubout -out dkim.public
```

#### DMARC Record

```dns
Type: TXT
Host: _dmarc
Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100
```

### Verification Process

1. **Add Domain** in Settings → Domains
2. **Configure DNS** records as shown above
3. **Verify** - System checks DNS propagation
4. **Activate** - Start sending from domain

Verification status:
- ⏳ **Pending** - DNS records not yet found
- ✅ **Verified** - All records valid
- ⚠️ **Partial** - Some records missing
- ❌ **Failed** - Invalid records

---

## SMTP Configuration

### Postfix Main Configuration

`/etc/postfix/main.cf`:

```conf
# Basic settings
myhostname = mail.example.com
mydomain = example.com
myorigin = $mydomain

# Network settings
inet_interfaces = all
inet_protocols = ipv4

# TLS settings
smtpd_tls_cert_file = /etc/postfix/certs/fullchain.pem
smtpd_tls_key_file = /etc/postfix/certs/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtp_tls_loglevel = 1

# DKIM
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# Queue settings
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
queue_run_delay = 300s
minimal_backoff_time = 300s
maximal_backoff_time = 4000s

# Rate limiting
smtp_destination_rate_delay = 1s
smtp_destination_concurrency_limit = 20
default_destination_rate_delay = 0
default_destination_concurrency_limit = 20

# Size limits
message_size_limit = 26214400
mailbox_size_limit = 0

# Header cleanup
header_checks = regexp:/etc/postfix/header_checks
```

### IP Warmup Schedule

When using new IP addresses, follow this warmup schedule:

| Day | Daily Volume | Notes |
|-----|--------------|-------|
| 1-2 | 50 | Test deliverability |
| 3-4 | 100 | Monitor bounces |
| 5-7 | 250 | Check reputation |
| 8-10 | 500 | Increase gradually |
| 11-14 | 1,000 | Monitor feedback loops |
| 15-21 | 2,500 | Watch for blocks |
| 22-30 | 5,000 | Approach normal volume |
| 31+ | 10,000+ | Full production |

Configure warmup in environment:
```env
IP_WARMUP_ENABLED=true
IP_WARMUP_DAY=15
IP_WARMUP_MAX_DAILY=5000
```

---

## Worker Configuration

### Queue Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `QUEUE_CONCURRENCY` | `10` | Concurrent jobs per worker |
| `QUEUE_RATE_LIMIT_MAX` | `100` | Max jobs per rate window |
| `QUEUE_RATE_LIMIT_DURATION` | `1000` | Rate window (ms) |
| `QUEUE_MAX_RETRIES` | `3` | Max retry attempts |
| `QUEUE_BACKOFF_TYPE` | `exponential` | Backoff strategy |
| `QUEUE_BACKOFF_DELAY` | `5000` | Initial backoff (ms) |

```env
QUEUE_CONCURRENCY=20
QUEUE_RATE_LIMIT_MAX=200
QUEUE_RATE_LIMIT_DURATION=1000
QUEUE_MAX_RETRIES=5
QUEUE_BACKOFF_TYPE=exponential
QUEUE_BACKOFF_DELAY=3000
```

### Job Priorities

| Queue | Priority | Use Case |
|-------|----------|----------|
| `critical` | 1 | Transactional (password reset, etc.) |
| `high` | 2 | Time-sensitive notifications |
| `default` | 3 | Regular messages |
| `low` | 4 | Bulk campaigns |
| `background` | 5 | Analytics, cleanup |

---

## AI Configuration

### Model Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_MODEL_PATH` | `/models` | Path to ONNX models |
| `AI_EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Embedding model |
| `AI_INFERENCE_THREADS` | `4` | Inference threads |
| `AI_MAX_BATCH_SIZE` | `32` | Max batch size |
| `AI_CACHE_ENABLED` | `true` | Cache embeddings |
| `AI_CACHE_TTL` | `86400` | Cache TTL (seconds) |

```env
AI_MODEL_PATH=/opt/apexmail/models
AI_EMBEDDING_MODEL=all-MiniLM-L6-v2
AI_INFERENCE_THREADS=8
AI_MAX_BATCH_SIZE=64
AI_CACHE_ENABLED=true
AI_CACHE_TTL=604800
```

### External AI (Optional)

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key (optional enhancement) |
| `ANTHROPIC_API_KEY` | Anthropic API key (optional) |

```env
# Optional - for enhanced capabilities
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
```

---

## Compliance Configuration

### GDPR Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `GDPR_ENABLED` | `true` | Enable GDPR features |
| `GDPR_RETENTION_DAYS` | `365` | Data retention period |
| `GDPR_EXPORT_FORMAT` | `json` | Export format |
| `GDPR_DELETION_DELAY` | `30` | Deletion delay (days) |

```env
GDPR_ENABLED=true
GDPR_RETENTION_DAYS=365
GDPR_EXPORT_FORMAT=json
GDPR_DELETION_DELAY=30
```

### Audit Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_ENABLED` | `true` | Enable audit logging |
| `AUDIT_RETENTION_DAYS` | `2555` | Retention (7 years) |
| `AUDIT_SIGNING_KEY` | - | HMAC signing key |

```env
AUDIT_ENABLED=true
AUDIT_RETENTION_DAYS=2555
AUDIT_SIGNING_KEY=base64-signing-key
```

---

## SLO Configuration

### Service Level Objectives

| Variable | Default | Description |
|----------|---------|-------------|
| `SLO_API_AVAILABILITY` | `99.9` | API availability target (%) |
| `SLO_API_LATENCY_P99` | `500` | P99 latency target (ms) |
| `SLO_DELIVERY_RATE` | `98.0` | Email delivery rate (%) |
| `SLO_DELIVERY_TIME` | `300` | Time to deliver (seconds) |

```env
SLO_API_AVAILABILITY=99.95
SLO_API_LATENCY_P99=200
SLO_DELIVERY_RATE=99.0
SLO_DELIVERY_TIME=120
```

### Alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERT_SLACK_WEBHOOK` | - | Slack webhook URL |
| `ALERT_PAGERDUTY_KEY` | - | PagerDuty routing key |
| `ALERT_EMAIL` | - | Alert email recipient |

```env
ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/...
ALERT_PAGERDUTY_KEY=abc123
ALERT_EMAIL=oncall@example.com
```

---

## Configuration Files

### TypeScript Config

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "rootDir": "./src"
  }
}
```

### ESLint Config

`.eslintrc.cjs`:
```javascript
module.exports = {
  root: true,
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    'prettier'
  ],
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-function-return-type': 'warn',
    'no-console': ['warn', { allow: ['warn', 'error'] }]
  }
};
```

### Prettier Config

`.prettierrc`:
```json
{
  "semi": true,
  "singleQuote": true,
  "tabWidth": 2,
  "trailingComma": "es5",
  "printWidth": 100
}
```
