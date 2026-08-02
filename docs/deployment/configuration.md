# Configuration Reference

Complete reference for all ApexMail configuration options.

## Environment Variables

### Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVIRONMENT` | ✓ | `development` | Environment: `development`, `production`, `test` |
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
| `JWT_PRIVATE_KEY_PEM` | ✓ | - | RSA private key used for JWT signing |
| `JWT_PUBLIC_KEY_PEM` | ✓ | - | RSA public key used for JWT verification |
| `JWT_ACCESS_TTL` | | `3600` | Access token TTL (seconds) |
| `JWT_REFRESH_TTL` | | `2592000` | Refresh token TTL (30 days) |
| `JWT_ALGORITHM` | | `RS256` | JWT algorithm |

```env
# Generate an RSA keypair and export both PEM values for the API server.
JWT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
JWT_ACCESS_TTL=3600
JWT_REFRESH_TTL=2592000
```

### Login CAPTCHA (KiwiCaptcha)

Login protection is available for both login surfaces:
- User web login: Rust SSR web surface served by `services/mail-server/crates/api-server` on the `127.0.0.1` host map (`/login`)
- Control-plane login: Rust SSR control-plane surface served by `services/mail-server/crates/api-server` on the `localhost` host map (`/login`)

KiwiCaptcha is a native Rust, self-contained proof-of-work CAPTCHA — no external services, no iframes, no external JS.

Server-side verification variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KIWI_ENABLED` | | `false` | Enforce CAPTCHA verification in login API routes |
| `KIWI_SECRET_KEY` | ✓ when enabled | `dev` | HMAC secret key for challenge signing and verification |
| `KIWI_PBKDF2_ITERATIONS` | | `50000` | PBKDF2 iteration count for proof-of-work |
| `KIWI_DIFFICULTY_BITS` | | `16` | Required leading zero bits (~1-3s solve time) |

```env
# Server-side enforcement
KIWI_ENABLED=true
KIWI_SECRET_KEY=your-production-secret-key
```

Behavior when enabled:
- Missing token: login is rejected (`CAPTCHA_REQUIRED`)
- Invalid token: login is rejected (`CAPTCHA_INVALID`)
- Server-side verification failure: login is rejected (`CAPTCHA_UNAVAILABLE`)

### Encryption

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENCRYPTION_KEY` | ✓ | - | AES-256 encryption key (32 bytes base64) |
| `ENCRYPTION_ALGORITHM` | | `aes-256-gcm` | Encryption algorithm |

```env
# Generate with: openssl rand -base64 32
ENCRYPTION_KEY="base64-encoded-32-byte-key"
```

### Tracking / SSE Streaming

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRACKING_SECRET_KEY` | ✓ (prod) | dev default | Shared HMAC-SHA256 secret for SSE stream tokens (min 32 chars in prod) |

Both the API server and tracking service must share the same `TRACKING_SECRET_KEY`.
See [Streaming API](../api/streaming.md) for details.

### Metrics

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `METRICS_PORT` | | `9090` | Prometheus metrics HTTP port (API server). Set to `0` to disable. |

The tracking service exposes metrics on port 9092 (configured via `METRICS_PORT` in its own config).

### Email Delivery Transport

ApexMail uses a **hybrid per-message routing** architecture. Both AWS SES (shared pool) and self-hosted SMTP (dedicated IPs via Hetzner) are always available — the `TransportRouter` decides per-message which path to use based on tenant dedicated IP ownership.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEFAULT_FROM_EMAIL` | | - | Default sender address |
| `DEFAULT_FROM_NAME` | | - | Default sender name |

> **Note:** The hybrid routing uses automatic per-message transport selection based on tenant dedicated IP ownership. The `EMAIL_TRANSPORT_TYPE` variable listed below is a legacy/advanced override for operators who want to bypass the hybrid model and force all traffic via a specific transport — it is **not** part of the standard routing configuration.

#### AWS SES Configuration (Shared Pool)

SES is used for tenants without dedicated IPs (the default path).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | ✓ | - | AWS IAM access key for SES |
| `AWS_SECRET_ACCESS_KEY` | ✓ | - | AWS IAM secret key for SES |
| `AWS_DEFAULT_REGION` | | `eu-west-1` | AWS region for SES |
| `SES_CONFIGURATION_SET` | | - | SES configuration set for event tracking |

```env
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_DEFAULT_REGION=eu-west-1
SES_CONFIGURATION_SET=apexmail-production
DEFAULT_FROM_EMAIL=noreply@example.com
DEFAULT_FROM_NAME="ApexMail"
```

SES handles DKIM signing automatically via Easy DKIM (2048-bit RSA). Domain identities are auto-provisioned when tenants verify domains.

#### Hetzner Cloud Configuration (Dedicated IPs)

Hetzner is used for tenants with dedicated IPs. The `DedicatedIpProvider` manages floating IPs via the Hetzner Cloud API.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HETZNER_API_TOKEN` | ✓ (for dedicated IPs) | - | Hetzner Cloud API token |
| `HETZNER_DEFAULT_LOCATION` | | `fsn1` | Default datacenter for new IPs |
| `HETZNER_MTA_SERVER_ID` | | - | Server ID for IP assignment (single-server mode) |

```env
HETZNER_API_TOKEN=your-hetzner-cloud-api-token
HETZNER_DEFAULT_LOCATION=fsn1
HETZNER_MTA_SERVER_ID=12345678
```

Dedicated IPs are auto-provisioned when tenants upgrade to plans with dedicated IP access. See [Hetzner Tool Contract](../tool-contracts/hetzner.md) for details.

#### Self-Hosted SMTP Configuration (Legacy/Advanced)

For advanced deployments that bypass the hybrid routing and use direct SMTP relay:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMAIL_TRANSPORT_TYPE` | | `ses` | Set to `smtp` to force all traffic via SMTP relay |
| `SMTP_HOST` | | `localhost` | SMTP relay host |
| `SMTP_PORT` | | `587` | SMTP relay port |
| `SMTP_SECURE` | | `true` | Use TLS |
| `SMTP_USERNAME` | | - | SMTP auth username |
| `SMTP_PASSWORD` | | - | SMTP auth password |
| `OUTBOUND_IPS` | | - | Comma-separated outbound IPs for source binding |
| `MTA_HOSTNAME` | ✓ | - | HELO/EHLO hostname |

> **Note:** This configuration is for operators who want to run a full self-hosted MTA without using the hybrid model. Most deployments should use the hybrid model with Hetzner dedicated IPs.

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

## SMTP Configuration (Self-Hosted Opt-In Only)

> **Note:** This section applies only when using `EMAIL_TRANSPORT_TYPE=smtp`. When using the default SES transport, SMTP configuration is not needed for outbound delivery. SMTP configuration below may still apply to inbound mail processing (ports 25/2525/2526).

### Postfix Main Configuration (if using Postfix relay)

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

### IP Warmup Schedule (Dedicated IPs via Hetzner)

> **Note:** Dedicated IPs are now provisioned via Hetzner Cloud floating IPs and managed by the `DedicatedIpProvider`. Warmup is handled automatically by the system.

New dedicated IPs follow a 45-day warmup schedule:

| Day | Daily Volume | Notes |
|-----|--------------|-------|
| 0-1 | 50 | Test deliverability |
| 2-3 | 100 | Monitor bounces |
| 4-7 | 250-500 | Check reputation |
| 8-14 | 1,000-2,500 | Increase gradually |
| 15-28 | 5,000-10,000 | Watch for blocks |
| 29-44 | 25,000-50,000 | Approach normal volume |
| 45+ | Unlimited | Full production |

During warmup, excess traffic overflows to SES shared sending automatically. No manual configuration needed.

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

Runtime configuration now lives in Rust crate configuration structs, environment-variable loaders, and deployment manifests.
