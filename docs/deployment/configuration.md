# Configuration Reference

ApexMail reads its configuration from environment variables. This page is the
reference for the variables that exist in the repository contract: the
development template [`.env.example`](../../.env.example), the compose files
([`docker-compose.yml`](../../docker-compose.yml),
[`docker-compose.prod.yml`](../../docker-compose.prod.yml),
[`docker-compose.override.yml`](../../docker-compose.override.yml)), and the
`${VAR:?}` guards the compose files enforce. Values below are the shipped
defaults or example values; production secrets are supplied through Docker
secrets (the `PROD_*_FILE` variables) or a secret manager.

## Required variables

These variables are enforced with `${VAR:?}` in the compose files, so a
deployment fails to start when one is unset. Production secrets follow the
file-backed pattern: `PROD_<NAME>_FILE` points at a Docker secret whose
contents are mounted as the matching environment variable.

| Variable | Enforced in | Purpose |
|---|---|---|
| `APEXMAIL_API_KEY` | `docker-compose.prod.yml` | Internal API key used by bundled tooling. |
| `BASE_URL` | `docker-compose.prod.yml` | Required in production. |
| `DKIM_PRIVATE_KEY_ENCRYPTION_KEY` | `docker-compose.yml` | Required in production. |
| `GRAFANA_ADMIN_PASSWORD` | `docker-compose.yml` | Strong password required for non-local Grafana |
| `JWT_PUBLIC_KEY_PEM` | `docker-compose.yml` | Required in production. |
| `JWT_SECRET` | `docker-compose.prod.yml` | Legacy symmetric JWT secret (compose wiring); RS256 PEM keys are the current path. |
| `LOG_STREAM_ENCRYPTION_KEY` | `docker-compose.prod.yml` | AES key encrypting streamed logs at rest. |
| `MFA_SECRET_ENCRYPTION_KEY` | `docker-compose.override.yml` | At-rest key encrypting stored TOTP/MFA secrets. |
| `MTA_ATTACHMENT_SCAN_ENABLED` | `docker-compose.prod.yml` | Required in production. |
| `MTA_ATTACHMENT_SCAN_MODE` | `docker-compose.prod.yml` | Required in production. |
| `MTA_IDS_ENABLED` | `docker-compose.prod.yml` | Required in production. |
| `MTA_SPAM_FILTER_ENABLED` | `docker-compose.prod.yml` | Required in production. |
| `OAUTH_REDIRECT_BASE_URL` | `docker-compose.prod.yml` | Required in production. |
| `PLACEMENT_ENCRYPTION_SECRET` | `docker-compose.prod.yml` | Generate: openssl rand -base64 32 |
| `SALES_CAMPAIGN_FROM_EMAIL` | `docker-compose.prod.yml` | Required in production. |
| `WAF_ENABLED` | `docker-compose.prod.yml` | Production requires the managed WAF policy (true). |
| `WAF_ENFORCE` | `docker-compose.prod.yml` | Production requires WAF enforcement (true). |
| `WORKER_DLP_ENABLED` | `docker-compose.prod.yml` | Required in production. |
| 34 `PROD_*_FILE` variables | `docker-compose.prod.yml` | File-backed production secrets; every mount has a `${VAR:?}` guard. See the list below. |

The guarded `PROD_*_FILE` set is: `PROD_API_KEY_HASH_SECRET_FILE`, `PROD_AUDIT_SIGNING_KEY_FILE`, `PROD_AWS_ACCESS_KEY_ID_FILE`, `PROD_AWS_SECRET_ACCESS_KEY_FILE`, `PROD_BACKUP_ENCRYPTION_KEY_FILE`, `PROD_CLICKHOUSE_ADMIN_PASSWORD_FILE`, `PROD_CLICKHOUSE_PASSWORD_FILE`, `PROD_COMPLIANCE_AUTH_TOKEN_FILE`, `PROD_COMPLIANCE_CONSENT_SIGNING_KEY_FILE`, `PROD_COMPLIANCE_SECRETS_ENCRYPTION_KEY_FILE`, `PROD_COMPLIANCE_SECRETS_KDF_SALT_FILE`, `PROD_CP_SESSION_SECRET_FILE`, `PROD_CSRF_SECRET_FILE`, `PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE`, `PROD_IMPERSONATION_SECRET_FILE`, `PROD_INTERNAL_SERVICE_TOKEN_FILE`, `PROD_ISOLATION_INTERNAL_API_KEY_FILE`, `PROD_JWT_PRIVATE_KEY_FILE`, `PROD_JWT_PUBLIC_KEY_FILE`, `PROD_JWT_SECRET_FILE`, `PROD_KIWI_SECRET_KEY_FILE`, `PROD_PDF_RENDERER_AUTH_TOKEN_FILE`, `PROD_POSTGRES_PASSWORD_FILE`, `PROD_REDIS_PASSWORD_FILE`, `PROD_SALES_UNSUBSCRIBE_SECRET_FILE`, `PROD_SESSION_SECRET_FILE`, `PROD_SMTP_PASSWORD_FILE`, `PROD_SMTP_USERNAME_FILE`, `PROD_STRIPE_SECRET_KEY_FILE`, `PROD_STRIPE_WEBHOOK_SECRET_FILE`, `PROD_TENANT_ENCRYPTION_KEY_FILE`, `PROD_TRACKING_SECRET_KEY_FILE`, `PROD_VERP_HMAC_SECRET_FILE`, `PROD_WEBHOOK_SIGNING_SECRET_FILE`.

The compose files also mount these file-backed secrets without a guard: `PROD_AI_ADMIN_TOKEN_FILE`, `PROD_AI_MODEL_API_KEY_FILE`, `PROD_HA_ADMIN_API_KEY_FILE`, `PROD_HA_INTERNAL_API_KEY_FILE`, `PROD_REDIS_PASSWORD_MAP_FILE`.

## Application variables

### PostgreSQL

PostgreSQL connection and pool settings.

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_USER` | `apexmail` | — |
| `POSTGRES_PASSWORD` | `***` | Generate: openssl rand -base64 32 |
| `POSTGRES_DB` | `apexmail` | — |
| `POSTGRES_PORT` | `5432` | — |
| `DB_HOST` | `localhost` | — |
| `DB_PORT` | `5432` | — |
| `DB_NAME` | `apexmail` | — |
| `DB_USER` | `apexmail` | — |
| `DB_PASSWORD` | `***` | Same as POSTGRES_PASSWORD for dev convenience |
| `DB_MAX_CONNECTIONS` | `20` | — |
| `API_REPLICA_COUNT` | `1` | — |
| `DB_CLUSTER_CONNECTION_BUDGET` | `(empty)` | — |

### Redis

Redis connection and pool settings.

| Variable | Default | Notes |
|---|---|---|
| `REDIS_PASSWORD` | `***` | Generate: openssl rand -base64 32 |
| `REDIS_PORT` | `6379` | — |
| `REDIS_HOST` | `localhost` | — |
| `REDIS_DB` | `0` | — |
| `REDIS_POOL_MAX_SIZE` | `40` | — |

### ClickHouse

ClickHouse analytics store.

| Variable | Default | Notes |
|---|---|---|
| `CLICKHOUSE_PASSWORD` | `***` | Generate: openssl rand -base64 32 |
| `CLICKHOUSE_PORT` | `127.0.0.1:9000` | — |
| `CLICKHOUSE_HTTP_PORT` | `8123` | — |

### API Server

api-server core, UI host routing, secrets and rate limits.

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | — |
| `HOST` | `0.0.0.0` | — |
| `PORT` | `3000` | — |
| `CORS_ORIGINS` | `*` | — |
| `TRUSTED_PROXIES` | `(empty)` | — |
| `MAX_INFLIGHT_REQUESTS` | `30` | — |
| `METRICS_PORT` | `9090` | — |
| `APEXMAIL_API_PORT` | `3000` | — |
| `APEXMAIL_API_BASE_URL` | `http://localhost:3000` | — |
| `JWT_PRIVATE_KEY_PEM` | `"-----BEGIN PRIVATE KEY-----\n***\n-----END PRIVATE KEY-----"` | — |
| `JWT_PREVIOUS_PUBLIC_KEYS_PEM` | `(empty)` | — |
| `JWT_EXPIRY` | `24h` | — |
| `API_KEY_HASH_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `WEBHOOK_SIGNING_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `SESSION_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `IMPERSONATION_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `CSRF_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `TRACKING_SECRET_KEY` | `***` | Generate: openssl rand -base64 32 |
| `INTERNAL_SERVICE_TOKEN` | `***` | Generate: openssl rand -base64 32 |
| `CONTROL_PLANE_API_KEY` | `***` | Generate: openssl rand -base64 32 |
| `CP_SESSION_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `UI_WEB_HOSTS` | `localhost,127.0.0.1,app.apexmail.ee` | — |
| `UI_CONTROL_PLANE_HOSTS` | `admin.apexmail.ee,control.apexmail.ee` | — |
| `UI_MARKETING_HOSTS` | `apexmail.ee,www.apexmail.ee` | — |
| `UI_MARKETING_SURFACE` | `marketing-zola` | — |
| `UI_DEFAULT_SURFACE` | `web` | — |
| `RATE_LIMIT_MAX_REQUESTS` | `1000` | — |
| `RATE_LIMIT_WINDOW_MS` | `60000` | — |
| `IDEMPOTENCY_TTL_SECONDS` | `86400` | — |

### Email Grader

Email grader limits.

| Variable | Default | Notes |
|---|---|---|
| `GRADER_ENABLED` | `true` | — |
| `GRADER_RATE_LIMIT` | `10` | — |
| `GRADER_RATE_WINDOW` | `3600` | — |
| `GRADER_CACHE_TTL` | `300` | — |
| `GRADER_MAX_BODY_SIZE` | `1048576` | — |

### Inbox Placement

Inbox placement testing.

| Variable | Default | Notes |
|---|---|---|
| `PLACEMENT_ENABLED` | `true` | — |
| `PLACEMENT_POLLING_INTERVAL` | `60` | — |
| `PLACEMENT_MAX_POLLING_ATTEMPTS` | `10` | — |
| `PLACEMENT_MAX_SEEDS_PER_TEST` | `50` | — |
| `PLACEMENT_MAX_TESTS_PER_HOUR` | `5` | — |
| `PLACEMENT_IMAP_TIMEOUT` | `30` | — |
| `PLACEMENT_ENCRYPT_PASSWORDS` | `true` | — |

### Outbound Queue

Outbound queue / SMTP relay target.

| Variable | Default | Notes |
|---|---|---|
| `SMTP_HOST` | `127.0.0.1` | — |
| `SMTP_PORT` | `1025` | — |

### Dev MTA (SMTP edge)

Dev MTA host bind address.

| Variable | Default | Notes |
|---|---|---|
| `SMTP_EDGE_BIND` | `127.0.0.1` | — |

### Dedicated IP / SES

SES, dedicated IP and domain-signing configuration.

| Variable | Default | Notes |
|---|---|---|
| `AWS_REGION` | `us-east-1` | — |
| `SES_IP_POOL_PREFIX` | `apexmail` | — |
| `SES_DEFAULT_WARMUP_DAYS` | `14` | — |
| `SES_CONFIGURATION_SET` | `(empty)` | — |
| `SNS_ALLOWED_TOPIC_ARNS` | `(empty)` | — |
| `SYSTEM_SENDER_BOOTSTRAP_ON_STARTUP` | `false` | — |
| `HETZNER_API_TOKEN` | `***` | Your Hetzner API token |
| `HETZNER_DEFAULT_LOCATION` | `fsn1` | — |
| `HETZNER_MTA_SERVER_ID` | `(empty)` | — |

### OAuth / SSO

OAuth login providers.

| Variable | Default | Notes |
|---|---|---|
| `GOOGLE_CLIENT_ID` | `(empty)` | — |
| `GOOGLE_CLIENT_SECRET` | `***` | Your Google OAuth client secret |
| `GITHUB_CLIENT_ID` | `(empty)` | — |
| `GITHUB_CLIENT_SECRET` | `***` | Your GitHub OAuth client secret |

### Enterprise SSO (SAML/OIDC, enterprise service)

Tenant SSO encryption.

| Variable | Default | Notes |
|---|---|---|
| `SSO_ENCRYPTION_KEY` | `(empty)` | — |

### Billing

Invoice seller details.

| Variable | Default | Notes |
|---|---|---|
| `BILLING_COMPANY_BANK` | `Wise` | — |
| `BILLING_COMPANY_IBAN` | `(empty)` | — |
| `BILLING_COMPANY_BIC` | `(empty)` | — |
| `BILLING_COMPANY_PHONE` | `(empty)` | — |

### KiwiCaptcha (native Rust proof-of-work CAPTCHA)

KiwiCaptcha proof-of-work CAPTCHA.

| Variable | Default | Notes |
|---|---|---|
| `KIWI_ENABLED` | `true` | — |
| `KIWI_SECRET_KEY` | `dev` | — |
| `KIWI_ARGON_M_KIB` | `50000` | — |
| `KIWI_DIFFICULTY_BITS` | `16` | — |
| `KIWI_CHALLENGE_TTL_SECS` | `120` | — |

### Observability

Telemetry and marketing asset paths.

| Variable | Default | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | — |
| `ANALYTICS_IMAGE_SRC` | `(empty)` | — |
| `MARKETING_PUBLIC_DIR` | `apps/marketing-zola/public` | — |

### Composite Connection Strings (derived from individual vars above)

Convenience composite URLs; individual components are also accepted.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql://apexmail:***@localhost:5432/apexmail` | — |
| `REDIS_URL` | `redis://:***@localhost:6379/0` | — |

### Storage

S3-compatible object storage.

| Variable | Default | Notes |
|---|---|---|
| `S3_ENDPOINT` | `http://localhost:9000` | — |
| `S3_REGION` | `us-east-1` | — |
| `S3_BUCKET` | `apexmail-dev` | — |
| `S3_ACCESS_KEY_ID` | `***` | Your S3 access key |
| `S3_SECRET_ACCESS_KEY` | `***` | Your S3 secret key |

### Tracking (Encryption & Signing)

Tracking pixel encryption, signing and rewrite gate.

| Variable | Default | Notes |
|---|---|---|
| `TRACKING_ENCRYPTION_KEY` | `***` | — |
| `TRACKING_SIGNATURE_KEY` | `***` | — |
| `TRACKING_ENABLED` | `true` | — |
| `TRACKING_ALLOWED_REDIRECT_DOMAINS` | `(empty)` | — |

### VERP bounce routing (worker SMTP transport)

VERP bounce routing.

| Variable | Default | Notes |
|---|---|---|
| `VERP_DOMAIN` | `bounces.apexmail.ee` | — |

### Sales Autopilot (internal sales engine, port 3010 internal-only)

Internal sales autopilot.

| Variable | Default | Notes |
|---|---|---|
| `SALES_CAMPAIGN_FROM_NAME` | `ApexMail` | — |
| `SALES_UNSUBSCRIBE_SECRET` | `***` | Generate: openssl rand -base64 32 |
| `SALES_PUBLIC_BASE_URL` | `http://localhost:3010` | — |
| `SALES_UNSUBSCRIBE_REDIRECT_URL` | `(empty)` | — |
| `SALES_ALLOWED_TENANTS` | `(empty)` | — |
| `SALES_ENRICHMENT_API_URL` | `https://enrich.apexmail.ee` | — |
| `ENRICHMENT_API_KEY` | `(empty)` | — |
| `SALES_DISPATCH_INTERVAL_SECS` | `30` | — |
| `SALES_DISPATCH_BATCH_SIZE` | `100` | — |
| `SALES_DISPATCH_CONCURRENCY` | `4` | — |

### Email Transport Override

Delivery transport selection.

| Variable | Default | Notes |
|---|---|---|
| `EMAIL_TRANSPORT_TYPE` | `ses` | — |

### Audit log signing

Audit-log hash-chain signing.

| Variable | Default | Notes |
|---|---|---|
| `AUDIT_SIGNING_KEY` | `***` | — |

### AI service (ai-service)

ai-service helpers; model features stay off until enabled.

| Variable | Default | Notes |
|---|---|---|
| `AI_MODEL_ENABLED` | `false` | — |
| `AI_MODEL_ENDPOINT` | `(empty)` | — |
| `AI_MODEL_NAME` | `(empty)` | — |
| `AI_MODEL_API_KEY` | `(empty)` | — |
| `AI_MODEL_TIMEOUT_SECS` | `30` | — |
| `AI_ADMIN_TOKEN` | `***` | — |
| `AI_TRAINING_RUNNER` | `(empty)` | — |
| `AI_TRAINING_WORKING_DIR` | `(empty)` | — |
| `AI_BIND` | `0.0.0.0:3012` | — |
| `AI_EMAIL_AGENT_ENABLED` | `false` | — |
| `AI_EMAIL_MAX_TOKENS` | `1024` | — |
| `AI_EMAIL_POLL_INTERVAL_SECS` | `15` | — |
| `AI_EMAIL_MAX_BODY_CHARS` | `8000` | — |
| `AI_EMAIL_REQUIRE_APPROVAL` | `true` | — |

### Worker health probe

Worker health endpoint.

| Variable | Default | Notes |
|---|---|---|
| `HEALTH_PORT` | `9090` | — |

### Grafana

Grafana and trusted reverse proxies.

| Variable | Default | Notes |
|---|---|---|
| `DDOS_TRUSTED_PROXIES` | `(empty)` | — |

### Overage (billing-service)

Overage allowance and invoicing.

| Variable | Default | Notes |
|---|---|---|
| `OVERAGE_ALLOWANCE_PERCENT` | `100` | — |
| `OVERAGE_INVOICING_ENABLED` | `true` | — |

### HA service (crates/ha, docker target `ha`, port 4300)

HA, isolation and platform key settings.

| Variable | Default | Notes |
|---|---|---|
| `HA_PORT` | `4300` | — |
| `FAILBACK_ENABLED` | `false` | — |
| `CHAOS_ENABLED` | `false` | — |
| `HA_INTERNAL_API_KEY` | `(empty)` | — |
| `HA_ADMIN_API_KEY` | `(empty)` | — |
| `ISOLATION_PORT` | `4500` | — |
| `ISOLATION_REDIS_DB` | `3` | — |
| `ISOLATION_CORS_ORIGINS` | `http://localhost:3000` | — |
| `ISOLATION_INTERNAL_API_KEY` | `dev-isolation-internal-api-key-change-me` | — |
| `TENANT_ENCRYPTION_KEY` | `dev-tenant-encryption-key-change-me-32b` | — |
| `DATA_KEY_ROTATION_DAYS` | `90` | — |
| `AUDIT_RETENTION_DAYS` | `365` | — |

### Inbound content security (mta inbound, crates/mta content_security.rs)

Inbound content security engines (default off).

| Variable | Default | Notes |
|---|---|---|
| `MTA_SPAM_REJECT_ENABLED` | `false` | — |
| `MTA_IDS_REFUSE` | `false` | — |

### Account Takeover Protection (ato-protection via api-server login flows)

Account-takeover protection thresholds.

| Variable | Default | Notes |
|---|---|---|
| `ATO_PROTECTION_ENABLED` | `(empty)` | — |
| `ATO_MFA_THRESHOLD` | `(empty)` | — |
| `ATO_BLOCK_THRESHOLD` | `(empty)` | — |

### Outbound DLP (worker pre-send gate, WORKER_DLP_ENABLED)

Worker pre-send DLP gate.

| Variable | Default | Notes |
|---|---|---|

### Per-workload internal credentials (P1 #6)

Per-workload internal service tokens.

| Variable | Default | Notes |
|---|---|---|
| `TEMPLATE_RENDERER_AUTH_TOKEN` | `***` | — |
| `PDF_RENDERER_AUTH_TOKEN` | `***` | — |
| `DEVEX_AUTH_TOKEN` | `***` | — |
| `AI_EMBEDDINGS_AUTH_TOKEN` | `***` | — |

### Compliance service (crates/compliance, docker target `compliance`, :3011)

Compliance service credentials.

| Variable | Default | Notes |
|---|---|---|
| `COMPLIANCE_AUTH_TOKEN` | `dev-compliance-token-change-me` | — |
| `SECRETS_ENCRYPTION_KEY` | `dev-secrets-encryption-key-change-me-32b` | — |

### Test infrastructure (Rust workspace, services/mail-server)

Test-only database URLs.

| Variable | Default | Notes |
|---|---|---|
| `TEST_DATABASE_URL` | `postgresql://postgres@localhost:5432/apexmail_integration_scratch` | — |
| `TEST_REDIS_URL` | `redis://localhost:6379` | — |
| `TEST_HOSTILE_DATABASE_URL` | `(empty)` | — |

### Compose-only runtime variables

These are set by the compose files and read by the services; they do not
appear in `.env.example`.

| Variable | Default in compose | Purpose |
|---|---|---|
| `AI_CHAT_RETENTION_DAYS` | see compose | Chat transcript retention (days). |
| `AI_REPLY_FROM` | see compose | From address for AI reply drafts. |
| `ANALYTICS_COLD_RETENTION_DAYS` | see compose | Cold analytics retention (days). |
| `ANALYTICS_COMPACTION_ENABLED` | see compose | Enable ClickHouse part compaction. |
| `ANALYTICS_HOT_RETENTION_DAYS` | see compose | Hot analytics retention (days). |
| `ANALYTICS_STO_HMAC_KEY` | see compose | HMAC key for send-time-optimization analytics. |
| `APEXMAIL_HA_FENCING` | see compose | HA service fencing mode. |
| `APP_ENV` | see compose | Service environment for config validation (production enforces dedicated credentials). |
| `AUTOMATION_TICK_SECS` | see compose | Automation scheduler tick interval. |
| `CLICKHOUSE_DATABASE` | see compose | ClickHouse database name. |
| `CLICKHOUSE_INSERT_TIMEOUT_SECONDS` | see compose | ClickHouse insert timeout. |
| `CLICKHOUSE_MAX_CONNECTIONS` | see compose | ClickHouse connection-pool size. |
| `CLICKHOUSE_USER` | see compose | ClickHouse user. |
| `DATABASE_REPLICA_URL` | see compose | Read-replica PostgreSQL URL (roadmap: read replicas). |
| `DB_REPLICA_HOSTS` | see compose | Read-replica hosts (roadmap: read replicas). |
| `DKIM_ENABLED` | see compose | Enable local SMTP DKIM signing (SMTP transport only). |
| `DKIM_KEY_PATH` | see compose | Path to the local DKIM key material. |
| `DKIM_SELECTOR` | see compose | DKIM selector for locally signed mail. |
| `GDPR_CLICKHOUSE_ERASURE_ENABLED` | see compose | Enable ClickHouse-side GDPR erasure. |
| `GDPR_EXPORT_BASE_URL` | see compose | Base URL used in GDPR export links. |
| `GDPR_VERIFY_BASE_URL` | see compose | Base URL used in GDPR verification links. |
| `KIWI_ALGORITHM` | see compose | KiwiCaptcha hash: sha256 (default) or argon2id. |
| `KIWI_ARGON2_DIFFICULTY_BITS` | see compose | Argon2id difficulty bits. |
| `KIWI_ARGON_P` | see compose | Argon2id parallelism. |
| `KIWI_ARGON_T` | see compose | Argon2id iterations. |
| `MAILSTORE_GRPC_ADDR` | see compose | Mailstore gRPC address. |
| `METRICS_ENABLED` | see compose | Enable the Prometheus metrics endpoint. |
| `NODE_ENV` | see compose | Service environment name (production refuses ephemeral credentials). |
| `OUTBOUND_MTA_HELO_DOMAIN` | see compose | Outbound MTA HELO/EHLO domain. |
| `PLACEMENT_SMTP_HOST` | see compose | SMTP host for placement seed injection. |
| `PLACEMENT_SMTP_PORT` | see compose | SMTP port for placement seed injection. |
| `RUST_LOG` | see compose | tracing filter for Rust services. |
| `SALES_AUTOPILOT_BASE_URL` | see compose | Sales-autopilot base URL. |
| `SMTP_PASSWORD` | see compose | SMTP relay password (SMTP transport / submission). |
| `SMTP_TLS` | see compose | Require TLS for the SMTP relay. |
| `SMTP_USERNAME` | see compose | SMTP relay username. |
| `SSO_FEDERATION_ALLOWLIST` | see compose | Allowlist of IdP federation metadata hosts. |
| `STRIPE_SECRET_KEY` | see compose | Stripe API secret (billing service). |
| `STRIPE_WEBHOOK_SECRET` | see compose | Stripe webhook signing secret. |
| `TRACKING_BASE_URL` | see compose | Public base URL of the tracking service. |
| `WORKER_REPLY_CLASSIFIER_AI_ENABLED` | see compose | Enable the AI reply classifier in the worker. |
| `WORKER_REPLY_CLASSIFIER_AI_URL` | see compose | Reply-classifier endpoint URL. |
| `WORKER_RUN_AUTOMATIONS` | see compose | Enable automation execution in the worker. |

### Deployment-stack variables

The compose files parameterize the bundled monitoring, backup and edge
services with the following variables. They configure the third-party images
rather than the ApexMail services; the compose files carry their defaults.

    `ALERTMANAGER_PORT`, `ALERT_EMAIL_CRITICAL`, `ALERT_EMAIL_WARNING`, `ANALYTICS_BACKUP_KEEP_COUNT`, `API_METRICS_PORT`, `API_PORT`, `BACKUP_KEEP_COUNT`, `BACKUP_KEEP_DAYS`, `BACKUP_KEEP_MONTHS`, `BACKUP_KEEP_WEEKS`, `BACKUP_SSH_KEY_FILE`, `BACKUP_SSH_KNOWN_HOSTS_FILE`, `BACKUP_TARGET`, `BILLING_API_BASE_URL`, `CLICKHOUSE_ADMIN_PASSWORD`, `CLICKHOUSE_BACKUP_KEEP_COUNT`, `CLICKHOUSE_BACKUP_KEEP_DAYS`, `CLICKHOUSE_NATIVE_PORT`, `COMPLIANCE_CONSENT_SIGNING_KEY`, `COMPLIANCE_CORS_ORIGIN`, `COMPLIANCE_SECRETS_ENCRYPTION_KEY`, `COMPLIANCE_SECRETS_KDF_SALT`, `DKIM_DOMAIN`, `ENTERPRISE_BASE_URL`, `ENTERPRISE_CORS_ORIGINS`, `ENTERPRISE_LOG_LEVEL`, `ENTERPRISE_PORT`, `FAILOVER_ENABLED`, `GF_SECURITY_ADMIN_USER`, `GHCR_NS`, `GRAFANA_PORT`, `JWT_PRIVATE_KEY_PEM_FILE`, `JWT_PUBLIC_KEY_PEM_FILE`, `LOCAL_DOMAINS`, `LOKI_PORT`, `MAILPIT_ALLOW_INSECURE`, `MAILPIT_SMTP_PORT`, `MAILPIT_WEB_PORT`, `MAIL_SERVER_HOSTNAME`, `MAIL_TLS_DOMAIN`, `OPSGENIE_API_KEY`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_GRPC_PORT`, `OTEL_HTTP_PORT`, `OTEL_TRACES_SAMPLING_PERCENTAGE`, `OUTBOUND_MTA_BATCH_SIZE`, `OUTBOUND_MTA_MAX_ATTEMPTS`, `OUTBOUND_MTA_POLL_SECS`, `PAGERDUTY_ROUTING_KEY`, `PDF_LOG_LEVEL`, `PROMETHEUS_PORT`, `PROMETHEUS_RETENTION`, `PROMETHEUS_RETENTION_SIZE`, `PROMETHEUS_WEB_PASSWORD`, `PROMETHEUS_WEB_PASSWORD_HASH`, `PROMETHEUS_WEB_USER`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_MAX_PER_MINUTE`, `REDIS_BACKUP_KEEP_COUNT`, `REDIS_POOL_SIZE`, `RUST_BACKTRACE`, `SLACK_WEBHOOK_PATH`, `SLACK_WEBHOOK_PATH_LOW`, `SUBMISSION_PORT`, `SYNTHETIC_INTERVAL_SECONDS`, `SYNTHETIC_SMTP_TARGETS`, `SYNTHETIC_TARGETS`, `SYNTHETIC_TIMEOUT_SECONDS`, `TEMPO_PORT`, `TLS_CERT_DIR`, `TRACKING_METRICS_PORT`, `TRACKING_PORT`, `WORKER_RUST_LOG`

## Removed variables

The retired configuration generation documented `OPENAI_API_KEY`,
`SENTRY_DSN`, `ENCRYPTION_KEY`, `DATABASE_POOL_MAX`, `FEATURE_*`, `SLO_*`,
`QUEUE_*`, `GDPR_*` (except the ClickHouse/export/verify variables above),
`AUDIT_ENABLED`, `REDIS_CLUSTER`, `CORS_*` and similar names that no service
reads. They are not part of the contract and are omitted here.

