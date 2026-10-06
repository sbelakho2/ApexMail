# ApexMail — Repository Map (generated)

> GENERATED FILE — do not edit by hand. `tools/generate_repo_map.py`
> regenerates this document from the source manifests listed per section;
> `ci/stages/validate.sh` runs the generator with `--check` and fails the
> validate stage when this file drifts from the tree.


## 1. Cargo workspace (`services/mail-server`)

54 workspace members: 23 binary crates, 31 library crates.

**Binary crates:** `crates/mailstore-core`, `crates/tracking-service`, `crates/worker-processors`, `crates/mta`, `crates/outbound-mta`, `crates/imap-server`, `crates/edge-cases`, `crates/analytics`, `crates/compliance`, `crates/isolation`, `crates/ha`, `crates/enterprise`, `crates/template-renderer`, `crates/ai-embeddings`, `crates/api-server`, `crates/billing-service`, `crates/devex-service`, `crates/observability-service`, `crates/ui-foundation`, `crates/sales-autopilot`, `crates/ai-service`, `crates/pdf-renderer`, `crates/migrator`

**Library crates:** `crates/mail-proto`, `crates/mail-common`, `crates/sales-knowledge`, `crates/queue-provider`, `crates/pattern-matcher`, `crates/rate-limiter`, `crates/dns-resolver`, `crates/auth-server`, `crates/accounting-core`, `crates/billing-common`, `crates/billing-entitlements`, `crates/platform-catalog`, `crates/apexmail-db`, `crates/apexmail-lib`, `crates/smoke-tests`, `crates/functional-tests`, `crates/integration-tests`, `crates/perf-tests`, `crates/fuzz-tests`, `crates/load-tests`, `crates/ddos-protection`, `crates/fingerprint`, `crates/waf-engine`, `crates/ids-engine`, `crates/spam-filter`, `crates/sandbox`, `crates/ato-protection`, `crates/dlp-engine`, `crates/threat-intel`, `crates/email-grader`, `crates/inbox-placement`

## 2. Dockerfile runtime targets

19 `FROM runtime-base AS <target>` stages in `services/mail-server/Dockerfile` (the deploy surfaces the capability-registry evidence cites):

- `mailstore`
- `api-server`
- `billing-service`
- `mta`
- `outbound-mta`
- `imap-server`
- `worker`
- `enterprise`
- `observability`
- `auth-server`
- `sales-autopilot`
- `compliance`
- `analytics-worker`
- `pdf-renderer`
- `ai-service`
- `ai-embeddings`
- `ha`
- `isolation`
- `migrator`

## 3. Compose services

`docker-compose.yml` (32 services): `postgres`, `redis`, `observability`, `otel-collector`, `tempo`, `tracking`, `api-server`, `enterprise`, `mta`, `worker`, `imap-server`, `outbound-mta`, `pdf-renderer`, `billing-service`, `analytics-worker`, `ai-service`, `sales-autopilot`, `compliance`, `ha`, `isolation`, `mailpit`, `clickhouse`, `prometheus`, `grafana`, `loki`, `alertmanager`, `postgres-exporter`, `redis-exporter`, `clickhouse-exporter`, `node-exporter`, `blackbox-exporter`, `synthetic-monitor`

`docker-compose.prod.yml` adds 10 services: `marketing`, `nginx`, `certbot`, `migrator`, `status-server`, `mailstore`, `postgres-backup`, `clickhouse-backup`, `redis-backup`, `analytics-backup`

## 4. Capability registry stages

Source of truth: `docs/development/capability-registry.json` (ladder: implemented → integration-tested → runtime-wired → deployed → monitored → advertised). The gate `tools/check_capability_claims.py` proves stage >= runtime-wired evidence exists in the tree and that claim surfaces only name runtime-wired capabilities outside `[roadmap]` context.

| Capability | Stage | Env gate |
|---|---|---|
| bimi-logo-verification | implemented | — |
| dane-tlsa-verification | implemented | — |
| mta-sts-tlsrpt | implemented | — |
| pattern-matcher-library | implemented | — |
| rate-limiter-crate-library | implemented | — |
| ai-reply-classification | runtime-wired | WORKER_REPLY_CLASSIFIER_AI_ENABLED |
| arc-sealing | runtime-wired | — |
| attachment-sandboxing | runtime-wired | MTA_ATTACHMENT_SCAN_ENABLED |
| console-assistant | runtime-wired | — |
| data-loss-prevention | runtime-wired | WORKER_DLP_ENABLED |
| ddos-middleware | runtime-wired | — |
| email-draft-agent | runtime-wired | AI_EMAIL_AGENT_ENABLED |
| fingerprint-library | runtime-wired | — |
| inbound-reply-mirroring | runtime-wired | — |
| intrusion-detection-prevention | runtime-wired | MTA_IDS_ENABLED |
| mta-event-webhooks | runtime-wired | — |
| objection-handling | runtime-wired | — |
| smtp-starttls | runtime-wired | — |
| spam-phishing-filtering | runtime-wired | MTA_SPAM_FILTER_ENABLED |
| threat-intelligence-feeds | runtime-wired | — |
| web-application-firewall | runtime-wired | — |
| account-takeover-protection | deployed | ATO_PROTECTION_ENABLED |
| high-availability-failover-service | deployed | — |
| tenant-isolation-enforcement | deployed | — |
| monitoring-alerting | monitored | — |
| application-tenant-isolation | advertised | — |
| audit-logging | advertised | — |
| backup-restore | advertised | — |
| deliverability-grader | advertised | — |
| dkim-signing-outbound | advertised | — |
| encryption-at-rest | advertised | — |
| enterprise-sso-saml-oidc | advertised | — |
| inbound-email-authentication-spf-dkim-dmarc | advertised | — |
| inbox-placement-testing | advertised | — |
| mfa-totp | advertised | — |
| password-hashing-argon2id | advertised | — |
| rate-limiting | advertised | — |
| rbac-scoped-api-keys | advertised | — |
| scim-provisioning | advertised | — |
| service-restart-persistence | advertised | — |
| social-login-oauth-google-github | advertised | — |
| tls-in-transit | advertised | — |
| webhook-hmac-signatures | advertised | — |

## 4b. Schema migrations

`services/mail-server/migrations/`: **215 `*.sql` files**, latest `243_demo_sessions.sql` (regenerated as the `ls | tail`).

`tools/migrations/`: 35 `*.sql` files.

## 5. UI route baseline

Source of truth: `docs/development/ui-baseline-manifest.json` (the pinned counts live in `services/mail-server/crates/ui-foundation/src/routing.rs`):

| Surface | routeCount | Routes listed |
|---|---|---|
| web | 37 | 37 |
| control-plane | 31 | 31 |
| marketing | 19 | 19 |
| marketing-zola | 38 | 38 |

**Total: 125 routes.**
