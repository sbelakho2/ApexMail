# Asset inventory (internal draft)

| Field | Value |
|---|---|
| Classification | Internal Policy, Confidential |
| Owner | ApexMail (compliance@apexmail.ee), Bel Consulting OÜ, registry code 16588745 |
| Written | 2026-10-28 |
| Review cycle | Quarterly, and whenever the topology manifest changes |

## What this inventory covers

This inventory covers every service declared in the topology manifest, the infrastructure compose services beside them, and the datastore classes that `docker-compose.prod.yml` runs. Each row carries a data-classification one-liner derived from the retention policy or the service notes in the cited source.

It is an internal draft for the evidence core. It records what the sources state and it claims no attestation status.

## Application services

| Service | Class | Compose surfaces (dev / prod) | Function (source note) | Datastore class | Data classification (derived) | Source |
|---|---|---|---|---|---|---|
| api-server | daemon | api-server / api-server | SSR console, control plane and REST API | PostgreSQL | Customer account data, API keys, console sessions; audit-logged admin actions | `docs/development/topology-manifest.json`; retention classes in `docs/compliance/data-retention.md` |
| tracking | daemon | tracking / tracking | Open, click and unsubscribe edge service | PostgreSQL | Event logs with recipient identifiers, plan-dependent retention | `docs/development/topology-manifest.json`; `docs/compliance/data-retention.md` section 3.2 |
| mta | daemon | mta / mta | Inbound SMTP and submission | PostgreSQL | Message content and headers, encrypted at rest with a retention window | `docs/development/topology-manifest.json`; invariant I24 in `docs/invariants.toml` |
| outbound-mta | daemon | outbound-mta / outbound-mta | Outbound relay with durable ledger and warmup admission | PostgreSQL | Outbound queue ledger rows and routing receipts | `docs/development/topology-manifest.json`; invariant I5 in `docs/invariants.toml` |
| imap-server | daemon | imap-server / imap-server | Read path, no dedicated down alert yet (declared fact) | PostgreSQL via mailstore reads | Mailbox message content read path | `docs/development/topology-manifest.json` |
| mailstore | daemon | null / mailstore | Message storage service, prod only in compose | PostgreSQL (message storage) | Stored message bodies, encrypted at rest, retention windowed | `docs/development/topology-manifest.json`; invariant I24 in `docs/invariants.toml` |
| worker | daemon | worker / worker | Queue processors for send, bounce and campaign | PostgreSQL plus Redis queues | Queued message content, suppression state, bounce records | `docs/development/topology-manifest.json`; invariant I6 in `docs/invariants.toml` |
| enterprise | daemon | enterprise / enterprise | Contracts and entitlement service | PostgreSQL | Contract and entitlement records | `docs/development/topology-manifest.json` |
| observability | daemon | observability / observability | Metrics and rules service | File-based rules, scrape targets only | Operational telemetry with no personal data | `docs/development/topology-manifest.json`; self-hosted table in `templates/compliance/subprocessors.md` |
| status-server | daemon | null / status-server | Auth-server binary serving the public status page, prod only | None of its own | Public component status only, product names | `docs/development/topology-manifest.json` |
| billing-service | daemon | billing-service / billing-service | Mollie, wallet and invoicing | PostgreSQL | Billing records kept 7 years, tokenized payment references, no full card numbers | `docs/development/topology-manifest.json`; `docs/compliance/data-retention.md` section 3.3; `templates/compliance/subprocessors.md` |
| sales-autopilot | daemon | sales-autopilot / sales-autopilot | Owner-only sales engine plus customer automation execution | PostgreSQL | Sales person graph and prospect records covered by the DSR registry | `docs/development/topology-manifest.json`; invariant I25 in `docs/invariants.toml` |
| compliance | daemon | compliance / compliance | GDPR and DSR automation, XBRL, retention | PostgreSQL | Erasure and export registry rows, retention categories | `docs/development/topology-manifest.json`; invariant I9 in `docs/invariants.toml` |
| analytics-worker | daemon | analytics-worker / analytics-worker | ClickHouse rollups and derived usage | ClickHouse | Delivery and engagement events plus aggregated metrics | `docs/development/topology-manifest.json`; self-hosted table in `templates/compliance/subprocessors.md` |
| pdf-renderer | daemon | pdf-renderer / pdf-renderer | Invoice and document rendering | None of its own, reads billing data | Invoice document content, transient | `docs/development/topology-manifest.json` |
| ai-service | daemon | ai-service / ai-service | AI chat, draft and training service | PostgreSQL plus chat retention window | Chat and draft content with `AI_CHAT_RETENTION_DAYS` window (90 default) | `docs/development/topology-manifest.json`; `.env.production.example` |
| migrator | oneshot | null / migrator | Canonical schema migration job run before services | PostgreSQL schema only | Schema definitions, no customer records of its own | `docs/development/topology-manifest.json` |
| ha | daemon | ha / ha | Failover, health check, backup and replication orchestrator | Reads datastore health | Backup orchestration metadata; no scrapeable metrics endpoint (declared gap) | `docs/development/topology-manifest.json` |
| isolation | daemon | isolation / isolation | Tenant isolation service: org, workspace, quota APIs, per-tenant keys, rate limits, isolation audit | PostgreSQL | Tenant org and quota records, per-tenant encryption keys, isolation audit rows | `docs/development/topology-manifest.json` |
| ai-embeddings | build-only | null / null | Image built but intentionally not deployed (declared fact) | None | Not applicable while undeployed | `docs/development/topology-manifest.json` |

## Infrastructure compose services

| Service | Datastore or role class | Data classification (derived) | Source |
|---|---|---|---|
| postgres | Primary relational datastore | All customer records per the retention schedule | `docs/development/topology-manifest.json` infrastructure list; `docker-compose.prod.yml` |
| postgres-backup | Encrypted backup writer | Encrypted nightly dumps mirrored offsite | `docker-compose.prod.yml`; `docs/operations/disaster-recovery.md` |
| postgres-exporter | Metrics exporter | Database metrics, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| redis | In-memory cache, queue and session store | Session tokens, rate-limit counters, ephemeral state, no backup | `templates/compliance/subprocessors.md` self-hosted table; `docs/operations/disaster-recovery.md` known gaps |
| redis-backup | Snapshot writer | Snapshot data, 7-day retention per policy | `docs/development/topology-manifest.json` infrastructure list; `docs/compliance/data-retention.md` section 3.5 |
| redis-exporter | Metrics exporter | Cache metrics, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| clickhouse | Analytics OLAP datastore | Delivery events, engagement events, bounce and complaint data | `templates/compliance/subprocessors.md` self-hosted table |
| clickhouse-backup | Encrypted backup writer | Encrypted nightly per-table dumps | `docker-compose.prod.yml`; `docs/operations/disaster-recovery.md` |
| clickhouse-exporter | Metrics exporter | Analytics database metrics, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| analytics-cold | Cold analytics store | Aggregated analytics, covered by no backup job (declared gap) | `docs/development/topology-manifest.json` infrastructure list; `docs/operations/disaster-recovery.md` known gaps |
| analytics-backup | Backup writer for the cold store | Backup artifacts for analytics data | `docs/development/topology-manifest.json` infrastructure list |
| loki | Log store | Operational logs, redaction enforced by disclosure gates | `docs/development/topology-manifest.json` infrastructure list; self-hosted table in `templates/compliance/subprocessors.md` |
| tempo | Trace store | Request traces with disclosure filtering | `docs/development/topology-manifest.json` infrastructure list; self-hosted table in `templates/compliance/subprocessors.md` |
| prometheus | Metrics store | Service metrics, no personal data | `docs/development/topology-manifest.json` infrastructure list; `deploy/prometheus.yml` |
| otel-collector | Telemetry collector | Logs, metrics and traces in transit | `docs/development/topology-manifest.json` infrastructure list |
| alertmanager | Alert routing | Alert notifications, operational only | `docs/development/topology-manifest.json` infrastructure list; `deploy/alertmanager.yml.tmpl` |
| grafana | Dashboards | Operational dashboards, no personal data | `docs/development/topology-manifest.json` infrastructure list; `docs/operations/monitoring.md` |
| blackbox-exporter | Synthetic probe | Probe results, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| node-exporter | Host metrics exporter | Host metrics, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| synthetic-monitor | Synthetic checks | Check outcomes, no personal data | `docs/development/topology-manifest.json` infrastructure list |
| nginx | Edge reverse proxy and TLS termination | TLS sessions, request metadata | `docs/development/topology-manifest.json` infrastructure list; `deploy/DEPLOYMENT.md` |
| certbot | Certificate issuance | Let's Encrypt certificates for the domain set | `docs/development/topology-manifest.json` infrastructure list; `deploy/DEPLOYMENT.md` |
| marketing | Static marketing site | Public content only | `docs/development/topology-manifest.json` infrastructure list |
| mailpit | Development SMTP sink | Local development mail, not production | `docs/development/topology-manifest.json` infrastructure list; `docker-compose.yml` |

## Host and deployment assets

| Asset | Classification (derived) | Source |
|---|---|---|
| Single production host in Finland running the full compose stack | Infrastructure asset, no personal data of its own | `docs/operations/disaster-recovery.md` reality check |
| Host-local state under `/opt/apexmail` (`.env`, `secrets/`, TLS material) | Secrets; operator duty to keep an offline copy | `docs/operations/disaster-recovery.md` known gaps |
| Offsite backup mirror reached by rsync over SSH | Encrypted backup artifacts leaving the host | `docs/operations/disaster-recovery.md` backup mechanism |
| Source repository and CI pipeline on the deploy host | Source code and release evidence, blessing-gated | `docs/invariants.toml` I20; `docs/audit/backlog-2026-10-26-readiness.md` item 9 |

## Reading the classification column

Classifications quote the retention policy and the manifest or compose notes for the row. Where a source states no classification, the row says so instead of inventing one.
