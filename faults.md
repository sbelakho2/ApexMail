# ApexMail Fault Remediation Ledger

> **Scan date:** 2026-05-01  
> **Resolution pass:** 2026-05-01  
> **Status:** All reopened rows from the May 1 comprehensive scan are fixed or verified against the current repository state.

**Legend:** 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⚪ INFO

---

## 🔴 Critical Issues

- [x] 🔴 **Three frontend apps were missing while docs still referenced them.** Resolved by replacing `docs/api-route-audit-report.md` with a current Rust API/UI route audit that documents the Axum + `ui-foundation` SSR replacement and the 93-route migration test contract.
- [x] 🔴 **`.env.production.example` referenced the wrong Node.js-era stack.** Rewritten for the current Rust services, RS256 API JWT keys, enterprise-only HS256 boundary, Redis/Postgres/ClickHouse, billing, tracing, and monitoring variables.
- [x] 🔴 **`.env.production.example` was git-ignored.** `.gitignore` now explicitly unignores `!.env.production.example` while keeping local `.env.*` files ignored.
- [x] 🔴 **SQLx migrations 004-019 were absent.** Added explicit reserved SQLx migration files `004_legacy_schema_slot_reserved.sql` through `019_legacy_schema_slot_reserved.sql`, giving the active migration chain contiguous slots 001-024.
- [x] 🔴 **Dual migration directories caused collision risk.** Docker Compose no longer mounts `tools/migrations` into Postgres initdb, and `tools/migrations/README.md` marks that directory as a legacy archive. `services/mail-server/migrations/` is now documented as the active source of truth.
- [x] 🔴 **Local secret files risked git tracking/history exposure.** Root `.gitignore` now explicitly ignores `secrets/`; `git ls-files secrets` and `git log --all -- secrets` both returned no tracked/history entries in this repo state. Added `docs/security/secrets.md` and `tools/validate-compose-secrets.sh`.
- [x] 🔴 **OTel collector discarded traces to logging only.** Local and Kubernetes collector configs now export traces to a Tempo OTLP backend while retaining debug output; Docker Compose and K8s include Tempo wiring.
- [x] 🔴 **API route audit referenced deleted frontends and stale 404s.** Rewritten against `api-server/src/app.rs`, Rust route modules, and the `ui-foundation` SSR route manifest.

## 🟠 High Issues

- [x] 🟠 **`services/mail-server/src/` looked like an empty root package.** Verified current `services/mail-server/Cargo.toml` is a virtual workspace and `services/mail-server/src/README.md` documents that runtime code lives under crates.
- [x] 🟠 **ClickHouse exporter sent the password twice.** Removed Basic auth generation; exporter now uses ClickHouse user/key headers only.
- [x] 🟠 **JWT secret naming was ambiguous.** Production env docs and `docs/security/secrets.md` now distinguish API `JWT_PRIVATE_KEY_PEM`/`JWT_PUBLIC_KEY_PEM` from the enterprise service's separate `JWT_SECRET`.
- [x] 🟠 **Alertmanager grouped only by alert name.** `deploy/alertmanager.yml` now groups by `alertname`, `severity`, and `instance`.
- [x] 🟠 **Alerting rules referenced metrics Rust services do not emit.** `deploy/alerting-rules.yml` now uses `apexmail_http_*` metrics, node exporter CPU/memory metrics, Redis exporter memory metrics, and request-path based billing/webhook signals.
- [x] 🟠 **mCaptcha docs link needed verification.** Verified `docs/security/mcaptcha-login.md` exists and `docs/quickstart.md` links to it.
- [x] 🟠 **`docker-compose.override.yml` only handled Postgres/Redis but default full-stack startup was confusing.** Override now documents infra-only default startup and moves application services behind the `full-stack` profile.
- [x] 🟠 **Grafana lacked billing/email business dashboards.** Added `deploy/grafana/dashboards/business-kpis.json` for billing, Stripe, delivery API, success ratio, and Redis queue capacity views.
- [x] 🟠 **K8s ConfigMap used placeholder URLs.** `deploy/k8s/configmap.yaml` now uses `api.apexmail.ee`, `app.apexmail.ee`, `admin.apexmail.ee`, and `track.apexmail.ee`.
- [x] 🟠 **Helm ingress defaulted to `mail.example.com`.** `deploy/helm/apexmail/values.yaml` and Helm docs now use `api.apexmail.ee`.
- [x] 🟠 **Support/contact email drifted across docs and data.** Source docs, API metadata, packages, AI training generators, and JSONL data were normalized to `support@apexmail.ee`.
- [x] 🟠 **Training JSONL duplicated large system prompts in every record.** `train.jsonl`, `test.jsonl`, and `val.jsonl` now store `system_prompt_id` references, with shared prompt text in `data/system_prompts.json`; training/evaluation loaders expand references at runtime.
- [x] 🟠 **Training data used British `Behaviour` spelling.** Source generators and JSONL data now use `Behavior`/`behavior` consistently.
- [x] 🟠 **Compose `!override` tags were compatibility risks.** Removed `!override` tags from dev and production compose files; compose configs render successfully.
- [x] 🟠 **CPU alert ignored multi-core hosts.** CPU alert now uses node exporter idle-time utilization and fires above 85% node CPU, not one core-second.
- [x] 🟠 **Lobster calculator was unrelated and undocumented.** Verified `README.md` and `Lobster/README.md` document it as a separate proof-of-concept, not ApexMail runtime code.
- [x] 🟠 **`sales-autopilot` lacked a binary entrypoint claim.** Verified `services/mail-server/crates/sales-autopilot/src/bin/server.rs` exists and starts the service.

## 🟡 Medium Issues

- [x] 🟡 **Compose secret files lacked a preflight.** Added executable `tools/validate-compose-secrets.sh` and documented it in `tools/README.md`.
- [x] 🟡 **Referenced GitHub workflows needed verification.** Verified workflow files exist and `tools/check-forbidden-patterns.sh` passes with SHA-pinned actions and job timeouts.
- [x] 🟡 **Base and override image tags diverged.** Base Compose now uses `postgres:16.8-alpine` and `redis:7.4-alpine`, matching local override versions.
- [x] 🟡 **Billing/webhook endpoints shared general API rate limits.** `deploy/nginx/nginx.conf` now defines `api_billing` and `api_webhooks` zones and routes billing/webhook paths through them.
- [x] 🟡 **Synthetic monitor broad exception handling hid detail.** Probe failures still preserve metrics, but now log full exception detail and traceback to stderr.
- [x] 🟡 **Marketing analytics pixel used an unverified Plausible host.** Source config and generated artifacts no longer reference `plausible.apexmail.ee`; analytics are explicitly disabled unless a deployed endpoint is configured.
- [x] 🟡 **Grafana monitoring profile lacked default admin env.** Base Compose now provides development defaults for `GF_SECURITY_ADMIN_USER` and `GF_SECURITY_ADMIN_PASSWORD`; production remains supplied by the production env/override path.
- [x] 🟡 **Postgres exporter used `sslmode=disable`.** Exporter DSN now uses `sslmode=require`.
- [x] 🟡 **Redis entrypoint failed without a secret-file fallback.** `deploy/redis/entrypoint.sh` now prefers the secret file but falls back to `REDIS_PASSWORD` when the file is absent.
- [x] 🟡 **Tooling scripts were underdocumented.** `tools/README.md` now documents the compose secret preflight and requires every retained tool to be classified as supported or historical/manual.
- [x] 🟡 **`.editorconfig` lacked Python coverage claim.** Verified current `.editorconfig` includes `[*.{rs,py}]` with four-space indentation.
- [x] 🟡 **K8s had no Prometheus alert rule source.** Added `deploy/k8s/observability/prometheus-rules.yaml` with Prometheus config/rule ConfigMaps and included it in kustomization.
- [x] 🟡 **Grafana datasource provisioning was incomplete.** Provisioning now includes stable UIDs for Prometheus, ClickHouse, PostgreSQL, and Tempo; Compose installs the ClickHouse datasource plugin.

## 🔵 Low / Info Issues

- [x] 🔵 **Migration systems used different formats.** `tools/migrations` is now a documented legacy archive; active schema changes go to SQLx migrations only.
- [x] 🔵 **Compose override lacked consistent port/security override behavior.** Removed Compose-specific tags and made full-stack application startup opt-in through profiles rather than partial ad hoc overrides.
- [x] 🔵 **`.dockerignore` excluded all Markdown.** Removed the broad `*.md` exclusion while keeping targeted docs-context rules.
- [x] 🔵 **README used `api.yourdomain.com`.** README and related deployment examples now use `api.apexmail.ee`.
- [x] 🔵 **Synthetic monitor Dockerfile relied on shebang resolution.** Dockerfile now uses `ENTRYPOINT ["python3", "/usr/local/bin/synthetic_probe"]`.
- [x] 🔵 **Redis queue eviction could drop critical jobs.** Compose and Redis entrypoint defaults now use `noeviction` with append-only persistence enabled.
- [x] 🔵 **Production compose also used `!override` tags.** Removed production `ports: !override []` tags; production compose config renders with standard YAML.
- [x] 🔵 **Visual parity reports were claimed missing.** Verified `reports/visual-parity/` contains before/after and live browser smoke screenshot artifacts for marketing and login views.

---

## Verification

- [x] `bash tools/check-forbidden-patterns.sh` passed.
- [x] `python3 tools/validate_pricing_drift.py` passed.
- [x] `python3 tools/check_marketing_contrast.py` passed.
- [x] `python3 tools/check_rust_panic_paths.py` passed at `1693/1700`.
- [x] `python3 tools/check_outbound_delivery_contract.py` passed.
- [x] Python compile checks passed for changed exporters and AI training loaders/scripts.
- [x] JSON/JSONL parsing passed for `data/system_prompts.json`, `data/manifest.json`, `train.jsonl`, `test.jsonl`, `val.jsonl`, and `golden_qa.jsonl`.
- [x] Shell syntax checks passed for `tools/validate-compose-secrets.sh`, `deploy/redis/entrypoint.sh`, and `tools/update-checksums.sh`.
- [x] Grafana dashboard JSON parsing passed for every dashboard.
- [x] YAML parsing passed for changed deployment, observability, Grafana, Prometheus, Alertmanager, and Helm files.
- [x] `docker compose -f docker-compose.yml -f docker-compose.override.yml config` passed.
- [x] `docker compose -f docker-compose.yml -f docker-compose.prod.yml config` passed with required production variables supplied.
- [x] `cargo test --manifest-path services/mail-server/Cargo.toml -p ui-foundation migration_all_93_routes_have_view_functions` passed.
- [x] `cargo test --manifest-path services/mail-server/Cargo.toml -p observability-service --lib otlp` passed.

**Total unresolved issues: 0**