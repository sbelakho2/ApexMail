# Risk register (internal draft)

| Field | Value |
|---|---|
| Classification | Internal Policy, Confidential |
| Owner | ApexMail (privacy@apexmail.ee, compliance@apexmail.ee), Bel Consulting OÜ, registry code 16588745 |
| Written | 2026-10-28 |
| Review cycle | Quarterly, and after every P1 incident |

## Scope, sources and honesty

This register lists the risks that canonical repository sources describe. Every row names the source of the risk and the control that already exists, with the file where that control lives.

It is an internal draft supporting the SOC 2 and ISO evidence effort. It claims no certification and no audit-readiness status beyond what the cited sources state.

## Risk rows

| # | Risk | Category | Source of risk | Existing control and where it lives | Residual note |
|---|------|----------|----------------|--------------------------------------|---------------|
| 1 | Single production host with no standby region or automatic failover | Availability | `docs/operations/disaster-recovery.md` (reality check: one host, no standby region) | Encrypted nightly `pg_dump` and ClickHouse dumps with restore verification (`deploy/hardening/scripts/postgres-backup-encrypt.sh`; `postgres-backup` and `clickhouse-backup` services in `docker-compose.prod.yml`); `docs/operations/runbooks/db-recovery.md` | Warm standby is repo-side only and operator-gated (`docs/audit/backlog-2026-10-26-readiness.md` tier 3.22: OPEN) |
| 2 | Recovery point stays at the nightly cadence until WAL archiving is enabled | Availability | `docs/operations/disaster-recovery.md` (WAL archiving off in production; RPO <= 24 h logical) | Repo-side WAL tooling with self-tests: `deploy/hardening/scripts/pg-wal-archive.sh`, `deploy/docker-compose.wal-archive.yml`, `pg-pitr-restore.sh`, `apexmail-wal-archive` alerts in `deploy/alerting-rules.yml` | Production enablement and encrypted PITR remain operator checklist steps (backlog items 2c and 3.21: OPEN) |
| 3 | Recovery-time objective is unmeasured in production | Availability | `docs/operations/disaster-recovery.md` (RTO hours, to be validated in drills); `docs/invariants.toml` I17 status `planned` | Automated restore drill service `postgres-restore-drill` in `docker-compose.prod.yml`; timed drill `tools/pitr_drill.sh`; cadence in `docs/operations/disaster-recovery-testing.md` | Invariant I17 claims a measured restore; the production drill is operator-executed |
| 4 | Redis loss discards queue contents, rate-limit counters and challenge state | Availability | `docs/operations/disaster-recovery.md` (known gaps: Redis has no backup) | `docs/operations/runbooks/redis-failure.md`; queue persistence contract in `docs/invariants.toml` I21 | In-flight queued email not yet persisted to PostgreSQL is gone on Redis loss |
| 5 | Analytics-cold store is covered by no backup job | Data protection | `docs/operations/disaster-recovery.md` (known gaps: analytics-cold) | Nightly per-table dumps cover ClickHouse only (`clickhouse-backup` in `docker-compose.prod.yml`) | The source records the gap and names no remediation owner |
| 6 | Hostile parser input is not fuzzed in campaigns | Security | `docs/invariants.toml` I15 (`2 fuzz targets, never run`); `docs/audit/backlog-2026-10-26-readiness.md` item 14: OPEN | Static panic-path gate `tools/check_rust_panic_paths.py` on lane T7 | Cadence CI smoke to nightly to pre-release is described but not running |
| 7 | A public trust claim could exceed the real attestation | Governance | `docs/audit/backlog-2026-10-26-readiness.md` item 1 (false SOC 2 attestation removed) | Runtime boundary `check_trust_claim()` in the compliance crate trust portal; status table `docs/security/framework-status.md` | Control-seed truth sweep still partial (backlog items 4.16 and 1.11: PARTIAL) |
| 8 | A route or queue exposes data across tenant boundaries | Access | `docs/invariants.toml` I7 and I27 | 57 cross-tenant route tests on lane T5; `services/mail-server/crates/mta/tests/inbound_recipient_isolation.rs` on lane V13 | Dogfood authz probes remain manual (I7 plan note) |
| 9 | Erasure misses a store that still holds subject data | Privacy | `docs/invariants.toml` I9 and I25 | 25-entry erasure and export registry in `compliance/gdpr_automation.rs`, lane T11; acceptance test `full_prospect_access_then_erasure_leaves_no_sales_pii` | Erasure tests run without `mail_journal` (I9 plan note) |
| 10 | A payment webhook applies twice or a cancelled plan charges again | Financial | `docs/invariants.toml` I2, I3, I26 | accounting-core ledger tests on lanes T4 and T3; wiring gate `tools/check_prod_billing_wiring.py` on lane V1 | Cancel and sweep coverage partly manual (I2 plan note, dogfood M23) |
| 11 | A suppressed address is reached on some send path | Compliance | `docs/invariants.toml` I6 | Suppression tests in `worker-processors`, lanes T4 and T5 | Dogfood M09 pass is manual |
| 12 | A backup stores plaintext or fails restore verification | Data protection | `docs/audit/backlog-2026-10-26-readiness.md` items 2b and 2d | Fail-closed encryption and restore check before plaintext deletion in `deploy/hardening/scripts/postgres-backup-encrypt.sh`; canonical envelope `deploy/hardening/scripts/backup-envelope.sh` | Key material lives host-local under `/opt/apexmail/secrets`; an offline copy is an operator duty (`docs/operations/disaster-recovery.md`) |
| 13 | An optional vendor engages without appearing in the register | Vendor | `templates/compliance/subprocessors.md` (optional subprocessors depend on deployment configuration) | Generated register with drift gate and zero-US check: `tools/generate_subprocessors.py`, lanes V24 and T12 | Engagement of OAuth providers, SES or S3 telemetry follows the active configuration |
| 14 | A change deploys without lane evidence | Change management | `docs/invariants.toml` I20; `docs/audit/backlog-2026-10-26-readiness.md` item 9 | Signed blessing verified fail-closed in `ci/pipeline.sh` and `deploy/scripts/deploy.sh` Step 0.5; asymmetric Ed25519 verification (sixth-audit item 12a) | Required GitHub status checks are deliberately skipped by owner directive |
| 15 | Evidence ages out without anybody noticing | Compliance operations | `docs/audit/backlog-2026-10-26-readiness.md` items 4.18 and 16 | `stale_evidence_controls` plus `sweep_stale_attestations` with the `validate.soc-evidence-cadence` gate (sixth-audit item 16: DONE) | The evidence core must operate before any observation period starts (item 4.19: OPEN) |
| 16 | EU-only routing promise breaks on a non-EU hop | Privacy | `docs/invariants.toml` I4 | Routing policy tests B1 and B4 in `outbound-mta`, lanes T4 and T6 | Residual depends on routing policy data staying current |
| 17 | Dedicated-IP or hosting location drifts from the published register | Governance | `docs/invariants.toml` I23 | `tools/generate_subprocessors.py --self-test` refuses a US fixture and detects a mutated register, lanes V24 and T12 | The public register withholds the provider identity by design (backlog item 1b) |

## How residual notes are read

Residual notes quote the cited sources rather than adding a new assessment. A row stays open until the source behind it changes.
