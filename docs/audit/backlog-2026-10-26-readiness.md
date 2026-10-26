# Readiness Backlog — external audit of HEAD d2d4a69d (2026-10-26)

Ordered by the external audit's own priority list. Status is executable
fact: DONE (shipped + tested in this repository), PARTIAL (mechanism
landed, the rest is tracked), or OPEN. Nothing here is claimed externally
until it ships.

| # | Program | Status | Where the truth lives |
|---|---|---|---|
| 1 | Remove the false public SOC 2 Type II attestation | **DONE** | `compliance::trust_portal` — `OWN_ATTESTATIONS = ["GDPR (Article 28 DPA)"]` + `check_trust_claim()` refuses SOC 2 / ISO / HIPAA self-claims; overview tests assert the exact set. `ai-service` `get_compliance_info`: fabricated `soc2_incident` arm replaced by truthful `incident_response`; `data_residency` is Helsinki single-region with an empty certifications list. |
| 1b | Solo-operator rewrites of public security claims | **DONE** | Security page (4 locales): no background checks, no fictional approvers/peer review/segregation — machine gates and the deploy-host gate blessing are stated instead. Trust-portal `security-measures.md` §10 rewritten the same way. |
| 1c | WAF/IDS enforcement-mode reconciliation | **DONE** | Security page (4 locales) now states enforcement mode (the managed baseline pins `WAF_ENFORCE=true`); body inspection and IDS/IPS remain honestly non-active. |
| 2 | Durability: mandatory off-host mirror | **DONE** | `postgres-backup-encrypt.sh` fails non-zero without `BACKUP_TARGET` or on rsync failure and writes `.last_offsite_ok`; compose refuses an empty `${VAR:?}` and the healthcheck requires a fresh stamp. |
| 2b | Durability: automated restore drill with measured evidence | **DONE** | `deploy/hardening/scripts/postgres-restore-drill.sh` (+ compose service): scratch-database restore, integrity probes, JSON evidence with measured RPO/RTO under `/backups/drill-evidence/`, unhealthy when stale, `--self-test` for CI. |
| 2c | Durability: **WAL archiving → PITR → warm standby** | **OPEN** | Highest-value remaining infra item. Requires an off-host WAL transport that is validated on the production host (owner-gated deploy); the runbooks still honestly state that PITR does not exist. RPO stays ~24h until this lands. |
| 3 | Mailbot: purpose-aware multi-label purpose classifier feeding policy | **OPEN** | The 11-value sales disposition taxonomy is still the classification output. Keep the promotion-safety machinery; replace what feeds it. |
| 4 | Mailbot: tenant-owned draft review UX | **OPEN** | `/v1/admin/ai/drafts` and `/web/admin/ai/drafts/*` remain operator-only; customers currently403. Largest product blocker; the solo operator cannot be the reviewer for 100 tenants. |
| 5 | Mailbot: 500–1,000 real-model threads scored end to end | **OPEN** | Dogfood evidence still runs the mock LLM. Needs real-model credentials (owner-gated). KPI: % drafts sendable with no/trivial edits, >90–95% per autosend class. |
| 6 | Console Assistant: large real-model evaluation | **OPEN** | Architecture verified; model quality unproven (mock-llm evidence). Controlled release only until scored. |
| 7 | Certification control/policy layer for the solo company | **PARTIAL** | `soc2.rs` seeds rewritten to Founder / System Operator + compensating controls (CI gates, gate blessing, external review); remaining internal policy texts (access-control, change-management review clauses) and the consistency sweep are open. |
| 8 | SOC 2/ISO internal evidence core (org risk register, asset inventory, vendor register, SoA, cadence alerts) | **OPEN** | Private, never advertised. |
| 9 | Release governance: signed commits + lane-complete blessing enforced at the repo/deploy boundary (invariant I20), GitHub branch protection aligned to the solo model | **OPEN** | `.gate-blessing.json` mechanism exists on the host; the repository-side enforcement and branch protection are not yet applied. |
| 10 | Sales Autopilot: monetary terminal reward | **DONE** | `RewardKind::reward_with_value` — `ln(1 + MRR/10)`, winsorised at €10k, floored above the paid rung; `record_reward` + batch path use it; regression tests pin scaling, ordering and the unknown-money fallback. |
| 11 | Procurement automation for 100 accounts (questionnaire bank, DPA/SLA packages, onboarding/evidence packages) | **OPEN** | |
| 12 | Dedicated Tenant one-command idempotent provisioning | **OPEN** | Keep the product scarce and high-priced until this ships. |

Release posture (audit's read, accepted): controlled production launch of core
mail yes; Console Assistant controlled yes; Mailbot internal/beta only.
