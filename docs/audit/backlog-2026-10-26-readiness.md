# Readiness Backlog — external audits of d2d4a69d and db7e0b4d (2026-10-26)

Ordered by the external audits' own priority lists. Status is executable
fact: DONE (shipped + tested in this repository), PARTIAL (mechanism
landed, the rest is tracked), or OPEN. Nothing here is claimed externally
until it ships. Public wording stays company-level: no organisation-size,
infrastructure-provider, or topology disclosure on any customer-facing
surface (owner directive 2026-10-26).

| # | Program | Status | Where the truth lives |
|---|---|---|---|
| 1 | Remove the false public SOC 2 Type II attestation | **DONE** | `compliance::trust_portal` — `OWN_ATTESTATIONS = ["GDPR (Article 28 DPA)"]`; `check_trust_claim()` is now the RUNTIME boundary of `overview()` (a forbidden claim fails the endpoint, not just a test). Overview schema split per audit finding 1: `apexmail_attestations` is a separate field, subprocessor certifications stay on `subprocessors[].certifications`, no merged headline array. `ai-service` trust answers truthful (`incident_response`, residency without topology). |
| 1b | Public security claims → company-level truth, no disclosures | **DONE** | Security page (4 locales): role-neutral wording (no staffing claims, no fictional approvers, no provider/host/topology disclosure); same for the TOM, the DPA pages, the subprocessor register (provider name withheld from all public output — the generator emits the generic identity and the seed/mirror/gate all carry it), data-locations and EU-sovereignty pages (4 locales each). |
| 1c | WAF/IDS truth reconciliation (second audit found an UNDERclaim) | **DONE** | The managed baseline sets `MTA_IDS_ENABLED=true` / `MTA_IDS_REFUSE=true` and the IDS engine is wired into the MTA inbound path — the public page now says IDS is an ACTIVE inbound control in all 4 locales; WAF body inspection stays honestly roadmap. |
| 2 | Durability: mandatory off-host mirror | **DONE** | `postgres-backup-encrypt.sh` fails non-zero without `BACKUP_TARGET` or on rsync failure and writes `.last_offsite_ok`; compose refuses an empty `${VAR:?}` and the healthcheck requires a fresh stamp. |
| 2b | Durability: automated restore drill — producer/consumer contract repaired | **DONE** | Second audit caught the drill decoding with drifted PBKDF2 iterations (100k vs 600k), so no real backup could pass. Fixed at the root: `deploy/hardening/scripts/backup-envelope.sh` is the ONE canonical envelope (AES-256-CBC, PBKDF2 600k, SHA-256, gzip) sourced by BOTH producer and drill, baked into the image AND bind-mounted; the drill stages decrypt → gunzip → pg_restore; `--self-test` runs a real codec round trip plus a drifted-parameter rejection; validate stage runs it. Proven end-to-end with a real `pg_dump -Fc` archive through producer encode → drill decode → byte-identical → scratch restore. |
| 2c | Durability: **WAL archiving → PITR → warm standby** | **PARTIAL** | Repo-side enablement landed 2026-10-25: `pg-wal-archive.sh` (archive_command, exits 0 only when the segment left the host), `deploy/docker-compose.wal-archive.yml` (operator-included override, `${WAL_ARCHIVE_TARGET:?}`), weekly physical base backup (`WAL_BASE_BACKUP_ENABLED`, 2 generations), `pg-pitr-restore.sh` (replay to RFC3339/latest with drill-shaped evidence), `apexmail-wal-archive` alerts, all with self-tests in the validate stage; DR doc carries the operator enablement checklist. Still OPEN: production enablement itself (owner-gated: env + override + key on the deploy host) and the warm standby beyond it. RPO stays ≤24h logical until the operator flips it, then minutes. |
| 2d | Backup encryption fail-closed | **DONE** | A missing key or openssl now FAILS the backup instead of silently storing plaintext; `ALLOW_UNENCRYPTED_BACKUPS=true` is the explicit development-only escape. |
| 3 | Mailbot: purpose-aware multi-label purpose classifier feeding policy | **OPEN** | The 11-value sales disposition taxonomy is still the classification output. Keep the promotion-safety machinery; replace what feeds it. |
| 4 | Mailbot: tenant-owned draft review UX | **OPEN** | `/v1/admin/ai/drafts` and `/web/admin/ai/drafts/*` remain operator-only; customers currently 403. Largest product blocker. |
| 5 | Mailbot: 500–1,000 real-model threads scored end to end | **OPEN** | Dogfood evidence still runs the mock LLM. Needs real-model credentials (owner-gated). KPI: % drafts sendable with no/trivial edits, >90–95% per autosend class. |
| 6 | Console Assistant: large real-model evaluation (~500-task corpus) | **OPEN** | Architecture verified; model quality unproven (mock-llm evidence). Controlled release only until scored. |
| 7 | Certification control/policy layer (org size never disclosed publicly) | **PARTIAL** | `soc2.rs` seeds rewritten to truthful control ownership; the internal change-management and access-control policy rewrite (CI gates as the independent control, no fictional reviewer roles) is in flight under the same no-disclosure rule. |
| 8 | SOC 2/ISO internal evidence core (org risk register, asset inventory, vendor register, SoA, cadence alerts) | **OPEN** | Private, never advertised. Do not begin a formal observation period before 7 and this land. |
| 9 | Release governance: blessing verified at BOTH deploy paths + repo-boundary status checks (I20) | **PARTIAL** | DONE: `deploy/scripts/deploy.sh` Step 0.5 verifies `.gate-blessing.json` fail-closed with the same `gate_blessing_refusal` the pipeline fetch stage uses (refuses wrong sha and incomplete lanes — proven); GitHub `main` protection APPLIED (force-push + deletion forbidden, admins included). OPEN: required status checks at the repo boundary — sequenced behind CI posting the six lane statuses to GitHub (nothing posts them today; enabling checks first would wedge every push); signed blessing artifacts (commit/config-digest/image-digests/lanes/timestamp/nonce) remain I20. |
| 10 | Sales Autopilot: monetary terminal reward | **DONE** | `RewardKind::reward_with_value` — `ln(1 + MRR/10)`, winsorised at €10k, floored above the paid rung; `record_reward` + batch path use it; regression tests pin scaling, ordering and the unknown-money fallback. |
| 10b | Sales Autopilot: separate the conversion posterior from monetary utility (P2) | **OPEN** | The reward scales money inside a Beta pseudo-posterior; a €4k retention adds ~6 pseudo-successes. Keep the monetary objective; move selection to P(outcome) × E[value\|outcome] − cost − risk with conservative promotion thresholds meanwhile. |
| 10c | GDPR DSR: sales person graph in export + erasure | **DONE** | Second audit's P0: the canonical DSR omitted the sales graph entirely. Now 25 registry entries (`ErasureStore::SalesSubject`/`SalesRetained`) each carrying BOTH the erasure statement and the export statement from one source; load-bearing execution order pinned (resolve → tombstone → points); access discloses every graph row; erasure leaves zero subject PII while pseudonymous process/statistical rows and the opt-out survive. Acceptance test: `full_prospect_access_then_erasure_leaves_no_sales_pii`. I25 evidence text updated. |
| 11 | Procurement automation for 100 accounts (questionnaire bank, DPA/SLA packages, onboarding/evidence packages) | **OPEN** | Answer strictly from the canonical truth registry; refuses anything unsupported. |
| 12 | Dedicated Tenant one-command idempotent provisioning | **OPEN** | Keep the product scarce and high-priced until this ships. |
| 13 | TOM truth sweep (DPA Annex 1 line-by-line) | **DONE** | `templates/compliance/security-measures.md`: every former false claim corrected (branch protection matches what is actually applied, no canary/staging, nightly GFS backups not weekly/daily-90d, no multi-zone/topology statements, drill measured not annual, RPO honest, roadmap labels where true); company-level wording throughout, no org-size/provider/topology disclosure. |
| 14 | Parser fuzzing campaigns (I15) | **OPEN** | SMTP/MIME hostile-parser territory. Cadence: CI smoke (seconds) → nightly hours → pre-release long campaign; every crash becomes a permanent regression corpus entry. |
| 15 | Centralize security-capability truth (one generated fact drives registry, deployment facts, public prose, TOM, questionnaires, AI answers, audit controls) | **OPEN** | The IDS underclaim/overclaim pair proved six hand-maintained descriptions drift; prose fixed this wave, centralization not yet built. |

## Third external audit (exfiltration-path scan of e898698e) — 2026-10-26

| # | Program | Status | Where the truth lives |
|---|---|---|---|
| E1 | VERP Return-Path reversibility (P0) | **DONE** | `apexmail_lib::verp` v3: AES-256-GCM token (key domain-separated from `VERP_HMAC_SECRET`), nothing decodable on the wire; worker mints v3 only, bounce server verifies v3 + v2-in-flight + v1-observation; pinned by `v3_token_carries_nothing_decodable` and the no-claims wire tests. |
| E2 | Mailbot prompt provider disclosure (P0) | **DONE** | Prompt rewritten: provider/transport/team language and the stale pricing table removed, 11-item never-disclose list added, pricing only from the runtime catalog; `ai-service/tests/prompt_disclosure_scan.rs` gates every prompt file AND the training corpora (drift-injection proven). 8 stale corpus generators scrubbed. |
| E3 | Reserved X-ApexMail-* headers on recipient mail (P0) | **DONE** | Canonical byte-level `strip_reserved_headers` in `apexmail_lib::email_headers` (single implementation); the SES raw-MIME adapter strips before SendRawEmail (correlation is via `email_queue.smtp_message_id`, not headers); the relay delegates; wire-capture test pins zero reserved headers + customer headers surviving. |
| E4 | Console Assistant residency geography (P1) | **DONE** | `data_residency` = EU/EEA only; the test now asserts the NEGATIVE property (no Helsinki/Nuremberg/provider/region-codes/hosts/IPs). |
| E5 | Health endpoints expose dependency state (P1) | **DONE** | Anonymous `/health/ready` + `/health/deep` answer `{"status":"ok"}` / 503 `{"status":"unavailable"}` only; full detail requires loopback or the `METRICS_TOKEN` bearer; all consumers (Prometheus blackbox, compose checks, lifecycle tests) verified. |
| E6 | Routing receipts expose transport/tenant/IP (P1) | **DONE** | `apexmail-routing-proof/v2` customer proof (opaque receipt id, policy, satisfied, residency class, timestamp, Ed25519 signature over the minimal payload — no tenant/transport/IP); public verify endpoint accepts both forms and refuses cross-form fields; internal v1 receipt unchanged for the ledger. |
| E7 | Events API raw metadata (P1) | **DONE** | Customer routes serialize an allowlist DTO (no transport/source-IP/host/provider keys); admin keeps raw. |
| E8 | Timeline names internal stores (P1) | **DONE** | Lifecycle source names (accepted/campaign/queue/delivery_attempt/delivery_event) + shared detail sanitizer (no IPs/hostnames/provider identities/SMTP transcripts/DB errors). |
| E9 | Status page shows implementation services (P1) | **DONE** | Components are product names only (API, Dashboard, Email sending, Login and account access, Billing and checkout, Tracking and analytics, Inbound email, Webhooks); no database/server/process names. |
| E10 | Questionnaire private-doc default (P1) | **DONE** | `include_private_documents` defaults to FALSE; private evidence only on explicit opt-in. |
| E11 | Trust portal public+NDA defect (P1) | **DONE** | Migration 271 CHECK constraint (proven live: contradictory insert refused), public query filters `requires_nda = FALSE`, upsert fails fast. |
| E12 | Static build artifact allowlist (P2) | **DONE** | `.htaccess`/`_headers`/`_redirects` removed from the served tree (their live redirects ported to nginx.conf); `tools/check_public_artifacts.py` gates the static tree + the served OpenAPI (admin/cp/internal/provider patterns), self-tested, wired into validate. |
| E13 | OpenAPI admin-surface gate (P2) | **DONE** | Same tool: the SERVED spec stays clean (it is today; the internal docs/api source legitimately documents admin routes). |
| E14 | SES callback route fingerprinting (P2) | **DONE** | `POST /hooks/delivery/:hook_id` (pure hex, 16-64 chars — a descriptive id is refused outright) reaches the SAME SNS-validated handler; mounted beside the legacy `/v1/ses` path, which stays for subscriptions already registered with AWS. Behavior parity pinned by test. |
| E15 | DisclosureClass/GovernedFact architecture | **DONE (foundation)** | `apexmail_lib::disclosure` — `DisclosureClass` (Public < Customer < SecurityReview < Internal, privilege-ordered) + `GovernedFact<T>` whose ONLY read path is `visible_to(audience)`; trust-portal own attestations are wired through it (class is a reviewable constant; reclassifying drops them from the anonymous overview). Remaining conversion: other outward paths consume facts through the module rather than literals. |
| E16 | Nine exposure-test program | **PARTIAL (8 of 9 lanes landed)** | Landed: external route census (`tools/check_route_census.py` + committed 84-route manifest; unknown/stale/forbidden/compliance-proxied all fail), outbound wire test (E3), API-response schema gate (`tools/check_customer_dtos.py`: generic `serde_json::Value` in customer Serialize structs fails unless allowlisted — 11 entries, each write-path verified), prompt/corpus gate (E2), generated-document render gate (all 8 compliance templates rendered through the real renderer; disclosure scan on ALL of them, zero-tolerance framework ban on the DPA annexes — it caught two single-host residuals during widening), static allowlist (E12/E13), protocol-surface sweep (`protocol_surface_sweep_hides_every_internal_identifier`: MIME headers, tracking token, unsubscribe token, Return-Path), legal exception manifest (`docs/operations/disclosure-exceptions.json`, schema-validated by check_public_artifacts). Owner-gated: the LIVE-model adversarial run — the 12-case disclosure corpus is committed and checker-green (267 cases total); execution needs real model credentials. |
| E17 | Dormant AI corpus regression risk | **DONE** | Corpora scrubbed + the prompt_disclosure_scan gate covers training/RAG inputs, not just website files. |
| E18 | Compliance templates carried provider/topology facts | **DONE** | The six non-annex templates (trust-center, data-locations, compliance, performance-methodology, responsible-disclosure, incident-response) were scrubbed — provider name, Nuremberg/Frankfurt facility claims, "single-host topology" x2, bootstrap script filename — and the render gate's disclosure scan now covers ALL eight templates (it caught two residuals the manual scrub missed). |

## Fourth external audit (broad re-audit of 886e437b) — 2026-10-27

Verdict shift accepted: disclosure containment **9/10 (major improvement, no longer a
launch blocker)**; controlled paying-customer launch **YES**; 100-contract steady state
**NO** until the five operational programs land. The remediation order below is the
audit's Tier 0-4 list with landing status.

| Tier | Program | Status |
|---|---|---|
| 0.1 | WAL archiving + PITR + weekly physical base backup (RPO minutes when enabled) | **DONE (repo-side)** — script (`pg-wal-archive.sh`), compose override (`deploy/docker-compose.wal-archive.yml`), backup-script weekly base backup (`WAL_BASE_BACKUP_ENABLED`), PITR restore with evidence (`pg-pitr-restore.sh`), archive-continuity alerts (`apexmail-wal-archive`), DR docs + operator checklist. Production enablement remains operator-gated (env + override + key); see also 2c. |
| 0.2 | Warm standby / second failure domain | OPEN — depends on 0.1 landing in production first (owner-gated infra). |
| 0.3 | Compilation/testing off the production machine | OPEN — owner infrastructure decision (separate CI host). Repo already supports it: the pipeline is host-agnostic, the deploy host verifies blessings and deploys only. |
| 0.4 | CI publishes stable GitHub checks, then make them required on main | Status publishing landed this wave (`apexmail/<lane>` contexts per stage, fail-open, token-gated: APEXMAIL_GITHUB_TOKEN/GH_TOKEN). Operator next steps: set the token on the CI runner, verify contexts on a real commit, then pin `apexmail/fetch,apexmail/validate,apexmail/docs,apexmail/ui,apexmail/test,apexmail/security` as required status checks (NOT before — contexts must be observable first or the branch wedges). |
| 0.5 | One clean full-workspace run from final HEAD | This wave (recorded in the release evidence; count reported honestly). |
| 1.6 | Purpose/risk/delivery-class classification replacing marketing-default replies | This wave: deterministic classifier + policy table + release-path fix (approved replies to inbound mail are SERVICE correspondence — the marketing-consent gate never applies to conversation replies; suppression/kill-switch/autonomy gates unchanged). The 11-value sales disposition stays for sales analytics. |
| 1.7 | Tenant-owned draft review UX | OPEN (the audit's remaining Mailbot GA blocker with 1.8). |
| 1.8 | 500-1,000 real-model thread study | OPEN, owner-gated credentials (corpus + grading rubric committed). |
| 1.9 | Empirical per-purpose autosend promotion | OPEN after 1.6 accumulates data. |
| 2.10 | Console live read-only tools (resolve the prompt/tool mismatch) | This wave: bounded one-round read-only tool loop in the live chat path, prompt matched to reality. |
| 2.11 | ~500-task real-model Assistant benchmark | OPEN, owner-gated credentials. |
| 3.12 | Onboarding as a state machine | OPEN. |
| 3.13 | Questionnaire/trust packages exception-only | PARTIAL: owner labels neutralized to "ApexMail" this wave; answer-bank truth-checking is the remaining build. |
| 3.14 | Dedicated Tenant idempotent provisioner | OPEN (bundle generation exists; physical provisioning is operator action). |
| 3.15 | Customer health/renewal/escalation queues | OPEN. |
| 4.16 | Control-seed truth sweep | PARTIAL: CC5.2 (Terraform/Helm fiction) and CC6.8 (sandbox overclaim) rewritten this wave; the remaining seeds get the same line-by-line treatment before any observation period. |
| 4.17 | Risk/assets/vendors/SoA/evidence-cadence core | OPEN (the real certification blocker). |
| 4.18 | Automated recurring evidence collection + overdue alerts | OPEN. |
| 4.19 | Operate the evidence core before starting Type II observation | OPEN — gated on 4.17/4.18. |

Also this wave: pricing.json's dead contradictory `ip_cost: 30` removed (audit item 7);
coverage gate gains CI_COVERAGE_DISK_REQUIRED=1 so a release run cannot silently skip
coverage on an undersized machine (item 6); questionnaire owner labels neutralized to
"ApexMail" (item 18 — no fictional teams, no solo disclosure).

## Fifth external audit (broad re-audit of e6a7c8b8) — 2026-10-28

Landed in `0acdc9fa` (code) and `974f2e7e` (console goldens).

Verdict accepted: controlled paying launch YES with exclusions (transactional SMTP,
journaling claims, low-RPO/PITR commitments, unattended questionnaires, SOC/ISO
representation); 100-contract steady state NO until the Tier-3 operations land. Its
tier list with landing status this wave:

| Tier | Item | Status |
|---|---|---|
| 0.1 | Encrypt WAL archives and physical base backups before offsite | DONE: `pg-wal-archive.sh` encrypts every segment (gzip + canonical envelope; NO KEY = NO ARCHIVE), `postgres-backup-encrypt.sh` seals the weekly `pg_basebackup` (`*.tar.gz.enc`), `pg-pitr-restore.sh` decrypts through a `--restore-command` mode and decrypts the base into its private scratch dir; the compose override mounts the envelope + key secret. Self-tests prove keyless refusal, encrypted-only artifacts, decrypt round trips, legacy plaintext reads. |
| 0.2 | `archive_timeout` + archive-lag RPO alert | DONE: `-c archive_timeout=${WAL_ARCHIVE_TIMEOUT_SECS:-300}` in the override (deterministic minute-scale bound even on a write-idle DB) + `PostgresWALArchiveLagExceeded` warning at 20m beside the 2h critical. |
| 0.3 | Mailbox "journaling" claim | RESOLVED AS A DOCUMENTATION-TRUTH DEFECT: the journal IS built (`mail_journal` migration 264 — worker copies outbound raw MIME, mailstore copies inbound, `/v1/journal` + `/settings/journal` tenant surface, retention purge). The audit quoted a STALE product_lines.rs comment ("nothing copies...") which also misled it; that comment is rewritten to the truth and the marketing/invoice label now says "in-platform" everywhere. Only the third-party/external journal connector does not exist and is not claimed; it stays open as a feature request. |
| 0.4 | SMTP authenticated message class | DONE: migration 272 adds `users.message_class` (default `marketing`; CHECK marketing/transactional/service); submission auth carries the credential's class into the queue category (server-owned, customer MIME headers ignored and covered by a forged-header test); no customer-facing creation surface exposes the field (deliberate operator write). |
| 0.5 | Platform/system emails off the implicit marketing default | DONE: `queue_system_email*` now REQUIRE an explicit category at compile time; all 9 callsites classified (password reset, verification, invites, email-MFA codes, billing/account lifecycle notices = transactional). |
| 1.6 | SOC evidence false-success | DONE: collector failures on evidence persistence count failed, carry the error, and the run status is never success with zero persisted (aggregate success/partial/failed). |
| 1.7 | Attestation from full required evidence | DONE: `recompute_attestation` requires every `evidence_required` type present + hash-valid + fresh (cadence), else clears both stamps; seeds start unattested. |
| 1.8 | Evidence append-only | DONE: migration 274 drops the upsert identity, adds an append identity (+collected_at+id), a trigger rejects UPDATEs, and every reader uses latest-row (`DISTINCT ON ... ORDER BY collected_at DESC`). Old one-item attestations cleared. |
| 1.9 | Questionnaire auto-answers from real evidence | DONE: Automated only when all mapped controls are in scope, every required evidence item exists latest-row and fresh, no manual evidence missing, no legal/contract judgment; confidence = fresh+valid / required (no more 0.92 constant); gaps named in notes. |
| 1.10 | Fake 24/7 rotation/SRE/CTO/Legal control claims | DONE: trust-center on-call rotation/PagerDuty/SRE-lead/CTO escalation replaced with operator-routed monitoring wording; A1.1 autoscaling claim replaced with the real rate-limit/quota/capacity-review mechanism; `Legal` department owners replaced with Founder / System Operator; broad team-label sweep across docs, runbooks, PGP text and security.txt. |
| 1.11 | Truth-sweep every SOC control | PARTIAL: twelve seeds rewritten this wave (autoscaling, SIEM, drift detection, BCP/DR, HIPAA key claims, logging redaction, subprocessors, privacy policy location, WAF/IDS data-lake, SEV targets...). The full line-by-line sweep continues before any observation period. |
| 1.12 | HIPAA answer must say not offered | DONE: inactive HIPAA answers state ApexMail does not offer HIPAA/BAA service and must not be represented as HIPAA-enabled; the workflow invitation is gone. |
| 2.13 | Mailbot `Other` human-review-only | DONE: other → Service / Medium / HumanReview, pinned by test. |
| 2.14 | Multi-label purpose classification | DONE: `classify_all` returns every matched purpose + effective risk (MAX) + strictest autonomy + primary; monotonicity property test (17^3 sweep). |
| 2.15 | Header/MIME-based OOO/DSN classification | DONE: automated requires structural evidence (Auto-Submitted, Precedence, DSN multipart/report, autoreply headers, null Return-Path) plus 7 documented subject-line templates; prose-only phrases can no longer mark a customer as machine mail (counterexample pinned). The claim SQL/DDL now carries `headers`. |
| 2.16 | Tenant-owned Mailbot review UX | DONE: tenant-scoped `/v1/ai-drafts` list/get/approve/reject with structured reason and regenerate share the operator approval core (consent, claims, audit all enforced server-side), plus the console page with its goldens. |
| 2.17 | 500-1,000 real-model Mailbot corpus | OPEN, owner-gated credentials (corpus + grading committed). |
| 2.18 | ~500-task real-model Console corpus | OPEN, owner-gated credentials. |
| 3.19 | Separate CI machine + status publishing | PARTIAL: publisher implemented (apexmail/<lane>); operator must run CI with the token, observe contexts, then enable required checks. Host separation = owner infra decision. |
| 3.20 | Required GitHub status checks | OPEN until contexts are observed (explicit sequencing to avoid wedging main). |
| 3.21 | Encrypted PITR enabled in production | OPEN, operator checklist step. |
| 3.22 | Warm standby / second failure domain | OPEN. |
| 3.23 | Dedicated Tenant billing line | DONE: `dedicated_tenant` is a contract line priced from the catalog with a one-time setup fee and minimum term (migration 275), flowing through the same invoice sweep under row locking. |
| 3.24 | Dedicated Tenant host provisioning | OPEN (bundle lifecycle exists; physical provisioning is operator action). |
| 3.25 | Risk/assets/vendors/SoA/evidence-cadence core | OPEN (real certification blocker). |
| 3.26 | Onboarding state machine | OPEN. |

Also this wave: the coverage strict-disk flag (`CI_COVERAGE_DISK_REQUIRED=1`) is documented; making the release gate set it automatically is recorded for the release-run work.

Release posture (audits' read, accepted): controlled paying-customer launch YES;
100-contract steady state NO until the Tier-3 operations land; Mailbot internal/beta
YES (5.8 GA: purpose classification, tenant review UX, real-model corpus are the
non-waivables); Console Assistant controlled YES (8.0 capability / 6.3 practical until
the real-model benchmark lands); SOC/ISO preparation YES, formal observation NO until
the evidence core exists and has operated.

Release verification at `974f2e7e` (the one sanctioned full-workspace run): 13,303
tests run through nextest; 166 failures, all in `worker-processors` and `migrator`
during the final minutes of a ~40-minute parallel run. An isolated rerun of exactly
those two crates against a fresh ephemeral Postgres and Redis at the same HEAD ran
871 tests: 871 passed, 0 skipped, exit 0. The full-run failures were load-induced
(late-run cluster), not defects.
