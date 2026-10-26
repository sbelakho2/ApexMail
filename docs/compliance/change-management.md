# Change Management Policy

> **Classification:** Internal Policy
> **Owner:** ApexMail
> Legal Entity: Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> Last Reviewed: 2026-10-25
> Review Cycle: Annually

---

## 1. Purpose

This policy governs how changes to the ApexMail platform are prepared, gated,
released, and rolled back. Every change passes the same deterministic controls
before it reaches production.

---

## 2. Scope

All changes to:

- Application source code (all packages in the monorepo).
- Database schemas (migrations).
- Infrastructure configuration (servers, networking, DNS).
- CI/CD pipeline configuration.
- Dependency versions (runtime libraries, base Docker images).
- Feature flags and runtime configuration.
- Security-sensitive components (auth, encryption, access control).

---

## 3. Change Categories and Their Controls

The author prepares the change. The mandatory independent control for every
category is the CI gate suite described in §4. Categories differ only in the
additional controls that apply on top of it.

| Category | Description | Additional controls |
|----------|-------------|---------------------|
| **Standard** | Routine code changes, feature work, defect repairs. | CI gate suite (§4). |
| **Security-sensitive** | Authentication, authorisation, encryption, data access, secrets handling. | CI gate suite with the security lanes (§4.2). |
| **Database migration** | Schema and data migrations. | Migration rules (§5). |
| **High-risk** | Migrations that alter applied ledger rows; changes on auth, billing, or security paths. | Migration rules (§5) and the additional gates (§6). |
| **Emergency** | Hotfixes for outages or active security incidents. | Emergency process (§10). |

---

## 4. The Independent Control: CI Gate Lanes

### 4.1 Required lanes

The required lane set is committed at `ci/required-lanes.txt`. A blessing that
is missing a row for any required lane, or records a row as anything other
than ok, is refused. The set covers the stage lanes `fetch`, `validate`,
`docs`, `ui`, `test`, and `security`, the required test sub-lanes (Rust, SDK
suites, browser, PHP, coverage ratchet), and the validation gates (lane
waivers, stub ban, invariants registry, ARK law, mirror, and artifacts
checks).

### 4.2 Security lanes

The `security` stage runs the security scanners on every change: `semgrep`
static analysis, `gitleaks` full-history secret scanning, `cargo audit`
dependency advisories, and `trivy` filesystem and image scans. Findings above
threshold fail the run. Triage happens in the committed scanner configuration
files, with justifications recorded next to each accepted finding.

### 4.3 Fail-closed execution

The pipeline stops at the first failing stage. A stage that ends as skip,
advisory, timeout, or failure is not a pass, and a run in that state cannot
produce a release blessing.

### 4.4 Rationale in the commit message

Every change carries a recorded rationale in its commit message. The git
history is the change record: what was done, and why, in the commit that
carries it.

---

## 5. Migration Safety

### 5.1 The additive-only rule

`tools/migration_lint.py` runs in the `validate` stage and refuses migration
SQL that breaks the additive, idempotent conventions:

- Destructive statements (`DROP TABLE`, `DROP COLUMN`, `DROP DATABASE`) must
  carry `IF EXISTS`.
- A destructive statement may also sit inside an existence-probing guard.
- `CREATE TABLE` and `CREATE INDEX` must be guarded with `IF NOT EXISTS`.
- `TRUNCATE` and `GRANT ALL` are forbidden in migrations.
- Every file must be valid inside one transaction. No explicit `COMMIT`, no
  `CREATE INDEX CONCURRENTLY`.
- `DELETE` and `UPDATE` statements without a `WHERE` clause are refused.

### 5.2 The production ledger

Applied migration files are checksummed in `_sqlx_migrations`, and the
migrator refuses to run if a recorded file's bytes change. Applied files are
therefore never edited in place. New migrations must satisfy the lint rules;
older exemptions inside the linter are recorded with justifications.

### 5.3 The migrate stage

The `migrate` stage runs the migrator before any service is recreated. It
dumps the applied ledger into the run directory first, as the pre-run backup.
It then fails the deploy if the applied count ever decreases.

---

## 6. High-Risk Changes

- Migrations that alter applied ledger rows follow §5 in full, including the
  ledger backup and the applied-count assertion.
- Changes on billing paths must pass `tools/check_prod_billing_wiring.py` in
  the `validate` stage. The gate pins the production payment wiring and
  refuses drift to retired provider surfaces.
- Every workspace change must pass `tools/check_invariants.py`, which keeps
  the invariant registry and the test-expectations file aligned with what the
  tree actually contains.
- Security-sensitive paths are covered by the security lanes (§4.2) like any
  other change.

---

## 7. Release: The Gate Blessing

After a green run of the full stage line, CI records a gate blessing: the
commit sha, the pipeline-config hash, and the per-lane statuses of that run.
The writer lives in `ci/pipeline.sh`; the refusal contract lives in
`ci/lib.sh` as `gate_blessing_refusal`.

A blessing is accepted only when all of the following hold:

- a blessing file exists on the host;
- its sha matches the commit being deployed;
- its pipeline-config hash matches the current pipeline configuration;
- every required lane in it records status ok.

Both deploy paths verify the blessing fail-closed before doing any work: the
canonical pipeline in `ci/stages/fetch.sh`, and the manual deploy script at
Step 0.5 of `deploy/scripts/deploy.sh`. A deploy without a valid blessing for
the current commit is refused.

### 7.1 Emergency override

`APEXMAIL_UNGATED_DEPLOY=1` bypasses the blessing check for a genuine
emergency. The bypass prints a loud warning that names itself as an
audit-visible bypass, and the deploy log records it.

---

## 8. Rollback

- Before services are recreated, `deploy/scripts/deploy.sh` snapshots the
  current images under a `:pre-deploy` tag (Step 1.5).
- If post-deploy verification fails, Step 8 retags that snapshot back onto
  `:latest` and recreates the stack, with no registry round-trip.
- The canonical pipeline's `verify` stage rolls the stack back to the previous
  verified sha when its probes fail (`CI_ROLLBACK_ON_VERIFY_FAIL`).
- For migrations, the run directory keeps the ledger dump taken before the
  run. Schema rollback is a corrective migration applied forward; the dump
  restores the record of what was applied.

---

## 9. Branch Protection

- Force pushes and branch deletions are forbidden on `main`. The rule is
  applied to the repository through the GitHub API.
- The `fetch` stage refuses to build a commit that is not pushed to `main`
  (`prove_head_pushed` in `ci/stages/fetch.sh`).
- Required status checks at the repository boundary are release-governance
  work and are tracked in §13.

---

## 10. Emergency Changes

### 10.1 Criteria

- Active P1 or P2 incident, per the [Incident Response](./incident-response.md)
  plan.
- Critical vulnerability with a known exploit and a severity score of 9.0 or
  above.
- Production outage affecting email delivery.

### 10.2 Process

1. The change is minimal and targets only the incident.
2. It lands on `main` and runs through the same CI gate suite (§4).
3. It deploys through the release pipeline and its blessing (§7).
4. When the gate line cannot be run in time, the deploy sets
   `APEXMAIL_UNGATED_DEPLOY=1`. The deploy log then carries an explicit
   emergency classification alongside the loud bypass line.
5. The gates relied upon are reviewed retrospectively within 48 hours, and the
   outcome is recorded in the incident record.

---

## 11. Feature Flags

Feature flags live in the database and are evaluated at runtime. A tenant
override wins over the global flag, a malformed override is ignored rather
than interpreted, and evaluation failures surface as errors. Administrative
flag changes are written to the audit trail.

---

## 12. Change Records

- Application changes: git history, with the rationale in the commit message.
- Migrations: the `migrations/` directories and the CI stage logs.
- Releases: the run records under `ci/runs/`, including manifests, stage
  logs, and the blessing.
- Emergency changes: the deploy log and the incident record.

---

## 13. Roadmap — not currently implemented

- Repository-boundary release governance: signed commits and lane-complete
  blessings enforced at the repository boundary, with required status checks
  configured on `main`.
- Progressive rollout: a canary stage in the deploy gate, with traffic
  shifting and automatic evaluation before full rollout. A deploy today is one
  verified rollout with post-deploy probes and automatic rollback.
- Automated feature-flag expiry and stale-flag cleanup.

---

## 14. Related Documents

- [Incident Response Plan](./incident-response.md)
- [Vulnerability Management Policy](./vulnerability-management.md)
- [Access Control Policy](./access-control.md)
- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Data Retention Policy](./data-retention.md)
