# Change Management Policy

> **Classification:** Internal Policy
> **Owner:** Engineering Lead, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Annually

---

## 1. Purpose

This policy governs how changes to the ApexMail platform are proposed, reviewed,
tested, deployed, and rolled back. It ensures that changes are introduced safely,
with appropriate oversight, and with minimal risk to customers and data.

---

## 2. Scope

All changes to:

- Application source code (all packages in the monorepo).
- Database schemas (migrations).
- Infrastructure configuration (Hetzner servers, networking, DNS).
- CI/CD pipeline configuration.
- Dependency versions (runtime libraries, base Docker images).
- Feature flags and runtime configuration.
- Security-sensitive components (auth, encryption, access control).

---

## 3. Change Categories

| Category | Description | Review Requirements |
|----------|-------------|-------------------|
| **Standard** | Routine code changes, feature development, bug fixes. | 1 code review approval. |
| **Security-sensitive** | Changes to authentication, authorisation, encryption, data access patterns, or secrets handling. | 2 code review approvals (at least 1 from security-aware reviewer). |
| **Infrastructure** | Changes to server configuration, networking, DNS, or cloud resources. | 1 approval from Admin role holder. |
| **Database migration** | Schema changes (DDL), data migrations. | 1 approval (standard), 2 approvals (destructive). |
| **Emergency** | Hotfixes for production outages or active security incidents. | 1 approval (may be retrospective). See §8. |

---

## 4. Code Review Requirements

### 4.1 General Rules

- **All changes** to the main branch require at least **1 approving review** from a
  team member who did not author the change.
- Self-merges are prohibited except under the emergency change process (§8).
- Reviews must assess: correctness, security implications, test coverage,
  performance impact, and adherence to coding standards.

### 4.2 Security-Sensitive Changes

Changes touching the following areas require **2 approving reviews**:

- Authentication and session management.
- Authorisation and RBAC logic.
- Cryptographic operations (hashing, encryption, key management).
- Data access layer (direct database queries, ORM model changes).
- API input validation and sanitisation.
- Secrets or environment variable handling.
- CORS, CSP, and other security headers.
- Dependencies with known security advisories.

At least one reviewer must have demonstrated security awareness (documented in
the team skills matrix or prior security review experience).

### 4.3 Review Checklist

Reviewers should verify:

- [ ] No secrets, credentials, or PII in the diff.
- [ ] Input validation for all new API endpoints.
- [ ] SQL injection prevention (parameterised queries).
- [ ] Appropriate error handling (no stack traces exposed to users).
- [ ] Test coverage for new or changed behavior.
- [ ] Migration safety (see §6).
- [ ] No unnecessary permission escalation.
- [ ] Logging does not capture sensitive data.

---

## 5. Deployment Process

### 5.1 Standard Deployment Pipeline

```
Developer branch
  → Pull Request (code review + CI checks)
    → Merge to main
      → CI build (lint, test, audit, image scan)
        → Deploy to staging
          → Staging validation (automated + manual smoke tests)
            → Canary deployment (10% of production traffic)
              → Monitor canary (15 minutes minimum)
                → Full production rollout
                  → Post-deployment monitoring (30 minutes)
```

### 5.2 CI Checks (Required to Pass)

| Check | Tool | Blocking |
|-------|------|----------|
| Linting (Rust) | `cargo clippy` | ✅ Yes |
| Type checking (Rust) | `cargo check` | ✅ Yes |
| Unit tests (Rust) | `cargo test` | ✅ Yes |
| Integration tests | `cargo test` targeted crates + environment checks | ✅ Yes |
| Dependency audit (Rust) | `cargo audit` | ✅ Yes (critical/high) |
| Container image scan | Trivy | ✅ Yes (critical/high) |
| Build | Cargo | ✅ Yes |

### 5.3 Staging Validation

- Staging environment mirrors production configuration.
- Automated smoke tests run after each staging deployment.
- Manual validation required for UI changes and new features.
- Staging must be green before production deployment proceeds.

### 5.4 Canary Deployment

- 10% of production traffic routed to the canary instance.
- Monitored for **minimum 15 minutes** before full rollout.
- Key metrics watched: error rate, latency (p50, p95, p99), email delivery rate.
- Automatic rollback if error rate increases by >2x or latency p99 exceeds
  thresholds.

---

## 6. Database Migration Safeguards

### 6.1 General Rules

- Migrations are versioned and stored in the repository (`migrations/` directories).
- Migrations run via CI/CD using a dedicated `migration_runner` database role.
- No manual migration execution in production.

### 6.2 Safe Migration Practices

- **Additive changes preferred:** Add columns, tables, and indexes. Avoid dropping
  or renaming in the same release.
- **Backward compatibility:** Migrations must not break the currently running
  application version. Deploy code that handles both old and new schemas, then
  migrate, then clean up.
- **Timeouts:** Long-running migrations (e.g., large table rewrites) must include
  a statement timeout and be tested against production-size data.

### 6.3 Destructive Migrations

The following operations are classified as **destructive** and require additional
safeguards:

- `DROP TABLE`
- `DROP COLUMN`
- `TRUNCATE`
- Bulk `DELETE` or `UPDATE` affecting >10% of a table.
- Column type changes that may lose data.

**Requirements for destructive migrations:**

1. **2 code review approvals** (at least 1 from an Admin role holder).
2. Data backup verified before execution.
3. Migration tested against a production-size dataset in staging.
4. Execution plan reviewed (`EXPLAIN`) for performance impact.
5. Scheduled during a maintenance window if the table is large.

---

## 7. Feature Flags

### 7.1 Purpose

Feature flags allow new functionality to be deployed to production without being
immediately visible to all users. This decouples deployment from release.

### 7.2 Guidelines

- New features behind flags by default if they affect user-facing behavior.
- Flags have an owner and a planned removal date (max 90 days after full rollout).
- Stale flags (past removal date) are tracked and cleaned up in regular maintenance.
- Flag state stored in the database or configuration, not hardcoded.

### 7.3 Flag Lifecycle

```
Created (disabled)
  → Enabled for internal testing
    → Enabled for beta users (% rollout)
      → Enabled for all users (100%)
        → Flag removed from code (cleanup PR)
```

---

## 8. Emergency Change Process (Hotfix Path)

For production outages, active security incidents, or critical vulnerabilities
where the standard process is too slow:

### 8.1 Criteria

- Active P1 or P2 incident (see [Incident Response](./incident-response.md)).
- Critical vulnerability with known exploit (CVSS ≥ 9.0).
- Production outage affecting email delivery.

### 8.2 Process

1. Hotfix branch created from the current production tag.
2. **Minimal change** targeting only the issue (no unrelated changes).
3. **1 code review approval** (can be asynchronous via chat/call if needed).
4. CI build must pass (tests may be scoped to the affected area).
5. Deployed directly to production (skipping staging and canary).
6. Immediate post-deployment monitoring (minimum 30 minutes).
7. Hotfix backported to the main branch via standard PR.

### 8.3 Post-Emergency Review

Within 48 hours of an emergency change:

- Document what was changed and why.
- Confirm the backport to main is merged.
- Assess whether the standard process should be updated to prevent future
  emergency changes for similar issues.
- File in the incident post-mortem if part of an incident.

---

## 9. Rollback Procedures

### 9.1 Application Rollback

- Previous container images are retained (tagged by commit SHA and build number).
- Rollback is a redeployment of the previous known-good image.
- Rollback decision made by the deployer or Incident Commander.
- Rollback target: complete within **5 minutes** of decision.

### 9.2 Database Rollback

- Every migration has a corresponding `down` migration.
- Database rollbacks are tested in staging before production use.
- If a rollback is not safe (data loss risk), the forward-fix approach is
  preferred: deploy a new migration that corrects the issue.

### 9.3 Rollback Triggers

Automatic or manual rollback is triggered by:

- Error rate increase >2x baseline after deployment.
- Latency p99 exceeding defined thresholds.
- Email delivery rate drop >5%.
- Any unhandled exception in a critical path.

---

## 10. Change Log Requirements

### 10.1 What to Log

All changes to production systems must be recorded:

- **Application changes:** Tracked via Git history and PR descriptions.
- **Infrastructure changes:** Logged in the ops channel and configuration
  management history.
- **Database migrations:** Tracked in the `migrations/` directories and CI logs.
- **Emergency changes:** Documented in the incident record.

### 10.2 PR Description Standards

Every pull request must include:

- **Summary:** What the change does and why.
- **Testing:** How the change was tested.
- **Rollback plan:** How to revert if something goes wrong.
- **Migration notes:** If applicable, migration details and backward compatibility.

---

## 11. Related Documents

- [Incident Response Plan](./incident-response.md)
- [Vulnerability Management Policy](./vulnerability-management.md)
- [Access Control Policy](./access-control.md)
- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Data Retention Policy](./data-retention.md)
