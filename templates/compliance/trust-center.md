# ApexMail Trust Center

**Operated by {{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia.

The ApexMail Trust Center provides inspectable evidence of our security and compliance posture. This page is public and continuously updated.

## How to Read This Page (statement taxonomy)

Every control statement on this page belongs to exactly one of five classes. Present-tense statements are used ONLY for the first two classes:

| Label | Meaning |
|---|---|
| **[Implemented in platform]** | Ships in the running ApexMail platform today and is verifiable in the tree (deployment facts: `docs/deployment-facts.json`; capability wiring: `docs/development/capability-registry.json`). |
| **[Implemented by provider]** | A control delivered by the infrastructure provider (e.g., Hetzner) under the deployment configuration. |
| **[Operator policy]** | A commitment about how humans operate the platform; it is a policy, not a code-verified platform behavior. |
| **[Roadmap]** | Planned; not live. Marked explicitly, never stated in the present tense. |
| **[Not currently implemented]** | Named so it cannot be mistaken for a live control. |

| Section | Classification |
|---|---|
| Encryption in Transit / Encryption at Rest | Implemented in the platform (LUKS block-volume encryption: implemented by provider) |
| Authentication / Authorization | Implemented in the platform; administrative-access and review-cadence rules are operator policy |
| Software Security / Infrastructure Security | Labeled per bullet |
| Monitoring | Implemented in the platform (alert rules in `deploy/alerting-rules.yml`) |
| Backups and Recovery / Business Continuity | Labeled per bullet |
| Data Deletion | Operator policy, enforced by platform retention jobs |
| Certifications / Penetration Tests | Status tables (roadmap / not currently available) |
| Vulnerability Disclosure | Operator policy |

## Security Overview

ApexMail provides transactional email infrastructure with EU/EEA-oriented deployment configurations and security designed for regulated industries. Active data and telemetry locations are deployment-specific and confirmed under the applicable agreement. The production topology is a single Hetzner host (Finland) running the full stack under Docker Compose; statements below are scoped to that reality.

### Encryption in Transit

- **Supported TLS versions**: TLS 1.3 for all external connections; TLS 1.2 is the minimum accepted version with cipher restrictions rejecting weak ciphers (RC4, 3DES, export-grade).
- **HTTPS enforcement**: All HTTP requests are redirected (301) to HTTPS. HSTS is set with `max-age=31536000; includeSubDomains; preload`.
- **SMTP TLS**: TLS is mandatory on port 587 (STARTTLS required). SMTP on port 25 is opportunistic STARTTLS; plaintext SMTP without STARTTLS is rejected on port 587.
- **Internal service traffic**: Inter-service communication runs on isolated, non-public deployment networks and does not cross the public internet. [roadmap] Service-to-service TLS (mutual TLS where service identity verification is required) is planned.
- **Certificate management**: Certificates are issued via Let's Encrypt (automated ACME renewal every 60 days). Certificate expiry monitoring triggers alerts at 30, 14, 7, and 1 day before expiry.

### Encryption at Rest

- **Databases encrypted**: PostgreSQL data directory is stored on LUKS-encrypted block volumes (AES-256-XTS). All database backups are encrypted before transfer to object storage.
- **Object stores encrypted**: S3-compatible object storage uses server-side encryption (AES-256). Customer-uploaded attachments and templates are encrypted at rest.
- **Backups encrypted**: All backup artifacts (database dumps, configuration snapshots, log archives) are encrypted with AES-256 before being written to backup storage. Backup encryption keys are separate from production keys.
- **Logs encrypted**: Log storage volumes are encrypted at rest. Log archives older than 30 days are compressed and encrypted before cold storage.
- **Key ownership**: ApexMail owns and manages encryption keys. Keys are stored in a dedicated secrets management service, never in configuration files or source code.
- **Key rotation policy**: Database encryption keys are rotated annually. TLS certificates auto-rotate every 60 days. API signing keys are rotated on compromise or annually, whichever comes first. Key rotation is non-disruptive (overlap period for all credentials).

### Authentication

- **Password requirements**: Minimum 12 characters; must include uppercase, lowercase, digit, and special character. Passwords are hashed with Argon2id (memory=19456 KiB, iterations=2, parallelism=1). Breached-password checking via k-anonymity API.
- **MFA availability**: TOTP-based two-factor authentication (2FA) is available for all accounts. SSO/SAML integration is available on Enterprise plans. WebAuthn/FIDO2 is planned.
- **Social login**: Google OAuth 2.0 and GitHub OAuth are supported for dashboard authentication.
- **Session duration**: Dashboard sessions expire after 24 hours of inactivity. API sessions are token-based with configurable expiry. Absolute maximum session lifetime is 7 days, after which re-authentication is required.
- **Session revocation**: Users can revoke all active sessions from the dashboard security settings page. Administrative session revocation is available to account owners. Sessions are automatically revoked on password change, role change, or account suspension.
- **API-key authentication**: API keys are 256-bit random values, displayed only once at creation time. Keys are stored as SHA-256 hashes; plaintext keys are never retrievable after initial display. API keys can be scoped to specific permissions and IP ranges (Enterprise). Keys can be rotated without downtime.
- **Key visibility rules**: Full API key value is shown exactly once (at creation). Subsequent views in the dashboard show only the 8-character prefix and 4-character suffix (e.g., `sk_live_a1b2…w9x0`). SMTP credentials follow the same visibility rule.

### Authorization

- **Roles**: Owner, Admin, Developer, Billing, Read-only. Each role has a defined permission set.
- **Permissions**: Granular permissions control API access, domain management, template editing, billing, team management, and audit log access. Permissions are additive; no implicit escalation paths exist.
- **Team access**: Team members are invited by email and assigned roles. Role changes are logged. Removing a team member immediately revokes all active sessions and API keys owned by that member.
- **Administrative access**: Production infrastructure access is restricted to a named set of SRE personnel via SSH with key-based authentication (no password auth). All administrative actions are logged with correlation IDs. Database access requires a break-glass procedure with manager approval and is time-limited (auto-expires after 4 hours).
- **Least privilege**: Service accounts and API keys default to minimum required permissions. New accounts start with zero permissions until explicitly granted. Internal services use per-service credentials with only the permissions required for their function.
- **Access reviews**: Quarterly access review for all personnel with production access. Semi-annual review of all service account permissions. Access is revoked within 24 hours of role change or departure.

### Software Security

- **[Implemented in platform]** Static analysis: SAST via Semgrep and Clippy (Rust) runs in the self-hosted pipeline on every run and fails closed on the deploy host. Rules cover OWASP Top 10 classes, injection, hardcoded secrets, and unsafe patterns; a SAST failure blocks the pipeline.
- **[Implemented in platform]** Secret scanning: Gitleaks over the full git history plus Trivy filesystem secret scanning run in the pipeline's security stage. Pre-commit hooks are available; detected secrets are triaged in-tree or rotated.
- **[Implemented in platform]** Dependency vulnerability scanning: cargo-audit (with a reviewed advisory ignore list), cargo-deny (advisories, bans, sources, licenses) and a Trivy CRITICAL/HIGH gate on images run on every pipeline run.
- **[Operator policy]** Dependency updates: manual `cargo update` → full `ci/check-pr.sh` gate → push; the host pipeline deploys only green trees. There is **no Dependabot** — GitHub-based automation was retired with the self-hosted CI cutover, and no dependency-update PRs are auto-created.
- **[Not currently implemented — operator-pending]** Codeowner review enforcement: we do NOT claim required CODEOWNERS review. Branch protection on `main` requires the `woodpecker` commit-status context, and `scripts/verify-branch-protection.sh` (which verifies required approvals and CODEOWNERS enforcement against the live GitHub API, failing closed) has not recorded a PASS. Until it does, review enforcement is operator-pending. The enforced substitutes today: the pre-push validate hook, `ci/check-pr.sh` for pre-merge verification, and the deploy-host pipeline that stops the line before images or deploy on any red stage.
- **[Implemented in platform]** Deployment control: the pipeline builds, gates, migrates, deploys and verifies in one ordered run; a red stage stops the line before deploy. **[Not currently implemented]** Canary percentages and automatic canary rollback — rollback is the documented manual retag procedure (`deploy/rollback-plan.md`).
- **[Implemented in platform]** Environment separation: production is a single Hetzner host under Docker Compose; development runs on developer machines against ephemeral containers. There are no separate staging clusters or environments — production data never leaves the production host, and CI test lanes use throwaway databases.

### Infrastructure Security

- **[Implemented in platform]** Network boundaries: one production host; Docker networks segment frontend, backend and data-plane traffic; database services have no host port binding and are reachable only on the internal Docker networks.
- **[Implemented in platform]** Firewalling: UFW default-deny incoming; inbound is limited to the service ports 25, 80, 443, 587 and 993 plus operator ports (22 SSH, 465 SMTPS, 2525/2526 bounce/FBL). Outbound is default-allow.
- **[Implemented in platform]** Host hardening: `deploy/scripts/hetzner-bootstrap.sh` installs Docker, configures UFW, hardens sshd (key-only authentication, no password auth) and adds fail2ban.
- **[Operator policy]** Administrative access: SSH with key-based authentication to the single production host by named operators. **[Not currently implemented]** Bastion hosts and session recording — there is no bastion tier to record.
- **[Implemented in platform]** Container isolation: services run as non-root users with dropped capabilities, `no-new-privileges`, read-only root filesystems plus tmpfs mounts where practical, and per-container CPU/memory limits (`docker-compose.prod.yml`).
- **[Operator policy]** Patch management: OS packages are patched promptly after release (critical security patches urgently); container images are rebuilt and redeployed on every pipeline deploy of the changed services.

### Monitoring

- **Application monitoring**: Prometheus metrics for all services, including request rates, error rates, latency percentiles, queue depth, and connection counts. Custom application metrics for business operations (messages processed, delivery attempts, bounce rates).
- **Infrastructure monitoring**: Host-level metrics (CPU, memory, disk, network) collected via node_exporter. Database metrics (connections, query performance) via postgres_exporter. Probe-based external monitoring via blackbox_exporter.
- **Security alerting**: Alerts for failed-authentication anomalies, service health (service-down, queue-backlog), and certificate expiry. [roadmap] Security-event alerting for request-screening (WAF) verdicts and IDS/IPS signals is planned; those engines are not active blocking controls today (see Security Measures).
- **Log retention**: Application and access logs retained per the retention registry (30 days by default, up to 365 days for Enterprise). Security audit logs retained for 365 days minimum (configurable via `AUDIT_RETENTION_DAYS`). Logs are immutable once written. Log archives are encrypted at rest.
- **On-call process**: 24/7/365 on-call rotation with primary and secondary responders. Alerts are routed via Alertmanager to PagerDuty. On-call handoff occurs at 09:00 UTC daily with documented status transfer.
- **Incident escalation**: Escalation from primary to secondary on-call after 15 minutes without acknowledgment. Escalation to SRE lead after 30 minutes. Escalation to CTO after 1 hour. See [Incident Response Policy](incident-response.md).

### Backups and Recovery

- **[Implemented in platform]** Backup frequency: nightly encrypted PostgreSQL `pg_dump` backups and nightly per-table ClickHouse dumps run as dedicated compose services (`postgres-backup`, `clickhouse-backup`). **[Not currently implemented]** WAL archiving — there is no continuous archiving and no point-in-time recovery; the recovery point is the last nightly backup.
- **[Implemented in platform]** Backup encryption: AES-256 with a PBKDF2-derived key from the `backup_encryption_key` Docker secret; encryption keys are separate from production data keys.
- **[Implemented in platform]** Backup retention: PostgreSQL keeps 14 daily / 8 weekly / 6 monthly generations (bounded to the newest 30); ClickHouse keeps 14 days / 14 artifacts; pruning is automatic. **[Operator policy]** Offsite mirroring (`BACKUP_TARGET`, rsync over SSH with pinned host keys) — recommended and monitored via backup healthchecks, but its configuration is an operator decision.
- **[Implemented in platform]** Restore verification: every backup is automatically decrypted and structurally validated (`pg_restore --list`, or the ClickHouse equivalent) before the plaintext is deleted — a backup that cannot be read is never counted as good, and each backup container's healthcheck requires a fresh artifact (< 25 h old).
- **[Not currently implemented]** Fully automated restore DRILLS: full-restore exercises are manual, at the documented quarterly cadence (`docs/operations/disaster-recovery-testing.md`), on a scratch host.
- **[Implemented in platform]** Recovery Point Objective (RPO): up to 24 hours — the last nightly backup. There is no near-real-time recovery point.
- **[Operator policy]** Recovery Time Objective (RTO): hours, not minutes (host rebuild + backup restore); the real number is measured and recorded in the quarterly drill. [roadmap] Cross-region failover is a planned Dedicated Tenant capability — not live; recovery is restore-based on the current single-host topology.
- **[Operator policy]** Geographic separation: backup locations follow the active deployment configuration and applicable agreement. Cross-region disaster recovery, where offered, is contract-specific and not a public-plan entitlement.

### Data Deletion

- **Account-deletion process**: Account owners can request full account deletion via the dashboard or support. Deletion follows the configured 30-day grace period (`GDPR_DELETION_GRACE_PERIOD`), after which it is irreversible. Customer data (messages, templates, domains, API keys, events, logs) is deleted within 30 days of the request. A 30-day grace window allows cancellation of deletion requests.
- **Message-data deletion**: Message content and metadata are permanently deleted within 30 days of account deletion or per the configured retention period (whichever is shorter). SMTP logs and delivery receipts are deleted on the same schedule.
- **Backup expiry**: Backups containing deleted customer data are expired as part of the normal retention rotation (a configured window, default 90 days). No backup is retained beyond that window for deleted account data.
- **Log retention**: See Logging and Monitoring section above. Logs containing customer data are purged at the end of their retention period.
- **Legal retention exceptions**: Where a legal obligation (e.g., tax records, court order) requires retention beyond the standard deletion period, affected data is quarantined and access is restricted to designated legal/compliance personnel only. The customer is notified if legally permitted.

### Certifications and Audit Status

| Framework | Status | Scope | Relevant Product | Auditor / Assessor | Last Assessment | Next Milestone | Evidence Availability | Contact Process |
|---|---|---|---|---|---|---|---|---|---|
| GDPR Compliance | Control-aligned | All personal data processing (customer data, email metadata, account data) | ApexMail Platform (all plans) | Internal DPO / legal counsel | 2026-07 — Internal audit | Ongoing — Continuous control monitoring | DPA (public), DSR process document (upon request), Article 30 record (upon request) | privacy@apexmail.ee |
| SOC 2 Type I | Planned — readiness assessment in progress | API, SMTP relay, dashboard, queue, auth, webhooks, billing | ApexMail Platform (multi-tenant) | To be selected (external CPA firm) | N/A — Readiness assessment in progress | Q1 2027 — Readiness assessment complete; Q3 2027 — Type I audit | Not yet available — Gated under NDA once complete | security@apexmail.ee |
| SOC 2 Type II | Planned — after Type I completion | Scope TBD (dependent on Type I scope) | ApexMail Platform | Same as Type I auditor | N/A | Q2 2028 — Type II audit (6–12 months after Type I) | Not yet available | security@apexmail.ee |
| ISO 27001 | Planned — evaluated based on customer demand | Scope TBD | ApexMail Platform | To be selected (accredited certification body) | N/A | Timeline dependent on customer demand | Not yet available | security@apexmail.ee |
| HIPAA | Not currently available | N/A | Enterprise / Dedicated Tenant only | N/A | N/A | BAA template available now for regulatory alignment | BAA template (upon request, under NDA) | security@apexmail.ee |
| PCI DSS | Not applicable | Payment processing (via Stripe) | N/A — Stripe is PCI DSS Level 1 certified | Stripe, Inc. | Valid — Continuous by Stripe | N/A | Stripe PCI DSS Attestation of Compliance (via Stripe dashboard) | support@apexmail.ee |

**Status labels used**:
| Label | Definition |
|---|---|
| Certified | Independent audit completed; certificate issued and current |
| Independently assessed | Third-party assessment complete; report available |
| Control-aligned | Internal controls mapped to framework; not externally validated |
| In progress | Active implementation or audit activity underway |
| Planned | On roadmap with defined timeline |
| Not currently available | Not on current roadmap or not applicable |
| Certification expired | Previous certificate has lapsed; renewal in progress or not pursued |

### Vulnerability Disclosure

ApexMail operates a responsible disclosure program with safe harbor for security researchers who follow our policy.

- **Security email**: {{SECURITY_EMAIL}}
- **PGP key**: Available at `/.well-known/security.txt`, `https://keys.openpgp.org/`, and upon request
  - Key fingerprint: `AB12 CD34 EF56 7890 1234 5678 90AB CDEF 1234 5678`
- **Safe harbor**: We will not pursue legal action against researchers who follow our [Responsible Disclosure Policy](responsible-disclosure.md)
- **Scope**: `*.apexmail.ee`, API endpoints (`api.apexmail.com`), dashboard (`app.apexmail.com`), SMTP infrastructure, support portal, status page
- **Out of scope**: Third-party services (Stripe, Hetzner, Let's Encrypt), social media accounts, physical security
- **Prohibited**: DoS/DDoS testing, bulk/spam email, social engineering, data exfiltration, credential harvesting
- **Response target**: Initial acknowledgment within 48 hours; triage within 5 business days; updates at least every 14 days
- **Disclosure process**: Coordinate disclosure timeline with researcher; publish advisories after remediation; credit researchers in release notes
- **Rewards**: No paid bug bounty program currently; researchers are acknowledged in our Hall of Fame and advisories
- **Full policy**: [Responsible Disclosure Policy](responsible-disclosure.md)
- **Security text file**: `https://apexmail.ee/.well-known/security.txt`

### Penetration Tests and Assessments

| Activity | Status |
|---|---|
| Independent penetration test | Planned — annual external application penetration test |
| Remediation of high/critical findings | In progress — per vulnerability management policy |
| Penetration test executive summary | Planned — publish after first test and remediation |
| Internal security assessment | In progress — continuous review by engineering team |
| Third-party risk assessment | In progress — annual review of subprocessors |

### Business Continuity and Disaster Recovery

- **Backup frequency**: Nightly automated encrypted backups (PostgreSQL and ClickHouse) with the documented retention generations (14 days / 8 weeks / 6 months for PostgreSQL; 14 days for ClickHouse).
- **Recovery Time Objective (RTO)**: hours, not minutes — measured in the quarterly rebuild drill (operator policy target).
- **Recovery Point Objective (RPO)**: up to 24 hours for transactional data (the last nightly backup); point-in-time recovery is not implemented.
- **Failover**: Service-level resilience on the current single-host topology — health-checked services with automatic restart; queue and message persistence to disk. [roadmap] Multi-AZ and cross-region failover are planned Dedicated Tenant capabilities, not live.
- **Testing**: Automated restorability validation on every backup (decrypt + structural check); full disaster-recovery drills are manual at the documented quarterly cadence.

### Incident Response

See [Incident Response Policy](incident-response.md) for full details.

Summary:
- Acknowledge confirmed incident within 15 minutes.
- Update every 30 minutes during active incident.
- Preliminary summary within 1 business day.
- Major-incident postmortem within 5 business days.

### Status Page

Real-time service status: `https://apexmail.ee/status`

## Document Requests

The following documents are available to Customers under NDA or as part of the security review process:

| Document | Availability |
|---|---|
| Data Processing Agreement (DPA) | Public — see [DPA](../legal/dpa.md) |
| Subprocessor List | Public — see [Subprocessors](subprocessors.md) |
| Technical and Organizational Measures (TOMs) | Available upon request — see [Security Measures](security-measures.md) summary |
| Penetration Test Summary | Gated — available under NDA after first test |
| Architecture Diagram | Gated — available under NDA |
| Business Continuity Summary | Gated — available under NDA |
| Standard Information Gathering (SIG) Questionnaire | In progress — available upon request |
| Consensus Assessments Initiative Questionnaire (CAIQ) | In progress — available upon request |
| Higher Education Community Vendor Assessment Toolkit (HECVAT) | In progress — available upon request |
| Business Associate Agreement (BAA) | Template available — see [BAA Template](../../docs/compliance/baa-template.md) |
| SOC 2 Report | Not yet available — see roadmap |
| ISO 27001 Certificate | Not yet available — see roadmap |

To request gated documents: contact **{{SUPPORT_EMAIL}}** with your organization details and specific document requirements.

## Security Roadmap

1. Independent penetration test (external application).
2. Remediate high and critical findings.
3. Publish penetration test executive summary.
4. SOC 2 readiness assessment.
5. SOC 2 Type I audit.
6. SOC 2 Type II audit (6–12 months after Type I).
7. ISO 27001 certification (if customer demand justifies).

## Contact

Security inquiries: **{{SECURITY_EMAIL}}**
Vulnerability disclosure: **{{SECURITY_EMAIL}}**
General inquiries: **{{SUPPORT_EMAIL}}**
