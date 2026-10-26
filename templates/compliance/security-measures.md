# Technical and Organizational Measures (TOMs)

This document describes the technical and organizational measures implemented by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia, to protect personal data processed through the ApexMail platform.

This document serves as Annex 1 to the [Data Processing Agreement (DPA)](../legal/dpa.md).

Production is operated from an EU data location in Helsinki, Finland. Each measure below is labeled as implemented now, as an operational policy, or as roadmap (explicitly excluded from the current deployment).

## 1. Access Control

### 1.1 Physical Access Control

- All production infrastructure is hosted in Helsinki, Finland, in commercial data center facilities operated by the EU infrastructure provider named in the subprocessor annex to this DPA.
- Physical access to data center facilities is controlled, restricted, and monitored by the facility operator.
- ApexMail does not hold physical access to data center facilities.

### 1.2 Logical Access Control

- Role-based access control (RBAC) for all platform services.
- API keys and SMTP credentials are scoped to minimum required permissions.
- Session-based authentication with automatic timeout after inactivity.
- TOTP-based two-factor authentication (2FA) implemented for console authentication.
- SSO/SAML integration (Enterprise plans).
- IP allowlists (Enterprise plans), enforced fail-closed at the control-plane authentication middleware.
- Audit logging of all authentication events and administrative actions (see section 8.1).

### 1.3 Data Access Control

- Customer data is logically separated at the application layer (tenant isolation); all queries are scoped by account.
- [roadmap] Dedicated-tenant physically or logically isolated infrastructure is not part of the current deployment. All tenants share the standard multi-tenant deployment. A dedicated-infrastructure deployment is a contractual option described in the DPA eligibility terms, not a measure of the current deployment.
- Database access is restricted to authorized service accounts that receive credentials through Docker secrets.
- Production database access is restricted to authorized ApexMail personnel holding production privileges; administrative access is logged and auditable.

## 2. Encryption

### 2.1 Encryption at Rest

- Backup data is encrypted at rest: nightly backups are encrypted with AES-256-CBC using a key derived with PBKDF2 (600,000 iterations, SHA-256) from a protected management secret, before any plaintext is deleted.
- [roadmap] Encryption of primary storage (database volumes, block storage) at rest is not implemented in the current deployment. Disk-level encryption options are documented but not enabled on production storage.

### 2.2 Encryption in Transit

- TLS 1.3 for all external connections (TLS 1.2 minimum).
- Cipher restrictions: only strong, modern cipher suites accepted.
- HSTS with preload and `includeSubDomains`.
- Secure cookie attributes: `Secure`, `HttpOnly`, `SameSite=Lax`.
- SMTP submission connections require STARTTLS (port 587); plaintext submission is rejected. Port 25 stays opportunistic STARTTLS for interoperability.

## 3. Network Security

- Production network is separate from the development environment; CI runs in a dedicated build environment and never on production infrastructure — production runs only deployment output that passed the required gates.
- Host firewall (UFW) restricts inbound traffic to required service ports only (default deny incoming, explicit allow list). Outbound traffic is not restricted at the host firewall, except that the backup mirror runs on a dedicated egress network.
- Application-layer DDoS and abuse protection:
  - Cost-based request rate limiting with per-tenant budgets.
  - Adaptive per-IP thresholds (statistical z-score anomaly detection over request patterns).
  - Request fingerprinting (JA4/TLS and HTTP/2 fingerprints) feeding reputation decisions.
  - Load-shedding middleware ahead of authentication and rate-limit work.
- An intrusion detection system is active in the MTA inbound mail path: the IDS engine inspects every inbound message and the production baseline refuses messages that trip it.
- [roadmap] Planned capabilities that are NOT active controls in the current deployment: network-edge DDoS layers (SYN-flood/XDP filtering, ML-based anomaly detection, challenge-response) and network-traffic monitoring/alerting of the IDS/IPS kind at the network edge.
- Threat-intelligence feed ingestion is implemented and wired into the API reputation path (domain blocklist shared with the grader engine). Feed lists are set through deployment configuration; the baseline ships with no feeds configured, so the blocklist stays empty until feeds are added.
- Network traffic monitoring and alerting for service health (Prometheus, Grafana, Alertmanager).

## 4. Application Security

- Request screening (web application firewall) on the public API: SQLi/XSS/traversal/command-injection/SSRF rules evaluate method, path, query string and headers. The managed production baseline enables and enforces these rules on public API requests. [roadmap] Request-body inspection is not implemented; body-level rule evaluation is excluded from the current deployment.
- Input validation and output encoding.
- Parameterized database queries (no SQL injection).
- Cross-Site Request Forgery (CSRF) tokens on all state-changing requests.
- Content Security Policy (CSP) headers.
- CORS policy restricted to authorized origins.
- Secure password hashing (Argon2id).

## 5. Email Security

### 5.1 Sending

- SPF, DKIM, and DMARC enforced for all outgoing email.
- [roadmap] Planned, not active in the current deployment: MTA-STS policy publication and DANE/TLSA verification; outbound spam and phishing filtering and attachment sandboxing on the outbound delivery path. These capabilities exist as library implementations that are not wired into the outbound delivery path.

### 5.2 Inbound

- SPF, DKIM, and DMARC evaluation of inbound mail with policy-based dispositions.
- Inbound spam and phishing filtering is active on the inbound mail path; verdicts are stored as message headers and the production baseline rejects messages above the configured threshold.
- Attachment sandboxing is active on the inbound mail path: file-type detection via magic bytes, SHA-256 hash checking against known malware, OLE2/macro detection, and executable/risky-file blocking, with per-attachment verdicts stored as message headers.
- The inbound intrusion detection system described in section 3 refuses inbound messages on an IDS verdict.

## 6. Account Security

- Brute-force protection: rate limiting on authentication endpoints, plus escalating account lockout after repeated failed authentication attempts. A lockout requires corroborating failures from at least two distinct source IPs, so a single hostile source cannot lock a victim out.
- Challenge (KiwiCaptcha) integration on selected public endpoints.
- Account takeover (ATO) protection is active on the password login path: risk banding over impossible-travel, device-fingerprint, and login-anomaly signals drives step-up MFA or refusal on high-risk logins. The control is explicitly enabled in the production baseline.
- API keys can be created and revoked without downtime.
- Account lock after repeated failed authentication attempts (see above).

## 7. Data Security

- Data loss prevention (DLP) is active on the outbound send path: the worker runs a pre-send DLP gate over every prepared message (subject, bodies, decoded attachments) before the durable send reservation, with PII pattern detection (including the Luhn algorithm for credit card numbers), Shannon-entropy scoring for sensitive data, and content-policy enforcement that can hold or block a message.
- Threat-intelligence feed ingestion (IP/domain blocklists, reputation scoring) is implemented and wired as described in section 3; feed lists are set through deployment configuration.
- Data classification and labeling per the data retention registry.

## 8. Operational Security

### 8.1 Monitoring and Logging

- Structured logging for all services with correlation IDs.
- Prometheus metrics collection with Grafana dashboards.
- Alertmanager alerts for security events, errors, and threshold violations.
- Logs retained per the retention registry (30 days by default, up to 365 days for Enterprise); security audit logs retained 365 days by default (`AUDIT_RETENTION_DAYS`).
- Logs include: authentication events, API calls, administrative actions, security events, error conditions.
- Logs do not contain: plaintext passwords, full API keys, full payment card numbers.

### 8.2 Vulnerability Management

- Dependency scanning in CI (cargo audit and Trivy filesystem scans).
- Secret scanning in CI/CD pipeline (gitleaks and repository scanning).
- Static Application Security Testing (SAST) in CI/CD (Semgrep, a required security lane).
- Container image scanning (Trivy) as a deploy-time gate together with a digest-pinned release manifest.
- Production configuration validation in CI: the merged production environment and compose files are checked against the managed security baseline, and every security-control variable must be defined explicitly.
- Regular dependency patching driven by the CI dependency audit; operating-system patching of production infrastructure is applied through scheduled maintenance.
- Vulnerability disclosure program with safe harbor.
- [roadmap] Dynamic Application Security Testing (DAST) for public-facing endpoints is not part of the current pipeline.

### 8.3 Change Management

- The main branch is protected by GitHub branch protection: force pushes and branch deletion are forbidden for everyone, including administrators. The six required CI lanes (fetch, validate, docs, ui, test, security) are recorded per release in the gate blessing described below, and both deploy paths verify it fail-closed. Repository-boundary status checks enforcing those same lanes before a merge are release-governance work; no human-approval requirement is configured.
- Automated testing in CI/CD pipeline across the required lanes.
- Deploy blessing: CI records a gate blessing for a green run (commit SHA, pipeline-config hash, per-gate-stage statuses). Both deployment paths — the self-hosted deploy pipeline and the manual hotfix path (`deploy/scripts/deploy.sh`) — refuse to deploy a commit that has no valid blessing under the current pipeline configuration, verified fail-closed.
- Deployment procedure: images are built in the deploy environment, gate-checked with Trivy and pinned by digest in a release manifest, migrations are gated before `compose up`, containers are recreated one service at a time with healthcheck verification.
- [roadmap] Staged deployments and canary releases are not part of the current deployment; there is no staging environment and no canary stage.
- Rollback capability for all deployments: the deploy script snapshots current images before the upgrade and retags the pre-deploy baseline back if post-deploy verification fails.

## 9. Business Continuity and Disaster Recovery

- Automated backups run nightly as full dumps (PostgreSQL `pg_dump` in custom format, gzip-compressed, plus nightly per-table ClickHouse dumps).
- Backup encryption: AES-256-CBC with a PBKDF2-derived key (600,000 iterations, SHA-256) from an operator-managed secret.
- Restore verification before plaintext deletion: every backup is decrypted and structurally validated (`pg_restore --list` or the ClickHouse equivalent) before the plaintext dump is deleted. A backup that cannot be decrypted and read is never counted as good.
- Backup retention follows a grandfather-father-son scheme: 14 daily, 8 weekly, and 6 monthly generations, bounded to the newest 30 backups.
- Offsite mirroring of encrypted backups is mandatory: the backup service refuses to run without an offsite target, the run fails if the mirror fails, and the healthcheck requires a recent offsite-success stamp. A backup that has not left the production environment does not count as a backup.
- Recovery point objective (RPO): up to the nightly backup interval (approximately 24 hours). WAL archiving and point-in-time recovery are [roadmap], explicitly not implemented and excluded from the current TOM.
- Recovery time objective (RTO): not claimed as a fixed figure. Database recovery is exercised automatically at least every 30 days by a restore drill that restores the newest real backup into a scratch database, runs integrity probes, and records measured RPO and RTO evidence as JSON. A drill that never succeeds turns the drill container unhealthy.
- Disaster recovery: an automated monthly restore drill plus documented manual recovery procedures for database recovery and full environment loss, including a quarterly manual drill on an isolated scratch environment.
- Incident response process with a defined escalation path (documented steps, audit-logged timeline).

## 9.1 What is not backed up

- Redis holds cache, queue, and challenge state only; after a loss, queue contents and cached state are gone.
- The analytics cold store has no backup job.
- Environment-local state (environment files, secret files, TLS certificates) must be re-rendered during rebuild; an offline copy of the secrets must be kept because they cannot be regenerated.

## 10. Personnel Security

- Production access requires multi-factor authentication; administrative access is logged and auditable.
- Access rights (dashboard roles and API keys) are reviewed quarterly and revoked on role or scope change.
- Principle of least privilege enforced: scoped roles, purpose-bound API keys, and an administrative system surface separated from customer consoles.
- Personnel security measures beyond access control (background checks, training programs, contractor agreements) are not claimed as implemented measures of the current deployment.

## 11. Data Separation

- Customer data isolated per-account at application layer.
- Each account has a unique identifier; all queries are scoped by account.
- Cross-account data access is not possible through the API.
- Administrative access is logged and auditable.

## 12. Compliance and Certification

| Measure | Status |
|---|---|
| GDPR compliance program | Control-aligned |
| DPA available | Yes |
| Data Protection Officer / Lead | privacy@apexmail.ee |
| Record of processing activities | Maintained |
| DSR process | Documented and operational |
| Subprocessor management | Per DPA requirements |

## 13. Contact

Security inquiries: **{{SECURITY_EMAIL}}**
Privacy inquiries: **{{PRIVACY_EMAIL}}**
