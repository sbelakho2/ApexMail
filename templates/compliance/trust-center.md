# ApexMail Trust Center

**Operated by {{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia.

The ApexMail Trust Center provides inspectable evidence of our security and compliance posture. This page is public and continuously updated.

## Security Overview

ApexMail provides EU-hosted transactional email infrastructure with security designed for regulated industries.

### Encryption in Transit

- **Supported TLS versions**: TLS 1.3 for all external connections; TLS 1.2 is the minimum accepted version with cipher restrictions rejecting weak ciphers (RC4, 3DES, export-grade).
- **HTTPS enforcement**: All HTTP requests are redirected (301) to HTTPS. HSTS is set with `max-age=31536000; includeSubDomains; preload`.
- **SMTP TLS**: TLS is mandatory on port 587 (STARTTLS required). SMTP on port 25 is opportunistic STARTTLS; plaintext SMTP without STARTTLS is rejected on port 587.
- **Internal service traffic**: All inter-service communication within the production network uses TLS 1.3 (mutual TLS where service identity verification is required). gRPC and internal HTTP calls are encrypted.
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

- **Code review**: All changes require at least one approving review from a team member who is not the author. Protected branches (main, production) require passing CI checks before merge. Security-sensitive changes require an additional review from a security-designated reviewer.
- **Branch protection**: The `main` and `production` branches are protected. Direct pushes are disabled. Linear history is enforced. Status checks (lint, test, build, SAST, secret scan) must pass before merge.
- **Dependency scanning**: Dependabot and cargo-audit run daily against all dependencies. Critical and high-severity vulnerabilities trigger an alert and block deployment. Dependency update PRs are auto-created with changelog references.
- **Static analysis**: SAST via Semgrep and Clippy (Rust) runs on every PR. Rules cover OWASP Top 10, injection, hardcoded secrets, and unsafe patterns. SAST failures block the CI pipeline.
- **Secret scanning**: Gitleaks runs on every commit and PR. Repository secret scanning (GitHub secret scanning) is enabled. Pre-commit hooks block accidental secret commits. Detected secrets trigger automatic key revocation.
- **Deployment approval**: Production deployments require explicit approval from a designated release manager. Canary deployments proceed automatically to 5% of traffic, then pause for manual approval before full rollout. Rollback is one-click and automated for canary health-check failures.
- **Environment separation**: Development, staging, and production environments are fully isolated (separate clusters, separate databases, separate credentials). No production data is used in staging. Staging uses synthetic data and test domains only. Access credentials differ across environments.

### Infrastructure Security

- **Network boundaries**: Production network is segmented into public-facing (API, SMTP, dashboard), internal (message queue, workers, database), and management (monitoring, logging, CI/CD) subnets. Traffic between subnets is controlled by firewall rules.
- **Firewalling**: Host-based firewalls (iptables/nftables) allow only required ports. Network-level firewall restricts inbound traffic to ports 80, 443, and 587. All other ports are blocked from public internet. Outbound traffic is restricted to required services only.
- **Private networking**: Internal service communication occurs over private network interfaces (not public IPs). Database instances are not exposed to the public internet. Internal DNS resolves only within the private network.
- **Administrative access**: SSH access is restricted to bastion hosts with IP allowlisting. No direct SSH from the internet to any production host. Session recording is enabled on bastion hosts.
- **Host hardening**: Minimal base images (distroless or Alpine where possible). Unused packages and services are removed. SSH is configured with key-only authentication, no root login, and a limited user set. Kernel hardening: ASLR, DEP/NX, seccomp profiles, read-only filesystems where applicable.
- **Patch management**: Operating system packages are patched within 7 days of release for non-critical updates and within 24 hours for critical security patches. Patch status is monitored via automated scanning. Container images are rebuilt and redeployed weekly.
- **Container isolation**: Application services run in isolated containers (Docker). Containers run as non-root users with dropped capabilities. Read-only root filesystems are used where practical. Resource limits (CPU, memory) are enforced per container. Container runtime security is monitored.

### Monitoring

- **Application monitoring**: Prometheus metrics for all services, including request rates, error rates, latency percentiles, queue depth, and connection counts. Custom application metrics for business operations (messages processed, delivery attempts, bounce rates).
- **Infrastructure monitoring**: Host-level metrics (CPU, memory, disk, network) collected via node_exporter. Database metrics (connections, query performance, replication lag) via postgres_exporter. Probe-based external monitoring from multiple geographic locations via blackbox_exporter.
- **Security alerting**: Alerts for: failed authentication spikes, new admin user creation, API key creation, permission changes, WAF rule triggers, IDS/IPS alerts, DDoS detection events, certificate expiry, and secret-scanning hits. All security alerts page the on-call engineer.
- **Log retention**: Application and access logs retained for 90 days (730 days for Enterprise). Security audit logs retained for 365 days minimum. Logs are immutable once written. Log archives are encrypted at rest.
- **On-call process**: 24/7/365 on-call rotation with primary and secondary responders. Alerts are routed via Alertmanager to PagerDuty. On-call handoff occurs at 09:00 UTC daily with documented status transfer.
- **Incident escalation**: Escalation from primary to secondary on-call after 15 minutes without acknowledgment. Escalation to SRE lead after 30 minutes. Escalation to CTO after 1 hour. See [Incident Response Policy](incident-response.md).

### Backups and Recovery

- **Backup frequency**: Full database backups daily at 02:00 UTC. Continuous WAL archiving for point-in-time recovery. Configuration backups on every change via infrastructure-as-code repository commits.
- **Backup retention**: Daily backups retained for 30 days. Weekly backups retained for 90 days. Monthly backups retained for 12 months. WAL archives retained for 7 days.
- **Restore testing**: Full database restore tested monthly in an isolated environment. Backup integrity verified automatically after each backup completes (checksum validation). Restore test results are logged and reviewed.
- **Recovery Point Objective (RPO)**: 24 hours for full database restore from daily backups. Point-in-time recovery available within the 7-day WAL archive window (near-real-time).
- **Recovery Time Objective (RTO)**: 4 hours for critical services (API, SMTP, queue). 8 hours for non-critical services (dashboard, analytics). Cross-region failover available for Enterprise within 2 hours.
- **Geographic separation**: Primary and backup data stores are in separate physical data center halls within the same region (Helsinki, Finland). Off-site backup copies are stored in a separate region. Cross-region disaster recovery is available for Enterprise plans.

### Data Deletion

- **Account-deletion process**: Account owners can request full account deletion via the dashboard or support. Deletion is irreversible. All customer data (messages, templates, domains, API keys, events, logs) is permanently deleted within 30 days of request. A 7-day grace period allows cancellation of deletion requests.
- **Message-data deletion**: Message content and metadata are permanently deleted within 30 days of account deletion or per the configured retention period (whichever is shorter). SMTP logs and delivery receipts are deleted on the same schedule.
- **Backup expiry**: Backups containing deleted customer data are expired as part of the normal retention rotation (30-day daily, 90-day weekly, 12-month monthly). No backup is retained beyond 12 months for deleted account data.
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

- **Backup frequency**: Daily automated backups with 30-day retention.
- **Recovery Time Objective (RTO)**: 4 hours for critical services.
- **Recovery Point Objective (RPO)**: 24 hours for transactional data; real-time replication for critical state.
- **Failover**: Multi-AZ deployment in primary region; cross-region failover capability for Enterprise.
- **Testing**: Disaster recovery tested annually (Enterprise: semi-annually).

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
