+++
title = "Security Overview"
description = "ApexMail security controls: encryption, authentication, network defense, incident response, vulnerability management, and compliance evidence."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Encryption

### Data in Transit

- TLS 1.2+ required for all API and SMTP connections.
- TLS 1.3 preferred where supported by the receiving MTA.
- MTA-STS policy with `mode: enforce` for inbound SMTP.
- DANE (TLSA record) validation for supported recipient domains on outbound SMTP delivery.
- WireGuard or private networking for inter-service communication.

### Data at Rest

- AES-256-GCM encryption for message content and attachments.
- Argon2id for password hashing (memory-hard, resistant to GPU/ASIC attacks).
- Encrypted database volumes (LUKS/dm-crypt).
- Encrypted backups with separate key management.
- Customer-managed encryption-key requirements may be evaluated only in a separately contracted deployment; they are not a public plan entitlement.

## Authentication and Access Control

- API keys scoped per environment (live/test) with configurable permissions.
- Webhook HMAC signatures (SHA-256) for event payload integrity.
- SAML SSO on Business and Enterprise plans; any provisioning commitment is confirmed in the applicable contract.
- Role-based access control (RBAC) with custom roles on Enterprise plan.
- Multi-factor authentication (TOTP) for dashboard access.
- Session management with configurable timeout and IP binding.

## Application Security

### Web Application Firewall (WAF)

- SQL injection detection (AST-based).
- XSS detection (AST-based).
- OWASP CRS-compatible rules.
- Input validation and sanitization on all API endpoints.
- Rate limiting per endpoint and API key.

### Intrusion Detection and Prevention (IDS/IPS)

- Signature-based detection.
- Protocol anomaly detection.
- Connection tracking and alerting.

### DDoS Protection (5-layer defense)

1. Layer 3/4: Rate limiting, SYN flood protection
2. Layer 7: Request signature analysis, challenge-response
3. ML-based anomaly detection
4. SMTP state machine protection
5. Adaptive throttling

### API Authentication

- All API endpoints require `X-API-Key` header with scoped API key.
- Webhook signatures verified via HMAC-SHA256.
- OAuth 2.0 for third-party integrations (Google, GitHub sign-in).
- Session-based authentication with secure, HTTP-only cookies for dashboard access.

## System Integrity Verification

System integrity is verified through automated, recurring checks across the deployment and runtime stack:

| Control | What Is Verified | Frequency | Evidence |
|---|---|---|---|
| **Signed deployment artifacts** | All application binaries and container images are cryptographically signed at build time. Deployments validate signatures before rollout. | Every build | Build attestation logs (immutable, append-only) |
| **Database-integrity checks** | PostgreSQL checksum validation on all data pages; hash-chain integrity on audit-log tables via chained SHA-256 digests. | Continuous (checksum on read); nightly full scan | Alert on corruption; audit-log chain verification endpoint |
| **Immutable deployment logs** | Every deployment event (who, what, when, git commit, artifact hash) is recorded in an append-only log. | Every deployment | Deployment history endpoint; tamper-evident log |
| **File-integrity monitoring** | System binaries, configuration files, and TLS certificates are monitored for unauthorized modification. | Continuous (inotify-based) | Alert on modification outside approved change windows |
| **Verified backup restores** | Automated restore tests validate backup integrity and recoverability. | Weekly | Restore success/failure log; sample data comparison |
| **Runtime integrity** | Application processes are monitored for unexpected binary changes or configuration drift vs. the declared infrastructure-as-code state. | Continuous | Drift detection alert; reconciliation report |

All verification results are internal operational controls. Current security-review material may be made available to qualified Enterprise prospects or customers upon request; it is not an external certification or a product entitlement.

The term "System Integrity Controls" refers to the combination of these controls. It does not imply external third-party certification or attestation. Any badge or label using this phrase must reference this section.

## Infrastructure Security

- Hetzner Online GmbH for compute, storage, and networking in the configured deployment region.
- CIS-hardened Debian/Ubuntu operating systems.
- Automated security patching with staged rollout.
- Immutable infrastructure through infrastructure-as-code.
- Network segmentation between application, data, and management planes.
- Network isolation: application servers, database servers, and management interfaces on separate VLANs.
- Secrets management via sealed secrets and environment isolation.

## Vulnerability Management

- Automated dependency scanning in CI/CD pipeline.
- Automated infrastructure vulnerability scanning (weekly cadence).
- Annual third-party penetration test (first external test planned — currently in procurement; results will be published after completion and remediation).
- Responsible disclosure program: [security@apexmail.ee](mailto:security@apexmail.ee)
- Vulnerability remediation targets by severity:
  - **Critical:** Immediate containment; target permanent remediation within 7 days.
  - **High:** Target within 30 days.
  - **Medium:** Target within 90 days.
  - **Low:** Risk-based — addressed in regular maintenance cycles.
  - **Actively exploited:** Emergency process regardless of severity.

## Incident Response

- Documented incident response plan with semi-annual tabletop exercises and annual full simulation.
- Security incident severity classification: Critical (SEV-1), High (SEV-2), Medium (SEV-3), Low (SEV-4).
- Status page updated within 15 minutes of confirmed SEV-1/SEV-2 incident. Customer notification via email within 1 hour for critical incidents.
- Post-incident summary within 1 business day for all incidents. Postmortem timing:
  - Initial incident report: within 5 business days for major incidents.
  - Final root-cause analysis: published when validation completes.
- Breach notification to customers without undue delay after becoming aware of a personal data breach. Supervisory authority notification as required under GDPR Article 33 (within 72 hours where applicable).

## Audit and Compliance Evidence

- ApexMail is not currently SOC 2 certified. Internal control mapping and readiness work do not create a certification, product entitlement, or certification-date commitment.
- Penetration test summary: planned for publication after the first external application penetration test is completed and high/critical findings are remediated. Not currently available.
- Security-questionnaire requests are assessed case by case using current review material; no standardized SIG, CAIQ, or HECVAT pack is a product entitlement.
- Audit logs are available on Growth, Scale, and Enterprise, with retention determined by the subscribed plan.
- Customer audit facilitation subject to Enterprise contract review.

## Operational Security

- Background checks for personnel with production access.
- Access reviews conducted quarterly.
- Production access requires multi-factor authentication and approval.
- Change management with peer review and rollback capability.
- Segregation of duties between development and operations.

## Related

- [Compliance Center](/compliance)
- [Architecture Overview](/architecture)
- [Privacy Policy](/privacy)
- [Data Processing Agreement](/dpa)
- [Acceptable Use Policy](/acceptable-use)
- [Responsible Disclosure](/responsible-disclosure)
