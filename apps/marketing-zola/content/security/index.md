+++
title = "Security Overview"
description = "ApexMail security controls: encryption, authentication, network defense, incident response, vulnerability management, and compliance evidence."
template = "prose.html"

[extra]
last_updated = "2026-10-02"
+++

## Encryption

### Data in Transit

- TLS 1.2+ required for all API and SMTP connections.
- TLS 1.3 preferred where supported by the receiving MTA.
- Private, non-public networking for inter-service communication (isolated deployment networks; no service-to-service traffic crosses the public internet).

[roadmap] MTA-STS policy publication (`mode: enforce`) and DANE (TLSA record) validation of recipient MX servers are planned capabilities; they are not enforced on the managed cloud's mail paths today.

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

### Request Screening (Web Application Firewall)

[roadmap] A request-screening firewall (WAF) built on SQLi/XSS/traversal/command-injection/SSRF rules evaluates the method, path, query string and headers of public API requests in monitor mode today: verdicts are logged, not blocked. Enabling blocking enforcement by default and extending inspection to request bodies are on the roadmap; the managed cloud's default posture does not include WAF blocking. Intrusion detection/prevention (IDS/IPS) exists as a library that inspects zero live traffic and is likewise not an active control.

- Input validation and sanitization on all API endpoints (handler-level validation).
- Rate limiting per endpoint and API key.

### DDoS and Abuse Protection

Application-layer defenses wired into the public API request path:

1. Cost-based request rate limiting with per-tenant budgets.
2. Adaptive per-IP thresholds (statistical z-score anomaly detection over request patterns).
3. Request fingerprinting (JA4/TLS and HTTP/2 fingerprints) feeding reputation decisions.
4. Load-shedding middleware that runs ahead of authentication and rate-limit work.

### API Authentication

- All API endpoints require `X-API-Key` header with scoped API key.
- Webhook signatures verified via HMAC-SHA256.
- OAuth 2.0 for third-party integrations (Google, GitHub sign-in).
- Session-based authentication with secure, HTTP-only cookies for dashboard access.

## System Integrity Verification

System integrity is verified through automated, recurring checks across the deployment and runtime stack:

| Control | What Is Verified | Frequency | Evidence |
|---|---|---|---|
| **Deployment artifact integrity** | Container images are digest-verified, not signed: each pipeline run records a release manifest (per-image SHA-256 digests, `SHA256SUMS.images`) and renders a digest-pinned compose override; deployment refuses to bring up any image whose digest does not match that manifest. | Every deployment | Release manifest + pre-deploy digest verification in the deploy stage |
| **Audit-log integrity** | Audit-log tables carry a hash chain: each row's SHA-256 digest is chained to its predecessor. | Continuous (per write) | Audit-log hash chain |
| **Deployment records** | Every pipeline run records a manifest (stage, status, exit code, duration) plus per-stage logs. These are internal operational records with no tamper-proofing guarantee and no customer-facing query surface. | Every deployment | CI run manifests (`ci/runs/<ts>/manifest.json`) |
| **Backup verification** | Every backup is automatically decrypted and structurally validated (`pg_restore --list`) before the plaintext is deleted — a backup that cannot be read is never counted as good. Full restore drills are manual at the documented quarterly cadence. | Every backup (automated validation); quarterly (manual drills) | Backup-time restorability validation; DR drill records |
| **Runtime resilience** | Services run health-checked with automatic restart; a failed post-deploy content probe triggers automatic rollback to the previous image pins. | Continuous | Container healthchecks; deploy-stage verify + rollback |

All verification results are internal operational controls. Current security-review material may be made available to qualified Enterprise prospects or customers upon request; it is not an external certification or a product entitlement.

The term "System Integrity Controls" refers to the combination of these controls. It does not imply external third-party certification or attestation. Any badge or label using this phrase must reference this section.

## Infrastructure Security

- Hetzner Online GmbH for compute, storage, and networking in the configured deployment region (a single host runs the full stack; there is no multi-region topology).
- CIS-hardened Debian/Ubuntu operating systems.
- Automated security patching with staged rollout.
- Declarative, version-controlled deployment: the entire stack is defined in Docker Compose files and deployed by the self-hosted CI pipeline.
- Docker network segmentation between frontend, backend, and database networks on the deployment host.
- Host firewall: inbound access limited to the mail/web service ports (25, 80, 443, 587, 993) plus operator ports; databases have no host port exposure.
- Secrets management via Docker secrets mounted from permission-restricted files (0600); no secrets baked into images or source.

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

- Penetration test summary: planned for publication after the first external application penetration test is completed and high/critical findings are remediated. Not currently available.
- Security-questionnaire requests are assessed case by case using current review material; no standardized SIG, CAIQ, or HECVAT pack is a product entitlement.
- ApexMail records API, configuration and admin actions in an operator audit trail; event retention follows the subscribed plan.
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
