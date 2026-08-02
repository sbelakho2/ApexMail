# Technical and Organizational Measures (TOMs)

This document describes the technical and organizational measures implemented by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia, to protect personal data processed through the ApexMail platform.

This document serves as Annex 1 to the [Data Processing Agreement (DPA)](../legal/dpa.md).

## 1. Access Control

### 1.1 Physical Access Control

- All production infrastructure hosted in ISO 27001 certified data centers (Hetzner).
- Physical access to data centers is restricted to authorized data center personnel.
- ApexMail personnel do not have physical access to data center facilities.
- Multi-factor authentication, biometric access controls, and video surveillance at data center facilities (provided by infrastructure provider).

### 1.2 Logical Access Control

- Role-based access control (RBAC) for all platform services.
- API keys and SMTP credentials are scoped to minimum required permissions.
- Session-based authentication with automatic timeout after inactivity.
- TOTP-based two-factor authentication (2FA) supported.
- SSO/SAML integration (Enterprise plans).
- IP allowlists (Enterprise plans).
- Audit logging of all authentication events and administrative actions.

### 1.3 Data Access Control

- Customer data is logically separated at the application layer (tenant isolation).
- Dedicated tenant customers have physically/logically isolated infrastructure.
- Database access restricted to authorized service accounts only.
- No direct production database access by developers without break-glass procedure.

## 2. Encryption

### 2.1 Encryption at Rest

- AES-256 encryption for data at rest (block storage, object storage, database storage).
- Encryption keys managed by the infrastructure provider.
- Backup data encrypted at rest.

### 2.2 Encryption in Transit

- TLS 1.3 for all external connections (TLS 1.2 minimum).
- Cipher restrictions: only strong, modern cipher suites accepted.
- HSTS with preload and `includeSubDomains`.
- Secure cookie attributes: `Secure`, `HttpOnly`, `SameSite=Lax`.
- SMTP connections require STARTTLS (port 587) — plaintext rejected.

## 3. Network Security

- Production network segmented from development and corporate networks.
- Firewall rules restrict inbound/outbound traffic to required services only.
- DDoS protection at network edge (5-layer defense):
  - Layer 3/4: Rate limiting, SYN flood protection.
  - Layer 7: Request signature analysis, challenge-response.
  - ML-based anomaly detection.
  - SMTP state machine protection.
  - Adaptive throttling.
- Intrusion Detection and Prevention System (IDS/IPS):
  - Signature-based detection.
  - Protocol anomaly detection.
  - Connection tracking and rate limiting.
- Network traffic monitoring and alerting.

## 4. Application Security

- Web Application Firewall (WAF):
  - AST-based SQL injection detection.
  - AST-based cross-site scripting (XSS) detection.
  - OWASP Core Rule Set (CRS) compatible.
- Input validation and output encoding.
- Parameterized database queries (no SQL injection).
- Cross-Site Request Forgery (CSRF) tokens on all state-changing requests.
- Content Security Policy (CSP) headers.
- CORS policy restricted to authorized origins.
- Secure password hashing (Argon2id).

## 5. Email Security

### 5.1 Sending

- SPF, DKIM, and DMARC enforced for all outgoing email.
- MTA-STS policy published for TLS enforcement.
- DANE/TLSA support for DANE verification.
- Spam and phishing filtering (outbound):
  - Bayesian content analysis.
  - Header analysis.
  - URL reputation checking.
  - Attachment sandboxing.

### 5.2 Inbound

- Attachment sandbox:
  - File type detection via magic bytes (not extension).
  - SHA-256 hash checking against known malware.
  - OLE2/macro detection.
  - Executable and risky file type blocking.
- Spam and phishing filtering for inbound email.

## 6. Account Security

- Account Takeover (ATO) Protection:
  - Impossible travel detection (Haversine distance).
  - Device fingerprinting.
  - Login anomaly detection with KiwiCaptcha integration.
- Brute-force protection: rate limiting on authentication endpoints.
- API key rotation supported without downtime.
- Automatic suspension after repeated failed authentication attempts.

## 7. Data Security

- Data Loss Prevention (DLP):
  - PII pattern detection (Luhn algorithm for credit card numbers).
  - Shannon entropy scoring for sensitive data detection.
  - Content policy enforcement.
- Threat Intelligence:
  - IP and domain blocklist integration.
  - CIDR range blocking.
  - Reputation scoring.
- Data classification and labeling.

## 8. Operational Security

### 8.1 Monitoring and Logging

- Structured logging for all services with correlation IDs.
- Prometheus metrics collection with Grafana dashboards.
- Alertmanager alerts for security events, errors, and threshold violations.
- Logs retained for 90 days (730 days for Enterprise).
- Logs include: authentication events, API calls, administrative actions, security events, error conditions.
- Logs do not contain: plaintext passwords, full API keys, full payment card numbers.

### 8.2 Vulnerability Management

- Dependency scanning in CI/CD pipeline.
- Secret scanning in CI/CD pipeline (gitleaks and repository scanning).
- Static Application Security Testing (SAST) in CI/CD.
- Dynamic Application Security Testing (DAST) for public-facing endpoints.
- Container image scanning.
- Infrastructure-as-Code (IaC) scanning.
- Regular OS and dependency patching.
- Vulnerability disclosure program with safe harbor.

### 8.3 Change Management

- Protected branches with mandatory code review.
- Pull request approval required before merge.
- Automated testing in CI/CD pipeline.
- Staged deployments (canary, rolling update).
- Rollback capability for all deployments.

## 9. Business Continuity and Disaster Recovery

- Daily automated backups with 30-day retention.
- Multi-zone deployment within primary region.
- Recovery Time Objective (RTO): 4 hours.
- Recovery Point Objective (RPO): 24 hours.
- Disaster recovery tested annually.
- Incident response team with defined escalation paths.

## 10. Personnel Security

- Background checks for personnel with access to production systems.
- Confidentiality agreements for all personnel and contractors.
- Security awareness training.
- Access rights reviewed on role change or departure.
- Principle of least privilege enforced.

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
