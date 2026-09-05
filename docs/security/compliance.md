# Security & Compliance



Comprehensive security documentation for ApexMail.

## Security Overview

ApexMail implements defense-in-depth security with multiple independent layers including network protection, application security, data encryption, and infrastructure hardening.

---

## Compliance Standards

### GDPR Compliance

ApexMail supports GDPR requirements:

| Requirement | Implementation |
|-------------|----------------|
| **Lawful Basis** | Consent tracking, legitimate interest documentation |
| **Data Minimization** | Configurable data retention, automatic purging |
| **Right to Access** | Data export API, self-service portal |
| **Right to Erasure** | Deletion API, cascading removal |
| **Right to Portability** | JSON/CSV export formats |
| **Data Protection** | Encryption at rest and in transit |
| **Breach Notification** | Audit logging, alerting system |
| **Privacy by Design** | Default privacy settings, consent requirements |

#### Data Subject Rights

##### Right to Access (Article 15)

```http
POST /v1/gdpr/export
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "subjectEmail": "user@example.com",
  "format": "json",
  "includeMetadata": true
}
```

Response:
```json
{
  "requestId": "gdpr_req_abc123",
  "status": "processing",
  "estimatedCompletion": "2026-03-01T12:00:00Z",
  "downloadUrl": null
}
```

##### Right to Erasure (Article 17)

```http
POST /v1/gdpr/delete
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "subjectEmail": "user@example.com",
  "reason": "user_request",
  "retainAuditLogs": true
}
```

#### Consent Management

Every consent event is recorded with:

- **Subject email** — the data subject's email address.
- **Purpose** — the processing purpose (marketing, transactional, or analytics).
- **Granted/revoked** — whether consent was given or withdrawn, and when.
- **Proof** — IP address, user agent, and a link to the consent source (e.g., form URL) for audit purposes.

Consent records are append-only and tamper-evident — revocations create new entries rather than modifying existing ones.

### CAN-SPAM Compliance

| Requirement | Implementation |
|-------------|----------------|
| **Accurate Headers** | From address validation, reply-to enforcement |
| **Honest Subject Lines** | Content review, deception detection |
| **Identify as Ad** | Required disclosure fields |
| **Physical Address** | Mandatory sender address |
| **Opt-Out Mechanism** | One-click unsubscribe, list-unsubscribe header |
| **Honor Opt-Outs** | Real-time suppression list |

### SOC 2 Type II

ApexMail security controls are designed to align with SOC 2 Trust Service Criteria:

| Category | Controls |
|----------|----------|
| **Security** | Access controls, encryption, monitoring, incident response |
| **Availability** | Redundancy, backups, disaster recovery, SLAs |
| **Processing Integrity** | Input validation, error handling, reconciliation |
| **Confidentiality** | Data classification, access restrictions, disposal |
| **Privacy** | Notice, consent, collection limitation, retention |

---

## Authentication & Authorization

### Authentication Methods

ApexMail supports multiple authentication methods:

- **API Keys** — Server-to-server integration
- **OAuth 2.0 + PKCE** — Third-party application integration
- **SAML 2.0** — Enterprise single sign-on

All authentication methods use industry-standard security.

### Role-Based Access Control (RBAC)

| Role | Capabilities |
|------|-------------|
| **Viewer** | Read-only access to messages, campaigns, and analytics |
| **Editor** | Everything in Viewer, plus create/edit messages and templates |
| **Admin** | Full access to all resources and settings |

Roles are hierarchical — each role inherits the permissions of the role below it. Custom roles with fine-grained permissions are available on Enterprise plans.

### Multi-Factor Authentication (MFA)

Supported MFA methods:
- **TOTP** (Google Authenticator, Authy)
- **WebAuthn** (Hardware keys, biometrics)
- **SMS** (Backup only, not recommended)
- **Email** (Backup only)

MFA is enforced for:
- Admin accounts (required)
- API key creation
- Sensitive settings changes
- Data exports

---

## Encryption

### Data at Rest

| Data Type | Encryption | Algorithm |
|-----------|------------|-----------|
| Sensitive fields (PII) | Field-level | AES-256-GCM |
| Storage (full) | Transparent | AES-256 |
| File storage | Server-side | AES-256 |
| Backups | Encrypted | AES-256-GCM |

#### Field-Level Encryption

Sensitive fields (email addresses, names, custom metadata) are individually encrypted using AES-256-GCM. This ensures that even if an attacker gains access to the underlying storage, individual fields remain protected.

- Key rotation happens without downtime.
- Encrypted fields remain searchable through your API and dashboard.

### Data in Transit

- **TLS 1.2+** baseline
- **TLS 1.3** preferred where supported
- **HSTS** enabled

Only forward-secret key exchange with authenticated encryption modes is accepted. Legacy ciphers are disabled.

### Key Management

- Encryption keys are rotated periodically with zero downtime.
- Distinct keys are used for different purposes (data encryption, token signing, backup encryption) to limit blast radius.

---

## Audit Logging

### Logged Events

| Category | Events |
|----------|--------|
| **Authentication** | Login, logout, MFA, password change, session invalidation |
| **Authorization** | Permission denied, role change, API key usage |
| **Data Access** | Read PII, export data, search queries |
| **Data Modification** | Create, update, delete operations |
| **Configuration** | Settings changes, webhook updates, integration changes |
| **Security** | Failed logins, rate limiting, suspicious activity |

### Audit Log Contents

Each audit log entry records:

| Field | Description |
|-------|-------------|
| **Timestamp** | When the event occurred (UTC) |
| **Actor** | Who performed the action (user, API key, or system) |
| **IP address** | Source IP of the request |
| **Action** | What was done (e.g., `campaign.send`, `contact.delete`) |
| **Resource** | The affected resource type and ID |
| **Changes** | Before/after values for modifications |

### Tamper-Evident Chain

Audit log entries are cryptographically chained — each entry includes a hash that depends on the previous entry. This means any modification to a historical record breaks the chain and is immediately detectable. Entries are additionally signed to prevent forgery.

### Audit Log Retention

Security events are retained long-term in tamper-proof storage. Access logs and operational logs have retention periods appropriate to their sensitivity. Retention periods meet or exceed regulatory requirements.

---

## Vulnerability Management

### Security Testing

| Type | Frequency |
|------|-----------|
| Static application security testing (SAST) | Every commit |
| Dynamic application security testing (DAST) | Regularly |
| Dependency vulnerability scanning | Continuously |
| Infrastructure vulnerability scanning | Every build |
| Penetration testing | Regularly (external vendor) |

### Vulnerability Response

Vulnerabilities are triaged by severity and remediated under incident response SLAs. Critical issues receive emergency remediation priority.

### Responsible Disclosure

Report security vulnerabilities to: security@apexmail.ee

We commit to:
- Acknowledging reports within 24 hours
- Providing updates every 7 days
- Crediting reporters (with permission)
- Not pursuing legal action for good-faith reports

---

## Incident Response

### Incident Classification

| Type | Examples | Lead Team |
|------|----------|-----------|
| **Data Breach** | Unauthorized access, exfiltration | Security |
| **Service Outage** | System down, degraded performance | Infrastructure |
| **Account Compromise** | Stolen credentials, unauthorized actions | Security |
| **Malware** | Infected systems, suspicious processes | Security |
| **Physical** | Hardware theft, facility breach | Operations |

### Response Phases

1. **Detection** - Identify and validate incident
2. **Containment** - Limit damage and spread
3. **Eradication** - Remove threat
4. **Recovery** - Restore normal operations
5. **Lessons Learned** - Document and improve

### Breach Notification

GDPR requires notification within 72 hours of discovery.

Notification template:
```markdown
## Data Breach Notification

**Date of Discovery**: [DATE]
**Date of Incident**: [DATE]
**Nature of Breach**: [DESCRIPTION]

### Data Affected
- Categories of data: [LIST]
- Approximate number of records: [NUMBER]
- Categories of data subjects: [LIST]

### Likely Consequences
[DESCRIPTION OF POTENTIAL IMPACT]

### Measures Taken
[ACTIONS TO ADDRESS THE BREACH]

### Recommendations
[STEPS DATA SUBJECTS SHOULD TAKE]

### Contact Information
Data Protection Officer: privacy@apexmail.ee
```

---

## Security Configurations

### Security Headers

ApexMail enforces strict security headers on all responses, including HSTS, content type protection, frame denial, and a restrictive referrer policy.

### Rate Limiting

ApexMail enforces rate limits on all API and authentication endpoints to protect against abuse and brute-force attacks. If you encounter rate limiting, check the `Retry-After` header for when to retry.

Rate-limited responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers.

---

## Security Checklist

### Development

- [ ] Input validation on all endpoints
- [ ] Parameterized queries (no SQL injection)
- [ ] Output encoding (XSS prevention)
- [ ] CSRF tokens for state-changing operations
- [ ] Secure session management
- [ ] No sensitive data in logs
- [ ] No hardcoded secrets

### Deployment

- [ ] TLS certificates valid
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] WAF rules active
- [ ] Secrets in vault
- [ ] Least-privilege access
- [ ] Network segmentation

### Operations

- [ ] Audit logging enabled
- [ ] Monitoring alerts configured
- [ ] Backup encryption verified
- [ ] Incident response plan tested
- [ ] Security training current
- [ ] Vendor assessments complete
- [ ] Penetration test scheduled
