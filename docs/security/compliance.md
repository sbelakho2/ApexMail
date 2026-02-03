# Security & Compliance

Comprehensive security documentation for ApexMail.

## Security Overview

ApexMail implements defense-in-depth security with multiple layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Network Layer                             │
│  • TLS 1.2+ encryption • DDoS protection • WAF rules            │
├─────────────────────────────────────────────────────────────────┤
│                      Application Layer                           │
│  • Authentication • Authorization • Input validation            │
├─────────────────────────────────────────────────────────────────┤
│                         Data Layer                               │
│  • Encryption at rest • Field-level encryption • Tokenization   │
├─────────────────────────────────────────────────────────────────┤
│                      Infrastructure Layer                        │
│  • Container isolation • Network segmentation • Secret mgmt     │
└─────────────────────────────────────────────────────────────────┘
```

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
POST /api/v1/gdpr/export
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
  "estimatedCompletion": "2024-01-16T12:00:00Z",
  "downloadUrl": null
}
```

##### Right to Erasure (Article 17)

```http
POST /api/v1/gdpr/delete
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "subjectEmail": "user@example.com",
  "reason": "user_request",
  "retainAuditLogs": true
}
```

#### Consent Management

```typescript
interface ConsentRecord {
  id: string;
  subjectEmail: string;
  purpose: 'marketing' | 'transactional' | 'analytics';
  granted: boolean;
  grantedAt: Date | null;
  revokedAt: Date | null;
  ipAddress: string;
  userAgent: string;
  proofUrl: string;
}
```

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

ApexMail security controls aligned with SOC 2 Trust Service Criteria:

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

| Method | Use Case | Security Level |
|--------|----------|----------------|
| JWT + Refresh Token | User sessions | High |
| API Keys | Server-to-server | Medium-High |
| OAuth 2.0 + PKCE | Third-party apps | High |
| SAML 2.0 | Enterprise SSO | High |

### Role-Based Access Control (RBAC)

```typescript
interface Permission {
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'admin';
  conditions?: Record<string, unknown>;
}

interface Role {
  name: string;
  permissions: Permission[];
  inherits?: string[];
}

// Built-in roles
const roles = {
  viewer: {
    permissions: [
      { resource: 'messages', action: 'read' },
      { resource: 'campaigns', action: 'read' },
      { resource: 'analytics', action: 'read' },
    ],
  },
  editor: {
    inherits: ['viewer'],
    permissions: [
      { resource: 'messages', action: 'create' },
      { resource: 'templates', action: 'create' },
      { resource: 'templates', action: 'update' },
    ],
  },
  admin: {
    inherits: ['editor'],
    permissions: [
      { resource: '*', action: 'admin' },
    ],
  },
};
```

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
| Database fields (PII) | Application-level | AES-256-GCM |
| Database (full) | Transparent | AES-256 (PostgreSQL) |
| File storage | Server-side | AES-256 |
| Backups | Encrypted | AES-256-GCM |

#### Field-Level Encryption

```typescript
// Encrypted fields in database
interface EncryptedContact {
  id: string;
  email: string;                    // Searchable hash
  emailEncrypted: string;           // Full encrypted value
  customFields: string;             // Encrypted JSON
  encryptionKeyId: string;          // Key version
}

// Encryption implementation
class FieldEncryption {
  async encrypt(plaintext: string, context: string): Promise<EncryptedField> {
    const key = await this.keyManager.getCurrentKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key.material, iv);
    cipher.setAAD(Buffer.from(context));
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    
    return {
      ciphertext: Buffer.concat([iv, encrypted, tag]).toString('base64'),
      keyId: key.id,
    };
  }
}
```

### Data in Transit

- **TLS 1.2+** for all connections
- **TLS 1.3** preferred where supported
- **Certificate pinning** for mobile apps
- **HSTS** enabled with preload

TLS Configuration:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_stapling on;
ssl_stapling_verify on;
```

### Key Management

```typescript
interface KeyVersion {
  id: string;
  material: Buffer;
  algorithm: 'aes-256-gcm';
  createdAt: Date;
  expiresAt: Date;
  status: 'active' | 'rotating' | 'retired';
}

class KeyManager {
  private keys: Map<string, KeyVersion> = new Map();
  
  async rotateKey(): Promise<void> {
    const newKey = await this.generateKey();
    const oldKey = await this.getCurrentKey();
    
    // Mark old key as rotating
    oldKey.status = 'rotating';
    
    // Re-encrypt data in background
    await this.reEncryptData(oldKey.id, newKey.id);
    
    // Retire old key
    oldKey.status = 'retired';
  }
}
```

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

### Audit Log Format

```typescript
interface AuditEntry {
  id: string;
  timestamp: Date;
  
  // Actor
  actor: {
    type: 'user' | 'api_key' | 'system' | 'webhook';
    id: string;
    email?: string;
    ip: string;
    userAgent: string;
  };
  
  // Action
  action: string;
  resource: {
    type: string;
    id: string;
  };
  
  // Context
  changes?: {
    before: Record<string, unknown>;
    after: Record<string, unknown>;
  };
  metadata?: Record<string, unknown>;
  
  // Integrity
  previousHash: string;
  hash: string;
  signature: string;
}
```

### Tamper-Evident Chain

```typescript
function createAuditEntry(action: AuditAction, previousEntry: AuditEntry | null): AuditEntry {
  const entry: Partial<AuditEntry> = {
    id: generateId(),
    timestamp: new Date(),
    ...action,
    previousHash: previousEntry?.hash ?? GENESIS_HASH,
  };
  
  // Create hash chain
  entry.hash = crypto
    .createHash('sha256')
    .update(JSON.stringify(entry))
    .digest('hex');
  
  // Sign with HSM
  entry.signature = hsm.sign(entry.hash);
  
  return entry as AuditEntry;
}
```

### Audit Log Retention

| Log Type | Retention | Storage |
|----------|-----------|---------|
| Security events | 7 years | Immutable storage |
| Access logs | 2 years | Compressed archive |
| Debug logs | 30 days | Hot storage |

---

## Vulnerability Management

### Security Testing

| Type | Frequency | Tools |
|------|-----------|-------|
| SAST | Every commit | CodeQL, Semgrep |
| DAST | Weekly | OWASP ZAP |
| Dependency scan | Daily | Snyk, npm audit |
| Container scan | Every build | Trivy |
| Penetration test | Quarterly | External vendor |

### Vulnerability Response

| Severity | Response Time | Action |
|----------|---------------|--------|
| Critical (CVSS 9.0+) | 24 hours | Emergency patch |
| High (CVSS 7.0-8.9) | 7 days | Prioritized fix |
| Medium (CVSS 4.0-6.9) | 30 days | Scheduled fix |
| Low (CVSS < 4.0) | 90 days | Next release |

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
Data Protection Officer: dpo@apexmail.ee
```

---

## Security Configurations

### Content Security Policy

```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://cdn.example.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

### Security Headers

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Rate Limiting

```typescript
const rateLimits = {
  // API endpoints
  'api:general': { window: 60, max: 1000 },
  'api:auth': { window: 60, max: 10 },
  'api:sensitive': { window: 60, max: 5 },
  
  // Per-user limits
  'user:login': { window: 300, max: 5 },
  'user:password-reset': { window: 3600, max: 3 },
  'user:mfa': { window: 300, max: 5 },
  
  // Per-IP limits
  'ip:general': { window: 60, max: 100 },
  'ip:auth': { window: 300, max: 20 },
};
```

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
