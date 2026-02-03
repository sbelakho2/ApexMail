# ADR 0010: Security Architecture

## Status

Accepted

## Date

2024-01-20

## Context

Email infrastructure is a high-value target for attackers:

1. **Data Sensitivity**: Emails contain business-critical information
2. **Reputation Risk**: Compromised systems can be used for spam/phishing
3. **Compliance**: GDPR, HIPAA, SOC 2 require security controls
4. **Trust**: Customers entrust us with their communications
5. **Attack Surface**: APIs, MTAs, and webhooks are exposed

## Decision

We implement a **Defense in Depth** security architecture:

### Authentication & Authorization

#### API Key Authentication

```typescript
// API keys are scoped with specific permissions
interface ApiKey {
  id: string;
  tenantId: string;
  hashedKey: string;          // Argon2 hash
  keyPrefix: string;          // am_live_ or am_test_
  permissions: Permission[];
  rateLimit: number;
  ipWhitelist?: string[];
  expiresAt?: Date;
  lastUsedAt?: Date;
}

// Permissions follow least privilege principle
type Permission = 
  | 'emails:send'
  | 'emails:read'
  | 'domains:manage'
  | 'webhooks:manage'
  | 'analytics:read';
```

#### JWT for Dashboard Sessions

```typescript
// Short-lived access tokens + refresh rotation
interface SessionTokens {
  accessToken: string;   // 15 min expiry
  refreshToken: string;  // 7 day expiry, single use
}

// Token payload
interface AccessTokenPayload {
  sub: string;           // User ID
  tid: string;           // Tenant ID
  roles: string[];       // User roles
  iat: number;           // Issued at
  exp: number;           // Expiration
}
```

### Encryption

#### Data at Rest

```
┌─────────────────────────────────────────────────────────┐
│                  Encryption Hierarchy                    │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐    │
│  │           Master Key (AWS KMS / Vault)          │    │
│  └────────────────────────┬────────────────────────┘    │
│                           │                              │
│  ┌────────────────────────▼────────────────────────┐    │
│  │              Data Encryption Keys               │    │
│  │     (Per-tenant, rotated every 90 days)         │    │
│  └────────────────────────┬────────────────────────┘    │
│                           │                              │
│  ┌────────────────────────▼────────────────────────┐    │
│  │               Encrypted Data                    │    │
│  │   - Email bodies (AES-256-GCM)                  │    │
│  │   - Attachments (AES-256-GCM)                   │    │
│  │   - Webhook secrets (AES-256-GCM)               │    │
│  │   - API keys (Argon2id)                         │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

```typescript
// Field-level encryption for sensitive data
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

class EncryptionService {
  async encrypt(plaintext: string, tenantId: string): Promise<EncryptedField> {
    const dek = await this.getOrCreateDEK(tenantId);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    
    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      keyVersion: dek.version,
    };
  }
}
```

#### Data in Transit

- TLS 1.3 required for all connections
- Certificate pinning for internal services
- mTLS between microservices

```typescript
// TLS configuration
const tlsConfig = {
  minVersion: 'TLSv1.3',
  cipherSuites: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
  ],
  ecdhCurves: ['X25519', 'P-256'],
};
```

### Input Validation & Sanitization

```typescript
// Strict schema validation with Zod
const sendEmailSchema = z.object({
  from: z.string().email().max(254),
  to: z.array(z.string().email().max(254)).min(1).max(50),
  subject: z.string().min(1).max(998),  // RFC 5322 limit
  html: z.string().max(5_000_000).optional(),  // 5MB limit
  text: z.string().max(5_000_000).optional(),
  attachments: z.array(attachmentSchema).max(10).optional(),
}).refine(
  (data) => data.html || data.text,
  { message: 'Either html or text is required' }
);

// Sanitize HTML to prevent XSS in email clients
import DOMPurify from 'isomorphic-dompurify';

function sanitizeEmailHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'u', 'a', 'img', 'table', 'tr', 'td', 'th', 'div', 'span'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'style', 'class'],
    ALLOW_DATA_ATTR: false,
  });
}
```

### Rate Limiting & Abuse Prevention

```typescript
// Multi-layer rate limiting
const rateLimiters = {
  // Per API key
  apiKey: new RateLimiter({
    windowMs: 60_000,
    max: 1000,
    keyGenerator: (req) => req.apiKey.id,
  }),
  
  // Per IP (for auth endpoints)
  ip: new RateLimiter({
    windowMs: 60_000,
    max: 10,
    keyGenerator: (req) => req.ip,
  }),
  
  // Per recipient domain (anti-spam)
  recipientDomain: new RateLimiter({
    windowMs: 3600_000,
    max: 100,
    keyGenerator: (req, email) => `${req.tenantId}:${getDomain(email.to)}`,
  }),
};

// Abuse detection
const abuseDetector = new AbuseDetector({
  rules: [
    { name: 'spam-pattern', pattern: /viagra|crypto|lottery/i, action: 'flag' },
    { name: 'phishing-link', pattern: /bit\.ly|tinyurl/i, action: 'review' },
    { name: 'high-bounce-rate', threshold: 0.1, action: 'throttle' },
  ],
});
```

### Audit Logging

```typescript
// Comprehensive audit trail
interface AuditEvent {
  id: string;
  timestamp: Date;
  tenantId: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId: string;
  ipAddress: string;
  userAgent: string;
  requestId: string;
  changes?: {
    field: string;
    oldValue: unknown;
    newValue: unknown;
  }[];
  outcome: 'success' | 'failure';
  failureReason?: string;
}

// Audit all sensitive operations
async function auditLog(event: AuditEvent) {
  // Write to immutable audit log
  await auditDB.insert(event);
  
  // Alert on suspicious activity
  if (await isAnomalous(event)) {
    await alertSecurityTeam(event);
  }
}
```

### Secret Management

```typescript
// No secrets in code or environment variables
// Use HashiCorp Vault or AWS Secrets Manager

const secretsClient = new SecretsManager({
  region: process.env.AWS_REGION,
});

async function getSecret(name: string): Promise<string> {
  const cached = secretsCache.get(name);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }
  
  const response = await secretsClient.getSecretValue({ SecretId: name });
  const value = response.SecretString!;
  
  secretsCache.set(name, {
    value,
    expiresAt: Date.now() + 300_000,  // 5 min cache
  });
  
  return value;
}
```

### Security Headers

```typescript
// Strict security headers for web dashboard
const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};
```

### Vulnerability Management

```yaml
# Automated security scanning in CI/CD
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    # Dependency scanning
    - run: pnpm audit --audit-level=high
    
    # SAST
    - uses: github/codeql-action/analyze@v2
    
    # Container scanning
    - uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'apexmail/api:${{ github.sha }}'
        severity: 'HIGH,CRITICAL'
        
    # Secret scanning
    - uses: trufflesecurity/trufflehog@main
```

## Consequences

### Positive

- **Defense in Depth**: Multiple layers prevent single point of failure
- **Compliance Ready**: Controls meet SOC 2, GDPR, HIPAA requirements
- **Auditability**: Complete trail for incident investigation
- **Trust**: Customers can verify security posture

### Negative

- **Complexity**: Security adds development overhead
- **Performance**: Encryption/decryption adds latency
- **Key Management**: Requires operational discipline

### Mitigations

- Provide security libraries and patterns for developers
- Use hardware security modules for key operations
- Regular security training for engineering team
- Engage third-party penetration testing annually

## References

- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [SOC 2 Type II Requirements](https://www.aicpa.org/soc4so)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
