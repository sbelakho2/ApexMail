# ADR 0010: Security Architecture

## Status

Accepted

> **Implementation Note (2026-04):** Security controls are implemented in Rust across the mail-server security crates. The examples below are conceptual reference material; the live implementation uses Rust-native crypto, token, validation, and rate-limiting libraries.

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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### JWT for Dashboard Sessions

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### Data in Transit

- TLS 1.3 required for all connections
- Certificate pinning for internal services
- mTLS between microservices

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Input Validation & Sanitization

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Rate Limiting & Abuse Prevention

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Audit Logging

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Secret Management

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Security Headers

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Vulnerability Management

```yaml
# Automated security scanning in CI/CD
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    # Dependency scanning
    - run: cargo deny check advisories
    
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

### Implemented Security Crate Stack (2026-02)

> **Update:** In addition to the authentication, encryption, input validation, and rate limiting controls described above, the mail server now implements 8 dedicated Rust security crates providing comprehensive defense-in-depth. All 230 unit tests pass. See [Security Systems Reference](../security/Security_Systems.md) for full details.

| Crate | Purpose | Tests |
|-------|---------|-------|
| `ddos-protection` | 5-layer DDoS defense: XDP, TLS fingerprinting, cost-based rate limiting, ML Isolation Forest anomaly detection, SMTP state machine protection, Redis CRDT cross-region coordination | 68 |
| `waf-engine` | AST-based SQL injection detection, HTML/JS XSS analysis, path traversal, command injection, OWASP CRS-compatible anomaly scoring with 4 paranoia levels | 25 |
| `ids-engine` | Suricata-compatible signature matching, SMTP/DNS/TLS protocol analysis, stateful connection tracking for port scan and SYN flood detection | 13 |
| `spam-filter` | Bayesian classification with online learning, SPF/DKIM/DMARC header analysis, Aho-Corasick content scoring, URL reputation (shorteners, suspicious TLDs, IDN homographs) | 23 |
| `sandbox` | File magic detection (PE/ELF/PDF/ZIP/OLE2/HTML), SHA-256 hashing, OLE2 macro detection, double extension attacks, policy engine with 40 dangerous extensions | 25 |
| `ato-protection` | Haversine impossible travel detection, SHA-256 device fingerprinting, failed-attempt lockout, time-of-day behavioral profiling | 21 |
| `dlp-engine` | PII detection (CC with Luhn validation, SSN, phone, email), Shannon entropy secret scanning, confidential keyword policy, domain allowlisting | 27 |
| `threat-intel` | IP/domain blocklist management with CIDR matching, TTL-based expiration, composite reputation scoring, Spamhaus DROP/EDROP feed support | 28 |

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
