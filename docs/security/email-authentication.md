# Advanced Email Authentication


ApexMail implements comprehensive email authentication beyond basic SPF/DKIM/DMARC to maximize deliverability and brand visibility.

> **Delivery transport note:** ApexMail generates a unique 2048-bit RSA key
> pair for each sending domain and publishes its public key directly as a TXT
> record. In SES mode, SES uses the same key through BYODKIM and requires the
> `bounce.<domain>` custom MAIL FROM SPF/MX records. In SMTP mode, the worker
> signs locally using the same protected per-domain key. Neither mode uses SES
> Easy-DKIM CNAME records or a global customer DKIM key.

## Overview

Modern email authentication requires multiple layers:

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Basic Authentication                          │
│  • SPF (Sender Policy Framework)                                │
│  • DKIM (DomainKeys Identified Mail)                            │
│  • DMARC (Domain-based Message Authentication)                  │
├─────────────────────────────────────────────────────────────────┤
│                   Advanced Authentication                        │
│  • ARC (Authenticated Received Chain) - RFC 8617                │
│  • MTA-STS (Strict Transport Security) - RFC 8461               │
│  • TLSRPT (TLS Reporting) - RFC 8460                           │
├─────────────────────────────────────────────────────────────────┤
│                    Brand Visibility                              │
│  • BIMI (Brand Indicators for Message Identification)           │
│  • VMC (Verified Mark Certificate)                              │
└─────────────────────────────────────────────────────────────────┘
```

## ARC (Authenticated Received Chain)

**RFC 8617** - Preserves authentication results across email forwarding.

### Why ARC Matters

When emails are forwarded through mailing lists or intermediaries, SPF and DKIM often break:

- SPF fails because the forwarding server's IP isn't in the original SPF record
- DKIM may fail if headers are modified during forwarding

ARC solves this by creating a chain of custody that receiving servers can verify.

### ARC Headers

ApexMail generates three ARC headers for each forwarded message:

```text
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=apexmail.ee; s=arc;
          t=1706000000; b=<signature>

ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
                       d=apexmail.ee; s=arc; h=from:to:subject:date;
                       bh=<body-hash>; b=<signature>

ARC-Authentication-Results: i=1; apexmail.ee; spf=pass; dkim=pass; dmarc=pass
```

### Usage

ARC headers are generated automatically by ApexMail when forwarding messages. You can check ARC validation results via the API:

```http
GET /v1/messages/:id/authentication
X-API-Key: YOUR_API_KEY
```

```json
{
  "arc": {
    "status": "pass",
    "chain": [
      { "instance": 1, "domain": "apexmail.ee", "result": "pass" }
    ]
  }
}
```

---

## MTA-STS (Mail Transfer Agent Strict Transport Security)

**RFC 8461** - Ensures TLS encryption is **enforced** (not opportunistic).

### Why MTA-STS Matters

Standard SMTP STARTTLS is opportunistic - it can be stripped by man-in-the-middle attacks. MTA-STS tells sending servers:

- TLS is **required** to deliver email
- Which MX servers are legitimate
- How long to cache this policy

Gmail prioritizes domains with MTA-STS for deliverability.

### Implementation

MTA-STS requires two components:

#### 1. DNS TXT Record

```dns
_mta-sts.yourdomain.com. IN TXT "v=STSv1; id=20240204001"
```

#### 2. Policy File

Host at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`:

```text
version: STSv1
mode: enforce
mx: mail.yourdomain.com
mx: *.apexmail.ee
max_age: 604800
```

### API Endpoints

```http
# Check MTA-STS configuration
GET /v1/domains/:id/mta-sts

# Response
{
  "domain": "yourdomain.com",
  "mtaSts": {
    "supported": true,
    "mode": "enforce",
    "policy": { ... },
    "errors": [],
    "warnings": [],
    "recommendations": []
  }
}
```

### Modes

| Mode | Description | Recommended For |
| ---- | ----------- | --------------- |
| `none` | Disabled | Initial setup |
| `testing` | Log-only, don't reject | First deployment |
| `enforce` | Reject non-TLS connections | Production |

---

## TLSRPT (TLS Reporting)

**RFC 8460** - Receives reports about TLS connection issues.

### DNS Record

```dns
_smtp._tls.yourdomain.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com"
```

### API Endpoint

```http
GET /v1/domains/:id/tlsrpt
```

---

## BIMI (Brand Indicators for Message Identification)

Display your brand logo in recipients' email clients (Gmail, Yahoo, Apple Mail).

### Requirements

1. **DMARC at Enforcement**: `p=quarantine` or `p=reject`
2. **SVG Tiny PS Logo**: Max 32KB, square, no scripts/animations
3. **Optional VMC**: Verified Mark Certificate for trademarked logos

### DNS Record

```dns
default._bimi.yourdomain.com. IN TXT "v=BIMI1; l=https://assets.yourdomain.com/logo.svg; a=https://assets.yourdomain.com/vmc.pem"
```

### Logo Requirements

| Requirement | Value |
| ----------- | ----- |
| Format | SVG Tiny Portable/Secure |
| Max Size | 32KB |
| Aspect Ratio | 1:1 (square) |
| Scripts | Not allowed |
| Animations | Not allowed |
| External References | Not allowed |
| Title Element | Required for accessibility |

### API Endpoints

```http
# Check BIMI configuration
GET /v1/domains/:id/bimi

# Validate BIMI logo
POST /v1/domains/:id/bimi/validate-logo
Content-Type: application/json

{
  "logoUrl": "https://assets.yourdomain.com/logo.svg"
}

# Response
{
  "valid": true,
  "errors": [],
  "warnings": ["Logo should include a <title> element for accessibility"],
  "requirements": [
    "Format: SVG Tiny Portable/Secure (baseProfile=\"tiny-ps\")",
    "Size: Maximum 32KB",
    "Aspect ratio: Must be square (1:1)",
    "No scripts, animations, or external references"
  ]
}
```

### Mailbox Provider Support

| Provider | BIMI Support | VMC Required |
| -------- | ------------ | ------------ |
| Gmail | ✅ Yes | ✅ Yes (for blue checkmark) |
| Yahoo | ✅ Yes | Optional |
| Apple Mail | ✅ Yes | Optional |
| Fastmail | ✅ Yes | Optional |
| Outlook | Varies by rollout | Varies by rollout |

---

## Comprehensive Authentication Score

Get an overall authentication score (0-100) for any domain:

```http
GET /v1/domains/:id/auth-status

# Response
{
  "domain": "yourdomain.com",
  "score": 87,
  "grade": "A-",
  "breakdown": {
    "basic": { "status": "pass", "points": 60, "maxPoints": 60 },
    "mtaSts": { "status": "warning", "points": 15, "maxPoints": 20 },
    "bimi": { "status": "pass", "points": 10, "maxPoints": 15 },
    "tlsrpt": { "status": "fail", "points": 0, "maxPoints": 5 }
  },
  "checks": {
    "spfDkimDmarc": { "status": "healthy", "issues": [] },
    "mtaSts": { "supported": true, "mode": "testing" },
    "bimi": { "supported": true, "logoValid": true, "certificateValid": false },
    "tlsrpt": { "supported": false }
  },
  "recommendations": [
    "MTA-STS is in testing mode. Change to 'enforce' for full protection.",
    "Consider obtaining a Verified Mark Certificate (VMC) for broader BIMI support"
  ]
}
```

### Scoring Breakdown

| Component | Max Points | Description |
| --------- | ---------- | ----------- |
| SPF/DKIM/DMARC | 60 | Basic authentication |
| MTA-STS | 20 | TLS enforcement |
| BIMI | 15 | Brand indicators |
| TLSRPT | 5 | TLS reporting |

### Grade Scale

| Score | Grade |
| ----- | ----- |
| 95-100 | A+ |
| 90-94 | A |
| 85-89 | A- |
| 80-84 | B+ |
| 75-79 | B |
| 70-74 | B- |
| 60-69 | C |
| 50-59 | D |
| <50 | F |

---

## Implementation Checklist

### Basic (Required)

- [ ] SPF record published
- [ ] DKIM signing enabled
- [ ] DMARC record with monitoring (`p=none`)
- [ ] Upgrade DMARC to enforcement (`p=quarantine` or `p=reject`)

### Advanced (Recommended)

- [ ] MTA-STS policy file hosted
- [ ] MTA-STS DNS record published
- [ ] TLSRPT record for TLS feedback
- [ ] MTA-STS mode set to `enforce`

### Brand Visibility (Optional)

- [ ] SVG Tiny PS logo created
- [ ] Logo hosted on HTTPS
- [ ] BIMI DNS record published
- [ ] VMC certificate obtained (for Gmail blue checkmark)

---

## Related Documentation

- [Domain Management API](../api/endpoints/domains.md)
- [Security & Compliance](../security/compliance.md)

## External Resources

- [RFC 8617 - ARC](https://tools.ietf.org/html/rfc8617)
- [RFC 8461 - MTA-STS](https://tools.ietf.org/html/rfc8461)
- [RFC 8460 - TLSRPT](https://tools.ietf.org/html/rfc8460)
- [BIMI Implementation Guide](https://bimigroup.org/implementation-guide/)
- [Google Postmaster Tools](https://postmaster.google.com/)
