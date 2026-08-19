# Domains API

Manage sending domains, DNS verification, and advanced email authentication.

## Endpoints

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| POST | `/v1/domains` | Add a new domain |
| GET | `/v1/domains` | List all domains |
| GET | `/v1/domains/:id` | Get domain details |
| POST | `/v1/domains/:id/verify` | Verify domain DNS |
| DELETE | `/v1/domains/:id` | Delete a domain |
| GET | `/v1/domains/:id/dns-records` | Get DNS setup instructions |
| GET | `/v1/domains/:id/auth-status` | Comprehensive auth score |

---

## Add Domain

```http
POST /v1/domains
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "name": "example.com"
}
```

### Request Body

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `name` | string | Yes | Domain name (e.g., `example.com`) |

### Response

```json
{
  "id": "018f0b28-b99a-7b41-84ac-66ebc643e3d1",
  "name": "example.com",
  "status": "pending",
  "ses_verified": false,
  "spf_verified": false,
  "dkim_verified": false,
  "dmarc_verified": false,
  "return_path_verified": false,
  "created_at": "2026-05-16T10:00:00Z"
}
```

Creation generates an encrypted 2048-bit RSA private key and a unique DKIM
selector. The private key is never returned. Retrieve the DNS values before
publishing records:

```http
GET /v1/domains/:id/dns-records
X-API-Key: {{api_key}}
```

The response contains four records: a `bounce.<domain>` SPF TXT record, a
direct `<selector>._domainkey.<domain>` DKIM TXT record, a region-specific
`bounce.<domain>` MX record with priority `10`, and a DMARC TXT record. Do not
replace them with SES Easy-DKIM CNAME records or ApexMail-owned DNS targets.

---

## Get Domain

```http
GET /v1/domains/:id
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "018f0b28-b99a-7b41-84ac-66ebc643e3d1",
  "name": "example.com",
  "status": "verified",
  "ses_verified": true,
  "spf_verified": true,
  "dkim_verified": true,
  "dmarc_verified": true,
  "return_path_verified": true,
  "created_at": "2026-05-16T10:00:00Z"
}
```

---

## Verify Domain

Trigger DNS verification for a pending domain.

```http
POST /v1/domains/:id/verify
X-API-Key: {{api_key}}
```

### Response

```json
{
  "domain": "example.com",
  "spf_verified": true,
  "dkim_verified": true,
  "dmarc_verified": true,
  "return_path_verified": true,
  "status": "verified"
}
```

In SES mode, a successful DNS check configures the BYODKIM identity and custom
MAIL FROM domain, then checks their actual SES status. The domain remains
`pending` until SES reports both as ready; a successful SES create request does
not by itself authorize sending.

---

## Advanced Authentication

### Check MTA-STS Configuration

```http
GET /v1/domains/:id/mta-sts
X-API-Key: {{api_key}}
```

### Response

```json
{
  "domain": "example.com",
  "mtaSts": {
    "supported": true,
    "mode": "enforce",
    "policy": {
      "version": "STSv1",
      "mode": "enforce",
      "mx": ["mail.example.com", "*.apexmail.ee"],
      "maxAge": 604800
    },
    "dnsRecord": {
      "version": "STSv1",
      "id": "20240115001"
    },
    "errors": [],
    "warnings": [],
    "recommendations": []
  },
  "setupInstructions": null
}
```

#### When Not Configured

```json
{
  "domain": "example.com",
  "mtaSts": {
    "supported": false,
    "mode": null,
    "errors": ["No _mta-sts TXT record found"],
    "recommendations": ["Add TXT record: _mta-sts.example.com with value \"v=STSv1; id=<unique-id>\""]
  },
  "setupInstructions": {
    "dnsRecord": {
      "type": "TXT",
      "name": "_mta-sts.example.com",
      "value": "v=STSv1; id=lxk4p5abc"
    },
    "policyFile": {
      "url": "https://mta-sts.example.com/.well-known/mta-sts.txt",
      "content": "version: STSv1\nmode: testing\nmx: *.apexmail.ee\nmax_age: 604800"
    },
    "tlsrptRecord": {
      "type": "TXT",
      "name": "_smtp._tls.example.com",
      "value": "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
    }
  }
}
```

---

### Check BIMI Configuration

```http
GET /v1/domains/:id/bimi
X-API-Key: {{api_key}}
```

### Response

```json
{
  "domain": "example.com",
  "bimi": {
    "supported": true,
    "record": {
      "version": "BIMI1",
      "logoUrl": "https://assets.example.com/logo.svg",
      "certificateUrl": "https://assets.example.com/vmc.pem",
      "selector": "default"
    },
    "logoValid": true,
    "dmarcValid": true,
    "certificateValid": true,
    "errors": [],
    "warnings": [],
    "recommendations": []
  },
  "setupInstructions": {
    "dnsRecord": {
      "type": "TXT",
      "name": "default._bimi.example.com",
      "value": "v=BIMI1; l=https://assets.example.com/logo.svg"
    },
    "requirements": [
      "DMARC policy must be at enforcement (p=quarantine or p=reject)",
      "Logo must be SVG Tiny Portable/Secure format",
      "Logo must be square aspect ratio",
      "Logo file size should be under 32KB"
    ],
    "steps": [
      "1. Ensure your DMARC policy is p=quarantine or p=reject",
      "2. Create an SVG Tiny PS version of your logo",
      "3. Host the logo at a publicly accessible HTTPS URL",
      "4. Add the BIMI DNS TXT record"
    ]
  }
}
```

---

### Validate BIMI Logo

```http
POST /v1/domains/:id/bimi/validate-logo
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "logoUrl": "https://assets.example.com/logo.svg"
}
```

### Response

```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Logo should include a <title> element for accessibility"
  ],
  "requirements": [
    "Format: SVG Tiny Portable/Secure (baseProfile=\"tiny-ps\")",
    "Size: Maximum 32KB",
    "Aspect ratio: Must be square (1:1)",
    "No scripts, animations, or external references",
    "Must include <title> element for accessibility"
  ]
}
```

---

### Check TLS Reporting

```http
GET /v1/domains/:id/tlsrpt
X-API-Key: {{api_key}}
```

### Response

```json
{
  "domain": "example.com",
  "tlsrpt": {
    "supported": true,
    "record": {
      "version": "TLSRPTv1",
      "rua": ["mailto:tlsrpt@example.com"]
    },
    "error": null
  }
}
```

---

### Comprehensive Authentication Status

Get a complete authentication score and grade for a domain.

```http
GET /v1/domains/:id/auth-status
X-API-Key: {{api_key}}
```

### Response

```json
{
  "domain": "example.com",
  "score": 92,
  "grade": "A",
  "breakdown": {
    "basic": { "status": "pass", "points": 60, "maxPoints": 60 },
    "mtaSts": { "status": "pass", "points": 20, "maxPoints": 20 },
    "bimi": { "status": "warning", "points": 10, "maxPoints": 15 },
    "tlsrpt": { "status": "fail", "points": 0, "maxPoints": 5 }
  },
  "checks": {
    "spfDkimDmarc": {
      "status": "healthy",
      "issues": []
    },
    "mtaSts": {
      "supported": true,
      "mode": "enforce",
      "errors": []
    },
    "bimi": {
      "supported": true,
      "logoValid": true,
      "certificateValid": false
    },
    "tlsrpt": {
      "supported": false
    }
  },
  "recommendations": [
    "Consider obtaining a Verified Mark Certificate (VMC) for broader BIMI support",
    "Add TLSRPT DNS record to receive TLS connection reports"
  ]
}
```

---

## Error Responses

### Domain Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Domain not found"
  }
}
```

### Domain Already Exists

```json
{
  "error": {
    "code": "DOMAIN_EXISTS",
    "message": "Domain example.com already exists"
  }
}
```

### Invalid Domain Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid domain format"
  }
}
```

---

## Related Documentation

- [Email Authentication Guide](../../security/email-authentication.md)
- [Rate Limits](../rate-limits.md)
- [Errors Reference](../errors.md)
