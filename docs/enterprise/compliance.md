# Compliance & Data Governance

ApexMail provides comprehensive compliance features to help organizations meet regulatory requirements including GDPR, CCPA, HIPAA, and industry-specific standards.

## Overview

Compliance features include:

- **Consent Management** - Track and manage subscriber consent
- **Data Subject Rights** - Handle access, deletion, and portability requests
- **Automatic DPA** - Generate compliant Data Processing Agreements
- **Audit Logging** - Complete audit trail for all data operations
- **Data Retention** - Configurable retention policies
- **Geographic Controls** - Data residency and processing restrictions

## Supported Regulations

| Regulation | Region | Key Requirements |
|------------|--------|------------------|
| GDPR | EU/EEA | Consent, Data Subject Rights, DPA |
| CCPA/CPRA | California | Opt-out, Do Not Sell, Access Rights |
| HIPAA | US Healthcare | PHI Protection, BAA |
| CASL | Canada | Express Consent, Unsubscribe |
| LGPD | Brazil | Similar to GDPR |
| PDPA | Singapore | Consent, Purpose Limitation |
| POPIA | South Africa | Consent, Data Protection |

## Consent Management

### Record Consent

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/consent \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "email": "user@example.com",
    "consent": {
      "marketing": true,
      "transactional": true,
      "thirdPartySharing": false
    },
    "source": {
      "type": "web_form",
      "url": "https://yoursite.com/signup",
      "ipAddress": "203.0.113.1",
      "userAgent": "Mozilla/5.0..."
    },
    "legalBasis": "consent",
    "language": "en-US",
    "privacyPolicyVersion": "2024-01",
    "doubleOptIn": true
  }'
```

### Response

```json
{
  "consent": {
    "id": "consent_abc123",
    "email": "user@example.com",
    "status": "pending_verification",
    "verificationEmailSent": true,
    "expiresAt": "2024-01-22T10:30:00Z",
    "auditTrail": {
      "consentRecordedAt": "2024-01-15T10:30:00Z",
      "recordedBy": "api_key_xxx",
      "ipAddress": "203.0.113.1"
    }
  }
}
```

### Consent Verification (Double Opt-In)

```bash
# Send verification email
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/consent/verify \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "consentId": "consent_abc123"
  }'

# Confirm consent (after user clicks verification link)
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/consent/confirm \
  -d '{
    "token": "verify_token_xxx"
  }'
```

### Check Consent Status

```bash
curl https://api.apexmail.ee/enterprise/v1/compliance/consent/status \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "email=user@example.com"
```

Response:
```json
{
  "email": "user@example.com",
  "consent": {
    "marketing": {
      "granted": true,
      "grantedAt": "2024-01-15T10:30:00Z",
      "source": "web_form",
      "legalBasis": "consent"
    },
    "transactional": {
      "granted": true,
      "grantedAt": "2024-01-15T10:30:00Z",
      "source": "web_form",
      "legalBasis": "contract"
    }
  },
  "preferences": {
    "emailFrequency": "weekly",
    "categories": ["product_updates", "promotions"]
  }
}
```

## Data Subject Rights

### Right to Access (DSAR)

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/dsar/access \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "email": "user@example.com",
    "requestedBy": "user",
    "verificationMethod": "email",
    "format": "json",
    "includeMetadata": true
  }'
```

Response:
```json
{
  "request": {
    "id": "dsar_access_123",
    "type": "access",
    "status": "processing",
    "estimatedCompletionTime": "2024-01-16T10:30:00Z",
    "verificationRequired": true,
    "verificationSentTo": "user@example.com"
  }
}
```

### Data Export Format

```json
{
  "dataSubject": {
    "email": "user@example.com",
    "profileData": {
      "firstName": "John",
      "lastName": "Doe",
      "createdAt": "2023-06-15T10:00:00Z"
    },
    "consentHistory": [...],
    "emailHistory": [...],
    "eventHistory": [...],
    "preferences": {...}
  },
  "exportedAt": "2024-01-15T10:30:00Z",
  "format": "json",
  "checksum": "sha256:abc123..."
}
```

### Right to Erasure (Right to be Forgotten)

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/dsar/erasure \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "email": "user@example.com",
    "requestedBy": "user",
    "scope": {
      "profileData": true,
      "emailHistory": true,
      "eventHistory": true,
      "consentRecords": false,
      "suppressionList": false
    },
    "reason": "user_request"
  }'
```

Response:
```json
{
  "request": {
    "id": "dsar_erasure_456",
    "type": "erasure",
    "status": "pending_verification",
    "scope": {
      "profileData": "scheduled",
      "emailHistory": "scheduled",
      "eventHistory": "scheduled",
      "consentRecords": "retained",
      "suppressionList": "retained"
    },
    "scheduledCompletionTime": "2024-01-22T10:30:00Z",
    "retentionNote": "Consent records retained for compliance audit purposes"
  }
}
```

### Right to Data Portability

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/dsar/portability \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "email": "user@example.com",
    "format": "json",
    "destination": {
      "type": "email",
      "email": "user@example.com"
    }
  }'
```

## Automatic DPA Generation

### Generate DPA

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/dpa/generate \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "controllerInfo": {
      "companyName": "Your Company Inc.",
      "address": "123 Business Ave, City, State 12345",
      "contactEmail": "privacy@yourcompany.com",
      "dpoEmail": "dpo@yourcompany.com"
    },
    "processingPurposes": [
      "Email delivery",
      "Analytics and reporting",
      "Personalization"
    ],
    "dataCategories": [
      "Email addresses",
      "Names",
      "Engagement data"
    ],
    "subProcessors": true,
    "jurisdiction": "EU",
    "sccs": true
  }'
```

Response:
```json
{
  "dpa": {
    "id": "dpa_abc123",
    "status": "draft",
    "version": "2024-01",
    "documents": {
      "dpa": {
        "url": "https://api.apexmail.ee/dpa/dpa_abc123.pdf",
        "format": "pdf"
      },
      "sccs": {
        "url": "https://api.apexmail.ee/dpa/sccs_abc123.pdf",
        "format": "pdf"
      },
      "subProcessorList": {
        "url": "https://api.apexmail.ee/dpa/subprocessors_abc123.pdf",
        "format": "pdf"
      }
    },
    "signingRequired": true,
    "signingUrl": "https://sign.apexmail.ee/dpa/dpa_abc123"
  }
}
```

### Sign DPA Electronically

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/dpa/sign \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "dpaId": "dpa_abc123",
    "signatory": {
      "name": "Jane Smith",
      "title": "Chief Privacy Officer",
      "email": "jane.smith@yourcompany.com"
    },
    "signatureMethod": "electronic"
  }'
```

## Audit Trail

### Query Audit Logs

```bash
curl https://api.apexmail.ee/enterprise/v1/compliance/audit-logs \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "accountId=acc_xxx" \
  -d "startDate=2024-01-01" \
  -d "endDate=2024-01-31" \
  -d "eventTypes=consent,dsar,data_access"
```

Response:
```json
{
  "auditLogs": [
    {
      "id": "audit_001",
      "timestamp": "2024-01-15T10:30:00Z",
      "eventType": "consent_recorded",
      "actor": {
        "type": "api_key",
        "id": "key_xxx"
      },
      "subject": "user@example.com",
      "details": {
        "consentType": "marketing",
        "action": "granted",
        "source": "web_form"
      },
      "ipAddress": "203.0.113.1",
      "userAgent": "..."
    },
    {
      "id": "audit_002",
      "timestamp": "2024-01-15T14:00:00Z",
      "eventType": "dsar_access_request",
      "actor": {
        "type": "data_subject",
        "email": "user@example.com"
      },
      "subject": "user@example.com",
      "details": {
        "requestId": "dsar_access_123",
        "status": "verified"
      }
    }
  ],
  "pagination": {
    "total": 150,
    "page": 1,
    "perPage": 50
  }
}
```

### Export Audit Logs

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/audit-logs/export \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "startDate": "2024-01-01",
    "endDate": "2024-01-31",
    "format": "csv",
    "includeSignature": true
  }'
```

## Data Retention Policies

### Configure Retention

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/compliance/retention \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "policies": {
      "emailContent": {
        "retentionDays": 90,
        "action": "delete"
      },
      "emailMetadata": {
        "retentionDays": 365,
        "action": "anonymize"
      },
      "eventLogs": {
        "retentionDays": 730,
        "action": "archive"
      },
      "auditLogs": {
        "retentionDays": 2555,
        "action": "archive"
      },
      "consentRecords": {
        "retentionDays": null,
        "action": "retain"
      }
    }
  }'
```

### Retention Actions

| Action | Description |
|--------|-------------|
| `delete` | Permanently delete data |
| `anonymize` | Remove PII, keep aggregated data |
| `archive` | Move to cold storage |
| `retain` | Keep indefinitely (for legal compliance) |

## Geographic Controls

### Configure Data Residency

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/compliance/data-residency \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "primaryRegion": "eu-west-1",
    "allowedRegions": ["eu-west-1", "eu-central-1"],
    "restrictedRegions": ["us-*", "cn-*"],
    "crossBorderTransfer": {
      "allowed": true,
      "mechanism": "sccs",
      "tia": true
      }
  }'
```

## Compliance Reporting

### Generate Compliance Report

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/reports \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "type": "gdpr_compliance",
    "period": {
      "start": "2024-01-01",
      "end": "2024-03-31"
    },
    "includeEvidence": true
  }'
```

Response:
```json
{
  "report": {
    "id": "report_abc123",
    "type": "gdpr_compliance",
    "generatedAt": "2024-04-01T10:00:00Z",
    "summary": {
      "consentRate": 98.5,
      "dsarRequests": 12,
      "dsarCompletionRate": 100,
      "avgDsarCompletionDays": 4.2,
      "dataBreaches": 0,
      "retentionCompliance": 100
    },
    "downloadUrl": "https://api.apexmail.ee/reports/report_abc123.pdf"
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/compliance/consent` | POST | Record consent |
| `/compliance/consent/verify` | POST | Send verification email |
| `/compliance/consent/confirm` | POST | Confirm consent |
| `/compliance/consent/status` | GET | Get consent status |
| `/compliance/dsar/access` | POST | Submit access request |
| `/compliance/dsar/erasure` | POST | Submit erasure request |
| `/compliance/dsar/portability` | POST | Submit portability request |
| `/compliance/dpa/generate` | POST | Generate DPA |
| `/compliance/dpa/sign` | POST | Sign DPA |
| `/compliance/audit-logs` | GET | Query audit logs |
| `/compliance/retention` | PUT | Configure retention |
| `/compliance/reports` | POST | Generate compliance report |
| `/compliance/encryption/status/:tenant_id` | GET | Check encryption status |
| `/compliance/encryption/encrypt-field` | POST | Encrypt a PHI field value |
| `/compliance/encryption/decrypt-field` | POST | Decrypt an encrypted value |

## HIPAA Field-Level Encryption

For healthcare organizations, ApexMail provides AES-256-GCM field-level
encryption for Protected Health Information (PHI). This goes beyond
database-level encryption-at-rest by encrypting individual field values
in the application layer.

### Architecture

```
Application Layer:
  plaintext → AES-256-GCM(DEK) → ciphertext
  DEK → AES-256-GCM(KEK) → wrapped_dek

Storage Layer:
  ENC:v1:<base64(version | kek_id | wrapped_dek | nonce | ciphertext)>
```

Each field value gets a unique random Data Encryption Key (DEK). The DEK
is wrapped by a Key Encryption Key (KEK) and stored alongside the
ciphertext. This envelope encryption scheme means:

- Rotating the KEK only requires re-wrapping DEKs, not re-encrypting data
- Compromising one field's DEK does not expose other fields
- The KEK never touches the database

### Protected Fields

The following field names are automatically identified as PHI:

| Field | Description |
|-------|-------------|
| `email` | Email address |
| `recipient` | Recipient address |
| `name` / `first_name` / `last_name` | Personal names |
| `phone` / `phone_number` | Phone numbers |
| `address` / `street_address` | Physical addresses |
| `city` / `state` / `zip_code` / `postal_code` | Address components |
| `ssn` / `social_security_number` | Social Security Number |
| `date_of_birth` / `dob` | Date of birth |
| `medical_record_number` / `mrn` | Medical records |
| `health_plan_id` / `insurance_id` | Insurance identifiers |
| `patient_id` | Patient identifiers |

### Encrypt a Field

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/compliance/encryption/encrypt-field \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "tenant_id": "ten_abc123",
    "field_name": "email",
    "plaintext": "patient@example.com"
  }'
```

**Response:**

```json
{
  "field_name": "email",
  "ciphertext": "ENC:v1:base64encodeddata..."
}
```

### Check Encryption Status

```bash
curl https://api.apexmail.ee/enterprise/v1/compliance/encryption/status/ten_abc123 \
  -H "X-API-Key: YOUR_API_KEY"
```

**Response:**

```json
{
  "tenant_id": "ten_abc123",
  "encryption_enabled": true,
  "algorithm": "AES-256-GCM",
  "key_scheme": "envelope (DEK wrapped by KEK)",
  "phi_fields_count": 18
}
```

### KEK Management

The KEK must be provisioned externally (never generated by ApexMail):

```bash
# Generate a 256-bit KEK
openssl rand -hex 32

# In Kubernetes, create the KEK secret
kubectl create secret generic apexmail-kek \
  --from-literal=kek_id='kek-2025-01' \
  --from-literal=kek_material='HEX_ENCODED_32_BYTE_KEY' \
  -n apexmail
```

The `kek_id` is embedded in every encrypted value, enabling key rotation:
deploy a new KEK with a new ID, and old values remain decryptable as long
as the previous KEK is still available.

## Best Practices

1. **Double Opt-In** - Always use verified consent for marketing emails
2. **Clear Purpose** - Document specific purposes for data processing
3. **Timely Response** - Complete DSAR requests within regulatory timeframes
4. **Regular Audits** - Review consent records and data access logs
5. **Retention Limits** - Don't keep data longer than necessary
6. **Document Everything** - Maintain evidence for compliance audits
7. **Train Staff** - Ensure team understands compliance procedures
8. **Rotate KEKs** - Rotate the Key Encryption Key at least annually for HIPAA
