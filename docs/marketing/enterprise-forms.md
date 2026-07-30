# Enterprise Form Specifications

> Last updated: 2026-07-29

## Form Types

| Form ID | Purpose | Page |
|---------|---------|------|
| `enterprise-pricing` | Enterprise pricing inquiry | /enterprise/, /pricing/ |
| `private-cloud-consultation` | Private Cloud consultation request | /private-cloud/ |
| `security-package` | Security documentation request | /enterprise/ |
| `migration-assessment` | Migration assessment request | /compare/*/, /enterprise/ |
| `data-residency` | Data residency inquiry | /enterprise/ |
| `architecture-review` | Architecture review request | /enterprise/ |

## Required Fields (All Forms)

| Field | Type | Required | Validation |
|-------|------|----------|-----------|
| Name | text | Yes | 1–255 characters |
| Work email | email | Yes | Valid email format, no disposable domains |
| Company | text | Yes | 1–255 characters |
| Job title | text | Yes | 1–255 characters |
| Country | select | Yes | ISO 3166-1 country list |
| Current provider | text | No | 1–255 characters |
| Monthly volume | number | Yes | Positive integer |
| Peak volume | number | No | Positive integer |
| Use case | textarea | Yes | 1–2000 characters |
| Required region | select | No | EEA, US, APAC, Custom |
| Compliance requirement | multiselect | No | GDPR, HIPAA, SOC 2, PCI, Other |
| Deployment preference | select | No | Shared Cloud, Dedicated Tenant, BYOC, Not sure |
| Target timeline | select | Yes | < 1 month, 1–3 months, 3–6 months, 6+ months |
| Additional context | textarea | No | 1–5000 characters |

## Validation Requirements

| Rule | Implementation |
|------|---------------|
| Work email format | RFC 5322 compliant |
| Required fields | Client-side and server-side validation |
| Maximum length | Enforced per field |
| Spam protection | Honeypot field + rate limiting (5 submissions/hour/IP) |
| Duplicate submission protection | Session-based deduplication (30min window) |
| Consent disclosure | Checkbox: "I agree to ApexMail processing my data to respond to this inquiry. See Privacy Policy." |
| Error messaging | Field-level error messages, accessible via aria-describedby |
| Accessible labels | All fields have `<label>` elements; required fields marked with asterisk and aria-required |

## Routing Requirements

| Action | System |
|--------|--------|
| Create CRM record | CRM integration |
| Assign lead owner | Round-robin or rules-based assignment |
| Send internal notification | Email to sales@apexmail.ee |
| Send customer acknowledgment | Confirmation email within 5 minutes |
| Preserve referral source | UTM parameters stored in CRM |
| Preserve UTM parameters | utm_source, utm_medium, utm_campaign |
| Record requested solution | Form type mapped to CRM product interest |
| Record submission timestamp | ISO 8601 UTC |

## Completion Verification

- Every test submission appears in CRM within 30 seconds
- Confirmation email received within 5 minutes
- Failed submissions generate alert to engineering
- Forms work on mobile (all fields tappable, keyboard-accessible)
- Keyboard navigation works through all form fields
- Screen reader announces validation errors
