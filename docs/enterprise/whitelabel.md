# White-Label & Custom Branding

ApexMail's white-label solution allows agencies and enterprises to offer email services under their own brand.

> **Endpoint reference:** every example below targets the shipped enterprise
> router (`services/mail-server/crates/enterprise/src/routes.rs`, mounted at
> `https://enterprise.apexmail.ee`). All routes require an authenticated
> tenant (`Authorization: Bearer <token>`) with access to the tenant being
> configured. Request bodies use `deny_unknown_fields` — unknown properties
> are rejected with `422`. Responses use the enterprise envelope
> `{success, data?, error?, code?}`.

## Overview

White-label features include:

- **UI Branding** - Company name, logos, colors, custom CSS, footer and support links
- **Branded Sending Domains** - Tracking, return-path, and custom-From domains with automatic DNS record generation
- **Branded System Emails** - Customizable subject/HTML/text templates for system email
- **Removal of ApexMail References** - Customer-facing surfaces carry your brand

## Brand Configuration

### Update Branding Config

```bash
curl -X PUT https://enterprise.apexmail.ee/whitelabel/config \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acc_xxx",
    "company_name": "YourMail Pro",
    "logo_url": "https://assets.yourcompany.com/logo.svg",
    "favicon_url": "https://assets.yourcompany.com/favicon.ico",
    "primary_color": "#dc2626",
    "secondary_color": "#52525b",
    "custom_css": ".btn-primary { border-radius: 0px; font-weight: 600; }",
    "footer_text": "© YourMail Pro",
    "support_email": "support@yourcompany.com",
    "support_url": "https://support.yourcompany.com"
  }'
```

The body accepts exactly `{tenant_id, company_name?, logo_url?, favicon_url?,
primary_color?, secondary_color?, custom_css?, footer_text?, support_email?,
support_url?}`. Only `tenant_id` is required; omitted fields leave the
stored values unchanged.

### Retrieve Branding Config

```bash
curl https://enterprise.apexmail.ee/whitelabel/config/acc_xxx \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:

```json
{
  "success": true,
  "data": {
    "id": "0e8c1b2a-3f4d-4e5a-9b8c-7d6e5f4a3b2c",
    "tenant_id": "acc_xxx",
    "company_name": "YourMail Pro",
    "logo_url": "https://assets.yourcompany.com/logo.svg",
    "primary_color": "#dc2626",
    "secondary_color": "#52525b",
    "accent_color": null,
    "font_family": null,
    "custom_css": ".btn-primary { border-radius: 0px; font-weight: 600; }",
    "favicon_url": "https://assets.yourcompany.com/favicon.ico",
    "footer_text": "© YourMail Pro",
    "support_email": "support@yourcompany.com",
    "support_url": "https://support.yourcompany.com",
    "privacy_url": null,
    "terms_url": null,
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-15T10:30:00Z"
  }
}
```

## Custom Sending Domains

White-label domains are *sending-surface* domains (tracking, return path,
custom From), each verified via a DNS TXT token.

### 1. Add a Domain

```bash
curl -X POST https://enterprise.apexmail.ee/whitelabel/domains \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acc_xxx",
    "domain": "mail.yourcompany.com",
    "domain_type": "tracking"
  }'
```

`domain_type` is one of `tracking` (CNAME to `tracking.apexmail.io`),
`return_path` (CNAME to `return.apexmail.io`), or `custom_from` (SPF/DKIM
TXT records). The response includes the generated `dns_records` and a
per-domain `verification_token`; `verification_status` starts as `pending`:

```json
{
  "success": true,
  "data": {
    "id": "6a5f4e3d-2c1b-4a09-8f7e-6d5c4b3a2f1e",
    "tenant_id": "acc_xxx",
    "domain": "mail.yourcompany.com",
    "domain_type": "tracking",
    "verification_status": "pending",
    "verification_token": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "dns_records": [
      { "record_type": "CNAME", "host": "track.mail.yourcompany.com", "value": "tracking.apexmail.io", "ttl": 3600 },
      { "record_type": "TXT", "host": "_apexmail-verify.mail.yourcompany.com", "value": "apexmail-verification=9f86d081…", "ttl": 3600 }
    ],
    "verified_at": null,
    "ssl_status": null,
    "ssl_certificate_id": null,
    "ssl_expires_at": null,
    "created_at": "2026-01-15T10:30:00Z"
  }
}
```

### 2. Publish the DNS Records

Add the records returned in `dns_records` — including the TXT verification
record — at your DNS provider:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| CNAME | `track.mail.yourcompany.com` | `tracking.apexmail.io` | Click/open tracking on your domain |
| TXT | `_apexmail-verify.mail.yourcompany.com` | `apexmail-verification=<token>` | Domain ownership verification |

### 3. Verify the Domain

Verification is a real DNS check: the domain is marked verified only when
the `_apexmail-verify.<domain>` TXT record contains the issued token.

```bash
curl -X POST https://enterprise.apexmail.ee/whitelabel/domains/{domain_id}/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

The response returns the domain with `verification_status` set to `verified`
or `failed`.

### 4. Manage Domains

List a tenant's domains (`limit` defaults to 50, capped at 200; `offset`
paginates):

```bash
curl "https://enterprise.apexmail.ee/whitelabel/domains/tenant/acc_xxx?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Remove a domain (the `tenant_id` path segment guards against cross-tenant
deletion):

```bash
curl -X DELETE https://enterprise.apexmail.ee/whitelabel/domains/acc_xxx/{domain_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response: `{"success": true, "data": {"deleted": true}}`.

## Branded System Emails

### Customize Email Templates

```bash
curl -X PUT https://enterprise.apexmail.ee/whitelabel/email-templates \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acc_xxx",
    "template_type": "welcome",
    "subject_template": "Welcome to {{company_name}}",
    "html_template": "<html>...</html>",
    "text_template": "Welcome to {{company_name}}..."
  }'
```

The body accepts exactly `{tenant_id, template_type, subject_template?,
html_template?, text_template?}`; the template is upserted per
`(tenant_id, template_type)`.

### List Email Templates

```bash
curl https://enterprise.apexmail.ee/whitelabel/email-templates/acc_xxx \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Returns the tenant's templates ordered by `template_type`. A tenant with no
white-label configuration gets a `404` (`code: "NOT_FOUND"`), not an empty
list.

Response:

```json
{
  "success": true,
  "data": [
    {
      "id": "1f2e3d4c-5b6a-4789-8a9b-0c1d2e3f4a5b",
      "tenant_id": "acc_xxx",
      "template_type": "welcome",
      "subject_template": "Welcome to {{company_name}}",
      "html_template": "<html>...</html>",
      "text_template": "Welcome to {{company_name}}...",
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

## Best Practices

1. **Consistent Branding** - Match your existing brand guidelines
2. **Verify DNS Before Verification Calls** - Point the `_apexmail-verify` TXT record before calling the verify endpoint; failed attempts set `verification_status` to `failed` until the record appears
3. **Staged Rollout** - Test `custom_css` changes on a staging tenant before production
4. **Backup Configurations** - Keep a copy of your branding config and templates (both are retrievable via `GET` endpoints)
5. **One Domain Per Surface** - Register separate domains for tracking, return-path, and custom-From as needed

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/whitelabel/config` | PUT | Update branding configuration |
| `/whitelabel/config/{tenant_id}` | GET | Get branding configuration |
| `/whitelabel/domains` | POST | Add a white-label sending domain |
| `/whitelabel/domains/{id}/verify` | POST | Verify a domain (DNS TXT token check) |
| `/whitelabel/domains/tenant/{tenant_id}` | GET | List a tenant's domains |
| `/whitelabel/domains/{tenant_id}/{id}` | DELETE | Remove a domain |
| `/whitelabel/email-templates` | PUT | Upsert a branded email template |
| `/whitelabel/email-templates/{tenant_id}` | GET | List branded email templates |
