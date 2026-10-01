# Sub-Accounts & Multi-Tenant Management

ApexMail provides sub-account management for agencies, resellers, and enterprise organizations managing multiple brands or clients.

> **Endpoint reference:** every example below targets the shipped enterprise
> router (`services/mail-server/crates/enterprise/src/routes.rs`, mounted at
> `https://enterprise.apexmail.ee`). All routes require an authenticated
> tenant (`Authorization: Bearer <token>`) and the caller must have access to
> the parent tenant. Request bodies use `deny_unknown_fields` — unknown
> properties are rejected with `422`.

## Overview

Sub-accounts enable:

- **Hierarchical Account Structure** - Create isolated environments for each client/brand
- **Resource Isolation** - Separate volume limits, sending domains, and data
- **Consolidated Billing** - Single parent relationship with per-sub-account volume tracking
- **Scoped API Keys** - Issue and revoke keys per sub-account

## Account Hierarchy

```
Parent Account (Agency/Enterprise)
├── Sub-Account A (Client 1)
│   ├── Sending Domain: client1.com
│   └── API Keys: 3
├── Sub-Account B (Client 2)
│   ├── Sending Domain: client2.com
│   └── API Keys: 5
└── Sub-Account C (Client 3)
    ├── Sending Domain: client3.com
    └── API Keys: 2
```

## Creating Sub-Accounts

### API Request

```bash
curl -X POST https://enterprise.apexmail.ee/sub-accounts \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "parent_id": "acc_parent",
    "name": "Client ABC",
    "email": "billing@clientabc.com",
    "domain": "clientabc.com",
    "plan": "starter",
    "volume_limit": 1000000,
    "inherit_parent_settings": false
  }'
```

Only `parent_id` and `name` are required; `email`, `domain`, `plan`,
`volume_limit`, and `inherit_parent_settings` (default `true`) are optional.

### Response

Responses use the enterprise envelope `{success, data?, error?, code?}`:

```json
{
  "success": true,
  "data": {
    "id": "7f9c24e5-1b3d-4a2f-9c8e-6d5f0a1b2c3d",
    "parent_id": "acc_parent",
    "name": "Client ABC",
    "status": "active",
    "email": "billing@clientabc.com",
    "domain": "clientabc.com",
    "plan": "starter",
    "volume_limit": 1000000,
    "volume_used": 0,
    "inherit_parent_settings": false,
    "settings": null,
    "metadata": null,
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-15T10:30:00Z"
  }
}
```

`status` is one of `active`, `suspended`, `pending`, `deactivated`.

## Volume Limits

The per-sub-account quota is the `volume_limit` field (emails per month). It
is set at creation and changed through the update endpoint — there is no
separate quotas endpoint:

```bash
curl -X PUT https://enterprise.apexmail.ee/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "volume_limit": 500000
  }'
```

The update body accepts exactly `{name?, email?, volume_limit?, settings?}`;
any other property (for example `status` or `metadata`) is rejected.

## Managing Sub-Accounts

### List Sub-Accounts of a Parent

Listing is scoped to a parent tenant — there is no bare `GET /sub-accounts`:

```bash
curl "https://enterprise.apexmail.ee/sub-accounts/parent/acc_parent?status=active&limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Query parameters: `status` (optional filter), `limit` (default 50, capped at
200), `offset`. Response: `{"success": true, "data": [ SubAccount, ... ]}`.

### Get Sub-Account

```bash
curl https://enterprise.apexmail.ee/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Update Sub-Account

```bash
curl -X PUT https://enterprise.apexmail.ee/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Client ABC - Premium",
    "settings": {"tier": "premium"}
  }'
```

### Suspend Sub-Account

```bash
curl -X POST https://enterprise.apexmail.ee/sub-accounts/{sub_account_id}/suspend \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "billing_issue"}'
```

Suspension sets `status` to `suspended`; the response returns the updated
sub-account. There is no dedicated reactivate endpoint — update the
sub-account's `settings`/plan via `PUT /sub-accounts/{id}` or contact
support to restore service.

### Delete Sub-Account

```bash
curl -X DELETE https://enterprise.apexmail.ee/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response: `{"success": true, "data": {"deleted": true}}`.

## Usage Statistics

Aggregated volume statistics are available per parent tenant — there is no
per-sub-account analytics endpoint (per-sub-account send activity is
available through the main API's analytics surface):

```bash
curl https://enterprise.apexmail.ee/sub-accounts/stats/acc_parent \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:

```json
{
  "success": true,
  "data": {
    "total": 3,
    "active": 2,
    "total_volume_used": 173730,
    "total_volume_limit": 3000000
  }
}
```

## Sub-Account API Keys

Each sub-account gets its own API keys, managed on the parent's
authentication.

### Create a Key

```bash
curl -X POST https://enterprise.apexmail.ee/sub-accounts/{sub_account_id}/api-keys \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Client ABC production",
    "permissions": ["emails:send", "templates:read"],
    "rate_limit": 100
  }'
```

The raw key is returned **only once** at creation — it cannot be retrieved
later:

```json
{
  "success": true,
  "data": {
    "id": "2c5b9e8a-4d7f-4c1b-a0d3-9e2f1b4c5a6b",
    "key": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "key_prefix": "9f86d081",
    "name": "Client ABC production"
  }
}
```

The key is a 64-character hex token (32 random bytes); `key_prefix` is its
first 8 characters, kept for identification.

### List Keys

```bash
curl https://enterprise.apexmail.ee/sub-accounts/{sub_account_id}/api-keys \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Listings expose key metadata only (id, prefix, name, permissions, status) —
never the raw key material.

### Revoke a Key

```bash
curl -X POST https://enterprise.apexmail.ee/sub-accounts/{sub_account_id}/api-keys/{key_id}/revoke \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Revoked keys immediately fail authentication.

## Data Isolation

Sub-accounts provide data isolation:

| Resource | Isolation Level |
|----------|-----------------|
| Emails | Fully isolated |
| Templates | Fully isolated |
| Analytics | Fully isolated |
| API Keys | Scoped to sub-account |
| Domains | Dedicated per sub-account |

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sub-accounts` | POST | Create sub-account |
| `/sub-accounts/{id}` | GET | Get sub-account details |
| `/sub-accounts/{id}` | PUT | Update sub-account (`name`/`email`/`volume_limit`/`settings`) |
| `/sub-accounts/{id}` | DELETE | Delete sub-account |
| `/sub-accounts/parent/{parent_id}` | GET | List sub-accounts of a parent |
| `/sub-accounts/{id}/suspend` | POST | Suspend sub-account |
| `/sub-accounts/stats/{parent_id}` | GET | Aggregated usage stats for a parent |
| `/sub-accounts/{id}/api-keys` | POST | Create sub-account API key |
| `/sub-accounts/{id}/api-keys` | GET | List sub-account API keys |
| `/sub-accounts/{id}/api-keys/{key_id}/revoke` | POST | Revoke an API key |

## Best Practices

1. **Start with Conservative Volume Limits** - Increase `volume_limit` as usage patterns justify it
2. **Use `settings`** - Store tiering/organizational data on the sub-account for reporting
3. **Monitor Usage** - Watch `volume_used` (and the parent-level stats endpoint) before limits are reached
4. **Regular Audits** - Review inactive sub-account API keys and revoke unused ones
5. **Document Naming Conventions** - Use consistent naming for easier management
