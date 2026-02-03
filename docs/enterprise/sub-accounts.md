# Sub-Accounts & Multi-Tenant Management

ApexMail provides comprehensive sub-account management for agencies, resellers, and enterprise organizations managing multiple brands or clients.

## Overview

Sub-accounts enable:

- **Hierarchical Account Structure** - Create isolated environments for each client/brand
- **Granular Permissions** - Control access at the sub-account level
- **Resource Isolation** - Separate quotas, sending domains, and data
- **Consolidated Billing** - Single invoice with per-sub-account breakdown
- **White-Label Ready** - Each sub-account can have custom branding

## Account Hierarchy

```
Parent Account (Agency/Enterprise)
├── Sub-Account A (Client 1)
│   ├── Sending Domain: client1.com
│   ├── Users: 5
│   └── API Keys: 3
├── Sub-Account B (Client 2)
│   ├── Sending Domain: client2.com
│   ├── Users: 10
│   └── API Keys: 5
└── Sub-Account C (Client 3)
    ├── Sending Domain: client3.com
    ├── Users: 3
    └── API Keys: 2
```

## Creating Sub-Accounts

### API Request

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/sub-accounts \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "parentAccountId": "acc_parent",
    "name": "Client ABC",
    "metadata": {
      "industry": "e-commerce",
      "region": "US-West"
    },
    "settings": {
      "maxMonthlyEmails": 1000000,
      "maxDomains": 5,
      "maxApiKeys": 10,
      "maxUsers": 25
    },
    "inheritParentSettings": false
  }'
```

### Response

```json
{
  "subAccount": {
    "id": "sub_abc123",
    "parentAccountId": "acc_parent",
    "name": "Client ABC",
    "status": "active",
    "settings": {
      "maxMonthlyEmails": 1000000,
      "maxDomains": 5,
      "maxApiKeys": 10,
      "maxUsers": 25
    },
    "usage": {
      "currentMonthEmails": 0,
      "domains": 0,
      "apiKeys": 0,
      "users": 0
    },
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

## Resource Quotas

### Setting Quotas

Configure limits per sub-account:

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/sub-accounts/{sub_account_id}/quotas \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "quotas": {
      "maxMonthlyEmails": 500000,
      "maxDomains": 3,
      "maxApiKeys": 5,
      "maxUsers": 10,
      "maxStorageGB": 50,
      "maxTemplates": 100,
      "maxSuppressionListSize": 100000
    }
  }'
```

### Quota Enforcement

When quotas are exceeded:

| Resource | Behavior | Action |
|----------|----------|--------|
| Monthly Emails | Hard limit | Emails rejected with `QUOTA_EXCEEDED` |
| Domains | Hard limit | Domain addition blocked |
| API Keys | Hard limit | Key creation blocked |
| Users | Hard limit | User invitation blocked |
| Storage | Soft limit | Warning at 80%, hard limit at 100% |

### Quota Alerts

Configure alerts when approaching limits:

```json
{
  "alerts": {
    "emailQuotaWarning": 80,
    "emailQuotaCritical": 95,
    "storageWarning": 75,
    "webhookUrl": "https://your-system.com/alerts"
  }
}
```

## Permissions & Access Control

### Role Hierarchy

```
Super Admin (Parent Account)
├── Full access to all sub-accounts
├── Can create/delete sub-accounts
└── Can modify quotas and billing

Sub-Account Admin
├── Full access to assigned sub-account
├── Can manage users within sub-account
└── Cannot modify quotas

Sub-Account User
├── Limited access based on role
├── Cannot manage other users
└── Operates within assigned permissions
```

### Permission Scopes

```json
{
  "permissions": {
    "emails": ["read", "send"],
    "templates": ["read", "write", "delete"],
    "domains": ["read"],
    "analytics": ["read"],
    "users": [],
    "apiKeys": ["read", "create"],
    "webhooks": ["read", "write"],
    "suppressions": ["read", "write"]
  }
}
```

## Managing Sub-Accounts

### List Sub-Accounts

```bash
curl https://api.apexmail.ee/enterprise/v1/sub-accounts \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response:
```json
{
  "subAccounts": [
    {
      "id": "sub_abc123",
      "name": "Client ABC",
      "status": "active",
      "usage": {
        "currentMonthEmails": 45230,
        "percentOfQuota": 45.2
      }
    },
    {
      "id": "sub_def456",
      "name": "Client DEF",
      "status": "active",
      "usage": {
        "currentMonthEmails": 128500,
        "percentOfQuota": 12.8
      }
    }
  ],
  "total": 2
}
```

### Update Sub-Account

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "name": "Client ABC - Premium",
    "status": "active",
    "metadata": {
      "tier": "premium"
    }
  }'
```

### Suspend Sub-Account

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/sub-accounts/{sub_account_id}/suspend \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "reason": "billing_issue",
    "notifyUsers": true
  }'
```

### Delete Sub-Account

```bash
curl -X DELETE https://api.apexmail.ee/enterprise/v1/sub-accounts/{sub_account_id} \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "confirmDeletion": true,
    "exportData": true,
    "retentionDays": 30
  }'
```

## Usage Analytics

### Sub-Account Analytics

```bash
curl https://api.apexmail.ee/enterprise/v1/sub-accounts/{sub_account_id}/analytics \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -G -d "startDate=2024-01-01" -d "endDate=2024-01-31"
```

Response:
```json
{
  "subAccountId": "sub_abc123",
  "period": {
    "start": "2024-01-01",
    "end": "2024-01-31"
  },
  "metrics": {
    "emailsSent": 45230,
    "delivered": 44850,
    "bounced": 380,
    "opened": 12450,
    "clicked": 3240,
    "deliveryRate": 99.16,
    "openRate": 27.76,
    "clickRate": 7.23
  },
  "quotaUsage": {
    "emails": {
      "used": 45230,
      "limit": 100000,
      "percentage": 45.2
    }
  }
}
```

### Aggregate Analytics

Get analytics across all sub-accounts:

```bash
curl https://api.apexmail.ee/enterprise/v1/sub-accounts/analytics/aggregate \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Billing

### Per-Sub-Account Billing

```bash
curl https://api.apexmail.ee/enterprise/v1/sub-accounts/billing \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -G -d "month=2024-01"
```

Response:
```json
{
  "month": "2024-01",
  "total": 2450.00,
  "currency": "USD",
  "breakdown": [
    {
      "subAccountId": "sub_abc123",
      "name": "Client ABC",
      "emailsSent": 45230,
      "cost": 452.30
    },
    {
      "subAccountId": "sub_def456",
      "name": "Client DEF",
      "emailsSent": 128500,
      "cost": 1285.00
    }
  ]
}
```

### Cost Allocation Tags

Tag sub-accounts for cost allocation:

```json
{
  "metadata": {
    "costCenter": "CC-1234",
    "department": "Marketing",
    "project": "Q1-Campaign"
  }
}
```

## Data Isolation

Sub-accounts provide complete data isolation:

| Resource | Isolation Level |
|----------|-----------------|
| Emails | Fully isolated |
| Templates | Fully isolated |
| Contacts | Fully isolated |
| Analytics | Fully isolated |
| API Keys | Scoped to sub-account |
| Webhooks | Scoped to sub-account |
| Domains | Dedicated per sub-account |

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sub-accounts` | POST | Create sub-account |
| `/sub-accounts` | GET | List sub-accounts |
| `/sub-accounts/{id}` | GET | Get sub-account details |
| `/sub-accounts/{id}` | PUT | Update sub-account |
| `/sub-accounts/{id}` | DELETE | Delete sub-account |
| `/sub-accounts/{id}/quotas` | PUT | Update quotas |
| `/sub-accounts/{id}/suspend` | POST | Suspend sub-account |
| `/sub-accounts/{id}/reactivate` | POST | Reactivate sub-account |
| `/sub-accounts/{id}/analytics` | GET | Get analytics |
| `/sub-accounts/billing` | GET | Get billing breakdown |

## Best Practices

1. **Start with Conservative Quotas** - Increase as needed based on usage patterns
2. **Use Metadata** - Tag sub-accounts for better organization and reporting
3. **Monitor Usage** - Set up alerts before quotas are reached
4. **Regular Audits** - Review inactive sub-accounts periodically
5. **Document Naming Conventions** - Use consistent naming for easier management
