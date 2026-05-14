# ApexMail API Endpoint Reference

This index lists all documented API endpoints for the ApexMail platform. Each resource group has a dedicated endpoint documentation file.

## Resource Groups

| Group | Base Path | Documentation | Description |
|-------|-----------|---------------|-------------|
| Messages | `/v1/messages` | [`messages.md`](messages.md) | Send and manage transactional emails |
| Auth | `/v1/auth` | [`auth.md`](auth.md) | Authentication, session management, API keys |
| Account | `/v1/account` | [`account.md`](account.md) | User profile and account management |
| Domains | `/v1/domains` | [`domains.md`](domains.md) | Sending domain configuration and verification |
| Templates | `/v1/templates` | [`templates.md`](templates.md) | Email template CRUD and rendering |
| Campaigns | `/v1/campaigns` | [`campaigns.md`](campaigns.md) | Marketing campaign management |
| Contacts | `/v1/contacts` | [`contacts.md`](contacts.md) | Contact management and bulk operations |
| Suppressions | `/v1/suppressions` | [`suppressions.md`](suppressions.md) | Suppression list management |
| Lists | `/v1/lists` | [`lists.md`](lists.md) | Audience list and subscriber management |
| Automations | `/v1/automations` | [`automations.md`](automations.md) | Automation workflow management |
| Events | `/v1/events` | [`events.md`](events.md) | Event history and delivery tracking |
| Analytics | `/v1/analytics` | [`analytics.md`](analytics.md) | Dashboard, volume, engagement, deliverability |
| Webhooks | `/v1/webhooks` | [`webhooks.md`](webhooks.md) | Webhook endpoint configuration |
| Billing | `/v1/billing` | [`billing.md`](billing.md) | Plans, usage, invoices, subscriptions |
| Dedicated IPs | `/v1/dedicated-ips` | [`dedicated-ips.md`](dedicated-ips.md) | Dedicated sending IP lifecycle |
| Support | `/v1/support` | [`support.md`](support.md) | Support ticket management |
| SCIM | `/v1/scim` | [`scim.md`](scim.md) | SCIM 2.0 user/group provisioning |
| Health | `/v1/health` | [`health.md`](health.md) | Liveness, readiness, and deep health checks |
| SES Notifications | `/v1/ses` | — (internal) | AWS SES bounce/complaint notification handler |
| Enterprise | `/v1/enterprise` | [`enterprise.md`](enterprise.md) | Enterprise private cloud, dedicated IP inventory, BYOIP |
| Analytics Export | `/v1/analytics` | [`analytics.md`](analytics.md) | Analytics data export (JSON/CSV/PDF) |
| Inbox Placement | `/v1/analytics` | [`../inbox-placement.md`](../inbox-placement.md) | Inbox placement testing and deliverability analysis |

## Authentication

All endpoints require authentication unless noted otherwise. See the [Auth API](auth.md) for details on the authentication flow.

- **API Key Authentication**: Include your API key in the `X-API-Key` header
- **Session Authentication**: Use cookies obtained from `/v1/auth/login`
- **Public Endpoints**: Auth endpoints (`/v1/auth/*`), health endpoints (`/v1/health/live`), SES notifications (`/v1/ses/notifications`)

## Common Headers

| Header | Description | Required |
|--------|-------------|----------|
| `X-API-Key` | API key for authentication | For API-key authenticated requests |
| `Content-Type` | Must be `application/json` | For requests with body |
| `Idempotency-Key` | Idempotency key for message sending | Optional (messages only) |
| `If-None-Match` | ETag for conditional requests | Optional |

## Pagination

List endpoints support cursor-based pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | number | 20 | Results per page (max: 100) |
| `cursor` | string | — | Cursor from previous response |
| `offset` | number | 0 | Offset-based pagination (legacy) |

Responses include pagination metadata:

```json
{
  "data": [...],
  "meta": {
    "has_more": true,
    "next_cursor": "cur_abc123..."
  }
}
```

## Rate Limiting

Rate limits are tier-based. See [`../rate-limits.md`](../rate-limits.md) for full details.

| Plan | Requests/Second |
|------|-----------------|
| Free | 10/s |
| Starter / Pro / PAYG | 100/s |
| Growth / Scale | 500/s |
| Enterprise | 5,000/s (customizable) |

## Error Responses

All errors follow a consistent format. See [`../errors.md`](../errors.md) for full details.

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable error message",
    "details": {
      "field": "description of the validation failure"
    }
  }
}
```
