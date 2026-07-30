# Campaigns API

> **Base path:** `/v1/campaigns`
> **Required scopes:** `campaigns:read` (GET), `campaigns:write` (POST / PATCH / DELETE)
> **Rate limit:** 60 requests/minute per API key
> **Idempotency:** Supported via `Idempotency-Key` header for POST endpoints
> **Content-Type:** `application/json`

The Campaigns API allows you to create and manage email marketing campaigns.

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/campaigns` | Create a campaign |
| GET | `/v1/campaigns` | List campaigns |
| GET | `/v1/campaigns/:id` | Get campaign details |
| PATCH | `/v1/campaigns/:id` | Update campaign |
| DELETE | `/v1/campaigns/:id` | Delete campaign |
| POST | `/v1/campaigns/:id/send` | Send campaign |
| POST | `/v1/campaigns/:id/schedule` | Schedule campaign |
| POST | `/v1/campaigns/:id/pause` | Pause sending |
| POST | `/v1/campaigns/:id/resume` | Resume sending |
| GET | `/v1/campaigns/:id/stats` | Get campaign statistics |

---

## Create Campaign

Create a new email campaign.

### Request

```http
POST /v1/campaigns
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "name": "January Newsletter",
  "subject": "Your January Update",
  "previewText": "See what's new this month...",
  "from": "newsletter@yourcompany.com",
  "fromName": "Your Company",
  "replyTo": "support@yourcompany.com",
  "templateId": "tmpl_newsletter_001",
  "variables": {
    "month": "January",
    "year": "2024"
  },
  "listIds": ["list_abc123", "list_def456"],
  "segmentId": "seg_active_users",
  "excludeListIds": ["list_unsubscribed"],
  "trackOpens": true,
  "trackClicks": true,
  "utmParams": {
    "source": "email",
    "medium": "newsletter",
    "campaign": "january-2024"
  },
  "settings": {
    "sendTimeOptimization": true,
    "timezone": "America/New_York",
    "throttleRate": 1000
  }
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Campaign name (internal) |
| `subject` | string | ✓ | Email subject line |
| `previewText` | string | | Preview text (snippet) |
| `from` | string | ✓ | Sender email (verified) |
| `fromName` | string | | Sender display name |
| `replyTo` | string | | Reply-to address |
| `templateId` | string | ✓ | Template to use |
| `html` | string | | Raw HTML (alternative to template) |
| `text` | string | | Plain text version |
| `variables` | object | | Global template variables |
| `listIds` | string[] | ✓* | Contact lists to send to |
| `segmentId` | string | | Segment filter |
| `excludeListIds` | string[] | | Lists to exclude |
| `trackOpens` | boolean | | Enable open tracking (default: true) |
| `trackClicks` | boolean | | Enable click tracking (default: true) |
| `utmParams` | object | | UTM parameters for links |
| `settings` | object | | Campaign settings |

### Settings Object

| Field | Type | Description |
|-------|------|-------------|
| `sendTimeOptimization` | boolean | Use AI to optimize send time per recipient |
| `timezone` | string | Default timezone for scheduling |
| `throttleRate` | number | Max emails per hour (0 = unlimited) |
| `ipPool` | string | Dedicated IP pool to use |

### Response

```json
{
  "id": "camp_xyz789",
  "name": "January Newsletter",
  "status": "draft",
  "subject": "Your January Update",
  "from": "newsletter@yourcompany.com",
  "recipientCount": 15420,
  "createdAt": "2024-01-15T10:30:00Z",
  "updatedAt": "2024-01-15T10:30:00Z"
}
```

### Campaign Status Values

| Status | Description |
|--------|-------------|
| `draft` | Campaign created but not sent |
| `scheduled` | Scheduled for future sending |
| `sending` | Currently being sent |
| `paused` | Sending paused |
| `completed` | Finished sending |
| `canceled` | Campaign canceled |

---

## List Campaigns

Retrieve paginated list of campaigns.

### Request

```http
GET /v1/campaigns?status=completed&limit=20
X-API-Key: {{api_key}}
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter by status |
| `search` | string | | Search by name |
| `startDate` | string | | Created after (ISO 8601) |
| `endDate` | string | | Created before |
| `limit` | number | 20 | Results per page (max: 100) |
| `cursor` | string | | Pagination cursor |

### Response

```json
{
  "data": [
    {
      "id": "camp_xyz789",
      "name": "January Newsletter",
      "status": "completed",
      "subject": "Your January Update",
      "from": "newsletter@yourcompany.com",
      "recipientCount": 15420,
      "sentCount": 15418,
      "openRate": 0.342,
      "clickRate": 0.089,
      "createdAt": "2024-01-15T10:30:00Z",
      "sentAt": "2024-01-16T09:00:00Z",
      "completedAt": "2024-01-16T11:45:00Z"
    }
  ],
  "pagination": {
    "hasMore": true,
    "nextCursor": "cur_abc123",
    "total": 145
  }
}
```

---

## Get Campaign Details

Retrieve full campaign details including content and settings.

### Request

```http
GET /v1/campaigns/camp_xyz789
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "camp_xyz789",
  "name": "January Newsletter",
  "status": "completed",
  "subject": "Your January Update",
  "previewText": "See what's new this month...",
  "from": "newsletter@yourcompany.com",
  "fromName": "Your Company",
  "replyTo": "support@yourcompany.com",
  "templateId": "tmpl_newsletter_001",
  "variables": {
    "month": "January",
    "year": "2024"
  },
  "listIds": ["list_abc123", "list_def456"],
  "segmentId": "seg_active_users",
  "excludeListIds": ["list_unsubscribed"],
  "trackOpens": true,
  "trackClicks": true,
  "utmParams": {
    "source": "email",
    "medium": "newsletter",
    "campaign": "january-2024"
  },
  "settings": {
    "sendTimeOptimization": true,
    "timezone": "America/New_York",
    "throttleRate": 1000
  },
  "recipientCount": 15420,
  "sentCount": 15418,
  "failedCount": 2,
  "createdAt": "2024-01-15T10:30:00Z",
  "updatedAt": "2024-01-15T14:00:00Z",
  "scheduledAt": "2024-01-16T09:00:00Z",
  "sentAt": "2024-01-16T09:00:00Z",
  "completedAt": "2024-01-16T11:45:00Z"
}
```

---

## Update Campaign

Update a draft campaign. Cannot update campaigns that are sending or completed.

### Request

```http
PATCH /v1/campaigns/camp_xyz789
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "name": "January Newsletter - Updated",
  "subject": "Your January Update - Don't Miss Out!",
  "settings": {
    "throttleRate": 2000
  }
}
```

### Response

```json
{
  "id": "camp_xyz789",
  "name": "January Newsletter - Updated",
  "status": "draft",
  "subject": "Your January Update - Don't Miss Out!",
  "updatedAt": "2024-01-15T15:30:00Z"
}
```

---

## Delete Campaign

Delete a draft or canceled campaign.

### Request

```http
DELETE /v1/campaigns/camp_xyz789
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "camp_xyz789",
  "deleted": true
}
```

---

## Send Campaign

Immediately start sending a campaign.

### Request

```http
POST /v1/campaigns/camp_xyz789/send
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body (Optional)

```json
{
  "testMode": false,
  "testEmails": []
}
```

### Parameters

| Field | Type | Description |
|-------|------|-------------|
| `testMode` | boolean | Send to test emails only |
| `testEmails` | string[] | Test email addresses |

### Response

```json
{
  "id": "camp_xyz789",
  "status": "sending",
  "recipientCount": 15420,
  "estimatedCompletion": "2024-01-16T11:45:00Z",
  "startedAt": "2024-01-16T09:00:00Z"
}
```

---

## Schedule Campaign

Schedule a campaign for future delivery.

### Request

```http
POST /v1/campaigns/camp_xyz789/schedule
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "scheduledAt": "2024-01-20T09:00:00Z",
  "timezone": "America/New_York"
}
```

### Response

```json
{
  "id": "camp_xyz789",
  "status": "scheduled",
  "scheduledAt": "2024-01-20T14:00:00Z",
  "recipientCount": 15420
}
```

---

## Pause Campaign

Pause a campaign that is currently sending.

### Request

```http
POST /v1/campaigns/camp_xyz789/pause
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "camp_xyz789",
  "status": "paused",
  "sentCount": 8500,
  "remainingCount": 6920,
  "pausedAt": "2024-01-16T10:15:00Z"
}
```

---

## Resume Campaign

Resume a paused campaign.

### Request

```http
POST /v1/campaigns/camp_xyz789/resume
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "camp_xyz789",
  "status": "sending",
  "sentCount": 8500,
  "remainingCount": 6920,
  "resumedAt": "2024-01-16T10:30:00Z"
}
```

---

## Get Campaign Statistics

Retrieve detailed statistics for a campaign.

### Request

```http
GET /v1/campaigns/camp_xyz789/stats
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "camp_xyz789",
  "name": "January Newsletter",
  "status": "completed",
  "delivery": {
    "sent": 15418,
    "delivered": 15102,
    "bounced": 316,
    "bounceRate": 0.0205,
    "hardBounces": 42,
    "softBounces": 274
  },
  "engagement": {
    "opens": 5245,
    "uniqueOpens": 4892,
    "openRate": 0.324,
    "clicks": 1456,
    "uniqueClicks": 1289,
    "clickRate": 0.085,
    "clickToOpenRate": 0.264,
    "unsubscribes": 23,
    "unsubscribeRate": 0.0015,
    "complaints": 2,
    "complaintRate": 0.0001
  },
  "links": [
    {
      "url": "https://yourcompany.com/products",
      "clicks": 856,
      "uniqueClicks": 742
    },
    {
      "url": "https://yourcompany.com/blog",
      "clicks": 412,
      "uniqueClicks": 389
    }
  ],
  "devices": {
    "desktop": 0.42,
    "mobile": 0.51,
    "tablet": 0.07
  },
  "clients": [
    { "name": "Gmail", "percentage": 0.34 },
    { "name": "Apple Mail", "percentage": 0.28 },
    { "name": "Outlook", "percentage": 0.18 },
    { "name": "Other", "percentage": 0.20 }
  ],
  "geo": [
    { "country": "US", "opens": 2456 },
    { "country": "CA", "opens": 892 },
    { "country": "GB", "opens": 654 }
  ],
  "timeline": {
    "hourly": [
      { "hour": "2024-01-16T09:00:00Z", "sent": 2500, "opens": 245, "clicks": 32 },
      { "hour": "2024-01-16T10:00:00Z", "sent": 4200, "opens": 890, "clicks": 156 }
    ]
  }
}
```

---

## A/B Testing

### Create A/B Test Campaign

```http
POST /v1/campaigns
X-API-Key: {{api_key}}
Content-Type: application/json
```

```json
{
  "name": "January Newsletter - A/B Test",
  "type": "ab_test",
  "variants": [
    {
      "name": "Variant A",
      "subject": "Your January Update",
      "weight": 50
    },
    {
      "name": "Variant B",
      "subject": "Don't Miss Our January News!",
      "weight": 50
    }
  ],
  "testSettings": {
    "sampleSize": 0.2,
    "winnerCriteria": "open_rate",
    "testDuration": 4,
    "autoSendWinner": true
  },
  "from": "newsletter@yourcompany.com",
  "templateId": "tmpl_newsletter_001",
  "listIds": ["list_abc123"]
}
```

### A/B Test Settings

| Field | Type | Description |
|-------|------|-------------|
| `sampleSize` | number | Percentage of list for test (0.1-0.5) |
| `winnerCriteria` | string | `open_rate`, `click_rate`, `revenue` |
| `testDuration` | number | Hours to run test |
| `autoSendWinner` | boolean | Automatically send winner to remaining |

### A/B Test Response

```json
{
  "id": "camp_xyz789",
  "type": "ab_test",
  "status": "testing",
  "variants": [
    {
      "id": "var_a",
      "name": "Variant A",
      "subject": "Your January Update",
      "sentCount": 1542,
      "openRate": 0.312,
      "clickRate": 0.078
    },
    {
      "id": "var_b",
      "name": "Variant B",
      "subject": "Don't Miss Our January News!",
      "sentCount": 1542,
      "openRate": 0.358,
      "clickRate": 0.092
    }
  ],
  "winner": "var_b",
  "testEndsAt": "2024-01-16T13:00:00Z"
}
```

---

## Webhooks

Campaign events are delivered via webhooks:

```json
{
  "event": "campaign.completed",
  "timestamp": "2024-01-16T11:45:00Z",
  "data": {
    "campaignId": "camp_xyz789",
    "name": "January Newsletter",
    "stats": {
      "sent": 15418,
      "delivered": 15102,
      "openRate": 0.324,
      "clickRate": 0.085
    }
  }
}
```

### Campaign Events

| Event | Description |
|-------|-------------|
| `campaign.created` | New campaign created |
| `campaign.scheduled` | Campaign scheduled |
| `campaign.started` | Campaign started sending |
| `campaign.paused` | Campaign paused |
| `campaign.resumed` | Campaign resumed |
| `campaign.completed` | Campaign finished |
| `campaign.canceled` | Campaign canceled |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Campaign doesn't exist |
| `INVALID_STATE` | 400 | Action not allowed for current campaign status |
| `VALIDATION_ERROR` | 422 | Request body failed schema validation |
| `DOMAIN_NOT_VERIFIED` | 400 | Sender domain not verified |
| `UNAUTHORIZED` | 401 | API key is missing or invalid |
| `INSUFFICIENT_SCOPE` | 403 | API key does not have the required scope |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |

---

## Related Webhooks

All campaign lifecycle events are delivered via the [Webhooks system](../webhooks.md). Key events include `campaign.created`, `campaign.scheduled`, `campaign.started`, `campaign.paused`, `campaign.resumed`, `campaign.completed`, and `campaign.canceled`. See the webhook reference above for full payload schemas.
