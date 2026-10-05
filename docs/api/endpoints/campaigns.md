# Campaigns API

> **Base path:** `/v1/campaigns`
> **Required scopes:** `campaigns:read` (GET), `campaigns:write` (POST / PATCH / DELETE)
> **Rate limit:** 60 requests/minute per API key
> **Idempotency:** Supported via `Idempotency-Key` header for POST endpoints
> **Content-Type:** `application/json`

The Campaigns API lets you create and manage email marketing campaigns. A
campaign targets a **lists-based audience** (`listIds` / `excludeListIds`),
optionally narrowed by a saved **segment** (`segmentId` — see the Segments
API): the audience is the union of the campaign's lists and the segment's
lists, filtered by the segment's tag/status match rules, minus the union of
both exclude sets. Delivery is performed by the platform's campaign worker,
which claims due scheduled campaigns, drains recipient rows through the
shared send-admission gate (suppression + quota), honors the campaign's
send settings (throttling, dedicated-IP pool, send-time optimization
window), runs A/B tests when configured, and finalizes the campaign to
`sent` / `partial`.

> This document describes the IMPLEMENTED contract. Field names are
> snake_case (`template_id`, `scheduled_at`, `list_ids`); the documented
> camelCase aliases (`templateId`, `scheduledAt`, `listIds`,
> `excludeListIds`, `segmentId`, `previewText`, `fromName`, `replyTo`,
> `trackOpens`, `trackClicks`, `utmParams`, `abTest`) are accepted on
> request bodies. Responses use snake_case.

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
| PATCH | `/v1/campaigns/:id` | Update a draft/scheduled/paused campaign |
| DELETE | `/v1/campaigns/:id` | Delete a draft or canceled campaign |
| POST | `/v1/campaigns/:id/send` | Send a draft campaign now |
| POST | `/v1/campaigns/:id/schedule` | Schedule a draft campaign |
| POST | `/v1/campaigns/:id/pause` | Pause sending |
| POST | `/v1/campaigns/:id/resume` | Resume sending |
| POST | `/v1/campaigns/:id/resend` | Requeue failed recipients of a finished campaign |
| GET | `/v1/campaigns/:id/stats` | Get campaign statistics |

---

## Create Campaign

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
  "variables": { "month": "January" },
  "listIds": ["0b97a7f2-1111-4222-8333-444455556666"],
  "segmentId": "8c42d0bb-3333-4444-8555-666677778888",
  "excludeListIds": ["7c31c9aa-2222-4333-9444-555566667777"],
  "trackOpens": true,
  "trackClicks": true,
  "utmParams": { "source": "email", "medium": "newsletter" },
  "settings": { "sendTimeOptimization": true, "timezone": "America/New_York", "throttleRate": 1000, "ipPool": "dedicated-eu-1" },
  "scheduledAt": "2026-01-20T09:00:00Z"
}
```

Exactly one content source is required before `send`: `templateId` **or**
raw `html` (optionally with `text`) — providing both is a 422.

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Campaign name (unique per tenant, max 200 characters) |
| `subject` | string | ✓ | Email subject line (max 500 characters). Supports `{{first_name}}`, `{{name}}`, `{{email}}` and `variables` merge tags |
| `previewText` | string | | Inbox preview snippet (max 300 characters); rendered as the standard hidden preheader |
| `from` | string | | Verified sender address. Required before `send` |
| `fromName` | string | | Display name for the MIME `From:` header (max 120 characters, single line) |
| `replyTo` | string | | Reply-To address (single email address) |
| `templateId` | string | | Template to render (must exist in the tenant) — alternative to raw `html` |
| `html` / `text` | string | | Raw bodies (max 1 MiB each) — the alternative to `templateId` |
| `variables` | object | | Global merge variables (string values, max 200 entries); contact identity (`email`, `name`, `first_name`) always wins a collision |
| `listIds` | string[] | | Contact lists whose subscribed members receive the campaign (max 50) |
| `segmentId` | string | | Saved segment whose lists and tag/status rules merge into the audience |
| `excludeListIds` | string[] | | Members of these lists are excluded from the audience (max 50) |
| `trackOpens` / `trackClicks` | boolean | | Per-campaign tracking toggles (default true); the unsubscribe affordance is always present |
| `utmParams` | object | | UTM parameters appended to every absolute link at render time (`source`, `medium`, `campaign`, `term`, `content`) |
| `settings` | object | | Send settings — see below |
| `scheduledAt` | string | | ISO 8601 due time; when present the campaign is born `scheduled` and the worker sends it when due |

An empty audience definition (no lists, no segment) targets **nobody** —
never the whole contact base. Sending to an empty audience converges the
campaign to `sent` with `recipientCount: 0`.

### Settings object

| Field | Type | Description |
|-------|------|-------------|
| `sendTimeOptimization` | boolean | Schedule each recipient at their optimal engagement hour (takes precedence over `scheduledAt` distribution) |
| `timezone` | string | IANA timezone used to interpret send-time-optimization windows and scheduling displays |
| `throttleRate` | number | Max emails per hour for this campaign's drain (0 = unlimited) |
| `ipPool` | string | Dedicated-IP pool (`dedicated_ips.ses_pool_name`) to route the campaign through |

### A/B testing (`abTest`)

```json
{
  "abTest": {
    "arms": [
      { "templateId": "tmpl_a" },
      { "templateId": "tmpl_b", "subject": "Alternative subject" }
    ],
    "testPercentage": 0.2,
    "metric": "open",
    "waitMinutes": 60
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `arms` | array | 2–4 arms, each `{templateId, subject?}` (templates must exist in the tenant) |
| `testPercentage` | number | Share of the audience in the test phase (0.1–0.5, default 0.2) |
| `metric` | string | `open` or `click` (default `open`) — the winner metric |
| `waitMinutes` | number | Test window before the winner is chosen (5–1440, default 60) |

The worker sends the sampled test recipients across the arms, records
per-arm opens/clicks from the events stream, picks the arm with the best
metric rate after the window, sends the winning content to the remaining
audience, and emits a `campaign.ab_winner_selected` webhook. Arm outcomes
are visible in the campaign stats.

### Response

`201 Created`

```json
{
  "id": "0f8b7c2e1a2b3c4d5e6f7a8b9c",
  "name": "January Newsletter",
  "subject": "Your January Update",
  "template_id": "3aJk2LmNopQrStUvWxYz012345",
  "from_email": "newsletter@yourcompany.com",
  "status": "draft",
  "scheduled_at": null,
  "list_ids": ["0b97a7f2-1111-4222-8333-444455556666"],
  "exclude_list_ids": [],
  "sent_count": 0,
  "recipient_count": 0,
  "created_at": "2026-01-15T10:30:00+00:00",
  "updated_at": "2026-01-15T10:30:00+00:00"
}
```

### Campaign Status Values

| Status | Description |
|--------|-------------|
| `draft` | Campaign created but not sent |
| `scheduled` | Scheduled for future sending (worker sends when due) |
| `sending` | Audience resolved; the worker is draining recipients |
| `paused` | Sending paused (worker claims skip paused campaigns) |
| `sent` | Drain finished, every recipient enqueued |
| `partial` | Drain finished with failed/suppressed recipients |
| `resending` | A resend job is queued/processing |
| `canceled` | Campaign canceled |

---

## List Campaigns

Retrieve a paginated list of campaigns (keyset cursor pagination).

### Request

```http
GET /v1/campaigns?limit=20
X-API-Key: {{api_key}}
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | number | 20 | Results per page (max: 100) |
| `offset` | number | 0 | Offset fallback pagination |
| `cursor` | string | | Pagination cursor (`meta.nextCursor` of the previous page) |
| `status` | string | | Filter by campaign status |
| `search` | string | | Case-insensitive substring match on the campaign name |
| `startDate` / `endDate` | string | | Created-at window (ISO 8601; `startDate` must not exceed `endDate`) |

### Response

```json
{
  "data": [
    {
      "id": "0f8b7c2e1a2b3c4d5e6f7a8b9c",
      "name": "January Newsletter",
      "subject": "Your January Update",
      "template_id": "3aJk2LmNopQrStUvWxYz012345",
      "from_email": "newsletter@yourcompany.com",
      "status": "sent",
      "scheduled_at": null,
      "list_ids": ["0b97a7f2-1111-4222-8333-444455556666"],
      "exclude_list_ids": [],
      "sent_count": 152,
      "recipient_count": 154,
      "created_at": "2026-01-15T10:30:00+00:00",
      "updated_at": "2026-01-16T11:45:00+00:00"
    }
  ],
  "error": null,
  "meta": {
    "hasMore": true,
    "nextCursor": "NTgyYj..."
  }
}
```

Responses carry an `ETag`; send `If-None-Match` to get a `304`.

---

## Get Campaign Details

```http
GET /v1/campaigns/:id
X-API-Key: {{api_key}}
```

Returns the same shape as a list row, including `recipient_count` (the
current audience size from `campaign_recipients`).

---

## Update Campaign

Update a draft, scheduled or paused campaign. Campaigns that are `sending`,
`sent`, `partial`, `resending` or `canceled` cannot be updated (`409`).

```http
PATCH /v1/campaigns/:id
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

All fields are optional; at least one must be present. Semantics match
Create. Setting `scheduledAt` on a `draft` campaign moves it to `scheduled`.

```json
{
  "name": "January Newsletter - Updated",
  "subject": "Your January Update - Don't Miss Out!",
  "scheduledAt": "2026-01-21T09:00:00Z"
}
```

### Response

`200` with the updated campaign object.

---

## Delete Campaign

Delete a draft or canceled campaign. Any other status is a `409`.

```http
DELETE /v1/campaigns/:id
X-API-Key: {{api_key}}
```

`204 No Content` on success.

---

## Send Campaign

Immediately start sending a draft campaign. The API resolves the audience
synchronously and returns the REAL outcome; the worker drains the resolved
recipients through suppression + quota admission and the delivery pipeline.

```http
POST /v1/campaigns/:id/send
X-API-Key: {{api_key}}
```

### Response

`200` with the campaign object (`status: "sending"`, `recipient_count`
audience size). A send with a **zero audience** converges to `sent`
immediately.

### Errors

- `400` if the campaign has no `from` sender or no `template` set, or its
  status is not `draft`
- `409` if the campaign status changed concurrently

---

## Schedule Campaign

Schedule a draft campaign for future delivery.

```http
POST /v1/campaigns/:id/schedule
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "scheduledAt": "2026-01-20T09:00:00Z"
}
```

### Response

`200` with the campaign object (`status: "scheduled"`, `scheduled_at` set).
The worker claims the campaign when the due time passes. A due time in the
past is claimed on the next worker tick.

---

## Pause Campaign

Pause a `sending`, `scheduled` or `resending` campaign. The worker's claims
all require a drainable status, so pausing stops the drain mid-flight; a
paused scheduled campaign does not start.

```http
POST /v1/campaigns/:id/pause
X-API-Key: {{api_key}}
```

`200` with the campaign object (`status: "paused"`).

---

## Resume Campaign

Resume a `paused` or `draft` campaign. A paused scheduled campaign whose due
time is still in the future resumes into `scheduled`; otherwise it resumes
into `sending` and the worker continues where it stopped. Per-recipient
idempotency keys make the continuation exactly-once.

```http
POST /v1/campaigns/:id/resume
X-API-Key: {{api_key}}
```

`200` with the campaign object.

---

## Resend Campaign

Requeue the FAILED recipients of a finished (`sent` / `partial`) campaign.
Suppressed recipients are never retried; already-sent recipients are never
re-sent. Returns a `campaign_jobs` row that the worker drains.

```http
POST /v1/campaigns/:id/resend
X-API-Key: {{api_key}}
```

### Response

```json
{
  "job_id": "9a1b2c3d-1111-4222-8333-444455556666",
  "campaign_id": "0f8b7c2e1a2b3c4d5e6f7a8b9c",
  "status": "queued"
}
```

The campaign moves to `resending`; when the worker finishes the drain it
converges back to `sent` / `partial`.

---

## Get Campaign Statistics

Retrieve per-campaign delivery and engagement statistics, joined through the
per-recipient `message_id` back-reference written by the send pipeline.

```http
GET /v1/campaigns/:id/stats
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "0f8b7c2e1a2b3c4d5e6f7a8b9c",
  "name": "January Newsletter",
  "status": "sent",
  "audience": {
    "total": 154,
    "queued": 0,
    "in_flight": 0,
    "sent": 152,
    "failed": 1,
    "suppressed": 1
  },
  "delivery": {
    "enqueued": 152,
    "delivered": 148,
    "bounced": 4,
    "failed": 0,
    "bounce_rate": 0.0263
  },
  "engagement": {
    "opens": 210,
    "unique_opens": 48,
    "open_rate": 0.3158,
    "clicks": 17,
    "unique_clicks": 12,
    "click_rate": 0.0789,
    "unsubscribes": 1,
    "devices": { "desktop": 22, "mobile": 14, "tablet": 3, "other": 2 }
  },
  "ab_test": {
    "arms": [
      { "arm": 0, "template_id": "tmpl_a", "trials": 30, "successes": 9 },
      { "arm": 1, "template_id": "tmpl_b", "subject": "Alternative subject", "trials": 31, "successes": 14 }
    ],
    "winner_arm": 1,
    "metric": "opened"
  }
}
```

`devices` classifies unique open events by user agent (desktop / mobile /
tablet / other). `ab_test` appears for A/B campaigns with per-arm trials,
successes, the chosen `winner_arm`, and the metric they were evaluated on.
(Per-link click tables, client/geo breakdowns and hourly timelines remain
unimplemented — they are not part of this contract.)

---

## Campaign lifecycle webhooks

Subscribe to the campaign lifecycle events on the Webhooks API
(`POST /v1/webhooks`, `events: ["campaign.started", ...]`):

| Event | Fired when |
|-------|-----------|
| `campaign.started` | An audience is resolved and the first recipients are queued (scheduled or immediate send) |
| `campaign.ab_winner_selected` | An A/B test window closed and the winning arm was promoted onto the remaining audience |
| `campaign.completed` | The drain finished; `status` converged to `sent` or `partial` |

Each delivery carries the standard envelope
`{id, type, tenantId, timestamp, data}` with the campaign id and outcome
counts under `data`. Message-level outcomes additionally fire
`message.accepted` (transport acceptance) and — from the provider feedback
and tracking pipelines — `message.delivered`, `message.bounced`,
`message.complained`, `message.opened` and `message.clicked`.

---

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| `400` | Malformed request, invalid state transition, or missing send prerequisites |
| `401` | API key is missing or invalid |
| `403` | API key does not have the required scope |
| `404` | Campaign (or referenced template/list) doesn't exist |
| `409` | Duplicate name, or the campaign state changed before the write |
| `422` | Request body failed schema validation (unknown fields are rejected) |
| `429` | Too many requests |
