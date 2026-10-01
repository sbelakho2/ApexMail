# Log Streaming

Stream enterprise log batches to an external destination (SIEM, log
aggregator, or your own HTTPS endpoint).

> **Source of truth:** the shipped router and service —
> `services/mail-server/crates/enterprise/src/routes.rs` (`/log-streams`
> routes) and `services/mail-server/crates/enterprise/src/log_streaming.rs`.
> This document was rewritten 2026-10-01 (audit SM15 verifier) to match the
> shipped code; the previous revision described endpoints, request schemas
> and an event vocabulary that the service does not implement.

## What ships today

- **Stream configuration CRUD** — create, get, update, delete, list,
  pause, resume log streams (per-tenant, `ent_log_streams`).
- **Three delivery paths** — `webhook`, `splunk`, and `datadog`. Any other
  `destination_type` value is accepted at create time but **fails
  verification and delivery** with
  `unsupported destination type '<type>'`.
- **Connectivity verification** — `POST /log-streams/{id}/verify` sends a
  test payload to the destination through the same SSRF-guarded,
  address-pinned HTTP client used for delivery.
- **Heartbeat delivery cycle** — a periodic delivery cycle posts a heartbeat
  batch to every active, verified stream and records per-batch delivery
  statistics (`ent_stream_batches`).

> **Not shipped yet:** per-event log payloads (email lifecycle events such
> as `message.delivered`) are **not** streamed today — the delivery cycle
> sends heartbeat batches only. The `log_categories` field is stored as a
> free-form filter label (the server does not validate category names).
> To stay forward-compatible with the platform event vocabulary, use the
> canonical webhook event names for categories — see the
> [webhooks endpoint docs](../api/endpoints/webhooks.md) or
> `KNOWN_WEBHOOK_EVENTS` in
> `services/mail-server/crates/api-server/src/routes/webhooks.rs`
> (`message.*`, `recipient.unsubscribed`, `placement_test.completed`,
> `inbound`, `*`).

## Authentication and scopes

All routes require an authenticated enterprise API key (see
[README](./README.md) for the base URL `https://enterprise.apexmail.ee`).

- Mutations (create, update, delete, pause, resume) require the
  `log-streams:write` scope (or admin).
- Reads and verify require tenant access to the stream's `tenant_id`.

## Create a Log Stream

The request body is strict (`deny_unknown_fields`): it accepts exactly

```text
{tenant_id*, name*, description?, destination_type*, destination_config?,
 log_categories?, batch_size?, batch_interval_seconds?, compression_enabled?}
```

`destination_config` is a free-form JSON object interpreted per destination
type (below). Secret-looking values in it (`token`, `api_key`, `secret`,
`password`, `secret_key`, `access_key`, `client_secret`, `shared_key`) are
encrypted at rest with the tenant id as additional authenticated data, and
masked (`****` + last 4 characters) in every API response.

```bash
curl -X POST https://enterprise.apexmail.ee/log-streams \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acc_parent",
    "name": "SIEM stream",
    "description": "Heartbeats to the security data lake",
    "destination_type": "webhook",
    "destination_config": {
      "url": "https://siem.yourcompany.com/apexmail",
      "secret": "whsec_stream_signing_secret"
    },
    "log_categories": ["message.delivered", "message.bounced"],
    "batch_size": 100,
    "batch_interval_seconds": 30,
    "compression_enabled": false
  }'
```

### Response

Responses use the enterprise envelope `{success, data?, error?, code?}`.
The stream resource looks like:

```json
{
  "success": true,
  "data": {
    "id": "7f9c24e5-1b3d-4a2f-9c8e-6d5f0a1b2c3d",
    "tenant_id": "acc_parent",
    "name": "SIEM stream",
    "description": "Heartbeats to the security data lake",
    "destination_type": "webhook",
    "status": "active",
    "enabled": true,
    "destination_config": {
      "url": "https://siem.yourcompany.com/apexmail",
      "secret": "****cret"
    },
    "log_categories": ["message.delivered", "message.bounced"],
    "batch_size": 100,
    "batch_interval_seconds": 30,
    "compression_enabled": false,
    "format": "json",
    "total_events_delivered": 0,
    "total_bytes_delivered": 0,
    "delivery_failures_count": 0,
    "last_delivery_at": null,
    "last_error": null,
    "last_error_at": null,
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-15T10:30:00Z"
  }
}
```

New streams are created `active` and `enabled`; `format` is always `json`.

## Destination Types

### `webhook`

```json
{
  "url": "https://siem.yourcompany.com/apexmail",
  "secret": "optional HMAC signing secret"
}
```

- Batches are `POST`ed as a JSON array with
  `Content-Type: application/json`.
- When `secret` is configured, each delivery is HMAC-SHA256 signed in the
  same `{timestamp}.{payload}` format as product webhooks and sent in the
  `X-ApexMail-Signature: sha256=<hex>` header.
- The URL is resolved through an SSRF guard and the connection is pinned to
  the resolved address; private/reserved addresses are rejected.

### `splunk`

```json
{
  "url": "https://hec.yourcompany.com:8088",
  "token": "your-hec-token"
}
```

Batches are `POST`ed to `<url>/services/collector/event` with
`Authorization: Splunk <token>`.

### `datadog`

```json
{
  "api_key": "your-datadog-api-key"
}
```

Batches are `POST`ed to the fixed Datadog logs intake
(`https://http-intake.logs.datadoghq.com/api/v2/logs`) with the
`DD-API-KEY` header.

> S3, BigQuery, Snowflake, Kafka, Kinesis and Elasticsearch destinations
> are **not implemented** — creating a stream with those `destination_type`
> values succeeds, but verification returns
> `{"verified": false, "reason": "unsupported destination type '...'"}` and
> every delivery cycle records a failure.

## What Is Delivered

The shipped delivery cycle posts **heartbeat batches** — a JSON array of a
single object:

```json
[
  {
    "ts": "2026-01-15T10:30:00Z",
    "service": "enterprise",
    "type": "heartbeat",
    "stream_id": "7f9c24e5-1b3d-4a2f-9c8e-6d5f0a1b2c3d"
  }
]
```

Per-event log payloads will reuse the platform's canonical event names
(`message.*`, `recipient.unsubscribed`, `placement_test.completed`,
`inbound`, `*`) when they ship; `log_categories` is the intended selector.

## Verify a Destination

`POST /log-streams/{id}/verify` sends a small connectivity-test payload to
the destination:

```bash
curl -X POST https://enterprise.apexmail.ee/log-streams/{stream_id}/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Responses (envelope-wrapped):

- `webhook`: `{"verified": true, "status": 200}` (HTTP status of the test
  POST).
- `splunk` / `datadog`: `{"verified": true}`.
- Unsupported type: `{"verified": false, "reason": "unsupported destination
  type '...'"}`.
- Network/HTTP failures return
  `{"success": false, "error": "...", "code": "VERIFICATION_FAILED"}`.

## Monitoring & Health

`GET /log-streams/{id}/stats` returns the recorded delivery statistics:

```json
{
  "success": true,
  "data": {
    "total_deliveries": 1234,
    "total_events": 1234,
    "total_bytes": 246800,
    "avg_duration_ms": 84.5,
    "success_rate": 0.998
  }
}
```

The stream resource itself carries `total_events_delivered`,
`total_bytes_delivered`, `delivery_failures_count`, `last_delivery_at`,
`last_error` and `last_error_at`, so polling `GET /log-streams/{id}` is
enough to watch health.

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/log-streams` | POST | Create a stream (body above) |
| `/log-streams/{id}` | GET | Get stream details |
| `/log-streams/{id}` | PUT | Update `{name?, description?, destination_config?, log_categories?}` |
| `/log-streams/{id}` | DELETE | Delete the stream |
| `/log-streams/tenant/{tenant_id}` | GET | List a tenant's streams |
| `/log-streams/{id}/pause` | POST | Pause the stream |
| `/log-streams/{id}/resume` | POST | Resume the stream |
| `/log-streams/{id}/verify` | POST | Send a connectivity test to the destination |
| `/log-streams/{id}/stats` | GET | Delivery statistics |

There is no bare `GET /log-streams` — listing is tenant-scoped.

## Best Practices

1. **Use `webhook` with an HMAC secret** — deliveries are signed, so your
   endpoint can reject forgeries.
2. **Call `verify` after create/update** — it exercises the exact SSRF
   guard and HTTP path a real delivery uses.
3. **Watch `delivery_failures_count` / `last_error`** on the stream
   resource; the delivery cycle records every failure there.
4. **Keep `log_categories` on the canonical event vocabulary** so category
   selectors keep working when per-event payloads ship.
