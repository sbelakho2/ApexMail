# Real-Time Event Streaming (SSE)

ApexMail provides real-time event streaming via Server-Sent Events (SSE),
enabling live delivery tracking in your application without polling.

## Overview

When an email event occurs (delivered, opened, clicked, bounced), the tracking
service publishes it to a Redis Pub/Sub channel. Clients connected to the SSE
endpoint receive events in real time as they happen.

```
┌──────────┐    SMTP/webhook    ┌─────────────────┐    Redis Pub/Sub    ┌────────────┐
│  Mailbox  │ ───────────────▶ │ Tracking Service │ ──────────────────▶ │ SSE Stream │
│  Provider │                   │  (processor)     │                     │ (client)   │
└──────────┘                   └─────────────────┘                     └────────────┘
```

## Authentication

SSE connections use short-lived stream tokens (not your API key). This limits
the blast radius if a token is intercepted on a long-lived connection.

### 1. Obtain a Stream Token

```bash
curl -X POST https://api.apexmail.ee/v1/stream/token \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "ttl_seconds": 300 }'
```

**Response:**

```json
{
  "token": "eyJhbGciOi...",
  "expires_at": "2025-01-15T10:35:00Z",
  "ttl_seconds": 300
}
```

| Parameter     | Type   | Default | Range       | Description                     |
|---------------|--------|---------|-------------|---------------------------------|
| `ttl_seconds` | number | 300     | 60 – 3600   | Token lifetime in seconds       |

### 2. Connect to the SSE Stream

```bash
curl -N "https://track.apexmail.ee/v1/stream?token=eyJhbGciOi..."
```

Or in JavaScript:

```javascript
const token = await getStreamToken();
const source = new EventSource(
  `https://track.apexmail.ee/v1/stream?token=${token}`
);

source.addEventListener('message', (event) => {
  const data = JSON.parse(event.data);
  console.log(`${data.event_type} for ${data.message_id}`);
});

source.addEventListener('error', (event) => {
  // Token expired or connection dropped — obtain a new token and reconnect
  source.close();
  reconnect();
});
```

## Query Parameters

| Parameter      | Type   | Default | Description                                       |
|----------------|--------|---------|---------------------------------------------------|
| `token`        | string | —       | **Required.** Stream token from `/v1/stream/token` |
| `event_types`  | string | all     | Comma-separated filter: `delivered,opened,clicked`  |

### Supported Event Types

- `delivered` — Email accepted by the recipient's mail server
- `opened` — Recipient opened the email (pixel tracked)
- `clicked` — Recipient clicked a tracked link
- `bounced` — Email bounced (hard or soft)
- `complained` — Spam complaint received
- `unsubscribed` — Recipient unsubscribed

## Event Format

Each SSE message is a JSON object:

```json
{
  "event_type": "delivered",
  "message_id": "msg_abc123",
  "recipient": "user@example.com",
  "timestamp": "2025-01-15T10:30:00Z",
  "metadata": {}
}
```

## Connection Limits

| Limit                      | Value       |
|----------------------------|-------------|
| Max connections per tenant | 5           |
| Max connection duration    | 1 hour      |
| Keepalive interval         | 15 seconds  |
| Token max TTL              | 1 hour      |

When the connection limit is reached, new connections receive HTTP 429.
When the max duration expires, the stream closes gracefully — reconnect
with a fresh token.

## Architecture Notes

- Events are published to Redis channel `events:{tenant_id}` after the
  tracking processor commits them to PostgreSQL.
- The SSE endpoint runs on the **tracking service** (port 3001), not the
  API server (port 3000). Route accordingly in your load balancer.
- Stream tokens are HMAC-SHA256 signed using the shared `TRACKING_SECRET_KEY`.
  Both the API server (issuer) and tracking service (verifier) must have
  the same key.

## Configuration

| Variable              | Service           | Description                              |
|-----------------------|-------------------|------------------------------------------|
| `TRACKING_SECRET_KEY` | API + Tracking    | Shared HMAC secret (min 32 chars in prod)|
