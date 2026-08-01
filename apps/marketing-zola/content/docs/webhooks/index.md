+++
title = "Webhooks"
description = "Deliver ApexMail events to your own systems for automation, observability, and support workflows."
template = "prose.html"
weight = 4
+++

## Why Webhooks

Polling works for debugging, but production systems usually want event delivery as changes happen. Webhooks let you push mail events into your own queue workers, CRMs, support tooling, or analytics pipelines.

## Typical Event Consumers

- Update customer timelines when a message is delivered or bounced.
- Trigger remediation flows when complaint or suppression-related events appear.
- Sync open and click activity into marketing or lifecycle automation systems.

---

## Event Catalog

Every webhook event shares a common top-level envelope:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique event identifier (e.g. `"evt_s1a2b3c4d5"`). Use for deduplication. |
| `event` | string | Event type name (e.g. `"message.sent"`). |
| `timestamp` | string | ISO 8601 timestamp of when the event occurred. |
| `data` | object | Type-specific payload (varies by event type). |

The following sections document each event type and the shape of its `data` payload.

### Event Summary

| Event | Trigger | Dedup key in `data` |
|-------|---------|---------------------|
| `message.sent` | Message accepted for delivery | `data.messageId` |
| `message.delivered` | Delivery confirmed by receiving MTA | `data.messageId` |
| `message.opened` | Recipient opens the email | `data.messageId` |
| `message.clicked` | Recipient clicks a link | `data.messageId` |
| `message.bounced` | Delivery permanently or temporarily rejected | `data.messageId` |
| `message.complained` | Recipient marks as spam | `data.messageId` |
| `recipient.unsubscribed` | Recipient unsubscribes | `data.email` |

---

### `message.sent`

Triggered when a message is accepted for delivery.

```json
{
  "id": "evt_s1a2b3c4d5",
  "event": "message.sent",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "from": "sender@company.com",
    "subject": "Welcome!",
    "campaignId": "camp_xyz789",
    "metadata": {
      "userId": "usr_123"
    }
  }
}
```

### `message.delivered`

Triggered when delivery is confirmed.

```json
{
  "id": "evt_d6e7f8g9h0",
  "event": "message.delivered",
  "timestamp": "2024-01-15T10:30:10Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "deliveredAt": "2024-01-15T10:30:10Z",
    "smtpResponse": "250 OK"
  }
}
```

### `message.opened`

Triggered when recipient opens the email.

```json
{
  "id": "evt_o1p2q3r4s5",
  "event": "message.opened",
  "timestamp": "2024-01-15T14:30:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "openedAt": "2024-01-15T14:30:00Z",
    "isFirstOpen": true,
    "openCount": 1,
    "context": {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "device": "mobile",
      "os": "iOS 17",
      "client": "Apple Mail",
      "geo": {
        "country": "US",
        "region": "CA",
        "city": "San Francisco"
      }
    }
  }
}
```

### `message.clicked`

Triggered when recipient clicks a link.

```json
{
  "id": "evt_c6d7e8f9g0",
  "event": "message.clicked",
  "timestamp": "2024-01-15T14:35:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "clickedAt": "2024-01-15T14:35:00Z",
    "url": "https://company.com/product",
    "linkId": "link_001",
    "isFirstClick": true,
    "clickCount": 1,
    "context": {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "device": "mobile"
    }
  }
}
```

### `message.bounced`

Triggered when email bounces.

```json
{
  "id": "evt_b1o2u3n4c5",
  "event": "message.bounced",
  "timestamp": "2024-01-15T10:30:15Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "invalid@example.com",
    "bounceType": "hard",
    "bounceCategory": "invalid_recipient",
    "bounceCode": "550",
    "bounceMessage": "User unknown",
    "diagnosticCode": "smtp; 550 5.1.1 User unknown"
  }
}
```

| Type | Description | Action |
|------|-------------|--------|
| `hard` | Permanent failure | Remove from list |
| `soft` | Temporary failure | Retry later |
| `block` | Blocked by receiver | Check reputation |

### `message.complained`

Triggered when recipient marks email as spam.

```json
{
  "id": "evt_m6c7o8m9p0",
  "event": "message.complained",
  "timestamp": "2024-01-15T16:00:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "complainedAt": "2024-01-15T16:00:00Z",
    "feedbackType": "abuse",
    "feedbackId": "fb_123"
  }
}
```

### `recipient.unsubscribed`

Triggered when recipient unsubscribes.

```json
{
  "id": "evt_u1n2s3u4b5",
  "event": "recipient.unsubscribed",
  "timestamp": "2024-01-15T14:40:00Z",
  "data": {
    "email": "user@example.com",
    "unsubscribedAt": "2024-01-15T14:40:00Z",
    "reason": "user_request",
    "method": "one_click",
    "listIds": ["list_abc123"]
  }
}
```

---

## Webhook Security

### Signature Header

Every webhook POST request includes a signature header that carries the timestamp and HMAC digest in a single value:

```
X-ApexMail-Signature: t=1705312200,v1=abc123...
```

The signature header uses the `t=` and `v1=` parameter format:

| Parameter | Type | Description |
|-----------|------|-------------|
| `t` | Unix timestamp (seconds) | When the signature was created |
| `v1` | Hex-encoded HMAC-SHA256 | The computed signature over the canonical payload |

The timestamp inside the signature header matches the value in the `X-ApexMail-Timestamp` response header (also provided as a standalone header for convenience).

### Timestamp Header

A separate `X-ApexMail-Timestamp` header carries the same Unix timestamp for easy timestamp-only validation without parsing the signature value:

```
X-ApexMail-Timestamp: 1705312200
```

| Header | Type | Description |
|--------|------|-------------|
| `X-ApexMail-Signature` | `t=<ts>,v1=<hex>` | Signature with embedded timestamp and HMAC-SHA256 digest |
| `X-ApexMail-Timestamp` | Unix timestamp (seconds) | Convenience header; always matches `t=` in signature |

### Signature Construction

ApexMail computes the signature using **HMAC-SHA256** over the canonical payload string:

```
"{timestamp}.{raw_request_body}"
```

where `{timestamp}` is the Unix-epoch seconds value and `{raw_request_body}` is the exact byte sequence of the HTTP request body (before any JSON parsing or charset conversion).

The signing key is your **Base64-decoded webhook secret**. Webhook secrets are generated and displayed as Base64 strings in the dashboard. You must Base64-decode the secret before using it as the HMAC key.

**Steps to verify on your side:**

1. Extract `t` and `v1` from the `X-ApexMail-Signature` header.
2. Read the raw request body bytes (do not parse or re-serialize JSON).
3. Construct the canonical payload: `f"{t}.{raw_body_bytes}"`.
4. Base64-decode your webhook secret to get the raw key bytes.
5. Compute `HMAC-SHA256(key=decoded_secret, message=canonical_payload)` and hex-encode the result.
6. Compare the computed hex digest against `v1` using a constant-time comparison.

### Replay Prevention

Verify that the `t` value (from the signature header or the `X-ApexMail-Timestamp` header) is within **5 minutes (300 seconds)** of your current clock. Reject any payload with a stale timestamp.

**Recommended tolerance:** `abs(now - t) > 300` → reject with HTTP 400.

Adjust for clock skew between your servers and ApexMail's signing infrastructure. If your servers drift, increase the tolerance window instead of disabling the check.

### Raw-Body Canonicalization

Always compute the signature over the **raw request body bytes** as received on the wire. Do not:
- Parse the body as JSON and re-serialize it
- Apply any charset transcoding
- Strip or reorder whitespace
- Apply any framing or pretty-printing

Any deviation from the exact byte sequence will produce a different signature and cause verification to fail.

### Secret Rotation

Webhooks support dual-secret rotation: when you add a new secret, ApexMail continues to accept the previous secret for a configurable transition window, allowing you to rotate without downtime.

During rotation, verify the signature against both the current and previous secrets. Accept the payload if either secret produces a match.

### Manual Verification Reference

```python
import base64
import hashlib
import hmac
import time


def verify_webhook_signature(
    raw_body: bytes,
    signature_header: str,
    secret_b64: str,
    *,
    tolerance_seconds: int = 300,
) -> bool:
    """Verify an ApexMail webhook signature.

    Args:
        raw_body: The raw request body bytes (before JSON parsing).
        signature_header: The value of the X-ApexMail-Signature header.
        secret_b64: Your Base64-encoded webhook signing secret.
        tolerance_seconds: Max allowed clock skew (default 300s = 5 min).

    Returns:
        True if the signature is valid and the timestamp is fresh.
    """
    params = {}
    for part in signature_header.split(","):
        key, _, value = part.partition("=")
        params[key.strip()] = value.strip()

    t = int(params.get("t", "0"))
    v1 = params.get("v1", "")

    if not t or not v1:
        return False

    if abs(int(time.time()) - t) > tolerance_seconds:
        return False

    decoded_key = base64.b64decode(secret_b64)
    canonical = f"{t}.".encode() + raw_body
    expected = hmac.new(decoded_key, canonical, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, v1)


def verify_webhook_signature_with_rotation(
    raw_body: bytes,
    signature_header: str,
    current_secret_b64: str,
    previous_secret_b64: str | None = None,
    *,
    tolerance_seconds: int = 300,
) -> bool:
    """Verify with dual-secret fallback for rotation windows."""
    if verify_webhook_signature(
        raw_body, signature_header, current_secret_b64,
        tolerance_seconds=tolerance_seconds,
    ):
        return True
    if previous_secret_b64:
        return verify_webhook_signature(
            raw_body, signature_header, previous_secret_b64,
            tolerance_seconds=tolerance_seconds,
        )
    return False
```

### SDK Helpers

The first-party SDKs (currently in development) will provide helper functions for signature verification. See the [SDKs](/docs/sdks/) page for status. Until the SDKs ship, verify signatures against the raw request body as shown above.

---

## Retry Schedule

ApexMail retries failed webhook deliveries with exponential backoff.

**Retryable failure conditions:**

- Network errors (connection refused, DNS failure, timeout)
- HTTP `408` (Request Timeout)
- HTTP `429` (Too Many Requests)
- HTTP `5xx` (Server errors)

**Default retry policy:**

| Setting | Default |
|---------|---------|
| Base delay | 30 seconds |
| Backoff multiplier | Exponential (2× per attempt) |
| Max retries | 3 |
| Max individual delay | 1 hour |

When a receiving endpoint returns `429` or `503` with a `Retry-After` header, ApexMail honors that delay instead of the computed backoff.

After the retry budget is exhausted, the failed delivery is recorded and removed from the pending queue. Failed events are retained for 7 days and can be manually replayed from the dashboard.

---

## Timeout

- Webhook endpoints must respond within **30 seconds**.
- If no response is received within 30 seconds, the delivery is treated as a timeout failure and enters the retry schedule.
- Endpoints should return `2xx` status immediately and process asynchronously to avoid timeouts.

---

## Accepted Success Codes

Any HTTP `2xx` status code (200–299) is treated as a successful delivery. Non-`2xx` responses trigger retry behavior as described above.

---

## Duplicate Handling

Webhooks use **at-least-once delivery**. The same event may be delivered multiple times, especially during retries. Every event carries a unique `id` field (e.g. `"evt_s1a2b3c4d5"`) that you can use for deduplication.

Make your handlers idempotent:

```python
def handle_webhook(event: dict) -> None:
    dedupe_key = f"webhook:{event['id']}"

    is_new = cache.set_if_absent(dedupe_key, '1', ttl_seconds=86400)
    if not is_new:
        return  # Already processed

    process_event(event)
```

Use the `id` field as the deduplication key. Store processed event IDs for at least **24 hours** to cover the full retry window. For recipient-level events (`recipient.unsubscribed`) that lack a `messageId`, the `id` field is the canonical deduplication key.

---

## Ordering Guarantees

Webhook events are **not guaranteed to be delivered in order**. Multiple events for the same message (e.g., `message.sent` followed by `message.delivered`) may arrive out of sequence. Always rely on the `timestamp` field in the event payload, not delivery order, to determine event chronology.

---

## Manual Replay

Failed webhook deliveries can be manually replayed from the dashboard or programmatically via the REST API.

### Dashboard

1. Go to **Settings** → **Webhooks**
2. Click on your endpoint
3. View **Failed Deliveries** tab
4. Retry individual events or download failed events for offline inspection

### REST API Endpoint

Replay individual failed events programmatically:

```
POST /v1/webhooks/{webhook_id}/events/{event_id}/replay
```

The endpoint accepts an empty body and returns `202 Accepted` if the event is queued for redelivery. Only events in `failed` status and within the 7-day retention window are eligible.

Failed events are retained for 7 days.

---

## Integration Guidance

- **Verify every payload** using the signature header before taking any action. Reject unverified payloads with HTTP `401`.
- **Make handlers idempotent** by deduplicating on the `id` field. Webhooks use at-least-once delivery and the same event can arrive multiple times.
- **Respond with `2xx` immediately** (200, 201, or 202 accepted). Do not block the webhook request on downstream work — push it to an internal queue instead.
- **Read the raw body** before letting any framework parse it. Pass the raw bytes to the signature verification function; do not parse and re-serialize.
- **Return `4xx` for client errors** (malformed payload, invalid signature, stale timestamp) so ApexMail can distinguish permanent failures from transient ones.
- **Monitor the Failed Deliveries tab** in the dashboard and set up alerts so you can investigate and replay events before the 7-day retention window expires.

For request-driven inspection alongside event delivery, use the [API Reference](/docs/api/) and [Analytics](/docs/analytics/) guides together.
