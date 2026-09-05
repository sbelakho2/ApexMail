# Webhook Endpoints

> **Note:** Webhook configuration and management is documented at [`docs/api/webhooks.md`](../webhooks.md).

## Overview

Webhooks allow you to receive real-time HTTP POST notifications when email events occur in your ApexMail account.

For complete documentation on creating, listing, testing, and managing webhooks, including event types, retry policies, and signature verification, see the [Webhooks Reference](../webhooks.md).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/webhooks` | Register a new webhook endpoint |
| GET | `/v1/webhooks` | List all registered webhooks |
| GET | `/v1/webhooks/:id` | Get webhook details |
| PUT | `/v1/webhooks/:id` | Update webhook configuration |
| DELETE | `/v1/webhooks/:id` | Delete a webhook |
| POST | `/v1/webhooks/:id/test` | Send a test event to the webhook |

See [Webhooks Reference](../webhooks.md) for detailed documentation, including event types, retry logic, and signature verification.
