+++
title = "API Reference"
description = "Authentication, core message endpoints, and the fastest way to send and inspect email with ApexMail."
template = "prose.html"
weight = 1
+++

## Authentication

Authenticate every request with the `X-API-Key` header over HTTPS.

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@example.com",
    "to": ["user@example.com"],
    "subject": "Welcome",
    "html": "<h1>Hello from ApexMail</h1>",
    "type": "transactional"
  }'
```

## Core Flows

- `POST /v1/messages` queues a transactional or campaign send.
- `GET /v1/messages` lists recent message activity for your tenant.
- `GET /v1/messages/{id}` retrieves the current status and delivery state for one message.
- `POST /v1/messages/{id}/cancel` stops a queued or scheduled message before delivery.
- `GET /v1/events` lets you retrieve delivery, open, click, and related event history.

## Practical Notes

- Use idempotency keys when your sender may retry the same write request.
- Keep API keys server-side; never embed them in browser code.
- Use the [API Console](/api-console) to test payloads before wiring them into your application.