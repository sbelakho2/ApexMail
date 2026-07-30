+++
title = "OpenAPI Specification"
description = "Complete OpenAPI 3.1 specification for the ApexMail API. Downloadable, machine-readable, and validated in CI."
template = "prose.html"
weight = 99

[extra]
last_updated = "2026-07-29"
+++

The ApexMail API is fully documented in OpenAPI 3.1 format. The specification is the canonical source for endpoint schemas, request/response models, error codes, and authentication.

## Download

The OpenAPI specification is available for download:

- **[openapi.yaml](/specs/openapi.yaml)** — OpenAPI 3.1 YAML specification

You can import this file into API tools such as:

- [Swagger Editor](https://editor.swagger.io/)
- [Postman](https://www.postman.com/)
- [Insomnia](https://insomnia.rest/)
- [Redoc](https://redocly.com/redoc)
- Any OpenAPI-compatible client generator

## Specification Contents

The specification covers:

| Area | Endpoints |
|------|-----------|
| Messages | `POST /v1/messages`, `GET /v1/messages`, `GET /v1/messages/{id}`, `POST /v1/messages/{id}/cancel`, `POST /v1/messages/batch` |
| Events | `GET /v1/events` |
| Domains | `GET /v1/domains`, `POST /v1/domains`, `POST /v1/domains/{id}/verify`, `DELETE /v1/domains/{id}` |
| Suppressions | `GET /v1/suppressions`, `POST /v1/suppressions`, `DELETE /v1/suppressions/{recipient}` |
| Webhooks | `GET /v1/webhooks`, `POST /v1/webhooks`, `DELETE /v1/webhooks/{id}` |
| API Keys | `GET /v1/api-keys`, `POST /v1/api-keys`, `DELETE /v1/api-keys/{id}` |
| Team | `GET /v1/team`, `POST /v1/team/invite` |
| Analytics | `GET /v1/analytics/summary` |
| Dedicated IPs | `GET /v1/ips`, `GET /v1/ips/pools` |
| Account | `GET /v1/account` |
| Email Grader | `POST /v1/grader/check`, `POST /v1/grader/submit` |

Each endpoint includes:
- HTTP method and path
- Authentication requirements
- Idempotency parameters
- Request body schema with field-level types, constraints, and defaults
- Response schemas for all status codes
- Error models for all error responses
- Rate-limit header documentation
- Pagination parameters

## Client Generation

The OpenAPI specification is validated in CI and can be used to generate typed SDK clients:

```bash
# Validate the specification
npx @redocly/cli lint openapi.yaml

# Generate a TypeScript client (example)
npx openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o ./generated-client
```

Generated clients compile against the specification and are used as SDK test clients during CI validation.

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-29 | Initial OpenAPI 3.1 specification covering all v1 endpoints |

## Schema Synchronization

The OpenAPI specification and the [API Reference documentation](/docs/api/) are maintained in synchronization. Changes to endpoint schemas are reflected in both the specification and the documentation. Builds fail when undocumented response codes or schema mismatches are detected.

For a narrative guide to using the API, see the [Quickstart](/quickstart/) and [API Reference](/docs/api/).
