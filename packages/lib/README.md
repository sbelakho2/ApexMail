# @apexmail/lib

Shared internal library for ApexMail services.

## Overview

Provides thin wrappers around external dependencies so implementations can be swapped without changing consumer code. Used by `api`, `worker`, `web`, `billing`, and other workspace apps.

## Sub-path Exports

| Import | Description |
|---|---|
| `@apexmail/lib/logger` | Pino-based structured logging |
| `@apexmail/lib/crypto` | Crypto wrapper (delegates to `@apexmail/crypto-native`) |
| `@apexmail/lib/storage` | S3 storage (`@aws-sdk/client-s3`) |
| `@apexmail/lib/http` | HTTP client |
| `@apexmail/lib/cache` | Redis cache (`ioredis`) |
| `@apexmail/lib/queue` | Job queue |
| `@apexmail/lib/time` | Time utilities |
| `@apexmail/lib/id` | ID generation (`nanoid`, `uuid`) |
| `@apexmail/lib/bot-detection` | Bot detection (delegates to `@apexmail/bot-detector-native`) |
| `@apexmail/lib/result` | Result/error types |
| `@apexmail/lib/mail-server-client` | gRPC client for mail-server |
| `@apexmail/lib/templates` | Handlebars / MJML template rendering |
| `@apexmail/lib/attachments` | Attachment handling |
| `@apexmail/lib/validation` | Input validation |
| `@apexmail/lib/company` | Company configuration |
| `@apexmail/lib/error-codes` | Shared error code constants |
| `@apexmail/lib/api-version` | API versioning |
| `@apexmail/lib/json` | JSON helpers |

## Internal

This is an internal package — not published to npm.
