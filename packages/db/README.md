# @apexmail/db

Shared PostgreSQL database layer for ApexMail services.

## Overview

Provides connection pooling (with PgBouncer support), schema fingerprinting for startup validation, transaction helpers, and typed repository modules for all core domain entities.

## Repositories

`api-keys` · `audit-logs` · `domains` · `events` · `inbound-messages` · `messages` · `reputation` · `smtp-credentials` · `subscriptions` · `support-tickets` · `suppressions` · `system` · `templates` · `tenants` · `users` · `webhooks`

## Usage

```ts
import { pool } from '@apexmail/db';
import { transaction } from '@apexmail/db';
import { messages } from '@apexmail/db';
```

Sub-path exports are available for migrations and schema:

```ts
import '@apexmail/db/migrations';
import '@apexmail/db/schema';
```

## Migrations

Three SQL migrations are included: initial schema, performance indexes, and analytics two-phase processing.

## Internal

This is an internal package — not published to npm.
