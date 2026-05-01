# Legacy Migration Archive

These paired `_up.sql` / `_down.sql` files are retained for historical schema archaeology only. They are no longer mounted into Docker Compose Postgres containers.

The active database migration source of truth is:

```text
services/mail-server/migrations/
```

Validate or apply the active SQLx chain with:

```bash
sqlx migrate run --source services/mail-server/migrations
sqlx migrate info --source services/mail-server/migrations
```

Do not add new runtime migrations here. New schema changes must be added as SQLx migrations under `services/mail-server/migrations/`.