# analytics

ApexMail analytics — query engine, compaction, STO, churn, subject analysis, bot detection, etc.

## Overview

The `analytics` crate provides the analytics backbone for ApexMail, including a query engine for engagement data, compaction routines, send-time optimization, churn prediction, subject-line analysis, and bot-detection heuristics. It processes event streams and produces actionable metrics for dashboards and AI-driven features.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
analytics = { path = "../analytics" }
```

## Cold storage durability contract (migration 231)

The analytics compaction worker migrates events older than
`hot_retention_days` from Postgres into cold-storage JSONL objects under
`storage_path`. Its durability contract is:

- **The ledger is the source of truth.** Each cold batch is committed as one
  row in `analytics_compaction_batches` (plus one covered-id row per event in
  `analytics_compaction_batch_event_ids` — see
  `migrations/231_analytics_compaction_ledger.sql`). That row — not the
  filesystem — is the commit point. Hot rows are deleted only after it
  exists, so no crash window can lose an event.
- **The filesystem is a materialization.** Objects are named
  `events_<uuid>.jsonl` (batch identity, never wall-clock identity) and are
  written temp file → fsync → atomic rename. A crash between the object write
  and the ledger commit leaves an orphan object: harmless, and it ages out
  with its month directory under cold retention.
- **The storage root must be durable.** `ANALYTICS_COLD_STORAGE_PATH`
  (`storage_path`) must be a durable mount, or backed by durable object
  storage/backup. If it is not explicitly marked durable
  (`ANALYTICS_COLD_STORAGE_DURABLE=1`), the worker logs a loud warning at
  startup and on every compaction run. The warning is deliberately non-fatal:
  the ledger survives in Postgres, so an ephemeral root degrades to
  "cold objects must be re-materialized", never to silent data loss of the
  commit record.
- **Recovery and verification read the ledger**, never "whatever files
  exist". Id-coverage checks for interrupted runs are one indexed probe over
  the current batch (`tenant_id, event_id` — work proportional to the batch,
  not to history).

## Development

```sh
cargo test -p analytics
cargo clippy -p analytics
```
