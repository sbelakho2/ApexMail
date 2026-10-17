# worker-processors

ApexMail Worker Processors — Rust implementation of queue-based background workers.

## Overview

The `worker-processors` crate implements the background worker processors for ApexMail. It consumes jobs from the queue provider and executes analytics aggregation, email delivery, reply handling, and webhook dispatch tasks, running as long-lived processes that scale horizontally with workload demand.

## Configuration

`WORKER_REPLY_CLASSIFIER_AI_ENABLED` (default `false`) opts into the AI
semantic layer of reply classification. It runs only for messages the
deterministic layer cannot prove; any failure (outage, disabled model,
invalid output) falls back to the audited Unknown/0.0 verdict, never a
guessed disposition.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
worker-processors = { path = "../worker-processors" }
```

## Development

```sh
cargo test -p worker-processors
cargo clippy -p worker-processors
```
