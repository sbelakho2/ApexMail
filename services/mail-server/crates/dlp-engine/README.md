# dlp-engine

WIRING-STATUS: WIRED INTO PRODUCTION — the worker's pre-send gate (worker-processors `email/dlp.rs`, env `WORKER_DLP_ENABLED`) scans every outbound message before acceptance.
> Integration contract: the OUTBOUND delivery worker (crates/worker-processors,
> `src/email/dlp.rs`, pre-send gate inside the email processor BEFORE the durable
> acceptance reservation) scans every prepared per-recipient copy with this
> engine when `WORKER_DLP_ENABLED=true`. The worker's dependency on this crate
> is in the tree and building, and the managed baseline
> (`.env.production.example`) pins `WORKER_DLP_ENABLED=true`: the managed cloud
> runs outbound DLP enforced (medium-severity findings quarantine the send,
> high severity refuse it; binary default remains OFF without an explicit
> operator decision). Live wiring status is tracked in
> docs/development/capability-registry.json (data-loss-prevention) and
> docs/deployment-facts.json (data_loss_prevention).

Data Loss Prevention engine — PII detection, sensitive data scanning, document watermarking, and outbound content policies.

## Overview

The `dlp-engine` crate prevents accidental or malicious data leakage from ApexMail. It detects personally identifiable information, scans attachments and message bodies for sensitive data patterns, applies document watermarks, and enforces outbound content policies before messages leave the system.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
dlp-engine = { path = "../dlp-engine" }
```

## Development

```sh
cargo test -p dlp-engine
cargo clippy -p dlp-engine
```
