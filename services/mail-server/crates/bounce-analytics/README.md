# bounce-analytics

Bounce aggregation and rollup worker for delivery health analysis.

## Audit Scope

Security-sensitive behavior is concentrated in `src/aggregator.rs` and `src/bin/worker.rs`: tenant-scoped aggregation, bounce classification rollups, and database writes. This crate is covered by the WS-ALL audit coverage ledger.

## Running

```sh
cargo test --manifest-path services/mail-server/Cargo.toml -p bounce-analytics --lib
```
