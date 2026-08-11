//! Tenant isolation tests — heavy load on one tenant must not degrade others.
//!
//! These tests verify the **noisy-neighbour** guarantee: concurrent throughput
//! for tenant B stays within acceptable bounds while tenant A is under maximum
//! sustained load. All operations are CPU-bound in-memory computations so that
//! contention (if any) is due to shared resources rather than I/O.
//!
//! | Metric        | Threshold       | Rationale                              |
//! |---------------|-----------------|----------------------------------------|
//! | Tenant B p50  | ≤ 2× baseline   | Median latency should not double       |
//! | Tenant B p90  | ≤ 3× baseline   | Tail latency should stay reasonable    |
//! | Tenant B tput | ≥ 50% baseline  | Throughput should halve at worst       |
