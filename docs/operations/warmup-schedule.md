# Warmup Schedule

> **Canonical reference** for the dedicated IP warmup schedule.
> Source of truth: [`mail-common::warmup`](../../services/mail-server/crates/mail-common/src/warmup.rs)

## Overview

New dedicated IPs start in `warming` status with a graduated send volume.
Over **60 days** the daily limit increases from 50 to unlimited, allowing IP
reputation to build gradually with mailbox providers.

## Graduated Schedule

| Day(s)   | Daily Limit |
|----------|-------------|
| 0–1      | 50          |
| 2–3      | 100         |
| 4–5      | 250         |
| 6–7      | 500         |
| 8–10     | 1,000       |
| 11–14    | 2,500       |
| 15–20    | 5,000       |
| 21–28    | 10,000      |
| 29–35    | 25,000      |
| 36–44    | 50,000      |
| 45–49    | 75,000      |
| 50–54    | 100,000     |
| 55–59    | 250,000     |
| 60+      | Unlimited   |

## Code reference

The canonical implementation lives in
[`mail-common::warmup::limit_for_day()`](../../services/mail-server/crates/mail-common/src/warmup.rs:6):

```rust
pub fn limit_for_day(day: u32) -> u64 {
    match day {
        0..=1     => 50,
        2..=3     => 100,
        4..=5     => 250,
        6..=7     => 500,
        8..=10    => 1_000,
        11..=14   => 2_500,
        15..=20   => 5_000,
        21..=28   => 10_000,
        29..=35   => 25_000,
        36..=44   => 50_000,
        45..=49   => 75_000,
        50..=54   => 100_000,
        55..=59   => 250_000,
        _         => u64::MAX,   // day 60+
    }
}
```

## Behaviour during warmup

- The `tick_warmup()` cron (API server) updates `warmup_progress` and
  graduates IPs to `active` status after 60 days.
- While warming, messages that would exceed the daily limit overflow to SES
  shared sending — deliverability is never blocked.
- The per-domain worker-side check uses `WarmupLimits::for_day()` which
  follows a compatible schedule.

## Related

- [Hybrid Email Infrastructure — Warmup](../architecture/hybrid-email-infrastructure.md)
- [Delivery Transport — IP Warmup](../architecture/delivery-transport.md)
- [Hetzner Tool Contract — Warmup](../tool-contracts/hetzner.md)
- [User Guide — Delivery Options](../user-guide/delivery-options.md)
