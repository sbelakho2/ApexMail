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

- **Enforcement is per source IP in the outbound queue.** Before opening an
  SMTP connection, `SmtpSender` calls `IpPool::reserve_send`, which atomically
  reserves one slot of the selected IP's daily quota through the Redis-backed
  `RedisWarmupQuotaStore` (check-and-increment Lua, key
  `apexmail:outbound:warmup:{identity}:{day}`, shared by every MTA process).
  The cap comes from `mail_common::warmup::limit_for_day()` for that IP's
  warmup day (`dedicated_ips.warmup_started_at`); day 60+ is unlimited.
- **A full cap refuses the send; it does not overflow.** When no candidate
  source IP can accept the send, `IpPool::reserve_send` returns
  `IpPoolError::WarmupQuotaExhausted` (and a candidate whose quota store is
  unavailable is likewise not sendable). There is **no automatic overflow to
  SES shared sending** in the runtime: shared traffic is SES-only and selected
  by `EMAIL_TRANSPORT_TYPE=ses`, with no per-message failover. A warming
  dedicated IP never silently exceeds its schedule.
- **Progress bookkeeping is not currently scheduled.** `DedicatedIpProvider`
  exposes `tick_warmup()` (updates `dedicated_ips.warmup_progress` and
  graduates IPs to `active` after `FULL_WARMUP_DAYS`) and
  `SesProvider::sync_warmup_progress()` exists, but **no runtime component in
  this tree calls either** — there is no warmup cron. Graduation/progress only
  advances if an operator invokes it; do not assume a running cron will do it.

The single schedule lives in
[`mail_common::warmup`](../../services/mail-server/crates/mail-common/src/warmup.rs)
and is used directly by the outbound queue and `DedicatedIpProvider`; the
historical `WarmupLimits::for_day()` type no longer exists.

## Related

- [Hybrid Email Infrastructure — Warmup](../architecture/hybrid-email-infrastructure.md)
- [Delivery Transport — IP Warmup](../architecture/delivery-transport.md)
- [Hetzner Tool Contract — Warmup](../tool-contracts/hetzner.md)
- [User Guide — Delivery Options](../user-guide/delivery-options.md)
