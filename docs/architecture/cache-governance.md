# Cache Governance

ApexMail uses in-memory and Redis-backed caches for latency control. Every cache must have an explicit TTL, bounded capacity, owner, and stale-data risk classification.

| Category | TTL Range | Capacity Requirement | Examples |
| --- | --- | --- | --- |
| Authentication/session authorization | 10s-300s | per-tenant or global bounded | API key status, SMTP auth cache |
| DNS/network validation | 60s-24h with upstream TTL ceiling | bounded by resolver config | DNS resolver, DANE/TLSA, webhook SSRF DNS cache |
| Delivery/provider state | 30s-10m | bounded by provider/domain keys | provider throttle, MX cache, suppression checks |
| Analytics/derived predictions | 5m-24h | bounded by tenant/entity keys | reply tracking, send-time prediction |
| UI/admin summaries | 1s-60s | bounded by dashboard key space | admin dashboard counters |

## Rules

- Cache constructors must set both TTL and maximum capacity when the cache library supports them.
- Configuration structs deserialized from files or environment-derived documents must use `#[serde(deny_unknown_fields)]`.
- TTL values above 24h require an ADR entry describing stale-data risk and an invalidation path.
- Security-sensitive caches must prefer short TTLs and fail closed when cache refresh fails.
- Test-only or deterministic helper caches must document why TTL/capacity is fixed rather than configurable.

## Current Follow-up Owners

- `template-renderer` and `dns-resolver` enforce config validation for configurable cache TTLs.
- Worker webhook DNS cache is environment controlled and bounded by `WEBHOOK_DNS_CACHE_*` defaults.
- Send-time prediction cache purges expired rows on access and emits `ai_send_time_cache_expired_deleted_total`.
