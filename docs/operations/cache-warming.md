# Cache Warming Strategy

> **Document Owner:** Infrastructure Team
> **Last Updated:** 2026-05-11
> **Related:** [`cache-governance.md`](../architecture/cache-governance.md), [`deploy/scripts/cache-warm.sh`](../../deploy/scripts/cache-warm.sh), [`deploy/DEPLOYMENT.md`](../../deploy/DEPLOYMENT.md)

## 1. Overview

Cache warming is the process of pre-populating caches with frequently accessed data before the system begins serving production traffic. Without cache warming, cold starts after deployment cause:

- **Elevated latency** — The first N requests after deployment must query the database or external services directly
- **Rate limiter false positives** — Cold rate limiters may allow excessive traffic before converging
- **DNS resolver delays** — MX, SPF, DKIM lookups for popular domains take 100ms+ each
- **Database query storms** — Many services simultaneously cache-miss and hit the database

This document defines the cache warming strategy for all ApexMail services.

## 2. Caches Requiring Warming

### 2.1 DNS Resolver Cache (moka)

| Property | Value |
|----------|-------|
| **Location** | [`dns-resolver/src/cache.rs`](../../services/mail-server/crates/dns-resolver/src/cache.rs) (`DnsCache`, wrapped by `CachedDnsResolver` in [`resolver.rs`](../../services/mail-server/crates/dns-resolver/src/resolver.rs)) |
| **Cache Type** | `moka::sync::Cache<String, CachedEntry>` (positive) and `moka::sync::Cache<String, ()>` (negative) |
| **Capacity** | 10,000 positive entries, 1,000 negative entries |
| **TTL** | Authoritative record TTL capped at 24h (300s default), 60s for negative results |
| **Warm-up Data** | Top 100 email provider domains (Gmail, Outlook, Yahoo, Proton, etc.) |
| **Warm-up Method** | Pre-resolve MX records via `dig`/`host` in [`deploy/scripts/cache-warm.sh`](../../deploy/scripts/cache-warm.sh) |

The `dns-resolver` crate provides the cache, but no production service
constructs `CachedDnsResolver` today (only tests reference it), and the
outbound SMTP transport (`worker-processors/src/email/transport.rs`)
connects to a configured relay where mail-send performs its own resolution.
There is no in-process warm-up hook for this cache.

**Pre-warm domains** (top 100 by email traffic volume):

```
gmail.com, outlook.com, yahoo.com, proton.me, protonmail.com,
mail.com, aol.com, icloud.com, gmx.com, gmx.net, web.de,
t-online.de, orange.fr, sfr.fr, free.fr, libero.it, tin.it,
hotmail.com, live.com, msn.com, office365.com, exchange.com,
yandex.com, yandex.ru, mail.ru, rambler.ru, list.ru,
qq.com, 163.com, 126.com, sina.com, sohu.com, yeah.net,
naver.com, hanmail.net, daum.net, korea.com, nate.com,
rediffmail.com, indiatimes.com, yahoo.co.in, hotmail.co.uk,
btinternet.com, ntlworld.com, virginmedia.com, blueyonder.co.uk,
zonnet.nl, xs4all.nl, planet.nl, hetnet.nl,
chello.at, gmx.at, aon.at, tele2.at,
swisscom.ch, bluewin.ch, sunrise.ch, gmx.ch,
telenet.be, skynet.be, proximus.be, belgacom.be,
telefonica.net, terra.es, ya.com, hotmail.es,
virgilio.it, alice.it, fastwebnet.it, libero.it,
o2.pl, wp.pl, interia.pl, poczta.onet.pl,
centrum.cz, seznam.cz, atlas.cz, volny.cz,
freemail.hu, citromail.hu, mailbox.hu, t-online.hu,
mail.bg, abv.bg, dir.bg, gmail.ru
```

### 2.2 Rate Limiter Cache

| Property | Value |
|----------|-------|
| **Location** | [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) |
| **Cache Type** | Redis + moka local cache |
| **Capacity** | 100,000 keys (Redis), 10,000 (moka local) |
| **Warm-up Data** | All active tenant rate limit configurations |
| **Warm-up Method** | Pre-load tenant configs from database into rate limiter stores |

### 2.3 Database Query Cache

| Property | Value |
|----------|-------|
| **Location** | `apexmail-db/src/pool.rs` |
| **Cache Type** | Statement cache (pgbouncer / sqlx) |
| **Capacity** | Configurable via `statement_cache_capacity` |
| **Warm-up Data** | Common query plans for hot queries |
| **Warm-up Method** | Pre-execute representative queries to warm query planner caches |

### 2.4 AI Send-Time Optimizer Cache

| Property | Value |
|----------|-------|
| **Location** | [`analytics/src/send_time_optimizer.rs`](../../services/mail-server/crates/analytics/src/send_time_optimizer.rs) |
| **Cache Type** | Redis (deadpool_redis) |
| **Capacity** | Configurable |
| **Warm-up Data** | Pre-computed send time recommendations for active tenants |
| **Warm-up Method** | Load from PostgreSQL into Redis at startup |

### 2.5 Template Renderer Cache

| Property | Value |
|----------|-------|
| **Location** | `template-renderer/src/cache.rs` |
| **Cache Type** | moka (compiled templates) |
| **Capacity** | 5,000 entries |
| **Warm-up Data** | Most recently used templates per tenant |
| **Warm-up Method** | Pre-compile top-N templates from database |

### 2.6 Session and Credential Lookups (API Server)

There is no in-process session cache. Sessions live in Redis plus the
`sessions` table, and JWTs are validated per request. The auth middleware keeps
two Redis caches that a warm-up can populate: API-key lookups
(`apexmail:api_key_cache:<key_hash>`) and tenant user-status entries, both in
[`api-server/src/middleware/auth.rs`](../../services/mail-server/crates/api-server/src/middleware/auth.rs).
There is no moka session cache to warm.

## 3. Warming Implementation

### 3.1 DNS Cache Warming (Rust)

```rust
use trust_dns_resolver::TokioAsyncResolver;
use moka::sync::Cache;
use std::sync::Arc;

/// Pre-warm the DNS MX record cache with top email provider domains.
pub async fn warm_dns_cache(
    resolver: &TokioAsyncResolver,
    cache: &Arc<Cache<String, MxRecord>>,
    domains: &[String],
) {
    let mut handles = Vec::with_capacity(domains.len());
    for domain in domains {
        let resolver = resolver.clone();
        let cache = Arc::clone(cache);
        let domain = domain.clone();
        handles.push(tokio::spawn(async move {
            match resolver.mx_lookup(domain.as_str()).await {
                Ok(response) => {
                    let records: Vec<MxRecord> = response.iter()
                        .map(|mx| MxRecord {
                            preference: mx.preference(),
                            exchange: mx.exchange().to_string(),
                        })
                        .collect();
                    cache.insert(domain.clone(), MxRecord::Multiple(records));
                    tracing::info!(domain = %domain, "DNS cache warmed");
                }
                Err(e) => {
                    tracing::warn!(domain = %domain, error = %e, "DNS pre-warm failed");
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }
}
```

### 3.2 Rate Limiter Cache Warming (Rust)

```rust
use sqlx::PgPool;
use deadpool_redis::redis::AsyncCommands;

/// Pre-load tenant rate limit configurations into Redis.
pub async fn warm_rate_limiter_cache(
    pg_pool: &PgPool,
    redis_conn: &mut deadpool_redis::Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch all active tenant rate limit configurations
    let tenants: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT tenant_id, max_requests_per_hour, max_burst_size
         FROM tenant_rate_limit_configs
         WHERE enabled = true"
    )
    .fetch_all(pg_pool)
    .await?;

    for (tenant_id, max_requests, burst_size) in &tenants {
        let key = format!("rate_limit:config:{}", tenant_id);
        redis_conn.set_multiple(&[
            (&format!("{}:max_requests", key), *max_requests),
            (&format!("{}:burst_size", key), *burst_size),
            (&format!("{}:window_seconds", key), 3600i64),
        ]).await?;
        tracing::info!(tenant = %tenant_id, "Rate limit config warmed");
    }

    tracing::info!(count = tenants.len(), "Rate limiter cache warming complete");
    Ok(())
}
```

### 3.3 Database Query Cache Warming (Rust)

```rust
use sqlx::PgPool;

/// Pre-execute common queries to warm PostgreSQL's query planner caches.
pub async fn warm_db_query_cache(pool: &PgPool) -> Result<(), sqlx::Error> {
    let warming_queries: Vec<(&str, &str)> = vec![
        ("tenant_config", "SELECT config FROM tenant_configs WHERE tenant_id = $1 LIMIT 1"),
        ("domain_check", "SELECT domain, verified FROM domains WHERE tenant_id = $1 AND domain = $2 LIMIT 1"),
        ("email_stats", "SELECT COUNT(*) FROM email_queue WHERE tenant_id = $1 AND status = $2"),
        ("recent_deliveries", "SELECT id, status FROM email_delivery_log WHERE email_id = $1 ORDER BY attempted_at DESC LIMIT 5"),
        ("template_lookup", "SELECT id, name FROM templates WHERE tenant_id = $1 AND id = $2 LIMIT 1"),
        ("account_check", "SELECT id, email FROM mail_accounts WHERE email = $1 LIMIT 1"),
        ("rate_limit_check", "SELECT max_requests, current_count FROM rate_limits WHERE tenant_id = $1 AND endpoint = $2 LIMIT 1"),
        ("bounce_stats", "SELECT COUNT(*) FROM bounce_analytics_daily WHERE tenant_id = $1 AND date >= $2"),
    ];

    for (name, query) in &warming_queries {
        // Use EXPLAIN (ANALYZE, TIMING false) to warm without full execution
        let explain = format!("EXPLAIN (ANALYZE, TIMING false) {}", query);
        match sqlx::query(&explain).execute(pool).await {
            Ok(_) => tracing::debug!(query = %name, "Query cache warmed"),
            Err(e) => tracing::warn!(query = %name, error = %e, "Query cache warm failed"),
        }
    }

    tracing::info!("Database query cache warming complete ({} queries)", warming_queries.len());
    Ok(())
}
```

## 4. Deployment Hook Integration

### 4.1 Post-deploy invocation (Docker Compose deployment)

There is no Kubernetes post-start hook — ApexMail deploys as Docker Compose
on a single host (see [`deploy/DEPLOYMENT.md`](../../deploy/DEPLOYMENT.md)).
Run the cache warming script over SSH after a deploy completes (optionally
wired into the tail of `deploy/scripts/deploy.sh` for the manual path):

```sh
ssh <hetzner-host> 'cd /opt/apexmail && bash deploy/scripts/cache-warm.sh'
```

### 4.2 Cache Warming Script

The shell script at [`deploy/scripts/cache-warm.sh`](../../deploy/scripts/cache-warm.sh) orchestrates cache warming for all services.

### 4.3 Kubernetes (roadmap only)

ApexMail deploys as Docker Compose on a single host. Kubernetes deployment
manifests, including an init-container form of cache warming, are not part of
the shipped deployment; treat any Kubernetes example as roadmap material.

## 5. Monitoring Cache Warmth

### 5.1 Metrics

| Metric | Description | Expected Value |
|--------|-------------|----------------|
| `apexmail_cache_warming_duration_seconds` | Time to complete warming | < 30s |
| `apexmail_cache_warming_items_loaded` | Number of items loaded | Varies by cache |
| `apexmail_cache_warming_errors_total` | Errors during warming | 0 |
| `apexmail_cache_hit_ratio` | Post-warmup hit ratio | > 0.90 |

### 5.2 Grafana Dashboard

Cache warmth is visualized in the [Infrastructure Overview](../../deploy/grafana/dashboards/infrastructure-overview.json) dashboard under the "Cache Performance" section.

### 5.3 Alerting

- `CacheHitRateDrop` — Warning if cache hit rate drops below 50% for 10 minutes
- `CacheWarmingFailure` — Warning if warming errors > 0

## 6. Cold Start Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| **Single container restart** | Local caches cold | DNS query cache refills naturally within TTL |
| **Compose recreate** | All caches cold for ~30s | Run `deploy/scripts/cache-warm.sh` after the recreate |
| **Additional replica** | New process cold | Each replica warms its own in-process caches from the shared Redis/DB |
| **Redis failover** | Rate limiter state lost | Redis re-populates from the database |
| **Host restart** | All caches cold | The deploy procedure re-runs warming before traffic |

## 7. Top Domains List

`deploy/scripts/cache-warm.sh` defaults `TOP_DOMAINS_FILE` to
`deploy/config/top-email-domains.txt`, but that file is not shipped in the
repository and `deploy/config/` does not exist. The script falls back to its
inline list of common provider domains, so DNS warm-up still runs; set
`TOP_DOMAINS_FILE` to a real file (any file with one domain per line) to
override the inline list.

## 8. Performance Budget

| Metric | Budget | Notes |
|--------|--------|-------|
| DNS cache warm (100 domains) | < 5s | Parallel resolution via tokio |
| Rate limiter cache warm (1000 tenants) | < 10s | Batch Redis SET operations |
| DB query cache warm (8 queries) | < 5s | EXPLAIN (ANALYZE, TIMING false) |
| Template cache warm (500 templates) | < 10s | Parallel compilation |
| **Total warming time** | **< 30s** | Run after the Compose recreate, before the deploy is announced complete |
