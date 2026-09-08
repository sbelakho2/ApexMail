+++
title = "Alert Runbooks"
description = "First-response checks for ApexMail production alerts and infrastructure regressions."
template = "prose.html"
weight = 5
+++

Use this page as the first-response index for production alerts. It is intentionally short: confirm the signal, identify blast radius, inspect the most recent deploy or dependency change, and only then move into service-specific remediation.

If an alert is caused by monitoring drift rather than a service failure, fix the metric or exporter path first so the alert pipeline remains trustworthy.

<h2 id="tracking-service-down">TrackingServiceDown</h2>

- Confirm `up{job="apexmail-tracking"}` is `0` for the target and not just a scrape timeout.
- Check tracking service restarts, recent deploys, and service discovery or proxy changes affecting the tracking endpoint.
- Inspect tracking logs before rollback so you can distinguish process crash, config failure, and network reachability issues.

<h2 id="high-api-latency">HighApiLatency</h2>

- Verify the latency jump with request volume, error rate, and dependency health rather than treating p95 in isolation.
- Check for slow database queries, queue pressure, or recent feature flags that expanded request work.
- If saturation is real, scale or shed load before debugging individual slow handlers.

<h2 id="high-api-error-rate">HighApiErrorRate</h2>

- Split the 5xx increase by route, tenant, and dependency so you know whether the failure is broad or localized.
- Compare with recent deploys, database errors, Redis failures, and upstream provider issues.
- If a new change correlates strongly, roll it back before deeper cleanup.

<h2 id="critical-api-error-rate">CriticalApiErrorRate</h2>

- Treat this as customer-impacting until disproven; establish whether core send or auth flows are failing.
- Check whether the same routes appear in `HighApiErrorRate` and whether upstream services are already degraded.
- Roll back or fail over quickly; detailed root-cause analysis comes after error-rate arrest.

<h2 id="high-cpu-usage">HighCpuUsage</h2>

- Identify the hot service and confirm the increase is sustained rather than deploy-time warmup.
- Check request load, background jobs, and any tight retry loops or runaway parsing workloads.
- Scale out if needed, then capture profiles or representative stack traces while the issue is live.

<h2 id="high-memory-usage">HighMemoryUsage</h2>

- Confirm the process RSS growth is persistent and not just cache warmup or one-off batch activity.
- Check for queue backlog, oversized responses, and recent code paths retaining large payloads in memory.
- If the service is close to OOM, increase headroom or drain traffic before collecting heap evidence.

<h2 id="high-event-loop-lag">HighEventLoopLag</h2>

- Correlate lag with CPU saturation, blocking I/O, and synchronous work accidentally running on async paths.
- Check background jobs, webhook processing, and any new request fan-out that increased per-request blocking.
- Reduce concurrency or disable the offending path before it cascades into timeouts.

<h2 id="email-queue-backlog">EmailQueueBacklog</h2>

- Confirm queue depth growth alongside worker throughput so you know whether demand or worker failure is driving it.
- Check downstream provider latency, worker health, and any paused or wedged delivery processors.
- If backlog continues climbing, scale workers or temporarily reduce intake.

<h2 id="critical-email-queue-backlog">CriticalEmailQueueBacklog</h2>

- Treat this as imminent delivery delay for customer traffic.
- Check whether workers are failing, providers are degraded, or queue storage is saturated.
- Stabilize throughput first, then communicate expected delivery delay if customer impact is material.

<h2 id="high-webhook-failure-rate">HighWebhookFailureRate</h2>

- Determine whether failures cluster by destination, tenant, or event type.
- Check retry backlog, downstream customer endpoint health, and any signing or payload-shape regressions.
- If the issue is limited to one destination, isolate it so global delivery remains healthy.

<h2 id="tracking-processing-backlog">TrackingProcessingBacklog</h2>

- Confirm the tracking service is up but not processing meaningful events, not simply receiving zero traffic.
- Check ingestion queues, worker consumers, and any Redis or database dependency needed for event flow.
- Compare against recent frontend or redirect changes that could have stopped event generation at the source.

<h2 id="stripe-webhook-failures">StripeWebhookFailures</h2>

- Inspect webhook signature validation, payload parsing, and billing-side database writes.
- Check whether Stripe is retrying the same events or whether new events are failing uniformly.
- If necessary, pause automated billing side effects until webhook correctness is restored.

<h2 id="postgres-down">PostgresDown</h2>

- Verify exporter reachability versus actual database reachability so you do not chase a monitoring-only issue.
- Check instance health, storage exhaustion, connection exhaustion, and recent schema or config changes.
- Recover primary availability first; only then investigate secondary effects in dependent services.

<h2 id="redis-down">RedisDown</h2>

- Confirm whether Redis itself is unavailable or just the exporter path.
- Check authentication, secret loading, persistence errors, and container restart loops.
- Prioritize recovery for auth, queue, and tracking flows that depend on Redis in the request path.

<h2 id="clickhouse-down">ClickHouseDown</h2>

- Confirm whether the outage is limited to analytics ingestion or also affects user-visible reporting paths.
- Check disk, container health, and recent migration or schema rollout activity.
- If ingestion must pause, preserve source-of-truth data elsewhere until ClickHouse returns.

<h2 id="postgres-high-connections">PostgresHighConnections</h2>

- Identify which services or queries are consuming the connection pool and whether idle connections are accumulating.
- Check for recent deploys that increased pool size, leaked transactions, or introduced retry storms.
- Reduce pressure before the database starts refusing new sessions.

<h2 id="low-disk-space">LowDiskSpace</h2>

- Determine which filesystem is filling and whether the growth is logs, database data, queue state, or build artifacts.
- Stop nonessential writes and rotate or purge safe data first.
- If a stateful service is near exhaustion, expand storage before corruption or restart loops begin.

<h2 id="tls-certificate-expiring-soon">TlsCertificateExpiringSoon</h2>

- Confirm which hostname is expiring and whether automated renewal is expected to handle it.
- Check certificate issuance logs, DNS challenges, and reverse-proxy reload state.
- Renew early enough to avoid emergency rotation during an unrelated incident.