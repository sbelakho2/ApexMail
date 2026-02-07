# Audit: apps/analytics, apps/billing, apps/mta

> 80 findings across 3 apps — file path, line range, code snippet, fix.

---

## Performance Bottlenecks

**1.** [apps/analytics/src/churn-prediction.ts](apps/analytics/src/churn-prediction.ts#L420-L440)
N+1 query in `getAtRiskTenants` — iterates tenants one-by-one.
```ts
for (const tenant of tenants.rows) {
  const prediction = await this.predictTenantChurn(tenant.id);
```
**Fix:** Batch all tenant IDs into a single query with `WHERE tenant_id = ANY($1)` and score in-memory, or use `Promise.all` with a concurrency limiter (e.g. `p-limit(5)`).

---

**2.** [apps/analytics/src/query-engine.ts](apps/analytics/src/query-engine.ts#L170-L210)
`getFunnelAnalysis` runs 5 sequential DB queries (one per funnel stage).
```ts
for (const stage of stages) {
  const result = await this.db.query(...)
```
**Fix:** Combine into a single CTE query that counts each stage in one round-trip, e.g. `SELECT event_type, COUNT(*) … GROUP BY event_type`.

---

**3.** [apps/analytics/src/campaign-autopilot.ts](apps/analytics/src/campaign-autopilot.ts#L320-L340)
`updateSelectionProbabilities` runs 10 000 Monte Carlo iterations synchronously on the event loop.
```ts
const SIMULATION_COUNT = 10000;
for (let i = 0; i < SIMULATION_COUNT; i++) { ... }
```
**Fix:** Reduce to 1 000 iterations (diminishing returns), or offload to a `worker_threads` pool so the event loop is not blocked.

---

**4.** [apps/analytics/src/send-time-optimizer.ts](apps/analytics/src/send-time-optimizer.ts#L400-L430)
`optimizeBatch` processes recipients in sequential batches of 50 with `Promise.all`, but each batch awaits before starting the next.
```ts
const batches = chunkArray(recipients, 50);
for (const batch of batches) {
  await Promise.all(batch.map(r => this.getOptimalSendTime(r)));
}
```
**Fix:** Use a streaming concurrency limiter (`p-limit(50)`) instead of chunked serial batches to keep throughput steady.

---

**5.** [apps/billing/src/services/sla-credits.ts](apps/billing/src/services/sla-credits.ts#L370-L390)
`runMonthlyCheck` processes enterprise tenants sequentially.
```ts
for (const row of tenantsResult.value.rows) {
  const result = await this.checkCompliance(row.id, periodStart, periodEnd);
```
**Fix:** Use `Promise.all` with a concurrency limit (e.g. 10 at a time) to parallelize SLO checks.

---

**6.** [apps/mta/src/servers/bounce.ts](apps/mta/src/servers/bounce.ts#L240-L290)
`processBounce` makes 5 sequential DB writes (event insert, message update, suppression upsert, webhook lookup, webhook queue insert) per bounce.
```ts
await this.db.query(`INSERT INTO events ...`);
await this.db.query(`UPDATE messages ...`);
await this.addToSuppressionList(...);
await this.queueBounceWebhook(...);
```
**Fix:** Merge into a single atomic CTE (event → message update → suppression upsert) plus a background webhook queue.

---

**7.** [apps/mta/src/servers/feedback-loop.ts](apps/mta/src/servers/feedback-loop.ts#L340-L400)
`processComplaint` makes 7 sequential DB round-trips.
```ts
const result = await this.db.query(...);           // find message
await this.db.query(`INSERT INTO events ...`);     // record event
await this.db.query(`UPDATE messages ...`);        // update status
await this.addToSuppressionList(...);              // suppression
await this.queueComplaintWebhook(...);             // webhook lookup + insert
await this.updateSenderReputation(...);            // reputation + redis + alert
```
**Fix:** Consolidate the DB writes into a single CTE query. Reputation Redis counters can fire in `Promise.all`.

---

**8.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L670-L730)
`processInboundMessage` stores each recipient sequentially in a loop.
```ts
for (const rcpt of envelope.rcptTo) {
  await this.db.query(`INSERT INTO inbound_messages ...`);
  if (linkedMessageId) { await this.recordReplyToOriginalMessage(...); }
  await this.queueInboundWebhook(...);
}
```
**Fix:** Batch recipients into a single multi-row `INSERT` with `unnest($1::text[], $2::text[], ...)`.

---

## Missing Error Handling

**9.** [apps/analytics/src/compaction.ts](apps/analytics/src/compaction.ts#L170-L190)
`fetchEventsForDate` has no try/catch around the database query; a DB timeout crashes the compaction worker.
```ts
async fetchEventsForDate(date: string): Promise<any[]> {
  const result = await this.db.query(`SELECT * FROM events WHERE ...`);
```
**Fix:** Wrap in try/catch, log the error, and return `[]` so the compaction cycle can continue with the next date.

---

**10.** [apps/analytics/src/reconciliation.ts](apps/analytics/src/reconciliation.ts#L120-L150)
`reconcile` loads all message IDs into an `ANY($1)` array parameter. If the query returns zero rows, the method succeeds silently without logging a reconciliation result.
```ts
const messageIds = events.map(e => e.message_id);
const result = await this.db.query(`... WHERE id = ANY($1)`, [messageIds]);
```
**Fix:** Add a `logger.info('Reconciliation complete', { matched, unmatched })` after the query for observability.

---

**11.** [apps/analytics/src/send-time-optimizer.ts](apps/analytics/src/send-time-optimizer.ts#L490)
Uses `require('crypto')` at runtime instead of a top-level `import`.
```ts
const crypto = require('crypto');
```
**Fix:** Replace with `import { randomBytes } from 'crypto';` at the top of the file. Dynamic require is slow and may break ESM builds.

---

**12.** [apps/mta/src/servers/bounce.ts](apps/mta/src/servers/bounce.ts#L160-L175)
`onData` collects chunks into an unbounded `Buffer[]` array with no size limit. A malicious client could send a large bounce and exhaust memory.
```ts
const chunks: Buffer[] = [];
stream.on('data', (chunk: Buffer) => { chunks.push(chunk); });
```
**Fix:** Track cumulative size and destroy the stream with a `552 Message too large` error when `this.config.maxMessageSize` is exceeded (as the inbound server already does).

---

**13.** [apps/mta/src/servers/feedback-loop.ts](apps/mta/src/servers/feedback-loop.ts#L293-L305)
Same unbounded buffer issue in `onData` — no size limit on incoming complaint messages.
```ts
const chunks: Buffer[] = [];
stream.on('data', (chunk: Buffer) => { chunks.push(chunk); });
```
**Fix:** Add a running size counter and destroy the stream when `maxMessageSize` is exceeded.

---

**14.** [apps/billing/src/services/invoices.ts](apps/billing/src/services/invoices.ts#L250-L260)
`generatePdfContent` interpolates user-supplied data (company name, address) directly into HTML without sanitisation, creating an XSS risk if the HTML is rendered in a browser.
```ts
<strong>${invoice.billingAddress.companyName}</strong><br>
${invoice.billingAddress.addressLine1}<br>
```
**Fix:** Escape HTML entities the same way `escapeXml` is used for the e-Invoice XML — create an `escapeHtml` helper and apply it to all interpolated values.

---

## In-Memory State That Should Be Persisted

**15.** [apps/analytics/src/bot-detection.ts](apps/analytics/src/bot-detection.ts#L30-L35)
`clickVelocityCache` is an in-memory `Map` (max 50 000 entries). It resets on restart, letting bots through until the cache warms up again.
```ts
private readonly clickVelocityCache = new Map<string, ClickRecord[]>();
private readonly MAX_VELOCITY_CACHE_SIZE = 50000;
```
**Fix:** Back with Redis sorted sets keyed by `click:velocity:{recipient}` with a TTL. On startup, the cache is warm immediately.

---

**16.** [apps/analytics/src/reply-tracking.ts](apps/analytics/src/reply-tracking.ts#L25-L30)
`replyCache` stores full reply content (text bodies) in-memory with a 50 000 entry cap. A single reply body can be hundreds of KB, so 50 000 entries could consume ~5 GB.
```ts
private readonly replyCache = new Map<string, CachedReply>();
private readonly MAX_REPLY_CACHE_SIZE = 50000;
```
**Fix:** Store only the reply metadata (message ID, timestamp, sender) in the cache, not the body. The body is already in the DB.

---

**17.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L76-L78)
`connectionCounts` and `sessions` maps are purely in-memory. In a multi-instance deployment, each instance tracks independently, so aggregate connection-per-IP limits are ineffective.
```ts
private readonly sessions = new Map<string, SessionContext>();
private readonly connectionCounts = new Map<string, number>();
```
**Fix:** Move connection counts to Redis (`INCR smtp:conn:{ip}` with a short TTL) so all MTA instances share the same view.

---

## Resource Leaks

**18.** [apps/mta/src/index.ts](apps/mta/src/index.ts#L200-L250)
Graceful shutdown closes the SMTP servers but **does not close the DB pool or Redis client**.
```ts
await inboundServer.stop();
await bounceServer.stop();
await feedbackLoopServer.stop();
// Missing: pool.end() and redis.quit()
```
**Fix:** Add `await pool.end(); await redis.quit();` after stopping the servers.

---

**19.** [apps/analytics/src/index.ts](apps/analytics/src/index.ts#L250-L280)
The cron scheduler `setInterval` references are stored but `clearInterval` is only called for some timers in the shutdown handler. If a timer fires after the DB pool is closed, it will throw an unhandled error.
```ts
// Shutdown
process.on('SIGTERM', async () => {
  // clears some intervals but not all
```
**Fix:** Keep all interval IDs in an array and clear every one in the shutdown handler before closing the DB pool.

---

**20.** [apps/analytics/src/compaction.ts](apps/analytics/src/compaction.ts#L380-L390)
`deleteDirectory` calls `fs.unlink()` on a directory path, which fails on Linux. The error is swallowed, leaving stale directories.
```ts
await fs.unlink(dirPath);
```
**Fix:** Use `fs.rm(dirPath, { recursive: true })` or `fs.rmdir(dirPath)`.

---

## Missing Validation

**21.** [apps/analytics/src/inbox-placement.ts](apps/analytics/src/inbox-placement.ts#L290-L310)
**SQL injection** — string-interpolates `days` parameter directly into an `INTERVAL` clause.
```ts
WHERE timestamp > NOW() - INTERVAL '${days} days'
```
**Fix:** Use parameterised interval: `WHERE timestamp > NOW() - ($1 || ' days')::interval` or `WHERE timestamp > NOW() - make_interval(days => $1)`.

---

**22.** [apps/analytics/src/query-engine.ts](apps/analytics/src/query-engine.ts#L350-L360)
`queryColdStorage` interpolates a file path into a DuckDB SQL string without sanitisation.
```ts
const result = db.prepare(`SELECT * FROM read_parquet('${filePath}')`).all();
```
**Fix:** Validate `filePath` against an allowlist of directories and reject path traversal characters (`..`, `~`).

---

**23.** [apps/billing/src/routes/billing.ts](apps/billing/src/routes/billing.ts#L50-L65)
The `planName` parameter from the request body is passed directly to `plans.getPlanByName()` without validating it's one of the known plan names.
```ts
const { planName } = await c.req.json();
const plan = await ctx.plans.getPlanByName(planName);
```
**Fix:** Validate with a Zod enum: `z.enum(['free','starter','pro','growth','scale','enterprise','payg'])`.

---

**24.** [apps/mta/src/servers/bounce.ts](apps/mta/src/servers/bounce.ts#L132-L140)
`isVerpAddress` constructs a regex from the VERP domain without escaping on every call, but the regex is already correct via `escapeRegex`. However, the regex is reconstructed on every call.
```ts
private isVerpAddress(email: string): boolean {
  const verpPattern = new RegExp(`^bounces\\+[^@]+@${this.escapeRegex(this.config.verpDomain)}$`, 'i');
```
**Fix:** Pre-compile the regex in the constructor and store it as a readonly field.

---

**25.** [apps/billing/src/services/enterprise-contracts.ts](apps/billing/src/services/enterprise-contracts.ts#L265-L275)
`calculateContractBilling` divides committed volume by `monthsInContract`, which can be zero if `startDate === endDate`.
```ts
const monthsInContract = Math.ceil(
  (contract.endDate.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
);
const monthlyCommitted = Math.floor(contract.committedVolume / monthsInContract);
```
**Fix:** Guard with `Math.max(1, monthsInContract)`.

---

**26.** [apps/billing/src/services/invoices.ts](apps/billing/src/services/invoices.ts#L380-L410)
`generateEInvoiceXml` interpolates user-supplied `postalCode` without XML escaping — only `companyName`, `addressLine1`, `city`, and `email` are escaped.
```ts
<PostalCode>${invoice.billingAddress.postalCode}</PostalCode>
<Country>${invoice.billingAddress.country}</Country>
```
**Fix:** Apply `this.escapeXml()` to **every** interpolated billing address field.

---

**27.** [apps/mta/src/auth/email-authentication.ts](apps/mta/src/auth/email-authentication.ts#L550-L560)
`parseDKIMKey` returns `any` type, losing all type safety downstream.
```ts
private parseDKIMKey(record: string): any {
  const params: any = { valid: true };
```
**Fix:** Define a `DKIMKeyRecord` interface with `valid`, `p`, `k`, `h`, `s`, `t`, `error` fields and use it.

---

**28.** [apps/billing/src/services/cost-circuit.ts](apps/billing/src/services/cost-circuit.ts#L370-L385)
`getCostReport` computes a daily trend with `COST_RATES.computePerHour / 100` embedded in the SQL string. This is string interpolation of a config value into SQL.
```ts
COUNT(*) * ${COST_RATES.computePerHour / 100} as cost
```
**Fix:** Pass the rate as a bind parameter: `COUNT(*) * $4 as cost`.

---

## Concurrency Issues

**29.** [apps/analytics/src/compaction.ts](apps/analytics/src/compaction.ts#L100-L120)
Two compaction workers can run concurrently and compact the same date's events. There is no distributed lock.
```ts
async compact(date: string): Promise<void> {
  const events = await this.fetchEventsForDate(date);
```
**Fix:** Acquire a Redis lock (`SET compaction:lock:{date} NX EX 300`) before starting compaction and release on completion.

---

**30.** [apps/analytics/src/reconciliation.ts](apps/analytics/src/reconciliation.ts#L50-L70)
Two reconciliation workers can run at the same time and double-process the same batch.
```ts
async reconcile(): Promise<void> {
  const events = await this.db.query(`SELECT ...`);
```
**Fix:** Use `FOR UPDATE SKIP LOCKED` in the event selection query, or a Redis advisory lock.

---

**31.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L310-L340)
`onAuth` has a TOCTOU race on the `authAttemptCounts` map — two concurrent auth requests from the same IP can both read the count before either increments it, bypassing the rate limit.
```ts
if (attempts) {
  if (attempts.count >= this.AUTH_RATE_LIMIT) { ... }
  attempts.count++;
}
```
**Fix:** Pre-increment before the check (`++attempts.count >= this.AUTH_RATE_LIMIT`), or move auth-attempt tracking to Redis `INCR`.

---

**32.** [apps/analytics/src/bot-detection.ts](apps/analytics/src/bot-detection.ts#L200-L220)
`checkClickVelocity` reads the cache, checks size, and evicts in separate non-atomic steps. Under high concurrency the cache can grow beyond `MAX_VELOCITY_CACHE_SIZE`.
```ts
if (this.clickVelocityCache.size >= this.MAX_VELOCITY_CACHE_SIZE) {
  // eviction
}
this.clickVelocityCache.set(key, records);
```
**Fix:** Evict *before* inserting and tolerate a brief overcount, or use an LRU cache (e.g. `lru-cache` package) which handles this atomically.

---

**33.** [apps/billing/src/services/wallet.ts](apps/billing/src/services/wallet.ts#L470-L510)
`processExpiredReservations` selects all pending-expired reservations then releases them one-by-one without `FOR UPDATE SKIP LOCKED`. Two concurrent runs can double-release.
```ts
const result = await this.db.query(
  `SELECT id FROM wallet_reservations WHERE status = 'pending' AND expires_at < NOW()`
);
for (const row of result.value.rows) {
  await this.releaseReservation(row.id);
}
```
**Fix:** Add `FOR UPDATE SKIP LOCKED` to the select, or use a Redis advisory lock.

---

## Unbounded Data Structures

**34.** [apps/analytics/src/compaction.ts](apps/analytics/src/compaction.ts#L110-L130)
`fetchEventsForDate` loads **all** events for an entire date into memory. For high-volume tenants this can be millions of rows.
```ts
const result = await this.db.query(`SELECT * FROM events WHERE date = $1`);
return result.rows;
```
**Fix:** Stream with a cursor (`DECLARE cursor … FETCH 10000`) or paginate with `LIMIT/OFFSET` and process in chunks.

---

**35.** [apps/analytics/src/reconciliation.ts](apps/analytics/src/reconciliation.ts#L80-L100)
Loads all unreconciled message IDs into a single `ANY($1)` array. PostgreSQL has a practical limit of ~65 535 parameters and the array transfer is O(n) memory.
```ts
const result = await this.db.query(`... WHERE id = ANY($1)`, [messageIds]);
```
**Fix:** Chunk `messageIds` into batches of 5 000 and run the query in a loop, or use a temp table.

---

**36.** [apps/analytics/src/churn-prediction.ts](apps/analytics/src/churn-prediction.ts#L380-L420)
`predictRecipientChurnBatch` builds a large CTE with all tenant recipients. For large tenants this can blow up the query planner.
```ts
WITH recipient_data AS (
  SELECT ... FROM messages ... GROUP BY to_address
)
```
**Fix:** Add `LIMIT 10000` to the CTE or paginate recipients.

---

**37.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L550-L560)
The `chunks` buffer in `onData` correctly checks `maxMessageSize` and calls `stream.destroy()`, but the already-collected chunks **remain in memory** until GC.
```ts
if (size > this.config.maxMessageSize) {
  stream.destroy(new Error('552 Message too large'));
}
```
**Fix:** Clear `chunks.length = 0` after destroying the stream so the buffers can be GC'd immediately.

---

**38.** [apps/mta/src/auth/email-authentication.ts](apps/mta/src/auth/email-authentication.ts#L920-L960)
`PUBLIC_SUFFIX_LIST` is a static `Set` with ~200 entries. This is fine for memory, but it's an incomplete PSL which will mis-extract organizational domains for unlisted ccTLDs (e.g. `.za`, `.id` subdomains not covered).
```ts
private static readonly PUBLIC_SUFFIX_LIST: Set<string> = new Set([ ... ]);
```
**Fix:** Use the `psl` npm package for correct organisational domain extraction, or fetch/cache the full PSL.

---

## Missing Batching

**39.** [apps/analytics/src/inbox-placement.ts](apps/analytics/src/inbox-placement.ts#L180-L200)
`sendTestEmails` sends seed-list emails sequentially, one at a time.
```ts
for (const seed of seedList) {
  await this.sendTestEmail(seed, ...);
}
```
**Fix:** Use `Promise.all` with a concurrency limiter (e.g. `p-limit(10)`) to send in parallel batches.

---

**40.** [apps/mta/src/servers/bounce.ts](apps/mta/src/servers/bounce.ts#L540-L570)
`queueBounceWebhook` finds webhooks then inserts one queue row per webhook in a loop.
```ts
for (const webhook of result.rows) {
  await this.db.query(`INSERT INTO webhook_queue ...`);
}
```
**Fix:** Use a single multi-row `INSERT` with `unnest`.

---

**41.** [apps/mta/src/servers/feedback-loop.ts](apps/mta/src/servers/feedback-loop.ts#L580-L610)
Same pattern — `queueComplaintWebhook` inserts webhook queue entries in a loop.
```ts
for (const webhook of result.rows) {
  await this.db.query(`INSERT INTO webhook_queue ...`);
}
```
**Fix:** Same — batch into a single multi-row `INSERT`.

---

**42.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L770-L800)
`queueInboundWebhook` also iterates webhooks and inserts one-by-one.
```ts
for (const webhook of result.rows) {
  await this.db.query(`INSERT INTO webhook_queue ...`);
}
```
**Fix:** Batch with multi-row `INSERT`.

---

**43.** [apps/billing/src/services/usage-alerts.ts](apps/billing/src/services/usage-alerts.ts#L240-L260)
`checkAllTenants` processes each tenant sequentially in the batch loop.
```ts
for (const row of rows) {
  const result = await this.checkAndAlert(row.id);
```
**Fix:** Process each batch page with `Promise.all` (concurrency-limited) instead of serial `for`.

---

## Query Inefficiencies

**44.** [apps/analytics/src/churn-prediction.ts](apps/analytics/src/churn-prediction.ts#L100-L140)
`predictTenantChurn` runs 3 sequential queries against the same tenant — engagement stats, recent activity, and historical trends.
```ts
const engagement = await this.db.query(`SELECT ... WHERE tenant_id = $1`);
const activity = await this.db.query(`SELECT ... WHERE tenant_id = $1`);
const trends = await this.db.query(`SELECT ... WHERE tenant_id = $1`);
```
**Fix:** Merge into a single query using CTEs or `Promise.all` for the three independent queries.

---

**45.** [apps/analytics/src/subject-line-analyzer.ts](apps/analytics/src/subject-line-analyzer.ts#L300-L340)
`getAudienceInsights` runs 3 separate queries (baseline, per-subject performance, length effect).
```ts
const baselineResult = await this.db.query(...);
const subjectResult = await this.db.query(...);
const lengthResult = await this.db.query(...);
```
**Fix:** The baseline and length queries can be combined into one CTE since they scan the same tables. At minimum, fire all three with `Promise.all`.

---

**46.** [apps/billing/src/services/cost-circuit.ts](apps/billing/src/services/cost-circuit.ts#L260-L290)
`checkCostSpike` calls `calculateCosts` twice — once for today, once for yesterday — each of which runs a DB query.
```ts
const todayCosts = await this.calculateCosts(tenantId, todayStart, now);
const yesterdayCosts = await this.calculateCosts(tenantId, yesterdayStart, todayStart);
```
**Fix:** Run both with `Promise.all` since they're independent.

---

**47.** [apps/billing/src/routes/admin.ts](apps/billing/src/routes/admin.ts#L340-L390)
The MRR report uses a correlated subquery in the `SELECT` list to count active subscriptions per month.
```sql
(SELECT COUNT(DISTINCT tenant_id) FROM stripe_subscriptions 
 WHERE status = 'active' AND created_at < DATE_TRUNC('month', s.canceled_at))
```
**Fix:** Replace with a window function or a separate CTE join to avoid the N×M cost.

---

**48.** [apps/billing/src/services/enterprise-contracts.ts](apps/billing/src/services/enterprise-contracts.ts#L810-L860)
`getContractUsage` calculates `monthsInContract` using `Math.ceil((end - start) / (30 days))` which is inaccurate for months with 28 or 31 days.
```ts
const monthsInContract = Math.ceil(
  (contract.endDate.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
);
```
**Fix:** Use `(endDate.getFullYear() - startDate.getFullYear()) * 12 + (endDate.getMonth() - startDate.getMonth())` for calendar-accurate month counting.

---

**49.** [apps/mta/src/servers/feedback-loop.ts](apps/mta/src/servers/feedback-loop.ts#L355-L370)
When complaint can't be matched by `message_id_header`, a fallback query does `ORDER BY created_at DESC LIMIT 1` on `to_address` with no index hint.
```ts
SELECT id, tenant_id, to_address FROM messages
WHERE to_address = $1
ORDER BY created_at DESC
LIMIT 1
```
**Fix:** Ensure a composite index exists on `(to_address, created_at DESC)` to avoid a full table scan.

---

**50.** [apps/analytics/src/inbox-placement.ts](apps/analytics/src/inbox-placement.ts#L350-L380)
`getProviderAnalysis` fires a separate query per provider with string interpolation for the interval.
```ts
for (const provider of providers) {
  const result = await this.db.query(`... WHERE provider = $1 AND ... INTERVAL '${days} days'`);
```
**Fix:** Single query with `GROUP BY provider` and a parameterised interval.

---

## Missing Observability

**51.** [apps/analytics/src/compaction.ts](apps/analytics/src/compaction.ts#L140-L160)
No duration or row-count metrics logged after a compaction run completes.
```ts
async compact(date: string): Promise<void> {
  const events = await this.fetchEventsForDate(date);
  // ... process ...
  // no summary log
```
**Fix:** Log `{ date, eventsProcessed, filesWritten, durationMs }` at the end.

---

**52.** [apps/analytics/src/bot-detection.ts](apps/analytics/src/bot-detection.ts#L100-L110)
No metric emitted when a click is classified as bot. There's no way to track false-positive rates.
```ts
if (isBot) {
  return { isBot: true, reason };
}
```
**Fix:** Add `this.logger.info('Bot click detected', { recipientId, reason, ip })`.

---

**53.** [apps/billing/src/services/metering.ts](apps/billing/src/services/metering.ts#L200-L220)
`flush` logs the count of flushed events but not the flush duration or the tenant breakdown.
```ts
logger.info('Metering flushed', { eventCount: buffer.length });
```
**Fix:** Add `durationMs`, `tenantCount`, and `dedupSkipped` to the log payload.

---

**54.** [apps/billing/src/services/wallet.ts](apps/billing/src/services/wallet.ts#L100-L120)
No log entry when a wallet balance goes negative (overspend). This is a critical financial event.
```ts
// balance can go negative from race conditions
```
**Fix:** After `executeTransaction`, check `if (newBalance < 0)` and log a warning with `{ tenantId, balance, transactionId }`.

---

**55.** [apps/mta/src/servers/bounce.ts](apps/mta/src/servers/bounce.ts#L80-L90)
`onConnect` has no logging — bounce connections are invisible in logs.
```ts
private onConnect(session: SMTPServerSession, callback: (err?: Error) => void): void {
  this.logger.debug('Bounce server connection', { ... });
  callback();
}
```
**Fix:** Upgrade from `debug` to `info` level and include `session.id` for correlation.

---

**56.** [apps/mta/src/auth/email-authentication.ts](apps/mta/src/auth/email-authentication.ts#L160-L170)
DNS cache hit/miss ratio is not tracked. Can't tell if the cache is effective.
```ts
const cached = this.dnsCache.get(cacheKey);
if (cached && cached.expires > Date.now()) { return cached.value; }
```
**Fix:** Increment Redis counters `dns:cache:hit` / `dns:cache:miss` or log periodically.

---

**57.** [apps/billing/src/services/dunning.ts](apps/billing/src/services/dunning.ts#L300-L320)
`processGracePeriodExpirations` logs per-tenant but has no aggregate summary.
```ts
for (const row of result.value.rows) {
  logger.info('Purged queued messages ...', { tenantId, purgedCount });
}
```
**Fix:** Add a final summary log: `{ processedCount, totalPurged, durationMs }`.

---

**58.** [apps/analytics/src/engagement-trust.ts](apps/analytics/src/engagement-trust.ts#L1-L463)
Entire file is pure computation with **zero logging** — no way to trace trust score calculations.
```ts
// 463 lines, no logger injected
```
**Fix:** Accept a `Logger` parameter and log at debug level for each score component.

---

**59.** [apps/analytics/src/campaign-autopilot.ts](apps/analytics/src/campaign-autopilot.ts#L600-L650)
No observability on Thompson Sampling decisions — which arm was selected, what the sampled values were, or the confidence level.
```ts
const sampledValues = arms.map(arm => this.sampleBeta(arm.alpha, arm.beta));
const selectedIndex = sampledValues.indexOf(Math.max(...sampledValues));
```
**Fix:** Log `{ selectedArm, sampledValues, alphas, betas, explorationRate }` at info level.

---

**60.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L550-L570)
No metric for message size distribution — can't detect abnormal large messages.
```ts
stream.on('data', (chunk: Buffer) => {
  chunks.push(chunk);
  size += chunk.length;
```
**Fix:** After `simpleParser`, log `{ messageId, sizeBytes, attachmentCount }` at info level.

---

## Additional Findings

**61.** [apps/analytics/src/send-time-optimizer.ts](apps/analytics/src/send-time-optimizer.ts#L80-L100)
`getOptimalSendTime` makes 2 sequential DB queries (hourly engagement + timezone data) per recipient.
```ts
const hourlyData = await this.db.query(`... WHERE recipient = $1`);
const tzData = await this.db.query(`... WHERE recipient = $1`);
```
**Fix:** Merge into one query with a JOIN or run with `Promise.all`.

---

**62.** [apps/billing/src/services/proration.ts](apps/billing/src/services/proration.ts#L140-L170)
`previewProration` makes 4 sequential DB queries — subscription, current plan, new plan, and period calculation.
```ts
const subResult = await this.db.query(...);
const currentPlanResult = await this.plans.getPlanByName(row.plan);
const newPlanResult = await this.plans.getPlanByName(newPlanName);
```
**Fix:** Fetch current and new plan with `Promise.all` since they're independent.

---

**63.** [apps/billing/src/services/viral-loop.ts](apps/billing/src/services/viral-loop.ts#L260-L290)
`shouldShowFooter` has a redundant double try/catch wrapping the same `JSON.parse` call.
```ts
try {
  try {
    features = JSON.parse(row.features || '{}');
  } catch {
    features = {};
  }
} catch {
```
**Fix:** Remove the outer try/catch — the inner one already handles parse failures.

---

**64.** [apps/billing/src/services/sla-credits.ts](apps/billing/src/services/sla-credits.ts#L140-L160)
Same redundant double try/catch pattern.
```ts
try {
  try {
    features = JSON.parse(row.features || '{}');
  } catch {
    features = {};
  }
} catch {
```
**Fix:** Remove the outer try/catch.

---

**65.** [apps/billing/src/services/enterprise-contracts.ts](apps/billing/src/services/enterprise-contracts.ts#L690-L710)
Same redundant double try/catch in `mapRow` for `additional_fees` parsing.
```ts
try {
  try {
    additionalFees = JSON.parse(row.additional_fees || '[]');
  } catch {
    additionalFees = [];
  }
} catch {
```
**Fix:** Remove the outer try/catch.

---

**66.** [apps/mta/src/auth/arc.ts](apps/mta/src/auth/arc.ts#L200-L215)
`validateARCChain` wraps everything in `new Promise(async (resolve) => {...})` — an async executor anti-pattern that swallows rejections.
```ts
export function validateARCChain(...): Promise<...> {
  return new Promise(async (resolve) => {
```
**Fix:** Make `validateARCChain` an `async function` directly and remove the `new Promise` wrapper.

---

**67.** [apps/mta/src/auth/bimi.ts](apps/mta/src/auth/bimi.ts#L295-L310)
`checkDMARCForBIMI` uses callback-based `dns.resolveTxt` wrapped in a `new Promise`. If the callback throws, the promise never settles.
```ts
dns.resolveTxt(`_dmarc.${domain}`, (err, records) => {
```
**Fix:** Use `dns.promises.resolveTxt` (already imported as `dns` in the module) and handle with try/catch.

---

**68.** [apps/mta/src/auth/mta-sts.ts](apps/mta/src/auth/mta-sts.ts#L135-L155)
Same callback-to-promise wrapping for `dns.resolveTxt` without error boundary around the callback body.
```ts
dns.resolveTxt(`_mta-sts.${domain}`, (err, records) => {
```
**Fix:** Use `dns.promises.resolveTxt`.

---

**69.** [apps/mta/src/auth/mta-sts.ts](apps/mta/src/auth/mta-sts.ts#L165-L200)
`fetchMTASTSPolicy` doesn't enforce a response body size limit. A malicious MTA-STS endpoint could send an unlimited response.
```ts
res.on('data', (chunk) => (data += chunk));
```
**Fix:** Track `data.length` and call `req.destroy()` if it exceeds a reasonable limit (e.g. 64 KB).

---

**70.** [apps/mta/src/auth/bimi.ts](apps/mta/src/auth/bimi.ts#L410-L440)
`fetchContent` is duplicated between `bimi.ts` (logo + VMC fetching). Could be extracted to a shared utility.
```ts
function fetchContent(url: string, maxSize: number): Promise<...> {
```
**Fix:** Move to a shared `apps/mta/src/utils/http.ts` module and import from both `bimi.ts` and `mta-sts.ts`.

---

**71.** [apps/billing/src/services/cost-circuit.ts](apps/billing/src/services/cost-circuit.ts#L430-L450)
`applyThrottling` silently swallows Redis errors. If throttling fails, the tenant continues at full speed with no alert.
```ts
} catch (error) {
  console.error(`[CostCircuit] Failed to apply throttling ...`);
}
```
**Fix:** After the catch, still `createAlert(tenantId, { alertType: 'throttle_failed', ... })` to surface the failure.

---

**72.** [apps/billing/src/services/metering.ts](apps/billing/src/services/metering.ts#L300-L320)
The crash-recovery method `recoverFromCrash` scans Redis keys with `SCAN` and pattern `meter:buffer:*`. If there are millions of keys, this loop blocks the event loop for each iteration.
```ts
let cursor = '0';
do {
  const [newCursor, keys] = await this.redis.scan(cursor, 'MATCH', 'meter:buffer:*', 'COUNT', 100);
```
**Fix:** Add a `COUNT 1000` to reduce round-trips, and yield to the event loop with `setImmediate` between iterations.

---

**73.** [apps/analytics/src/query-engine.ts](apps/analytics/src/query-engine.ts#L500-L530)
DuckDB instance is created in-memory per call and never closed in error paths.
```ts
const db = new Database(':memory:');
try { ... } finally { /* missing db.close() */ }
```
**Fix:** Add `db.close()` in a `finally` block.

---

**74.** [apps/analytics/src/inbox-placement.ts](apps/analytics/src/inbox-placement.ts#L100-L120)
`runInboxPlacementTest` stores seed-list results in an in-memory array and never persists them to the database.
```ts
const results: TestResult[] = [];
for (const seed of seedList) { ... results.push(result); }
return results;
```
**Fix:** After collecting results, batch-insert them into an `inbox_placement_results` table for historical analysis.

---

**75.** [apps/billing/src/app.ts](apps/billing/src/app.ts#L100-L120)
JWT verification error messages leak internal details (`error.message` is returned to the client).
```ts
return c.json({ error: `Authentication failed: ${error.message}` }, 401);
```
**Fix:** Return a generic `{ error: 'Authentication failed' }` and log the details server-side.

---

**76.** [apps/billing/src/services/stripe-integration.ts](apps/billing/src/services/stripe-integration.ts#L600-L640)
`switchSubscription` saga — if Stripe update succeeds but the DB finalise CTE fails, the saga is marked `db_failed` but there's no automated reconciliation job to fix it.
```ts
logger.error('CRITICAL: Stripe updated but DB failed - manual reconciliation required', {
  action: 'MANUAL_SUBSCRIPTION_RECONCILIATION_REQUIRED'
});
```
**Fix:** Create a background job that scans for `status = 'db_failed'` sagas and retries the DB update, or at minimum create an alert/PagerDuty integration.

---

**77.** [apps/mta/src/auth/email-authentication.ts](apps/mta/src/auth/email-authentication.ts#L730-L750)
`verifyDKIMBodyHash` calls `createHash` and `createVerify` using a bare import name, but the top of the file imports `* as crypto`. It references `createHash` and `createVerify` without the `crypto.` prefix — these will be `ReferenceError` at runtime.
```ts
const hash = createHash(algorithm).update(body).digest('base64');
// ...
const verifier = createVerify(algorithm);
```
**Fix:** Use `crypto.createHash(...)` and `crypto.createVerify(...)`, or add named imports.

---

**78.** [apps/mta/src/servers/inbound.ts](apps/mta/src/servers/inbound.ts#L630-L640)
`processInboundMessage` stores the entire `rawMessage` buffer in the DB for every inbound email. For a 25 MB message, this is stored as a `bytea` column.
```ts
raw_message, headers, attachments,
```
**Fix:** Store the raw message in object storage (S3/MinIO) and save only the reference URL in the database.

---

**79.** [apps/mta/src/servers/feedback-loop.ts](apps/mta/src/servers/feedback-loop.ts#L610-L640)
`updateSenderReputation` fires 4 Redis commands sequentially (`INCR`, `EXPIRE`, `GET`, `GET`).
```ts
await this.redis.incr(key);
await this.redis.expire(key, 86400 * 7);
const recentComplaints = await this.redis.get(...);
const recentSent = await this.redis.get(...);
```
**Fix:** Use a Redis pipeline to batch all 4 commands into a single round-trip.

---

**80.** [apps/billing/src/services/plans.ts](apps/billing/src/services/plans.ts#L530-L540)
`initializeDefaultPlans` inserts 7 default plans sequentially with individual DB queries.
```ts
for (const plan of DEFAULT_PLANS) {
  await this.createOrUpdatePlan(plan);
}
```
**Fix:** Batch into a single multi-row `INSERT … ON CONFLICT DO UPDATE` query.

---

*80 findings total across analytics (22), billing (33), and MTA (25).*
