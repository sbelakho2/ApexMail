# ApexMail — 500 Highest-Impact Improvements

> Compiled from deep research across the entire monorepo. Prioritized by impact.
> **Not** new customer features — only correctness, performance, security, reliability, and wiring fixes.
> **No** systematic/bulk-rename changes — each item is a distinct, targeted improvement.

---

## Legend

| Priority | Meaning |
|----------|---------|
| 🔴 P0 | Data loss, security hole, or crash — fix immediately |
| 🟠 P1 | Correctness bug, significant perf issue, or unwired code |
| 🟡 P2 | Moderate improvement — perf, resilience, or cleanup |
| 🟢 P3 | Minor — polish, docs, minor perf |

---

## 1 — DATA LOSS & CORRECTNESS BUGS (P0)

1. **Tracking WAL events lost on flush failure** — `apps/tracking/src/event-processor.ts` — Lua LTRIM drains events from Redis, but if `writeEvents()` throws (Postgres down), the events are gone. Re-push drained events back to Redis in the catch block.
2. **Analytics events lost on processing failure** — `apps/worker/src/processors/analytics.ts` — Events are marked `processed = true` atomically in the fetch CTE. If `flushBuffers()` fails, they're lost. Use two-phase: mark `processing` on fetch, `processed` after successful flush.
3. **Multi-tenant suppression check uses only first tenant** — `apps/worker/src/processors/email.ts` — `checkBulkSuppression(emails, jobs[0].tenantId)` misses suppressions for other tenants in the batch. Group jobs by tenantId.
4. **API null-byte middleware consumes request body** — `apps/api/src/app.ts` — `c.req.text()` consumes the body stream; downstream `c.req.json()` fails on valid POST/PUT/PATCH requests. Read body via `c.req.raw.clone()` instead.
5. **Webhook circuit breaker depletes retries without trying** — `apps/worker/src/processors/webhook.ts` — When circuit breaker is open, attempt counter is incremented without contacting the endpoint. After `maxRetries` skips, job is permanently failed. Don't increment attempts for CB skips.
6. **Analytics aggregation key parsing is broken for 4-segment keys** — `apps/worker/src/processors/analytics.ts` — Destructure only captures 3 parts; campaign-only keys use `||` creating ambiguous parsing. Embed type and dimensions as explicit fields in the aggregation value.
7. **SMTP send timeout leaks socket** — `apps/worker/src/processors/email.ts` — `Promise.race` timeout doesn't cancel `sendMail()`. The SMTP connection stays open, never returned to pool. Use Nodemailer's built-in `socketTimeout`/`connectionTimeout`.
8. **Post-send side-effects can mark sent email as failed** — `apps/worker/src/processors/email.ts` — `incrementWarmupCounter` and `ipRateLimiter.recordSend` are outside try/catch. If they throw, the catch calls `failJob()` on an already-sent email.
9. **API key rotation not transactional** — `packages/db/src/repositories/api-keys.ts` — `rotateKey()` does findById + create + revoke without a transaction. If create succeeds but revoke fails, both old and new keys are active.
10. **Control plane impersonation issues token for "unknown" operator** — `apps/control-plane/src/app/api/auth/impersonate/route.ts` — Session decode failure silently uses `operatorId = 'unknown'` and issues a valid token. Return 401 instead.
11. **Tracking X-Forwarded-For trusts leftmost IP** — `apps/tracking/src/routes.ts` — Should iterate right-to-left, peeling off trusted proxies. Current approach trusts attacker-supplied leftmost IP.
12. **Inbound reply processor has no concurrent-processing guard** — `apps/worker/src/processors/reply.ts` — Simple SELECT without FOR UPDATE. Two workers can process the same message, double-suppressing. Use `SELECT ... FOR UPDATE SKIP LOCKED`.
13. **Suppression check uses wrong column name** — `packages/db/src/repositories/subscriptions.ts` — Queries `email` and `reason` columns but suppression table uses `email_hash` and `type`. Queries silently fail or return wrong results.
14. **Tenant DELETE has no cascade protection** — `apps/control-plane/src/app/api/tenants/route.ts` — Hard-deletes tenants, orphaning messages, subscriptions, GDPR requests, etc. Use soft-delete.
15. **Sales-autopilot drip emails are never actually sent** — `apps/sales-autopilot/src/index.ts` — Send callback is a no-op logger: `logger.info('Would send email', ...)`. Wire actual email API.
16. **Sales CRM `getLead` has no tenant scoping** — `apps/sales-autopilot/src/crm/index.ts` — `SELECT * FROM sales_leads WHERE id = $1` — any tenant can read any lead by guessing the ID.
17. **AI health endpoint always returns healthy** — `apps/ai/src/index.ts` — Hardcoded `{ status: 'healthy', services: { inference: 'ready' } }` regardless of actual model state or circuit breaker.
18. **Control plane returns demo data on API errors** — `apps/control-plane/src/app/api/*/route.ts` — 8+ route handlers catch errors and return hardcoded demo arrays. Operators see fake data when services are down.
19. **Enterprise JWT decode never verifies signature** — `apps/enterprise/src/services/sso.ts` — `decodeJWT()` only base64-decodes the payload without signature verification. Use `jose` library.
20. **Sales-autopilot SQL injection via LIMIT interpolation** — `apps/sales-autopilot/src/crm/index.ts` — `` `LIMIT ${options.limit}` `` directly interpolates user input. Use parameterized query.

## 2 — SECURITY (P0–P1)

21. **DKIM keys loaded globally across all tenants** — `apps/worker/src/processors/email.ts` — All verified domains' private keys loaded into memory regardless of tenant. Load lazily per-domain at send time.
22. **Tracking token is reversible base64 with no HMAC** — `apps/worker/src/processors/email.ts` — `encodeTrackingId()` uses plain base64url. Anyone can decode/forge tracking pixels. Add HMAC signature.
23. **Unsubscribe token payload leaks PII in plaintext** — `apps/tracking/src/codec.ts` — Token is signed but not encrypted. tenantId and recipient email are visible in base64. Encrypt like tracking tokens.
24. **Enterprise SAML accepts SHA-1 signatures** — `apps/enterprise/src/services/sso.ts` — Only logs a warning. Reject by default; require opt-in config flag.
25. **HA /internal/sync has no authentication** — `apps/ha/src/app.ts` — Any network-reachable client can POST fake sync data. Add auth middleware.
26. **Ops service has no authentication on any route** — `apps/ops/src/app.ts` — All ops routes including admin endpoints are completely unauthenticated.
27. **Compliance auth token uses non-timing-safe comparison** — `apps/compliance/src/routes.ts` — `token !== expectedToken`. Use `timingSafeEqual`.
28. **HA hardcoded default API keys** — `apps/ha/src/index.ts` — Falls back to `'internal-key'` / `'admin-key'` if env vars missing. Throw in production instead.
29. **Control plane login rate limiter uses in-memory Map** — `apps/control-plane/src/app/api/auth/login/route.ts` — Resets on every deployment, trivially bypassable in serverless. Move to Redis.
30. **Control plane logout via GET enables CSRF** — `apps/control-plane/src/app/api/auth/logout/route.ts` — `<img src="/api/auth/logout">` logs out admin. Remove GET handler; POST-only.
31. **Edge-cases alerting rules accept arbitrary regex** — `apps/edge-cases/src/app.ts` — ReDoS vector via user-supplied patterns. Use `re2` or timeout.
32. **Edge-cases webhook trigger has no SSRF protection** — `apps/edge-cases/src/app.ts` — `fetch(url)` with no private-IP check. Reuse SSRF validation from webhook processor.
33. **Sales-autopilot custom field regex injection** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — `new RegExp(userKey, 'g')` where key comes from lead data. A crafted key like `.*` matches everything. Escape the key.
34. **Enterprise credential encryption uses AES-CBC** — `apps/enterprise/src/services/private-deploy.ts` — Rest of codebase uses AES-GCM (authenticated encryption). Migrate to GCM.
35. **Observability dashboard share key uses Math.random()** — `apps/observability/src/services/dashboards.ts` — Use `crypto.randomBytes()` for unguessable share keys.
36. **Control plane NEXT_PUBLIC_ env vars leak internal URLs** — `apps/control-plane/src/lib/api.ts` — Server-only URLs bundled into client JS. Remove `NEXT_PUBLIC_` prefix.
37. **Sales-autopilot XSS in promo HTML injection** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — `${promo.content.text}` injected raw into HTML. HTML-escape before interpolation.
38. **Control plane proxy endpoint allows arbitrary URL requests** — `apps/control-plane/src/app/api/proxy/route.ts` — Even with SSRF protections, exposes broad request proxy capability. Restrict to domain allowlist.
39. **Enterprise devex sandbox template injection** — `apps/enterprise/src/services/private-deploy.ts` — User variables interpolated into HTML without escaping. HTML-escape values.
40. **Warmup check is non-atomic TOCTOU** — `apps/worker/src/processors/email.ts` — Redis GET (check) then INCR (record) allows concurrent workers to exceed daily limit by up to `concurrency` count. Use atomic INCR + check returned value.

## 3 — PERFORMANCE: DATABASE QUERIES (P1)

41. **API key lookup uses SELECT *** — `packages/db/src/repositories/api-keys.ts` — This is the hot path for every API request. Select only needed columns (id, prefix, hash, scopes, tenant_id, is_active, ip_whitelist). Drop description, created_at.
42. **Suppression check uses SELECT *** — `packages/db/src/repositories/suppressions.ts` — Called on every send path. Only id, type, scope, email_hash are needed.
43. **Message findById uses SELECT *** — `packages/db/src/repositories/messages.ts` — `html_body` and `text_body` can be megabytes. Add `{ includeBody?: boolean }` option.
44. **7 repositories do separate COUNT then SELECT for pagination** — `packages/db/src/repositories/{events,domains,audit-logs,webhooks,api-keys,tenants,inbound}.ts` — Use `COUNT(*) OVER()` window function (single pass) like messages/suppressions already do.
45. **Audit logs findByResource has no LIMIT** — `packages/db/src/repositories/audit-logs.ts` — A heavily-modified resource could have thousands of entries. Add `LIMIT 100`.
46. **Events findByMessageId has no LIMIT** — `packages/db/src/repositories/events.ts` — A message could have thousands of open/click events. Add `LIMIT 1000` or paginate.
47. **Webhooks findByTenant has no LIMIT** — `packages/db/src/repositories/webhooks.ts` — Returns all webhooks for a tenant. Add pagination.
48. **Missing index on messages.mta_message_id** — `packages/db/src/repositories/messages.ts` — `findByMtaMessageId` does a sequential scan. Add partial index WHERE mta_message_id IS NOT NULL.
49. **Analytics domain aggregation uses expression in GROUP BY** — `packages/db/src/repositories/events.ts` — `SPLIT_PART(recipient_email, '@', 2)` can't use an index. Store domain as a separate indexed column or create functional index.
50. **Audit log hash chain lookup needs composite index** — `packages/db/src/repositories/audit-logs.ts` — `ORDER BY timestamp DESC, id DESC` needs index on `(tenant_id, timestamp DESC, id DESC)`.
51. **Idempotency key cleanup has no LIMIT** — `packages/db/src/repositories/messages.ts` — `DELETE FROM idempotency_keys WHERE expires_at < NOW()` could delete millions of rows. Use batched deletion with LIMIT 10000.
52. **Inbound messages cleanup deletes unbounded rows** — `packages/db/src/repositories/inbound-messages.ts` — Three DELETEs in parallel with no LIMIT can lock millions of rows. Use batched deletion.
53. **Template listVersions missing tenantId parameter** — `apps/api/src/routes/templates.ts` — Repo call has no tenant defense-in-depth at DB level despite ownership check at route level.
54. **Domain DNS health check fetches all verified domains** — `packages/db/src/repositories/domains.ts` — SELECT * with no LIMIT. Add LIMIT 100 and process in batches.
55. **Subscription preference upsert is N sequential INSERTs** — `packages/db/src/repositories/subscriptions.ts` — Loop with individual INSERTs per category. Use single multi-row INSERT with unnest.
56. **Reputation alert check-then-insert TOCTOU** — `packages/db/src/repositories/reputation.ts` — `SELECT COUNT` then `INSERT` race. Use INSERT ... ON CONFLICT.
57. **Events and domains stats have no caching** — `apps/api/src/routes/events.ts`, `apps/api/src/routes/domains.ts` — Hit DB on every request unlike analytics.ts which uses Redis cache-aside.
58. **Analytics correlated subqueries for unique counts** — `apps/worker/src/processors/analytics.ts` — `runCompaction` uses 2 correlated subqueries per row. Pre-compute with single aggregate query and JOIN.
59. **Analytics SCAN on Redis is slow with many keys** — `apps/worker/src/processors/analytics.ts` — Constructs explicit keys instead of SCAN pattern matching thousands of keys.
60. **Control plane dashboard stats has duplicate DB pool** — `apps/control-plane/src/app/api/dashboard/stats/route.ts` — Creates a shadow pool competing with the shared one. Import from `@/lib/db`.

## 4 — PERFORMANCE: RUNTIME (P1)

61. **Suppression cache eviction sorts entire Map on every batch** — `apps/worker/src/processors/email.ts` — Full spread+sort of 10K entries. Use insertion-order eviction or LRU cache library.
62. **Tracking pixel headers rebuilt on every request** — `apps/tracking/src/routes.ts` — Pre-compute the static headers object and Content-Length string at module level.
63. **Tracking bot detection tests 18 regexes sequentially** — `apps/tracking/src/routes.ts` — Combine into single alternation regex for one `.test()` call.
64. **Tracking event processing makes 4+ sequential Redis round-trips** — `apps/tracking/src/event-processor.ts` — Dedup SET NX + RPUSH + INCR pipeline + unique click SET NX. Consolidate into single Lua script.
65. **Tracking double JSON serialization** — `apps/tracking/src/event-processor.ts` — Event is JSON.stringify'd for checksum, then serialized again inside envelope. Construct envelope with raw payload string.
66. **Tracking WAL checksum verification re-serializes on every flush** — `apps/tracking/src/event-processor.ts` — SHA-256 recompute on parse. Consider cheaper hash (xxhash) or skip if Redis AOF guarantees integrity.
67. **Tracking CORS middleware on pixel path is unnecessary** — `apps/tracking/src/routes.ts` — `<img>` tags don't trigger CORS. Remove CORS middleware from pixel path to save 30+ bytes per response.
68. **Tracking Lua script sent as text on every flush** — `apps/tracking/src/event-processor.ts` — Use `defineCommand` / `evalsha` to send only SHA1 hash after first call.
69. **Tracking creates 3 Date objects per event** — `apps/tracking/src/event-processor.ts` — Create one and reuse.
70. **Tracking incrementCounter creates 2 Date objects per call** — `apps/tracking/src/event-processor.ts` — Create one and reuse.
71. **Tracking metrics endpoint makes 5 sequential Redis GETs** — `apps/tracking/src/index.ts` — Use pipeline or MGET for single round-trip.
72. **API sequential audit log writes block responses** — `apps/api/src/routes/*.ts` — Audit logs are `await`ed on every mutation. Fire-and-forget with `.catch(log)` to save one DB round-trip per response.
73. **API sequential domain lookup in batch send** — `apps/api/src/routes/messages.ts` — Loop with `await domainsRepo.findByDomain(domain, tenantId)`. Use `Promise.all()` for concurrent lookups.
74. **API sequential suppression + domain check on send** — `apps/api/src/routes/messages.ts` — Independent queries run sequentially. Use `Promise.all()`.
75. **API message detail: sequential message + events queries** — `apps/api/src/routes/messages.ts` — Use `Promise.all()`.
76. **API domain verify: sequential update + audit + re-read** — `apps/api/src/routes/domains.ts` — Update + audit are independent → `Promise.all()`. Re-read avoidable with RETURNING.
77. **Tracking preferences GET: 3 sequential DB queries** — `apps/tracking/src/routes.ts` — All independent → `Promise.all()`.
78. **Tracking readiness probe: sequential DB + Redis** — `apps/tracking/src/routes.ts` — `Promise.all([db.query('SELECT 1'), redis.ping()])`.
79. **Worker warmup day lookup queries DB per job** — `apps/worker/src/processors/email.ts` — `calculateWarmupDay` does full `findById` per job. Cache with 1-hour TTL per domain.
80. **Worker per-job PG client acquisition** — `apps/worker/src/processors/email.ts` — Every successful send acquires a dedicated PG client for a 3-query transaction. Batch completed jobs per poll cycle.
81. **Webhook per-job PG client acquisition** — `apps/worker/src/processors/webhook.ts` — Same pattern. Batch completions.
82. **DNS resolver created per webhook delivery** — `apps/worker/src/processors/webhook.ts` — `new Resolver()` + `setServers()` per delivery. Create once in constructor.
83. **DNS lookups not cached for webhooks** — `apps/worker/src/processors/webhook.ts` — Same URL gets A+AAAA lookups on every delivery. Add 60s TTL DNS cache.
84. **Webhook response body fully buffered before truncation** — `apps/worker/src/processors/webhook.ts` — Malicious endpoint could send 1GB response body. Use streaming reader with byte limit.
85. **AI tokenizer is O(n × k) for special tokens** — `apps/ai/src/services/tokenizer.ts` — `text.slice(i).startsWith(token)` allocates per character. Use `text.startsWith(token, i)`.
86. **AI vector search is brute-force O(n × d)** — `apps/ai/src/services/vector-store.ts` — Full cosine similarity scan on every query. Use HNSW index for sub-linear search.
87. **AI exportStore serializes entire vector store as JSON** — `apps/ai/src/services/vector-store.ts` — 10K vectors × 384 dims = ~150MB JSON. Use streaming/binary format.
88. **AI LRU eviction is O(n) full scan** — `apps/ai/src/services/vector-store.ts` — Scans entire accessOrder map. Use min-heap or doubly-linked list.
89. **AI Monte Carlo defaults to 10K samples — blocks event loop** — `apps/ai/src/services/send-time-optimizer.ts` — Synchronous loop. Reduce default or run in worker thread.
90. **Sales-autopilot top-leads fetches ALL leads then activities one-by-one** — `apps/sales-autopilot/src/index.ts` — N+1 pattern. Use single query with `WHERE lead_id = ANY($1)`.
91. **Sales-autopilot getReadyEnrollments scans ALL enrollments** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — Linear scan of entire Map. Use DB query `WHERE status = 'active' AND next_step_at <= NOW()`.
92. **Sales-autopilot enrichment makes 3 HTTP requests with no caching** — `apps/sales-autopilot/src/enrichment/company.ts` — Same domain re-enriched on every scoring. Add Redis cache with 24h TTL.
93. **Observability per-row log INSERT in a loop** — `apps/observability/src/services/logging.ts` — N sequential INSERTs. Use single multi-row INSERT.
94. **Observability exportedSpans uses Array.shift() — O(n)** — `apps/observability/src/services/tracing.ts` — Use ring buffer or splice amortization.
95. **Lib Levenshtein uses full O(n×m) matrix** — `packages/lib/src/utils.ts` — Use two-row rolling array with early termination when distance > threshold.
96. **Control plane formatDate creates new Intl.DateTimeFormat per call** — `apps/control-plane/src/lib/utils.ts` — Cache formatter at module level.
97. **API pg_stat_activity query on every readiness probe** — `apps/api/src/routes/health.ts` — Use pool's in-memory totalCount/idleCount instead.
98. **API webhook list filters in application memory** — `apps/api/src/routes/webhooks.ts` — Fetches all webhooks then filters. Push enabled/event filters to SQL.
99. **AI InferenceEngine created 3 times independently** — `apps/ai/src/services/{chatbot,content-generator,embeddings}.ts` — Each service creates its own engine. Share via dependency injection.
100. **Sales-autopilot pipeline operations use linear scans** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — `getLeadEnrollments`, `getTenantCampaigns`, `getActivePromos` all do Array.from().filter(). Add secondary indexes (Maps by tenantId, leadId).

## 5 — PERFORMANCE: CONCURRENCY & QUEUING (P1)

101. **Webhook per-tenant limit releases job with no delay** — `apps/worker/src/processors/webhook.ts` — Job immediately re-released to `pending`. On next 100ms poll, same job re-fetched → hot loop. Set `scheduled_at = NOW() + INTERVAL '5s'`.
102. **Webhook retry max delay cap too low at 60s** — `apps/worker/src/processors/webhook.ts` — Exhausts retries during a 5-minute outage. Increase to 300s.
103. **Analytics processor ignores concurrency config** — `apps/worker/src/processors/analytics.ts` — `concurrency` is accepted but unused. Processes batches sequentially.
104. **Analytics concurrent flush risk** — `apps/worker/src/processors/analytics.ts` — Timer and buffer-full can trigger `flushBuffers()` concurrently. Add flushing mutex.
105. **Analytics hourly aggregation scheduling drift** — `apps/worker/src/processors/analytics.ts` — Next timer scheduled when current run starts, not finishes. Move scheduling to after completion.
106. **Worker stale job recovery misses analytics_queue** — `apps/worker/src/index.ts` — Only sweeps `email_queue` and `webhook_queue`.
107. **Analytics eventBuffer has no size cap** — `apps/worker/src/processors/analytics.ts` — Grows without bound if Postgres is down. Add MAX_EVENT_BUFFER_SIZE.
108. **Reply handler processes messages sequentially** — `apps/worker/src/processors/reply.ts` — 100 messages processed one at a time including LLM calls. Use `Promise.allSettled` with concurrency limit.
109. **Reply handler has no stale processing recovery** — `apps/worker/src/processors/reply.ts` — Crashed worker leaves messages stuck in `processing_at IS NOT NULL`. Add sweep to main worker loop.
110. **Circuit breaker HALF_OPEN → CLOSED success counter has no TTL** — `apps/worker/src/utils/circuit-breaker.ts` — Stale successes from hours ago can close the circuit. Add TTL.
111. **Circuit breaker OPEN → HALF_OPEN has no concurrency control** — `apps/worker/src/utils/circuit-breaker.ts` — All concurrent callers transition and send requests. Use Redis SET NX.
112. **Circuit breaker Redis keys have no TTL** — `apps/worker/src/utils/circuit-breaker.ts` — Accumulate forever. Set 24h TTL.
113. **Circuit breaker success-in-CLOSED deletes failure count** — `apps/worker/src/utils/circuit-breaker.ts` — One success resets all failures. Let rolling window handle expiration naturally.
114. **Worker email requeue uses flat 60s delay** — `apps/worker/src/processors/email.ts` — Ignores rate limiter's computed `retryAfter` value.
115. **Worker uncaughtException handler runs async shutdown** — `apps/worker/src/index.ts` — Process is in undefined state after uncaught exception. Should log and `process.exit(1)` immediately.
116. **Worker process.exit(0) in shutdown prevents finally blocks** — `apps/worker/src/index.ts` — Let event loop drain naturally after cleanup.
117. **Worker metrics server stopped before processors in shutdown** — `apps/worker/src/index.ts` — Lose observability during critical drain phase. Move after processors stop.
118. **Worker heartbeat reports stale processor count** — `apps/worker/src/index.ts` — `activeProcessors` captured by closure at startup, never updated.
119. **Worker rate limiter waitQueue has no per-waiter timeout** — `apps/worker/src/processors/email.ts` — Promise hangs forever if refill rate is low. Add 30s per-waiter timeout.
120. **Tracking flush timer uses setInterval — fires even during active flush** — `apps/tracking/src/event-processor.ts` — Use setTimeout with re-scheduling after each flush completes.

## 6 — UNWIRED & DEAD CODE (P1)

121. **Sales-autopilot campaignRepository not wired at startup** — `apps/sales-autopilot/src/index.ts` — `setCampaignRepository()` never called. Drip engine falls back to in-memory only.
122. **Sales-autopilot Redis config defined but never used** — `apps/sales-autopilot/src/index.ts` — Parsed config exists but no Redis connection is created. Wire for rate limiting, caching.
123. **Sales-autopilot `getLeadsNeedingAttention` exported but never called** — `apps/sales-autopilot/src/leads/scoring.ts` — Wire to cron job or route endpoint.
124. **Sales-autopilot `getOverdueTasks`, `getLeadsNeedingFollowUp`, `getRottenLeads` exported but unused** — `apps/sales-autopilot/src/leads/pipeline.ts` — Wire to route handlers or scheduled jobs.
125. **Sales-autopilot demo slot generator creates ephemeral IDs** — `apps/sales-autopilot/src/leads/calendar.ts` — Generated slots shadow module-level Map. `bookSlot()` always returns null for generated slots.
126. **Sales-autopilot ICS endpoint uses mock slot data** — `apps/sales-autopilot/src/index.ts` — Returns "tomorrow" regardless of actual booking. Look up actual slot.
127. **Sales-autopilot inbox message never persisted** — `apps/sales-autopilot/src/index.ts` — Classified message returned via HTTP but never stored in DB.
128. **Sales-autopilot LinkedIn enrichment always fails** — `apps/sales-autopilot/src/enrichment/company.ts` — LinkedIn serves JS-rendered pages to non-browser agents. Always returns `{}`.
129. **Sales-autopilot lead scoring discards enrichment data** — `apps/sales-autopilot/src/index.ts` — Enrichment is fetched for scoring but not persisted. Re-enriches on every score request.
130. **AI `RedisPatternStore` class is dead code (424 lines)** — `apps/ai/src/services/pattern-store.ts` — Exported but never instantiated. Wire into STO or remove.
131. **AI `sentimentAnalyzer` singleton never used** — `apps/ai/src/services/sentiment.ts` — Module-level singleton created but `contentGenerator` creates its own instance.
132. **AI `SentimentAnalyzer` NB model never trained in production** — `apps/ai/src/services/sentiment.ts` — Always falls through to AFINN lexicon path. Either pre-train or remove NB wrapper.
133. **AI `engagementData` Map has no persistence** — `apps/ai/src/services/send-time-optimizer.ts` — Service restart = total data loss. Wire Redis persistence.
134. **AI `serviceBootstrap` module singleton unused** — `apps/ai/src/index.ts` — Separate instance created in bootstrap `initialize()`. Remove dead export.
135. **Reply handler Redis instance stored but never used** — `apps/worker/src/processors/reply.ts` — `_redis`, `_queueKey`, `_processedKey` all suppressed with `@ts-expect-error`. Implement dedup or remove.
136. **Tracking dead code: isDuplicate method** — `apps/tracking/src/event-processor.ts` — Suppressed with `@ts-expect-error`. Superseded by `isDuplicateWithTTL`. Delete.
137. **Tracking dead code: _markProcessed method** — `apps/tracking/src/event-processor.ts` — Same. Delete.
138. **Control plane secrets API is hardcoded demo data** — `apps/control-plane/src/app/api/secrets/route.ts` — Mutations are no-ops. Return 501 or wire to vault.
139. **Control plane feature flags API is hardcoded** — `apps/control-plane/src/app/api/features/route.ts` — Toggles not persisted. Wire to DB or return 501.
140. **Control plane system health API is hardcoded** — `apps/control-plane/src/app/api/system/health/route.ts` — Shows fake healthy status. Wire to service queries.
141. **Control plane calendar, support, content, inbox, IP warmer, lead discovery APIs all hardcoded** — `apps/control-plane/src/app/api/*/route.ts` — 6 API endpoints return static demo data.
142. **Observability dead spans Map field** — `apps/observability/src/services/tracing.ts` — `spans: Map` initialized but never written to.
143. **Observability stub methods: `analyzePerformanceAnomaly`, `detectBottleneck`** — `apps/observability/src/services/tracing.ts` — Only set Redis keys but do no real work.
144. **Observability `getIndustryBenchmarks` returns hardcoded values** — `apps/observability/src/services/metrics.ts` — Ignores `industry` parameter.
145. **Messages `archiveOld` is a no-op placeholder** — `packages/db/src/repositories/messages.ts` — Only counts rows, never actually archives.
146. **Ops `notifySubscribers` is unimplemented** — `apps/ops/src/services/status-page.ts` — Emits events but no delivery.
147. **Ops all StatusPage/ComplianceManager state is in-memory only** — `apps/ops/src/services/status-page.ts`, `apps/ops/src/services/compliance-manager.ts` — Process restart loses everything.
148. **HA STONITH fencing is a no-op stub** — `apps/ha/src/services/failover.ts` — Only emits event, doesn't isolate region.
149. **Edge-cases ClamAV health check is no-op** — `apps/edge-cases/src/app.ts` — Try block never actually connects to ClamAV.
150. **DevEx sandbox stats use in-memory increment** — `apps/devex/src/services/sandbox.ts` — Concurrent requests produce lost-update race. Use DB `UPDATE ... SET api_calls = api_calls + 1`.

## 7 — IN-MEMORY STATE THAT SHOULD BE IN DATABASE (P1)

151. **Sales-autopilot promo configs/stats in Maps** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — Create `promo_configs` table. Persist on create/update/delete.
152. **Sales-autopilot demo slots/scheduling prefs in Maps** — `apps/sales-autopilot/src/leads/calendar.ts` — Create `demo_slots` and `scheduling_preferences` tables.
153. **Sales-autopilot domain rate-limit buckets in Map** — `apps/sales-autopilot/src/enrichment/scraper.ts` — Use Redis-backed token buckets for multi-instance rate limiting.
154. **Sales-autopilot robots.txt cache in Map** — `apps/sales-autopilot/src/enrichment/scraper.ts` — Store parsed rules in Redis with 1-hour TTL.
155. **Ops StatusPage components/incidents/subscribers** — `apps/ops/src/services/status-page.ts` — Persist to database, hydrate on startup.
156. **Ops ComplianceManager certifications/documents** — `apps/ops/src/services/compliance-manager.ts` — Same as above.
157. **AI engagementData** — `apps/ai/src/services/send-time-optimizer.ts` — Persist patterns to Redis, use Map as L1 cache.
158. **AI historicalData/subscriberData** — `apps/ai/src/services/send-time-optimizer.ts` — Cap + persist.
159. **AI chatbot pendingActions** — `apps/ai/src/services/chatbot.ts` — Add TTL-based cleanup or DB persistence.
160. **Observability alerting 5 unbounded Maps** — `apps/observability/src/services/alerting.ts` — Add max-size cap + LRU eviction, or move to Redis.

## 8 — MISSING ERROR HANDLING (P1–P2)

161. **API c.req.json() throws SyntaxError → 500 on malformed JSON** — `apps/api/src/app.ts` — Add SyntaxError case to global error handler returning 400.
162. **API auth routes on public router without authentication** — `apps/api/src/app.ts` — `/me`, `/logout`, `/refresh`, `/csrf-token` are unauthenticated. Split into public (login only) and protected sub-routers.
163. **Analytics pipeline.exec() errors silently ignored** — `apps/worker/src/processors/analytics.ts` — Redis pipeline returns `[error, result]` tuples. Check for errors.
164. **Analytics flush error logged twice** — `apps/worker/src/processors/analytics.ts` — `flushBuffers` re-throws after logging. Timer `.catch()` logs again. Don't re-throw.
165. **Reply handler LLM response parsed without validation** — `apps/worker/src/processors/reply.ts` — Cast without verifying classification enum or confidence range.
166. **Reply handler LLM fetch has no timeout** — `apps/worker/src/processors/reply.ts` — Can hang indefinitely. Add `AbortSignal.timeout(10000)`.
167. **Reply handler `?` regex matches any email with a question mark** — `apps/worker/src/processors/reply.ts` — Pattern `/\?/` in question-detection fires on URLs. Require word boundary context.
168. **Reply handler pattern matching never short-circuits** — `apps/worker/src/processors/reply.ts` — All 80 regexes tested even after high-confidence match. Short-circuit above 0.8.
169. **Reply handler word matching has no word boundaries** — `apps/worker/src/processors/reply.ts` — `'yes'.includes('yes')` also matches "yesterday". Use `\b` regex.
170. **Webhook delivery attempt not recorded on non-retryable failure** — `apps/worker/src/processors/webhook.ts` — `failJob` skips intermediate attempt record. Always record attempt.
171. **Webhook tenantActiveJobs can become permanently inflated** — `apps/worker/src/processors/webhook.ts` — Error before `finally` block leaves count inflated, blocking all tenant jobs.
172. **Webhook dedup query depends on payload JSON structure** — `apps/worker/src/processors/webhook.ts` — Use dedicated `dedup_key` column instead of JSON path queries.
173. **Metrics server histogram +Inf bucket miscounted** — `apps/worker/src/utils/metrics.ts` — Values exceeding largest bucket (10s) not incremented into any bucket. Add overflow handler.
174. **Metrics server has no request timeout** — `apps/worker/src/utils/metrics.ts` — Slow Prometheus scraper can hold connection indefinitely. Add `server.setTimeout(5000)`.
175. **Metrics server stop() has no close timeout** — `apps/worker/src/utils/metrics.ts` — Can hang if connections are open. Use `server.closeAllConnections()`.
176. **Notifier listener leaks on stop** — `apps/worker/src/utils/notifier.ts` — `once(channel)` listener not removed when notifier is stopped.
177. **Sales-autopilot c.req.json() no try/catch** — `apps/sales-autopilot/src/index.ts` — Multiple routes crash on malformed JSON. Add global SyntaxError handler.
178. **Sales-autopilot batch enrichment no array limit** — `apps/sales-autopilot/src/index.ts` — Single request can trigger thousands of HTTP requests. Limit to 100.
179. **Sales-autopilot storeLead failure aborts entire batch** — `apps/sales-autopilot/src/enrichment/scraper.ts` — One failure kills remaining leads. Wrap per-item in try/catch.
180. **Compliance CronJob instances not tracked for shutdown** — `apps/compliance/src/routes.ts` — Store refs and call `.stop()` on SIGTERM.
181. **Compliance GDPR export stored in DB TEXT column** — `apps/compliance/src/routes.ts` — Large exports blow up database. Use object storage.
182. **Compliance risk reassessment has no concurrency guard** — `apps/compliance/src/routes.ts` — Overlapping cron runs reassess same tenants.
183. **HA failover distributed lock has no fencing token** — `apps/ha/src/services/failover.ts` — Slow process losing lock can still complete failover. Implement fencing tokens.
184. **HA pg_dump stderr not captured at error level** — `apps/ha/src/services/backup.ts` — Failures go unnoticed.
185. **HA WAL archiving doesn't verify success** — `apps/ha/src/services/replication.ts` — Missed WAL segment breaks PITR.
186. **Observability evaluation loop has no error handling** — `apps/observability/src/services/alerting.ts` — Single throw kills the interval loop. Wrap body in try/catch.
187. **Observability advisory lock not released in finally** — `apps/isolation/src/services/data-isolation.ts` — RLS policy creation failure leaks the lock.
188. **Observability alert sorted-set removes before processing** — `apps/observability/src/services/alerting.ts` — Worker crash loses message IDs. Use ZPOPMIN or two-phase.
189. **AI JSON.parse at module top-level with no try/catch** — `apps/ai/src/index.ts` — `JSON.parse(process.env.AI_MODELS)` crashes on invalid JSON.
190. **AI isMainModule check broken for ESM** — `apps/ai/src/index.ts` — `require.main === module` doesn't work in ESM. Use `import.meta.url`.

## 9 — MISSING VALIDATION (P2)

191. **API events batch: recipientEmail set to empty string** — `apps/api/src/routes/events.ts` — Breaks analytics queries. Actually look up the message.
192. **API events: missing date range validation on 5 stats endpoints** — `apps/api/src/routes/events.ts` — Unbounded aggregation queries possible. Apply 90-day cap.
193. **API events: missing UUID validation on eventId** — `apps/api/src/routes/events.ts` — Add regex check before DB call.
194. **API events: missing scope validation for events:write** — `apps/api/src/routes/events.ts` — Scope not in VALID_SCOPES enum.
195. **API messages: missing status enum validation on list** — `apps/api/src/routes/messages.ts` — `as` cast provides no runtime validation.
196. **API messages: missing date validation on since/until** — `apps/api/src/routes/messages.ts` — `new Date(invalid)` produces NaN date silently.
197. **API messages: messageId UUID validation on events sub-route** — `apps/api/src/routes/messages.ts` — Missing for `/messages/:messageId/events`.
198. **API domains: missing status enum validation** — `apps/api/src/routes/domains.ts` — Invalid status values pass to SQL.
199. **API domains: missing NaN/negative guard on limit/offset** — `apps/api/src/routes/domains.ts` — `parseInt(NaN)` passes through.
200. **API suppressions: missing type/scope enum validation** — `apps/api/src/routes/suppressions.ts` — `as` cast has no runtime check.
201. **API suppressions: missing UUID validation on suppression ID params** — `apps/api/src/routes/suppressions.ts` — 2 route params.
202. **API suppressions: remove only deletes first suppression** — `apps/api/src/routes/suppressions.ts` — Email with multiple suppression types only removes first.
203. **API templates: search param has no length limit** — `apps/api/src/routes/templates.ts` — Can trigger expensive LIKE queries.
204. **API templates: duplicate body not validated** — `apps/api/src/routes/templates.ts` — `body.name` can be 10MB.
205. **API webhooks: creation drops validated fields** — `apps/api/src/routes/webhooks.ts` — `timeout`, `retryConfig`, `maxRetries`, `headers` validated but not passed to repo.
206. **API webhooks: test endpoint leaks remote response body** — `apps/api/src/routes/webhooks.ts` — Up to 1000 chars of target server response. Redact in production.
207. **API analytics: missing NaN guard on limit in campaigns** — `apps/api/src/routes/analytics.ts` — `parseInt` NaN fallthrough.
208. **API analytics: missing sort validation** — `apps/api/src/routes/analytics.ts` — Invalid sortBy values silently ignored.
209. **API health: deep check exposes internal system details** — `apps/api/src/routes/health.ts` — DB connection counts, memory, event loop lag. Add authentication.
210. **Tracking: List-Unsubscribe body not trimmed** — `apps/tracking/src/routes.ts` — RFC 8058 body may have trailing CRLF. Call `.trim()`.
211. **Tracking: decodeURIComponent can throw on malformed %** — `apps/tracking/src/routes.ts` — Click handler doesn't wrap in try/catch.
212. **Tracking: domain matching is case-sensitive** — `apps/tracking/src/routes.ts` — DNS domains are case-insensitive. Normalize to lowercase.
213. **Tracking: link hash keys have no TTL** — `apps/tracking/src/routes.ts` — Redis hash `links:{tenantId}:{messageId}` grows forever. Add EXPIRE.
214. **Tracking: fire-and-forget hset swallows errors silently** — `apps/tracking/src/routes.ts` — `.catch(() => {})`. At least log.
215. **Tracking: unsubscribe webhook queueing blocks response** — `apps/tracking/src/routes.ts` — `await queueUnsubscribeWebhook(...)` is on critical path. Fire-and-forget.
216. **Tracking: webhook queue insert has no transaction/batching** — `apps/tracking/src/routes.ts` — Per-webhook INSERT in a loop. Batch and wrap in transaction.
217. **Tracking: Redis suppression publish awaited** — `apps/tracking/src/event-processor.ts` — `await redis.publish()` blocks. Fire-and-forget.
218. **Tracking: EventProcessor flushIntervalMs=1000, maxBufferSize=100 caps throughput** — `apps/tracking/src/index.ts` — 100 events/sec max. Increase to 500-1000.
219. **Tracking: Redis missing enableOfflineQueue: false** — `apps/tracking/src/index.ts` — When Redis down, commands buffer unboundedly → OOM. Fail fast.
220. **Tracking: shutdown timeout 15s may be too short for deep WAL** — `apps/tracking/src/index.ts` — Make configurable, increase to 30s.

## 10 — MISSING INDEXES & SCHEMA (P2)

221. **Missing composite index: events (tenant_id, message_id)** — For tenant-scoped joins.
222. **Missing composite index: audit_logs (tenant_id, timestamp DESC, id DESC)** — For hash chain lookups.
223. **Missing partial index: smtp_credentials (created_at) WHERE is_active = true** — For credential rotation queries.
224. **Missing functional index: events split_part(recipient_email, '@', 2)** — For domain-level analytics.
225. **Missing index: messages (tenant_id, to_address, created_at DESC)** — For tracking unsubscribe message lookup.
226. **Missing index: webhook_deliveries (webhook_id, delivered_at)** — For webhook health checks on every failure.
227. **Missing advisory: compaction_log unique date index** — For efficient compaction status lookups.
228. **Missing index: inbound_messages processing_at** — For stale processing recovery sweep.
229. **Observability routes: /traces/stats overshadowed by /traces/:traceId** — Register static routes before parameterized ones.
230. **Observability routes: /incidents/summary overshadowed** — Same issue.

## 11 — RESOURCE LEAKS (P2)

231. **Tracking flush timer interval never cleared properly** — `apps/tracking/src/event-processor.ts` — Use setTimeout pattern instead.
232. **AI rate limit cleanup interval never cleared on shutdown** — `apps/ai/src/index.ts` — Store handle, `.unref()`, clear on shutdown.
233. **AI module-level service instantiation — 8 eager singletons** — `apps/ai/src/index.ts` — Double-loads models. Use lazy getters or inject from bootstrap.
234. **Observability deduplication cleanup interval not unref'd** — `apps/observability/src/services/alerting.ts`.
235. **Observability SLOManager refresh interval no stop method** — `apps/observability/src/services/metrics.ts`.
236. **Observability MetricsCollector leak detection — interval per connection** — `apps/observability/src/services/metrics.ts` — Use single service-level sweep instead.
237. **Observability log stream timers not cleared on stream deletion** — `apps/observability/src/services/logging.ts`.
238. **Ops no graceful shutdown handler** — `apps/ops/src/index.ts` — No SIGTERM/SIGINT handlers at all.
239. **Ops incident escalation timers not unref'd** — `apps/ops/src/services/incident-manager.ts`.
240. **HA monitoring intervals not unref'd** — `apps/ha/src/services/monitoring.ts`.
241. **HA failover history unbounded** — `apps/ha/src/services/failover.ts` — Add MAX_FAILOVER_HISTORY cap.
242. **HA chaos experiment Map never cleaned up** — `apps/ha/src/services/chaos.ts` — Expired experiments not removed.
243. **Control plane DB pool no error handler** — `apps/control-plane/src/lib/db.ts` — Idle client error crashes process.
244. **Control plane DB pool no shutdown hook** — `apps/control-plane/src/lib/db.ts` — Connections leak on exit.
245. **Control plane loginAttempts Map never cleaned up** — `apps/control-plane/src/app/api/auth/login/route.ts` — Grows without bound.
246. **Sales-autopilot enrollments Map keeps completed enrollments** — `apps/sales-autopilot/src/campaigns/drip-engine.ts` — Remove terminal-state entries.
247. **Sales-autopilot domainBuckets Map never pruned** — `apps/sales-autopilot/src/enrichment/scraper.ts`.
248. **Sales-autopilot demo slots Map grows without bound** — `apps/sales-autopilot/src/leads/calendar.ts`.
249. **AI chatbot pendingActions Map has no TTL** — `apps/ai/src/services/chatbot.ts`.
250. **AI pullHistory array grows unboundedly** — `apps/ai/src/services/send-time-optimizer.ts` — Cap at 100K entries.

## 12 — MISSING RETURNING / ROWCOUNT CHECKS (P2)

251. **tenants.activate — no RETURNING** — `packages/db/src/repositories/tenants.ts` — Caller needs separate findById.
252. **tenants.updateSettings — no RETURNING** — Same.
253. **domains.markExpired — no RETURNING or rowCount check** — Silent failure if domain not found.
254. **users.updatePassword — no rowCount check** — Silent failure on non-existent user.
255. **api-keys.revoke — no rowCount check** — Silent if key already revoked.
256. **webhook-queue markDelivered — no rowCount check** — Silent if job gone.
257. **webhook-queue markFailed — no rowCount check** — Same.
258. **webhooks.recordFailure — no RETURNING or rowCount** — `WHERE failure_count >= 9` check but no verification webhook still exists.

## 13 — REPOSITORY CONSISTENCY (P2)

259. **WebhooksRepository takes raw Pool instead of DatabasePool** — Bypasses leak detection, slow query logging.
260. **InboundMessagesRepository takes raw Pool** — Same.
261. **SubscriptionsRepository takes raw Pool** — Same.
262. **SmtpCredentialsRepository takes raw Pool** — Same.
263. **ReputationRepository takes raw Pool** — Same.
264. **SystemRepository takes raw Pool** — Same.
265. **webhooks.recordFailure has no tenant_id in WHERE** — `UPDATE webhooks SET ... WHERE id = $1` missing tenant guard.

## 14 — SQL SAFETY (P2)

266. **Analytics DATE_TRUNC interpolation** — `packages/db/src/repositories/events.ts` — String interpolates granularity into SQL. Whitelist-validate before use.
267. **Billing DATE_TRUNC interpolation** — `apps/billing/src/index.ts` — Same pattern.
268. **Analytics domain DATE_TRUNC interpolation** — `packages/db/src/repositories/events.ts` — Same.
269. **Worker stale job recovery table name interpolation** — `apps/worker/src/index.ts` — `${table}` in SQL. Add whitelist guard.
270. **API key debounce interval interpolation** — `packages/db/src/repositories/api-keys.ts` — Computed constant interpolated. Use $N parameter.
271. **Observability time_bucket interval interpolation** — `apps/observability/src/services/metrics.ts` — Whitelist valid intervals.
272. **Observability aggregation function interpolation** — `apps/observability/src/services/metrics.ts` — Whitelist valid functions.
273. **Isolation CREATE SCHEMA string template** — `apps/isolation/src/services/data-isolation.ts` — Verify sanitizer or use `format()`.

## 15 — SDK IMPROVEMENTS (P2)

274. **Node SDK: no idempotency key support** — `packages/sdk-node/src/resources/emails.ts` — Python SDK supports it but Node doesn't.
275. **Node SDK: no ID validation before URL interpolation** — `packages/sdk-node/src/resources/*.ts` — Path traversal risk.
276. **Node SDK: no debug/logging mode** — No way to trace outgoing requests for integration debugging.
277. **Node SDK: no AbortSignal support** — Can't cancel in-flight requests.
278. **Node SDK: domains.list has no pagination** — `packages/sdk-node/src/resources/domains.ts`.
279. **Node SDK: apiKeys.list has no pagination** — Same.
280. **Node SDK: webhooks.list has no pagination** — Same.
281. **Node SDK: whitespace-only body passes validation** — `packages/sdk-node/src/resources/emails.ts` — `' '` is truthy.
282. **Node SDK: undefined values serialized as null** — `packages/sdk-node/src/resources/emails.ts` — Filter before JSON.stringify.
283. **Node SDK: baseUrl no format validation** — Accept only valid HTTPS URLs.
284. **Node SDK: analytics getStats no date range validation** — start must be < end.
285. **Node SDK: timeout not cleared after response body read** — Race condition on slow body parsing.
286. **Python SDK: batch() no size limit** — `packages/sdk-python/src/apexmail/resources/emails.py` — Node validates ≤ 1000.
287. **Python SDK: no email format validation** — `packages/sdk-python/src/apexmail/resources/emails.py`.
288. **Python SDK: no body presence validation** — At least one of html/text required.
289. **Python SDK: domains.list no pagination** — Same gap as Node SDK.
290. **Python SDK: webhooks.list no pagination** — Same.
291. **Python SDK: no ID validation on get/update/delete** — Path traversal risk.
292. **Python SDK: webhook create no HTTPS validation** — Allows HTTP URLs.
293. **Python SDK: webhook update sends empty payload** — All kwargs None → sends `{}`.
294. **Python SDK: _request doesn't handle 204 No Content** — Falls through to error handler.
295. **Python SDK: event name enum differs from Node SDK** — `email.sent` vs `email_sent`. Align across SDKs.
296. **Python SDK: sync client no __del__ fallback** — Connection leak if `close()` forgotten.
297. **Python SDK: massive code duplication sync/async** — Extract shared payload-building base class.

## 16 — CONTROL PLANE (P2)

298. **9 API route files return demo data on error** — Revenue, CRM, Risk, Audit, Campaigns, Compliance, Secrets, System Health, Calendar. Return 500 instead.
299. **controlPlaneFetch never checks response.ok** — `apps/control-plane/src/lib/api.ts` — 16+ functions parse error responses as valid data.
300. **controlPlaneFetch has no timeout** — Hung upstream blocks indefinitely. Add AbortController with 10s timeout.
301. **controlPlaneFetch has no retry logic** — No retries for transient 5xx.
302. **6 API list endpoints missing pagination** — Tenants, GDPR, CRM leads, Risk, Campaigns, Audit.
303. **Dashboard stats returns 200 on DB failure** — Returns zeroed data. Return 500 or include error field.
304. **IP spoofing via X-Forwarded-For in login + middleware** — Trust rightmost untrusted, not leftmost.
305. **Impersonation doesn't validate tenantId exists** — Token issued for non-existent tenant.
306. **SSRF allowlist checks use substring matching** — `':3001'` blocks false positives. Use origin allowlist.
307. **Duplicate `fetchMetrics` functions** — `apps/control-plane/src/lib/api.ts` — Consolidate.

## 17 — SALES-AUTOPILOT (P2)

308. **Campaign stats increment is non-atomic** — `drip-engine.ts` — `campaign.stats.totalEnrolled++` is read-modify-write. Use DB atomic UPDATE.
309. **Slot booking has no CAS guard** — `calendar.ts` — Concurrent bookings both see `available`. Use `UPDATE ... WHERE status = 'available'`.
310. **Campaign processor processes enrollments sequentially** — `drip-engine.ts` — 100 enrollments take 100× time. Use `Promise.allSettled` with concurrency.
311. **Promo click/conversion no error handling** — `drip-engine.ts` — `recordClick()` silently drops for missing promos. Return 404.
312. **DB persist failures swallowed in campaign creation** — `drip-engine.ts` — Catches error, logs, returns success. Propagate to caller.
313. **DB persist failures swallowed in enrollment** — Same pattern.
314. **Calendar generateSlots has no upper bound** — `calendar.ts` — Year 2100 end date → millions of slots.
315. **Discovery maxPagesPerSource has no upper bound** — 1000 → thousands of scrape requests.
316. **Top-leads loads all tenant leads into memory** — Use pagination/streaming.
317. **getRottenLeads loads all tenant leads for JS filtering** — Push logic into SQL WHERE clause.
318. **filterLeads returns all matching leads with no pagination** — Add LIMIT/OFFSET.
319. **ScrapeResult interface declared twice** — Remove duplicate at L120.
320. **updatePromoConfig Object.assign allows overwriting id/tenantId** — Runtime bypass of TypeScript Omit. Destructure only allowed fields.
321. **Compiled regex patterns use /g flag with .test()** — `lastIndex` state causes skipped matches. Use non-g patterns with replaceAll.
322. **Stage matching uses name-to-snake conversion** — Fragile. Match by stage id or enum value directly.
323. **totalValue always returns 0** — `const totalValue = 0` never updated. Fix or remove.
324. **extractFirstName guesses from email** — `sales@acme.com` → "Sales". Prefer enrichment data.
325. **scrapedToLeads returns Partial<Lead> cast to Lead** — Missing required fields. Validate before storeLead.

## 18 — OBSERVABILITY & OPS (P2)

326. **Observability dataStore Map keys unbounded** — `apps/observability/src/services/metrics.ts` — Unique metric+label combos accumulate. Add MAX_KEYS cap.
327. **Observability notifications array unbounded** — `apps/observability/src/services/alerting.ts` — Never trimmed.
328. **Observability incidentHistory truncation copies entire array** — `apps/ops/src/services/incident-manager.ts` — Use `splice(0, excess)` instead of `slice`.
329. **Ops parseInt without NaN guard** — Multiple routes accept invalid limit/offset.
330. **Ops incident IDs use Date.now() + Math.random()** — Use crypto.randomUUID().
331. **Ops escalation timers not unref'd** — Prevent clean exit.
332. **Ops EventEmitters don't set maxListeners** — Default 10 → Node warning. Set to 50.
333. **Ops health checks silently pass when no handler registered** — Should fail-open with warning.
334. **Ops label parsing is brittle** — `pair.split('=')` breaks on values containing `=`.
335. **Ops metrics push gateway has no retry** — Transient failures drop metrics.

## 19 — HA & ENTERPRISE (P2)

336. **HA distributed lock has no fencing token** — Slow process can complete stale failover.
337. **HA region health Map — no validation on regions count** — Accept unlimited regions.
338. **HA chaos experiments can run in production** — config override bypasses NODE_ENV check.
339. **HA backup encryption key optional in code** — Config throws but service accepts undefined.
340. **HA Redis circuit breaker state persistence — no reconnection handling** — Silent failures reset all circuits on restart.
341. **Enterprise SAML request ID missing underscore prefix** — Spec recommends `_` prefix for XML IDs.
342. **Enterprise SandboxEnvironment array per sandbox unbounded** — Cap at MAX_CAPTURES.
343. **Enterprise private-deploy sanitizeIdentifier strips hyphens** — `apex-mail` → `apexmail`. Allow hyphens/dots.
344. **Enterprise credential encryption should use AES-GCM** — Currently CBC without HMAC.
345. **Enterprise deep path traversal — continue vs return** — `__proto__` path skips one segment but continues traversal.

## 20 — TRACKING OPTIMIZATION (P2)

346. **Tracking pool max connections too low (25)** — Increase to 50 for high-throughput.
347. **Tracking Redis missing enableReadyCheck and connectTimeout** — Add for reliability.
348. **Tracking Redis double-prefixes keys** — `keyPrefix: 'tracking:'` + key constants already include `tracking:`.
349. **Tracking pool idle timeout 10s causes churn** — Increase to 30s.
350. **Tracking rate limit EXPIRE called on every request** — Use Lua script to EXPIRE only on first INCR.
351. **Tracking 429 returns JSON for pixel requests** — Return transparent GIF with 429 status instead.
352. **Tracking 429 missing Retry-After header** — Per RFC 6585.
353. **Tracking logging middleware runs on /health** — Floods logs with K8s probes. Skip health paths.
354. **Tracking health endpoint always returns 200** — No actual health check. Add event loop check.
355. **Tracking unhandledRejection triggers full shutdown** — Too aggressive. Use error counter threshold.
356. **Tracking click handler: domain verification on critical path** — Pre-warm cache at startup.
357. **Tracking preferences per-category INSERT in loop** — Use single multi-row INSERT with unnest.
358. **Tracking webhook queue per-webhook INSERT in loop** — Batch into single multi-row INSERT.
359. **Tracking codec Buffer.alloc instead of allocUnsafe** — All bytes written. Use allocUnsafe for speed.
360. **Tracking codec decode no bounds checking** — Corrupted token can read past buffer end.

## 21 — BILLING & MTA (P2)

361. **Billing usage query DATE_TRUNC interpolation** — Use parameterized or whitelist.
362. **Billing dunning schedule in-memory only** — Should be DB-backed for persistence.
363. **Billing invoice PDF HTML has XSS risk** — User data injected into HTML. Escape.
364. **Billing shutdown doesn't clean up timers** — Multiple intervals/timeouts not cleared.
365. **MTA inbound message INSERT has no dedup** — Retried SMTP sessions create duplicates. Add ON CONFLICT.
366. **MTA bounce/complaint cleanup unbounded DELETE** — Add LIMIT for batched deletion.
367. **MTA resolver created per DNS lookup** — Create once in constructor, reuse.

## 22 — LIB & SHARED (P2)

368. **InMemoryCache setNX is not atomic** — `await` between check and set creates re-entrancy window.
369. **InMemoryCache incr is not atomic** — Same issue.
370. **InMemoryCache incrWithExpire resets TTL on every call** — Sliding window changes rate-limiter semantics.
371. **RateLimiter tenantCounts never shrinks** — No cap on distinct tenant IDs within a window.
372. **Queue job payload JSON.parse with no try-catch** — Corrupt payload crashes dequeue loop.
373. **deriveKeySync blocks event loop** — Provide async counterpart for non-startup code.
374. **HTTP client retry has no jitter** — Thundering herd on retries. Add randomized jitter.
375. **gRPC proto object reloaded on every connect** — Cache at module level.
376. **AWS SigV4 signer incomplete** — Missing query strings, multi-value headers, session tokens. Use `@aws-sdk/s3-request-presigner`.
377. **S3 cleanup no concurrency guard** — Parallel runs can double-delete.
378. **MJML compile warnings discarded** — Include in result for template authors.
379. **Logger singleton ignores different options on subsequent calls** — Throw if options differ.
380. **Template engine only uses simple regex** — Stored engine type (handlebars/liquid/ejs) ignored.

## 23 — AI SERVICE (P2)

381. **AI subject line check precedence wrong** — `if (length > 60) ... else if (length > 70)` — 70 check unreachable. Reverse order.
382. **AI Math.random() sort for shuffle** — Biased, spec-violating. Use Fisher-Yates.
383. **AI cosine similarity divide by zero** — Zero-magnitude vectors → NaN. Guard.
384. **AI inference queue processes items one at a time** — Named "batch queue" but sequential. Drain multiple items.
385. **AI inference queue timeout can corrupt another item** — `splice(findIndex)` returns -1 → removes last item.
386. **AI Gamma distribution sampler can infinite-loop** — No max-iteration guard. Add 1000-iteration cap.
387. **AI importStore no JSON parse error handling** — Throws on invalid input.
388. **AI getAllVectors copies entire store** — 10K × 384 = 30MB allocation. Return iterator.
389. **AI accessCounter can overflow Number.MAX_SAFE_INTEGER** — Use BigInt or periodic re-normalization.
390. **AI STO timezone offset is approximate** — Fragile DST handling. Use proper tz library.
391. **AI signal handlers double-register on repeated init** — Use `process.once()` instead of `process.on()`.
392. **AI bootstrap initialization is fire-and-forget** — Failed init → 200 health check. Set 503 on failure.
393. **AI embedBatch is just Promise.all(map(embed))** — Not true model batching. Gate with semaphore at minimum.
394. **AI no request body size limit** — 100MB JSON parsed before validation.
395. **AI StorePatternssBatch typo** — Rename to `storePatternsBatch`.
396. **AI Redis SCAN+DEL without pipeline** — N round-trips. Accumulate keys, delete in single pipeline.
397. **AI STO historicalData lastModelUpdate set on skip** — Prevents future checks. Don't set timestamp when skipping.
398. **AI STO subscriberData patterns unbounded per subscriber** — Cap at 500 most recent.
399. **AI STO getPatterns without IDs spreads all data** — Memory spike. Use iterator/sampling.
400. **AI content generator word detection — no word boundaries** — `text.includes('amazing')` matches `unamazing`. Use `\b` regex.

## 24 — EDGE CASES & DEVEX (P2)

401. **Edge-cases attachment double base64 decode** — Decodes once for content, again for size. Decode once.
402. **Edge-cases startDate/endDate not validated** — `new Date(undefined)` → NaN.
403. **Edge-cases EAI support defaults to true** — Unknown domains assumed to support EAI. Default false (conservative).
404. **Edge-cases success rate NaN when both counters zero** — `0/0 * 100 || 0` → 0. Should be 100 (no failures).
405. **Edge-cases rate limit uses in-memory Map** — Multi-instance deployments bypass.
406. **Edge-cases ICS VTIMEZONE hardcoded offsets** — Use proper VTIMEZONE database.
407. **Edge-cases dynamic import('crypto') on every call** — Static import at module level.
408. **Edge-cases CIDR prefix length not validated** — `/33` for IPv4 accepted.
409. **Edge-cases filter rules compile regex without ReDoS protection** — Same as #31.
410. **DevEx sandbox environments Map unbounded** — DB-backed but Map not capped.
411. **DevEx capturedEmails array per sandbox not trimmed** — Enforce MAX_CAPTURES.
412. **DevEx sandbox stats use in-memory increment** — Race condition. Use DB atomic update.
413. **DevEx attachmentService pool dependency unused** — Pool stored but never queried from routes.
414. **DevEx cli-tool template variables not escaped** — User HTML injected into templates.
415. **DevEx multiple dynamic imports** — Move to static imports.

## 25 — COMPLIANCE & ISOLATION (P2–P3)

416. **Compliance signing key stored as plain string in config** — Risk of accidental logging. Store as Buffer.
417. **Compliance encryption key passed as plain string** — Same issue.
418. **Compliance content scan stats cache key injection** — User-controlled strings interpolated into Redis key. Hash or validate inputs.
419. **Compliance GDPR processing error handling is per-request not per-batch** — Top-level failure stops entire batch.
420. **Compliance schema uses inline DDL not migrations** — `CREATE TABLE IF NOT EXISTS` on every startup. Use proper migration system.
421. **Isolation token-bucket uses MULTI/EXEC not Lua** — Conflicts under high concurrency. Use single Lua script.
422. **Isolation audit buffer splice-then-insert race** — Concurrent writes can interleave. Use atomic swap.
423. **Isolation audit buffer on-failure prepend race** — Same issue.
424. **Isolation data isolation ops EventEmitter no maxListeners** — Default 10 → Node warning.
425. **Isolation encryption key rotation no locking** — Concurrent rotations corrupt state.

## 26 — WORKER MISC (P2–P3)

426. **Worker error rate check allocates new array per batch** — `this.recentOutcomes.filter()` creates array just to count. Use reduce or counter.
427. **Worker Array.shift() in trimming loop** — O(n²). Use `splice(0, excess)`.
428. **Worker DMARC alignment warning but email still sent** — Wasting rate limit quota and reputation. Optionally reject.
429. **Worker link rewriting regex misses unquoted href** — Some HTML generators produce unquoted attributes. Broaden regex or use HTML parser.
430. **Worker `</body>` replacement only replaces first occurrence** — Use regex or find last occurrence.
431. **Worker recentOutcomes timestamp field never used** — Remove or implement time-based windowing.
432. **Worker rate limiter rejection returns Promise.reject** — Use `throw` instead to avoid unhandled rejection risk.
433. **Worker rate limiter Date.now() precision loss** — Use `performance.now()` for sub-millisecond accuracy.
434. **Worker suppression cache individual-write size check missing** — Bypasses batch eviction cap.
435. **Worker unknown errors never retried** — Classified as non-transient. Many are network glitches. Treat like transient.
436. **Webhook response body read error silently ignored** — At least log a warning.
437. **Webhook dedup uses hardcoded DNS servers** — Air-gapped environments can't reach 8.8.8.8. Make configurable.
438. **Analytics Redis pipeline errors not checked** — `pipeline.exec()` returns `[err, result]` tuples. Verify no errors.
439. **Analytics key parsing uses double-pipe ambiguity** — Campaign-only key `tenantId||campaignId` creates ambiguous segments.
440. **Analytics concurrency config accepted but unused** — Remove config or implement.

## 27 — MINOR PERFORMANCE (P3)

441. **API inflight Map grows without TTL** — `apps/api/src/app.ts` — Add periodic cleanup for stuck entries.
442. **API DNS cache uses FIFO not LRU** — `packages/db/src/repositories/domains.ts` — Frequently accessed domains evicted first.
443. **Control plane formatDate/formatCurrency create Intl objects per call** — Cache at module level.
444. **Tracking Content-Length string computed per request** — Pre-compute `TRANSPARENT_GIF.length.toString()` once.
445. **Tracking /o.gif duplicates entire pixel handler logic** — Extract shared helper function.
446. **Tracking request logging uses Date.now() not performance.now()** — Less precision for latency.
447. **AI tokenizer should pre-sort special tokens by length** — Longest-match-first avoids substring conflicts.
448. **Sales-autopilot getActivePromos scans all promos** — Index by tenantId.
449. **Observability per-row metric INSERT** — Same as #93 but for metrics table.
450. **Webhook manual parameter numbering in batch INSERT** — Fragile. Use unnest() approach.

## 28 — MINOR CORRECTNESS (P3)

451. **API webhook test returns 200 on failure** — Return 502/422 for programmatic distinction.
452. **API events:write scope not in VALID_SCOPES** — API keys can't be issued with this scope.
453. **Tracking rate limit returns 429 JSON for pixel** — Email clients can't parse JSON.
454. **Tracking pixel missing X-Robots-Tag header** — Prevent search engine indexing.
455. **Tracking click redirect missing CSP header** — Some browsers render interstitial.
456. **Control plane `GET /me` on public auth router** — Unauthenticated access.
457. **Control plane `POST /refresh` on public router** — Token refresh without auth.
458. **Node SDK test for 500 doesn't verify retry count** — Should mock 4 responses.
459. **Python SDK event enum doesn't match Node SDK** — `email.sent` vs `email_sent`.
460. **Python SDK missing model exports** — ValidationError, RateLimitError not in __init__.py.

## 29 — DOCUMENTATION & TYPES (P3)

461. **API response envelope inconsistency** — Some routes return `{ data }`, others return raw objects.
462. **API deprecation middleware exists but never applied** — `deprecated()` factory created but no routes use it.
463. **Worker C-100 batch completions documented but not implemented** — Comment says "batch" but code is per-job.
464. **Sales-autopilot ScrapeResult declared twice** — Duplicate interface.
465. **AI StorePatternssBatch typo** — Double 's'.
466. **Python SDK massive sync/async duplication** — Extract shared base class.
467. **Observability duplicate config objects** — `logStream` and `logStreaming` overlap.
468. **Edge-cases ICS VTIMEZONE uses hardcoded offsets** — Document or fix.
469. **Sales-autopilot calendar.ts ICS returns mock data** — Document as stub.
470. **Template engine type field ignored** — Document that only simple `{{var}}` replacer is used.

## 30 — WIRING & INTEGRATION (P3)

471. **Sales-autopilot enrichment data not persisted on lead** — Score saved but company/tech data discarded.
472. **Sales-autopilot rescheduleBooking no CRM activity record** — Should record meeting_scheduled activity.
473. **Sales-autopilot getLeadEnrollments no O(1) lookup** — Add Map-based index by campaignId+leadId.
474. **Observability alert notification dispatch no retry** — Queue failed notifications for retry.
475. **Observability span flush failure loses spans** — Re-add to buffer on failure.
476. **Observability sensitive-field masking doesn't recurse** — Only masks top-level fields.
477. **HA WAL archiving result not verified** — Check command exit status.
478. **HA pg_dump stderr logged at debug level** — Should be error level.
479. **Ops metrics push no retry** — Single failure drops metrics.
480. **Compliance alert Redis push error handling** — If Redis down, alert lost. Use file/stderr fallback.

## 31 — ADDITIONAL HIGH-IMPACT (P1–P3)

481. **Tracking suppression insert outside transaction** — Process crash after event enqueue but before suppression → emails still sent to unsubscribed user.
482. **Tracking event buffer writeEvents errors destroy connection** — `client.release()` should pass `true` on error to destroy corrupt connection.
483. **Tracking batch INSERT parameter limit** — PG max ~65535 params. With 10 params/event, max batch is 6500. Add guard.
484. **Worker email processor doesn't emit metrics** — Despite metrics server, no `counter.inc()` or `histogram.observe()` calls.
485. **Worker webhook processor doesn't emit metrics** — Same gap.
486. **Analytics double-logging on flush failure** — Error logged in flushBuffers then re-thrown and logged again in caller.
487. **API idempotency middleware only on /messages** — Should cover all mutation routes.
488. **API CSV export not streamed** — Full CSV built in memory. Use streaming response.
489. **Message status transition TOCTOU** — Read-then-write race. Move check into SQL WHERE clause.
490. **Control plane response.ok never checked** — 16+ functions parse error bodies as data.
491. **Tracking codec unsubscribe token uses : delimiter** — Emails can contain colons in local part. Use `|` or binary format.
492. **Tracking codec HMAC truncated to 128 bits** — Adequate but tight. Consider full 256 bits.
493. **Sales-autopilot processIncomingMessage error not caught** — Crash on single message failure kills entire inbox processing.
494. **Sales-autopilot campaign persist-to-DB failures return success** — In-memory data lost on restart. Propagate errors.
495. **AI InferenceEngine processQueue doesn't re-enter** — New items added during processing are never picked up until next external trigger.
496. **Compliance risk reassessment no overlap guard** — Concurrent cron runs reassess same tenants.
497. **Tracking Redis key double-prefix** — `tracking:tracking:` in actual Redis keys.
498. **Edge-cases auto-responder patterns double-compiled** — Regex → string → regex. Store compiled RegExp directly.
499. **Control plane proxy GET exposes arbitrary URL fetch** — Remove or restrict to allowlist.
500. **HA internal sync/cluster endpoints unauthenticated** — Any network peer can POST fake data.

---

## Summary by Area

| Area | Count |
|------|-------|
| Database queries & schema | ~60 |
| Worker (email/webhook/analytics/reply) | ~80 |
| Tracking | ~65 |
| API routes | ~50 |
| Sales-autopilot | ~50 |
| AI service | ~50 |
| Control plane | ~40 |
| Observability & Ops | ~35 |
| HA & Enterprise | ~25 |
| Compliance & Isolation | ~15 |
| Lib/shared packages | ~15 |
| SDKs (Node + Python) | ~30 |
| **Total** | **~500** |

## Priority Distribution

| Priority | Count | Description |
|----------|-------|-------------|
| 🔴 P0 | ~40 | Data loss, security holes, crashes |
| 🟠 P1 | ~200 | Correctness, perf, unwired code |
| 🟡 P2 | ~200 | Moderate improvements |
| 🟢 P3 | ~60 | Minor polish |
