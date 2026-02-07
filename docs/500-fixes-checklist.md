# ApexMail — 500 Improvements Checklist

> Implementation tracking for all 500 high-impact improvements.
> Each batch is tested (build 23/23, tests 41/41) before being checked off.

---

## Batch 1: P0 Data Loss & Critical Correctness (#1–10)
- [ ] 1. Tracking WAL events lost on flush failure — re-push drained events on catch
- [ ] 2. Analytics events lost on processing failure — two-phase mark processing→processed
- [ ] 3. Multi-tenant suppression check uses only first tenant — group by tenantId
- [ ] 4. API null-byte middleware consumes request body — clone before reading
- [ ] 5. Webhook circuit breaker depletes retries without trying — skip attempt increment on CB open
- [ ] 6. Analytics aggregation key parsing broken for 4-segment keys — use structured fields
- [ ] 7. SMTP send timeout leaks socket — use Nodemailer built-in timeouts
- [ ] 8. Post-send side-effects can mark sent email as failed — move inside try/catch
- [ ] 9. API key rotation not transactional — wrap in transaction
- [ ] 10. Control plane impersonation issues token for "unknown" — return 401

## Batch 2: P0 Critical Correctness (#11–20)
- [ ] 11. Tracking X-Forwarded-For trusts leftmost IP — iterate right-to-left
- [ ] 12. Inbound reply no concurrent-processing guard — FOR UPDATE SKIP LOCKED
- [ ] 13. Suppression check uses wrong column — fix column names
- [ ] 14. Tenant DELETE no cascade — soft-delete
- [ ] 15. Sales-autopilot drip emails never sent — wire actual email API call
- [ ] 16. Sales CRM getLead no tenant scoping — add tenant_id to WHERE
- [ ] 17. AI health endpoint always healthy — check actual model state
- [ ] 18. Control plane returns demo data on API errors — return 500
- [ ] 19. Enterprise JWT decode never verifies signature — use jose verify
- [ ] 20. Sales-autopilot SQL injection via LIMIT — parameterize

## Batch 3: Security (#21–40)
- [ ] 21. DKIM keys loaded globally — load per-domain lazily
- [ ] 22. Tracking token no HMAC — add HMAC signature
- [ ] 23. Unsubscribe token leaks PII — encrypt payload
- [ ] 24. Enterprise SAML accepts SHA-1 — reject by default
- [ ] 25. HA /internal/sync no auth — add middleware
- [ ] 26. Ops no auth on any route — add auth middleware
- [ ] 27. Compliance non-timing-safe comparison — use timingSafeEqual
- [ ] 28. HA hardcoded default API keys — throw in production
- [ ] 29. Control plane login rate limiter in-memory — note for Redis migration
- [ ] 30. Control plane logout GET enables CSRF — POST only
- [ ] 31. Edge-cases alerting rules accept arbitrary regex — add ReDoS guard
- [ ] 32. Edge-cases webhook no SSRF protection — add private-IP check
- [ ] 33. Sales-autopilot regex injection — escape user key
- [ ] 34. Enterprise AES-CBC → AES-GCM
- [ ] 35. Observability share key Math.random — use crypto.randomBytes
- [ ] 36. Control plane NEXT_PUBLIC_ leaks — remove prefix
- [ ] 37. Sales-autopilot XSS in promo HTML — escape
- [ ] 38. Control plane proxy arbitrary URL — restrict allowlist
- [ ] 39. Enterprise template variable injection — HTML-escape
- [ ] 40. Warmup check TOCTOU — atomic INCR + check

## Batch 4: DB Query Performance (#41–60)
- [ ] 41. API key lookup SELECT * — select needed columns only
- [ ] 42. Suppression check SELECT * — select needed columns only
- [ ] 43. Message findById SELECT * — add includeBody option
- [ ] 44. 7 repos separate COUNT+SELECT — use COUNT(*) OVER()
- [ ] 45. Audit logs findByResource no LIMIT — add LIMIT
- [ ] 46. Events findByMessageId no LIMIT — add LIMIT
- [ ] 47. Webhooks findByTenant no LIMIT — add pagination
- [ ] 48. Missing index on messages.mta_message_id — add index
- [ ] 49. Analytics domain GROUP BY expression — functional index note
- [ ] 50. Audit log composite index needed — note for migration
- [ ] 51. Idempotency cleanup unbounded DELETE — batch with LIMIT
- [ ] 52. Inbound messages cleanup unbounded — batch with LIMIT
- [ ] 53. Template listVersions missing tenantId — add param
- [ ] 54. Domain DNS health check no LIMIT — add LIMIT + batch
- [ ] 55. Subscription preference N INSERTs — multi-row INSERT
- [ ] 56. Reputation alert TOCTOU — ON CONFLICT
- [ ] 57. Events and domains stats no caching — add Redis cache-aside
- [ ] 58. Analytics correlated subqueries — pre-compute aggregate
- [ ] 59. Analytics SCAN slow — construct explicit keys
- [ ] 60. Control plane duplicate DB pool — import shared

## Batch 5: Runtime Performance (#61–80)
- [ ] 61. Suppression cache sorts entire Map — insertion-order eviction
- [ ] 62. Tracking pixel headers rebuilt per request — pre-compute
- [ ] 63. Tracking bot detection 18 regexes — single combined regex
- [ ] 64. Tracking 4+ sequential Redis round-trips — Lua consolidation
- [ ] 65. Tracking double JSON serialization — single serialization
- [ ] 66. Tracking WAL checksum re-serialization — skip if redundant
- [ ] 67. Tracking CORS on pixel path unnecessary — remove
- [ ] 68. Tracking Lua script sent as text — use evalsha
- [ ] 69. Tracking 3 Date objects per event — reuse one
- [ ] 70. Tracking incrementCounter 2 Dates — reuse one
- [ ] 71. Tracking metrics 5 sequential Redis GETs — pipeline
- [ ] 72. API audit log writes block responses — fire-and-forget
- [ ] 73. API sequential domain lookup in batch — Promise.all
- [ ] 74. API sequential suppression + domain check — Promise.all
- [ ] 75. API message detail sequential queries — Promise.all
- [ ] 76. API domain verify sequential — Promise.all + RETURNING
- [ ] 77. Tracking preferences 3 sequential DB queries — Promise.all
- [ ] 78. Tracking readiness probe sequential — Promise.all
- [ ] 79. Worker warmup day lookup per job — cache 1h TTL
- [ ] 80. Worker per-job PG client — batch completions

## Batch 6: Runtime Performance (#81–100)
- [ ] 81. Webhook per-job PG client — batch completions
- [ ] 82. DNS resolver created per webhook — create once
- [ ] 83. DNS lookups not cached for webhooks — 60s TTL
- [ ] 84. Webhook response body fully buffered — stream with limit
- [ ] 85. AI tokenizer O(n×k) — use startsWith with offset
- [ ] 86. AI vector search O(n×d) — add simple optimization
- [ ] 87. AI exportStore serializes entire store — stream note
- [ ] 88. AI LRU eviction O(n) scan — use sorted approach
- [ ] 89. AI Monte Carlo 10K blocks event loop — reduce default
- [ ] 90. Sales top-leads N+1 — batch query
- [ ] 91. Sales getReadyEnrollments scans all — DB query
- [ ] 92. Sales enrichment no cache — Redis cache 24h
- [ ] 93. Observability per-row log INSERT — multi-row
- [ ] 94. Observability exportedSpans shift O(n) — splice
- [ ] 95. Lib Levenshtein O(n×m) matrix — two-row rolling
- [ ] 96. Control plane formatDate creates Intl per call — cache
- [ ] 97. API pg_stat_activity on readiness — use pool counts
- [ ] 98. API webhook list filters in memory — push to SQL
- [ ] 99. AI InferenceEngine created 3 times — share singleton
- [ ] 100. Sales pipeline linear scans — secondary indexes

## Batch 7: Concurrency & Queuing (#101–120)
- [ ] 101. Webhook per-tenant limit no delay — set scheduled_at
- [ ] 102. Webhook retry max delay 60s too low — increase 300s
- [ ] 103. Analytics processor ignores concurrency — implement
- [ ] 104. Analytics concurrent flush risk — add mutex
- [ ] 105. Analytics hourly drift — schedule after completion
- [ ] 106. Worker stale recovery misses analytics_queue — add
- [ ] 107. Analytics eventBuffer no size cap — add max
- [ ] 108. Reply handler sequential processing — parallel with limit
- [ ] 109. Reply handler no stale recovery — add sweep
- [ ] 110. Circuit breaker HALF_OPEN success no TTL — add TTL
- [ ] 111. Circuit breaker OPEN→HALF_OPEN no concurrency — SET NX
- [ ] 112. Circuit breaker keys no TTL — add 24h TTL
- [ ] 113. Circuit breaker success-in-CLOSED deletes all failures — let window expire
- [ ] 114. Worker email requeue flat 60s — use computed retryAfter
- [ ] 115. Worker uncaughtException async shutdown — exit immediately
- [ ] 116. Worker process.exit(0) prevents finally — drain naturally
- [ ] 117. Worker metrics stopped before processors — reorder
- [ ] 118. Worker heartbeat stale processor count — update dynamically
- [ ] 119. Worker rate limiter waitQueue no timeout — add 30s
- [ ] 120. Tracking flush timer fires during active flush — use setTimeout

## Batch 8: Unwired & Dead Code (#121–150)
- [ ] 121. Sales campaignRepository not wired — call setCampaignRepository
- [ ] 122. Sales Redis config unused — wire connection
- [ ] 123. Sales getLeadsNeedingAttention unused — wire to route
- [ ] 124. Sales getOverdueTasks/getRottenLeads unused — wire to routes
- [ ] 125. Sales demo slot generator ephemeral IDs — fix lookups
- [ ] 126. Sales ICS uses mock data — look up actual slot
- [ ] 127. Sales inbox message never persisted — store in DB
- [ ] 128. Sales LinkedIn enrichment always fails — mark unsupported
- [ ] 129. Sales lead scoring discards enrichment — persist
- [ ] 130. AI RedisPatternStore dead code — remove or wire
- [ ] 131. AI sentimentAnalyzer singleton unused — remove
- [ ] 132. AI NB model never trained — remove wrapper
- [ ] 133. AI engagementData no persistence — add Redis
- [ ] 134. AI serviceBootstrap singleton unused — remove
- [ ] 135. Reply handler Redis fields unused — remove dead fields
- [ ] 136. Tracking isDuplicate dead code — delete
- [ ] 137. Tracking _markProcessed dead code — delete
- [ ] 138. Control plane secrets API hardcoded — return 501
- [ ] 139. Control plane feature flags hardcoded — return 501
- [ ] 140. Control plane system health hardcoded — wire to queries
- [ ] 141. Control plane 6 APIs hardcoded — return 501
- [ ] 142. Observability dead spans Map — remove
- [ ] 143. Observability stub methods — add TODO markers
- [ ] 144. Observability getIndustryBenchmarks hardcoded — note param
- [ ] 145. Messages archiveOld no-op — implement or mark
- [ ] 146. Ops notifySubscribers unimplemented — add TODO
- [ ] 147. Ops StatusPage/ComplianceManager in-memory — note for DB
- [ ] 148. HA STONITH fencing no-op — add TODO marker
- [ ] 149. Edge-cases ClamAV health no-op — add TODO marker
- [ ] 150. DevEx sandbox stats in-memory — use DB atomic

## Batch 9: In-Memory → DB/Redis (#151–160)
- [ ] 151. Sales promo configs/stats in Maps — DB persistence
- [ ] 152. Sales demo slots/prefs in Maps — DB persistence
- [ ] 153. Sales domain rate-limit buckets — Redis
- [ ] 154. Sales robots.txt cache — Redis
- [ ] 155. Ops StatusPage — DB persistence
- [ ] 156. Ops ComplianceManager — DB persistence
- [ ] 157. AI engagementData — Redis persistence
- [ ] 158. AI historicalData/subscriberData — cap + persist
- [ ] 159. AI chatbot pendingActions — TTL cleanup
- [ ] 160. Observability alerting 5 Maps — max-size cap + LRU

## Batch 10: Error Handling (#161–190)
- [ ] 161. API SyntaxError → 500 on malformed JSON — return 400
- [ ] 162. API auth routes on public router — split routers
- [ ] 163. Analytics pipeline.exec errors ignored — check tuples
- [ ] 164. Analytics flush error double-logged — don't re-throw
- [ ] 165. Reply handler LLM response no validation — validate
- [ ] 166. Reply handler LLM no timeout — add AbortSignal
- [ ] 167. Reply handler ? regex overmatch — word boundary
- [ ] 168. Reply handler no short-circuit — exit above 0.8
- [ ] 169. Reply handler word matching no boundaries — use \b
- [ ] 170. Webhook delivery attempt not recorded on fail — always record
- [ ] 171. Webhook tenantActiveJobs permanently inflated — fix finally
- [ ] 172. Webhook dedup depends on JSON structure — use dedup_key
- [ ] 173. Metrics histogram +Inf bucket miscounted — add overflow
- [ ] 174. Metrics server no request timeout — add 5s
- [ ] 175. Metrics server stop no close timeout — closeAllConnections
- [ ] 176. Notifier listener leaks on stop — remove listener
- [ ] 177. Sales c.req.json no try/catch — global handler
- [ ] 178. Sales batch enrichment no limit — cap at 100
- [ ] 179. Sales storeLead failure aborts batch — per-item try/catch
- [ ] 180. Compliance CronJob not tracked — store refs
- [ ] 181. Compliance GDPR export in TEXT column — note for obj storage
- [ ] 182. Compliance risk reassessment no guard — add mutex
- [ ] 183. HA distributed lock no fencing token — implement
- [ ] 184. HA pg_dump stderr not captured — log at error
- [ ] 185. HA WAL archiving no verify — check exit status
- [ ] 186. Observability eval loop no error handling — try/catch
- [ ] 187. Observability advisory lock not in finally — fix
- [ ] 188. Observability alert removes before processing — use ZPOPMIN
- [ ] 189. AI JSON.parse module-level no try/catch — wrap
- [ ] 190. AI isMainModule broken for ESM — fix check

## Batch 11: Validation (#191–220)
- [ ] 191. API events recipientEmail empty string — look up message
- [ ] 192. API events missing date range validation — 90-day cap
- [ ] 193. API events missing UUID validation — regex check
- [ ] 194. API events missing scope validation — add check
- [ ] 195. API messages missing status enum validation — runtime check
- [ ] 196. API messages missing date validation — check NaN
- [ ] 197. API messages messageId UUID validation — add check
- [ ] 198. API domains missing status enum — validate
- [ ] 199. API domains NaN/negative limit/offset — guard
- [ ] 200. API suppressions missing type/scope enum — validate
- [ ] 201. API suppressions missing UUID validation — add
- [ ] 202. API suppressions remove only first — remove all matching
- [ ] 203. API templates search no length limit — cap at 200
- [ ] 204. API templates body not validated — size limit
- [ ] 205. API webhooks creation drops fields — pass to repo
- [ ] 206. API webhooks test leaks response body — redact
- [ ] 207. API analytics NaN limit — guard
- [ ] 208. API analytics sort validation — whitelist
- [ ] 209. API health deep check exposes internals — add auth
- [ ] 210. Tracking List-Unsubscribe body not trimmed — trim
- [ ] 211. Tracking decodeURIComponent can throw — try/catch
- [ ] 212. Tracking domain matching case-sensitive — normalize
- [ ] 213. Tracking link hash keys no TTL — add EXPIRE
- [ ] 214. Tracking hset swallows errors — log
- [ ] 215. Tracking unsubscribe webhook blocks response — fire-and-forget
- [ ] 216. Tracking webhook queue per-INSERT — batch
- [ ] 217. Tracking Redis publish blocks — fire-and-forget
- [ ] 218. Tracking EventProcessor low throughput config — increase
- [ ] 219. Tracking Redis missing enableOfflineQueue:false — add
- [ ] 220. Tracking shutdown timeout 15s — increase to 30s

## Batch 12: Indexes, Schema & Resource Leaks (#221–250)
- [ ] 221. Missing composite index events (tenant_id, message_id) — migration note
- [ ] 222. Missing composite index audit_logs — migration note
- [ ] 223. Missing partial index smtp_credentials — migration note
- [ ] 224. Missing functional index events domain — migration note
- [ ] 225. Missing index messages (tenant_id, to_address, created_at) — migration note
- [ ] 226. Missing index webhook_deliveries — migration note
- [ ] 227. Missing compaction_log unique date index — migration note
- [ ] 228. Missing index inbound_messages processing_at — migration note
- [ ] 229. Observability /traces/stats route shadowed — reorder
- [ ] 230. Observability /incidents/summary shadowed — reorder
- [ ] 231. Tracking flush timer never cleared — setTimeout pattern
- [ ] 232. AI rate limit cleanup interval — unref + clear
- [ ] 233. AI 8 eager singletons — lazy getters
- [ ] 234. Observability dedup interval not unref'd — fix
- [ ] 235. Observability SLOManager no stop — add stop method
- [ ] 236. Observability leak detection interval per connection — single sweep
- [ ] 237. Observability log stream timers not cleared — fix
- [ ] 238. Ops no graceful shutdown — add SIGTERM handler
- [ ] 239. Ops escalation timers not unref'd — fix
- [ ] 240. HA monitoring intervals not unref'd — fix
- [ ] 241. HA failover history unbounded — cap
- [ ] 242. HA chaos experiment Map never cleaned — add cleanup
- [ ] 243. Control plane DB pool no error handler — add
- [ ] 244. Control plane DB pool no shutdown — add
- [ ] 245. Control plane loginAttempts Map never cleaned — add TTL cleanup
- [ ] 246. Sales enrollments Map keeps completed — remove terminal
- [ ] 247. Sales domainBuckets Map never pruned — add cleanup
- [ ] 248. Sales demo slots Map unbounded — add cap
- [ ] 249. AI chatbot pendingActions no TTL — add cleanup
- [ ] 250. AI pullHistory unbounded — cap at 100K

## Batch 13: RETURNING, rowCount & Repository Consistency (#251–273)
- [ ] 251. tenants.activate no RETURNING — add
- [ ] 252. tenants.updateSettings no RETURNING — add
- [ ] 253. domains.markExpired no RETURNING/rowCount — add
- [ ] 254. users.updatePassword no rowCount — add
- [ ] 255. api-keys.revoke no rowCount — add
- [ ] 256. webhook-queue markDelivered no rowCount — add
- [ ] 257. webhook-queue markFailed no rowCount — add
- [ ] 258. webhooks.recordFailure no RETURNING/rowCount — add
- [ ] 259. WebhooksRepository raw Pool → DatabasePool
- [ ] 260. InboundMessagesRepository raw Pool → DatabasePool
- [ ] 261. SubscriptionsRepository raw Pool → DatabasePool
- [ ] 262. SmtpCredentialsRepository raw Pool → DatabasePool
- [ ] 263. ReputationRepository raw Pool → DatabasePool
- [ ] 264. SystemRepository raw Pool → DatabasePool
- [ ] 265. webhooks.recordFailure missing tenant_id WHERE — add
- [ ] 266. Analytics DATE_TRUNC interpolation — whitelist
- [ ] 267. Billing DATE_TRUNC interpolation — whitelist
- [ ] 268. Analytics domain DATE_TRUNC interpolation — whitelist
- [ ] 269. Worker stale job table name interpolation — whitelist
- [ ] 270. API key debounce interval interpolation — parameterize
- [ ] 271. Observability time_bucket interpolation — whitelist
- [ ] 272. Observability aggregation function interpolation — whitelist
- [ ] 273. Isolation CREATE SCHEMA template — sanitize

## Batch 14: SDKs (#274–297)
- [ ] 274. Node SDK no idempotency key — add support
- [ ] 275. Node SDK no ID validation — add regex check
- [ ] 276. Node SDK no debug mode — add logging option
- [ ] 277. Node SDK no AbortSignal — add support
- [ ] 278. Node SDK domains.list no pagination — add
- [ ] 279. Node SDK apiKeys.list no pagination — add
- [ ] 280. Node SDK webhooks.list no pagination — add
- [ ] 281. Node SDK whitespace body passes — trim check
- [ ] 282. Node SDK undefined serialized as null — filter
- [ ] 283. Node SDK baseUrl no validation — validate
- [ ] 284. Node SDK analytics no date validation — check
- [ ] 285. Node SDK timeout not cleared — clear on response
- [ ] 286. Python SDK batch no size limit — add 1000 cap
- [ ] 287. Python SDK no email validation — add
- [ ] 288. Python SDK no body validation — check presence
- [ ] 289. Python SDK domains.list no pagination — add
- [ ] 290. Python SDK webhooks.list no pagination — add
- [ ] 291. Python SDK no ID validation — add
- [ ] 292. Python SDK webhook no HTTPS validation — add
- [ ] 293. Python SDK webhook update empty payload — check
- [ ] 294. Python SDK no 204 handling — add
- [ ] 295. Python SDK event enum mismatch — align
- [ ] 296. Python SDK sync client no __del__ — add
- [ ] 297. Python SDK sync/async duplication — extract base

## Batch 15: Control Plane (#298–307)
- [ ] 298. 9 API routes return demo data on error — return 500
- [ ] 299. controlPlaneFetch no response.ok check — add
- [ ] 300. controlPlaneFetch no timeout — add AbortController
- [ ] 301. controlPlaneFetch no retry — add retry logic
- [ ] 302. 6 API list endpoints missing pagination — add
- [ ] 303. Dashboard stats returns 200 on DB failure — return 500
- [ ] 304. IP spoofing via X-Forwarded-For — fix direction
- [ ] 305. Impersonation no tenantId validation — validate
- [ ] 306. SSRF allowlist substring matching — origin check
- [ ] 307. Duplicate fetchMetrics functions — consolidate

## Batch 16: Sales-Autopilot (#308–325)
- [ ] 308. Campaign stats increment non-atomic — DB atomic UPDATE
- [ ] 309. Slot booking no CAS — UPDATE WHERE available
- [ ] 310. Campaign processor sequential — parallel with limit
- [ ] 311. Promo click/conversion no error handling — return 404
- [ ] 312. DB persist failures swallowed in campaign — propagate
- [ ] 313. DB persist failures swallowed in enrollment — propagate
- [ ] 314. Calendar generateSlots no upper bound — cap
- [ ] 315. Discovery maxPagesPerSource no bound — cap at 100
- [ ] 316. Top-leads loads all into memory — pagination
- [ ] 317. getRottenLeads loads all — SQL WHERE
- [ ] 318. filterLeads no pagination — add LIMIT
- [ ] 319. ScrapeResult declared twice — remove duplicate
- [ ] 320. updatePromoConfig Object.assign overwrite — destructure
- [ ] 321. Compiled regex /g with .test() — remove g flag
- [ ] 322. Stage matching by name — match by id
- [ ] 323. totalValue always 0 — fix or remove
- [ ] 324. extractFirstName from email — prefer enrichment
- [ ] 325. scrapedToLeads Partial cast — validate

## Batch 17: Observability & Ops (#326–335)
- [ ] 326. Observability dataStore Map unbounded — cap
- [ ] 327. Observability notifications unbounded — trim
- [ ] 328. Observability incidentHistory copies array — splice
- [ ] 329. Ops parseInt no NaN guard — add
- [ ] 330. Ops incident IDs Date.now+random — crypto.randomUUID
- [ ] 331. Ops escalation timers not unref'd — fix
- [ ] 332. Ops EventEmitters maxListeners — set 50
- [ ] 333. Ops health checks silently pass — warn
- [ ] 334. Ops label parsing brittle — fix split
- [ ] 335. Ops metrics push no retry — add retry

## Batch 18: HA & Enterprise (#336–345)
- [ ] 336. HA distributed lock no fencing token — implement
- [ ] 337. HA region health Map no validation — validate
- [ ] 338. HA chaos in production — check NODE_ENV
- [ ] 339. HA backup encryption key optional — require
- [ ] 340. HA Redis CB state no reconnection — handle
- [ ] 341. Enterprise SAML request ID prefix — add underscore
- [ ] 342. Enterprise SandboxEnvironment unbounded — cap
- [ ] 343. Enterprise sanitizeIdentifier strips hyphens — allow
- [ ] 344. Enterprise credential AES-GCM — migrate
- [ ] 345. Enterprise deep path traversal — return vs continue

## Batch 19: Tracking Optimization (#346–360)
- [ ] 346. Tracking pool max too low — increase to 50
- [ ] 347. Tracking Redis missing enableReadyCheck/connectTimeout — add
- [ ] 348. Tracking Redis double-prefix — remove extra prefix
- [ ] 349. Tracking pool idle timeout 10s → 30s
- [ ] 350. Tracking rate limit EXPIRE every request — conditional
- [ ] 351. Tracking 429 JSON for pixel — return GIF
- [ ] 352. Tracking 429 missing Retry-After — add header
- [ ] 353. Tracking logging on /health — skip
- [ ] 354. Tracking health endpoint always 200 — add checks
- [ ] 355. Tracking unhandledRejection too aggressive — counter threshold
- [ ] 356. Tracking click domain verification on critical path — cache
- [ ] 357. Tracking preferences per-category INSERT loop — multi-row
- [ ] 358. Tracking webhook queue per-INSERT — batch
- [ ] 359. Tracking Buffer.alloc → allocUnsafe — speed
- [ ] 360. Tracking decode no bounds checking — add guard

## Batch 20: Billing, MTA & Lib (#361–380)
- [ ] 361. Billing DATE_TRUNC interpolation — whitelist
- [ ] 362. Billing dunning schedule in-memory — note for DB
- [ ] 363. Billing invoice PDF XSS — escape
- [ ] 364. Billing shutdown no timer cleanup — clear timers
- [ ] 365. MTA inbound INSERT no dedup — ON CONFLICT
- [ ] 366. MTA bounce cleanup unbounded — LIMIT batch
- [ ] 367. MTA resolver per lookup — create once
- [ ] 368. InMemoryCache setNX not atomic — fix
- [ ] 369. InMemoryCache incr not atomic — fix
- [ ] 370. InMemoryCache incrWithExpire resets TTL — don't reset
- [ ] 371. RateLimiter tenantCounts never shrinks — add cap
- [ ] 372. Queue job JSON.parse no try-catch — wrap
- [ ] 373. deriveKeySync blocks event loop — add async variant
- [ ] 374. HTTP retry no jitter — add randomized jitter
- [ ] 375. gRPC proto reloaded per connect — cache module-level
- [ ] 376. AWS SigV4 incomplete — note for SDK migration
- [ ] 377. S3 cleanup no concurrency guard — add mutex
- [ ] 378. MJML warnings discarded — include in result
- [ ] 379. Logger singleton ignores different options — warn
- [ ] 380. Template engine type field ignored — note

## Batch 21: AI Service (#381–400)
- [ ] 381. AI subject line check precedence — reverse order
- [ ] 382. AI Math.random sort — Fisher-Yates
- [ ] 383. AI cosine similarity divide by zero — guard
- [ ] 384. AI inference queue sequential — drain multiple
- [ ] 385. AI inference queue timeout corrupts — fix splice
- [ ] 386. AI gamma distribution infinite loop — cap iterations
- [ ] 387. AI importStore no JSON parse error — try/catch
- [ ] 388. AI getAllVectors copies entire store — return iterator
- [ ] 389. AI accessCounter overflow — periodic re-normalization
- [ ] 390. AI STO timezone approximate — proper DST
- [ ] 391. AI signal handlers double-register — process.once
- [ ] 392. AI bootstrap fire-and-forget — set 503 on failure
- [ ] 393. AI embedBatch not batched — gate with semaphore
- [ ] 394. AI no request body size limit — add limit
- [ ] 395. AI StorePatternssBatch typo — rename
- [ ] 396. AI Redis SCAN+DEL no pipeline — accumulate+pipeline
- [ ] 397. AI STO lastModelUpdate set on skip — don't set
- [ ] 398. AI STO subscriberData unbounded — cap at 500
- [ ] 399. AI STO getPatterns spreads all — sampling
- [ ] 400. AI content word detection no boundaries — use \b

## Batch 22: Edge Cases & DevEx (#401–415)
- [ ] 401. Edge-cases attachment double base64 — decode once
- [ ] 402. Edge-cases date params not validated — check
- [ ] 403. Edge-cases EAI default true — default false
- [ ] 404. Edge-cases success rate NaN — fix calculation
- [ ] 405. Edge-cases rate limit in-memory — note for Redis
- [ ] 406. Edge-cases ICS VTIMEZONE hardcoded — note
- [ ] 407. Edge-cases dynamic import crypto — static import
- [ ] 408. Edge-cases CIDR prefix not validated — validate
- [ ] 409. Edge-cases filter rules ReDoS — guard
- [ ] 410. DevEx sandbox Map unbounded — cap
- [ ] 411. DevEx capturedEmails not trimmed — enforce limit
- [ ] 412. DevEx sandbox stats in-memory race — DB atomic
- [ ] 413. DevEx attachmentService pool unused — wire or remove
- [ ] 414. DevEx cli-tool template not escaped — escape
- [ ] 415. DevEx dynamic imports — static imports

## Batch 23: Compliance & Isolation (#416–425)
- [ ] 416. Compliance signing key plain string — note
- [ ] 417. Compliance encryption key plain string — note
- [ ] 418. Compliance scan cache key injection — hash inputs
- [ ] 419. Compliance GDPR per-request not per-batch — per-item
- [ ] 420. Compliance schema inline DDL — note for migrations
- [ ] 421. Isolation token-bucket MULTI→Lua — note
- [ ] 422. Isolation audit buffer splice race — atomic swap
- [ ] 423. Isolation audit buffer prepend race — fix
- [ ] 424. Isolation EventEmitter maxListeners — set 50
- [ ] 425. Isolation encryption key rotation no lock — add lock

## Batch 24: Worker Misc (#426–440)
- [ ] 426. Worker error rate array allocation — use counter
- [ ] 427. Worker Array.shift trimming — splice
- [ ] 428. Worker DMARC warning still sends — optionally reject
- [ ] 429. Worker link rewriting regex edge cases — broaden
- [ ] 430. Worker </body> only first occurrence — find last
- [ ] 431. Worker recentOutcomes timestamp unused — remove or use
- [ ] 432. Worker rate limiter Promise.reject — use throw
- [ ] 433. Worker rate limiter Date.now precision — note
- [ ] 434. Worker suppression cache individual write size — check
- [ ] 435. Worker unknown errors never retried — treat as transient
- [ ] 436. Webhook response body read error ignored — log
- [ ] 437. Webhook dedup hardcoded DNS — configurable
- [ ] 438. Analytics pipeline errors not checked — verify
- [ ] 439. Analytics key double-pipe ambiguity — fix format
- [ ] 440. Analytics concurrency config unused — implement or remove

## Batch 25: Minor Performance (#441–450)
- [ ] 441. API inflight Map no TTL — periodic cleanup
- [ ] 442. API DNS cache FIFO not LRU — fix eviction
- [ ] 443. Control plane Intl objects per call — cache
- [ ] 444. Tracking Content-Length per request — pre-compute
- [ ] 445. Tracking /o.gif duplicates pixel — extract helper
- [ ] 446. Tracking request timing Date.now — performance.now
- [ ] 447. AI tokenizer pre-sort by length — sort
- [ ] 448. Sales getActivePromos scans all — index by tenant
- [ ] 449. Observability per-row metric INSERT — multi-row
- [ ] 450. Webhook manual param numbering — unnest approach

## Batch 26: Minor Correctness (#451–470)
- [ ] 451. API webhook test returns 200 on failure — return 502
- [ ] 452. API events:write scope not in enum — add
- [ ] 453. Tracking rate limit 429 JSON for pixel — GIF
- [ ] 454. Tracking pixel X-Robots-Tag — add header
- [ ] 455. Tracking click redirect CSP — add header
- [ ] 456. Control plane GET /me on public router — move
- [ ] 457. Control plane POST /refresh on public — move
- [ ] 458. Node SDK 500 test no retry count — verify
- [ ] 459. Python SDK event enum mismatch — align
- [ ] 460. Python SDK missing model exports — add
- [ ] 461. API response envelope inconsistency — normalize
- [ ] 462. API deprecation middleware unused — note
- [ ] 463. Worker batch completions documented not implemented — note
- [ ] 464. Sales ScrapeResult duplicate — remove
- [ ] 465. AI StorePatternssBatch typo — fix
- [ ] 466. Python SDK sync/async duplication — extract base
- [ ] 467. Observability duplicate config objects — consolidate
- [ ] 468. Edge-cases ICS VTIMEZONE hardcoded — document
- [ ] 469. Sales calendar ICS mock data — document
- [ ] 470. Template engine type ignored — document

## Batch 27: Wiring & Integration (#471–500)
- [ ] 471. Sales enrichment data not persisted on lead — persist
- [ ] 472. Sales rescheduleBooking no CRM record — add activity
- [ ] 473. Sales getLeadEnrollments no O(1) lookup — add Map index
- [ ] 474. Observability alert notification no retry — queue
- [ ] 475. Observability span flush failure loses spans — re-add
- [ ] 476. Observability sensitive-field masking no recurse — add depth
- [ ] 477. HA WAL archiving result not verified — check status
- [ ] 478. HA pg_dump stderr at debug — error level
- [ ] 479. Ops metrics push no retry — add retry
- [ ] 480. Compliance alert Redis fallback — stderr fallback
- [ ] 481. Tracking suppression outside transaction — wrap
- [ ] 482. Tracking writeEvents client.release error — pass true
- [ ] 483. Tracking batch INSERT param limit — guard
- [ ] 484. Worker email no metrics — add counter/histogram
- [ ] 485. Worker webhook no metrics — add counter/histogram
- [ ] 486. Analytics double-logging flush — fix
- [ ] 487. API idempotency only on /messages — extend
- [ ] 488. API CSV export not streamed — stream
- [ ] 489. Message status transition TOCTOU — SQL WHERE
- [ ] 490. Control plane response.ok never checked — add
- [ ] 491. Tracking codec : delimiter in emails — use | 
- [ ] 492. Tracking codec HMAC 128-bit — consider 256
- [ ] 493. Sales processIncomingMessage no catch — add
- [ ] 494. Sales campaign persist failures return success — propagate
- [ ] 495. AI processQueue no re-entry — trigger re-drain
- [ ] 496. Compliance risk reassessment overlap — guard
- [ ] 497. Tracking Redis key double-prefix — fix
- [ ] 498. Edge-cases auto-responder double-compiled — store compiled
- [ ] 499. Control plane proxy GET — remove or restrict
- [ ] 500. HA internal endpoints unauthenticated — add auth

---

## Progress Summary

| Batch | Items | Status |
|-------|-------|--------|
| 1 | #1–10 | ⬜ |
| 2 | #11–20 | ⬜ |
| 3 | #21–40 | ⬜ |
| 4 | #41–60 | ⬜ |
| 5 | #61–80 | ⬜ |
| 6 | #81–100 | ⬜ |
| 7 | #101–120 | ⬜ |
| 8 | #121–150 | ⬜ |
| 9 | #151–160 | ⬜ |
| 10 | #161–190 | ⬜ |
| 11 | #191–220 | ⬜ |
| 12 | #221–250 | ⬜ |
| 13 | #251–273 | ⬜ |
| 14 | #274–297 | ⬜ |
| 15 | #298–307 | ⬜ |
| 16 | #308–325 | ⬜ |
| 17 | #326–335 | ⬜ |
| 18 | #336–345 | ⬜ |
| 19 | #346–360 | ⬜ |
| 20 | #361–380 | ⬜ |
| 21 | #381–400 | ⬜ |
| 22 | #401–415 | ⬜ |
| 23 | #416–425 | ⬜ |
| 24 | #426–440 | ⬜ |
| 25 | #441–450 | ⬜ |
| 26 | #451–470 | ⬜ |
| 27 | #471–500 | ⬜ |
