# Tool Contract: Redis

> Internal engineering document — specifies the interface contract between ApexMail services and Redis.

| Field | Value |
|-------|-------|
| **Version** | Redis 7+ |
| **Role** | Cache, rate limiting, session storage, pub/sub event bus |
| **Hosting** | Hetzner Cloud ARM server (currently CAX41) (co-located with API) |
| **Persistence** | RDB snapshots every 60 s if ≥ 1000 keys changed; AOF disabled |
| **Max Memory** | 2 GB (`maxmemory 2gb`) |
| **Eviction Policy** | `allkeys-lru` |

---

## 1. Connection Management

### Pooling

> **Note (2026-02):** The Rust tracking service uses `deadpool_redis` for connection pooling. TypeScript apps use `ioredis`.

- Rust services use `deadpool_redis` with async connection pooling.
- TypeScript/Next.js apps use `ioredis` for Redis operations.
- **Max connections per service**:

| Service | Connections |
|---------|------------|
| Tracking (Rust) | 16 |
| Web (Next.js) | 10 |
| Control Plane | 5 |

- Connections use `lazyConnect: true` — established on first command, not at boot.
- All connections MUST set a `commandTimeout` of **5 s** and `connectTimeout` of **3 s**.
- Connection strings are injected via `REDIS_URL` env var. Never hard-code credentials.
- `enableReadyCheck: true` — client waits for Redis `LOADING` state to clear before sending commands.

### Health Check

- Every service pings Redis on startup. If the ping fails after 3 retries (1 s backoff), the service exits with code 1 and is restarted by systemd.

---

## 2. Key Naming Convention

All keys MUST follow this hierarchical pattern:

```
apexmail:<domain>:<tenant_id>:<resource>:<identifier>
```

### Examples

| Purpose | Key Pattern | Example |
|---------|------------|---------|
| API response cache | `apexmail:cache:<tenant>:<resource>:<id>` | `apexmail:cache:t_abc:campaign:c_123` |
| Rate limit counter | `apexmail:rl:<tenant>:<action>:<window>` | `apexmail:rl:t_abc:api:60s` |
| Rate limit sliding | `apexmail:rls:<tenant>:<action>` | `apexmail:rls:t_abc:send` |
| Session | `apexmail:sess:<session_id>` | `apexmail:sess:s_a1b2c3` |
| Blocklist | `apexmail:bl:<tenant>:<type>` | `apexmail:bl:t_abc:email` |
| Lock | `apexmail:lock:<resource>:<id>` | `apexmail:lock:campaign:c_123` |
| Pub/sub channel | `apexmail:evt:<event_type>` | `apexmail:evt:email_sent` |
| Feature flag | `apexmail:ff:<flag_name>` | `apexmail:ff:new_editor` |
| Queue metadata | `apexmail:q:<queue>:<field>` | `apexmail:q:send:depth` |

### Rules

1. Keys MUST use colons (`:`) as separators — never dots or slashes.
2. Tenant IDs are prefixed with `t_` to prevent collision with system keys.
3. Keys MUST NOT contain spaces or special characters beyond colons and underscores.
4. Maximum key length: 256 bytes (enforced by application-level validation).

---

## 3. TTL Policy

**Every key MUST have a TTL.** Unbounded keys are a production incident waiting to happen.

| Key Type | Default TTL | Max TTL |
|----------|------------|---------|
| API cache | 60 s | 300 s |
| Session | 24 h | 7 d |
| Rate limit window | Matches window (e.g., 60 s) | 120 s |
| Distributed lock | 30 s | 60 s |
| Feature flag | 5 min | 30 min |
| Blocklist | 24 h | 30 d |
| Pub/sub | N/A (ephemeral) | N/A |

### Enforcement

- CI lint step scans all `redis.set()` / `redis.setex()` calls and fails if no TTL argument is present.
- The `RedisClient` wrapper class in `packages/lib/src/redis.ts` **requires** a TTL parameter on all write methods. There is no raw `.set()` without TTL.

---

## 4. Data Types & Usage Patterns

### Strings — Cache

```ts
await redis.setex(`apexmail:cache:${tenantId}:campaign:${id}`, 60, JSON.stringify(campaign));
const cached = await redis.get(`apexmail:cache:${tenantId}:campaign:${id}`);
```

- Values are JSON-serialized. Max value size: **64 KB** (enforced at application layer).
- Cache-aside pattern: check Redis → miss → query PostgreSQL → write to Redis → return.

### Sorted Sets — Rate Limiting (Sliding Window)

```ts
// Sliding window rate limiter
const now = Date.now();
const windowMs = 60_000;
const key = `apexmail:rls:${tenantId}:api`;

await redis
  .multi()
  .zremrangebyscore(key, 0, now - windowMs)
  .zadd(key, now, `${now}:${requestId}`)
  .zcard(key)
  .expire(key, Math.ceil(windowMs / 1000) + 1)
  .exec();
```

- Each request is a member scored by timestamp.
- Window is trimmed atomically with the count check.

### Sets — Blocklists

```ts
await redis.sadd(`apexmail:bl:${tenantId}:email`, 'spam@example.com');
const blocked = await redis.sismember(`apexmail:bl:${tenantId}:email`, recipientEmail);
```

- Blocklists are loaded from PostgreSQL on cache miss and cached for 24 h.
- Max set size: 100,000 members. Tenants exceeding this are moved to PostgreSQL-only lookups.

### Pub/Sub — Internal Events

```ts
// Publisher (Worker)
await redis.publish('apexmail:evt:email_sent', JSON.stringify({ emailId, tenantId }));

// Subscriber (API — WebSocket relay)
redis.subscribe('apexmail:evt:email_sent');
redis.on('message', (channel, message) => { /* relay to WS */ });
```

### Rules

1. Pub/sub is fire-and-forget. Consumers MUST tolerate missed messages.
2. Pub/sub connections are **dedicated** — a subscribing connection cannot issue other commands.
3. Message payload MUST be JSON, under **8 KB**.
4. Do NOT use pub/sub for critical workflows. Use PostgreSQL LISTEN/NOTIFY or the job queue instead.

### Hashes — Session Storage

```ts
await redis.hset(`apexmail:sess:${sessionId}`, {
  userId: user.id,
  tenantId: user.tenantId,
  role: user.role,
  createdAt: Date.now().toString(),
});
await redis.expire(`apexmail:sess:${sessionId}`, 86400);
```

---

## 5. Lua Scripts for Atomic Operations

Complex multi-step operations MUST use Lua scripts to guarantee atomicity.

### Registered Scripts

| Script | Purpose | Keys | Args |
|--------|---------|------|------|
| `rate_limit_check` | Sliding window rate limit check + increment | 1 (rate limit key) | window_ms, max_requests, now |
| `acquire_lock` | Distributed lock acquisition with fencing token | 1 (lock key) | token, ttl_ms |
| `release_lock` | Safe lock release (only if token matches) | 1 (lock key) | token |
| `cache_stampede` | Probabilistic early expiration (XFetch) | 1 (cache key) | ttl, delta, beta |

### Rules

1. Lua scripts for TypeScript apps live in `packages/lib/src/`. Rust services embed scripts directly in code.
2. Scripts are loaded at startup via `SCRIPT LOAD` and called via `EVALSHA`.
3. Scripts MUST NOT call `TIME` — pass timestamps as arguments for determinism.
4. Scripts MUST complete in < **5 ms**. Redis is single-threaded; long scripts block everything.
5. Scripts are reviewed with the same rigor as database migrations.

---

## 6. Memory Management

### Monitoring

| Metric | Alert Threshold |
|--------|----------------|
| `redis_memory_used_bytes` | > 1.6 GB (80%) |
| `redis_connected_clients` | > 50 |
| `redis_evicted_keys_total` | > 100/min sustained |
| `redis_keyspace_hits / (hits + misses)` | < 80% hit rate |

### Eviction Behavior

- Policy: `allkeys-lru` — when memory limit is reached, least-recently-used keys are evicted regardless of TTL.
- This means **no key is guaranteed to survive** until its TTL if memory pressure is high. Services MUST handle cache misses gracefully.
- Rate limit keys and locks use short TTLs and small values — they are low eviction targets in practice.

---

## 7. Error Handling

1. All Redis operations are wrapped in try/catch. A Redis failure MUST NOT crash the service.
2. Cache reads: on failure, fall through to PostgreSQL. Log a warning.
3. Rate limiting: on failure, **allow the request** (fail-open) and log an error. Never block users because Redis is down.
4. Locks: on failure, retry with exponential backoff (3 attempts, 100/200/400 ms).
5. Pub/sub: on disconnect, the subscriber reconnects automatically (ioredis built-in). Events during the gap are lost — this is acceptable by design.

---

## 8. Security

1. Redis is bound to the private network interface (`bind 10.0.0.0/8`). It is NOT exposed to the internet.
2. Authentication via `requirepass` — password injected from environment.
3. The `CONFIG`, `DEBUG`, `FLUSHALL`, `FLUSHDB`, `KEYS` commands are renamed/disabled in production via `rename-command`.
4. `KEYS *` is NEVER used in application code. Use `SCAN` with a cursor for iteration.
5. TLS is not used for the Redis link (private network only). If Redis moves to a separate host with public transit, TLS becomes mandatory.

---

*Last updated: 2026-02-09*
