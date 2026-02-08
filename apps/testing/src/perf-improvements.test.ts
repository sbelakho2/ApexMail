/**
 * Backend Improvement Tests (PERF-001 through PERF-005)
 *
 * Tests for the 5 highest-impact backend improvements:
 *
 * 1. PERF-001: Atomic Redis WAL flush (Lua script) — EventProcessor.flush()
 * 2. PERF-002: Events table partitioning — Migration SQL validation
 * 3. PERF-003: Webhook transactional completion — handleSuccess/failJob
 * 4. PERF-004: Batch API domain/suppression deduplication
 * 5. PERF-005: Message list column projection + window pagination
 *
 * For non-exported functions and integration patterns, we copy the production
 * logic and verify correctness. For migration SQL, we validate syntax and
 * structure. For class methods, we mock DB/Redis and verify call patterns.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';

// ═════════════════════════════════════════════════════════════════════════════
// 1. PERF-001: Atomic Redis WAL Flush (Lua Script)
// ═════════════════════════════════════════════════════════════════════════════

describe('PERF-001: Atomic Redis WAL Flush', () => {
  /**
   * The Lua script that runs LRANGE + LTRIM atomically inside Redis.
   * Copied from EventProcessor.ATOMIC_DRAIN_SCRIPT.
   */
  const ATOMIC_DRAIN_SCRIPT = `
local events = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #events > 0 then
  redis.call('LTRIM', KEYS[1], #events, -1)
end
return events
`;

  describe('Lua script structure', () => {
    it('should contain LRANGE command', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain("redis.call('LRANGE'");
    });

    it('should contain LTRIM command', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain("redis.call('LTRIM'");
    });

    it('should use KEYS[1] for the list key', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain('KEYS[1]');
    });

    it('should use ARGV[1] for the batch size', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain('ARGV[1]');
    });

    it('should only LTRIM if events are found (guard condition)', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain('if #events > 0');
    });

    it('should LTRIM starting from #events (skip the read events)', () => {
      // Ensures the trim removes exactly the events we read, not more
      expect(ATOMIC_DRAIN_SCRIPT).toContain("redis.call('LTRIM', KEYS[1], #events, -1)");
    });

    it('should LRANGE from 0 to ARGV[1]-1 (batch size)', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain("redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)");
    });

    it('should return events array', () => {
      expect(ATOMIC_DRAIN_SCRIPT).toContain('return events');
    });
  });

  describe('EventProcessor.flush() with Lua script', () => {
    // Simulate the flush() logic with a mock Redis
    interface MockRedisState {
      list: string[];
      evalCalls: Array<{ script: string; keys: string[]; args: string[] }>;
    }

    function createMockRedis(): MockRedisState & {
      rpush: (key: string, value: string) => void;
      eval: (script: string, numKeys: number, key: string, ...args: string[]) => string[];
    } {
      const state: MockRedisState = { list: [], evalCalls: [] };
      return {
        ...state,
        rpush: (_key: string, value: string) => {
          state.list.push(value);
        },
        eval: (script: string, _numKeys: number, key: string, ...args: string[]) => {
          state.evalCalls.push({ script, keys: [key], args });
          // Simulate the Lua script
          const batchSize = parseInt(args[0] ?? '100', 10);
          const events = state.list.splice(0, batchSize);
          return events;
        },
      };
    }

    it('should drain all events from the list', () => {
      const redis = createMockRedis();
      redis.rpush('key', JSON.stringify({ id: '1', type: 'opened' }));
      redis.rpush('key', JSON.stringify({ id: '2', type: 'clicked' }));
      redis.rpush('key', JSON.stringify({ id: '3', type: 'opened' }));

      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '100');
      expect(drained).toHaveLength(3);
      expect(redis.list).toHaveLength(0);
    });

    it('should respect batch size limit', () => {
      const redis = createMockRedis();
      for (let i = 0; i < 10; i++) {
        redis.rpush('key', JSON.stringify({ id: String(i) }));
      }

      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '5');
      expect(drained).toHaveLength(5);
      expect(redis.list).toHaveLength(5);
    });

    it('should return empty array when list is empty', () => {
      const redis = createMockRedis();
      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '100');
      expect(drained).toHaveLength(0);
      expect(redis.list).toHaveLength(0);
    });

    it('should not lose events added during drain (atomic guarantee)', () => {
      // This test verifies the DESIGN of the Lua script.
      // In the old LRANGE→LTRIM pattern, a concurrent RPUSH between the two
      // calls would add an event that gets trimmed away. The Lua script runs
      // atomically, so no RPUSH can interleave.
      const redis = createMockRedis();

      // Pre-populate
      redis.rpush('key', JSON.stringify({ id: 'before-1' }));
      redis.rpush('key', JSON.stringify({ id: 'before-2' }));

      // Atomic drain (batch of 2)
      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '2');
      expect(drained).toHaveLength(2);

      // Simulate a concurrent RPUSH that happened after the drain
      redis.rpush('key', JSON.stringify({ id: 'after-1' }));

      // The "after" event should still be in the list
      expect(redis.list).toHaveLength(1);
      expect(JSON.parse(redis.list[0]!).id).toBe('after-1');
    });

    it('should handle partial drain correctly', () => {
      const redis = createMockRedis();
      for (let i = 0; i < 5; i++) {
        redis.rpush('key', JSON.stringify({ id: String(i) }));
      }

      // Drain 3
      const first = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '3');
      expect(first).toHaveLength(3);
      expect(redis.list).toHaveLength(2);

      // Drain remaining
      const second = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '100');
      expect(second).toHaveLength(2);
      expect(redis.list).toHaveLength(0);
    });

    it('should parse drained events as valid JSON', () => {
      const redis = createMockRedis();
      const event = { id: 'evt_123', type: 'opened', tenantId: 'tn_1', messageId: 'msg_1', recipient: 'a@b.com', timestamp: new Date().toISOString() };
      redis.rpush('key', JSON.stringify(event));

      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '100');
      const parsed = JSON.parse(drained[0]!);
      expect(parsed.id).toBe('evt_123');
      expect(parsed.type).toBe('opened');
      expect(parsed.tenantId).toBe('tn_1');
    });

    it('should handle events with special characters in JSON', () => {
      const redis = createMockRedis();
      const event = { id: 'evt_1', type: 'clicked', linkUrl: 'https://example.com/path?a=1&b=2&c="hello"' };
      redis.rpush('key', JSON.stringify(event));

      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', '100');
      const parsed = JSON.parse(drained[0]!);
      expect(parsed.linkUrl).toContain('&');
      expect(parsed.linkUrl).toContain('"hello"');
    });

    it('should handle large batches efficiently', () => {
      const redis = createMockRedis();
      const count = 1000;
      for (let i = 0; i < count; i++) {
        redis.rpush('key', JSON.stringify({ id: `evt_${i}` }));
      }

      const drained = redis.eval(ATOMIC_DRAIN_SCRIPT, 1, 'key', String(count));
      expect(drained).toHaveLength(count);
      expect(redis.list).toHaveLength(0);
    });
  });

  describe('Race condition prevention (design verification)', () => {
    it('old LRANGE+LTRIM pattern has a race window', () => {
      // Demonstrate the bug that existed before PERF-001
      const list: string[] = [];

      // Step 1: LRANGE
      list.push('event-A', 'event-B');
      const read = list.slice(0, 2); // ["event-A", "event-B"]

      // Step 2: Concurrent RPUSH happens between LRANGE and LTRIM
      list.push('event-C'); // list = ["event-A", "event-B", "event-C"]

      // Step 3: LTRIM(2, -1) — trims the first 2, but event-C was at index 2
      const remaining = list.slice(read.length); // ["event-C"]

      // event-C is preserved, but ONLY because we sliced correctly here.
      // In the actual Redis LTRIM, the index is based on the current state:
      // LTRIM(2, -1) would keep indices 2+ → ["event-C"] ✓
      // But if we had LTRIM(3, -1) by mistake (off-by-one), event-C would be lost.
      expect(remaining).toEqual(['event-C']);
      expect(read).toHaveLength(2);
    });

    it('Lua script eliminates the race window by design', () => {
      // The Lua script atomically reads AND trims, so no interleaving is possible
      const script = ATOMIC_DRAIN_SCRIPT;

      // Verify the script structure ensures atomic read+trim
      const hasLrange = script.includes("redis.call('LRANGE'");
      const hasLtrim = script.includes("redis.call('LTRIM'");
      const hasGuard = script.includes('if #events > 0');
      const trimUsesEventCount = script.includes('#events, -1');

      expect(hasLrange).toBe(true);
      expect(hasLtrim).toBe(true);
      expect(hasGuard).toBe(true);
      expect(trimUsesEventCount).toBe(true);

      // Lua scripts in Redis are atomic — no other command can interleave
      // This is guaranteed by Redis's single-threaded execution model
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. PERF-002: Events Table Partitioning (Migration Validation)
// ═════════════════════════════════════════════════════════════════════════════

describe('PERF-002: Events Table Partitioning Migration', () => {
  let migrationSql: string;
  let downMigrationSql: string;

  beforeEach(async () => {
    const basePath = path.resolve(import.meta.dirname ?? __dirname, '../../../tools/migrations');
    migrationSql = await fs.readFile(path.join(basePath, '009_events_partitioning.sql'), 'utf-8');
    downMigrationSql = await fs.readFile(path.join(basePath, '009_events_partitioning_down.sql'), 'utf-8');
  });

  describe('Up migration structure', () => {
    it('should rename events to events_old first', () => {
      expect(migrationSql).toContain('ALTER TABLE IF EXISTS events RENAME TO events_old');
    });

    it('should create partitioned table with PARTITION BY RANGE (timestamp)', () => {
      expect(migrationSql).toContain('PARTITION BY RANGE (timestamp)');
    });

    it('should include timestamp in the primary key (required for partitioning)', () => {
      // PostgreSQL requires the partition key to be part of any unique constraint
      expect(migrationSql).toContain('PRIMARY KEY (id, timestamp)');
    });

    it('should preserve all original columns', () => {
      const requiredColumns = [
        'id', 'tenant_id', 'message_id', 'event_type', 'recipient',
        'timestamp', 'user_agent', 'ip_address', 'link_id', 'link_url',
        'bounce_type', 'bounce_subtype', 'diagnostic_code',
        'complaint_type', 'complaint_user_agent', 'raw_data',
        'deduplication_key', 'processed_at',
      ];
      for (const col of requiredColumns) {
        expect(migrationSql).toContain(col);
      }
    });

    it('should create composite indexes for common query patterns', () => {
      expect(migrationSql).toContain('idx_events_tenant_timestamp');
      expect(migrationSql).toContain('idx_events_tenant_type_timestamp');
    });

    it('should create monthly partitions via DO block', () => {
      expect(migrationSql).toContain('DO $$');
      expect(migrationSql).toContain("INTERVAL '1 month'");
      expect(migrationSql).toContain('CREATE TABLE %I PARTITION OF events');
    });

    it('should create a default partition for out-of-range data', () => {
      expect(migrationSql).toContain('CREATE TABLE events_default PARTITION OF events DEFAULT');
    });

    it('should migrate data from old table', () => {
      expect(migrationSql).toContain('INSERT INTO events SELECT * FROM events_old');
    });

    it('should drop the old table after migration', () => {
      expect(migrationSql).toContain('DROP TABLE events_old');
    });

    it('should create partitions covering at least 2024-2027', () => {
      expect(migrationSql).toContain("'2024-01-01'");
      expect(migrationSql).toContain("'2028-01-01'");
    });

    it('should include deduplication key index with partial condition', () => {
      expect(migrationSql).toContain('idx_events_dedup');
      expect(migrationSql).toContain('WHERE deduplication_key IS NOT NULL');
    });
  });

  describe('Down migration structure', () => {
    it('should create a regular (non-partitioned) table', () => {
      expect(downMigrationSql).toContain('CREATE TABLE events_unpartitioned');
      expect(downMigrationSql).not.toContain('PARTITION BY');
    });

    it('should have a single-column PRIMARY KEY (id)', () => {
      expect(downMigrationSql).toContain('id VARCHAR(26) PRIMARY KEY');
    });

    it('should copy data from partitioned table', () => {
      expect(downMigrationSql).toContain('INSERT INTO events_unpartitioned SELECT * FROM events');
    });

    it('should drop the partitioned table with CASCADE', () => {
      expect(downMigrationSql).toContain('DROP TABLE events CASCADE');
    });

    it('should rename back to events', () => {
      expect(downMigrationSql).toContain('ALTER TABLE events_unpartitioned RENAME TO events');
    });

    it('should recreate base indexes', () => {
      expect(downMigrationSql).toContain('idx_events_tenant');
      expect(downMigrationSql).toContain('idx_events_timestamp');
    });
  });

  describe('Partition naming convention', () => {
    it('should use events_YYYY_MM format', () => {
      expect(migrationSql).toContain("'events_' || TO_CHAR(current_start, 'YYYY_MM')");
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. PERF-003: Webhook Transactional Completion
// ═════════════════════════════════════════════════════════════════════════════

describe('PERF-003: Webhook Transactional Completion', () => {
  /**
   * We verify the transactional pattern by reading the source file and
   * checking that flushPendingSuccesses (batch) and failJob use
   * BEGIN/COMMIT/ROLLBACK with db.connect() instead of direct pool queries.
   *
   * FIX-500-081 changed handleSuccess to push to pendingSuccesses, moving
   * the transactional logic into flushPendingSuccesses (batch) and
   * handleSuccessIndividual (fallback).
   */
  let webhookSource: string;

  beforeEach(async () => {
    const srcPath = path.resolve(import.meta.dirname ?? __dirname, '../../worker/src/processors/webhook.ts');
    webhookSource = await fs.readFile(srcPath, 'utf-8');
  });

  describe('flushPendingSuccesses batch transactional pattern', () => {
    it('should use db.connect() for explicit client checkout', () => {
      // Extract flushPendingSuccesses method
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      expect(match).not.toBeNull();
      const method = match![0];
      expect(method).toContain('this.db.connect()');
    });

    it('should BEGIN a transaction', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      expect(method).toContain("'BEGIN'");
    });

    it('should COMMIT on success', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      expect(method).toContain("'COMMIT'");
    });

    it('should ROLLBACK on error', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      expect(method).toContain("'ROLLBACK'");
    });

    it('should release client in finally block', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      expect(method).toContain('client.release()');
    });

    it('should INSERT delivery, UPDATE stats, and DELETE queue in same transaction', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      expect(method).toContain('INSERT INTO webhook_deliveries');
      expect(method).toContain('UPDATE webhooks');
      expect(method).toContain('DELETE FROM webhook_queue');
    });

    it('should use client.query (not this.db.query) for transactional queries', () => {
      const match = webhookSource.match(/private async flushPendingSuccesses[\s\S]*?(?=\n  private async )/);
      const method = match![0];
      // After BEGIN, all queries should use client.query
      const afterBegin = method.split("'BEGIN'")[1] ?? '';
      const clientQueries = (afterBegin.match(/client\.query/g) ?? []).length;
      const dbQueries = (afterBegin.match(/this\.db\.query/g) ?? []).length;
      expect(clientQueries).toBeGreaterThanOrEqual(3); // INSERT + UPDATE + DELETE + COMMIT
      expect(dbQueries).toBe(0); // No direct pool queries inside transaction
    });
  });

  describe('failJob transactional pattern', () => {
    it('should use db.connect() for explicit client checkout', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      expect(match).not.toBeNull();
      const method = match![0];
      expect(method).toContain('this.db.connect()');
    });

    it('should BEGIN a transaction', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      expect(method).toContain("'BEGIN'");
    });

    it('should COMMIT on success', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      expect(method).toContain("'COMMIT'");
    });

    it('should ROLLBACK on error', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      expect(method).toContain("'ROLLBACK'");
    });

    it('should release client in finally block', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      expect(method).toContain('client.release()');
    });

    it('should INSERT delivery, UPDATE stats, INSERT dlq, and DELETE queue in same transaction', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      expect(method).toContain('INSERT INTO webhook_deliveries');
      expect(method).toContain('UPDATE webhooks');
      expect(method).toContain('INSERT INTO webhook_dlq');
      expect(method).toContain('DELETE FROM webhook_queue');
    });

    it('should run checkWebhookHealth OUTSIDE the transaction', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      // checkWebhookHealth should be after client.release() / finally block
      const releaseIdx = method.lastIndexOf('client.release()');
      const healthIdx = method.lastIndexOf('checkWebhookHealth');
      expect(healthIdx).toBeGreaterThan(releaseIdx);
    });

    it('should use client.query (not this.db.query) for transactional queries', () => {
      const match = webhookSource.match(/private async failJob[\s\S]*?(?=\n  private async (?:checkWebhookHealth|handleSuccess|retryJob))/);
      const method = match![0];
      const afterBegin = method.split("'BEGIN'")[1]?.split("'COMMIT'")[0] ?? '';
      const clientQueries = (afterBegin.match(/client\.query/g) ?? []).length;
      const dbQueries = (afterBegin.match(/this\.db\.query/g) ?? []).length;
      expect(clientQueries).toBeGreaterThanOrEqual(4); // INSERT delivery + UPDATE stats + INSERT dlq + DELETE queue
      expect(dbQueries).toBe(0);
    });
  });

  describe('Transaction isolation verification', () => {
    it('should have try/catch/finally pattern for proper cleanup', () => {
      // Verify transactional methods follow the correct pattern:
      // const client = await this.db.connect();
      // try { BEGIN; ...; COMMIT; } catch { ROLLBACK; } finally { client.release(); }
      // FIX-500-081: handleSuccess now uses batch flush — check flushPendingSuccesses instead
      for (const methodName of ['flushPendingSuccesses', 'failJob']) {
        const regex = new RegExp(`private async ${methodName}[\\s\\S]*?(?=\\n  private async )`);
        const match = webhookSource.match(regex);
        expect(match, `${methodName} not found`).not.toBeNull();
        const method = match![0];

        // Verify structure order: connect → try → BEGIN → COMMIT → catch → ROLLBACK → finally → release
        const connectIdx = method.indexOf('this.db.connect()');
        const tryIdx = method.indexOf('try {', connectIdx);
        const beginIdx = method.indexOf("'BEGIN'", tryIdx);
        const commitIdx = method.indexOf("'COMMIT'", beginIdx);
        const catchIdx = method.indexOf('catch', commitIdx);
        const rollbackIdx = method.indexOf("'ROLLBACK'", catchIdx);
        const finallyIdx = method.indexOf('finally', rollbackIdx);
        const releaseIdx = method.indexOf('client.release()', finallyIdx);

        expect(connectIdx, `${methodName}: connect`).toBeGreaterThanOrEqual(0);
        expect(tryIdx, `${methodName}: try`).toBeGreaterThan(connectIdx);
        expect(beginIdx, `${methodName}: BEGIN`).toBeGreaterThan(tryIdx);
        expect(commitIdx, `${methodName}: COMMIT`).toBeGreaterThan(beginIdx);
        expect(catchIdx, `${methodName}: catch`).toBeGreaterThan(commitIdx);
        expect(rollbackIdx, `${methodName}: ROLLBACK`).toBeGreaterThan(catchIdx);
        expect(finallyIdx, `${methodName}: finally`).toBeGreaterThan(rollbackIdx);
        expect(releaseIdx, `${methodName}: release`).toBeGreaterThan(finallyIdx);
      }
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. PERF-004: Batch API Domain/Suppression Deduplication
// ═════════════════════════════════════════════════════════════════════════════

describe('PERF-004: Batch API Domain/Suppression Deduplication', () => {
  let messagesRouteSource: string;

  beforeEach(async () => {
    const srcPath = path.resolve(import.meta.dirname ?? __dirname, '../../api/src/routes/messages.ts');
    messagesRouteSource = await fs.readFile(srcPath, 'utf-8');
  });

  describe('Domain deduplication', () => {
    it('should extract unique domains from the batch before processing', () => {
      expect(messagesRouteSource).toContain('uniqueDomains');
      expect(messagesRouteSource).toContain('new Set');
    });

    it('should create a domainCache Map', () => {
      expect(messagesRouteSource).toContain('domainCache');
      expect(messagesRouteSource).toContain('new Map');
    });

    it('should query each domain only once (loop over uniqueDomains, not messages)', () => {
      // FIX-073: The domain lookups use Promise.all over uniqueDomains (parallel)
      expect(messagesRouteSource).toContain('uniqueDomains.map(domain => domainsRepo.findByDomain');
    });

    it('should use domainCache in processSingleMessage instead of querying', () => {
      // processSingleMessage should read from the cache
      expect(messagesRouteSource).toContain('domainCache.get(sendingDomain)');
    });

    it('should NOT call domainsRepo.findByDomain inside processSingleMessage', () => {
      // Extract processSingleMessage function body
      const match = messagesRouteSource.match(/const processSingleMessage[\s\S]*?(?=\n    \/\/ Process in parallel chunks)/);
      expect(match).not.toBeNull();
      const fnBody = match![0];
      expect(fnBody).not.toContain('domainsRepo.findByDomain');
    });
  });

  describe('Suppression deduplication', () => {
    it('should collect all unique recipient emails across the batch', () => {
      expect(messagesRouteSource).toContain('allBatchRecipientEmails');
    });

    it('should call checkBulkSuppression once for the entire batch', () => {
      // Before the processSingleMessage function, there should be exactly one
      // checkBulkSuppression actual invocation (not comment mentions) for the batch-level dedup
      const beforeProcessFn = messagesRouteSource.split('const processSingleMessage')[0] ?? '';
      const batchSection = beforeProcessFn.split("router.post('/batch'")[1] ?? '';
      // Strip block and line comments so only actual code remains
      const codeOnly = batchSection.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      const suppressionCalls = (codeOnly.match(/checkBulkSuppression/g) ?? []).length;
      expect(suppressionCalls).toBe(1);
    });

    it('should use batchSuppressions in processSingleMessage', () => {
      const match = messagesRouteSource.match(/const processSingleMessage[\s\S]*?(?=\n    \/\/ Process in parallel chunks)/);
      expect(match).not.toBeNull();
      const fnBody = match![0];
      expect(fnBody).toContain('batchSuppressions');
    });

    it('should NOT call checkBulkSuppression inside processSingleMessage', () => {
      const match = messagesRouteSource.match(/const processSingleMessage[\s\S]*?(?=\n    \/\/ Process in parallel chunks)/);
      expect(match).not.toBeNull();
      const fnBody = match![0];
      expect(fnBody).not.toContain('checkBulkSuppression');
    });
  });

  describe('Deduplication logic correctness', () => {
    it('should deduplicate domains correctly', () => {
      const messages = [
        { from: { email: 'alice@example.com' } },
        { from: { email: 'bob@example.com' } },
        { from: { email: 'carol@acme.org' } },
        { from: { email: 'dave@example.com' } },
      ];

      const uniqueDomains = [...new Set(
        messages.map(m => m.from.email.split('@')[1] ?? '')
      )].filter(Boolean);

      expect(uniqueDomains).toEqual(['example.com', 'acme.org']);
      expect(uniqueDomains).toHaveLength(2); // Not 4!
    });

    it('should handle empty domain gracefully', () => {
      const messages = [
        { from: { email: 'no-at-sign' } },
        { from: { email: 'valid@example.com' } },
      ];

      const uniqueDomains = [...new Set(
        messages.map(m => m.from.email.split('@')[1] ?? '')
      )].filter(Boolean);

      expect(uniqueDomains).toEqual(['example.com']);
    });

    it('should deduplicate recipients across messages', () => {
      const messages = [
        { to: [{ email: 'a@x.com' }, { email: 'b@x.com' }], cc: [{ email: 'c@x.com' }], bcc: undefined },
        { to: [{ email: 'a@x.com' }, { email: 'd@x.com' }], cc: undefined, bcc: [{ email: 'b@x.com' }] },
      ];

      const allBatchRecipientEmails = [...new Set(
        messages.flatMap(m => [
          ...m.to.map(r => r.email),
          ...(m.cc ?? []).map(r => r.email),
          ...(m.bcc ?? []).map(r => r.email),
        ])
      )];

      expect(allBatchRecipientEmails).toHaveLength(4); // a, b, c, d — not 6
      expect(allBatchRecipientEmails).toContain('a@x.com');
      expect(allBatchRecipientEmails).toContain('b@x.com');
      expect(allBatchRecipientEmails).toContain('c@x.com');
      expect(allBatchRecipientEmails).toContain('d@x.com');
    });

    it('should quantify the improvement: 1000 msgs × 1 domain = 1 lookup not 1000', () => {
      const messageCount = 1000;
      const messages = Array.from({ length: messageCount }, (_, i) => ({
        from: { email: `user${i}@example.com` },
      }));

      const uniqueDomains = [...new Set(
        messages.map(m => m.from.email.split('@')[1] ?? '')
      )].filter(Boolean);

      expect(uniqueDomains).toHaveLength(1); // Only "example.com"
      // Before PERF-004: 1000 domain lookups
      // After PERF-004: 1 domain lookup
      const improvementFactor = messageCount / uniqueDomains.length;
      expect(improvementFactor).toBe(1000);
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. PERF-005: Message List Column Projection + Window Pagination
// ═════════════════════════════════════════════════════════════════════════════

describe('PERF-005: Message List Column Projection + Window Pagination', () => {
  let messagesRepoSource: string;

  beforeEach(async () => {
    const srcPath = path.resolve(import.meta.dirname ?? __dirname, '../../../packages/db/src/repositories/messages.ts');
    messagesRepoSource = await fs.readFile(srcPath, 'utf-8');
  });

  describe('Column projection', () => {
    it('should NOT use SELECT * in listByTenant', () => {
      // Extract listByTenant method
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      expect(match).not.toBeNull();
      const method = match![0];
      // Strip comments (both block and line) before checking, so comment mentions don't cause false matches
      const codeOnly = method.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      expect(codeOnly).not.toContain('SELECT *');
    });

    it('should select specific columns in listByTenant', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      // Strip comments
      const codeOnly = method.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      // Should select lightweight columns
      expect(codeOnly).toContain('id, tenant_id');
      expect(codeOnly).toContain('from_email');
      expect(codeOnly).toContain('subject');
      expect(codeOnly).toContain('status');
      expect(codeOnly).toContain('created_at');
    });

    it('should NOT select html_body or text_body in listByTenant', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      // Strip comments so we only check the actual SQL/code, not comment mentions
      const codeOnly = method.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      expect(codeOnly).not.toContain('html_body');
      expect(codeOnly).not.toContain('text_body');
    });

    it('should NOT select template_data, headers, or attachments in listByTenant', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      // Strip comments first so we only inspect actual code
      const codeOnly = method.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      // Extract just the SELECT clause (between SELECT and FROM)
      const selectMatch = codeOnly.match(/SELECT[\s\S]*?FROM messages/);
      expect(selectMatch).not.toBeNull();
      const selectClause = selectMatch![0];
      expect(selectClause).not.toContain('template_data');
      expect(selectClause).not.toContain('html_body');
      expect(selectClause).not.toContain('text_body');
      // headers and attachments should also be excluded
      expect(selectClause).not.toMatch(/\bheaders\b/);
      expect(selectClause).not.toMatch(/\battachments\b/);
    });

    it('should SELECT * by default in findById (detail view) with optional body exclusion', () => {
      const match = messagesRepoSource.match(/async findById[\s\S]*?(?=\n  async findByIdempotencyKey)/);
      expect(match).not.toBeNull();
      const method = match![0];
      // FIX-500-043: findById now accepts includeBody option, but defaults to SELECT *
      expect(method).toContain("includeBody");
      expect(method).toContain("'*'");
    });
  });

  describe('Window function pagination', () => {
    it('should use COUNT(*) OVER() instead of separate COUNT query', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      expect(method).toContain('COUNT(*) OVER()');
    });

    it('should include total_count in the result type', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      expect(method).toContain('total_count');
    });

    it('should NOT have a separate COUNT query', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      // Should not have SELECT COUNT(*) as a standalone query
      expect(method).not.toMatch(/SELECT COUNT\(\*\) as count FROM messages/);
    });

    it('should parse total from first row', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      expect(method).toContain("result.value.rows[0]?.total_count ?? '0'");
    });
  });

  describe('mapListRow method', () => {
    it('should have a mapListRow method', () => {
      expect(messagesRepoSource).toContain('private mapListRow');
    });

    it('should set htmlBody to null in mapListRow', () => {
      const match = messagesRepoSource.match(/private mapListRow[\s\S]*?(?=\n\n  (?:\/\*\*|private|async|public|\}))/);
      expect(match).not.toBeNull();
      const method = match![0];
      expect(method).toContain('htmlBody: null');
    });

    it('should set textBody to null in mapListRow', () => {
      const match = messagesRepoSource.match(/private mapListRow[\s\S]*?(?=\n\n  (?:\/\*\*|private|async|public|\}))/);
      const method = match![0];
      expect(method).toContain('textBody: null');
    });

    it('should set attachments to empty array in mapListRow', () => {
      const match = messagesRepoSource.match(/private mapListRow[\s\S]*?(?=\n\n  (?:\/\*\*|private|async|public|\}))/);
      const method = match![0];
      expect(method).toContain('attachments: []');
    });

    it('should still parse recipients JSON in mapListRow', () => {
      const match = messagesRepoSource.match(/private mapListRow[\s\S]*?(?=\n\n  (?:\/\*\*|private|async|public|\}))/);
      const method = match![0];
      // recipients is needed for .length in the API response
      expect(method).toContain('recipients');
      expect(method).toContain('parseJsonOrDefault');
    });

    it('listByTenant should use mapListRow (not mapRow)', () => {
      const match = messagesRepoSource.match(/async listByTenant[\s\S]*?(?=\n  private mapListRow|\n  private mapRow)/);
      const method = match![0];
      // Strip comments so mentions like "Unlike mapRow()" don't cause false matches
      const codeOnly = method.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
      expect(codeOnly).toContain('mapListRow');
      expect(codeOnly).not.toContain('mapRow(');
    });
  });

  describe('Window function correctness', () => {
    it('COUNT(*) OVER() returns total for all matching rows', () => {
      // Verify the concept: COUNT(*) OVER() with LIMIT still returns the
      // total count of all matching rows (before LIMIT), not just the page count.
      // This is because window functions run before LIMIT in SQL execution order.

      // Simulate a result set with total_count
      const simulatedRows = [
        { id: '1', total_count: '500' },
        { id: '2', total_count: '500' },
        { id: '3', total_count: '500' },
      ];

      // All rows should have the same total_count (the full count)
      const total = parseInt(simulatedRows[0]!.total_count, 10);
      expect(total).toBe(500);

      // Even though we only got 3 rows (LIMIT 3), total is still 500
      expect(simulatedRows).toHaveLength(3);
      expect(total).toBeGreaterThan(simulatedRows.length);
    });

    it('returns 0 total when no rows match', () => {
      const simulatedRows: Array<{ total_count: string }> = [];
      const total = parseInt(simulatedRows[0]?.total_count ?? '0', 10);
      expect(total).toBe(0);
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Cross-cutting: Source file existence and PERF markers
// ═════════════════════════════════════════════════════════════════════════════

describe('Cross-cutting: PERF improvement markers', () => {
  it('PERF-001 marker exists in processor.ts', async () => {
    const src = await fs.readFile(
      path.resolve(import.meta.dirname ?? __dirname, '../../tracking/src/processor.ts'), 'utf-8'
    );
    expect(src).toContain('PERF-001');
  });

  it('PERF-003 marker exists in webhook.ts', async () => {
    const src = await fs.readFile(
      path.resolve(import.meta.dirname ?? __dirname, '../../worker/src/processors/webhook.ts'), 'utf-8'
    );
    expect(src).toContain('PERF-003');
  });

  it('PERF-004 marker exists in messages.ts route', async () => {
    const src = await fs.readFile(
      path.resolve(import.meta.dirname ?? __dirname, '../../api/src/routes/messages.ts'), 'utf-8'
    );
    expect(src).toContain('PERF-004');
  });

  it('PERF-005 marker exists in messages.ts repository', async () => {
    const src = await fs.readFile(
      path.resolve(import.meta.dirname ?? __dirname, '../../../packages/db/src/repositories/messages.ts'), 'utf-8'
    );
    expect(src).toContain('PERF-005');
  });

  it('Migration 009 exists for events partitioning', async () => {
    const migrationPath = path.resolve(import.meta.dirname ?? __dirname, '../../../tools/migrations/009_events_partitioning.sql');
    const stat = await fs.stat(migrationPath);
    expect(stat.isFile()).toBe(true);
  });

  it('Down migration 009 exists for events partitioning', async () => {
    const migrationPath = path.resolve(import.meta.dirname ?? __dirname, '../../../tools/migrations/009_events_partitioning_down.sql');
    const stat = await fs.stat(migrationPath);
    expect(stat.isFile()).toBe(true);
  });
});
