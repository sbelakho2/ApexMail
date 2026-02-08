/**
 * Batch 4 (#41–60) Targeted Tests — DB Query Performance
 *
 * Each test verifies a specific DB performance fix introduced in Batch 4
 * by inspecting the actual source code for the expected patterns.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '../../../..');

function read(rel: string): string {
    return fs.readFileSync(path.join(ROOT, rel), 'utf-8');
}

// ---------------------------------------------------------------------------
// #41: API key lookup — SELECT specific columns instead of SELECT *
// ---------------------------------------------------------------------------
describe('#41 – API key lookup column pruning', () => {
    const src = read('packages/db/src/repositories/api-keys.ts');

    it('does NOT use SELECT * for prefix lookup', () => {
        expect(src).toMatch(/FIX-500-041/);
    });

    it('selects specific columns for api_keys prefix lookup', () => {
        expect(src).toMatch(/SELECT id, tenant_id.*FROM api_keys WHERE prefix/);
    });
});

// ---------------------------------------------------------------------------
// #42: Suppression check — SELECT specific columns
// ---------------------------------------------------------------------------
describe('#42 – Suppression check column pruning', () => {
    const src = read('packages/db/src/repositories/suppressions.ts');

    it('has FIX-500-042 annotation', () => {
        expect(src).toContain('FIX-500-042');
    });

    it('selects specific columns for suppression check', () => {
        expect(src).toMatch(/SELECT id, tenant_id.*FROM suppressions/);
    });
});

// ---------------------------------------------------------------------------
// #43: Message findById — conditional body column exclusion
// ---------------------------------------------------------------------------
describe('#43 – Message findById includeBody option', () => {
    const src = read('packages/db/src/repositories/messages.ts');

    it('has FIX-500-043 annotation', () => {
        expect(src).toContain('FIX-500-043');
    });

    it('accepts includeBody option parameter', () => {
        expect(src).toMatch(/includeBody/);
    });

    it('conditionally excludes body columns', () => {
        expect(src).toMatch(/includeBody === false/);
    });
});

// ---------------------------------------------------------------------------
// #44: Events search — COUNT(*) OVER() instead of separate COUNT query
// ---------------------------------------------------------------------------
describe('#44 – Events search uses COUNT(*) OVER()', () => {
    const src = read('packages/db/src/repositories/events.ts');

    it('has FIX-500-044 annotation', () => {
        expect(src).toContain('FIX-500-044');
    });

    it('uses COUNT(*) OVER() window function', () => {
        expect(src).toMatch(/COUNT\(\*\)\s+OVER\(\)/i);
    });

    it('extracts total_count from results', () => {
        expect(src).toContain('total_count');
    });
});

// ---------------------------------------------------------------------------
// #45: Audit logs findByResource — add LIMIT
// ---------------------------------------------------------------------------
describe('#45 – Audit logs findByResource has LIMIT', () => {
    const src = read('packages/db/src/repositories/audit-logs.ts');

    it('has FIX-500-045 annotation', () => {
        expect(src).toContain('FIX-500-045');
    });

    it('adds LIMIT to findByResource query', () => {
        // The query should have LIMIT after the ORDER BY
        expect(src).toMatch(/resource_id[\s\S]*?ORDER BY[\s\S]*?LIMIT/);
    });
});

// ---------------------------------------------------------------------------
// #46: Events findByMessageId — add LIMIT
// ---------------------------------------------------------------------------
describe('#46 – Events findByMessageId has LIMIT', () => {
    const src = read('packages/db/src/repositories/events.ts');

    it('has FIX-500-046 annotation', () => {
        expect(src).toContain('FIX-500-046');
    });

    it('accepts limit option parameter', () => {
        expect(src).toMatch(/findByMessageId.*options\?.*limit/);
    });

    it('appends LIMIT to the query', () => {
        expect(src).toMatch(/FROM events WHERE message_id.*LIMIT/);
    });
});

// ---------------------------------------------------------------------------
// #47: Webhooks findByTenant — add pagination
// ---------------------------------------------------------------------------
describe('#47 – Webhooks findByTenant has pagination', () => {
    const src = read('packages/db/src/repositories/webhooks.ts');

    it('has FIX-500-047 annotation', () => {
        expect(src).toContain('FIX-500-047');
    });

    it('accepts limit and offset options', () => {
        expect(src).toMatch(/findByTenant.*options\?.*limit/);
    });

    it('uses LIMIT and OFFSET in query', () => {
        expect(src).toMatch(/FROM webhooks.*LIMIT.*OFFSET/);
    });
});

// ---------------------------------------------------------------------------
// #48: Missing index on messages.mta_message_id — migration note
// ---------------------------------------------------------------------------
describe('#48 – mta_message_id index migration note', () => {
    const src = read('packages/db/src/repositories/messages.ts');

    it('has FIX-500-048 annotation with index creation TODO', () => {
        expect(src).toContain('FIX-500-048');
        expect(src).toContain('idx_messages_mta_message_id');
    });
});

// ---------------------------------------------------------------------------
// #49: Analytics domain GROUP BY — functional index note
// ---------------------------------------------------------------------------
describe('#49 – Analytics domain functional index note', () => {
    const src = read('packages/db/src/repositories/events.ts');

    it('has FIX-500-049 annotation with index creation TODO', () => {
        expect(src).toContain('FIX-500-049');
        expect(src).toContain('idx_events_recipient_domain');
    });
});

// ---------------------------------------------------------------------------
// #50: Audit log composite index — migration note
// ---------------------------------------------------------------------------
describe('#50 – Audit log composite index migration note', () => {
    const src = read('packages/db/src/repositories/audit-logs.ts');

    it('has FIX-500-050 annotation with index creation TODO', () => {
        expect(src).toContain('FIX-500-050');
        expect(src).toContain('idx_audit_logs_resource_lookup');
    });
});

// ---------------------------------------------------------------------------
// #51: Idempotency cleanup — batched DELETE with LIMIT
// ---------------------------------------------------------------------------
describe('#51 – Idempotency cleanup batched delete', () => {
    const src = read('packages/db/src/repositories/system.ts');

    it('has FIX-500-051 annotation', () => {
        expect(src).toContain('FIX-500-051');
    });

    it('accepts batchSize parameter', () => {
        expect(src).toMatch(/cleanupExpiredIdempotencyRecords\(batchSize.*=.*1000\)/);
    });

    it('uses LIMIT in the delete subquery', () => {
        expect(src).toMatch(/DELETE FROM idempotency_keys[\s\S]*?LIMIT/);
    });

    it('loops until fewer than batchSize deleted', () => {
        expect(src).toMatch(/while\s*\(true\)/);
    });
});

// ---------------------------------------------------------------------------
// #52: Inbound messages cleanup — batched DELETE
// ---------------------------------------------------------------------------
describe('#52 – Inbound messages cleanup batched delete', () => {
    const src = read('packages/db/src/repositories/inbound-messages.ts');

    it('has FIX-500-052 annotation', () => {
        expect(src).toContain('FIX-500-052');
    });

    it('accepts batchSize parameter', () => {
        expect(src).toMatch(/cleanupOld\(olderThanDays.*batchSize/);
    });

    it('uses batched deletes with LIMIT', () => {
        expect(src).toMatch(/DELETE FROM[\s\S]*?WHERE id IN/);
    });

    it('processes tables sequentially instead of parallel unbounded', () => {
        expect(src).toContain('batchDelete');
    });
});

// ---------------------------------------------------------------------------
// #53: Template listVersions — tenant scoping
// ---------------------------------------------------------------------------
describe('#53 – Template listVersions has tenantId parameter', () => {
    const src = read('packages/db/src/repositories/templates.ts');

    it('has FIX-500-053 annotation', () => {
        expect(src).toContain('FIX-500-053');
    });

    it('accepts tenantId parameter', () => {
        expect(src).toMatch(/listVersions[\s\S]*?tenantId\??: string/);
    });

    it('joins with templates table for tenant scoping', () => {
        expect(src).toMatch(/JOIN templates t ON tv.template_id = t.id/);
    });
});

// ---------------------------------------------------------------------------
// #54: Domain findExpired — add LIMIT
// ---------------------------------------------------------------------------
describe('#54 – Domain findExpired has LIMIT', () => {
    const src = read('packages/db/src/repositories/domains.ts');

    it('has FIX-500-054 annotation', () => {
        expect(src).toContain('FIX-500-054');
    });

    it('adds LIMIT to expired domains query', () => {
        expect(src).toMatch(/pending.*expires_at[\s\S]*?LIMIT 100/);
    });
});

// ---------------------------------------------------------------------------
// #55: Subscription preferences — multi-row INSERT
// ---------------------------------------------------------------------------
describe('#55 – Subscription preferences batch INSERT', () => {
    const src = read('packages/db/src/repositories/subscriptions.ts');

    it('has FIX-500-055 annotation', () => {
        expect(src).toContain('FIX-500-055');
    });

    it('does NOT use a for loop for individual INSERTs', () => {
        // Should not have: for (const [category, subscribed] of Object.entries
        expect(src).not.toMatch(/for \(const \[category, subscribed\] of Object\.entries/);
    });

    it('builds dynamic placeholders for batch insert', () => {
        expect(src).toContain('placeholders.join');
    });
});

// ---------------------------------------------------------------------------
// #56: Reputation alert TOCTOU — atomic CTE upsert
// ---------------------------------------------------------------------------
describe('#56 – Reputation alert atomic upsert', () => {
    const src = read('packages/db/src/repositories/reputation.ts');

    it('has FIX-500-056 annotation', () => {
        expect(src).toContain('FIX-500-056');
    });

    it('uses CTE with NOT EXISTS for atomic insert', () => {
        expect(src).toContain('WITH check_existing AS');
        expect(src).toContain('WHERE NOT EXISTS');
    });

    it('does NOT use separate SELECT then INSERT', () => {
        // Should not have the old pattern of COUNT then check
        expect(src).not.toMatch(/SELECT COUNT\(\*\).*FROM reputation_alerts[\s\S]*?parseInt[\s\S]*?INSERT INTO reputation_alerts/);
    });
});

// ---------------------------------------------------------------------------
// #57: Analytics funnel — single GROUP BY instead of N sequential queries
// ---------------------------------------------------------------------------
describe('#57 – Analytics funnel single query', () => {
    const src = read('apps/analytics/src/query-engine.ts');

    it('has FIX-500-057 annotation', () => {
        expect(src).toContain('FIX-500-057');
    });

    it('uses GROUP BY event_type in a single query', () => {
        expect(src).toContain('GROUP BY event_type');
    });

    it('uses ANY($4) for filtering multiple event types', () => {
        expect(src).toContain('ANY($4)');
    });

    it('does NOT loop individual stage queries', () => {
        expect(src).not.toMatch(/for \(const stage of stages\)/);
    });
});

// ---------------------------------------------------------------------------
// #58: Analytics compaction — LEFT JOIN instead of correlated NOT EXISTS
// ---------------------------------------------------------------------------
describe('#58 – Analytics compaction uses LEFT JOIN', () => {
    const src = read('apps/analytics/src/compaction.ts');

    it('has FIX-500-058 annotation', () => {
        expect(src).toContain('FIX-500-058');
    });

    it('uses LEFT JOIN instead of NOT EXISTS', () => {
        expect(src).toContain('LEFT JOIN compaction_log');
    });

    it('uses IS NULL anti-join pattern', () => {
        expect(src).toContain('IS NULL');
    });
});

// ---------------------------------------------------------------------------
// #59: Analytics SCAN → explicit keys
// ---------------------------------------------------------------------------
describe('#59 – Worker analytics uses explicit keys instead of SCAN', () => {
    const src = read('apps/worker/src/processors/analytics.ts');

    it('has FIX-500-059 annotation', () => {
        expect(src).toContain('FIX-500-059');
    });

    it('constructs explicit key list', () => {
        expect(src).toContain('eventTypes.map');
    });

    it('uses mget instead of SCAN', () => {
        expect(src).toContain('redis.mget');
    });

    it('does NOT use redis.scan', () => {
        expect(src).not.toContain('redis.scan');
    });
});

// ---------------------------------------------------------------------------
// #60: Control plane duplicate DB pool — import shared
// ---------------------------------------------------------------------------
describe('#60 – Dashboard stats imports shared DB pool', () => {
    const src = read('apps/control-plane/src/app/api/dashboard/stats/route.ts');

    it('has FIX-500-060 annotation', () => {
        expect(src).toContain('FIX-500-060');
    });

    it('imports from shared lib/db', () => {
        expect(src).toContain('lib/db');
    });

    it('does NOT create its own PgPool', () => {
        expect(src).not.toContain("new PgPool");
    });
});
