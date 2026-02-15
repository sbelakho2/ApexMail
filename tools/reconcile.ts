/**
 * Data Reconciliation Tool
 * Reconciles data between messages, queue, and events tables
 */

import { Pool } from 'pg';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error('DATABASE_URL must be set to run reconciliation');
}

const pool = new Pool({
  connectionString: databaseUrl,
});

interface ReconciliationIssue {
  type: 'orphan_queue' | 'orphan_event' | 'status_mismatch' | 'missing_queue';
  messageId?: string;
  queueId?: string;
  eventId?: string;
  details: string;
}

async function reconcile() {
  console.log('🔄 Starting data reconciliation...\n');

  const issues: ReconciliationIssue[] = [];

  try {
    // 1. Find orphan queue entries (no corresponding message)
    console.log('Checking for orphan queue entries...');
    const orphanQueueResult = await pool.query(`
      SELECT eq.id, eq.message_id
      FROM email_queue eq
      LEFT JOIN messages m ON eq.message_id = m.id
      WHERE m.id IS NULL
      LIMIT 100
    `);

    for (const row of orphanQueueResult.rows) {
      issues.push({
        type: 'orphan_queue',
        queueId: row.id,
        messageId: row.message_id,
        details: `Queue entry ${row.id} references non-existent message ${row.message_id}`,
      });
    }
    console.log(`   Found ${orphanQueueResult.rows.length} orphan queue entries\n`);

    // 2. Find messages with status mismatch
    console.log('Checking for status mismatches...');
    const statusMismatchResult = await pool.query(`
      SELECT m.id, m.status as message_status, eq.status as queue_status
      FROM messages m
      JOIN email_queue eq ON m.id = eq.message_id
      WHERE m.status != eq.status
      LIMIT 100
    `);

    for (const row of statusMismatchResult.rows) {
      issues.push({
        type: 'status_mismatch',
        messageId: row.id,
        details: `Message ${row.id} has status '${row.message_status}' but queue has '${row.queue_status}'`,
      });
    }
    console.log(`   Found ${statusMismatchResult.rows.length} status mismatches\n`);

    // 3. Find messages without queue entries
    console.log('Checking for messages without queue entries...');
    const missingQueueResult = await pool.query(`
      SELECT m.id, m.status
      FROM messages m
      LEFT JOIN email_queue eq ON m.id = eq.message_id
      WHERE eq.id IS NULL
        AND m.status IN ('queued', 'pending', 'processing')
      LIMIT 100
    `);

    for (const row of missingQueueResult.rows) {
      issues.push({
        type: 'missing_queue',
        messageId: row.id,
        details: `Message ${row.id} with status '${row.status}' has no queue entry`,
      });
    }
    console.log(`   Found ${missingQueueResult.rows.length} messages without queue entries\n`);

    // 4. Find orphan events
    console.log('Checking for orphan events...');
    const orphanEventsResult = await pool.query(`
      SELECT e.id, e.message_id
      FROM events e
      LEFT JOIN messages m ON e.message_id = m.id
      WHERE m.id IS NULL
        AND e.message_id IS NOT NULL
      LIMIT 100
    `);

    for (const row of orphanEventsResult.rows) {
      issues.push({
        type: 'orphan_event',
        eventId: row.id,
        messageId: row.message_id,
        details: `Event ${row.id} references non-existent message ${row.message_id}`,
      });
    }
    console.log(`   Found ${orphanEventsResult.rows.length} orphan events\n`);

    // Summary
    console.log('📊 Reconciliation Summary:');
    console.log(`   Total issues found: ${issues.length}`);
    console.log(`   - Orphan queue entries: ${issues.filter(i => i.type === 'orphan_queue').length}`);
    console.log(`   - Orphan events: ${issues.filter(i => i.type === 'orphan_event').length}`);
    console.log(`   - Status mismatches: ${issues.filter(i => i.type === 'status_mismatch').length}`);
    console.log(`   - Missing queue entries: ${issues.filter(i => i.type === 'missing_queue').length}`);

    if (issues.length > 0) {
      console.log('\n⚠️  Issues found. Run with --fix to auto-correct.');
      
      // Show sample issues
      console.log('\nSample issues:');
      issues.slice(0, 10).forEach(issue => {
        console.log(`   - ${issue.type}: ${issue.details}`);
      });

      process.exit(1);
    } else {
      console.log('\n✅ No issues found! Data is consistent.');
    }
  } catch (error) {
    console.error('❌ Reconciliation failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  reconcile().catch(error => {
    console.error(error);
    process.exit(1);
  });
}

export { reconcile };
