/**
 * Event Reconciliation Worker - Verifies exact-once event processing
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { config } from './config.js';

interface ReconciliationWorkerConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
}

interface ReconciliationResult {
  date: string;
  status: 'success' | 'discrepancy' | 'error';
  messagesSent: number;
  eventsExpected: number;
  eventsFound: number;
  discrepancies: DiscrepancyDetail[];
  duration: number;
}

interface DiscrepancyDetail {
  messageId: string;
  tenantId: string;
  expectedEvents: string[];
  foundEvents: string[];
  missingEvents: string[];
  extraEvents: string[];
}

export class ReconciliationWorker {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;
  private running = false;
  private stopRequested = false;

  constructor(options: ReconciliationWorkerConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
  }

  async start(): Promise<void> {
    this.logger.info('Starting reconciliation worker', {
      schedule: config.reconciliation.schedule,
    });

    // Run initial reconciliation for yesterday
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    await this.runReconciliation(yesterday);
  }

  async stop(): Promise<void> {
    this.stopRequested = true;
    
    while (this.running) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    this.logger.info('Reconciliation worker stopped');
  }

  async runReconciliation(date: Date): Promise<ReconciliationResult> {
    if (this.running) {
      this.logger.warn('Reconciliation already in progress');
      return {
        date: date.toISOString().split('T')[0],
        status: 'error',
        messagesSent: 0,
        eventsExpected: 0,
        eventsFound: 0,
        discrepancies: [],
        duration: 0,
      };
    }

    this.running = true;
    const startTime = Date.now();
    const dateStr = date.toISOString().split('T')[0];

    this.logger.info('Starting reconciliation', { date: dateStr });

    try {
      const nextDate = new Date(date);
      nextDate.setDate(nextDate.getDate() + 1);

      // Get all messages sent on this date
      const messagesResult = await this.db.query<{
        id: string;
        tenant_id: string;
        status: string;
        recipient_count: number;
      }>(`
        SELECT id, tenant_id, status, 
               COALESCE(recipient_count, 1) as recipient_count
        FROM messages
        WHERE created_at >= $1 AND created_at < $2
      `, [date, nextDate]);

      const messages = messagesResult.rows;
      const messageIds = messages.map(m => m.id);

      // Get all events for these messages
      const eventsResult = await this.db.query<{
        message_id: string;
        event_type: string;
        recipient: string;
      }>(`
        SELECT message_id, event_type, recipient
        FROM events
        WHERE message_id = ANY($1)
      `, [messageIds]);

      // Build event map
      const eventsByMessage = new Map<string, Set<string>>();
      for (const event of eventsResult.rows) {
        const key = event.message_id;
        const events = eventsByMessage.get(key) ?? new Set();
        events.add(`${event.event_type}:${event.recipient}`);
        eventsByMessage.set(key, events);
      }

      // Check for discrepancies
      const discrepancies: DiscrepancyDetail[] = [];
      let eventsExpected = 0;

      for (const message of messages) {
        if (this.stopRequested) break;

        // Every sent message should have at least one event (queued, sent, delivered, bounced, etc.)
        const messageEvents = eventsByMessage.get(message.id) ?? new Set();
        
        // Determine expected events based on status
        const expectedEvents = this.getExpectedEvents(message.status);
        eventsExpected += expectedEvents.length;

        // Find missing and extra events
        const foundEventTypes = new Set(
          Array.from(messageEvents).map(e => e.split(':')[0])
        );
        
        const missingEvents: string[] = [];
        for (const expected of expectedEvents) {
          if (!foundEventTypes.has(expected)) {
            missingEvents.push(expected);
          }
        }

        // Check for unexpected terminal states
        const terminalEvents = ['delivered', 'bounced', 'complained', 'failed'];
        const foundTerminal = terminalEvents.filter(t => foundEventTypes.has(t));
        
        if (foundTerminal.length > 1) {
          // Multiple terminal events is suspicious
          discrepancies.push({
            messageId: message.id,
            tenantId: message.tenant_id,
            expectedEvents,
            foundEvents: Array.from(foundEventTypes),
            missingEvents: [],
            extraEvents: foundTerminal.slice(1),
          });
        }

        if (missingEvents.length > 0) {
          discrepancies.push({
            messageId: message.id,
            tenantId: message.tenant_id,
            expectedEvents,
            foundEvents: Array.from(foundEventTypes),
            missingEvents,
            extraEvents: [],
          });
        }
      }

      // Calculate totals
      const messagesSent = messages.length;
      const eventsFound = eventsResult.rows.length;
      const status = discrepancies.length === 0 ? 'success' : 'discrepancy';

      // Store reconciliation result
      await this.storeResult({
        date: dateStr,
        status,
        messagesSent,
        eventsExpected,
        eventsFound,
        discrepancies,
        duration: Date.now() - startTime,
      });

      // Alert on significant discrepancies
      if (discrepancies.length > 0) {
        await this.alertDiscrepancies(dateStr, discrepancies);
      }

      const result: ReconciliationResult = {
        date: dateStr,
        status,
        messagesSent,
        eventsExpected,
        eventsFound,
        discrepancies,
        duration: Date.now() - startTime,
      };

      this.logger.info('Reconciliation completed', {
        date: dateStr,
        status,
        messagesSent,
        eventsFound,
        discrepancyCount: discrepancies.length,
        durationMs: result.duration,
      });

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error('Reconciliation failed', {
        date: dateStr,
        error: errorMessage,
      });

      return {
        date: dateStr,
        status: 'error',
        messagesSent: 0,
        eventsExpected: 0,
        eventsFound: 0,
        discrepancies: [],
        duration: Date.now() - startTime,
      };

    } finally {
      this.running = false;
    }
  }

  private getExpectedEvents(status: string): string[] {
    // Based on message status, determine which events should exist
    switch (status) {
      case 'queued':
        return ['queued'];
      case 'sending':
        return ['queued', 'sending'];
      case 'sent':
        return ['queued', 'sent'];
      case 'delivered':
        return ['queued', 'sent', 'delivered'];
      case 'bounced':
        return ['queued', 'sent', 'bounced'];
      case 'complained':
        return ['queued', 'sent', 'delivered', 'complained'];
      case 'failed':
        return ['queued', 'failed'];
      case 'deferred':
        return ['queued', 'deferred'];
      default:
        return ['queued'];
    }
  }

  private async storeResult(result: ReconciliationResult): Promise<void> {
    const id = generateId('rec');
    
    await this.db.query(`
      INSERT INTO reconciliation_log (
        id, date, status, messages_sent, events_expected, events_found,
        discrepancy_count, discrepancy_details, duration_ms, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      ON CONFLICT (date) DO UPDATE SET
        status = EXCLUDED.status,
        messages_sent = EXCLUDED.messages_sent,
        events_expected = EXCLUDED.events_expected,
        events_found = EXCLUDED.events_found,
        discrepancy_count = EXCLUDED.discrepancy_count,
        discrepancy_details = EXCLUDED.discrepancy_details,
        duration_ms = EXCLUDED.duration_ms,
        updated_at = NOW()
    `, [
      id,
      result.date,
      result.status,
      result.messagesSent,
      result.eventsExpected,
      result.eventsFound,
      result.discrepancies.length,
      JSON.stringify(result.discrepancies.slice(0, 100)), // Limit stored details
      result.duration,
    ]);
  }

  private async alertDiscrepancies(date: string, discrepancies: DiscrepancyDetail[]): Promise<void> {
    // Store alert
    const alertId = generateId('alt');
    
    await this.db.query(`
      INSERT INTO system_alerts (
        id, alert_type, severity, title, message, metadata, created_at
      ) VALUES ($1, 'reconciliation_discrepancy', 'warning', $2, $3, $4, NOW())
    `, [
      alertId,
      `Event Reconciliation Discrepancy - ${date}`,
      `Found ${discrepancies.length} discrepancies during daily reconciliation for ${date}`,
      JSON.stringify({
        date,
        discrepancyCount: discrepancies.length,
        sampleDiscrepancies: discrepancies.slice(0, 5),
      }),
    ]);

    // Publish to Redis for real-time alerting
    await this.redis.publish('alerts:reconciliation', JSON.stringify({
      id: alertId,
      date,
      discrepancyCount: discrepancies.length,
      timestamp: new Date().toISOString(),
    }));

    this.logger.warn('Reconciliation discrepancies found', {
      date,
      discrepancyCount: discrepancies.length,
    });
  }

  /**
   * Run a quick health check on recent data
   */
  async quickHealthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    try {
      // Check for messages without any events (older than 5 minutes)
      const orphanedResult = await this.db.query<{ count: string }>(`
        SELECT COUNT(*) as count
        FROM messages m
        WHERE m.created_at < NOW() - INTERVAL '5 minutes'
          AND m.status NOT IN ('draft', 'scheduled')
          AND NOT EXISTS (
            SELECT 1 FROM events e WHERE e.message_id = m.id
          )
      `);

      const orphanedCount = parseInt(orphanedResult.rows[0].count, 10);
      if (orphanedCount > 0) {
        issues.push(`${orphanedCount} messages without events`);
      }

      // Check for event processing lag
      const lagResult = await this.db.query<{ lag_seconds: number }>(`
        SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp))) as lag_seconds
        FROM events
        WHERE timestamp > NOW() - INTERVAL '1 hour'
      `);

      const lagSeconds = lagResult.rows[0]?.lag_seconds ?? 0;
      if (lagSeconds > 300) { // 5 minutes
        issues.push(`Event processing lag: ${Math.round(lagSeconds)}s`);
      }

      // Check for queue backlog
      const queueResult = await this.db.query<{ count: string }>(`
        SELECT COUNT(*) as count
        FROM message_queue
        WHERE status = 'pending'
          AND created_at < NOW() - INTERVAL '5 minutes'
      `);

      const queueBacklog = parseInt(queueResult.rows[0].count, 10);
      if (queueBacklog > 1000) {
        issues.push(`Queue backlog: ${queueBacklog} messages`);
      }

      return {
        healthy: issues.length === 0,
        issues,
      };

    } catch (error) {
      return {
        healthy: false,
        issues: [`Health check error: ${error instanceof Error ? error.message : 'Unknown'}`],
      };
    }
  }
}
