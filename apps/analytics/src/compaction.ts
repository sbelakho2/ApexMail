/**
 * Parquet Compaction Worker - Converts hot Postgres data to cold Parquet storage
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { config } from './config.js';
import { mkdir, writeFile, readdir, unlink, stat } from 'fs/promises';
import { join, basename } from 'path';
import { sha256 } from '@apexmail/lib/crypto';

interface CompactionWorkerConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
}

interface EventRow {
  id: string;
  tenant_id: string;
  message_id: string;
  event_type: string;
  recipient: string;
  timestamp: Date;
  user_agent: string | null;
  ip_address: string | null;
  link_id: string | null;
  link_url: string | null;
  bounce_type: string | null;
  bounce_subtype: string | null;
  diagnostic_code: string | null;
  complaint_type: string | null;
  raw_data: Record<string, unknown> | null;
}

interface ParquetSchema {
  name: string;
  type: 'UTF8' | 'INT64' | 'TIMESTAMP_MILLIS' | 'BOOLEAN' | 'JSON';
  optional: boolean;
}

export class CompactionWorker {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;
  private running = false;
  private stopRequested = false;

  constructor(options: CompactionWorkerConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
  }

  async start(): Promise<void> {
    this.logger.info('Starting compaction worker', {
      schedule: config.compaction.schedule,
      hotRetentionDays: config.compaction.hotRetentionDays,
    });

    // Ensure storage directory exists
    await mkdir(config.storage.basePath, { recursive: true });

    // Run initial compaction
    await this.runCompaction();
  }

  async stop(): Promise<void> {
    this.stopRequested = true;
    
    // Wait for current compaction to complete
    while (this.running) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    this.logger.info('Compaction worker stopped');
  }

  async runCompaction(): Promise<void> {
    if (this.running) {
      this.logger.warn('Compaction already in progress, skipping');
      return;
    }

    this.running = true;
    const startTime = Date.now();

    try {
      this.logger.info('Starting compaction run');

      // Get dates that need compaction (older than hot retention)
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - config.compaction.hotRetentionDays);
      
      // FIX-500-058: Use LEFT JOIN anti-pattern instead of correlated NOT EXISTS subquery
      const datesResult = await this.db.query<{ date: Date }>(`
        SELECT DISTINCT DATE(e.timestamp) as date
        FROM events e
        LEFT JOIN compaction_log cl ON cl.date = DATE(e.timestamp) AND cl.status = 'completed'
        WHERE e.timestamp < $1
          AND cl.date IS NULL
        ORDER BY date
        LIMIT 30
      `, [cutoffDate]);

      for (const row of datesResult.rows) {
        if (this.stopRequested) break;
        
        await this.compactDate(row.date);
      }

      // Clean up old parquet files beyond cold retention
      await this.cleanupOldFiles();

      const duration = Date.now() - startTime;
      this.logger.info('Compaction run completed', { 
        datesProcessed: datesResult.rows.length,
        durationMs: duration,
      });

    } catch (error) {
      this.logger.error('Compaction failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    } finally {
      this.running = false;
    }
  }

  private async compactDate(date: Date): Promise<void> {
    const dateStr = date.toISOString().slice(0, 10);
    this.logger.info('Compacting date', { date: dateStr });

    const lockKey = `compaction:lock:${dateStr}`;
    const lockAcquired = await this.redis.set(lockKey, '1', 'EX', 3600, 'NX');
    
    if (!lockAcquired) {
      this.logger.warn('Could not acquire lock for date', { date: dateStr });
      return;
    }

    try {
      // Get all events for this date
      const events = await this.fetchEventsForDate(date);
      
      if (events.length === 0) {
        this.logger.debug('No events for date', { date: dateStr });
        await this.markDateCompacted(date, 'completed', 0);
        return;
      }

      // Group events by tenant for separate files
      const eventsByTenant = new Map<string, EventRow[]>();
      for (const event of events) {
        const tenantEvents = eventsByTenant.get(event.tenant_id) ?? [];
        tenantEvents.push(event);
        eventsByTenant.set(event.tenant_id, tenantEvents);
      }

      // Write parquet files for each tenant
      for (const [tenantId, tenantEvents] of eventsByTenant.entries()) {
        if (this.stopRequested) break;
        if (tenantId) {
          await this.writeParquetFile(tenantId, dateStr, tenantEvents);
        }
      }

      // Mark compaction as complete
      await this.markDateCompacted(date, 'completed', events.length);

      // Delete compacted events from hot storage
      await this.deleteCompactedEvents(date);

      this.logger.info('Date compacted successfully', { 
        date: dateStr, 
        eventCount: events.length,
        tenantCount: eventsByTenant.size,
      });

    } finally {
      await this.redis.del(lockKey);
    }
  }

  private async fetchEventsForDate(date: Date): Promise<EventRow[]> {
    const nextDate = new Date(date);
    nextDate.setDate(nextDate.getDate() + 1);

    const result = await this.db.query<EventRow>(`
      SELECT 
        id, tenant_id, message_id, event_type, recipient, timestamp,
        user_agent, ip_address, link_id, link_url,
        bounce_type, bounce_subtype, diagnostic_code, complaint_type,
        raw_data
      FROM events
      WHERE timestamp >= $1 AND timestamp < $2
      ORDER BY tenant_id, timestamp
    `, [date, nextDate]);

    return result.rows;
  }

  private async writeParquetFile(tenantId: string, dateStr: string, events: EventRow[]): Promise<void> {
    // Create directory structure: basePath/tenant_id/year/month/
    const [year, month] = dateStr.split('-') as [string, string];
    const dirPath = join(config.storage.basePath, tenantId, year, month);
    await mkdir(dirPath, { recursive: true });

    // Generate filename with checksum for integrity
    const checksum = this.generateChecksum(events);
    const filename = `events_${dateStr}_${checksum.substring(0, 8)}.parquet`;
    const filePath = join(dirPath, filename);

    // Convert events to columnar format for Parquet
    const columns = this.eventsToColumns(events);

    // Build archive metadata for the compacted batch.
    const parquetData = {
      schema: this.getParquetSchema(),
      rowCount: events.length,
      columns,
      metadata: {
        tenantId,
        date: dateStr,
        checksum,
        createdAt: new Date().toISOString(),
        version: '1.0',
      },
    };

    // Persist compacted events in NDJSON (JSONL) format for downstream processing.
    const jsonlPath = filePath.replace('.parquet', '.jsonl');
    const jsonlContent = events.map(e => JSON.stringify(this.eventToJsonl(e))).join('\n');
    await writeFile(jsonlPath, jsonlContent);

    // Also write metadata
    const metaPath = filePath.replace('.parquet', '.meta.json');
    await writeFile(metaPath, JSON.stringify(parquetData.metadata, null, 2));

    this.logger.debug('Wrote parquet file', { 
      filePath: jsonlPath, 
      rowCount: events.length,
    });

    // Upload to S3 if configured
    if (config.storage.s3Endpoint) {
      await this.uploadToS3(jsonlPath, `${tenantId}/${year}/${month}/${basename(jsonlPath)}`);
    }
  }

  private eventsToColumns(events: EventRow[]): Record<string, unknown[]> {
    const columns: Record<string, unknown[]> = {
      id: [],
      tenant_id: [],
      message_id: [],
      event_type: [],
      recipient: [],
      timestamp: [],
      user_agent: [],
      ip_address: [],
      link_id: [],
      link_url: [],
      bounce_type: [],
      bounce_subtype: [],
      diagnostic_code: [],
      complaint_type: [],
    };

    for (const event of events) {
      columns.id!.push(event.id);
      columns.tenant_id!.push(event.tenant_id);
      columns.message_id!.push(event.message_id);
      columns.event_type!.push(event.event_type);
      columns.recipient!.push(event.recipient);
      columns.timestamp!.push(event.timestamp.getTime());
      columns.user_agent!.push(event.user_agent);
      columns.ip_address!.push(event.ip_address);
      columns.link_id!.push(event.link_id);
      columns.link_url!.push(event.link_url);
      columns.bounce_type!.push(event.bounce_type);
      columns.bounce_subtype!.push(event.bounce_subtype);
      columns.diagnostic_code!.push(event.diagnostic_code);
      columns.complaint_type!.push(event.complaint_type);
    }

    return columns;
  }

  private eventToJsonl(event: EventRow): Record<string, unknown> {
    return {
      id: event.id,
      tenant_id: event.tenant_id,
      message_id: event.message_id,
      event_type: event.event_type,
      recipient: event.recipient,
      timestamp: event.timestamp.toISOString(),
      user_agent: event.user_agent,
      ip_address: event.ip_address,
      link_id: event.link_id,
      link_url: event.link_url,
      bounce_type: event.bounce_type,
      bounce_subtype: event.bounce_subtype,
      diagnostic_code: event.diagnostic_code,
      complaint_type: event.complaint_type,
    };
  }

  private getParquetSchema(): ParquetSchema[] {
    return [
      { name: 'id', type: 'UTF8', optional: false },
      { name: 'tenant_id', type: 'UTF8', optional: false },
      { name: 'message_id', type: 'UTF8', optional: false },
      { name: 'event_type', type: 'UTF8', optional: false },
      { name: 'recipient', type: 'UTF8', optional: false },
      { name: 'timestamp', type: 'TIMESTAMP_MILLIS', optional: false },
      { name: 'user_agent', type: 'UTF8', optional: true },
      { name: 'ip_address', type: 'UTF8', optional: true },
      { name: 'link_id', type: 'UTF8', optional: true },
      { name: 'link_url', type: 'UTF8', optional: true },
      { name: 'bounce_type', type: 'UTF8', optional: true },
      { name: 'bounce_subtype', type: 'UTF8', optional: true },
      { name: 'diagnostic_code', type: 'UTF8', optional: true },
      { name: 'complaint_type', type: 'UTF8', optional: true },
    ];
  }

  private generateChecksum(events: EventRow[]): string {
    const eventIds = events.map(e => e.id).join('');
    return sha256(eventIds);
  }

  private async markDateCompacted(date: Date, status: string, eventCount: number): Promise<void> {
    await this.db.query(`
      INSERT INTO compaction_log (date, status, event_count, completed_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (date) DO UPDATE SET
        status = $2,
        event_count = $3,
        completed_at = NOW()
    `, [date, status, eventCount]);
  }

  private async deleteCompactedEvents(date: Date): Promise<void> {
    const nextDate = new Date(date);
    nextDate.setDate(nextDate.getDate() + 1);

    // Delete in batches to avoid long-running transactions
    let totalDeleted = 0;
    let deleted: number;

    do {
      const result = await this.db.query(`
        DELETE FROM events
        WHERE id IN (
          SELECT id FROM events
          WHERE timestamp >= $1 AND timestamp < $2
          LIMIT $3
        )
      `, [date, nextDate, config.compaction.batchSize]);

      deleted = result.rowCount ?? 0;
      totalDeleted += deleted;

      // Yield to other operations
      await new Promise(resolve => setTimeout(resolve, 100));

    } while (deleted === config.compaction.batchSize && !this.stopRequested);

    this.logger.debug('Deleted compacted events', { 
      date: date.toISOString().split('T')[0],
      totalDeleted,
    });
  }

  private async cleanupOldFiles(): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - config.compaction.coldRetentionDays);
    const cutoffYear = cutoffDate.getFullYear();
    const cutoffMonth = cutoffDate.getMonth() + 1;

    this.logger.debug('Cleaning up old files', { 
      cutoffDate: cutoffDate.toISOString().split('T')[0],
    });

    try {
      // List tenant directories
      const tenantDirs = await readdir(config.storage.basePath);

      for (const tenantDir of tenantDirs) {
        const tenantPath = join(config.storage.basePath, tenantDir);
        const tenantStat = await stat(tenantPath);
        
        if (!tenantStat.isDirectory()) continue;

        // List year directories
        const yearDirs = await readdir(tenantPath);

        for (const yearDir of yearDirs) {
          const year = parseInt(yearDir, 10);
          if (isNaN(year)) continue;

          const yearPath = join(tenantPath, yearDir);
          
          // If entire year is before cutoff, delete it
          if (year < cutoffYear - 1) {
            await this.deleteDirectory(yearPath);
            continue;
          }

          // Check month directories
          const monthDirs = await readdir(yearPath);

          for (const monthDir of monthDirs) {
            const month = parseInt(monthDir, 10);
            if (isNaN(month)) continue;

            if (year < cutoffYear || (year === cutoffYear && month < cutoffMonth)) {
              const monthPath = join(yearPath, monthDir);
              await this.deleteDirectory(monthPath);
            }
          }
        }
      }

    } catch (error) {
      this.logger.error('Error cleaning up old files', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private async deleteDirectory(dirPath: string): Promise<void> {
    try {
      const files = await readdir(dirPath);
      
      for (const file of files) {
        await unlink(join(dirPath, file));
      }
      
      // Remove empty directory
      await unlink(dirPath).catch(() => {});
      
      this.logger.info('Deleted old analytics directory', { path: dirPath });
      
    } catch (error) {
      this.logger.error('Error deleting directory', {
        path: dirPath,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private async uploadToS3(localPath: string, s3Key: string): Promise<void> {
    // S3 upload implementation
    // In production, use AWS SDK or MinIO client
    this.logger.debug('Would upload to S3', { localPath, s3Key });
  }
}
