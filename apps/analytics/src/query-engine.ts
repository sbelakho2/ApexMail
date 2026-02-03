/**
 * DuckDB Query Engine - For fast analytical queries on cold and hot data
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { config } from './config.js';
import { readdir, mkdir } from 'fs/promises';
import { join } from 'path';
import * as duckdb from 'duckdb';

interface QueryEngineConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
}

interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

interface AggregationResult {
  dimension: string;
  count: number;
  percentage?: number;
}

interface AnalyticsQuery {
  tenantId: string;
  startDate: Date;
  endDate: Date;
  eventTypes?: string[];
  groupBy?: 'hour' | 'day' | 'week' | 'month';
  dimensions?: string[];
  limit?: number;
}

export class QueryEngine {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;
  private duckDb: duckdb.Database | null = null;
  private duckConn: duckdb.Connection | null = null;

  constructor(options: QueryEngineConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
  }

  async initialize(): Promise<void> {
    this.logger.info('Initializing query engine');
    
    // Initialize DuckDB for cold storage queries
    try {
      const dbPath = config.duckdb.dbPath;
      
      // Ensure directory exists for DuckDB file
      const dbDir = dbPath.substring(0, dbPath.lastIndexOf('/'));
      await mkdir(dbDir, { recursive: true });
      
      // Initialize DuckDB with memory limits from config
      this.duckDb = new duckdb.Database(dbPath);
      this.duckConn = this.duckDb.connect();
      
      // Configure DuckDB settings
      await this.runDuckDbQuery(`SET memory_limit='${config.duckdb.memoryLimit}'`);
      await this.runDuckDbQuery(`SET threads=${config.duckdb.threads}`);
      
      // Install and load parquet extension
      await this.runDuckDbQuery(`INSTALL parquet`);
      await this.runDuckDbQuery(`LOAD parquet`);
      
      this.logger.info('DuckDB initialized', { 
        path: dbPath,
        memoryLimit: config.duckdb.memoryLimit,
        threads: config.duckdb.threads,
      });
    } catch (error) {
      this.logger.error('Failed to initialize DuckDB, falling back to PostgreSQL only', { error });
      // Continue without DuckDB - fall back to PostgreSQL for all queries
    }
    
    this.logger.info('Query engine initialized');
  }

  private runDuckDbQuery(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.duckConn) {
        reject(new Error('DuckDB connection not initialized'));
        return;
      }
      this.duckConn.run(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  private queryDuckDb<T>(sql: string): Promise<T[]> {
    return new Promise((resolve, reject) => {
      if (!this.duckConn) {
        reject(new Error('DuckDB connection not initialized'));
        return;
      }
      this.duckConn.all(sql, (err, result) => {
        if (err) reject(err);
        else resolve(result as T[]);
      });
    });
  }

  async close(): Promise<void> {
    if (this.duckConn) {
      this.duckConn.close();
      this.duckConn = null;
    }
    if (this.duckDb) {
      this.duckDb.close();
      this.duckDb = null;
    }
    this.logger.info('Query engine closed');
  }

  /**
   * Get time series data for events
   */
  async getTimeSeries(query: AnalyticsQuery): Promise<TimeSeriesPoint[]> {
    const { tenantId, startDate, endDate, eventTypes, groupBy = 'day' } = query;

    const truncExpr = this.getTimeTruncExpression(groupBy);
    const eventFilter = eventTypes?.length 
      ? `AND event_type = ANY($4)` 
      : '';

    const result = await this.db.query<{ period: Date; count: string }>(`
      SELECT 
        ${truncExpr} as period,
        COUNT(*) as count
      FROM events
      WHERE tenant_id = $1
        AND timestamp >= $2 AND timestamp < $3
        ${eventFilter}
      GROUP BY period
      ORDER BY period
    `, eventTypes?.length 
      ? [tenantId, startDate, endDate, eventTypes]
      : [tenantId, startDate, endDate]
    );

    return result.rows.map((row: { period: Date; count: string }) => ({
      timestamp: row.period.toISOString(),
      value: parseInt(row.count, 10),
    }));
  }

  /**
   * Get aggregated metrics by dimension
   */
  async getAggregation(
    query: AnalyticsQuery,
    dimension: 'event_type' | 'recipient_domain' | 'bounce_type' | 'link_id'
  ): Promise<AggregationResult[]> {
    const { tenantId, startDate, endDate, eventTypes, limit = 20 } = query;

    let dimensionExpr: string;
    switch (dimension) {
      case 'recipient_domain':
        dimensionExpr = `SPLIT_PART(recipient, '@', 2)`;
        break;
      default:
        dimensionExpr = dimension;
    }

    const eventFilter = eventTypes?.length 
      ? `AND event_type = ANY($4)` 
      : '';

    const result = await this.db.query<{ dimension: string; count: string }>(`
      SELECT 
        ${dimensionExpr} as dimension,
        COUNT(*) as count
      FROM events
      WHERE tenant_id = $1
        AND timestamp >= $2 AND timestamp < $3
        ${eventFilter}
        AND ${dimensionExpr} IS NOT NULL
      GROUP BY dimension
      ORDER BY count DESC
      LIMIT $${eventTypes?.length ? 5 : 4}
    `, eventTypes?.length 
      ? [tenantId, startDate, endDate, eventTypes, limit]
      : [tenantId, startDate, endDate, limit]
    );

    // Calculate total for percentages
    const total = result.rows.reduce((sum: number, row: { dimension: string; count: string }) => sum + parseInt(row.count, 10), 0);

    return result.rows.map((row: { dimension: string; count: string }) => {
      const count = parseInt(row.count, 10);
      return {
        dimension: row.dimension,
        count,
        percentage: total > 0 ? (count / total) * 100 : 0,
      };
    });
  }

  /**
   * Get funnel analysis (queued -> sent -> delivered -> opened -> clicked)
   */
  async getFunnelAnalysis(query: AnalyticsQuery): Promise<{
    stages: Array<{
      stage: string;
      count: number;
      dropoff: number;
      percentage: number;
    }>;
  }> {
    const { tenantId, startDate, endDate } = query;

    const stages = ['queued', 'sent', 'delivered', 'opened', 'clicked'];
    const counts: number[] = [];

    for (const stage of stages) {
      const result = await this.db.query<{ count: string }>(`
        SELECT COUNT(DISTINCT message_id) as count
        FROM events
        WHERE tenant_id = $1
          AND timestamp >= $2 AND timestamp < $3
          AND event_type = $4
      `, [tenantId, startDate, endDate, stage]);

      counts.push(parseInt(result.rows[0]?.count ?? '0', 10));
    }

    const initial = counts[0] || 1;

    return {
      stages: stages.map((stage, i) => {
        const count = counts[i] ?? 0;
        const prevCount = i > 0 ? (counts[i - 1] ?? count) : count;
        return {
          stage,
          count,
          dropoff: i > 0 && prevCount > 0 
            ? Math.round((1 - count / prevCount) * 100) 
            : 0,
          percentage: Math.round((count / initial) * 100),
        };
      }),
    };
  }

  /**
   * Get deliverability metrics
   */
  async getDeliverabilityMetrics(query: AnalyticsQuery): Promise<{
    deliveryRate: number;
    bounceRate: number;
    complaintRate: number;
    openRate: number;
    clickRate: number;
    unsubscribeRate: number;
  }> {
    const { tenantId, startDate, endDate } = query;

    const result = await this.db.query<{
      event_type: string;
      count: string;
    }>(`
      SELECT event_type, COUNT(*) as count
      FROM events
      WHERE tenant_id = $1
        AND timestamp >= $2 AND timestamp < $3
        AND event_type IN ('sent', 'delivered', 'bounced', 'complained', 'opened', 'clicked', 'unsubscribed')
      GROUP BY event_type
    `, [tenantId, startDate, endDate]);

    const counts: Record<string, number> = {};
    for (const row of result.rows) {
      counts[row.event_type] = parseInt(row.count, 10);
    }

    const sent = counts.sent || 1;
    const delivered = counts.delivered || 1; // Avoid division by zero

    return {
      deliveryRate: Math.round((delivered / sent) * 100),
      bounceRate: Math.round(((counts.bounced || 0) / sent) * 100),
      complaintRate: Math.round(((counts.complained || 0) / sent) * 10000) / 100, // To 2 decimals
      openRate: Math.round(((counts.opened || 0) / delivered) * 100),
      clickRate: Math.round(((counts.clicked || 0) / delivered) * 100),
      unsubscribeRate: Math.round(((counts.unsubscribed || 0) / delivered) * 10000) / 100,
    };
  }

  /**
   * Get recipient engagement histogram
   */
  async getEngagementHistogram(query: AnalyticsQuery): Promise<{
    buckets: Array<{
      range: string;
      count: number;
    }>;
  }> {
    const { tenantId, startDate, endDate } = query;

    // Get engagement scores per recipient
    const result = await this.db.query<{ bucket: string; count: string }>(`
      WITH recipient_engagement AS (
        SELECT 
          recipient,
          SUM(CASE WHEN event_type = 'opened' THEN 1 ELSE 0 END) as opens,
          SUM(CASE WHEN event_type = 'clicked' THEN 1 ELSE 0 END) as clicks,
          SUM(CASE WHEN event_type = 'unsubscribed' THEN 1 ELSE 0 END) as unsubscribes,
          COUNT(*) as total_events
        FROM events
        WHERE tenant_id = $1
          AND timestamp >= $2 AND timestamp < $3
        GROUP BY recipient
      ),
      scored AS (
        SELECT 
          recipient,
          CASE 
            WHEN unsubscribes > 0 THEN 'unsubscribed'
            WHEN clicks > 2 THEN 'highly_engaged'
            WHEN opens > 2 THEN 'engaged'
            WHEN opens > 0 THEN 'somewhat_engaged'
            ELSE 'not_engaged'
          END as engagement_bucket
        FROM recipient_engagement
      )
      SELECT engagement_bucket as bucket, COUNT(*) as count
      FROM scored
      GROUP BY engagement_bucket
      ORDER BY 
        CASE engagement_bucket
          WHEN 'highly_engaged' THEN 1
          WHEN 'engaged' THEN 2
          WHEN 'somewhat_engaged' THEN 3
          WHEN 'not_engaged' THEN 4
          WHEN 'unsubscribed' THEN 5
        END
    `, [tenantId, startDate, endDate]);

    return {
      buckets: result.rows.map((row: { bucket: string; count: string }) => ({
        range: row.bucket,
        count: parseInt(row.count, 10),
      })),
    };
  }

  /**
   * Query cold storage (Parquet files) for historical data
   */
  async queryColdStorage(query: AnalyticsQuery): Promise<{
    eventCount: number;
    sampleEvents: Array<{
      id: string;
      eventType: string;
      recipient: string;
      timestamp: string;
    }>;
  }> {
    const { tenantId, startDate, endDate } = query;

    // Find relevant Parquet files
    const files = await this.findParquetFiles(tenantId, startDate, endDate);

    if (files.length === 0) {
      return { eventCount: 0, sampleEvents: [] };
    }

    // Use DuckDB to query Parquet/JSONL files for cold storage analytics
    if (!this.duckConn) {
      this.logger.warn('DuckDB not initialized, skipping cold storage query');
      return { eventCount: 0, sampleEvents: [] };
    }

    try {
      // Query all files using DuckDB's glob pattern for JSONL files
      const jsonlFiles = files.filter(f => f.endsWith('.jsonl'));
      
      if (jsonlFiles.length === 0) {
        return { eventCount: 0, sampleEvents: [] };
      }

      // Create a view over the JSONL files
      const fileList = jsonlFiles.map(f => `'${f}'`).join(', ');
      
      // Get event count
      const countResult = await this.queryDuckDb<{ cnt: number }>(
        `SELECT COUNT(*) as cnt FROM read_json_auto([${fileList}])`
      );
      const eventCount = countResult[0]?.cnt || 0;

      // Get sample events
      const sampleResult = await this.queryDuckDb<{
        id: string;
        event_type: string;
        recipient: string;
        timestamp: string;
      }>(
        `SELECT id, event_type, recipient, timestamp 
         FROM read_json_auto([${fileList}]) 
         LIMIT 10`
      );

      this.logger.info('Queried cold storage', {
        tenantId,
        fileCount: jsonlFiles.length,
        eventCount,
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
      });

      return {
        eventCount,
        sampleEvents: sampleResult.map(row => ({
          id: row.id,
          eventType: row.event_type,
          recipient: row.recipient,
          timestamp: row.timestamp,
        })),
      };
    } catch (error) {
      this.logger.error('Cold storage query failed', { error, tenantId });
      return { eventCount: 0, sampleEvents: [] };
    }
  }

  /**
   * Get real-time stats from Redis
   * 
   * Redis key structure:
   * - stats:{tenantId}:today:{eventType} -> count
   * - stats:{tenantId}:hour:{eventType} -> count
   */
  async getRealtimeStats(tenantId: string): Promise<{
    today: Record<string, number>;
    thisHour: Record<string, number>;
  }> {
    const eventTypes = ['sent', 'delivered', 'opened', 'clicked', 'bounced', 'complained'];
    
    // Get today's date key (UTC)
    const now = new Date();
    const todayKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`;
    const hourKey = `${todayKey}:${String(now.getUTCHours()).padStart(2, '0')}`;
    
    // Build Redis multi-get pipeline for efficiency
    const pipeline = this.redis.pipeline();
    
    // Get today's stats
    for (const eventType of eventTypes) {
      pipeline.get(`stats:${tenantId}:day:${todayKey}:${eventType}`);
    }
    
    // Get this hour's stats
    for (const eventType of eventTypes) {
      pipeline.get(`stats:${tenantId}:hour:${hourKey}:${eventType}`);
    }
    
    const results = await pipeline.exec();
    
    // Parse results
    const today: Record<string, number> = {};
    const thisHour: Record<string, number> = {};
    
    if (results) {
      // First half: today's stats
      for (let i = 0; i < eventTypes.length; i++) {
        const result = results[i];
        const eventType = eventTypes[i];
        if (result && eventType) {
          const [err, value] = result;
          today[eventType] = err ? 0 : parseInt(String(value ?? '0'), 10);
        }
      }
      
      // Second half: this hour's stats
      for (let i = 0; i < eventTypes.length; i++) {
        const result = results[eventTypes.length + i];
        const eventType = eventTypes[i];
        if (result && eventType) {
          const [err, value] = result;
          thisHour[eventType] = err ? 0 : parseInt(String(value ?? '0'), 10);
        }
      }
    }

    return { today, thisHour };
  }

  private getTimeTruncExpression(groupBy: 'hour' | 'day' | 'week' | 'month'): string {
    switch (groupBy) {
      case 'hour':
        return `DATE_TRUNC('hour', timestamp)`;
      case 'day':
        return `DATE_TRUNC('day', timestamp)`;
      case 'week':
        return `DATE_TRUNC('week', timestamp)`;
      case 'month':
        return `DATE_TRUNC('month', timestamp)`;
    }
  }

  private async findParquetFiles(
    tenantId: string,
    startDate: Date,
    endDate: Date
  ): Promise<string[]> {
    const files: string[] = [];
    const tenantPath = join(config.storage.basePath, tenantId);

    try {
      const yearDirs = await readdir(tenantPath);

      for (const yearDir of yearDirs) {
        const year = parseInt(yearDir, 10);
        if (isNaN(year)) continue;

        // Check if year is in range
        if (year < startDate.getFullYear() || year > endDate.getFullYear()) {
          continue;
        }

        const yearPath = join(tenantPath, yearDir);
        const monthDirs = await readdir(yearPath);

        for (const monthDir of monthDirs) {
          const month = parseInt(monthDir, 10);
          if (isNaN(month)) continue;

          // Check if month is in range
          const monthStart = new Date(year, month - 1, 1);
          const monthEnd = new Date(year, month, 0);

          if (monthEnd < startDate || monthStart > endDate) {
            continue;
          }

          const monthPath = join(yearPath, monthDir);
          const monthFiles = await readdir(monthPath);

          for (const file of monthFiles) {
            if (file.endsWith('.jsonl') || file.endsWith('.parquet')) {
              files.push(join(monthPath, file));
            }
          }
        }
      }

    } catch {
      // Directory doesn't exist or is inaccessible
    }

    return files;
  }
}
