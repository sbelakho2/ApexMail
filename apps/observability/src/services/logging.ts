/**
 * Structured Logging Service
 * 
 * Centralized logging with:
 * - Structured JSON logs
 * - Log levels
 * - Context propagation
 * - Log aggregation
 * - Sensitive data masking
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { config } from '../config.js';

export enum LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  FATAL = 5,
}

export interface LogEntry {
  id?: string;
  timestamp: Date;
  level: LogLevel;
  levelName: string;
  message: string;
  service: string;
  traceId?: string;
  spanId?: string;
  context?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  duration?: number;
  metadata?: Record<string, unknown>;
}

export interface LogQuery {
  service?: string;
  level?: LogLevel;
  minLevel?: LogLevel;
  traceId?: string;
  startTime?: Date;
  endTime?: Date;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface LogStats {
  totalLogs: number;
  byLevel: Record<string, number>;
  byService: Record<string, number>;
  errorRate: number;
  logsPerMinute: number;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class LoggingService {
  private db: Pool;
  private redis: Redis;
  private buffer: LogEntry[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private currentLevel: LogLevel;
  private serviceName: string;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.currentLevel = this.parseLogLevel(config.logging.level);
    this.serviceName = config.tracing.serviceName;
  }

  /**
   * Initialize logging service
   */
  async initialize(): Promise<void> {
    // Start flush interval
    this.flushInterval = setInterval(async () => {
      await this.flushBuffer();
    }, 5000);

    console.log('[Logging] Service initialized');
  }

  /**
   * Log a trace message
   */
  trace(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.TRACE, message, context);
  }

  /**
   * Log a debug message
   */
  debug(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  /**
   * Log an info message
   */
  info(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.INFO, message, context);
  }

  /**
   * Log a warning message
   */
  warn(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.WARN, message, context);
  }

  /**
   * Log an error message
   */
  error(message: string, error?: Error, context?: Record<string, unknown>): void {
    this.log(LogLevel.ERROR, message, context, error);
  }

  /**
   * Log a fatal message
   */
  fatal(message: string, error?: Error, context?: Record<string, unknown>): void {
    this.log(LogLevel.FATAL, message, context, error);
  }

  /**
   * Create a child logger with additional context
   */
  child(context: Record<string, unknown>): LoggingService {
    const childLogger = new LoggingService(this.db, this.redis);
    childLogger.currentLevel = this.currentLevel;
    childLogger.serviceName = this.serviceName;
    // Note: In production, would properly inherit context
    return childLogger;
  }

  /**
   * Create a logger with trace context
   */
  withTrace(traceId: string, spanId?: string): {
    trace: (message: string, context?: Record<string, unknown>) => void;
    debug: (message: string, context?: Record<string, unknown>) => void;
    info: (message: string, context?: Record<string, unknown>) => void;
    warn: (message: string, context?: Record<string, unknown>) => void;
    error: (message: string, error?: Error, context?: Record<string, unknown>) => void;
    fatal: (message: string, error?: Error, context?: Record<string, unknown>) => void;
  } {
    return {
      trace: (message, context) => this.log(LogLevel.TRACE, message, { ...context, traceId, spanId }),
      debug: (message, context) => this.log(LogLevel.DEBUG, message, { ...context, traceId, spanId }),
      info: (message, context) => this.log(LogLevel.INFO, message, { ...context, traceId, spanId }),
      warn: (message, context) => this.log(LogLevel.WARN, message, { ...context, traceId, spanId }),
      error: (message, error, context) => this.log(LogLevel.ERROR, message, { ...context, traceId, spanId }, error),
      fatal: (message, error, context) => this.log(LogLevel.FATAL, message, { ...context, traceId, spanId }, error),
    };
  }

  /**
   * Query logs
   */
  async queryLogs(query: LogQuery): Promise<Result<{ logs: LogEntry[]; total: number }>> {
    try {
      let sql = 'SELECT * FROM obs_logs WHERE 1=1';
      const params: unknown[] = [];
      let paramIndex = 1;

      if (query.service) {
        sql += ` AND service = $${paramIndex}`;
        params.push(query.service);
        paramIndex++;
      }

      if (query.level !== undefined) {
        sql += ` AND level = $${paramIndex}`;
        params.push(query.level);
        paramIndex++;
      }

      if (query.minLevel !== undefined) {
        sql += ` AND level >= $${paramIndex}`;
        params.push(query.minLevel);
        paramIndex++;
      }

      if (query.traceId) {
        sql += ` AND trace_id = $${paramIndex}`;
        params.push(query.traceId);
        paramIndex++;
      }

      if (query.startTime) {
        sql += ` AND timestamp >= $${paramIndex}`;
        params.push(query.startTime);
        paramIndex++;
      }

      if (query.endTime) {
        sql += ` AND timestamp <= $${paramIndex}`;
        params.push(query.endTime);
        paramIndex++;
      }

      if (query.search) {
        sql += ` AND (message ILIKE $${paramIndex} OR context::text ILIKE $${paramIndex})`;
        params.push(`%${query.search}%`);
        paramIndex++;
      }

      // Count total
      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM (${sql}) subq`,
        params
      );

      // Add ordering and pagination
      sql += ' ORDER BY timestamp DESC';

      if (query.limit) {
        sql += ` LIMIT $${paramIndex}`;
        params.push(query.limit);
        paramIndex++;
      }

      if (query.offset) {
        sql += ` OFFSET $${paramIndex}`;
        params.push(query.offset);
      }

      const result = await this.db.query(sql, params);

      const logs: LogEntry[] = result.rows.map(row => ({
        id: row.id,
        timestamp: new Date(row.timestamp),
        level: row.level,
        levelName: this.levelToName(row.level),
        message: row.message,
        service: row.service,
        traceId: row.trace_id,
        spanId: row.span_id,
        context: row.context,
        error: row.error_info,
        duration: row.duration,
        metadata: row.metadata,
      }));

      return {
        ok: true,
        value: {
          logs,
          total: parseInt(countResult.rows[0].total),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get logs for a specific trace
   */
  async getLogsByTrace(traceId: string): Promise<Result<LogEntry[]>> {
    const result = await this.queryLogs({ traceId, limit: 1000 });
    if (!result.ok) {
      return result;
    }
    return { ok: true, value: result.value.logs };
  }

  /**
   * Get log statistics
   */
  async getLogStats(options: {
    startTime: Date;
    endTime: Date;
    service?: string;
  }): Promise<Result<LogStats>> {
    try {
      let serviceCondition = '';
      const params: unknown[] = [options.startTime, options.endTime];
      
      if (options.service) {
        serviceCondition = ' AND service = $3';
        params.push(options.service);
      }

      // Total and by level
      const levelResult = await this.db.query(`
        SELECT level, COUNT(*) as count
        FROM obs_logs
        WHERE timestamp >= $1 AND timestamp <= $2 ${serviceCondition}
        GROUP BY level
      `, params);

      // By service
      const serviceResult = await this.db.query(`
        SELECT service, COUNT(*) as count
        FROM obs_logs
        WHERE timestamp >= $1 AND timestamp <= $2
        GROUP BY service
      `, [options.startTime, options.endTime]);

      // Calculate stats
      const byLevel: Record<string, number> = {};
      let totalLogs = 0;
      let errorCount = 0;

      for (const row of levelResult.rows) {
        const levelName = this.levelToName(row.level);
        byLevel[levelName] = parseInt(row.count);
        totalLogs += parseInt(row.count);
        if (row.level >= LogLevel.ERROR) {
          errorCount += parseInt(row.count);
        }
      }

      const byService: Record<string, number> = {};
      for (const row of serviceResult.rows) {
        byService[row.service] = parseInt(row.count);
      }

      const durationMinutes = (options.endTime.getTime() - options.startTime.getTime()) / 60000;

      return {
        ok: true,
        value: {
          totalLogs,
          byLevel,
          byService,
          errorRate: totalLogs > 0 ? errorCount / totalLogs : 0,
          logsPerMinute: durationMinutes > 0 ? totalLogs / durationMinutes : 0,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Stream logs in real-time
   */
  async streamLogs(
    callback: (log: LogEntry) => void,
    filter?: {
      service?: string;
      minLevel?: LogLevel;
    }
  ): Promise<{ unsubscribe: () => void }> {
    const subscriber = this.redis.duplicate();
    
    await subscriber.subscribe('logs:stream');
    
    subscriber.on('message', (_channel, message) => {
      try {
        const log = JSON.parse(message) as LogEntry;
        
        // Apply filters
        if (filter?.service && log.service !== filter.service) {
          return;
        }
        if (filter?.minLevel !== undefined && log.level < filter.minLevel) {
          return;
        }
        
        callback(log);
      } catch (error) {
        console.error('[Logging] Failed to parse streamed log:', error);
      }
    });

    return {
      unsubscribe: async () => {
        await subscriber.unsubscribe('logs:stream');
        await subscriber.quit();
      },
    };
  }

  /**
   * Delete old logs
   */
  async deleteOldLogs(olderThanDays: number = config.logRetentionDays): Promise<Result<number>> {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - olderThanDays);

      const result = await this.db.query(
        'DELETE FROM obs_logs WHERE timestamp < $1',
        [cutoff]
      );

      console.log(`[Logging] Deleted ${result.rowCount} old log entries`);

      return { ok: true, value: result.rowCount || 0 };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // Private methods

  private log(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>,
    error?: Error
  ): void {
    if (level < this.currentLevel) {
      return;
    }

    // Mask sensitive data
    const maskedContext = context ? this.maskSensitiveData(context) : undefined;

    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      levelName: this.levelToName(level),
      message: this.truncateMessage(message),
      service: this.serviceName,
      traceId: context?.traceId as string | undefined,
      spanId: context?.spanId as string | undefined,
      context: maskedContext,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
      } : undefined,
    };

    // Output to console
    this.outputToConsole(entry);

    // Buffer for database persistence
    this.buffer.push(entry);

    // Publish to Redis for real-time streaming
    this.publishLog(entry);
  }

  private outputToConsole(entry: LogEntry): void {
    if (config.logging.format === 'json') {
      console.log(JSON.stringify(entry));
    } else {
      const timestamp = entry.timestamp.toISOString();
      const level = entry.levelName.padEnd(5);
      const trace = entry.traceId ? `[${entry.traceId.substring(0, 8)}]` : '';
      const context = entry.context ? JSON.stringify(entry.context) : '';
      
      let message = `${timestamp} ${level} ${trace} ${entry.message}`;
      if (context) {
        message += ` ${context}`;
      }
      if (entry.error) {
        message += `\n  Error: ${entry.error.name}: ${entry.error.message}`;
        if (entry.error.stack) {
          message += `\n  ${entry.error.stack}`;
        }
      }

      console.log(message);
    }
  }

  private async publishLog(entry: LogEntry): Promise<void> {
    try {
      await this.redis.publish('logs:stream', JSON.stringify(entry));
    } catch {
      // Ignore publish errors
    }
  }

  private async flushBuffer(): Promise<void> {
    if (this.buffer.length === 0) {
      return;
    }

    const logsToFlush = [...this.buffer];
    this.buffer = [];

    try {
      for (const log of logsToFlush) {
        await this.db.query(`
          INSERT INTO obs_logs (
            timestamp, level, level_name, message, service,
            trace_id, span_id, context, error_info, duration, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [
          log.timestamp,
          log.level,
          log.levelName,
          log.message,
          log.service,
          log.traceId,
          log.spanId,
          log.context ? JSON.stringify(log.context) : null,
          log.error ? JSON.stringify(log.error) : null,
          log.duration,
          log.metadata ? JSON.stringify(log.metadata) : null,
        ]);
      }
    } catch (error) {
      console.error('[Logging] Failed to flush log buffer:', error);
      // Re-add failed logs to buffer
      this.buffer.push(...logsToFlush);
    }
  }

  private maskSensitiveData(data: Record<string, unknown>): Record<string, unknown> {
    const masked: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(data)) {
      if (config.logging.sensitiveFields.some(field => 
        key.toLowerCase().includes(field.toLowerCase())
      )) {
        masked[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        masked[key] = this.maskSensitiveData(value as Record<string, unknown>);
      } else {
        masked[key] = value;
      }
    }
    
    return masked;
  }

  private truncateMessage(message: string): string {
    if (message.length > config.logging.maxMessageLength) {
      return message.substring(0, config.logging.maxMessageLength) + '... [truncated]';
    }
    return message;
  }

  private parseLogLevel(level: string): LogLevel {
    const levelMap: Record<string, LogLevel> = {
      trace: LogLevel.TRACE,
      debug: LogLevel.DEBUG,
      info: LogLevel.INFO,
      warn: LogLevel.WARN,
      error: LogLevel.ERROR,
      fatal: LogLevel.FATAL,
    };
    return levelMap[level.toLowerCase()] ?? LogLevel.INFO;
  }

  private levelToName(level: LogLevel): string {
    const names: Record<LogLevel, string> = {
      [LogLevel.TRACE]: 'TRACE',
      [LogLevel.DEBUG]: 'DEBUG',
      [LogLevel.INFO]: 'INFO',
      [LogLevel.WARN]: 'WARN',
      [LogLevel.ERROR]: 'ERROR',
      [LogLevel.FATAL]: 'FATAL',
    };
    return names[level] ?? 'INFO';
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    await this.flushBuffer();
    console.log('[Logging] Service shut down');
  }
}
