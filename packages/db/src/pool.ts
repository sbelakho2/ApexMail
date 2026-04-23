/**
 * Database Connection Pool
 * 
 * Configured for PgBouncer in transaction mode:
 * - API service: 20 connections
 * - Worker service: 30 connections
 * - MTA service: 10 connections
 * 
 * Total: 60 connections to pool, pool handles up to 100 to Postgres
 */

import { Pool, type PoolConfig, type PoolClient, type QueryResult } from 'pg';
import { getLogger, type Logger } from '@apexmail/lib/logger';
import { Result } from '@apexmail/lib';

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  maxConnections: number;
  idleTimeoutMs: number;
  connectionTimeoutMs: number;
  statementTimeoutMs: number;
  ssl?: boolean | { rejectUnauthorized: boolean };
}

export interface QueryOptions {
  timeout?: number;
  name?: string;
}

const DEFAULT_CONFIG: Pick<DatabaseConfig, 'host' | 'port' | 'database' | 'maxConnections' | 'idleTimeoutMs' | 'connectionTimeoutMs' | 'statementTimeoutMs'> = {
  host: 'localhost',
  port: 5432,
  database: 'apexmail',
  maxConnections: 20,
  idleTimeoutMs: 10 * 60 * 1000, // 10 minutes
  connectionTimeoutMs: 5000, // 5 seconds
  statementTimeoutMs: 30000, // 30 seconds
};

/**
 * Safely parse an integer from string with validation
 * Throws an error if the value is invalid
 */
function parseIntSafe(value: string | undefined, defaultValue: number, name: string): number {
  if (value === undefined || value === '') {
    return defaultValue;
  }
  
  const parsed = parseInt(value, 10);
  
  if (isNaN(parsed)) {
    throw new Error(`Invalid ${name}: "${value}" is not a valid integer`);
  }
  
  if (parsed < 0) {
    throw new Error(`Invalid ${name}: "${value}" must be a non-negative integer`);
  }
  
  return parsed;
}

/**
 * Validate port number is within valid range
 */
function validatePort(port: number, name: string): number {
  if (port < 1 || port > 65535) {
    throw new Error(`Invalid ${name}: port must be between 1 and 65535, got ${port}`);
  }
  return port;
}

class DatabasePool {
  private pool: Pool | null = null;
  private readonly config: DatabaseConfig;
  private readonly logger: Logger;
  private isShuttingDown = false;
  private healthCheckTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * G-210: Connection leak detection.
   * Tracks when each client was checked out. A periodic scan warns about
   * connections held longer than LEAK_THRESHOLD_MS, helping identify code
   * that forgets to call client.release().
   */
  private readonly checkedOutClients = new Map<PoolClient, { acquiredAt: number; stack: string }>();
  private leakDetectionTimer: ReturnType<typeof setInterval> | null = null;
  private static readonly LEAK_THRESHOLD_MS = 30_000; // 30 seconds
  private static readonly LEAK_CHECK_INTERVAL_MS = 15_000; // check every 15 seconds

  constructor(config: Partial<DatabaseConfig> = {}) {
    // Parse and validate port
    const portFromEnv = process.env['DB_PORT'];
    const portValue = config.port ?? parseIntSafe(portFromEnv, DEFAULT_CONFIG.port, 'DB_PORT');
    const validatedPort = validatePort(portValue, 'DB_PORT');

    // Parse and validate max connections
    const maxConnFromEnv = process.env['DB_MAX_CONNECTIONS'];
    const maxConnValue = config.maxConnections ?? parseIntSafe(maxConnFromEnv, DEFAULT_CONFIG.maxConnections, 'DB_MAX_CONNECTIONS');
    
    if (maxConnValue < 1 || maxConnValue > 1000) {
      throw new Error(`Invalid DB_MAX_CONNECTIONS: must be between 1 and 1000, got ${maxConnValue}`);
    }

    this.config = {
      host: config.host ?? process.env['DB_HOST'] ?? DEFAULT_CONFIG.host,
      port: validatedPort,
      database: config.database ?? process.env['DB_NAME'] ?? DEFAULT_CONFIG.database,
      user: config.user ?? process.env['DB_USER'] ?? 'postgres',
      password: config.password ?? process.env['DB_PASSWORD'] ?? (() => { throw new Error('DB_PASSWORD must be configured — refusing to connect with an empty password'); })(),
      maxConnections: maxConnValue,
      idleTimeoutMs: config.idleTimeoutMs ?? DEFAULT_CONFIG.idleTimeoutMs,
      connectionTimeoutMs: config.connectionTimeoutMs ?? DEFAULT_CONFIG.connectionTimeoutMs,
      statementTimeoutMs: config.statementTimeoutMs ?? DEFAULT_CONFIG.statementTimeoutMs,
      ssl: config.ssl ?? (process.env['DB_SSL'] === 'true' ? { rejectUnauthorized: process.env['DB_SSL_REJECT_UNAUTHORIZED'] !== 'false' } : undefined),
    };
    
    this.logger = getLogger().child({ component: 'db-pool' });
  }

  private getPoolConfig(): PoolConfig {
    // Set statement timeout via connection options so it's active
    // from the very first query, not after connection is established
    const timeoutMs = Math.floor(this.config.statementTimeoutMs);
    
    return {
      host: this.config.host,
      port: this.config.port,
      database: this.config.database,
      user: this.config.user,
      password: this.config.password,
      max: this.config.maxConnections,
      idleTimeoutMillis: this.config.idleTimeoutMs,
      connectionTimeoutMillis: this.config.connectionTimeoutMs,
      ssl: this.config.ssl,
      // Set application name for pg_stat_activity
      application_name: process.env['SERVICE_NAME'] ?? 'apexmail',
      // statement_timeout via options parameter is applied during connection
      // This ensures timeout is in effect before any user queries run
      options: `-c statement_timeout=${timeoutMs}`,
    };
  }

  async connect(): Promise<void> {
    if (this.pool) {
      return;
    }

    this.pool = new Pool(this.getPoolConfig());

    // Set up event handlers
    this.pool.on('connect', (_client) => {
      // statement_timeout is now set via options parameter in getPoolConfig()
      // This commented out code is kept for reference but no longer needed
      if (process.env['DB_POOL_DEBUG'] === 'true') {
        this.logger.debug('New database connection established');
      }
    });

    this.pool.on('error', (err) => {
      this.logger.error('Database pool error', { error: err.message });
    });

    // G-210: clean up leak tracking when client is removed from the pool
    this.pool.on('remove', (client) => {
      this.checkedOutClients.delete(client);
      if (process.env['DB_POOL_DEBUG'] === 'true') {
        this.logger.debug('Database connection removed from pool');
      }
    });

    // Test connection
    try {
      const client = await this.pool.connect();
      await client.query('SELECT 1');
      client.release();
      this.logger.info('Database connected', {
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
        maxConnections: this.config.maxConnections,
      });
    } catch (error) {
      this.logger.error('Failed to connect to database', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    // C-075: Start periodic health check to verify pool connectivity
    // and keep idle connections alive through PgBouncer / firewalls.
    this.startHealthCheck();

    // G-210: Start connection leak detection
    this.startLeakDetection();
  }

  /**
   * C-075: Periodic health check — runs SELECT 1 every 30 s to detect
   * stale connections early and keep the pool warm.
   */
  private startHealthCheck(): void {
    if (this.healthCheckTimer) return;

    const HEALTH_CHECK_INTERVAL_MS = 30_000; // 30 seconds

    this.healthCheckTimer = setInterval(async () => {
      if (!this.pool || this.isShuttingDown) return;

      try {
        const { waitingCount, idleCount } = this.getStats();
        if (waitingCount > 0 && idleCount === 0) {
          this.logger.debug('Skipping pool health check due to load', {
            waitingCount,
            idleCount,
          });
          return;
        }
        const start = Date.now();
        await this.pool.query('SELECT 1');
        const duration = Date.now() - start;

        this.logger.debug('Pool health check passed', {
          durationMs: duration,
          ...this.getStats(),
        });
      } catch (error) {
        this.logger.error('Pool health check failed', {
          error: error instanceof Error ? error.message : String(error),
          ...this.getStats(),
        });
      }
    }, HEALTH_CHECK_INTERVAL_MS);

    // Allow process to exit even if timer is still active
    this.healthCheckTimer.unref();
  }

  /**
   * G-210: Periodically scan for connections held longer than LEAK_THRESHOLD_MS.
   */
  private startLeakDetection(): void {
    if (this.leakDetectionTimer) return;

    this.leakDetectionTimer = setInterval(() => {
      if (this.isShuttingDown) return;

      const now = Date.now();
      for (const [_client, info] of this.checkedOutClients) {
        const heldMs = now - info.acquiredAt;
        if (heldMs > DatabasePool.LEAK_THRESHOLD_MS) {
          this.logger.warn('Possible connection leak detected', {
            heldMs,
            acquiredAt: new Date(info.acquiredAt).toISOString(),
            stack: info.stack,
            ...this.getStats(),
          });
        }
      }
    }, DatabasePool.LEAK_CHECK_INTERVAL_MS);

    this.leakDetectionTimer.unref();
  }

  async disconnect(): Promise<void> {
    if (!this.pool || this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;

    // G-210: Stop leak detection before closing pool
    if (this.leakDetectionTimer) {
      clearInterval(this.leakDetectionTimer);
      this.leakDetectionTimer = null;
    }

    // C-075: Stop health check before closing pool
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
    
    try {
      await this.pool.end();
      this.pool = null;
      this.logger.info('Database pool closed');
    } finally {
      this.isShuttingDown = false;
    }
  }

  getPool(): Pool {
    if (!this.pool) {
      throw new Error('Database pool not initialized. Call connect() first.');
    }
    return this.pool;
  }

  async query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
    options: QueryOptions = {}
  ): Promise<Result<QueryResult<T>, Error>> {
    if (!this.pool) {
      return Result.err(new Error('Database pool not initialized'));
    }

    const start = Date.now();
    
    try {
      const result = await this.pool.query<T>({
        text,
        values,
        name: options.name,
      });

      const duration = Date.now() - start;
      
      // C-066: Lower slow query threshold from 1000ms to 500ms for earlier detection
      if (duration > 500) {
        this.logger.warn('Slow query detected', {
          duration,
          query: text.slice(0, 100),
          rowCount: result.rowCount,
        });
      }

      return Result.ok(result);
    } catch (error) {
      const duration = Date.now() - start;
      this.logger.error('Query failed', {
        error: error instanceof Error ? error.message : String(error),
        duration,
        query: text.slice(0, 100),
      });
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getClient(): Promise<PoolClient> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }
    const client = await this.pool.connect();

    // G-210: Track checkout for leak detection
    const stack = new Error('Connection acquired here').stack ?? '';
    this.checkedOutClients.set(client, { acquiredAt: Date.now(), stack });

    // Wrap the release method to automatically remove from tracking
    const originalRelease = client.release.bind(client);
    client.release = (err?: Error | boolean) => {
      this.checkedOutClients.delete(client);
      return originalRelease(err);
    };

    return client;
  }

  getStats(): {
    totalCount: number;
    idleCount: number;
    waitingCount: number;
  } {
    if (!this.pool) {
      return { totalCount: 0, idleCount: 0, waitingCount: 0 };
    }
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
    };
  }

  /**
   * FIX-POOL-MONITOR: Export pool metrics in Prometheus format.
   * Returns a string suitable for /metrics endpoint.
   */
  getPrometheusMetrics(serviceName: string = 'apexmail'): string {
    const stats = this.getStats();
    const checkedOutCount = this.checkedOutClients.size;
    const maxConnections = this.config.maxConnections;
    const utilizationPct = stats.totalCount > 0 
      ? ((stats.totalCount - stats.idleCount) / maxConnections * 100).toFixed(2)
      : '0.00';

    const lines: string[] = [
      '# HELP db_pool_connections_total Total number of connections in the pool',
      '# TYPE db_pool_connections_total gauge',
      `db_pool_connections_total{service="${serviceName}"} ${stats.totalCount}`,
      '',
      '# HELP db_pool_connections_idle Number of idle connections',
      '# TYPE db_pool_connections_idle gauge',
      `db_pool_connections_idle{service="${serviceName}"} ${stats.idleCount}`,
      '',
      '# HELP db_pool_connections_waiting Number of queries waiting for a connection',
      '# TYPE db_pool_connections_waiting gauge',
      `db_pool_connections_waiting{service="${serviceName}"} ${stats.waitingCount}`,
      '',
      '# HELP db_pool_connections_checked_out Number of connections currently checked out',
      '# TYPE db_pool_connections_checked_out gauge',
      `db_pool_connections_checked_out{service="${serviceName}"} ${checkedOutCount}`,
      '',
      '# HELP db_pool_connections_max Maximum configured connections',
      '# TYPE db_pool_connections_max gauge',
      `db_pool_connections_max{service="${serviceName}"} ${maxConnections}`,
      '',
      '# HELP db_pool_utilization_percent Pool utilization percentage',
      '# TYPE db_pool_utilization_percent gauge',
      `db_pool_utilization_percent{service="${serviceName}"} ${utilizationPct}`,
    ];

    return lines.join('\n');
  }

  /**
   * FIX-POOL-MONITOR: Check pool health and return alerts.
   * Returns array of warning messages if thresholds are exceeded.
   */
  checkPoolHealth(): { healthy: boolean; warnings: string[] } {
    const stats = this.getStats();
    const warnings: string[] = [];
    const maxConnections = this.config.maxConnections;

    // Alert if utilization > 80%
    const utilization = (stats.totalCount - stats.idleCount) / maxConnections;
    if (utilization > 0.8) {
      warnings.push(
        `High pool utilization: ${(utilization * 100).toFixed(1)}% ` +
        `(${stats.totalCount - stats.idleCount}/${maxConnections} connections in use)`
      );
    }

    // Alert if queries are waiting
    if (stats.waitingCount > 0) {
      warnings.push(
        `${stats.waitingCount} queries waiting for connections - consider increasing pool size`
      );
    }

    // Alert if potential leaks detected
    if (this.checkedOutClients.size > maxConnections * 0.5) {
      warnings.push(
        `${this.checkedOutClients.size} connections checked out - possible connection leak`
      );
    }

    return {
      healthy: warnings.length === 0,
      warnings,
    };
  }
}

// Service-specific pool configurations
const POOL_CONFIGS: Record<string, Partial<DatabaseConfig>> = {
  api: { maxConnections: 20 },
  worker: { maxConnections: 30 },
  mta: { maxConnections: 10 },
  default: { maxConnections: 20 },
};

export class DatabasePoolRegistry {
  private readonly dbPools: Map<string, DatabasePool> = new Map();

  getDatabase(service: string = 'default'): DatabasePool {
    const serviceName = service in POOL_CONFIGS ? service : 'default';

    let pool = this.dbPools.get(serviceName);
    if (!pool) {
      const poolConfig = POOL_CONFIGS[serviceName] ?? {};
      pool = new DatabasePool(poolConfig);
      this.dbPools.set(serviceName, pool);
    }
    return pool;
  }

  async disconnectAllPools(): Promise<void> {
    const disconnectPromises: Promise<void>[] = [];
    for (const pool of this.dbPools.values()) {
      disconnectPromises.push(pool.disconnect());
    }
    await Promise.all(disconnectPromises);
    this.dbPools.clear();
  }
}

const defaultRegistry = new DatabasePoolRegistry();

/**
 * Get a database pool for a specific service.
 * Each service gets its own pool with appropriate connection limits.
 * @param service - Service name ('api', 'worker', 'mta'). Defaults to 'default'.
 * @returns DatabasePool instance for the service
 */
export function getDatabase(service: string = 'default'): DatabasePool {
  return defaultRegistry.getDatabase(service);
}

/**
 * Create a new database pool with custom configuration.
 * Use this when you need a pool with specific settings not covered by service defaults.
 */
export function createDatabase(config?: Partial<DatabaseConfig>): DatabasePool {
  return new DatabasePool(config);
}

/**
 * Disconnect all database pools. Call during graceful shutdown.
 */
export async function disconnectAllPools(): Promise<void> {
  await defaultRegistry.disconnectAllPools();
}

export { DatabasePool };

export function createDatabaseRegistry(): DatabasePoolRegistry {
  return new DatabasePoolRegistry();
}
