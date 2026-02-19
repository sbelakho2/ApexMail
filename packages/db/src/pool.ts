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

const DEFAULT_CONFIG: Partial<DatabaseConfig> = {
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
    const portValue = config.port ?? parseIntSafe(portFromEnv, DEFAULT_CONFIG.port!, 'DB_PORT');
    const validatedPort = validatePort(portValue, 'DB_PORT');

    // Parse and validate max connections
    const maxConnFromEnv = process.env['DB_MAX_CONNECTIONS'];
    const maxConnValue = config.maxConnections ?? parseIntSafe(maxConnFromEnv, DEFAULT_CONFIG.maxConnections!, 'DB_MAX_CONNECTIONS');
    
    if (maxConnValue < 1 || maxConnValue > 1000) {
      throw new Error(`Invalid DB_MAX_CONNECTIONS: must be between 1 and 1000, got ${maxConnValue}`);
    }

    this.config = {
      host: config.host ?? process.env['DB_HOST'] ?? DEFAULT_CONFIG.host!,
      port: validatedPort,
      database: config.database ?? process.env['DB_NAME'] ?? DEFAULT_CONFIG.database!,
      user: config.user ?? process.env['DB_USER'] ?? 'postgres',
      password: config.password ?? process.env['DB_PASSWORD'] ?? '',
      maxConnections: maxConnValue,
      idleTimeoutMs: config.idleTimeoutMs ?? DEFAULT_CONFIG.idleTimeoutMs!,
      connectionTimeoutMs: config.connectionTimeoutMs ?? DEFAULT_CONFIG.connectionTimeoutMs!,
      statementTimeoutMs: config.statementTimeoutMs ?? DEFAULT_CONFIG.statementTimeoutMs!,
      ssl: config.ssl ?? (process.env['DB_SSL'] === 'true' ? { rejectUnauthorized: process.env['DB_SSL_REJECT_UNAUTHORIZED'] !== 'false' } : undefined),
    };
    
    this.logger = getLogger().child({ component: 'db-pool' });
  }

  private getPoolConfig(): PoolConfig {
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
    };
  }

  async connect(): Promise<void> {
    if (this.pool) {
      return;
    }

    this.pool = new Pool(this.getPoolConfig());

    // Set up event handlers
    this.pool.on('connect', (client) => {
      // Set statement timeout on each new connection
      // SECURITY: Use parameterized query to prevent SQL injection
      // Note: SET statement_timeout accepts an integer (milliseconds) directly
      // The value is validated as number in config, so this is safe
      const timeoutMs = Math.floor(this.config.statementTimeoutMs);
      if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > 2147483647) {
        this.logger.error('Invalid statement timeout value', { timeoutMs });
        return;
      }
      // Postgres does not accept parameters for SET statements; value is validated as int.
      void client.query(`SET statement_timeout = ${timeoutMs}`).catch((error) => {
        this.logger.error('Failed to set statement_timeout', {
          error: error instanceof Error ? error.message : String(error),
          timeoutMs,
        });
      });
      this.logger.debug('New database connection established');
    });

    this.pool.on('error', (err) => {
      this.logger.error('Database pool error', { error: err.message });
    });

    this.pool.on('remove', () => {
      this.logger.debug('Database connection removed from pool');
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
        const start = Date.now();
        const client = await this.pool.connect();
        await client.query('SELECT 1');
        client.release();
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

    // Monkey-patch release so we can clean up tracking
    const originalRelease = client.release.bind(client);
    client.release = (err?: boolean | Error) => {
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
}

// Service-specific pool configurations
const POOL_CONFIGS: Record<string, Partial<DatabaseConfig>> = {
  api: { maxConnections: 20 },
  worker: { maxConnections: 30 },
  mta: { maxConnections: 10 },
  default: { maxConnections: 20 },
};

// Map of service name to pool instance for proper isolation
const dbPools: Map<string, DatabasePool> = new Map();

/**
 * Get a database pool for a specific service.
 * Each service gets its own pool with appropriate connection limits.
 * @param service - Service name ('api', 'worker', 'mta'). Defaults to 'default'.
 * @returns DatabasePool instance for the service
 */
export function getDatabase(service: string = 'default'): DatabasePool {
  const serviceName = service in POOL_CONFIGS ? service : 'default';
  
  let pool = dbPools.get(serviceName);
  if (!pool) {
    const poolConfig = POOL_CONFIGS[serviceName] ?? {};
    pool = new DatabasePool(poolConfig);
    dbPools.set(serviceName, pool);
  }
  return pool;
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
  const disconnectPromises: Promise<void>[] = [];
  for (const pool of dbPools.values()) {
    disconnectPromises.push(pool.disconnect());
  }
  await Promise.all(disconnectPromises);
  dbPools.clear();
}

export { DatabasePool };
