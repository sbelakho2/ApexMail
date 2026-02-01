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

class DatabasePool {
  private pool: Pool | null = null;
  private readonly config: DatabaseConfig;
  private readonly logger: Logger;
  private isShuttingDown = false;

  constructor(config: Partial<DatabaseConfig> = {}) {
    this.config = {
      host: config.host ?? process.env['DB_HOST'] ?? DEFAULT_CONFIG.host!,
      port: config.port ?? parseInt(process.env['DB_PORT'] ?? String(DEFAULT_CONFIG.port), 10),
      database: config.database ?? process.env['DB_NAME'] ?? DEFAULT_CONFIG.database!,
      user: config.user ?? process.env['DB_USER'] ?? 'postgres',
      password: config.password ?? process.env['DB_PASSWORD'] ?? '',
      maxConnections: config.maxConnections ?? parseInt(process.env['DB_MAX_CONNECTIONS'] ?? String(DEFAULT_CONFIG.maxConnections), 10),
      idleTimeoutMs: config.idleTimeoutMs ?? DEFAULT_CONFIG.idleTimeoutMs!,
      connectionTimeoutMs: config.connectionTimeoutMs ?? DEFAULT_CONFIG.connectionTimeoutMs!,
      statementTimeoutMs: config.statementTimeoutMs ?? DEFAULT_CONFIG.statementTimeoutMs!,
      ssl: config.ssl ?? (process.env['DB_SSL'] === 'true' ? { rejectUnauthorized: false } : undefined),
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
      client.query(`SET statement_timeout = ${this.config.statementTimeoutMs}`);
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
  }

  async disconnect(): Promise<void> {
    if (!this.pool || this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    
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
      
      if (duration > 1000) {
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
    return this.pool.connect();
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
};

// Singleton pool instance
let dbPool: DatabasePool | null = null;

export function getDatabase(service?: string): DatabasePool {
  if (!dbPool) {
    const poolConfig = service ? POOL_CONFIGS[service] : {};
    dbPool = new DatabasePool(poolConfig);
  }
  return dbPool;
}

export function createDatabase(config?: Partial<DatabaseConfig>): DatabasePool {
  return new DatabasePool(config);
}

export { DatabasePool };
