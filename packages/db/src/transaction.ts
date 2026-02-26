/**
 * Transaction Helpers
 * 
 * Provides:
 * - Automatic rollback on error
 * - Nested transaction support via savepoints
 * - Retry with exponential backoff
 * - Serialization failure handling
 */

import type { PoolClient } from 'pg';
import { Result } from '@apexmail/lib';
import { getLogger, type Logger } from '@apexmail/lib/logger';
import type { DatabasePool } from './pool.js';

export type IsolationLevel = 
  | 'READ COMMITTED'
  | 'REPEATABLE READ'
  | 'SERIALIZABLE';

export interface TransactionOptions {
  isolationLevel?: IsolationLevel;
  readOnly?: boolean;
  deferrable?: boolean;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
}

export interface TransactionContext {
  client: PoolClient;
  savepoint(name: string): Promise<void>;
  rollbackTo(name: string): Promise<void>;
  releaseSavepoint(name: string): Promise<void>;
}

const DEFAULT_OPTIONS: TransactionOptions = {
  isolationLevel: 'READ COMMITTED',
  readOnly: false,
  deferrable: false,
  timeout: 30000,
  retries: 3,
  retryDelay: 100,
};

/**
 * SECURITY: Validate and sanitize savepoint names to prevent SQL injection
 * PostgreSQL savepoint names must be valid identifiers
 */
function sanitizeSavepointName(name: string): string {
  // Only allow alphanumeric characters and underscores, max 63 characters (PostgreSQL limit)
  if (!name || typeof name !== 'string') {
    throw new Error('Savepoint name must be a non-empty string');
  }
  
  // Check for valid identifier pattern: starts with letter or underscore, followed by alphanumeric/underscore
  const sanitized = name.replace(/[^a-zA-Z0-9_]/g, '');
  
  if (sanitized.length === 0) {
    throw new Error('Savepoint name must contain at least one alphanumeric character');
  }
  
  // Ensure it starts with a letter or underscore (PostgreSQL identifier rule)
  if (!/^[a-zA-Z_]/.test(sanitized)) {
    throw new Error('Savepoint name must start with a letter or underscore');
  }
  
  // PostgreSQL identifier max length is 63 characters
  if (sanitized.length > 63) {
    throw new Error('Savepoint name must not exceed 63 characters');
  }
  
  // Double-quote the identifier for safety (handles reserved words)
  // This is the PostgreSQL way to quote identifiers
  return `"${sanitized}"`;
}

const logger: Logger = getLogger().child({ component: 'transaction' });

/**
 * Check if an error is a serialization failure that should be retried
 */
function isRetryableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  
  const pgError = error as Error & { code?: string };
  // 40001 = serialization_failure
  // 40P01 = deadlock_detected
  return pgError.code === '40001' || pgError.code === '40P01';
}

/**
 * Execute a function within a database transaction
 */
export async function withTransaction<T>(
  db: DatabasePool,
  fn: (ctx: TransactionContext) => Promise<T>,
  options: TransactionOptions = {}
): Promise<Result<T, Error>> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const pool = db.getPool();
  
  let lastError: Error | null = null;
  let attempt = 0;

  while (attempt <= (opts.retries ?? 0)) {
    const client = await pool.connect();
    
    try {
      // Build transaction start command
      let startCommand = 'BEGIN';
      const modifiers: string[] = [];
      
      // BUG-002 FIX: Explicit whitelist validation for isolation level
      const VALID_ISOLATION_LEVELS = ['READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE'] as const;
      if (opts.isolationLevel) {
        if (!VALID_ISOLATION_LEVELS.includes(opts.isolationLevel as typeof VALID_ISOLATION_LEVELS[number])) {
          throw new Error(`Invalid isolation level: ${opts.isolationLevel}`);
        }
        modifiers.push(`ISOLATION LEVEL ${opts.isolationLevel}`);
      }
      if (opts.readOnly) {
        modifiers.push('READ ONLY');
      }
      if (opts.deferrable && opts.isolationLevel === 'SERIALIZABLE' && opts.readOnly) {
        modifiers.push('DEFERRABLE');
      }
      
      if (modifiers.length > 0) {
        startCommand = `BEGIN ${modifiers.join(' ')}`;
      }

      // Set statement timeout if specified — MUST be after BEGIN
      // so SET LOCAL applies to this transaction only, not the session

      await client.query(startCommand);

      if (opts.timeout) {
        const timeoutMs = Number(opts.timeout);
        if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300000) {
          throw new Error(`Invalid statement_timeout value: ${opts.timeout}. Must be a positive integer up to 300000ms.`);
        }
        const safeTimeoutMs = Math.floor(timeoutMs);
        await client.query(`SET LOCAL statement_timeout = ${safeTimeoutMs}`);
      }

      // Create transaction context
      const ctx: TransactionContext = {
        client,
        async savepoint(name: string): Promise<void> {
          const safeName = sanitizeSavepointName(name);
          await client.query(`SAVEPOINT ${safeName}`);
        },
        async rollbackTo(name: string): Promise<void> {
          const safeName = sanitizeSavepointName(name);
          await client.query(`ROLLBACK TO SAVEPOINT ${safeName}`);
        },
        async releaseSavepoint(name: string): Promise<void> {
          const safeName = sanitizeSavepointName(name);
          await client.query(`RELEASE SAVEPOINT ${safeName}`);
        },
      };

      // Execute the function
      const result = await fn(ctx);

      // Commit
      await client.query('COMMIT');

      return Result.ok(result);
    } catch (error) {
      // Rollback on error
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        logger.error('Rollback failed', {
          error: rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        });
      }

      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if we should retry
      if (isRetryableError(error) && attempt < (opts.retries ?? 0)) {
        attempt++;
        const delay = (opts.retryDelay ?? 100) * Math.pow(2, attempt - 1);
        
        logger.warn('Retrying transaction due to serialization failure', {
          attempt,
          delay,
          error: lastError.message,
        });

        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      logger.error('Transaction failed', {
        error: lastError.message,
        attempt,
        isolationLevel: opts.isolationLevel,
      });

      return Result.err(lastError);
    } finally {
      client.release();
    }
  }

  return Result.err(lastError ?? new Error('Transaction failed after retries'));
}

/**
 * Execute a read-only query in a transaction
 */
export async function withReadTransaction<T>(
  db: DatabasePool,
  fn: (ctx: TransactionContext) => Promise<T>,
  options: Omit<TransactionOptions, 'readOnly'> = {}
): Promise<Result<T, Error>> {
  return withTransaction(db, fn, { ...options, readOnly: true });
}

/**
 * Execute a serializable transaction with automatic retry
 */
export async function withSerializableTransaction<T>(
  db: DatabasePool,
  fn: (ctx: TransactionContext) => Promise<T>,
  options: Omit<TransactionOptions, 'isolationLevel'> = {}
): Promise<Result<T, Error>> {
  return withTransaction(db, fn, {
    ...options,
    isolationLevel: 'SERIALIZABLE',
    retries: options.retries ?? 5, // More retries for serializable
  });
}

/**
 * Advisory lock for distributed coordination
 */
export async function withAdvisoryLock<T>(
  db: DatabasePool,
  lockKey: bigint | [number, number],
  fn: () => Promise<T>,
  options: { timeout?: number; shared?: boolean } = {}
): Promise<Result<T, Error>> {
  const pool = db.getPool();
  const client = await pool.connect();

  try {
    // Calculate lock ID
    const lockId = Array.isArray(lockKey) 
      ? lockKey 
      : [Number(lockKey >> BigInt(32)), Number(lockKey & BigInt(0xFFFFFFFF))];

    // Try to acquire lock
    const lockFn = options.shared ? 'pg_try_advisory_lock_shared' : 'pg_try_advisory_lock';
    const lockResult = await client.query<{ acquired: boolean }>(
      `SELECT ${lockFn}($1, $2) as acquired`,
      lockId
    );

    if (!lockResult.rows[0]?.acquired) {
      return Result.err(new Error('Failed to acquire advisory lock'));
    }

    try {
      // Execute function
      const result = await fn();
      return Result.ok(result);
    } finally {
      // Release lock
      const unlockFn = options.shared ? 'pg_advisory_unlock_shared' : 'pg_advisory_unlock';
      await client.query(`SELECT ${unlockFn}($1, $2)`, lockId);
    }
  } catch (error) {
    return Result.err(error instanceof Error ? error : new Error(String(error)));
  } finally {
    client.release();
  }
}

/**
 * Generate a stable lock key from a string
 */
export function stringToLockKey(str: string): bigint {
  // Simple hash function to convert string to bigint
  let hash = BigInt(0);
  for (let i = 0; i < str.length; i++) {
    const char = BigInt(str.charCodeAt(i));
    hash = ((hash << BigInt(5)) - hash) + char;
    hash = hash & BigInt('0x7FFFFFFFFFFFFFFF'); // Keep within BIGINT range
  }
  return hash;
}
