/**
 * @apexmail/db - Database Layer
 * 
 * Provides:
 * - Connection pooling with PgBouncer support
 * - Schema fingerprinting for startup validation
 * - Transaction helpers
 * - Query builders
 */

export * from './pool.js';
export * from './fingerprint.js';
export * from './transaction.js';
export * from './repositories/index.js';
