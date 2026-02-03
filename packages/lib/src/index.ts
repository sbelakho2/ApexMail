/**
 * @apexmail/lib - Internal Library Wrappers
 * 
 * Thin Interface Pattern: All external dependencies are wrapped in internal
 * interfaces to allow swapping implementations without changing consumer code.
 * 
 * This is the single source of truth for all shared utilities across:
 * - api
 * - worker
 * - web
 */

export * from './logger/index.js';
export * from './crypto/index.js';
export * from './storage/index.js';
export * from './http/index.js';
export * from './cache/index.js';
export * from './queue/index.js';
export * from './time/index.js';
export * from './id/index.js';
export * from './json/index.js';
export * from './result.js';
export * from './mail-server-client.js';
export * from './templates/index.js';
export * from './attachments/index.js';
export * from './validation/index.js';
