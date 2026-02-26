/**
 * @module json
 * @description Safe JSON parsing utilities to prevent crashes from corrupted data
 */

import { Result } from '../result.js';

/**
 * Safely parse JSON string with error handling
 * Returns a Result type instead of throwing
 */
export function safeJsonParse<T = unknown>(
  json: string,
  defaultValue?: T
): Result<T, Error> {
  try {
    const parsed = JSON.parse(json) as T;
    return { ok: true, value: parsed };
  } catch (error) {
    const hasDefault = arguments.length >= 2;
    if (hasDefault) {
      if (defaultValue === null) {
        return {
          ok: false,
          error: new Error('JSON parse error: defaultValue was null'),
        };
      }
      return { ok: true, value: defaultValue };
    }
    return {
      ok: false,
      error: new Error(`JSON parse error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    };
  }
}

/**
 * Parse JSON with a default fallback value
 * Never throws - returns default on any error
 */
export function parseJsonOrDefault<T>(json: string | null | undefined, defaultValue: T): T {
  if (!json) return defaultValue;
  try {
    return JSON.parse(json) as T;
  } catch {
    return defaultValue;
  }
}

/**
 * Safely stringify JSON with error handling
 * Handles circular references and BigInt
 */
export function safeJsonStringify(
  value: unknown,
  space?: number
): Result<string, Error> {
  try {
    const seen = new WeakSet<object>();
    const stringified = JSON.stringify(value, (_key, val) => {
      // Handle BigInt
      if (typeof val === 'bigint') {
        return val.toString();
      }
      if (val && typeof val === 'object') {
        if (seen.has(val as object)) {
          throw new Error('Circular reference detected');
        }
        seen.add(val as object);
      }
      return val;
    }, space);
    
    if (stringified === undefined) {
      return { ok: false, error: new Error('JSON.stringify returned undefined') };
    }
    
    return { ok: true, value: stringified };
  } catch (error) {
    return {
      ok: false,
      error: new Error(`JSON stringify error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    };
  }
}

/**
 * Parse JSON from database row, with safe defaults
 * Designed for JSONB columns that might be null, empty, or malformed
 */
export function parseDbJson<T>(
  value: string | null | undefined,
  defaultValue: T
): T {
  if (value === null || value === undefined || value === '') {
    return defaultValue;
  }
  
  try {
    return JSON.parse(value) as T;
  } catch {
    // Log warning but don't crash
    console.warn(`[parseDbJson] Failed to parse JSON value, using default`);
    return defaultValue;
  }
}
