/**
 * ID Generation - Unique identifiers for all entities
 * 
 * Provides:
 * - UUIDs v7 (time-ordered)
 * - Short IDs for URLs
 * - Message-IDs (RFC 5322)
 * - Idempotency keys
 * - API key generation
 */

import { v7 as uuidv7, v4 as uuidv4 } from 'uuid';
import { nanoid, customAlphabet } from 'nanoid';
import { secureRandomHex, secureRandomBase64 } from '../crypto/index.js';

// Custom alphabets for different use cases
const URL_SAFE_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const READABLE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // No 0, 1, I, O for readability

const urlSafeId = customAlphabet(URL_SAFE_ALPHABET, 21);
const readableId = customAlphabet(READABLE_ALPHABET, 8);

/**
 * Generate a UUID v7 (time-ordered, sortable)
 * Preferred for database primary keys
 */
export function generateUuid(): string {
  return uuidv7();
}

/**
 * Generate a UUID v4 (random)
 * Use when time-ordering is not needed
 */
export function generateRandomUuid(): string {
  return uuidv4();
}

/**
 * Generate a short, URL-safe ID
 * Use for public-facing IDs in URLs
 */
export function generateShortId(length = 21): string {
  return urlSafeId(length);
}

/**
 * Generate a human-readable ID
 * Use for verification codes, short links
 */
export function generateReadableId(length = 8): string {
  return readableId(length);
}

/**
 * Generate an RFC 5322 compliant Message-ID
 * Format: <uuid@domain>
 */
export function generateMessageId(domain = 'apexmail.ee'): string {
  return `<${uuidv7()}@${domain}>`;
}

/**
 * Generate an idempotency key
 * Use for preventing duplicate API requests
 */
export function generateIdempotencyKey(): string {
  return `idem_${uuidv7()}`;
}

/**
 * Generate an API key
 * Format: apx_live_<random> or apx_test_<random>
 */
export function generateApiKey(mode: 'live' | 'test' = 'live'): {
  key: string;
  prefix: string;
  hash: string;
} {
  const prefix = `apx_${mode}_`;
  const secret = secureRandomBase64(32);
  const key = `${prefix}${secret}`;
  
  // Store only the hash in DB
  const { sha256 } = require('../crypto/index.js') as typeof import('../crypto/index.js');
  const hash = sha256(key);
  
  return { key, prefix, hash };
}

/**
 * Generate a webhook signing secret
 */
export function generateWebhookSecret(): string {
  return `whsec_${secureRandomBase64(32)}`;
}

/**
 * Generate a DKIM selector
 * Format: apexmail{YYYYWW}
 */
export function generateDkimSelector(date: Date = new Date()): string {
  const year = date.getFullYear();
  const weekNum = getIsoWeek(date);
  return `apexmail${year}${weekNum.toString().padStart(2, '0')}`;
}

/**
 * Generate a VERP (Variable Envelope Return Path) address
 * Format: bounce+localpart=domain@apexmail.ee
 */
export function generateVerpAddress(
  recipientEmail: string,
  bounceDomain = 'apexmail.ee'
): string {
  const encoded = recipientEmail.replace('@', '=');
  return `bounce+${encoded}@${bounceDomain}`;
}

/**
 * Parse a VERP address back to the original recipient
 */
export function parseVerpAddress(verpAddress: string): string | null {
  const match = verpAddress.match(/^bounce\+([^@]+)@/);
  if (!match?.[1]) return null;
  return match[1].replace('=', '@');
}

/**
 * Generate a tracking pixel ID
 */
export function generateTrackingId(): string {
  return `trk_${nanoid(16)}`;
}

/**
 * Generate a click tracking ID
 */
export function generateClickId(): string {
  return `clk_${nanoid(16)}`;
}

/**
 * Generate a tenant ID
 */
export function generateTenantId(): string {
  return `ten_${nanoid(12)}`;
}

/**
 * Generate a user ID
 */
export function generateUserId(): string {
  return `usr_${nanoid(12)}`;
}

/**
 * Generate a domain verification token
 */
export function generateDomainVerificationToken(): string {
  return `apexmail-verify=${secureRandomHex(32)}`;
}

/**
 * Generate a session ID
 */
export function generateSessionId(): string {
  return `sess_${secureRandomBase64(32)}`;
}

/**
 * Generate a password reset token
 */
export function generatePasswordResetToken(): string {
  return `rst_${secureRandomBase64(32)}`;
}

/**
 * Generate an email confirmation token
 */
export function generateEmailConfirmationToken(): string {
  return `eml_${secureRandomBase64(32)}`;
}

/**
 * Generate a honeypot token (for canary detection)
 */
export function generateHoneypotToken(): string {
  return `APXHONEY_${secureRandomHex(24)}`;
}

/**
 * Validate UUID format
 */
export function isValidUuid(str: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}

/**
 * Validate Message-ID format
 */
export function isValidMessageId(str: string): boolean {
  // Basic RFC 5322 Message-ID validation
  return /^<[^<>@\s]+@[^<>@\s]+>$/.test(str);
}

/**
 * Extract UUID from Message-ID
 */
export function extractUuidFromMessageId(messageId: string): string | null {
  const match = messageId.match(/^<([0-9a-f-]{36})@/i);
  return match?.[1] ?? null;
}

/**
 * Generate a unique ID (alias for generateUuid)
 * Default function for generating entity IDs
 */
export function generateId(): string {
  return generateUuid();
}

// Helper: Get ISO week number
function getIsoWeek(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
}
