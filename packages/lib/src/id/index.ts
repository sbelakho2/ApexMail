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

/**
 * ID usage policy:
 * - `generateUuid()` (UUID v7) for primary keys and internal references.
 * - `generateShortId()` / `generateReadableId()` (nanoid) for user-facing IDs.
 * - `generateRandomUuid()` (UUID v4) only for legacy integrations.
 */
export const ID_USAGE_POLICY = {
  internal: 'UUIDv7 for primary keys and internal references',
  public: 'Nanoid-based short IDs for URLs and user-facing tokens',
  legacy: 'UUIDv4 only when external systems require v4',
} as const;

import { v4 as uuidv4 } from 'uuid';
import { randomBytes, createHash } from 'node:crypto';
import { nanoid, customAlphabet } from 'nanoid';
import { secureRandomHex, secureRandomBase64 } from '../crypto/index.js';

// Custom alphabets for different use cases
const URL_SAFE_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const READABLE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // No 0, 1, I, O for readability

const urlSafeId = customAlphabet(URL_SAFE_ALPHABET, 21);
const readableId = customAlphabet(READABLE_ALPHABET, 8);

/**
 * Generate a UUID v7 (time-ordered, sortable)
 * Implementation based on RFC 9562
 * Preferred for database primary keys
 */
export function generateUuid(): string {
  // Get current timestamp in milliseconds
  const timestamp = Date.now();
  
  // Convert timestamp to bytes (48 bits / 6 bytes)
  const timestampBytes = Buffer.alloc(6);
  timestampBytes.writeUIntBE(timestamp, 0, 6);
  
  // Generate random bytes for the rest
  const random = randomBytes(10);
  
  // Build UUID v7 format: timestamp (48 bits) + version (4 bits) + random (12 bits) + variant (2 bits) + random (62 bits)
  const uuid = Buffer.alloc(16);
  
  // Copy timestamp bytes (48 bits)
  timestampBytes.copy(uuid, 0, 0, 6);
  
  // Set version 7 (0111) in the 4 high bits of byte 6
  uuid[6] = (random[0]! & 0x0f) | 0x70;
  uuid[7] = random[1]!;
  
  // Set variant (10) in the 2 high bits of byte 8
  uuid[8] = (random[2]! & 0x3f) | 0x80;
  
  // Copy remaining random bytes
  random.copy(uuid, 9, 3, 10);
  
  // Format as UUID string
  const hex = uuid.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
  return `<${generateUuid()}@${domain}>`;
}

/**
 * Generate an idempotency key
 * Use for preventing duplicate API requests
 */
export function generateIdempotencyKey(): string {
  return `idem_${generateUuid()}`;
}

const API_KEY_PREFIX_LENGTH = 8;

/**
 * Generate an API key
 * Format: am_live_<random> or am_test_<random>
 */
export function generateApiKey(mode: 'live' | 'test' = 'live'): {
  key: string;
  prefix: string;
  hash: string;
} {
  const basePrefix = `am_${mode}_`;
  const secret = secureRandomBase64(32);
  const key = `${basePrefix}${secret}`;
  const prefix = `${basePrefix}${secret.slice(0, API_KEY_PREFIX_LENGTH)}`;
  
  // Generate a hash for storage
  const hash = createHash('sha256').update(key).digest('hex');
  
  return { key, prefix, hash };
}

/**
 * Parse an API key to extract mode and validate format
 */
export function parseApiKey(key: string): {
  valid: boolean;
  mode: 'live' | 'test' | null;
  prefix: string | null;
  legacyPrefix?: string | null;
} {
  const livePrefix = 'am_live_';
  const testPrefix = 'am_test_';
  
  if (key.startsWith(livePrefix)) {
    const suffix = key.slice(livePrefix.length);
    if (suffix.length >= API_KEY_PREFIX_LENGTH) {
      return {
        valid: true,
        mode: 'live',
        prefix: `${livePrefix}${suffix.slice(0, API_KEY_PREFIX_LENGTH)}`,
        legacyPrefix: livePrefix,
      };
    }
    return { valid: true, mode: 'live', prefix: livePrefix, legacyPrefix: null };
  }
  
  if (key.startsWith(testPrefix)) {
    const suffix = key.slice(testPrefix.length);
    if (suffix.length >= API_KEY_PREFIX_LENGTH) {
      return {
        valid: true,
        mode: 'test',
        prefix: `${testPrefix}${suffix.slice(0, API_KEY_PREFIX_LENGTH)}`,
        legacyPrefix: testPrefix,
      };
    }
    return { valid: true, mode: 'test', prefix: testPrefix, legacyPrefix: null };
  }
  
  return { valid: false, mode: null, prefix: null };
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
 * Generate a unique ID with optional prefix
 * Default function for generating entity IDs
 * @param prefix Optional prefix to prepend (e.g., 'whk', 'msg', 'evt')
 */
export function generateId(prefix?: string): string {
  const uuid = generateUuid();
  return prefix ? `${prefix}_${uuid}` : uuid;
}

// Helper: Get ISO week number
function getIsoWeek(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
}
