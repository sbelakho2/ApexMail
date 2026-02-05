/**
 * Crypto Wrapper - Thin Interface over Node.js crypto
 * 
 * Provides:
 * - HMAC signatures for webhooks
 * - AES-256-GCM encryption for secrets
 * - Hash chaining for audit logs (Merkle-like)
 * - DKIM key generation
 * - Secure random generation
 */

import {
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
  generateKeyPairSync,
  timingSafeEqual,
  scrypt,
  type ScryptOptions,
} from 'node:crypto';
import { Result } from '../result.js';

// Promisified scrypt with proper typing
function scryptAsync(
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: ScryptOptions
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

// Constants
const AES_KEY_LENGTH = 32; // 256 bits
const AES_IV_LENGTH = 12; // 96 bits for GCM
const SCRYPT_KEYLEN = 32;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export interface HMACOptions {
  algorithm?: 'sha256' | 'sha384' | 'sha512';
}

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  version: 1;
}

export interface DKIMKeyPair {
  privateKey: string;
  publicKey: string;
  publicKeyDNS: string;
  selector: string;
}

export interface HashChainEntry {
  hash: string;
  previousHash: string;
  data: string;
  timestamp: number;
  index: number;
}

/**
 * Generate HMAC signature for webhook verification
 */
export function signHMAC(
  payload: string | Buffer,
  secret: string,
  options: HMACOptions = {}
): string {
  const algorithm = options.algorithm ?? 'sha256';
  const hmac = createHmac(algorithm, secret);
  hmac.update(payload);
  return hmac.digest('hex');
}

/**
 * Verify HMAC signature with timing-safe comparison
 */
export function verifyHMAC(
  payload: string | Buffer,
  signature: string,
  secret: string,
  options: HMACOptions = {}
): boolean {
  const expected = signHMAC(payload, secret, options);
  
  if (expected.length !== signature.length) {
    return false;
  }
  
  return timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(signature, 'hex')
  );
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(plaintext: string, key: Buffer): EncryptedPayload {
  if (key.length !== AES_KEY_LENGTH) {
    throw new Error(`Key must be ${AES_KEY_LENGTH} bytes`);
  }
  
  const iv = randomBytes(AES_IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  
  let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    version: 1,
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(
  encrypted: EncryptedPayload,
  key: Buffer
): Result<string, Error> {
  if (key.length !== AES_KEY_LENGTH) {
    return Result.err(new Error(`Key must be ${AES_KEY_LENGTH} bytes`));
  }
  
  if (encrypted.version !== 1) {
    return Result.err(new Error(`Unsupported encryption version: ${encrypted.version}`));
  }
  
  try {
    const iv = Buffer.from(encrypted.iv, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let plaintext = decipher.update(encrypted.ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');
    
    return Result.ok(plaintext);
  } catch (error) {
    return Result.err(
      error instanceof Error ? error : new Error('Decryption failed')
    );
  }
}

/**
 * Hash a password using scrypt
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derivedKey = await scryptAsync(
    password,
    salt,
    SCRYPT_KEYLEN,
    { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }
  );
  
  // Format: $scrypt$N$r$p$salt$hash
  return [
    '$scrypt',
    SCRYPT_N.toString(16),
    SCRYPT_R.toString(16),
    SCRYPT_P.toString(16),
    salt.toString('base64'),
    derivedKey.toString('base64'),
  ].join('$');
}

/**
 * Verify a password against a hash
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  const parts = hash.split('$');
  
  if (parts.length !== 7 || parts[1] !== 'scrypt') {
    return false;
  }
  
  const n = parseInt(parts[2] as string, 16);
  const r = parseInt(parts[3] as string, 16);
  const p = parseInt(parts[4] as string, 16);
  const salt = Buffer.from(parts[5] as string, 'base64');
  const storedKey = Buffer.from(parts[6] as string, 'base64');
  
  const derivedKey = await scryptAsync(
    password,
    salt,
    SCRYPT_KEYLEN,
    { N: n, r, p }
  );
  
  return timingSafeEqual(storedKey, derivedKey);
}

/**
 * Generate a SHA-256 hash
 */
export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Generate a SHA-512 hash
 */
export function sha512(data: string | Buffer): string {
  return createHash('sha512').update(data).digest('hex');
}

/**
 * Create a hash chain entry (for audit logs)
 */
export function createHashChainEntry(
  data: string | Record<string, unknown>,
  previousHash: string | null,
  index: number = 0
): HashChainEntry {
  const timestamp = Date.now();
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
  const prevHash = previousHash ?? '';
  const payload = `${prevHash}|${dataStr}|${timestamp}|${index}`;
  const hash = sha256(payload);
  
  return {
    hash,
    previousHash: prevHash,
    data: dataStr,
    timestamp,
    index,
  };
}

/**
 * Verify a hash chain entry
 * Uses timing-safe comparison to prevent timing attacks
 */
export function verifyHashChainEntry(entry: HashChainEntry): boolean {
  const payload = `${entry.previousHash}|${entry.data}|${entry.timestamp}|${entry.index}`;
  const expectedHash = sha256(payload);
  
  // Use timing-safe comparison to prevent timing attacks
  try {
    const hashBuffer = Buffer.from(entry.hash, 'hex');
    const expectedBuffer = Buffer.from(expectedHash, 'hex');
    if (hashBuffer.length !== expectedBuffer.length) {
      return false;
    }
    return timingSafeEqual(hashBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

/**
 * Verify an entire hash chain
 */
export function verifyHashChain(entries: HashChainEntry[]): Result<boolean, { index: number; reason: string }> {
  if (entries.length === 0) {
    return Result.ok(true);
  }
  
  // Sort by index
  const sorted = [...entries].sort((a, b) => a.index - b.index);
  
  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i]!;
    
    // Verify individual entry hash
    if (!verifyHashChainEntry(entry)) {
      return Result.err({ index: entry.index, reason: 'Invalid hash' });
    }
    
    // Verify chain linkage (except for first entry)
    if (i > 0) {
      const prevEntry = sorted[i - 1]!;
      if (entry.previousHash !== prevEntry.hash) {
        return Result.err({ index: entry.index, reason: 'Chain broken - previous hash mismatch' });
      }
    }
  }
  
  return Result.ok(true);
}

/**
 * Generate DKIM key pair
 */
export function generateDKIMKeyPair(selector: string, domain: string): DKIMKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
  
  // Extract the base64 part for DNS record
  const publicKeyBase64 = publicKey
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s/g, '');
  
  // Format for DNS TXT record
  const publicKeyDNS = `v=DKIM1; k=rsa; p=${publicKeyBase64}`;
  
  return {
    privateKey,
    publicKey,
    publicKeyDNS,
    selector: `${selector}._domainkey.${domain}`,
  };
}

/**
 * Generate secure random bytes
 */
export function secureRandomBytes(length: number): Buffer {
  return randomBytes(length);
}

/**
 * Generate a secure random hex string
 */
export function secureRandomHex(length: number): string {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Generate a secure random base64 string
 */
export function secureRandomBase64(length: number): string {
  return randomBytes(length).toString('base64url');
}

/**
 * Derive an encryption key from a password
 */
export async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return scryptAsync(password, salt, AES_KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
}

/**
 * Generate a new encryption key
 */
export function generateEncryptionKey(): Buffer {
  return randomBytes(AES_KEY_LENGTH);
}

/**
 * HMAC sign for webhook verification (alias for signHMAC)
 */
export function hmacSign(
  secret: string,
  data: string,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'
): string {
  return signHMAC(data, secret, { algorithm });
}

/**
 * Generate a random token (hex string)
 */
export function randomToken(bytes: number = 32): string {
  return randomBytes(bytes).toString('hex');
}

/**
 * Hash data using SHA-256 (alias for sha256)
 */
export function hashSha256(data: string | Buffer): string {
  return sha256(data);
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  
  return timingSafeEqual(bufA, bufB);
}

/**
 * Create HMAC signature with specified output encoding
 * Used for JWT signing and other protocols requiring specific encoding
 */
export function createHmacSignature(
  secret: string,
  data: string,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256',
  encoding: 'hex' | 'base64' | 'base64url' = 'hex'
): string {
  const hmac = createHmac(algorithm, secret);
  hmac.update(data);
  return hmac.digest(encoding);
}

/**
 * Verify HMAC signature with timing-safe comparison
 * Supports multiple encodings for different protocols
 */
export function verifyHmacSignature(
  secret: string,
  data: string,
  signature: string,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256',
  encoding: 'hex' | 'base64' | 'base64url' = 'hex'
): boolean {
  const expected = createHmacSignature(secret, data, algorithm, encoding);
  return timingSafeCompare(signature, expected);
}

/**
 * Generate a cryptographically secure random UUID
 */
export function generateUUID(): string {
  // Use crypto.randomUUID if available (Node 14.17+), otherwise generate manually
  if (typeof (globalThis as { crypto?: { randomUUID?: () => string } }).crypto?.randomUUID === 'function') {
    return (globalThis as { crypto: { randomUUID: () => string } }).crypto.randomUUID();
  }
  
  // Manual UUID v4 generation
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // Variant 10
  
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ============================================
// AES-128-GCM Functions for Tracking Codec
// ============================================

const AES_128_KEY_LENGTH = 16; // 128 bits
const AES_128_IV_LENGTH = 12;  // 96 bits for GCM
const AES_128_AUTH_TAG_LENGTH = 16;

export interface AES128GCMResult {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

/**
 * Encrypt data using AES-128-GCM (for compact URL-safe tracking tokens)
 */
export function encryptAES128GCM(
  plaintext: Buffer,
  key: Buffer
): AES128GCMResult {
  if (key.length !== AES_128_KEY_LENGTH) {
    throw new Error(`Key must be ${AES_128_KEY_LENGTH} bytes for AES-128-GCM`);
  }
  
  const iv = randomBytes(AES_128_IV_LENGTH);
  const cipher = createCipheriv('aes-128-gcm', key, iv);
  
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  
  const authTag = cipher.getAuthTag();
  
  return { ciphertext, iv, authTag };
}

/**
 * Decrypt data using AES-128-GCM
 */
export function decryptAES128GCM(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer
): Result<Buffer, Error> {
  if (key.length !== AES_128_KEY_LENGTH) {
    return Result.err(new Error(`Key must be ${AES_128_KEY_LENGTH} bytes for AES-128-GCM`));
  }
  
  if (iv.length !== AES_128_IV_LENGTH) {
    return Result.err(new Error(`IV must be ${AES_128_IV_LENGTH} bytes`));
  }
  
  if (authTag.length !== AES_128_AUTH_TAG_LENGTH) {
    return Result.err(new Error(`Auth tag must be ${AES_128_AUTH_TAG_LENGTH} bytes`));
  }
  
  try {
    const decipher = createDecipheriv('aes-128-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return Result.ok(plaintext);
  } catch (error) {
    return Result.err(
      error instanceof Error ? error : new Error('Decryption failed')
    );
  }
}

/**
 * Derive a key from a secret using HMAC (for key derivation in tracking codec)
 */
export function deriveKeyHMAC(
  secret: string,
  info: string,
  keyLength: number = 32
): Buffer {
  return createHmac('sha256', secret)
    .update(info)
    .digest()
    .subarray(0, keyLength);
}

/**
 * Generate HMAC and return raw buffer (for truncated signatures)
 */
export function hmacBuffer(
  secret: Buffer,
  data: string,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'
): Buffer {
  return createHmac(algorithm, secret).update(data).digest();
}

/**
 * Timing-safe comparison for buffers
 */
export function timingSafeCompareBuffers(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

// ============================================
// AES-256-CBC Functions for Enterprise Encryption
// ============================================

const AES_256_CBC_KEY_LENGTH = 32;
const AES_256_CBC_IV_LENGTH = 16;

/**
 * Derive a key synchronously using scrypt (for config encryption)
 */
export function deriveKeySync(
  password: string,
  salt: string | Buffer,
  keyLength: number = AES_256_CBC_KEY_LENGTH
): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('node:crypto').scryptSync(password, salt, keyLength);
}

/**
 * Encrypt text using AES-256-CBC with scrypt-derived key
 * Format: salt:iv:ciphertext (all hex-encoded)
 * 
 * SECURITY: Now generates a random salt for each encryption operation
 * to ensure unique keys even with the same password
 */
export function encryptAES256CBC(
  plaintext: string,
  encryptionKey: string,
  providedSalt?: string | Buffer
): string {
  // SECURITY: Generate a random 16-byte salt if not provided
  const salt = providedSalt 
    ? (typeof providedSalt === 'string' ? Buffer.from(providedSalt, 'hex') : providedSalt)
    : randomBytes(16);
  
  const key = deriveKeySync(encryptionKey, salt, AES_256_CBC_KEY_LENGTH);
  const iv = randomBytes(AES_256_CBC_IV_LENGTH);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Format: salt:iv:ciphertext (all hex)
  const saltHex = typeof providedSalt === 'string' ? providedSalt : salt.toString('hex');
  return saltHex + ':' + iv.toString('hex') + ':' + encrypted;
}

/**
 * Decrypt text using AES-256-CBC with scrypt-derived key
 * Expects format: salt:iv:ciphertext (all hex-encoded)
 * Also supports legacy format: iv:ciphertext with explicit salt parameter
 * 
 * SECURITY: Salt is now embedded in the ciphertext for proper key derivation
 */
export function decryptAES256CBC(
  ciphertext: string,
  encryptionKey: string,
  legacySalt?: string
): Result<string, Error> {
  try {
    const parts = ciphertext.split(':');
    
    let salt: Buffer;
    let ivHex: string;
    let encrypted: string;
    
    if (parts.length === 3) {
      // New format: salt:iv:ciphertext
      salt = Buffer.from(parts[0] || '', 'hex');
      ivHex = parts[1] || '';
      encrypted = parts[2] || '';
    } else if (parts.length === 2 && legacySalt) {
      // Legacy format: iv:ciphertext with separate salt
      salt = Buffer.from(legacySalt, legacySalt.length === 32 ? 'hex' : 'utf8');
      ivHex = parts[0] || '';
      encrypted = parts[1] || '';
    } else {
      return Result.err(new Error('Invalid ciphertext format - expected salt:iv:ciphertext'));
    }
    
    if (!ivHex || !encrypted || salt.length === 0) {
      return Result.err(new Error('Invalid ciphertext format'));
    }
    
    const key = deriveKeySync(encryptionKey, salt, AES_256_CBC_KEY_LENGTH);
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return Result.ok(decrypted);
  } catch (error) {
    return Result.err(
      error instanceof Error ? error : new Error('Decryption failed')
    );
  }
}

// ============================================
// AES-256-GCM Streaming Functions for Backups
// ============================================

const AES_256_GCM_IV_LENGTH = 16;
const AES_256_GCM_AUTH_TAG_LENGTH = 16;

/**
 * Create a cipher transform stream for AES-256-GCM encryption
 * Returns the cipher and the IV that was generated
 */
export function createAES256GCMCipher(
  key: Buffer
): { cipher: import('crypto').CipherGCM; iv: Buffer } {
  const iv = randomBytes(AES_256_GCM_IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv) as import('crypto').CipherGCM;
  return { cipher, iv };
}

/**
 * Create a decipher transform stream for AES-256-GCM decryption
 */
export function createAES256GCMDecipher(
  key: Buffer,
  iv: Buffer
): import('crypto').DecipherGCM {
  return createDecipheriv('aes-256-gcm', key, iv) as import('crypto').DecipherGCM;
}

/**
 * Encrypt a buffer using AES-256-GCM
 * Returns: iv (16 bytes) + authTag (16 bytes) + ciphertext
 */
export function encryptBufferAES256GCM(
  plaintext: Buffer,
  key: Buffer
): Buffer {
  if (key.length !== AES_KEY_LENGTH) {
    throw new Error(`Key must be ${AES_KEY_LENGTH} bytes for AES-256-GCM`);
  }
  
  const iv = randomBytes(AES_256_GCM_IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv) as import('crypto').CipherGCM;
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Decrypt a buffer using AES-256-GCM
 * Expects: iv (16 bytes) + authTag (16 bytes) + ciphertext
 */
export function decryptBufferAES256GCM(
  ciphertext: Buffer,
  key: Buffer
): Result<Buffer, Error> {
  if (key.length !== AES_KEY_LENGTH) {
    return Result.err(new Error(`Key must be ${AES_KEY_LENGTH} bytes for AES-256-GCM`));
  }
  
  if (ciphertext.length < AES_256_GCM_IV_LENGTH + AES_256_GCM_AUTH_TAG_LENGTH + 1) {
    return Result.err(new Error('Ciphertext too short'));
  }
  
  try {
    const iv = ciphertext.subarray(0, AES_256_GCM_IV_LENGTH);
    const authTag = ciphertext.subarray(AES_256_GCM_IV_LENGTH, AES_256_GCM_IV_LENGTH + AES_256_GCM_AUTH_TAG_LENGTH);
    const encrypted = ciphertext.subarray(AES_256_GCM_IV_LENGTH + AES_256_GCM_AUTH_TAG_LENGTH);
    
    const decipher = createDecipheriv('aes-256-gcm', key, iv) as import('crypto').DecipherGCM;
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    
    return Result.ok(decrypted);
  } catch (error) {
    return Result.err(
      error instanceof Error ? error : new Error('Decryption failed')
    );
  }
}

/**
 * Create a SHA-256 hash object for incremental hashing (streaming)
 */
export function createSHA256Hash(): import('crypto').Hash {
  return createHash('sha256');
}
