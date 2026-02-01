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
 */
export function verifyHashChainEntry(entry: HashChainEntry): boolean {
  const payload = `${entry.previousHash}|${entry.data}|${entry.timestamp}|${entry.index}`;
  const expectedHash = sha256(payload);
  return entry.hash === expectedHash;
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
