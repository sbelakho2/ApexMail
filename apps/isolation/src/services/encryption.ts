/**
 * Encryption Service
 * 
 * Data encryption at rest:
 * - Field-level encryption using AES-256-GCM (authenticated encryption)
 * - Key management
 * - Key rotation
 * - Encrypted storage
 * 
 * SECURITY FIXES:
 * - Replaced CBC mode with GCM mode for authenticated encryption
 * - Added proper IV/nonce handling
 * - Uses Node.js crypto module instead of CryptoJS for better security
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { Result } from '@apexmail/lib';
import { config } from '../config.js';

// AES-256-GCM constants
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;  // 96 bits (recommended for GCM)
const AUTH_TAG_LENGTH = 16; // 128 bits

export interface EncryptionKey {
  id: string;
  version: number;
  algorithm: string;
  encryptedKey: string;
  status: 'active' | 'rotating' | 'retired';
  createdAt: Date;
  rotatedAt: Date | null;
  expiresAt: Date;
}

export interface EncryptedField {
  ciphertext: string;
  keyId: string;
  algorithm: string;
  iv: string;
  authTag: string; // Added for GCM authentication
}

export interface EncryptionPolicy {
  id: string;
  name: string;
  resource: string;
  fields: string[];
  algorithm: string;
  keyRotationDays: number;
}

/**
 * Derive a key from the master key using HKDF for proper key derivation
 * SECURITY: Uses HKDF instead of raw key material
 */
function deriveKey(masterKey: string, salt: Buffer, info: string): Buffer {
  // Use HKDF to derive a proper AES key from the master key
  const ikm = Buffer.from(masterKey, 'utf-8');
  const derivedKey = crypto.hkdfSync('sha256', ikm, salt, info, KEY_LENGTH);
  return Buffer.from(derivedKey);
}

export class EncryptionService {
  private db: Pool;
  // @ts-expect-error - reserved for future caching
  private _redis: Redis;
  private masterKey: string;
  private activeKeys: Map<string, EncryptionKey> = new Map();
  private policies: Map<string, EncryptionPolicy> = new Map();
  
  // Salt for master key derivation (should be stored securely in production)
  private masterSalt: Buffer;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this._redis = redis;
    this.masterKey = config.security.encryptionKey;
    
    // SECURITY: Generate a consistent salt from the master key for key derivation
    // In production, this should be stored separately
    this.masterSalt = crypto.createHash('sha256').update(this.masterKey + '-salt').digest().subarray(0, 16);
  }

  /**
   * Initialize encryption service
   */
  async initialize(): Promise<void> {
    await this.loadActiveKeys();
    await this.loadPolicies();
    
    // Check for key rotation needs
    await this.checkKeyRotation();

    console.log('[Encryption] Service initialized with AES-256-GCM');
  }

  /**
   * Encrypt the data key with the master key using AES-256-GCM
   * SECURITY: Uses authenticated encryption for key wrapping
   */
  private encryptDataKey(rawKey: Buffer): string {
    const derivedMasterKey = deriveKey(this.masterKey, this.masterSalt, 'data-key-encryption');
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, derivedMasterKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    
    const encrypted = Buffer.concat([cipher.update(rawKey), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Format: iv:authTag:ciphertext (all base64)
    return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted.toString('base64')}`;
  }

  /**
   * Decrypt the data key with the master key using AES-256-GCM
   * SECURITY: Uses authenticated encryption for key unwrapping
   */
  private decryptDataKey(encryptedKey: string): Buffer {
    const parts = encryptedKey.split(':');
    
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted key format');
    }
    
    // Ensure parts exist before converting to Buffer
    if (!parts[0] || !parts[1] || !parts[2]) {
      throw new Error('Encrypted key has missing components');
    }
    
    const iv = Buffer.from(parts[0], 'base64');
    const authTag = Buffer.from(parts[1], 'base64');
    const encrypted = Buffer.from(parts[2], 'base64');
    
    const derivedMasterKey = deriveKey(this.masterKey, this.masterSalt, 'data-key-encryption');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, derivedMasterKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);
    
    const decryptedParts = [decipher.update(encrypted), decipher.final()];
    return Buffer.concat(decryptedParts);
  }

  /**
   * Generate a new data encryption key
   */
  async generateDataKey(organizationId: string): Promise<Result<EncryptionKey>> {
    const id = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + config.security.dataKeyRotationDays * 24 * 60 * 60 * 1000);

    // SECURITY: Generate cryptographically secure random key
    const rawKey = crypto.randomBytes(KEY_LENGTH);
    
    // Encrypt with master key using authenticated encryption
    const encryptedKey = this.encryptDataKey(rawKey);

    // Get next version
    const versionResult = await this.db.query(`
      SELECT COALESCE(MAX(version), 0) + 1 as next_version
      FROM iso_encryption_keys
      WHERE organization_id = $1
    `, [organizationId]);

    const version = parseInt(versionResult.rows[0]?.next_version ?? '1', 10);

    const key: EncryptionKey = {
      id,
      version,
      algorithm: 'AES-256-GCM',
      encryptedKey,
      status: 'active',
      createdAt: now,
      rotatedAt: null,
      expiresAt,
    };

    try {
      await this.db.query(`
        INSERT INTO iso_encryption_keys (
          id, organization_id, version, algorithm, encrypted_key,
          status, created_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [id, organizationId, version, key.algorithm, encryptedKey, 'active', now, expiresAt]);

      // Retire old active keys
      await this.db.query(`
        UPDATE iso_encryption_keys
        SET status = 'retired'
        WHERE organization_id = $1 AND id != $2 AND status = 'active'
      `, [organizationId, id]);

      this.activeKeys.set(id, key);

      console.log(`[Encryption] Generated new data key for org ${organizationId}`);

      return { ok: true, value: key };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Encrypt a value using AES-256-GCM (authenticated encryption)
   * SECURITY: Uses GCM mode which provides both confidentiality and integrity
   */
  async encrypt(organizationId: string, plaintext: string): Promise<Result<EncryptedField>> {
    // Get active key for organization
    const keyResult = await this.getActiveKey(organizationId);
    if (!keyResult.ok) {
      // Generate new key if none exists
      const newKeyResult = await this.generateDataKey(organizationId);
      if (!newKeyResult.ok) return newKeyResult;
    }

    const activeKeyResult = keyResult.ok ? keyResult : await this.getActiveKey(organizationId);
    if (!activeKeyResult.ok || !activeKeyResult.value) {
      return { ok: false, error: new Error('Failed to get encryption key') };
    }
    const key = activeKeyResult.value;

    try {
      // Decrypt the data key using authenticated decryption
      const decryptedKey = this.decryptDataKey(key.encryptedKey);

      // Generate cryptographically secure IV (nonce) for GCM
      const iv = crypto.randomBytes(IV_LENGTH);

      // Create cipher with AES-256-GCM
      const cipher = crypto.createCipheriv(ALGORITHM, decryptedKey, iv, {
        authTagLength: AUTH_TAG_LENGTH,
      });

      // Encrypt the data
      const plaintextBuffer = Buffer.from(plaintext, 'utf-8');
      const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const encryptedField: EncryptedField = {
        ciphertext: encrypted.toString('base64'),
        keyId: key.id,
        algorithm: 'AES-256-GCM',
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
      };

      return { ok: true, value: encryptedField };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Decrypt a value using AES-256-GCM (authenticated decryption)
   * SECURITY: Verifies authentication tag to detect tampering
   */
  async decrypt(encrypted: EncryptedField): Promise<Result<string>> {
    // Get the key used for encryption
    const keyResult = await this.getKeyById(encrypted.keyId);
    if (!keyResult.ok) return keyResult;

    try {
      // Decrypt the data key using authenticated decryption
      const decryptedKey = this.decryptDataKey(keyResult.value.encryptedKey);

      // Parse the encrypted components
      if (!encrypted.iv || !encrypted.ciphertext) {
        return { ok: false, error: new Error('Missing required encryption parameters') };
      }
      const iv = Buffer.from(encrypted.iv, 'base64');
      const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
      
      // SECURITY: Require auth tag for GCM mode
      if (!encrypted.authTag) {
        return { ok: false, error: new Error('Missing authentication tag - data may have been tampered with') };
      }
      const authTag = Buffer.from(encrypted.authTag, 'base64');

      // Create decipher with AES-256-GCM
      const decipher = crypto.createDecipheriv(ALGORITHM, decryptedKey, iv, {
        authTagLength: AUTH_TAG_LENGTH,
      });
      decipher.setAuthTag(authTag);

      // Decrypt the data (authentication is verified automatically)
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const plaintext = decrypted.toString('utf-8');

      return { ok: true, value: plaintext };
    } catch (error) {
      // GCM mode will throw if authentication fails (tampering detected)
      if (error instanceof Error && error.message.includes('Unsupported state or unable to authenticate')) {
        return { ok: false, error: new Error('Decryption failed - data may have been tampered with') };
      }
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Encrypt an object's fields according to policy
   */
  async encryptObject(
    organizationId: string,
    resource: string,
    data: Record<string, unknown>
  ): Promise<Result<Record<string, unknown>>> {
    const policy = this.policies.get(resource);
    if (!policy) {
      // No policy, return as-is
      return { ok: true, value: data };
    }

    const encrypted: Record<string, unknown> = { ...data };

    for (const field of policy.fields) {
      if (data[field] !== undefined && data[field] !== null) {
        const value = String(data[field]);
        const result = await this.encrypt(organizationId, value);
        
        if (!result.ok) return result;
        
        encrypted[field] = result.value;
      }
    }

    return { ok: true, value: encrypted };
  }

  /**
   * Decrypt an object's fields according to policy
   */
  async decryptObject(
    resource: string,
    data: Record<string, unknown>
  ): Promise<Result<Record<string, unknown>>> {
    const policy = this.policies.get(resource);
    if (!policy) {
      return { ok: true, value: data };
    }

    const decrypted: Record<string, unknown> = { ...data };

    for (const field of policy.fields) {
      const encryptedField = data[field] as EncryptedField | undefined;
      
      if (encryptedField && typeof encryptedField === 'object' && 'ciphertext' in encryptedField) {
        const result = await this.decrypt(encryptedField);
        
        if (!result.ok) return result;
        
        decrypted[field] = result.value;
      }
    }

    return { ok: true, value: decrypted };
  }

  /**
   * Rotate encryption key for an organization
   */
  async rotateKey(organizationId: string): Promise<Result<EncryptionKey>> {
    // Generate new key
    const newKeyResult = await this.generateDataKey(organizationId);
    if (!newKeyResult.ok) return newKeyResult;

    const newKey = newKeyResult.value;

    // Get old active key
    const oldKeyResult = await this.db.query(`
      SELECT id FROM iso_encryption_keys
      WHERE organization_id = $1 AND status = 'retired'
      ORDER BY created_at DESC
      LIMIT 1
    `, [organizationId]);

    if (oldKeyResult.rows.length > 0) {
      const oldKeyId = oldKeyResult.rows[0].id;

      // Re-encrypt data with new key
      await this.reencryptData(organizationId, oldKeyId, newKey.id);
    }

    console.log(`[Encryption] Rotated key for org ${organizationId}`);

    return { ok: true, value: newKey };
  }

  /**
   * Re-encrypt all data for an organization
   */
  async reencryptData(organizationId: string, oldKeyId: string, _newKeyId: string): Promise<Result<void>> {
    // This would re-encrypt all encrypted fields in the database
    // For each policy, iterate through affected tables and re-encrypt

    for (const policy of this.policies.values()) {
      try {
        // Get all records with encrypted fields using the old key
        const tableName = this.resourceToTable(policy.resource);
        
        for (const field of policy.fields) {
          // Validate field name to prevent SQL injection
          if (!/^[a-z_][a-z0-9_]*$/i.test(field)) {
            console.error(`[Encryption] Invalid field name: ${field}`);
            continue;
          }
          
          const result = await this.db.query(`
            SELECT id, "${field}" FROM ${tableName}
            WHERE organization_id = $1
              AND "${field}"->>'keyId' = $2
          `, [organizationId, oldKeyId]);

          for (const row of result.rows) {
            const encryptedField = row[field] as EncryptedField;
            
            // Decrypt with old key
            const decrypted = await this.decrypt(encryptedField);
            if (!decrypted.ok) continue;

            // Re-encrypt with new key
            const reencrypted = await this.encrypt(organizationId, decrypted.value);
            if (!reencrypted.ok) continue;

            // Update record
            await this.db.query(`
              UPDATE ${tableName}
              SET "${field}" = $2
              WHERE id = $1
            `, [row.id, JSON.stringify(reencrypted.value)]);
          }
        }
      } catch (error) {
        console.error(`[Encryption] Re-encryption error for ${policy.resource}:`, error);
      }
    }

    return { ok: true, value: undefined };
  }

  /**
   * Create encryption policy
   */
  async createPolicy(policy: Omit<EncryptionPolicy, 'id'>): Promise<Result<EncryptionPolicy>> {
    const id = uuidv4();

    const fullPolicy: EncryptionPolicy = {
      ...policy,
      id,
    };

    try {
      await this.db.query(`
        INSERT INTO iso_encryption_policies (id, name, resource, fields, algorithm, key_rotation_days)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [id, policy.name, policy.resource, JSON.stringify(policy.fields), policy.algorithm, policy.keyRotationDays]);

      this.policies.set(policy.resource, fullPolicy);

      return { ok: true, value: fullPolicy };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Hash a value (for searchable encryption)
   */
  hash(value: string, salt?: string): string {
    const toHash = salt ? `${salt}:${value}` : value;
    return crypto.createHash('sha256').update(toHash).digest('hex');
  }

  /**
   * Generate a secure random token
   */
  generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  // ==================== Private Methods ====================

  private async loadActiveKeys(): Promise<void> {
    try {
      const result = await this.db.query(`
        SELECT * FROM iso_encryption_keys WHERE status = 'active'
      `);

      for (const row of result.rows) {
        const key: EncryptionKey = {
          id: row.id,
          version: row.version,
          algorithm: row.algorithm,
          encryptedKey: row.encrypted_key,
          status: row.status,
          createdAt: new Date(row.created_at),
          rotatedAt: row.rotated_at ? new Date(row.rotated_at) : null,
          expiresAt: new Date(row.expires_at),
        };
        this.activeKeys.set(row.organization_id, key);
      }
    } catch (error) {
      console.warn('[Encryption] Could not load keys:', error);
    }
  }

  private async loadPolicies(): Promise<void> {
    try {
      const result = await this.db.query('SELECT * FROM iso_encryption_policies');

      for (const row of result.rows) {
        const policy: EncryptionPolicy = {
          id: row.id,
          name: row.name,
          resource: row.resource,
          fields: row.fields || [],
          algorithm: row.algorithm,
          keyRotationDays: row.key_rotation_days,
        };
        this.policies.set(policy.resource, policy);
      }
    } catch (error) {
      console.warn('[Encryption] Could not load policies:', error);
    }
  }

  private async checkKeyRotation(): Promise<void> {
    // Check for keys that need rotation
    const result = await this.db.query(`
      SELECT DISTINCT organization_id
      FROM iso_encryption_keys
      WHERE status = 'active' AND expires_at < NOW() + INTERVAL '7 days'
    `);

    for (const row of result.rows) {
      console.log(`[Encryption] Key rotation needed for org ${row.organization_id}`);
      // In production, would trigger rotation workflow
    }
  }

  private async getActiveKey(organizationId: string): Promise<Result<EncryptionKey>> {
    // Check cache
    if (this.activeKeys.has(organizationId)) {
      return { ok: true, value: this.activeKeys.get(organizationId)! };
    }

    try {
      const result = await this.db.query(`
        SELECT * FROM iso_encryption_keys
        WHERE organization_id = $1 AND status = 'active'
        ORDER BY version DESC
        LIMIT 1
      `, [organizationId]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('No active encryption key found') };
      }

      const row = result.rows[0];
      const key: EncryptionKey = {
        id: row.id,
        version: row.version,
        algorithm: row.algorithm,
        encryptedKey: row.encrypted_key,
        status: row.status,
        createdAt: new Date(row.created_at),
        rotatedAt: row.rotated_at ? new Date(row.rotated_at) : null,
        expiresAt: new Date(row.expires_at),
      };

      this.activeKeys.set(organizationId, key);

      return { ok: true, value: key };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private async getKeyById(keyId: string): Promise<Result<EncryptionKey>> {
    try {
      const result = await this.db.query(
        'SELECT * FROM iso_encryption_keys WHERE id = $1',
        [keyId]
      );

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Encryption key not found') };
      }

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          version: row.version,
          algorithm: row.algorithm,
          encryptedKey: row.encrypted_key,
          status: row.status,
          createdAt: new Date(row.created_at),
          rotatedAt: row.rotated_at ? new Date(row.rotated_at) : null,
          expiresAt: new Date(row.expires_at),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private resourceToTable(resource: string): string {
    const mapping: Record<string, string> = {
      email: 'emails',
      contact: 'contacts',
      api_key: 'api_keys',
      webhook: 'webhooks',
    };
    const tableName = mapping[resource];
    if (!tableName) {
      throw new Error(`Unknown resource type: ${resource}`);
    }
    return tableName;
  }
}
