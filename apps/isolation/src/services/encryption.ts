/**
 * Encryption Service
 * 
 * Data encryption at rest:
 * - Field-level encryption
 * - Key management
 * - Key rotation
 * - Encrypted storage
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config.js';

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
}

export interface EncryptionPolicy {
  id: string;
  name: string;
  resource: string;
  fields: string[];
  algorithm: string;
  keyRotationDays: number;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class EncryptionService {
  private db: Pool;
  private redis: Redis;
  private masterKey: string;
  private activeKeys: Map<string, EncryptionKey> = new Map();
  private policies: Map<string, EncryptionPolicy> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.masterKey = config.security.encryptionKey;
  }

  /**
   * Initialize encryption service
   */
  async initialize(): Promise<void> {
    await this.loadActiveKeys();
    await this.loadPolicies();
    
    // Check for key rotation needs
    await this.checkKeyRotation();

    console.log('[Encryption] Service initialized');
  }

  /**
   * Generate a new data encryption key
   */
  async generateDataKey(organizationId: string): Promise<Result<EncryptionKey>> {
    const id = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + config.security.dataKeyRotationDays * 24 * 60 * 60 * 1000);

    // Generate random key
    const rawKey = CryptoJS.lib.WordArray.random(32).toString();
    
    // Encrypt with master key
    const encryptedKey = CryptoJS.AES.encrypt(rawKey, this.masterKey).toString();

    // Get next version
    const versionResult = await this.db.query(`
      SELECT COALESCE(MAX(version), 0) + 1 as next_version
      FROM iso_encryption_keys
      WHERE organization_id = $1
    `, [organizationId]);

    const version = versionResult.rows[0].next_version;

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
   * Encrypt a value
   */
  async encrypt(organizationId: string, plaintext: string): Promise<Result<EncryptedField>> {
    // Get active key for organization
    const keyResult = await this.getActiveKey(organizationId);
    if (!keyResult.ok) {
      // Generate new key if none exists
      const newKeyResult = await this.generateDataKey(organizationId);
      if (!newKeyResult.ok) return newKeyResult;
    }

    const key = keyResult.ok ? keyResult.value : (await this.getActiveKey(organizationId)).value!;

    try {
      // Decrypt the data key
      const decryptedKey = CryptoJS.AES.decrypt(key.encryptedKey, this.masterKey).toString(CryptoJS.enc.Utf8);

      // Generate IV
      const iv = CryptoJS.lib.WordArray.random(16).toString();

      // Encrypt the data
      const ciphertext = CryptoJS.AES.encrypt(plaintext, decryptedKey, {
        iv: CryptoJS.enc.Hex.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }).toString();

      const encrypted: EncryptedField = {
        ciphertext,
        keyId: key.id,
        algorithm: key.algorithm,
        iv,
      };

      return { ok: true, value: encrypted };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Decrypt a value
   */
  async decrypt(encrypted: EncryptedField): Promise<Result<string>> {
    // Get the key used for encryption
    const keyResult = await this.getKeyById(encrypted.keyId);
    if (!keyResult.ok) return keyResult;

    try {
      // Decrypt the data key
      const decryptedKey = CryptoJS.AES.decrypt(
        keyResult.value.encryptedKey,
        this.masterKey
      ).toString(CryptoJS.enc.Utf8);

      // Decrypt the data
      const plaintext = CryptoJS.AES.decrypt(encrypted.ciphertext, decryptedKey, {
        iv: CryptoJS.enc.Hex.parse(encrypted.iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }).toString(CryptoJS.enc.Utf8);

      return { ok: true, value: plaintext };
    } catch (error) {
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
  async reencryptData(organizationId: string, oldKeyId: string, newKeyId: string): Promise<Result<void>> {
    // This would re-encrypt all encrypted fields in the database
    // For each policy, iterate through affected tables and re-encrypt

    for (const policy of this.policies.values()) {
      try {
        // Get all records with encrypted fields using the old key
        const tableName = this.resourceToTable(policy.resource);
        
        for (const field of policy.fields) {
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
    return CryptoJS.SHA256(toHash).toString();
  }

  /**
   * Generate a secure random token
   */
  generateToken(length: number = 32): string {
    return CryptoJS.lib.WordArray.random(length).toString();
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
    return mapping[resource] || resource;
  }
}
