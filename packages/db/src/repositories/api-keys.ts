/**
 * API Keys Repository - Scoped API keys with rotation support
 */

import { Result } from '@apexmail/lib';
import { generateUuid, generateApiKey, parseApiKey } from '@apexmail/lib/id';
import { hashPassword, verifyPassword } from '@apexmail/lib/crypto';
import { getLogger, type Logger } from '@apexmail/lib/logger';
import type { DatabasePool } from '../pool.js';

export type ApiKeyScope =
  | 'messages:send'
  | 'messages:read'
  | 'messages:write'
  | 'domains:read'
  | 'domains:write'
  | 'suppressions:read'
  | 'suppressions:write'
  | 'events:read'
  | 'templates:read'
  | 'templates:write'
  | 'analytics:read'
  | 'webhooks:read'
  | 'webhooks:write'
  | 'admin';

export interface ApiKey {
  id: string;
  tenantId: string;
  userId: string | null;
  name: string;
  prefix: string; // First 8 chars for display/lookup
  keyHash: string;
  scopes: ApiKeyScope[];
  rateLimit: number; // requests per minute
  allowedIps: string[] | null;
  allowedDomains: string[] | null;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  lastUsedIp: string | null;
  usageCount: number;
  isActive: boolean;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateApiKeyInput {
  tenantId: string;
  userId?: string;
  name: string;
  scopes: ApiKeyScope[];
  rateLimit?: number;
  allowedIps?: string[];
  allowedDomains?: string[];
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface UpdateApiKeyInput {
  name?: string;
  scopes?: ApiKeyScope[];
  rateLimit?: number;
  allowedIps?: string[] | null;
  allowedDomains?: string[] | null;
  expiresAt?: Date | null;
  isActive?: boolean;
  metadata?: Record<string, unknown>;
}

export interface ApiKeyWithSecret extends ApiKey {
  secretKey: string; // Only returned on creation
}

export interface VerifyApiKeyResult {
  valid: boolean;
  apiKey: ApiKey | null;
  reason?: 'not_found' | 'inactive' | 'expired' | 'ip_blocked' | 'invalid_hash';
}

export class ApiKeysRepository {
  private readonly logger: Logger;

  constructor(private readonly db: DatabasePool) {
    this.logger = getLogger().child({ component: 'api-keys-repo' });
  }

  /**
   * F-245: Validate that an IP or CIDR string is well-formed.
   * Accepts plain IPv4 addresses (e.g. "192.168.1.1") and CIDR notation
   * (e.g. "10.0.0.0/8"). Returns null if valid, or an error message.
   */
  private validateIpOrCidr(value: string): string | null {
    const cidrMatch = value.match(/^([^/]+)(?:\/(.+))?$/);
    if (!cidrMatch || !cidrMatch[1]) return `Invalid IP/CIDR: ${value}`;

    const ip = cidrMatch[1];
    const prefix = cidrMatch[2];

    // Validate IPv4
    const parts = ip.split('.');
    if (parts.length !== 4) return `Invalid IPv4 address: ${ip}`;
    for (const part of parts) {
      const n = parseInt(part, 10);
      if (isNaN(n) || n < 0 || n > 255 || String(n) !== part) {
        return `Invalid IPv4 octet "${part}" in: ${ip}`;
      }
    }

    // Validate CIDR prefix if present
    if (prefix !== undefined) {
      const prefixNum = parseInt(prefix, 10);
      if (isNaN(prefixNum) || prefixNum < 0 || prefixNum > 32 || String(prefixNum) !== prefix) {
        return `Invalid CIDR prefix "/${prefix}" in: ${value}`;
      }
    }

    return null; // Valid
  }

  /**
   * F-245: Validate an array of IP/CIDR entries. Returns an error Result
   * if any entry is malformed, otherwise returns null.
   */
  private validateAllowedIps(ips: string[]): string | null {
    for (const ip of ips) {
      const trimmed = ip.trim();
      if (!trimmed) return 'Empty IP address entry';
      const error = this.validateIpOrCidr(trimmed);
      if (error) return error;
    }
    return null;
  }

  async create(input: CreateApiKeyInput): Promise<Result<ApiKeyWithSecret, Error>> {
    // F-245: Validate IP whitelist values before persisting
    if (input.allowedIps && input.allowedIps.length > 0) {
      const ipError = this.validateAllowedIps(input.allowedIps);
      if (ipError) {
        return Result.err(new Error(`Invalid IP whitelist: ${ipError}`));
      }
    }

    const id = generateUuid();
    const { key: secretKey, prefix } = generateApiKey();
    
    // Hash the key for storage
    const keyHash = await hashPassword(secretKey);
    
    const now = new Date();

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO api_keys (
        id, tenant_id, user_id, name, prefix, key_hash, scopes,
        rate_limit, allowed_ips, allowed_domains, expires_at,
        is_active, metadata, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (id) DO NOTHING
      RETURNING *`,
      [
        id,
        input.tenantId,
        input.userId ?? null,
        input.name,
        prefix,
        keyHash,
        input.scopes,
        input.rateLimit ?? 1000,
        input.allowedIps ?? null,
        input.allowedDomains ?? null,
        input.expiresAt ?? null,
        true,
        JSON.stringify(input.metadata ?? {}),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      // B-040: ON CONFLICT (id) DO NOTHING means a duplicate id was generated;
      // this is astronomically unlikely with UUIDs but handle gracefully.
      this.logger.warn('API key creation returned no rows — possible duplicate id conflict', {
        tenantId: input.tenantId,
        name: input.name,
      });
      return Result.err(new Error('Failed to create API key: duplicate conflict'));
    }

    const apiKey = this.mapRow(row);
    return Result.ok({
      ...apiKey,
      secretKey, // Only returned once during creation
    });
  }

  async verify(key: string, clientIp?: string): Promise<Result<VerifyApiKeyResult, Error>> {
    const parsed = parseApiKey(key);
    if (!parsed) {
      return Result.ok({
        valid: false,
        apiKey: null,
        reason: 'not_found',
      });
    }

    // C-074: Look up by prefix + is_active for efficient retrieval.
    // The WHERE clause is ordered so the btree index on (prefix, is_active)
    // is used effectively, and inactive keys are pruned before hash verification.
    //
    // C-120: Required indexes for API key lookup performance:
    //   CREATE INDEX idx_api_keys_prefix_active ON api_keys (prefix, is_active);
    //   CREATE INDEX idx_api_keys_key_hash ON api_keys USING hash (key_hash);
    // The prefix index drives the WHERE clause; the key_hash hash index
    // supports any future key_hash-based lookups (e.g. migration or audit).
    // Without these indexes, every verify() call triggers a sequential scan.
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM api_keys WHERE prefix = $1 AND is_active = true',
      [parsed.prefix]
    );

    if (!result.ok) return result;

    const rows = result.value.rows;
    if (rows.length === 0) {
      return Result.ok({
        valid: false,
        apiKey: null,
        reason: 'not_found',
      });
    }

    // FIX-005: Multiple API keys may share the same prefix.
    // Iterate all matching rows and verify the hash against each.
    let matchedApiKey: ApiKey | null = null;
    for (const row of rows) {
      const candidate = this.mapRow(row);
      const hashMatch = await verifyPassword(key, row.key_hash);
      if (hashMatch) {
        matchedApiKey = candidate;
        break;
      }
    }

    if (!matchedApiKey) {
      return Result.ok({
        valid: false,
        apiKey: null,
        reason: 'invalid_hash',
      });
    }

    const apiKey = matchedApiKey;

    // Note: is_active is already filtered in the query (C-074) but keep a
    // defensive check in case the query is changed.
    if (!apiKey.isActive) {
      return Result.ok({
        valid: false,
        apiKey,
        reason: 'inactive',
      });
    }

    // Check expiration
    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      return Result.ok({
        valid: false,
        apiKey,
        reason: 'expired',
      });
    }

    // Check IP whitelist
    if (clientIp && apiKey.allowedIps && apiKey.allowedIps.length > 0) {
      if (!this.isIpAllowed(clientIp, apiKey.allowedIps)) {
        return Result.ok({
          valid: false,
          apiKey,
          reason: 'ip_blocked',
        });
      }
    }

    // Update last used (fire and forget — errors logged, not re-thrown)
    this.updateLastUsed(apiKey.id, clientIp);

    return Result.ok({
      valid: true,
      apiKey,
    });
  }

  /**
   * F-214: Debounced last-used-at update.
   * Only writes to the database if the existing last_used_at is more than
   * 5 minutes old. This prevents write amplification on high-traffic API
   * keys that may be used hundreds of times per second, while still keeping
   * a reasonably accurate last-used timestamp for auditing.
   */
  private static readonly LAST_USED_DEBOUNCE_MS = 5 * 60 * 1000; // 5 minutes

  private async updateLastUsed(id: string, ip?: string): Promise<void> {
    try {
      await this.db.query(
        `UPDATE api_keys 
         SET last_used_at = NOW(), 
             last_used_ip = COALESCE($2, last_used_ip),
             usage_count = usage_count + 1,
             updated_at = NOW()
         WHERE id = $1
           AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '${ApiKeysRepository.LAST_USED_DEBOUNCE_MS / 1000} seconds')`,
        [id, ip ?? null]
      );
    } catch (error) {
      this.logger.error('Failed to update API key last used timestamp', {
        apiKeyId: id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private isIpAllowed(clientIp: string, allowedIps: string[]): boolean {
    for (const allowed of allowedIps) {
      if (allowed === clientIp) return true;
      
      // CIDR notation support
      if (allowed.includes('/')) {
        if (this.isIpInCidr(clientIp, allowed)) return true;
      }
    }
    return false;
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    if (!bits || !range) return ip === range;

    const mask = parseInt(bits, 10);
    if (isNaN(mask) || mask < 0 || mask > 32) return false;

    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);
    if (ipNum === null || rangeNum === null) return false;

    const maskNum = ~((1 << (32 - mask)) - 1);
    return (ipNum & maskNum) === (rangeNum & maskNum);
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;

    let num = 0;
    for (const part of parts) {
      const n = parseInt(part, 10);
      if (isNaN(n) || n < 0 || n > 255) return null;
      num = (num << 8) | n;
    }
    return num >>> 0; // Convert to unsigned
  }

  async findById(id: string, tenantId: string): Promise<Result<ApiKey | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM api_keys WHERE id = $1 AND tenant_id = $2',
      [id, tenantId]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async update(id: string, input: UpdateApiKeyInput, tenantId: string): Promise<Result<ApiKey, Error>> {
    // F-245: Validate IP whitelist values before persisting
    if (input.allowedIps && input.allowedIps.length > 0) {
      const ipError = this.validateAllowedIps(input.allowedIps);
      if (ipError) {
        return Result.err(new Error(`Invalid IP whitelist: ${ipError}`));
      }
    }

    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }
    if (input.scopes !== undefined) {
      updates.push(`scopes = $${paramIndex++}`);
      values.push(input.scopes);
    }
    if (input.rateLimit !== undefined) {
      updates.push(`rate_limit = $${paramIndex++}`);
      values.push(input.rateLimit);
    }
    if (input.allowedIps !== undefined) {
      updates.push(`allowed_ips = $${paramIndex++}`);
      values.push(input.allowedIps);
    }
    if (input.allowedDomains !== undefined) {
      updates.push(`allowed_domains = $${paramIndex++}`);
      values.push(input.allowedDomains);
    }
    if (input.expiresAt !== undefined) {
      updates.push(`expires_at = $${paramIndex++}`);
      values.push(input.expiresAt);
    }
    if (input.isActive !== undefined) {
      updates.push(`is_active = $${paramIndex++}`);
      values.push(input.isActive);
    }
    if (input.metadata !== undefined) {
      updates.push(`metadata = metadata || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.metadata));
    }

    updates.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE api_keys SET ${updates.join(', ')} WHERE id = $${paramIndex} AND tenant_id = $${paramIndex + 1} RETURNING *`,
      [...values, tenantId]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('API key not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  /**
   * E-173: API key rotation with optional grace period.
   *
   * Creates a brand-new API key that inherits the old key's scopes, rate limits,
   * IP/domain restrictions, and metadata. If `gracePeriodMs` is provided the old
   * key remains active but is set to expire after the grace window, giving
   * consumers time to switch over. Without a grace period the old key is
   * revoked immediately.
   *
   * Returns the newly created key (with its plaintext secret). The old key's
   * id is recorded in the new key's metadata for audit traceability.
   */
  async rotate(
    id: string,
    tenantId: string,
    options?: { gracePeriodMs?: number }
  ): Promise<Result<ApiKeyWithSecret, Error>> {
    // 1. Look up the existing key to copy its configuration
    const existingResult = await this.findById(id, tenantId);
    if (!existingResult.ok) return existingResult as Result<ApiKeyWithSecret, Error>;
    if (!existingResult.value) {
      return Result.err(new Error('API key not found'));
    }
    const existing = existingResult.value;

    // 2. Create the replacement key, inheriting all settings
    const createResult = await this.create({
      tenantId,
      userId: existing.userId ?? undefined,
      name: `${existing.name} (rotated)`,
      scopes: existing.scopes,
      rateLimit: existing.rateLimit,
      allowedIps: existing.allowedIps ?? undefined,
      allowedDomains: existing.allowedDomains ?? undefined,
      expiresAt: existing.expiresAt ?? undefined,
      metadata: {
        ...existing.metadata,
        rotatedFromKeyId: id,
        rotatedAt: new Date().toISOString(),
      },
    });
    if (!createResult.ok) return createResult;

    // 3. Retire the old key — either immediately or after a grace period
    if (options?.gracePeriodMs && options.gracePeriodMs > 0) {
      const expiresAt = new Date(Date.now() + options.gracePeriodMs);
      const updateResult = await this.update(id, { expiresAt }, tenantId);
      if (!updateResult.ok) {
        this.logger.warn('Failed to set grace-period expiry on old key during rotation', {
          oldKeyId: id,
          newKeyId: createResult.value.id,
          error: updateResult.error.message,
        });
        // Non-fatal: the new key was already created; worst case the old key
        // stays active with its original expiry.
      } else {
        this.logger.info('API key rotated with grace period', {
          oldKeyId: id,
          newKeyId: createResult.value.id,
          gracePeriodMs: options.gracePeriodMs,
        });
      }
    } else {
      // No grace period — revoke immediately
      const revokeResult = await this.revoke(id, tenantId);
      if (!revokeResult.ok) {
        this.logger.warn('Failed to revoke old key during rotation', {
          oldKeyId: id,
          newKeyId: createResult.value.id,
          error: revokeResult.error.message,
        });
      } else {
        this.logger.info('API key rotated (old key revoked immediately)', {
          oldKeyId: id,
          newKeyId: createResult.value.id,
        });
      }
    }

    return createResult;
  }

  async revoke(id: string, tenantId?: string): Promise<Result<void, Error>> {
    // FIX-008: Enforce tenant isolation — prevent cross-tenant key revocation
    const sql = tenantId
      ? `UPDATE api_keys SET is_active = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2`
      : `UPDATE api_keys SET is_active = false, updated_at = NOW() WHERE id = $1`;
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query(sql, params);

    if (result.ok) {
      // E-146: Audit trail for API key revocation
      this.logger.info('API key revoked', {
        apiKeyId: id,
        tenantId: tenantId ?? 'unknown',
      });
    }

    return result.ok ? Result.ok(undefined) : result;
  }

  async delete(id: string, tenantId?: string): Promise<Result<void, Error>> {
    // FIX-008: Enforce tenant isolation — prevent cross-tenant key deletion
    const sql = tenantId
      ? 'DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2'
      : 'DELETE FROM api_keys WHERE id = $1';
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query(sql, params);
    return result.ok ? Result.ok(undefined) : result;
  }

  async listByTenant(
    tenantId: string,
    options: { includeInactive?: boolean; limit?: number; offset?: number } = {}
  ): Promise<Result<{ apiKeys: ApiKey[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (!options.includeInactive) {
      conditions.push('is_active = true');
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM api_keys ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM api_keys ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      apiKeys: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async listByUser(userId: string): Promise<Result<ApiKey[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      name: string;
      prefix: string;
      key_hash: string;
      scopes: ApiKeyScope[];
      rate_limit: number;
      allowed_ips: string[] | null;
      allowed_domains: string[] | null;
      expires_at: Date | null;
      last_used_at: Date | null;
      last_used_ip: string | null;
      usage_count: number;
      is_active: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM api_keys WHERE user_id = $1 AND is_active = true ORDER BY created_at DESC`,
      [userId]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async cleanupExpired(): Promise<Result<number, Error>> {
    // Don't delete, just deactivate expired keys
    const result = await this.db.query<{ count: string }>(
      `WITH updated AS (
        UPDATE api_keys 
        SET is_active = false, updated_at = NOW()
        WHERE expires_at < NOW() AND is_active = true
        RETURNING 1
      ) SELECT COUNT(*) as count FROM updated`
    );

    if (!result.ok) return result;

    return Result.ok(parseInt(result.value.rows[0]?.count ?? '0', 10));
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    user_id: string | null;
    name: string;
    prefix: string;
    key_hash: string;
    scopes: ApiKeyScope[];
    rate_limit: number;
    allowed_ips: string[] | null;
    allowed_domains: string[] | null;
    expires_at: Date | null;
    last_used_at: Date | null;
    last_used_ip: string | null;
    usage_count: number;
    is_active: boolean;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): ApiKey {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      name: row.name,
      prefix: row.prefix,
      keyHash: row.key_hash,
      scopes: row.scopes,
      rateLimit: row.rate_limit,
      allowedIps: row.allowed_ips,
      allowedDomains: row.allowed_domains,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at,
      lastUsedIp: row.last_used_ip,
      usageCount: row.usage_count,
      isActive: row.is_active,
      metadata: typeof row.metadata === 'string'
        ? JSON.parse(row.metadata) as Record<string, unknown>
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
