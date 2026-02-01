/**
 * Sub-Account Service
 * 
 * Agency and reseller sub-account management
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config, EnterprisePlan } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum SubAccountStatus {
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  PENDING = 'pending',
  DELETED = 'deleted',
}

export interface SubAccount {
  id: string;
  parentAccountId: string;
  name: string;
  slug: string;
  email: string;
  status: SubAccountStatus;
  volumeLimit: number;
  volumeUsed: number;
  settings: SubAccountSettings;
  createdAt: Date;
  updatedAt: Date;
}

export interface SubAccountSettings {
  inheritParentDomains: boolean;
  inheritParentTemplates: boolean;
  inheritParentSuppressions: boolean;
  customDomains: string[];
  apiKeyPrefix?: string;
  webhookUrl?: string;
  notificationEmails: string[];
}

export interface SubAccountStats {
  id: string;
  name: string;
  emailsSent: number;
  emailsDelivered: number;
  emailsBounced: number;
  emailsOpened: number;
  emailsClicked: number;
  volumeUsed: number;
  volumeLimit: number;
  volumePercentage: number;
}

export interface VolumeAllocation {
  subAccountId: string;
  allocatedVolume: number;
  usedVolume: number;
  remainingVolume: number;
  periodStart: Date;
  periodEnd: Date;
}

export interface SubAccountAPIKey {
  id: string;
  subAccountId: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  scopes: string[];
  expiresAt?: Date;
  createdAt: Date;
  lastUsedAt?: Date;
}

/**
 * Sub-Account Service for agency/reseller management
 */
export class SubAccountService {
  private pool: Pool;
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Create a new sub-account
   */
  async createSubAccount(
    parentAccountId: string,
    data: {
      name: string;
      slug: string;
      email: string;
      volumeLimit?: number;
      settings?: Partial<SubAccountSettings>;
    }
  ): Promise<Result<SubAccount>> {
    try {
      // Check sub-account limit
      const countResult = await this.pool.query(`
        SELECT COUNT(*) as count FROM ent_sub_accounts
        WHERE parent_account_id = $1 AND status != 'deleted'
      `, [parentAccountId]);

      if (parseInt(countResult.rows[0].count, 10) >= config.subAccounts.maxSubAccounts) {
        return {
          ok: false,
          error: new Error(`Maximum sub-account limit (${config.subAccounts.maxSubAccounts}) reached`),
        };
      }

      // Check slug uniqueness
      const slugCheck = await this.pool.query(`
        SELECT id FROM ent_sub_accounts
        WHERE parent_account_id = $1 AND slug = $2 AND status != 'deleted'
      `, [parentAccountId, data.slug]);

      if (slugCheck.rows.length > 0) {
        return { ok: false, error: new Error('Sub-account slug already exists') };
      }

      const id = uuidv4();
      const settings: SubAccountSettings = {
        inheritParentDomains: config.subAccounts.inheritParentSettings,
        inheritParentTemplates: config.subAccounts.inheritParentSettings,
        inheritParentSuppressions: config.subAccounts.inheritParentSettings,
        customDomains: [],
        notificationEmails: [data.email],
        ...data.settings,
      };

      const result = await this.pool.query(`
        INSERT INTO ent_sub_accounts (
          id, parent_account_id, name, slug, email, status,
          volume_limit, volume_used, settings, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, NOW(), NOW())
        RETURNING *
      `, [
        id,
        parentAccountId,
        data.name,
        data.slug,
        data.email,
        SubAccountStatus.ACTIVE,
        data.volumeLimit || 0,
        JSON.stringify(settings),
      ]);

      const row = result.rows[0];
      return {
        ok: true,
        value: this.rowToSubAccount(row),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get sub-account by ID
   */
  async getSubAccount(id: string): Promise<Result<SubAccount | null>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_sub_accounts WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return { ok: true, value: this.rowToSubAccount(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List sub-accounts for parent
   */
  async listSubAccounts(
    parentAccountId: string,
    includeDeleted: boolean = false
  ): Promise<Result<SubAccount[]>> {
    try {
      let query = `
        SELECT * FROM ent_sub_accounts
        WHERE parent_account_id = $1
      `;

      if (!includeDeleted) {
        query += ` AND status != 'deleted'`;
      }

      query += ' ORDER BY created_at DESC';

      const result = await this.pool.query(query, [parentAccountId]);

      return {
        ok: true,
        value: result.rows.map(row => this.rowToSubAccount(row)),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Update sub-account
   */
  async updateSubAccount(
    id: string,
    updates: Partial<{
      name: string;
      email: string;
      status: SubAccountStatus;
      volumeLimit: number;
      settings: Partial<SubAccountSettings>;
    }>
  ): Promise<Result<SubAccount>> {
    try {
      // Get current sub-account
      const current = await this.getSubAccount(id);
      if (!current.ok) return { ok: false, error: current.error };
      if (!current.value) {
        return { ok: false, error: new Error('Sub-account not found') };
      }

      const mergedSettings = updates.settings
        ? { ...current.value.settings, ...updates.settings }
        : current.value.settings;

      const result = await this.pool.query(`
        UPDATE ent_sub_accounts SET
          name = COALESCE($2, name),
          email = COALESCE($3, email),
          status = COALESCE($4, status),
          volume_limit = COALESCE($5, volume_limit),
          settings = $6,
          updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `, [
        id,
        updates.name,
        updates.email,
        updates.status,
        updates.volumeLimit,
        JSON.stringify(mergedSettings),
      ]);

      return { ok: true, value: this.rowToSubAccount(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Suspend sub-account
   */
  async suspendSubAccount(id: string, reason?: string): Promise<Result<void>> {
    try {
      await this.pool.query(`
        UPDATE ent_sub_accounts SET
          status = $2,
          suspended_reason = $3,
          suspended_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `, [id, SubAccountStatus.SUSPENDED, reason]);

      // Invalidate API keys
      await this.redis.del(`subaccount:keys:${id}`);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Delete sub-account (soft delete)
   */
  async deleteSubAccount(id: string): Promise<Result<void>> {
    try {
      await this.pool.query(`
        UPDATE ent_sub_accounts SET
          status = $2,
          deleted_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `, [id, SubAccountStatus.DELETED]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get aggregate statistics for all sub-accounts
   */
  async getAggregateStats(
    parentAccountId: string,
    startDate: Date,
    endDate: Date
  ): Promise<Result<SubAccountStats[]>> {
    try {
      const result = await this.pool.query(`
        SELECT 
          s.id,
          s.name,
          COALESCE(stats.emails_sent, 0) as emails_sent,
          COALESCE(stats.emails_delivered, 0) as emails_delivered,
          COALESCE(stats.emails_bounced, 0) as emails_bounced,
          COALESCE(stats.emails_opened, 0) as emails_opened,
          COALESCE(stats.emails_clicked, 0) as emails_clicked,
          s.volume_used,
          s.volume_limit
        FROM ent_sub_accounts s
        LEFT JOIN (
          SELECT 
            sub_account_id,
            SUM(CASE WHEN event_type = 'sent' THEN 1 ELSE 0 END) as emails_sent,
            SUM(CASE WHEN event_type = 'delivered' THEN 1 ELSE 0 END) as emails_delivered,
            SUM(CASE WHEN event_type = 'bounced' THEN 1 ELSE 0 END) as emails_bounced,
            SUM(CASE WHEN event_type = 'opened' THEN 1 ELSE 0 END) as emails_opened,
            SUM(CASE WHEN event_type = 'clicked' THEN 1 ELSE 0 END) as emails_clicked
          FROM ent_sub_account_events
          WHERE created_at BETWEEN $2 AND $3
          GROUP BY sub_account_id
        ) stats ON s.id = stats.sub_account_id
        WHERE s.parent_account_id = $1 AND s.status != 'deleted'
        ORDER BY stats.emails_sent DESC NULLS LAST
      `, [parentAccountId, startDate, endDate]);

      return {
        ok: true,
        value: result.rows.map(row => ({
          id: row.id,
          name: row.name,
          emailsSent: parseInt(row.emails_sent, 10),
          emailsDelivered: parseInt(row.emails_delivered, 10),
          emailsBounced: parseInt(row.emails_bounced, 10),
          emailsOpened: parseInt(row.emails_opened, 10),
          emailsClicked: parseInt(row.emails_clicked, 10),
          volumeUsed: row.volume_used,
          volumeLimit: row.volume_limit,
          volumePercentage: row.volume_limit > 0 
            ? Math.round((row.volume_used / row.volume_limit) * 100)
            : 0,
        })),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Allocate volume to sub-account
   */
  async allocateVolume(
    subAccountId: string,
    volume: number,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<VolumeAllocation>> {
    try {
      const result = await this.pool.query(`
        INSERT INTO ent_volume_allocations (
          id, sub_account_id, allocated_volume, used_volume,
          period_start, period_end, created_at
        ) VALUES ($1, $2, $3, 0, $4, $5, NOW())
        ON CONFLICT (sub_account_id, period_start) DO UPDATE SET
          allocated_volume = $3
        RETURNING *
      `, [uuidv4(), subAccountId, volume, periodStart, periodEnd]);

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          subAccountId: row.sub_account_id,
          allocatedVolume: row.allocated_volume,
          usedVolume: row.used_volume,
          remainingVolume: row.allocated_volume - row.used_volume,
          periodStart: row.period_start,
          periodEnd: row.period_end,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Track volume usage
   */
  async trackVolumeUsage(subAccountId: string, count: number = 1): Promise<Result<void>> {
    try {
      // Update sub-account volume
      await this.pool.query(`
        UPDATE ent_sub_accounts SET
          volume_used = volume_used + $2,
          updated_at = NOW()
        WHERE id = $1
      `, [subAccountId, count]);

      // Update current period allocation
      await this.pool.query(`
        UPDATE ent_volume_allocations SET
          used_volume = used_volume + $2
        WHERE sub_account_id = $1
        AND period_start <= NOW()
        AND period_end >= NOW()
      `, [subAccountId, count]);

      // Update Redis counter
      const dateKey = new Date().toISOString().split('T')[0];
      await this.redis.hincrby(`subaccount:volume:${subAccountId}`, dateKey, count);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Check if sub-account has remaining volume
   */
  async checkVolumeLimit(subAccountId: string): Promise<Result<{ allowed: boolean; remaining: number }>> {
    try {
      const result = await this.pool.query(`
        SELECT volume_limit, volume_used FROM ent_sub_accounts
        WHERE id = $1
      `, [subAccountId]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Sub-account not found') };
      }

      const { volume_limit, volume_used } = result.rows[0];

      // If no limit set (0), allow unlimited
      if (volume_limit === 0) {
        return { ok: true, value: { allowed: true, remaining: -1 } };
      }

      const remaining = volume_limit - volume_used;
      return {
        ok: true,
        value: {
          allowed: remaining > 0,
          remaining: Math.max(0, remaining),
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Create API key for sub-account
   */
  async createAPIKey(
    subAccountId: string,
    name: string,
    scopes: string[],
    expiresAt?: Date
  ): Promise<Result<{ key: string; apiKey: SubAccountAPIKey }>> {
    try {
      const id = uuidv4();
      const rawKey = `sak_${uuidv4().replace(/-/g, '')}`;
      const keyPrefix = rawKey.substring(0, 12);
      const keyHash = require('crypto').createHash('sha256').update(rawKey).digest('hex');

      await this.pool.query(`
        INSERT INTO ent_sub_account_api_keys (
          id, sub_account_id, name, key_prefix, key_hash,
          scopes, expires_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      `, [id, subAccountId, name, keyPrefix, keyHash, scopes, expiresAt]);

      const apiKey: SubAccountAPIKey = {
        id,
        subAccountId,
        name,
        keyPrefix,
        keyHash,
        scopes,
        expiresAt,
        createdAt: new Date(),
      };

      // Invalidate cache
      await this.redis.del(`subaccount:keys:${subAccountId}`);

      return {
        ok: true,
        value: { key: rawKey, apiKey },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Validate sub-account API key
   */
  async validateAPIKey(key: string): Promise<Result<{ subAccountId: string; scopes: string[] } | null>> {
    try {
      const keyHash = require('crypto').createHash('sha256').update(key).digest('hex');

      const result = await this.pool.query(`
        SELECT k.*, s.status as account_status
        FROM ent_sub_account_api_keys k
        JOIN ent_sub_accounts s ON k.sub_account_id = s.id
        WHERE k.key_hash = $1
        AND (k.expires_at IS NULL OR k.expires_at > NOW())
        AND s.status = 'active'
      `, [keyHash]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const row = result.rows[0];

      // Update last used
      await this.pool.query(`
        UPDATE ent_sub_account_api_keys SET last_used_at = NOW() WHERE id = $1
      `, [row.id]);

      return {
        ok: true,
        value: {
          subAccountId: row.sub_account_id,
          scopes: row.scopes,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Record sub-account event
   */
  async recordEvent(
    subAccountId: string,
    eventType: string,
    messageId?: string,
    metadata?: Record<string, any>
  ): Promise<Result<void>> {
    try {
      await this.pool.query(`
        INSERT INTO ent_sub_account_events (
          id, sub_account_id, event_type, message_id, metadata, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
      `, [uuidv4(), subAccountId, eventType, messageId, JSON.stringify(metadata || {})]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  private rowToSubAccount(row: any): SubAccount {
    return {
      id: row.id,
      parentAccountId: row.parent_account_id,
      name: row.name,
      slug: row.slug,
      email: row.email,
      status: row.status as SubAccountStatus,
      volumeLimit: row.volume_limit,
      volumeUsed: row.volume_used,
      settings: row.settings,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
