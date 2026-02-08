/**
 * Tenants Repository
 */

import { Result, parseJsonOrDefault } from '@apexmail/lib';
import { generateTenantId } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';
import { withTransaction } from '../transaction.js';

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan: 'free' | 'growth' | 'scale' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  settings: TenantSettings;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface TenantSettings {
  defaultFromEmail?: string;
  defaultFromName?: string;
  webhookUrl?: string;
  webhookSecret?: string;
  customTrackingDomain?: string;
  dataResidency?: 'eu' | 'us' | 'auto';
  retentionDays?: number;
  legalHold?: boolean;
}

export interface CreateTenantInput {
  name: string;
  slug: string;
  plan?: Tenant['plan'];
  settings?: Partial<TenantSettings>;
  metadata?: Record<string, unknown>;
}

export interface UpdateTenantInput {
  name?: string;
  plan?: Tenant['plan'];
  status?: Tenant['status'];
  settings?: Partial<TenantSettings>;
  metadata?: Record<string, unknown>;
}

export class TenantsRepository {
  constructor(private readonly db: DatabasePool) {}

  async create(input: CreateTenantInput): Promise<Result<Tenant, Error>> {
    const id = generateTenantId();
    const now = new Date();

    const result = await this.db.query<{
      id: string;
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        id,
        input.name,
        input.slug,
        input.plan ?? 'free',
        'pending',
        JSON.stringify(input.settings ?? {}),
        JSON.stringify(input.metadata ?? {}),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to create tenant'));
    }

    return Result.ok(this.mapRow(row));
  }

  async findById(id: string): Promise<Result<Tenant | null, Error>> {
    const result = await this.db.query<{
      id: string;
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM tenants WHERE id = $1',
      [id]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findBySlug(slug: string): Promise<Result<Tenant | null, Error>> {
    const result = await this.db.query<{
      id: string;
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM tenants WHERE slug = $1',
      [slug]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async update(id: string, input: UpdateTenantInput): Promise<Result<Tenant, Error>> {
    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }
    if (input.plan !== undefined) {
      updates.push(`plan = $${paramIndex++}`);
      values.push(input.plan);
    }
    if (input.status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(input.status);
    }
    if (input.settings !== undefined) {
      updates.push(`settings = settings || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.settings));
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
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE tenants SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Tenant not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  async suspend(id: string, reason: string): Promise<Result<void, Error>> {
    return withTransaction(this.db, async (ctx) => {
      await ctx.client.query(
        `UPDATE tenants SET status = 'suspended', updated_at = NOW(),
         metadata = metadata || $2::jsonb
         WHERE id = $1`,
        [id, JSON.stringify({ suspendedReason: reason, suspendedAt: new Date().toISOString() })]
      );
    });
  }

  // FIX-500-251: Add RETURNING + rowCount check
  async activate(id: string): Promise<Result<void, Error>> {
    const result = await this.db.query(
      `UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1 RETURNING id`,
      [id]
    );
    if (!result.ok) return result;
    if (result.value.rowCount === 0) {
      return Result.err(new Error(`Tenant ${id} not found`));
    }
    return Result.ok(undefined);
  }

  // FIX-500-252: Add RETURNING id + rowCount check
  async setLegalHold(id: string, enabled: boolean): Promise<Result<void, Error>> {
    const result = await this.db.query(
      `UPDATE tenants 
       SET settings = jsonb_set(settings, '{legalHold}', $2::jsonb),
           updated_at = NOW()
       WHERE id = $1 RETURNING id`,
      [id, JSON.stringify(enabled)]
    );
    if (!result.ok) return result;
    if (result.value.rowCount === 0) {
      return Result.err(new Error(`Tenant ${id} not found`));
    }
    return Result.ok(undefined);
  }

  async list(options: {
    limit?: number;
    offset?: number;
    status?: Tenant['status'];
    plan?: Tenant['plan'];
  } = {}): Promise<Result<{ tenants: Tenant[]; total: number }, Error>> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (options.status) {
      conditions.push(`status = $${paramIndex++}`);
      values.push(options.status);
    }
    if (options.plan) {
      conditions.push(`plan = $${paramIndex++}`);
      values.push(options.plan);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM tenants ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM tenants ${whereClause} 
       ORDER BY created_at DESC 
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    type TenantRow = {
      id: string;
      name: string;
      slug: string;
      plan: Tenant['plan'];
      status: Tenant['status'];
      settings: string;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    };

    return Result.ok({
      tenants: (result.value.rows as TenantRow[]).map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  private mapRow(row: {
    id: string;
    name: string;
    slug: string;
    plan: Tenant['plan'];
    status: Tenant['status'];
    settings: string;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): Tenant {
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      plan: row.plan,
      status: row.status,
      settings: typeof row.settings === 'string' 
        ? parseJsonOrDefault<TenantSettings>(row.settings, {} as TenantSettings)
        : row.settings as unknown as TenantSettings,
      metadata: typeof row.metadata === 'string'
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
