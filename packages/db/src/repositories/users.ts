/**
 * Users Repository
 */

import { Result, createLogger } from '@apexmail/lib';
import { generateUserId } from '@apexmail/lib/id';
import { hashPassword, verifyPassword } from '@apexmail/lib/crypto';
import type { DatabasePool } from '../pool.js';

const logger = createLogger({ name: 'users-repository' });

export interface User {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  status: 'active' | 'invited' | 'disabled';
  emailVerified: boolean;
  lastLoginAt: Date | null;
  mfaEnabled: boolean;
  preferences: Record<string, unknown>; // Stored in metadata.preferences
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  tenantId: string;
  email: string;
  name: string;
  password: string;
  role?: User['role'];
}

export interface UpdateUserInput {
  name?: string;
  role?: User['role'];
  status?: User['status'];
  emailVerified?: boolean;
  mfaEnabled?: boolean;
  lastLoginAt?: Date;
  preferences?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export class UsersRepository {
  constructor(private readonly db: DatabasePool) {}

  async create(input: CreateUserInput): Promise<Result<User, Error>> {
    const id = generateUserId();
    const passwordHash = await hashPassword(input.password);
    const now = new Date();

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, 
                          email_verified, mfa_enabled, metadata, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (email, tenant_id) DO NOTHING
       RETURNING id, tenant_id, email, name, role, status, email_verified, 
                 last_login_at, mfa_enabled, metadata, created_at, updated_at`,
      [
        id,
        input.tenantId,
        input.email.toLowerCase(),
        input.name,
        passwordHash,
        input.role ?? 'member',
        'active',
        false,
        false,
        JSON.stringify({}),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      // B-048: ON CONFLICT (email, tenant_id) DO NOTHING produces no rows
      return Result.err(new Error(`User with email '${input.email.toLowerCase()}' already exists in this tenant`));
    }

    return Result.ok(this.mapRow(row));
  }

  async findById(id: string, tenantId?: string): Promise<Result<User | null, Error>> {
    const sql = tenantId
      ? `SELECT id, tenant_id, email, name, role, status, email_verified,
              last_login_at, mfa_enabled, metadata, created_at, updated_at
         FROM users WHERE id = $1 AND tenant_id = $2`
      : `SELECT id, tenant_id, email, name, role, status, email_verified,
              last_login_at, mfa_enabled, metadata, created_at, updated_at
         FROM users WHERE id = $1`;
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(sql, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByEmail(email: string, tenantId?: string): Promise<Result<User | null, Error>> {
    const query = tenantId
      ? `SELECT id, tenant_id, email, name, role, status, email_verified,
                last_login_at, mfa_enabled, metadata, created_at, updated_at
         FROM users WHERE email = $1 AND tenant_id = $2`
      : `SELECT id, tenant_id, email, name, role, status, email_verified,
                last_login_at, mfa_enabled, metadata, created_at, updated_at
         FROM users WHERE email = $1`;

    const params = tenantId ? [email.toLowerCase(), tenantId] : [email.toLowerCase()];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(query, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async verifyCredentials(email: string, password: string, tenantId?: string): Promise<Result<User | null, Error>> {
    // A-002: When tenantId is provided, scope the query to prevent cross-tenant login
    const sql = tenantId
      ? `SELECT * FROM users WHERE email = $1 AND status = 'active' AND tenant_id = $2`
      : `SELECT * FROM users WHERE email = $1 AND status = 'active'`;
    const params = tenantId ? [email.toLowerCase(), tenantId] : [email.toLowerCase()];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      password_hash: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(sql, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.ok(null);
    }

    const valid = await verifyPassword(password, row.password_hash);
    if (!valid) {
      return Result.ok(null);
    }

    // Update last login (fire-and-forget but log errors — E-139)
    this.db.query(
      'UPDATE users SET last_login_at = NOW() WHERE id = $1',
      [row.id]
    ).then((res) => {
      if (!res.ok) {
        logger.error('Failed to update last login', { error: (res.error as Error).message, userId: row.id });
      }
    }).catch((err: unknown) => {
      logger.error('Failed to update last login', { error: err instanceof Error ? err.message : String(err), userId: row.id });
    });

    return Result.ok(this.mapRow(row));
  }

  async update(id: string, input: UpdateUserInput, tenantId?: string): Promise<Result<User, Error>> {
    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }
    if (input.role !== undefined) {
      updates.push(`role = $${paramIndex++}`);
      values.push(input.role);
    }
    if (input.status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(input.status);
    }
    if (input.emailVerified !== undefined) {
      updates.push(`email_verified = $${paramIndex++}`);
      values.push(input.emailVerified);
    }
    if (input.mfaEnabled !== undefined) {
      updates.push(`mfa_enabled = $${paramIndex++}`);
      values.push(input.mfaEnabled);
    }
    if (input.lastLoginAt !== undefined) {
      updates.push(`last_login_at = $${paramIndex++}`);
      values.push(input.lastLoginAt);
    }
    if (input.preferences !== undefined) {
      // Store preferences inside metadata.preferences
      updates.push(`metadata = jsonb_set(COALESCE(metadata, '{}'), '{preferences}', $${paramIndex++}::jsonb)`);
      values.push(JSON.stringify(input.preferences));
    }
    if (input.metadata !== undefined) {
      updates.push(`metadata = metadata || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.metadata));
    }

    updates.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);
    const whereClause = tenantId
      ? `WHERE id = $${paramIndex++} AND tenant_id = $${paramIndex}`
      : `WHERE id = $${paramIndex}`;
    if (tenantId) values.push(tenantId);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE users SET ${updates.join(', ')} ${whereClause}
       RETURNING id, tenant_id, email, name, role, status, email_verified,
                 last_login_at, mfa_enabled, metadata, created_at, updated_at`,
      values
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('User not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  async updatePassword(id: string, newPassword: string, tenantId?: string): Promise<Result<void, Error>> {
    const passwordHash = await hashPassword(newPassword);
    const sql = tenantId
      ? 'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3'
      : 'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2';
    const params = tenantId ? [passwordHash, id, tenantId] : [passwordHash, id];
    const result = await this.db.query(sql, params);
    return result.ok ? Result.ok(undefined) : result;
  }

  async listByTenant(
    tenantId: string,
    options: { limit?: number; offset?: number } = {}
  ): Promise<Result<{ users: User[]; total: number }, Error>> {
    const countResult = await this.db.query<{ count: string }>(
      'SELECT COUNT(*) as count FROM users WHERE tenant_id = $1',
      [tenantId]
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, tenant_id, email, name, role, status, email_verified,
              last_login_at, mfa_enabled, metadata, created_at, updated_at
       FROM users WHERE tenant_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset]
    );

    if (!result.ok) return result;

    return Result.ok({
      users: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async checkDeadManSwitch(thresholdDays: number): Promise<Result<User[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      email: string;
      name: string;
      role: User['role'];
      status: User['status'];
      email_verified: boolean;
      last_login_at: Date | null;
      mfa_enabled: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, tenant_id, email, name, role, status, email_verified,
              last_login_at, mfa_enabled, metadata, created_at, updated_at
       FROM users 
       WHERE role = 'owner' 
         AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '1 day' * $1)`,
      [thresholdDays]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    email: string;
    name: string;
    role: User['role'];
    status: User['status'];
    email_verified: boolean;
    last_login_at: Date | null;
    mfa_enabled: boolean;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): User {
    const metadata = typeof row.metadata === 'string'
      ? JSON.parse(row.metadata) as Record<string, unknown>
      : row.metadata as unknown as Record<string, unknown>;
    
    // Extract preferences from metadata if present
    const preferences = (metadata.preferences ?? {}) as Record<string, unknown>;
    
    return {
      id: row.id,
      tenantId: row.tenant_id,
      email: row.email,
      name: row.name,
      role: row.role,
      status: row.status,
      emailVerified: row.email_verified,
      lastLoginAt: row.last_login_at,
      mfaEnabled: row.mfa_enabled,
      preferences,
      metadata,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
