/**
 * Domains Repository
 */

import { Result } from '@apexmail/lib';
import { generateUuid, generateDomainVerificationToken } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';

export interface Domain {
  id: string;
  tenantId: string;
  domain: string;
  status: 'pending' | 'verified' | 'failed' | 'expired';
  verificationToken: string;
  verificationMethod: 'dns_txt' | 'dns_cname' | 'meta_tag';
  verifiedAt: Date | null;
  expiresAt: Date | null;
  dnsRecords: DnsRecords;
  healthStatus: DnsHealthStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface DnsRecords {
  spf?: { value: string; verified: boolean; lastChecked?: Date };
  dkim?: { selector: string; value: string; verified: boolean; lastChecked?: Date };
  dmarc?: { value: string; verified: boolean; lastChecked?: Date };
  mx?: { value: string; verified: boolean; lastChecked?: Date };
  returnPath?: { value: string; verified: boolean; lastChecked?: Date };
}

export interface DnsHealthStatus {
  overall: 'healthy' | 'warning' | 'critical' | 'unknown';
  issues: string[];
  lastChecked: Date | null;
}

export interface CreateDomainInput {
  tenantId: string;
  domain: string;
  verificationMethod?: Domain['verificationMethod'];
}

export interface UpdateDomainInput {
  status?: Domain['status'];
  verifiedAt?: Date | null;
  dnsRecords?: Partial<DnsRecords>;
  healthStatus?: DnsHealthStatus;
}

export class DomainsRepository {
  constructor(private readonly db: DatabasePool) {}

  async create(input: CreateDomainInput): Promise<Result<Domain, Error>> {
    const id = generateUuid();
    const verificationToken = generateDomainVerificationToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 72 * 60 * 60 * 1000); // 72 hours

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO domains (id, tenant_id, domain, status, verification_token, 
                            verification_method, expires_at, dns_records, health_status,
                            created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        id,
        input.tenantId,
        input.domain.toLowerCase(),
        'pending',
        verificationToken,
        input.verificationMethod ?? 'dns_txt',
        expiresAt,
        JSON.stringify({}),
        JSON.stringify({ overall: 'unknown', issues: [], lastChecked: null }),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to create domain'));
    }

    return Result.ok(this.mapRow(row));
  }

  async findById(id: string): Promise<Result<Domain | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM domains WHERE id = $1',
      [id]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByDomain(domain: string, tenantId: string): Promise<Result<Domain | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM domains WHERE domain = $1 AND tenant_id = $2',
      [domain.toLowerCase(), tenantId]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async update(id: string, input: UpdateDomainInput): Promise<Result<Domain, Error>> {
    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(input.status);
    }
    if (input.verifiedAt !== undefined) {
      updates.push(`verified_at = $${paramIndex++}`);
      values.push(input.verifiedAt);
    }
    if (input.dnsRecords !== undefined) {
      updates.push(`dns_records = dns_records || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.dnsRecords));
    }
    if (input.healthStatus !== undefined) {
      updates.push(`health_status = $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.healthStatus));
    }

    updates.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE domains SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Domain not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  async verify(id: string): Promise<Result<Domain, Error>> {
    return this.update(id, {
      status: 'verified',
      verifiedAt: new Date(),
    });
  }

  async markExpired(id: string): Promise<Result<void, Error>> {
    const result = await this.db.query(
      `UPDATE domains SET status = 'expired', updated_at = NOW() WHERE id = $1`,
      [id]
    );
    return result.ok ? Result.ok(undefined) : result;
  }

  async delete(id: string): Promise<Result<void, Error>> {
    const result = await this.db.query(
      'DELETE FROM domains WHERE id = $1',
      [id]
    );
    return result.ok ? Result.ok(undefined) : result;
  }

  async listByTenant(
    tenantId: string,
    options: { status?: Domain['status']; limit?: number; offset?: number } = {}
  ): Promise<Result<{ domains: Domain[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.status) {
      conditions.push(`status = $${paramIndex++}`);
      values.push(options.status);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM domains ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM domains ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      domains: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async listVerified(tenantId: string): Promise<Result<Domain[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM domains WHERE tenant_id = $1 AND status = 'verified' ORDER BY domain`,
      [tenantId]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async listPendingExpiring(): Promise<Result<Domain[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM domains 
       WHERE status = 'pending' AND expires_at < NOW()
       ORDER BY expires_at`
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async listNeedingHealthCheck(olderThanMinutes: number): Promise<Result<Domain[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      domain: string;
      status: Domain['status'];
      verification_token: string;
      verification_method: Domain['verificationMethod'];
      verified_at: Date | null;
      expires_at: Date | null;
      dns_records: string;
      health_status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM domains 
       WHERE status = 'verified' 
         AND (health_status->>'lastChecked' IS NULL 
              OR (health_status->>'lastChecked')::timestamptz < NOW() - INTERVAL '1 minute' * $1)
       ORDER BY RANDOM()
       LIMIT 100`,
      [olderThanMinutes]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    domain: string;
    status: Domain['status'];
    verification_token: string;
    verification_method: Domain['verificationMethod'];
    verified_at: Date | null;
    expires_at: Date | null;
    dns_records: string;
    health_status: string;
    created_at: Date;
    updated_at: Date;
  }): Domain {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      domain: row.domain,
      status: row.status,
      verificationToken: row.verification_token,
      verificationMethod: row.verification_method,
      verifiedAt: row.verified_at,
      expiresAt: row.expires_at,
      dnsRecords: typeof row.dns_records === 'string'
        ? JSON.parse(row.dns_records) as DnsRecords
        : row.dns_records as unknown as DnsRecords,
      healthStatus: typeof row.health_status === 'string'
        ? JSON.parse(row.health_status) as DnsHealthStatus
        : row.health_status as unknown as DnsHealthStatus,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
