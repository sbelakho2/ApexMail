/**
 * Tenant Service
 * 
 * Core tenant/workspace management:
 * - Organization management
 * - Workspace provisioning
 * - Tenant lifecycle management
 * - Isolation level management
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config, IsolationLevel, QuotaConfig } from '../config.js';

export enum TenantStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  DEACTIVATED = 'deactivated',
  DELETED = 'deleted',
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  billingEmail: string;
  plan: string;
  status: TenantStatus;
  isolationLevel: IsolationLevel;
  metadata: Record<string, unknown>;
  settings: OrgSettings;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrgSettings {
  defaultWorkspaceQuota: QuotaConfig;
  ssoEnabled: boolean;
  ssoProvider?: string;
  ssoConfig?: Record<string, unknown>;
  enforceMfa: boolean;
  allowedDomains: string[];
  ipWhitelist: string[];
  dataRetentionDays: number;
  auditLogEnabled: boolean;
}

export interface Workspace {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  status: TenantStatus;
  schemaName: string | null;
  databaseName: string | null;
  quota: QuotaConfig;
  usage: WorkspaceUsage;
  settings: WorkspaceSettings;
  createdAt: Date;
  updatedAt: Date;
}

export interface WorkspaceUsage {
  emailsSentThisMonth: number;
  storageUsedBytes: number;
  apiRequestsThisMinute: number;
  webhooksSentThisMonth: number;
  contactsCount: number;
  templatesCount: number;
  domainsCount: number;
}

export interface WorkspaceSettings {
  timezone: string;
  locale: string;
  defaultFromEmail: string;
  defaultFromName: string;
  trackOpens: boolean;
  trackClicks: boolean;
  customBranding: boolean;
  webhookEnabled: boolean;
}

export interface TenantUser {
  id: string;
  organizationId: string;
  workspaceIds: string[];
  email: string;
  role: TenantRole;
  status: 'active' | 'invited' | 'suspended';
  permissions: string[];
  lastActiveAt: Date | null;
  createdAt: Date;
}

export enum TenantRole {
  OWNER = 'owner',
  ADMIN = 'admin',
  MEMBER = 'member',
  VIEWER = 'viewer',
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class TenantService {
  private db: Pool;
  private redis: Redis;
  private orgCache: Map<string, Organization> = new Map();
  private workspaceCache: Map<string, Workspace> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
  }

  // ==================== Organization Management ====================

  /**
   * Create a new organization
   */
  async createOrganization(data: {
    name: string;
    slug: string;
    billingEmail: string;
    plan?: string;
    isolationLevel?: IsolationLevel;
    ownerId: string;
  }): Promise<Result<Organization>> {
    const id = uuidv4();
    const now = new Date();

    // Validate slug uniqueness
    const existingSlug = await this.db.query(
      'SELECT id FROM iso_organizations WHERE slug = $1',
      [data.slug]
    );
    if (existingSlug.rows.length > 0) {
      return { ok: false, error: new Error('Organization slug already exists') };
    }

    const settings: OrgSettings = {
      defaultWorkspaceQuota: config.tenant.defaultQuota,
      ssoEnabled: false,
      enforceMfa: false,
      allowedDomains: [],
      ipWhitelist: [],
      dataRetentionDays: 365,
      auditLogEnabled: true,
    };

    const org: Organization = {
      id,
      name: data.name,
      slug: data.slug,
      billingEmail: data.billingEmail,
      plan: data.plan || 'free',
      status: TenantStatus.ACTIVE,
      isolationLevel: data.isolationLevel || IsolationLevel.SHARED,
      metadata: {},
      settings,
      createdAt: now,
      updatedAt: now,
    };

    try {
      await this.db.query('BEGIN');

      // Create organization
      await this.db.query(`
        INSERT INTO iso_organizations (
          id, name, slug, billing_email, plan, status, isolation_level,
          metadata, settings, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      `, [
        id, data.name, data.slug, data.billingEmail, org.plan, org.status,
        org.isolationLevel, JSON.stringify(org.metadata), JSON.stringify(settings),
        now, now,
      ]);

      // Create owner membership
      await this.db.query(`
        INSERT INTO iso_org_members (id, organization_id, user_id, role, status, created_at)
        VALUES ($1, $2, $3, $4, 'active', $5)
      `, [uuidv4(), id, data.ownerId, TenantRole.OWNER, now]);

      // Set up isolation based on level
      if (org.isolationLevel === IsolationLevel.DEDICATED_SCHEMA) {
        await this.createDedicatedSchema(id);
      }

      await this.db.query('COMMIT');

      // Log audit event
      await this.logAuditEvent({
        organizationId: id,
        action: 'organization.created',
        actorId: data.ownerId,
        details: { name: data.name, plan: org.plan },
      });

      this.orgCache.set(id, org);

      console.log(`[Tenant] Created organization: ${data.name} (${id})`);

      return { ok: true, value: org };
    } catch (error) {
      await this.db.query('ROLLBACK');
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get organization by ID
   */
  async getOrganization(id: string): Promise<Result<Organization>> {
    // Check cache
    if (this.orgCache.has(id)) {
      return { ok: true, value: this.orgCache.get(id)! };
    }

    try {
      const result = await this.db.query(
        'SELECT * FROM iso_organizations WHERE id = $1',
        [id]
      );

      if (result.rows.length === 0) {
        return { ok: false, error: new Error(`Organization not found: ${id}`) };
      }

      const org = this.rowToOrganization(result.rows[0]);
      this.orgCache.set(id, org);

      return { ok: true, value: org };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update organization
   */
  async updateOrganization(id: string, updates: Partial<Organization>): Promise<Result<Organization>> {
    const existing = await this.getOrganization(id);
    if (!existing.ok) return existing;

    const updated: Organization = {
      ...existing.value,
      ...updates,
      id,
      createdAt: existing.value.createdAt,
      updatedAt: new Date(),
    };

    try {
      await this.db.query(`
        UPDATE iso_organizations SET
          name = $2, billing_email = $3, plan = $4, status = $5,
          metadata = $6, settings = $7, updated_at = $8
        WHERE id = $1
      `, [
        id, updated.name, updated.billingEmail, updated.plan, updated.status,
        JSON.stringify(updated.metadata), JSON.stringify(updated.settings),
        updated.updatedAt,
      ]);

      this.orgCache.set(id, updated);

      return { ok: true, value: updated };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Suspend organization
   */
  async suspendOrganization(id: string, reason: string, actorId: string): Promise<Result<void>> {
    try {
      await this.db.query('BEGIN');

      // Update organization status
      await this.db.query(`
        UPDATE iso_organizations SET status = $2, updated_at = $3 WHERE id = $1
      `, [id, TenantStatus.SUSPENDED, new Date()]);

      // Suspend all workspaces
      await this.db.query(`
        UPDATE iso_workspaces SET status = $2, updated_at = $3 WHERE organization_id = $1
      `, [id, TenantStatus.SUSPENDED, new Date()]);

      await this.db.query('COMMIT');

      // Clear caches
      this.orgCache.delete(id);
      for (const [key, ws] of this.workspaceCache.entries()) {
        if (ws.organizationId === id) {
          this.workspaceCache.delete(key);
        }
      }

      // Log audit event
      await this.logAuditEvent({
        organizationId: id,
        action: 'organization.suspended',
        actorId,
        details: { reason },
      });

      console.log(`[Tenant] Suspended organization: ${id}`);

      return { ok: true, value: undefined };
    } catch (error) {
      await this.db.query('ROLLBACK');
      return { ok: false, error: error as Error };
    }
  }

  // ==================== Workspace Management ====================

  /**
   * Create a workspace
   */
  async createWorkspace(data: {
    organizationId: string;
    name: string;
    slug: string;
    creatorId: string;
    quota?: Partial<QuotaConfig>;
  }): Promise<Result<Workspace>> {
    // Get organization
    const orgResult = await this.getOrganization(data.organizationId);
    if (!orgResult.ok) return { ok: false, error: orgResult.error };

    const org = orgResult.value;

    // Check workspace limit
    const countResult = await this.db.query(
      'SELECT COUNT(*) as count FROM iso_workspaces WHERE organization_id = $1',
      [data.organizationId]
    );
    const currentCount = parseInt(countResult.rows[0].count);
    if (currentCount >= config.tenant.maxWorkspacesPerOrg) {
      return { ok: false, error: new Error('Maximum workspace limit reached') };
    }

    // Validate slug uniqueness within org
    const existingSlug = await this.db.query(
      'SELECT id FROM iso_workspaces WHERE organization_id = $1 AND slug = $2',
      [data.organizationId, data.slug]
    );
    if (existingSlug.rows.length > 0) {
      return { ok: false, error: new Error('Workspace slug already exists in this organization') };
    }

    const id = uuidv4();
    const now = new Date();

    const quota: QuotaConfig = {
      ...org.settings.defaultWorkspaceQuota,
      ...data.quota,
    };

    const usage: WorkspaceUsage = {
      emailsSentThisMonth: 0,
      storageUsedBytes: 0,
      apiRequestsThisMinute: 0,
      webhooksSentThisMonth: 0,
      contactsCount: 0,
      templatesCount: 0,
      domainsCount: 0,
    };

    const settings: WorkspaceSettings = {
      timezone: 'UTC',
      locale: 'en-US',
      defaultFromEmail: '',
      defaultFromName: '',
      trackOpens: true,
      trackClicks: true,
      customBranding: false,
      webhookEnabled: true,
    };

    let schemaName: string | null = null;
    let databaseName: string | null = null;

    // Set up isolation based on org level
    if (org.isolationLevel === IsolationLevel.DEDICATED_SCHEMA) {
      schemaName = `ws_${id.replace(/-/g, '_')}`;
    } else if (org.isolationLevel === IsolationLevel.DEDICATED_DATABASE) {
      databaseName = `apexmail_ws_${id.replace(/-/g, '_')}`;
    }

    const workspace: Workspace = {
      id,
      organizationId: data.organizationId,
      name: data.name,
      slug: data.slug,
      status: TenantStatus.ACTIVE,
      schemaName,
      databaseName,
      quota,
      usage,
      settings,
      createdAt: now,
      updatedAt: now,
    };

    try {
      await this.db.query('BEGIN');

      // Create workspace record
      await this.db.query(`
        INSERT INTO iso_workspaces (
          id, organization_id, name, slug, status, schema_name, database_name,
          quota, usage, settings, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        id, data.organizationId, data.name, data.slug, TenantStatus.ACTIVE,
        schemaName, databaseName, JSON.stringify(quota), JSON.stringify(usage),
        JSON.stringify(settings), now, now,
      ]);

      // Add creator as workspace member
      await this.db.query(`
        INSERT INTO iso_workspace_members (id, workspace_id, user_id, role, created_at)
        VALUES ($1, $2, $3, $4, $5)
      `, [uuidv4(), id, data.creatorId, TenantRole.ADMIN, now]);

      // Create schema/database if needed
      if (schemaName) {
        await this.createWorkspaceSchema(schemaName);
      }

      await this.db.query('COMMIT');

      // Log audit event
      await this.logAuditEvent({
        organizationId: data.organizationId,
        workspaceId: id,
        action: 'workspace.created',
        actorId: data.creatorId,
        details: { name: data.name },
      });

      this.workspaceCache.set(id, workspace);

      console.log(`[Tenant] Created workspace: ${data.name} (${id})`);

      return { ok: true, value: workspace };
    } catch (error) {
      await this.db.query('ROLLBACK');
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get workspace by ID
   */
  async getWorkspace(id: string): Promise<Result<Workspace>> {
    // Check cache
    if (this.workspaceCache.has(id)) {
      return { ok: true, value: this.workspaceCache.get(id)! };
    }

    try {
      const result = await this.db.query(
        'SELECT * FROM iso_workspaces WHERE id = $1',
        [id]
      );

      if (result.rows.length === 0) {
        return { ok: false, error: new Error(`Workspace not found: ${id}`) };
      }

      const workspace = this.rowToWorkspace(result.rows[0]);
      this.workspaceCache.set(id, workspace);

      return { ok: true, value: workspace };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update workspace
   */
  async updateWorkspace(id: string, updates: Partial<Workspace>): Promise<Result<Workspace>> {
    const existing = await this.getWorkspace(id);
    if (!existing.ok) return existing;

    const updated: Workspace = {
      ...existing.value,
      ...updates,
      id,
      organizationId: existing.value.organizationId,
      createdAt: existing.value.createdAt,
      updatedAt: new Date(),
    };

    try {
      await this.db.query(`
        UPDATE iso_workspaces SET
          name = $2, status = $3, quota = $4, settings = $5, updated_at = $6
        WHERE id = $1
      `, [
        id, updated.name, updated.status, JSON.stringify(updated.quota),
        JSON.stringify(updated.settings), updated.updatedAt,
      ]);

      this.workspaceCache.set(id, updated);

      return { ok: true, value: updated };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete workspace
   */
  async deleteWorkspace(id: string, actorId: string): Promise<Result<void>> {
    const workspace = await this.getWorkspace(id);
    if (!workspace.ok) return workspace;

    try {
      await this.db.query('BEGIN');

      // Mark as deleted
      await this.db.query(`
        UPDATE iso_workspaces SET status = $2, updated_at = $3 WHERE id = $1
      `, [id, TenantStatus.DELETED, new Date()]);

      // Schedule schema cleanup if applicable
      if (workspace.value.schemaName) {
        await this.db.query(`
          INSERT INTO iso_cleanup_queue (id, type, target_id, schema_name, scheduled_at)
          VALUES ($1, 'schema', $2, $3, NOW() + INTERVAL '30 days')
        `, [uuidv4(), id, workspace.value.schemaName]);
      }

      await this.db.query('COMMIT');

      // Clear cache
      this.workspaceCache.delete(id);

      // Log audit event
      await this.logAuditEvent({
        organizationId: workspace.value.organizationId,
        workspaceId: id,
        action: 'workspace.deleted',
        actorId,
        details: {},
      });

      console.log(`[Tenant] Deleted workspace: ${id}`);

      return { ok: true, value: undefined };
    } catch (error) {
      await this.db.query('ROLLBACK');
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List workspaces for organization
   */
  async listWorkspaces(organizationId: string): Promise<Result<Workspace[]>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM iso_workspaces
        WHERE organization_id = $1 AND status != 'deleted'
        ORDER BY created_at DESC
      `, [organizationId]);

      const workspaces = result.rows.map(row => this.rowToWorkspace(row));

      return { ok: true, value: workspaces };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // ==================== Usage Tracking ====================

  /**
   * Update workspace usage
   */
  async updateUsage(workspaceId: string, usageUpdate: Partial<WorkspaceUsage>): Promise<Result<void>> {
    try {
      const workspace = await this.getWorkspace(workspaceId);
      if (!workspace.ok) return workspace;

      const newUsage: WorkspaceUsage = {
        ...workspace.value.usage,
        ...usageUpdate,
      };

      await this.db.query(`
        UPDATE iso_workspaces SET usage = $2, updated_at = $3 WHERE id = $1
      `, [workspaceId, JSON.stringify(newUsage), new Date()]);

      // Update cache
      workspace.value.usage = newUsage;
      this.workspaceCache.set(workspaceId, workspace.value);

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Increment usage counter
   */
  async incrementUsage(workspaceId: string, metric: keyof WorkspaceUsage, amount: number = 1): Promise<Result<void>> {
    const workspace = await this.getWorkspace(workspaceId);
    if (!workspace.ok) return workspace;

    const current = workspace.value.usage[metric] as number;
    return this.updateUsage(workspaceId, { [metric]: current + amount });
  }

  /**
   * Check quota
   */
  async checkQuota(workspaceId: string, metric: keyof QuotaConfig, amount: number = 1): Promise<Result<boolean>> {
    const workspace = await this.getWorkspace(workspaceId);
    if (!workspace.ok) return workspace;

    const usageKey = this.quotaToUsageKey(metric);
    const currentUsage = workspace.value.usage[usageKey] as number;
    const limit = workspace.value.quota[metric];

    const allowed = currentUsage + amount <= limit;

    return { ok: true, value: allowed };
  }

  // ==================== Member Management ====================

  /**
   * Add member to workspace
   */
  async addWorkspaceMember(workspaceId: string, userId: string, role: TenantRole, inviterId: string): Promise<Result<void>> {
    const workspace = await this.getWorkspace(workspaceId);
    if (!workspace.ok) return workspace;

    // Check member limit
    const countResult = await this.db.query(
      'SELECT COUNT(*) as count FROM iso_workspace_members WHERE workspace_id = $1',
      [workspaceId]
    );
    const currentCount = parseInt(countResult.rows[0].count);
    if (currentCount >= config.tenant.maxUsersPerWorkspace) {
      return { ok: false, error: new Error('Maximum member limit reached') };
    }

    try {
      await this.db.query(`
        INSERT INTO iso_workspace_members (id, workspace_id, user_id, role, created_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = $4
      `, [uuidv4(), workspaceId, userId, role, new Date()]);

      // Log audit event
      await this.logAuditEvent({
        organizationId: workspace.value.organizationId,
        workspaceId,
        action: 'member.added',
        actorId: inviterId,
        details: { userId, role },
      });

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Remove member from workspace
   */
  async removeWorkspaceMember(workspaceId: string, userId: string, removerId: string): Promise<Result<void>> {
    const workspace = await this.getWorkspace(workspaceId);
    if (!workspace.ok) return workspace;

    try {
      await this.db.query(`
        DELETE FROM iso_workspace_members WHERE workspace_id = $1 AND user_id = $2
      `, [workspaceId, userId]);

      // Log audit event
      await this.logAuditEvent({
        organizationId: workspace.value.organizationId,
        workspaceId,
        action: 'member.removed',
        actorId: removerId,
        details: { userId },
      });

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Check member access
   */
  async checkMemberAccess(workspaceId: string, userId: string): Promise<Result<{ hasAccess: boolean; role?: TenantRole }>> {
    try {
      const result = await this.db.query(`
        SELECT role FROM iso_workspace_members
        WHERE workspace_id = $1 AND user_id = $2
      `, [workspaceId, userId]);

      if (result.rows.length === 0) {
        return { ok: true, value: { hasAccess: false } };
      }

      return {
        ok: true,
        value: {
          hasAccess: true,
          role: result.rows[0].role,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // ==================== Private Methods ====================

  private async createDedicatedSchema(orgId: string): Promise<void> {
    const schemaName = `org_${orgId.replace(/-/g, '_')}`;
    await this.db.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
    // Would create org-level tables in this schema
  }

  private async createWorkspaceSchema(schemaName: string): Promise<void> {
    await this.db.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
    
    // Create workspace-specific tables
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS "${schemaName}".emails (
        id VARCHAR(64) PRIMARY KEY,
        subject TEXT,
        body TEXT,
        status VARCHAR(32),
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS "${schemaName}".contacts (
        id VARCHAR(64) PRIMARY KEY,
        email VARCHAR(255),
        name VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS "${schemaName}".templates (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(255),
        content TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  }

  private async logAuditEvent(event: {
    organizationId: string;
    workspaceId?: string;
    action: string;
    actorId: string;
    details: Record<string, unknown>;
  }): Promise<void> {
    try {
      await this.db.query(`
        INSERT INTO iso_audit_logs (id, organization_id, workspace_id, action, actor_id, details, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        uuidv4(),
        event.organizationId,
        event.workspaceId || null,
        event.action,
        event.actorId,
        JSON.stringify(event.details),
        new Date(),
      ]);
    } catch (error) {
      console.error('[Tenant] Failed to log audit event:', error);
    }
  }

  private quotaToUsageKey(quotaKey: keyof QuotaConfig): keyof WorkspaceUsage {
    const mapping: Record<keyof QuotaConfig, keyof WorkspaceUsage> = {
      emailsPerMonth: 'emailsSentThisMonth',
      storageBytes: 'storageUsedBytes',
      apiRequestsPerMinute: 'apiRequestsThisMinute',
      webhooksPerMonth: 'webhooksSentThisMonth',
      contactsLimit: 'contactsCount',
      templatesLimit: 'templatesCount',
      domainsLimit: 'domainsCount',
    };
    return mapping[quotaKey];
  }

  private rowToOrganization(row: Record<string, unknown>): Organization {
    return {
      id: row.id as string,
      name: row.name as string,
      slug: row.slug as string,
      billingEmail: row.billing_email as string,
      plan: row.plan as string,
      status: row.status as TenantStatus,
      isolationLevel: row.isolation_level as IsolationLevel,
      metadata: (row.metadata as Record<string, unknown>) || {},
      settings: (row.settings as OrgSettings) || {},
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    };
  }

  private rowToWorkspace(row: Record<string, unknown>): Workspace {
    return {
      id: row.id as string,
      organizationId: row.organization_id as string,
      name: row.name as string,
      slug: row.slug as string,
      status: row.status as TenantStatus,
      schemaName: row.schema_name as string | null,
      databaseName: row.database_name as string | null,
      quota: (row.quota as QuotaConfig) || config.tenant.defaultQuota,
      usage: (row.usage as WorkspaceUsage) || {
        emailsSentThisMonth: 0,
        storageUsedBytes: 0,
        apiRequestsThisMinute: 0,
        webhooksSentThisMonth: 0,
        contactsCount: 0,
        templatesCount: 0,
        domainsCount: 0,
      },
      settings: (row.settings as WorkspaceSettings) || {},
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    };
  }
}
