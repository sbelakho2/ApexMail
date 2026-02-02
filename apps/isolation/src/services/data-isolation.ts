/**
 * Data Isolation Service
 * 
 * Enforces data isolation between tenants:
 * - Row-level security
 * - Schema isolation
 * - Query filtering
 * - Cross-tenant access prevention
 */

import { Pool, PoolClient } from 'pg';
import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { IsolationLevel } from '../config.js';

export interface IsolationContext {
  organizationId: string;
  workspaceId: string;
  userId: string;
  isolationLevel: IsolationLevel;
  schemaName?: string;
  permissions: string[];
}

export interface IsolatedQuery {
  text: string;
  values: unknown[];
  schemaName?: string;
}

export interface DataAccessPolicy {
  id: string;
  name: string;
  resource: string;
  conditions: PolicyCondition[];
  actions: ('read' | 'write' | 'delete')[];
  effect: 'allow' | 'deny';
}

export interface PolicyCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'in' | 'not_in' | 'contains' | 'starts_with';
  value: unknown;
}

export class DataIsolationService {
  private db: Pool;
  private redis: Redis;
  private policies: Map<string, DataAccessPolicy[]> = new Map();
  // @ts-expect-error - reserved for future schema isolation
  private _schemaConnections: Map<string, Pool> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.loadPolicies();
  }

  /**
   * Validate schema name to prevent SQL injection
   */
  private validateSchemaName(schemaName: string): boolean {
    // Only allow alphanumeric, underscores, and must start with a letter or underscore
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(schemaName);
  }

  /**
   * Create an isolated database connection for a workspace
   */
  async getIsolatedConnection(context: IsolationContext): Promise<Result<PoolClient>> {
    try {
      const client = await this.db.connect();

      // Set session variables for RLS
      await client.query(`SET app.current_organization_id = $1`, [context.organizationId]);
      await client.query(`SET app.current_workspace_id = $1`, [context.workspaceId]);
      await client.query(`SET app.current_user_id = $1`, [context.userId]);

      // Set schema search path if using schema isolation
      if (context.isolationLevel === IsolationLevel.DEDICATED_SCHEMA && context.schemaName) {
        // Validate schema name to prevent SQL injection
        if (!this.validateSchemaName(context.schemaName)) {
          client.release();
          return { ok: false, error: new Error('Invalid schema name') };
        }
        await client.query(`SET search_path TO "${context.schemaName}", public`);
      }

      return { ok: true, value: client };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Execute a query with tenant isolation
   */
  async executeIsolatedQuery<T>(
    context: IsolationContext,
    query: string,
    values: unknown[] = []
  ): Promise<Result<T[]>> {
    const connectionResult = await this.getIsolatedConnection(context);
    if (!connectionResult.ok) return connectionResult;

    const client = connectionResult.value;

    try {
      // Transform query to add tenant filters
      const isolatedQuery = this.addTenantFilters(query, context);
      
      const result = await client.query(isolatedQuery.text, [...isolatedQuery.values, ...values]);
      
      return { ok: true, value: result.rows as T[] };
    } catch (error) {
      return { ok: false, error: error as Error };
    } finally {
      client.release();
    }
  }

  /**
   * Validate that a query doesn't access other tenants' data
   */
  validateQueryAccess(query: string, _context: IsolationContext): Result<boolean> {
    const normalizedQuery = query.toLowerCase();

    // Check for dangerous patterns
    const dangerousPatterns = [
      /information_schema/i,
      /pg_catalog/i,
      /pg_tables/i,
      /\bset\s+search_path/i,
      /\bset\s+role/i,
      /\bset\s+session/i,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(normalizedQuery)) {
        return { ok: false, error: new Error('Query contains forbidden patterns') };
      }
    }

    // Verify all table references have tenant context
    const tablePattern = /(?:from|join|update|insert\s+into|delete\s+from)\s+(\w+)/gi;
    const tables = [...normalizedQuery.matchAll(tablePattern)].map(m => m[1]);
    
    // These tables must always be filtered by workspace_id or organization_id
    const tenantedTables = ['emails', 'contacts', 'templates', 'campaigns', 'webhooks', 'api_keys'];
    
    for (const table of tables) {
      if (table && tenantedTables.includes(table)) {
        // Check if query includes workspace_id or organization_id filter
        const hasFilter = normalizedQuery.includes('workspace_id') || 
                         normalizedQuery.includes('organization_id');
        if (!hasFilter) {
          return { ok: false, error: new Error(`Query must filter ${table} by tenant`) };
        }
      }
    }

    return { ok: true, value: true };
  }

  /**
   * Check if a user can access a resource
   */
  async checkResourceAccess(
    context: IsolationContext,
    resource: string,
    resourceId: string,
    action: 'read' | 'write' | 'delete'
  ): Promise<Result<boolean>> {
    // Check if resource belongs to the workspace
    const ownershipResult = await this.verifyResourceOwnership(
      context,
      resource,
      resourceId
    );
    if (!ownershipResult.ok) return ownershipResult;
    if (!ownershipResult.value) {
      return { ok: true, value: false };
    }

    // Check policies
    const policies = this.policies.get(resource) || [];
    
    for (const policy of policies) {
      if (!policy.actions.includes(action)) continue;

      const matches = await this.evaluatePolicyConditions(context, policy.conditions);
      
      if (matches) {
        return { ok: true, value: policy.effect === 'allow' };
      }
    }

    // Default deny
    return { ok: true, value: false };
  }

  /**
   * Validate and sanitize SQL identifier (table/schema name)
   * Prevents SQL injection by only allowing alphanumeric chars and underscores
   */
  private sanitizeIdentifier(identifier: string): string {
    // Only allow alphanumeric characters and underscores
    const sanitized = identifier.replace(/[^a-zA-Z0-9_]/g, '');
    
    // Ensure it doesn't start with a number
    if (/^\d/.test(sanitized)) {
      throw new Error(`Invalid identifier: ${identifier} - cannot start with a number`);
    }
    
    // Ensure it's not empty after sanitization
    if (sanitized.length === 0) {
      throw new Error(`Invalid identifier: ${identifier} - contains no valid characters`);
    }
    
    // Limit length to prevent abuse
    if (sanitized.length > 63) {
      throw new Error(`Invalid identifier: ${identifier} - exceeds maximum length of 63 characters`);
    }
    
    return sanitized;
  }

  /**
   * Create row-level security policies for a table
   */
  async setupRLS(tableName: string, schemaName: string = 'public'): Promise<Result<void>> {
    try {
      // SECURITY: Sanitize identifiers to prevent SQL injection
      const safeTableName = this.sanitizeIdentifier(tableName);
      const safeSchemaName = this.sanitizeIdentifier(schemaName);
      
      // Validate the identifiers match (no characters were stripped)
      if (safeTableName !== tableName || safeSchemaName !== schemaName) {
        return { 
          ok: false, 
          error: new Error(`Invalid table or schema name: contains disallowed characters`) 
        };
      }

      // Enable RLS
      await this.db.query(`
        ALTER TABLE "${safeSchemaName}"."${safeTableName}" ENABLE ROW LEVEL SECURITY
      `);

      // Force RLS for table owner
      await this.db.query(`
        ALTER TABLE "${safeSchemaName}"."${safeTableName}" FORCE ROW LEVEL SECURITY
      `);

      // Create select policy
      await this.db.query(`
        CREATE POLICY "${safeTableName}_select_policy" ON "${safeSchemaName}"."${safeTableName}"
        FOR SELECT
        USING (
          workspace_id = current_setting('app.current_workspace_id', true)::VARCHAR
          OR organization_id = current_setting('app.current_organization_id', true)::VARCHAR
        )
      `);

      // Create insert policy
      await this.db.query(`
        CREATE POLICY "${safeTableName}_insert_policy" ON "${safeSchemaName}"."${safeTableName}"
        FOR INSERT
        WITH CHECK (
          workspace_id = current_setting('app.current_workspace_id', true)::VARCHAR
        )
      `);

      // Create update policy
      await this.db.query(`
        CREATE POLICY "${safeTableName}_update_policy" ON "${safeSchemaName}"."${safeTableName}"
        FOR UPDATE
        USING (
          workspace_id = current_setting('app.current_workspace_id', true)::VARCHAR
        )
      `);

      // Create delete policy
      await this.db.query(`
        CREATE POLICY "${safeTableName}_delete_policy" ON "${safeSchemaName}"."${safeTableName}"
        FOR DELETE
        USING (
          workspace_id = current_setting('app.current_workspace_id', true)::VARCHAR
        )
      `);

      console.log(`[Isolation] Set up RLS for ${safeSchemaName}.${safeTableName}`);

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Migrate workspace to a new isolation level
   */
  async migrateIsolationLevel(
    workspaceId: string,
    currentLevel: IsolationLevel,
    targetLevel: IsolationLevel
  ): Promise<Result<void>> {
    console.log(`[Isolation] Migrating workspace ${workspaceId} from ${currentLevel} to ${targetLevel}`);

    try {
      await this.db.query('BEGIN');

      if (currentLevel === IsolationLevel.SHARED && targetLevel === IsolationLevel.DEDICATED_SCHEMA) {
        await this.migrateToSchema(workspaceId);
      } else if (currentLevel === IsolationLevel.DEDICATED_SCHEMA && targetLevel === IsolationLevel.SHARED) {
        await this.migrateFromSchema(workspaceId);
      }

      await this.db.query('COMMIT');

      console.log(`[Isolation] Migration complete for workspace ${workspaceId}`);

      return { ok: true, value: undefined };
    } catch (error) {
      await this.db.query('ROLLBACK');
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Audit cross-tenant access attempts
   */
  async auditAccessAttempt(
    context: IsolationContext,
    targetWorkspaceId: string,
    resource: string,
    action: string,
    allowed: boolean
  ): Promise<void> {
    const isCrossTenant = context.workspaceId !== targetWorkspaceId;

    if (isCrossTenant || !allowed) {
      await this.db.query(`
        INSERT INTO iso_access_audit_logs (
          id, organization_id, workspace_id, user_id, target_workspace_id,
          resource, action, allowed, is_cross_tenant, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        `audit_${Date.now()}`,
        context.organizationId,
        context.workspaceId,
        context.userId,
        targetWorkspaceId,
        resource,
        action,
        allowed,
        isCrossTenant,
        new Date(),
      ]);

      if (isCrossTenant && !allowed) {
        // Publish security alert
        await this.redis.publish('security:alerts', JSON.stringify({
          type: 'cross_tenant_access_attempt',
          severity: 'high',
          context,
          targetWorkspaceId,
          resource,
          action,
          timestamp: new Date().toISOString(),
        }));
      }
    }
  }

  // ==================== Private Methods ====================

  private async loadPolicies(): Promise<void> {
    try {
      const result = await this.db.query('SELECT * FROM iso_access_policies WHERE enabled = true');
      
      for (const row of result.rows) {
        const policy: DataAccessPolicy = {
          id: row.id,
          name: row.name,
          resource: row.resource,
          conditions: row.conditions || [],
          actions: row.actions || [],
          effect: row.effect,
        };

        if (!this.policies.has(policy.resource)) {
          this.policies.set(policy.resource, []);
        }
        this.policies.get(policy.resource)!.push(policy);
      }
    } catch (error) {
      console.warn('[Isolation] Could not load policies:', error);
    }
  }

  private addTenantFilters(query: string, context: IsolationContext): IsolatedQuery {
    const normalizedQuery = query.trim().toLowerCase();
    let modifiedQuery = query;
    const additionalValues: unknown[] = [];
    let valueIndex = 1;

    // For SELECT queries, add WHERE clause if not present
    if (normalizedQuery.startsWith('select')) {
      if (!normalizedQuery.includes('where')) {
        // Find position after FROM clause
        const fromMatch = query.match(/\bFROM\s+\w+/i);
        if (fromMatch) {
          const insertPos = (fromMatch.index ?? 0) + fromMatch[0].length;
          modifiedQuery = 
            query.slice(0, insertPos) + 
            ` WHERE workspace_id = $${valueIndex++}` + 
            query.slice(insertPos);
          additionalValues.push(context.workspaceId);
        }
      } else {
        // Add to existing WHERE clause
        const wherePos = normalizedQuery.indexOf('where') + 5;
        modifiedQuery = 
          query.slice(0, wherePos) + 
          ` workspace_id = $${valueIndex++} AND` + 
          query.slice(wherePos);
        additionalValues.push(context.workspaceId);
      }
    }

    // For INSERT queries, ensure workspace_id is included
    if (normalizedQuery.startsWith('insert')) {
      // This would be more complex in a real implementation
      // Would need to parse the column list and add workspace_id
    }

    return {
      text: modifiedQuery,
      values: additionalValues,
      schemaName: context.schemaName,
    };
  }

  private async verifyResourceOwnership(
    context: IsolationContext,
    resource: string,
    resourceId: string
  ): Promise<Result<boolean>> {
    const tableMap: Record<string, string> = {
      email: 'emails',
      contact: 'contacts',
      template: 'templates',
      campaign: 'campaigns',
      domain: 'domains',
    };

    const tableName = tableMap[resource];
    if (!tableName) {
      return { ok: false, error: new Error(`Unknown resource type: ${resource}`) };
    }

    try {
      const result = await this.db.query(`
        SELECT id FROM ${tableName}
        WHERE id = $1 AND workspace_id = $2
      `, [resourceId, context.workspaceId]);

      return { ok: true, value: result.rows.length > 0 };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private async evaluatePolicyConditions(
    context: IsolationContext,
    conditions: PolicyCondition[]
  ): Promise<boolean> {
    for (const condition of conditions) {
      const contextValue = this.getContextValue(context, condition.field);
      
      let matches = false;
      switch (condition.operator) {
        case 'equals':
          matches = contextValue === condition.value;
          break;
        case 'not_equals':
          matches = contextValue !== condition.value;
          break;
        case 'in':
          matches = Array.isArray(condition.value) && condition.value.includes(contextValue);
          break;
        case 'not_in':
          matches = Array.isArray(condition.value) && !condition.value.includes(contextValue);
          break;
        case 'contains':
          matches = typeof contextValue === 'string' && 
                   typeof condition.value === 'string' &&
                   contextValue.includes(condition.value);
          break;
        case 'starts_with':
          matches = typeof contextValue === 'string' && 
                   typeof condition.value === 'string' &&
                   contextValue.startsWith(condition.value);
          break;
      }

      if (!matches) return false;
    }

    return true;
  }

  private getContextValue(context: IsolationContext, field: string): unknown {
    const fieldMap: Record<string, unknown> = {
      'organization_id': context.organizationId,
      'workspace_id': context.workspaceId,
      'user_id': context.userId,
      'isolation_level': context.isolationLevel,
      'permissions': context.permissions,
    };

    return fieldMap[field];
  }

  private async migrateToSchema(workspaceId: string): Promise<void> {
    const schemaName = `ws_${workspaceId.replace(/-/g, '_')}`;

    // Create schema
    await this.db.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);

    // Create tables in new schema
    const tables = ['emails', 'contacts', 'templates', 'campaigns', 'webhooks'];
    
    for (const table of tables) {
      // Copy structure
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS "${schemaName}"."${table}" 
        (LIKE public."${table}" INCLUDING ALL)
      `);

      // Copy data
      await this.db.query(`
        INSERT INTO "${schemaName}"."${table}"
        SELECT * FROM public."${table}" WHERE workspace_id = $1
      `, [workspaceId]);

      // Delete from shared table
      await this.db.query(`
        DELETE FROM public."${table}" WHERE workspace_id = $1
      `, [workspaceId]);
    }

    // Update workspace record
    await this.db.query(`
      UPDATE iso_workspaces SET schema_name = $2 WHERE id = $1
    `, [workspaceId, schemaName]);
  }

  private async migrateFromSchema(workspaceId: string): Promise<void> {
    const result = await this.db.query(
      'SELECT schema_name FROM iso_workspaces WHERE id = $1',
      [workspaceId]
    );
    
    const schemaName = result.rows[0]?.schema_name;
    if (!schemaName) return;

    const tables = ['emails', 'contacts', 'templates', 'campaigns', 'webhooks'];

    for (const table of tables) {
      // Copy data back to shared table
      await this.db.query(`
        INSERT INTO public."${table}"
        SELECT * FROM "${schemaName}"."${table}"
      `);
    }

    // Drop schema
    await this.db.query(`DROP SCHEMA "${schemaName}" CASCADE`);

    // Update workspace record
    await this.db.query(`
      UPDATE iso_workspaces SET schema_name = NULL WHERE id = $1
    `, [workspaceId]);
  }
}
