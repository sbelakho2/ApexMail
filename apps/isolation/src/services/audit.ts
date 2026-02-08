/**
 * Audit Service
 * 
 * Comprehensive audit logging:
 * - Action tracking
 * - Compliance logging
 * - Security events
 * - Data access logging
 */

import { Pool, type PoolClient as _PoolClient } from 'pg';
import type { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { Result, createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'isolation:audit' });

/**
 * Simple hash function for advisory lock IDs
 */
function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash);
}

export enum AuditEventType {
  // Authentication events
  AUTH_LOGIN = 'auth.login',
  AUTH_LOGOUT = 'auth.logout',
  AUTH_FAILED = 'auth.failed',
  AUTH_MFA_ENABLED = 'auth.mfa_enabled',
  AUTH_MFA_DISABLED = 'auth.mfa_disabled',
  AUTH_PASSWORD_CHANGED = 'auth.password_changed',
  AUTH_API_KEY_CREATED = 'auth.api_key_created',
  AUTH_API_KEY_REVOKED = 'auth.api_key_revoked',

  // Organization events
  ORG_CREATED = 'org.created',
  ORG_UPDATED = 'org.updated',
  ORG_SUSPENDED = 'org.suspended',
  ORG_REACTIVATED = 'org.reactivated',
  ORG_DELETED = 'org.deleted',

  // Workspace events
  WORKSPACE_CREATED = 'workspace.created',
  WORKSPACE_UPDATED = 'workspace.updated',
  WORKSPACE_DELETED = 'workspace.deleted',

  // Member events
  MEMBER_INVITED = 'member.invited',
  MEMBER_ADDED = 'member.added',
  MEMBER_REMOVED = 'member.removed',
  MEMBER_ROLE_CHANGED = 'member.role_changed',

  // Data events
  DATA_CREATED = 'data.created',
  DATA_READ = 'data.read',
  DATA_UPDATED = 'data.updated',
  DATA_DELETED = 'data.deleted',
  DATA_EXPORTED = 'data.exported',
  DATA_IMPORTED = 'data.imported',

  // Security events
  SECURITY_PERMISSION_GRANTED = 'security.permission_granted',
  SECURITY_PERMISSION_REVOKED = 'security.permission_revoked',
  SECURITY_ACCESS_DENIED = 'security.access_denied',
  SECURITY_SUSPICIOUS_ACTIVITY = 'security.suspicious_activity',
  SECURITY_RATE_LIMITED = 'security.rate_limited',

  // Billing events
  BILLING_PLAN_CHANGED = 'billing.plan_changed',
  BILLING_PAYMENT_SUCCESS = 'billing.payment_success',
  BILLING_PAYMENT_FAILED = 'billing.payment_failed',

  // Email events
  EMAIL_SENT = 'email.sent',
  EMAIL_FAILED = 'email.failed',
  EMAIL_BOUNCED = 'email.bounced',
  EMAIL_COMPLAINED = 'email.complained',

  // Settings events
  SETTINGS_CHANGED = 'settings.changed',
  WEBHOOK_CONFIGURED = 'webhook.configured',
  DOMAIN_ADDED = 'domain.added',
  DOMAIN_VERIFIED = 'domain.verified',
  DOMAIN_REMOVED = 'domain.removed',
}

export enum AuditSeverity {
  INFO = 'info',
  WARNING = 'warning',
  CRITICAL = 'critical',
}

export interface AuditEvent {
  id: string;
  organizationId: string;
  workspaceId: string | null;
  type: AuditEventType;
  severity: AuditSeverity;
  actorId: string;
  actorType: 'user' | 'system' | 'api_key';
  actorIp: string | null;
  actorUserAgent: string | null;
  resource: string | null;
  resourceId: string | null;
  action: string;
  details: Record<string, unknown>;
  metadata: Record<string, unknown>;
  timestamp: Date;
}

export interface AuditQuery {
  organizationId: string;
  workspaceId?: string;
  types?: AuditEventType[];
  severity?: AuditSeverity;
  actorId?: string;
  resource?: string;
  startTime?: Date;
  endTime?: Date;
  limit?: number;
  offset?: number;
}

export class AuditService {
  private db: Pool;
  private redis: Redis;
  private buffer: AuditEvent[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private bufferSize = 100;
  private flushIntervalMs = 5000;
  // SOC2-002 FIX: Signing key required in all environments (reserved for future signing functionality)
  // @ts-expect-error - Reserved for future audit record signing implementation
  private readonly signingKey: string;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    // SOC2-002 FIX: Require signing key in all environments, not just production
    const key = process.env.AUDIT_SIGNING_KEY;
    if (!key || key.length < 32) {
      throw new Error('AUDIT_SIGNING_KEY must be set and at least 32 characters in all environments');
    }
    this.signingKey = key;
  }

  /**
   * Initialize audit service
   */
  async initialize(): Promise<void> {
    // Start buffer flush interval with error handling
    this.flushInterval = setInterval(() => {
      this.flushBuffer().catch(err => {
        logger.error('[Audit] Buffer flush failed:', { error: err instanceof Error ? err.message : String(err) });
      });
    }, this.flushIntervalMs);

    logger.info('[Audit] Service initialized');
  }

  /**
   * Log an audit event
   */
  async log(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<Result<AuditEvent>> {
    const fullEvent: AuditEvent = {
      ...event,
      id: uuidv4(),
      timestamp: new Date(),
    };

    // Add to buffer
    this.buffer.push(fullEvent);

    // SOC2-003 FIX: Flush synchronously for critical events to prevent data loss on crash
    if (event.severity === AuditSeverity.CRITICAL) {
      // Write critical events immediately with write-ahead logging
      await this.flushBuffer();
      await this.publishRealTimeEvent(fullEvent);
    } else if (this.buffer.length >= this.bufferSize) {
      // Flush if buffer is full for non-critical events
      await this.flushBuffer();
    }

    return { ok: true, value: fullEvent };
  }

  /**
   * Log authentication event
   */
  async logAuth(options: {
    organizationId: string;
    type: AuditEventType;
    actorId: string;
    actorIp?: string;
    actorUserAgent?: string;
    success: boolean;
    details?: Record<string, unknown>;
  }): Promise<Result<AuditEvent>> {
    return this.log({
      organizationId: options.organizationId,
      workspaceId: null,
      type: options.type,
      severity: options.success ? AuditSeverity.INFO : AuditSeverity.WARNING,
      actorId: options.actorId,
      actorType: 'user',
      actorIp: options.actorIp || null,
      actorUserAgent: options.actorUserAgent || null,
      resource: 'auth',
      resourceId: options.actorId,
      action: options.type.split('.')[1] ?? 'unknown',
      details: options.details || {},
      metadata: { success: options.success },
    });
  }

  /**
   * Log data access event
   */
  async logDataAccess(options: {
    organizationId: string;
    workspaceId: string;
    actorId: string;
    actorType: 'user' | 'system' | 'api_key';
    resource: string;
    resourceId: string;
    action: 'create' | 'read' | 'update' | 'delete';
    actorIp?: string;
    details?: Record<string, unknown>;
  }): Promise<Result<AuditEvent>> {
    const typeMap: Record<string, AuditEventType> = {
      create: AuditEventType.DATA_CREATED,
      read: AuditEventType.DATA_READ,
      update: AuditEventType.DATA_UPDATED,
      delete: AuditEventType.DATA_DELETED,
    };

    return this.log({
      organizationId: options.organizationId,
      workspaceId: options.workspaceId,
      type: typeMap[options.action] ?? AuditEventType.DATA_READ,
      severity: AuditSeverity.INFO,
      actorId: options.actorId,
      actorType: options.actorType,
      actorIp: options.actorIp || null,
      actorUserAgent: null,
      resource: options.resource,
      resourceId: options.resourceId,
      action: options.action,
      details: options.details || {},
      metadata: {},
    });
  }

  /**
   * Log security event
   */
  async logSecurity(options: {
    organizationId: string;
    workspaceId?: string;
    type: AuditEventType;
    severity: AuditSeverity;
    actorId: string;
    actorIp?: string;
    details: Record<string, unknown>;
  }): Promise<Result<AuditEvent>> {
    return this.log({
      organizationId: options.organizationId,
      workspaceId: options.workspaceId || null,
      type: options.type,
      severity: options.severity,
      actorId: options.actorId,
      actorType: 'user',
      actorIp: options.actorIp || null,
      actorUserAgent: null,
      resource: 'security',
      resourceId: null,
      action: options.type.split('.')[1] ?? 'unknown',
      details: options.details,
      metadata: {},
    });
  }

  /**
   * AUDIT-001 FIX: Verify hash chain integrity with transaction lock to prevent TOCTOU
   */
  async verifyHashChain(organizationId: string, startTime?: Date, endTime?: Date): Promise<Result<{ valid: boolean; brokenAt?: string }>> {
    const client = await this.db.connect();
    try {
      // Use advisory lock to prevent concurrent verification/modification
      await client.query('SELECT pg_advisory_xact_lock($1)', [hashCode(organizationId)]);
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      let sql = `SELECT id, timestamp, details, metadata FROM iso_audit_logs 
                 WHERE organization_id = $1`;
      const params: unknown[] = [organizationId];
      let paramIndex = 2;

      if (startTime) {
        sql += ` AND timestamp >= $${paramIndex++}`;
        params.push(startTime);
      }
      if (endTime) {
        sql += ` AND timestamp <= $${paramIndex++}`;
        params.push(endTime);
      }
      sql += ' ORDER BY timestamp ASC FOR UPDATE';

      const result = await client.query(sql, params);
      let previousHash = '';

      for (const row of result.rows) {
        const expectedHash = this.computeEventHash(row, previousHash);
        const storedHash = (row.metadata as Record<string, unknown>)?.chainHash as string;
        if (storedHash && storedHash !== expectedHash) {
          await client.query('ROLLBACK');
          return { ok: true, value: { valid: false, brokenAt: row.id } };
        }
        previousHash = expectedHash;
      }

      await client.query('COMMIT');
      return { ok: true, value: { valid: true } };
    } catch (error) {
      await client.query('ROLLBACK');
      return { ok: false, error: error as Error };
    } finally {
      client.release();
    }
  }

  private computeEventHash(event: Record<string, unknown>, previousHash: string): string {
    const data = JSON.stringify({ ...event, previousHash });
    // Use a simple hash for the chain (in production, use crypto)
    return Buffer.from(data).toString('base64').slice(0, 32);
  }

  /**
   * Query audit events
   */
  async query(query: AuditQuery): Promise<Result<{ events: AuditEvent[]; total: number }>> {
    try {
      let whereClause = 'organization_id = $1';
      const params: unknown[] = [query.organizationId];
      let paramIndex = 2;

      if (query.workspaceId) {
        whereClause += ` AND workspace_id = $${paramIndex++}`;
        params.push(query.workspaceId);
      }

      if (query.types && query.types.length > 0) {
        whereClause += ` AND type = ANY($${paramIndex++})`;
        params.push(query.types);
      }

      if (query.severity) {
        whereClause += ` AND severity = $${paramIndex++}`;
        params.push(query.severity);
      }

      if (query.actorId) {
        whereClause += ` AND actor_id = $${paramIndex++}`;
        params.push(query.actorId);
      }

      if (query.resource) {
        whereClause += ` AND resource = $${paramIndex++}`;
        params.push(query.resource);
      }

      if (query.startTime) {
        whereClause += ` AND timestamp >= $${paramIndex++}`;
        params.push(query.startTime);
      }

      if (query.endTime) {
        whereClause += ` AND timestamp <= $${paramIndex++}`;
        params.push(query.endTime);
      }

      // Get total count
      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM iso_audit_logs WHERE ${whereClause}`,
        params
      );

      // Get events
      const result = await this.db.query(`
        SELECT * FROM iso_audit_logs
        WHERE ${whereClause}
        ORDER BY timestamp DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `, [...params, query.limit || 100, query.offset || 0]);

      const events = result.rows.map(row => this.rowToEvent(row));

      return {
        ok: true,
        value: {
          events,
          total: parseInt(countResult.rows[0]?.total ?? '0', 10),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get audit statistics
   */
  async getStats(organizationId: string, days: number = 30): Promise<Result<{
    totalEvents: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    byDay: Array<{ date: string; count: number }>;
    topActors: Array<{ actorId: string; count: number }>;
  }>> {
    const startTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    try {
      // Total events
      const totalResult = await this.db.query(`
        SELECT COUNT(*) as total FROM iso_audit_logs
        WHERE organization_id = $1 AND timestamp >= $2
      `, [organizationId, startTime]);

      // By type
      const typeResult = await this.db.query(`
        SELECT type, COUNT(*) as count FROM iso_audit_logs
        WHERE organization_id = $1 AND timestamp >= $2
        GROUP BY type
      `, [organizationId, startTime]);

      // By severity
      const severityResult = await this.db.query(`
        SELECT severity, COUNT(*) as count FROM iso_audit_logs
        WHERE organization_id = $1 AND timestamp >= $2
        GROUP BY severity
      `, [organizationId, startTime]);

      // By day
      const dayResult = await this.db.query(`
        SELECT DATE(timestamp) as date, COUNT(*) as count FROM iso_audit_logs
        WHERE organization_id = $1 AND timestamp >= $2
        GROUP BY DATE(timestamp)
        ORDER BY date
      `, [organizationId, startTime]);

      // Top actors
      const actorResult = await this.db.query(`
        SELECT actor_id, COUNT(*) as count FROM iso_audit_logs
        WHERE organization_id = $1 AND timestamp >= $2
        GROUP BY actor_id
        ORDER BY count DESC
        LIMIT 10
      `, [organizationId, startTime]);

      const byType: Record<string, number> = {};
      for (const row of typeResult.rows) {
        byType[row.type] = parseInt(row.count);
      }

      const bySeverity: Record<string, number> = {};
      for (const row of severityResult.rows) {
        bySeverity[row.severity] = parseInt(row.count);
      }

      return {
        ok: true,
        value: {
          totalEvents: parseInt(totalResult.rows[0]?.total ?? '0', 10),
          byType,
          bySeverity,
          byDay: dayResult.rows.map(row => ({
            date: row.date.toISOString().split('T')[0],
            count: parseInt(row.count, 10),
          })),
          topActors: actorResult.rows.map(row => ({
            actorId: row.actor_id,
            count: parseInt(row.count, 10),
          })),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Export audit logs
   */
  async export(query: AuditQuery, format: 'json' | 'csv'): Promise<Result<string>> {
    const result = await this.query({ ...query, limit: 10000 });
    if (!result.ok) return result;

    const events = result.value.events;

    if (format === 'json') {
      return { ok: true, value: JSON.stringify(events, null, 2) };
    }

    // CSV format
    const headers = [
      'id', 'timestamp', 'type', 'severity', 'actor_id', 'actor_type',
      'actor_ip', 'resource', 'resource_id', 'action', 'details',
    ];

    const rows = events.map(event => [
      event.id,
      event.timestamp.toISOString(),
      event.type,
      event.severity,
      event.actorId,
      event.actorType,
      event.actorIp || '',
      event.resource || '',
      event.resourceId || '',
      event.action,
      JSON.stringify(event.details),
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

    const csv = [headers.join(','), ...rows].join('\n');

    return { ok: true, value: csv };
  }

  /**
   * Clean up old audit logs
   */
  async cleanup(): Promise<Result<number>> {
    const cutoffDate = new Date(Date.now() - config.security.auditRetentionDays * 24 * 60 * 60 * 1000);

    try {
      const result = await this.db.query(`
        DELETE FROM iso_audit_logs WHERE timestamp < $1
      `, [cutoffDate]);

      logger.info(`[Audit] Cleaned up ${result.rowCount} old audit logs`);

      return { ok: true, value: result.rowCount ?? 0 };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    await this.flushBuffer();
    logger.info('[Audit] Service shut down');
  }

  // ==================== Private Methods ====================

  private async flushBuffer(): Promise<void> {
    if (this.buffer.length === 0) return;

    // FIX-500-422: Use splice(0) for atomic swap instead of spread-copy + reassign.
    // The spread-copy pattern ([...this.buffer]; this.buffer = []) has a race:
    // if logEvent() pushes between the spread and the assignment, the event is lost.
    // splice(0) atomically removes and returns all elements in a single operation.
    const eventsToFlush = this.buffer.splice(0);

    try {
      // Batch insert
      const values = eventsToFlush.map(event => [
        event.id,
        event.organizationId,
        event.workspaceId,
        event.type,
        event.severity,
        event.actorId,
        event.actorType,
        event.actorIp,
        event.actorUserAgent,
        event.resource,
        event.resourceId,
        event.action,
        JSON.stringify(event.details),
        JSON.stringify(event.metadata),
        event.timestamp,
      ]);

      const placeholders = values.map((_, i) => {
        const offset = i * 15;
        return `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6}, $${offset + 7}, $${offset + 8}, $${offset + 9}, $${offset + 10}, $${offset + 11}, $${offset + 12}, $${offset + 13}, $${offset + 14}, $${offset + 15})`;
      }).join(', ');

      await this.db.query(`
        INSERT INTO iso_audit_logs (
          id, organization_id, workspace_id, type, severity, actor_id,
          actor_type, actor_ip, actor_user_agent, resource, resource_id,
          action, details, metadata, timestamp
        ) VALUES ${placeholders}
      `, values.flat());
    } catch (error) {
      logger.error('[Audit] Failed to flush buffer:', { error: error instanceof Error ? error.message : String(error) });
      // FIX-500-423: Use unshift to prepend into the *existing* buffer array.
      // Previously [...eventsToFlush, ...this.buffer] created a new array, racing
      // with concurrent logEvent() pushes that would be lost.
      this.buffer.unshift(...eventsToFlush);
    }
  }

  private async publishRealTimeEvent(event: AuditEvent): Promise<void> {
    await this.redis.publish('audit:critical', JSON.stringify(event));
  }

  private rowToEvent(row: Record<string, unknown>): AuditEvent {
    return {
      id: row.id as string,
      organizationId: row.organization_id as string,
      workspaceId: row.workspace_id as string | null,
      type: row.type as AuditEventType,
      severity: row.severity as AuditSeverity,
      actorId: row.actor_id as string,
      actorType: row.actor_type as 'user' | 'system' | 'api_key',
      actorIp: row.actor_ip as string | null,
      actorUserAgent: row.actor_user_agent as string | null,
      resource: row.resource as string | null,
      resourceId: row.resource_id as string | null,
      action: row.action as string,
      details: (row.details as Record<string, unknown>) || {},
      metadata: (row.metadata as Record<string, unknown>) || {},
      timestamp: new Date(row.timestamp as string),
    };
  }
}
