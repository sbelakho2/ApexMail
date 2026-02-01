/**
 * Enterprise Support Service
 * 
 * Priority support queue and SLA tracking
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config, TicketPriority, EnterprisePlan } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum TicketStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  WAITING_CUSTOMER = 'waiting_customer',
  WAITING_INTERNAL = 'waiting_internal',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
}

export enum TicketCategory {
  TECHNICAL = 'technical',
  BILLING = 'billing',
  DELIVERABILITY = 'deliverability',
  INTEGRATION = 'integration',
  SECURITY = 'security',
  FEATURE_REQUEST = 'feature_request',
  ACCOUNT = 'account',
  OTHER = 'other',
}

export interface SupportTicket {
  id: string;
  accountId: string;
  createdBy: string;
  assignedTo?: string;
  subject: string;
  description: string;
  category: TicketCategory;
  priority: TicketPriority;
  status: TicketStatus;
  tags: string[];
  sla: SLAConfig;
  slaStatus: SLAStatus;
  firstResponseAt?: Date;
  resolvedAt?: Date;
  closedAt?: Date;
  satisfactionRating?: number;
  satisfactionComment?: string;
  metadata: TicketMetadata;
  createdAt: Date;
  updatedAt: Date;
}

export interface TicketMetadata {
  browser?: string;
  os?: string;
  source?: 'email' | 'web' | 'api' | 'chat' | 'phone';
  relatedTickets?: string[];
  affectedMessageIds?: string[];
  errorCodes?: string[];
}

export interface SLAConfig {
  firstResponseMinutes: number;
  resolutionMinutes: number;
  escalationMinutes: number;
  plan: EnterprisePlan;
}

export interface SLAStatus {
  firstResponseDue: Date;
  resolutionDue: Date;
  firstResponseMet: boolean | null;
  resolutionMet: boolean | null;
  breached: boolean;
  escalated: boolean;
  escalatedAt?: Date;
}

export interface TicketComment {
  id: string;
  ticketId: string;
  authorId: string;
  authorName: string;
  authorType: 'customer' | 'agent' | 'system';
  content: string;
  isInternal: boolean;
  attachments: TicketAttachment[];
  createdAt: Date;
}

export interface TicketAttachment {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  url: string;
}

export interface SupportAgent {
  id: string;
  name: string;
  email: string;
  role: 'agent' | 'senior' | 'manager' | 'admin';
  specializations: TicketCategory[];
  maxTickets: number;
  currentTickets: number;
  isAvailable: boolean;
  skills: string[];
}

export interface EscalationPolicy {
  id: string;
  name: string;
  conditions: EscalationCondition[];
  actions: EscalationAction[];
  isActive: boolean;
}

export interface EscalationCondition {
  type: 'time_elapsed' | 'priority' | 'category' | 'customer_tier' | 'sla_breach';
  operator: 'equals' | 'greater_than' | 'less_than' | 'in';
  value: any;
}

export interface EscalationAction {
  type: 'assign' | 'notify' | 'priority_increase' | 'page';
  target: string;
  message?: string;
}

export interface SupportMetrics {
  period: { start: Date; end: Date };
  ticketsCreated: number;
  ticketsResolved: number;
  ticketsClosed: number;
  averageFirstResponseTime: number;
  averageResolutionTime: number;
  slaFirstResponseRate: number;
  slaResolutionRate: number;
  satisfactionScore: number;
  ticketsByPriority: Record<TicketPriority, number>;
  ticketsByCategory: Record<TicketCategory, number>;
  topIssues: { issue: string; count: number }[];
}

/**
 * Enterprise Support Service
 */
export class SupportService {
  private pool: Pool;
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Create support ticket
   */
  async createTicket(
    accountId: string,
    createdBy: string,
    data: {
      subject: string;
      description: string;
      category: TicketCategory;
      priority?: TicketPriority;
      tags?: string[];
      metadata?: Partial<TicketMetadata>;
    }
  ): Promise<Result<SupportTicket>> {
    try {
      const id = uuidv4();

      // Get account's plan for SLA
      const planResult = await this.getAccountPlan(accountId);
      const plan = planResult || EnterprisePlan.BUSINESS;

      // Determine priority (auto-escalate for enterprise)
      const priority = data.priority || 
        (plan === EnterprisePlan.ENTERPRISE ? TicketPriority.HIGH : TicketPriority.NORMAL);

      // Get SLA config based on plan and priority
      const sla = this.getSLAConfig(plan, priority);
      const slaStatus = this.initializeSLAStatus(sla);

      await this.pool.query(`
        INSERT INTO ent_support_tickets (
          id, account_id, created_by, subject, description,
          category, priority, status, tags, sla, sla_status,
          metadata, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
      `, [
        id,
        accountId,
        createdBy,
        data.subject,
        data.description,
        data.category,
        priority,
        TicketStatus.OPEN,
        data.tags || [],
        JSON.stringify(sla),
        JSON.stringify(slaStatus),
        JSON.stringify(data.metadata || {}),
      ]);

      // Auto-assign if possible
      await this.autoAssignTicket(id, data.category, priority);

      // Queue for SLA monitoring
      await this.redis.zadd(
        'support:sla_monitoring',
        slaStatus.firstResponseDue.getTime(),
        id
      );

      // Publish event
      await this.redis.publish('support:ticket_created', JSON.stringify({
        ticketId: id,
        accountId,
        priority,
        category: data.category,
      }));

      return this.getTicket(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get ticket by ID
   */
  async getTicket(id: string): Promise<Result<SupportTicket>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_support_tickets WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Ticket not found') };
      }

      return { ok: true, value: this.rowToTicket(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List tickets with filters
   */
  async listTickets(
    filters: {
      accountId?: string;
      assignedTo?: string;
      status?: TicketStatus | TicketStatus[];
      priority?: TicketPriority | TicketPriority[];
      category?: TicketCategory;
      slaBreach?: boolean;
      startDate?: Date;
      endDate?: Date;
    },
    pagination: { page: number; limit: number } = { page: 1, limit: 20 }
  ): Promise<Result<{ tickets: SupportTicket[]; total: number }>> {
    try {
      const conditions: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      if (filters.accountId) {
        conditions.push(`account_id = $${paramIndex++}`);
        params.push(filters.accountId);
      }
      if (filters.assignedTo) {
        conditions.push(`assigned_to = $${paramIndex++}`);
        params.push(filters.assignedTo);
      }
      if (filters.status) {
        if (Array.isArray(filters.status)) {
          conditions.push(`status = ANY($${paramIndex++})`);
          params.push(filters.status);
        } else {
          conditions.push(`status = $${paramIndex++}`);
          params.push(filters.status);
        }
      }
      if (filters.priority) {
        if (Array.isArray(filters.priority)) {
          conditions.push(`priority = ANY($${paramIndex++})`);
          params.push(filters.priority);
        } else {
          conditions.push(`priority = $${paramIndex++}`);
          params.push(filters.priority);
        }
      }
      if (filters.category) {
        conditions.push(`category = $${paramIndex++}`);
        params.push(filters.category);
      }
      if (filters.slaBreach !== undefined) {
        conditions.push(`(sla_status->>'breached')::boolean = $${paramIndex++}`);
        params.push(filters.slaBreach);
      }
      if (filters.startDate) {
        conditions.push(`created_at >= $${paramIndex++}`);
        params.push(filters.startDate);
      }
      if (filters.endDate) {
        conditions.push(`created_at <= $${paramIndex++}`);
        params.push(filters.endDate);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      // Count
      const countResult = await this.pool.query(`
        SELECT COUNT(*) as total FROM ent_support_tickets ${whereClause}
      `, params);

      // Get tickets
      const offset = (pagination.page - 1) * pagination.limit;
      params.push(pagination.limit, offset);

      const result = await this.pool.query(`
        SELECT * FROM ent_support_tickets
        ${whereClause}
        ORDER BY
          CASE priority
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'normal' THEN 3
            WHEN 'low' THEN 4
          END,
          created_at ASC
        LIMIT $${paramIndex++} OFFSET $${paramIndex}
      `, params);

      return {
        ok: true,
        value: {
          tickets: result.rows.map(row => this.rowToTicket(row)),
          total: parseInt(countResult.rows[0].total, 10),
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
   * Update ticket
   */
  async updateTicket(
    id: string,
    updates: Partial<{
      assignedTo: string;
      status: TicketStatus;
      priority: TicketPriority;
      tags: string[];
    }>
  ): Promise<Result<SupportTicket>> {
    try {
      const setClause: string[] = ['updated_at = NOW()'];
      const params: any[] = [id];
      let paramIndex = 2;

      if (updates.assignedTo !== undefined) {
        setClause.push(`assigned_to = $${paramIndex++}`);
        params.push(updates.assignedTo);
      }
      if (updates.status) {
        setClause.push(`status = $${paramIndex++}`);
        params.push(updates.status);

        if (updates.status === TicketStatus.RESOLVED) {
          setClause.push(`resolved_at = NOW()`);
        } else if (updates.status === TicketStatus.CLOSED) {
          setClause.push(`closed_at = NOW()`);
        }
      }
      if (updates.priority) {
        setClause.push(`priority = $${paramIndex++}`);
        params.push(updates.priority);
      }
      if (updates.tags) {
        setClause.push(`tags = $${paramIndex++}`);
        params.push(updates.tags);
      }

      await this.pool.query(`
        UPDATE ent_support_tickets SET ${setClause.join(', ')} WHERE id = $1
      `, params);

      // Update SLA if status changed to resolved
      if (updates.status === TicketStatus.RESOLVED) {
        await this.updateSLAResolution(id);
      }

      return this.getTicket(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Add comment to ticket
   */
  async addComment(
    ticketId: string,
    authorId: string,
    authorName: string,
    authorType: 'customer' | 'agent' | 'system',
    content: string,
    isInternal: boolean = false,
    attachments: TicketAttachment[] = []
  ): Promise<Result<TicketComment>> {
    try {
      const id = uuidv4();

      await this.pool.query(`
        INSERT INTO ent_ticket_comments (
          id, ticket_id, author_id, author_name, author_type,
          content, is_internal, attachments, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `, [
        id,
        ticketId,
        authorId,
        authorName,
        authorType,
        content,
        isInternal,
        JSON.stringify(attachments),
      ]);

      // If this is the first agent response, update first response time
      if (authorType === 'agent' && !isInternal) {
        await this.updateFirstResponse(ticketId);
      }

      // Update ticket status if agent replied
      if (authorType === 'agent') {
        await this.pool.query(`
          UPDATE ent_support_tickets SET
            status = 'waiting_customer',
            updated_at = NOW()
          WHERE id = $1 AND status = 'open'
        `, [ticketId]);
      } else if (authorType === 'customer') {
        await this.pool.query(`
          UPDATE ent_support_tickets SET
            status = CASE
              WHEN status = 'waiting_customer' THEN 'in_progress'
              ELSE status
            END,
            updated_at = NOW()
          WHERE id = $1
        `, [ticketId]);
      }

      // Publish event
      await this.redis.publish('support:comment_added', JSON.stringify({
        ticketId,
        commentId: id,
        authorType,
        isInternal,
      }));

      return {
        ok: true,
        value: {
          id,
          ticketId,
          authorId,
          authorName,
          authorType,
          content,
          isInternal,
          attachments,
          createdAt: new Date(),
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
   * Get ticket comments
   */
  async getComments(ticketId: string, includeInternal: boolean = false): Promise<Result<TicketComment[]>> {
    try {
      let query = `
        SELECT * FROM ent_ticket_comments WHERE ticket_id = $1
      `;

      if (!includeInternal) {
        query += ` AND is_internal = false`;
      }

      query += ` ORDER BY created_at ASC`;

      const result = await this.pool.query(query, [ticketId]);

      return {
        ok: true,
        value: result.rows.map(row => ({
          id: row.id,
          ticketId: row.ticket_id,
          authorId: row.author_id,
          authorName: row.author_name,
          authorType: row.author_type,
          content: row.content,
          isInternal: row.is_internal,
          attachments: row.attachments,
          createdAt: row.created_at,
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
   * Escalate ticket
   */
  async escalateTicket(
    ticketId: string,
    reason: string,
    escalateTo?: string
  ): Promise<Result<SupportTicket>> {
    try {
      const ticketResult = await this.getTicket(ticketId);
      if (!ticketResult.ok) return { ok: false, error: ticketResult.error };

      const ticket = ticketResult.value;

      // Update SLA status
      const slaStatus = {
        ...ticket.slaStatus,
        escalated: true,
        escalatedAt: new Date(),
      };

      // Increase priority if not already critical
      const newPriority = ticket.priority === TicketPriority.CRITICAL
        ? TicketPriority.CRITICAL
        : ticket.priority === TicketPriority.HIGH
          ? TicketPriority.CRITICAL
          : TicketPriority.HIGH;

      await this.pool.query(`
        UPDATE ent_support_tickets SET
          priority = $2,
          assigned_to = COALESCE($3, assigned_to),
          sla_status = $4,
          updated_at = NOW()
        WHERE id = $1
      `, [ticketId, newPriority, escalateTo, JSON.stringify(slaStatus)]);

      // Add system comment
      await this.addComment(
        ticketId,
        'system',
        'System',
        'system',
        `Ticket escalated: ${reason}`,
        true
      );

      // Publish escalation event
      await this.redis.publish('support:ticket_escalated', JSON.stringify({
        ticketId,
        reason,
        newPriority,
        escalateTo,
      }));

      return this.getTicket(ticketId);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Submit satisfaction rating
   */
  async submitSatisfaction(
    ticketId: string,
    rating: number,
    comment?: string
  ): Promise<Result<void>> {
    try {
      if (rating < 1 || rating > 5) {
        return { ok: false, error: new Error('Rating must be between 1 and 5') };
      }

      await this.pool.query(`
        UPDATE ent_support_tickets SET
          satisfaction_rating = $2,
          satisfaction_comment = $3,
          updated_at = NOW()
        WHERE id = $1
      `, [ticketId, rating, comment]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get support metrics
   */
  async getMetrics(
    startDate: Date,
    endDate: Date,
    accountId?: string
  ): Promise<Result<SupportMetrics>> {
    try {
      const conditions = ['created_at BETWEEN $1 AND $2'];
      const params: any[] = [startDate, endDate];

      if (accountId) {
        conditions.push('account_id = $3');
        params.push(accountId);
      }

      const whereClause = conditions.join(' AND ');

      // Get ticket counts
      const countResult = await this.pool.query(`
        SELECT
          COUNT(*) as created,
          COUNT(*) FILTER (WHERE resolved_at IS NOT NULL) as resolved,
          COUNT(*) FILTER (WHERE closed_at IS NOT NULL) as closed,
          AVG(EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60) FILTER (WHERE first_response_at IS NOT NULL) as avg_first_response,
          AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60) FILTER (WHERE resolved_at IS NOT NULL) as avg_resolution,
          AVG(satisfaction_rating) FILTER (WHERE satisfaction_rating IS NOT NULL) as avg_satisfaction,
          COUNT(*) FILTER (WHERE (sla_status->>'firstResponseMet')::boolean = true) as sla_first_response_met,
          COUNT(*) FILTER (WHERE (sla_status->>'resolutionMet')::boolean = true) as sla_resolution_met,
          COUNT(*) FILTER (WHERE first_response_at IS NOT NULL) as responded_tickets,
          COUNT(*) FILTER (WHERE resolved_at IS NOT NULL) as resolved_tickets_for_sla
        FROM ent_support_tickets
        WHERE ${whereClause}
      `, params);

      // Get tickets by priority
      const priorityResult = await this.pool.query(`
        SELECT priority, COUNT(*) as count
        FROM ent_support_tickets
        WHERE ${whereClause}
        GROUP BY priority
      `, params);

      // Get tickets by category
      const categoryResult = await this.pool.query(`
        SELECT category, COUNT(*) as count
        FROM ent_support_tickets
        WHERE ${whereClause}
        GROUP BY category
      `, params);

      // Get top issues (from tags)
      const issuesResult = await this.pool.query(`
        SELECT unnest(tags) as issue, COUNT(*) as count
        FROM ent_support_tickets
        WHERE ${whereClause}
        GROUP BY issue
        ORDER BY count DESC
        LIMIT 10
      `, params);

      const stats = countResult.rows[0];

      return {
        ok: true,
        value: {
          period: { start: startDate, end: endDate },
          ticketsCreated: parseInt(stats.created, 10),
          ticketsResolved: parseInt(stats.resolved, 10),
          ticketsClosed: parseInt(stats.closed, 10),
          averageFirstResponseTime: Math.round(parseFloat(stats.avg_first_response) || 0),
          averageResolutionTime: Math.round(parseFloat(stats.avg_resolution) || 0),
          slaFirstResponseRate: parseInt(stats.responded_tickets, 10) > 0
            ? parseInt(stats.sla_first_response_met, 10) / parseInt(stats.responded_tickets, 10)
            : 1,
          slaResolutionRate: parseInt(stats.resolved_tickets_for_sla, 10) > 0
            ? parseInt(stats.sla_resolution_met, 10) / parseInt(stats.resolved_tickets_for_sla, 10)
            : 1,
          satisfactionScore: parseFloat(stats.avg_satisfaction) || 0,
          ticketsByPriority: Object.fromEntries(
            priorityResult.rows.map(r => [r.priority, parseInt(r.count, 10)])
          ) as Record<TicketPriority, number>,
          ticketsByCategory: Object.fromEntries(
            categoryResult.rows.map(r => [r.category, parseInt(r.count, 10)])
          ) as Record<TicketCategory, number>,
          topIssues: issuesResult.rows.map(r => ({
            issue: r.issue,
            count: parseInt(r.count, 10),
          })),
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
   * Check SLA breaches
   */
  async checkSLABreaches(): Promise<Result<SupportTicket[]>> {
    try {
      const now = new Date();

      // Find tickets that have breached SLA
      const result = await this.pool.query(`
        SELECT * FROM ent_support_tickets
        WHERE status NOT IN ('resolved', 'closed')
        AND (
          (first_response_at IS NULL AND (sla_status->>'firstResponseDue')::timestamptz < $1)
          OR
          (resolved_at IS NULL AND (sla_status->>'resolutionDue')::timestamptz < $1)
        )
        AND (sla_status->>'breached')::boolean = false
      `, [now]);

      const breachedTickets: SupportTicket[] = [];

      for (const row of result.rows) {
        const ticket = this.rowToTicket(row);

        // Update SLA status to breached
        const slaStatus = {
          ...ticket.slaStatus,
          breached: true,
        };

        if (!ticket.firstResponseAt && ticket.slaStatus.firstResponseDue < now) {
          slaStatus.firstResponseMet = false;
        }
        if (!ticket.resolvedAt && ticket.slaStatus.resolutionDue < now) {
          slaStatus.resolutionMet = false;
        }

        await this.pool.query(`
          UPDATE ent_support_tickets SET
            sla_status = $2,
            updated_at = NOW()
          WHERE id = $1
        `, [ticket.id, JSON.stringify(slaStatus)]);

        // Escalate critical breaches
        if (ticket.priority === TicketPriority.CRITICAL || ticket.priority === TicketPriority.HIGH) {
          await this.escalateTicket(ticket.id, 'SLA breach');
        }

        breachedTickets.push({ ...ticket, slaStatus });
      }

      return { ok: true, value: breachedTickets };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get agent workload
   */
  async getAgentWorkload(): Promise<Result<SupportAgent[]>> {
    try {
      const result = await this.pool.query(`
        SELECT 
          a.*,
          COUNT(t.id) FILTER (WHERE t.status NOT IN ('resolved', 'closed')) as current_tickets
        FROM ent_support_agents a
        LEFT JOIN ent_support_tickets t ON a.id = t.assigned_to
        WHERE a.is_available = true
        GROUP BY a.id
        ORDER BY current_tickets ASC
      `);

      return {
        ok: true,
        value: result.rows.map(row => ({
          id: row.id,
          name: row.name,
          email: row.email,
          role: row.role,
          specializations: row.specializations,
          maxTickets: row.max_tickets,
          currentTickets: parseInt(row.current_tickets, 10),
          isAvailable: row.is_available,
          skills: row.skills,
        })),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  // Private methods

  private async getAccountPlan(accountId: string): Promise<EnterprisePlan | null> {
    const result = await this.pool.query(`
      SELECT plan FROM accounts WHERE id = $1
    `, [accountId]);

    return result.rows[0]?.plan || null;
  }

  private getSLAConfig(plan: EnterprisePlan, priority: TicketPriority): SLAConfig {
    const slaConfigs: Record<EnterprisePlan, Record<TicketPriority, { firstResponse: number; resolution: number; escalation: number }>> = {
      [EnterprisePlan.STARTER]: {
        [TicketPriority.CRITICAL]: { firstResponse: 240, resolution: 1440, escalation: 480 },
        [TicketPriority.HIGH]: { firstResponse: 480, resolution: 2880, escalation: 960 },
        [TicketPriority.NORMAL]: { firstResponse: 1440, resolution: 5760, escalation: 2880 },
        [TicketPriority.LOW]: { firstResponse: 2880, resolution: 10080, escalation: 5760 },
      },
      [EnterprisePlan.BUSINESS]: {
        [TicketPriority.CRITICAL]: { firstResponse: 60, resolution: 480, escalation: 120 },
        [TicketPriority.HIGH]: { firstResponse: 120, resolution: 960, escalation: 240 },
        [TicketPriority.NORMAL]: { firstResponse: 480, resolution: 2880, escalation: 960 },
        [TicketPriority.LOW]: { firstResponse: 1440, resolution: 5760, escalation: 2880 },
      },
      [EnterprisePlan.ENTERPRISE]: {
        [TicketPriority.CRITICAL]: { firstResponse: 15, resolution: 120, escalation: 30 },
        [TicketPriority.HIGH]: { firstResponse: 30, resolution: 240, escalation: 60 },
        [TicketPriority.NORMAL]: { firstResponse: 120, resolution: 960, escalation: 240 },
        [TicketPriority.LOW]: { firstResponse: 480, resolution: 2880, escalation: 960 },
      },
      [EnterprisePlan.CUSTOM]: {
        [TicketPriority.CRITICAL]: { firstResponse: 10, resolution: 60, escalation: 15 },
        [TicketPriority.HIGH]: { firstResponse: 15, resolution: 120, escalation: 30 },
        [TicketPriority.NORMAL]: { firstResponse: 60, resolution: 480, escalation: 120 },
        [TicketPriority.LOW]: { firstResponse: 240, resolution: 1440, escalation: 480 },
      },
    };

    const cfg = slaConfigs[plan][priority];

    return {
      firstResponseMinutes: cfg.firstResponse,
      resolutionMinutes: cfg.resolution,
      escalationMinutes: cfg.escalation,
      plan,
    };
  }

  private initializeSLAStatus(sla: SLAConfig): SLAStatus {
    const now = new Date();
    return {
      firstResponseDue: new Date(now.getTime() + sla.firstResponseMinutes * 60 * 1000),
      resolutionDue: new Date(now.getTime() + sla.resolutionMinutes * 60 * 1000),
      firstResponseMet: null,
      resolutionMet: null,
      breached: false,
      escalated: false,
    };
  }

  private async autoAssignTicket(
    ticketId: string,
    category: TicketCategory,
    priority: TicketPriority
  ): Promise<void> {
    // Find available agent with matching specialization and capacity
    const result = await this.pool.query(`
      SELECT a.id FROM ent_support_agents a
      LEFT JOIN (
        SELECT assigned_to, COUNT(*) as ticket_count
        FROM ent_support_tickets
        WHERE status NOT IN ('resolved', 'closed')
        GROUP BY assigned_to
      ) tc ON a.id = tc.assigned_to
      WHERE a.is_available = true
      AND $1 = ANY(a.specializations)
      AND COALESCE(tc.ticket_count, 0) < a.max_tickets
      ORDER BY COALESCE(tc.ticket_count, 0) ASC
      LIMIT 1
    `, [category]);

    if (result.rows.length > 0) {
      await this.pool.query(`
        UPDATE ent_support_tickets SET assigned_to = $2 WHERE id = $1
      `, [ticketId, result.rows[0].id]);
    }
  }

  private async updateFirstResponse(ticketId: string): Promise<void> {
    const ticketResult = await this.getTicket(ticketId);
    if (!ticketResult.ok || ticketResult.value.firstResponseAt) return;

    const ticket = ticketResult.value;
    const now = new Date();
    const firstResponseMet = now <= ticket.slaStatus.firstResponseDue;

    const slaStatus = {
      ...ticket.slaStatus,
      firstResponseMet,
    };

    await this.pool.query(`
      UPDATE ent_support_tickets SET
        first_response_at = NOW(),
        sla_status = $2
      WHERE id = $1
    `, [ticketId, JSON.stringify(slaStatus)]);
  }

  private async updateSLAResolution(ticketId: string): Promise<void> {
    const ticketResult = await this.getTicket(ticketId);
    if (!ticketResult.ok) return;

    const ticket = ticketResult.value;
    const now = new Date();
    const resolutionMet = now <= ticket.slaStatus.resolutionDue;

    const slaStatus = {
      ...ticket.slaStatus,
      resolutionMet,
    };

    await this.pool.query(`
      UPDATE ent_support_tickets SET
        sla_status = $2
      WHERE id = $1
    `, [ticketId, JSON.stringify(slaStatus)]);
  }

  private rowToTicket(row: any): SupportTicket {
    return {
      id: row.id,
      accountId: row.account_id,
      createdBy: row.created_by,
      assignedTo: row.assigned_to,
      subject: row.subject,
      description: row.description,
      category: row.category as TicketCategory,
      priority: row.priority as TicketPriority,
      status: row.status as TicketStatus,
      tags: row.tags,
      sla: row.sla,
      slaStatus: row.sla_status,
      firstResponseAt: row.first_response_at,
      resolvedAt: row.resolved_at,
      closedAt: row.closed_at,
      satisfactionRating: row.satisfaction_rating,
      satisfactionComment: row.satisfaction_comment,
      metadata: row.metadata,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
