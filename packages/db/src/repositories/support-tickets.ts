/**
 * Support Tickets Repository
 *
 * Manages customer support tickets with full CRUD, messaging,
 * category/title enforcement, and analytics queries.
 */

import { createLogger } from '@apexmail/lib';
import type { DatabasePool } from '../pool.js';

const logger = createLogger({ name: 'support-tickets-repository' });

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type TicketStatus = 'open' | 'in_progress' | 'waiting_on_customer' | 'resolved' | 'closed';
export type TicketPriority = 'low' | 'medium' | 'high' | 'urgent';
export type TicketCategory = 'billing' | 'technical' | 'feature_request' | 'bug' | 'general';

export interface SupportTicket {
  id: string;
  subject: string;
  description: string;
  tenantId: string;
  tenantName: string;
  tenantEmail: string;
  status: TicketStatus;
  priority: TicketPriority;
  category: TicketCategory;
  assignee: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SupportTicketMessage {
  id: string;
  ticketId: string;
  content: string;
  author: string;
  authorType: 'customer' | 'support' | 'bot';
  attachments: string[];
  createdAt: Date;
}

export interface CreateTicketInput {
  tenantId: string;
  tenantName: string;
  tenantEmail: string;
  subject: string;
  description: string;
  category: TicketCategory;
  priority?: TicketPriority;
}

export interface AddMessageInput {
  ticketId: string;
  content: string;
  author: string;
  authorType: 'customer' | 'support' | 'bot';
  attachments?: string[];
}

export interface UpdateTicketInput {
  status?: TicketStatus;
  priority?: TicketPriority;
  assignee?: string | null;
  category?: TicketCategory;
}

export interface TicketAnalytics {
  totalTickets: number;
  openTickets: number;
  inProgressTickets: number;
  resolvedTickets: number;
  closedTickets: number;
  urgentTickets: number;
  avgResolutionHours: number;
  ticketsByCategory: Record<string, number>;
  ticketsByPriority: Record<string, number>;
  ticketsOverTime: { date: string; count: number }[];
  topTenants: { tenantName: string; count: number }[];
}

/* ------------------------------------------------------------------ */
/*  Repository                                                         */
/* ------------------------------------------------------------------ */

export class SupportTicketsRepository {
  constructor(private readonly db: DatabasePool) {}

  /* --- Create ---------------------------------------------------- */

  async create(input: CreateTicketInput): Promise<SupportTicket> {
    const id = `tkt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date();

    const result = await this.db.query<{
      id: string; subject: string; description: string;
      tenant_id: string; tenant_name: string; tenant_email: string;
      status: TicketStatus; priority: TicketPriority; category: TicketCategory;
      assignee: string | null; created_at: Date; updated_at: Date;
    }>(
      `INSERT INTO support_tickets
         (id, subject, description, tenant_id, tenant_name, tenant_email,
          status, priority, category, assignee, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8, NULL, $9, $10)
       RETURNING *`,
      [
        id,
        input.subject,
        input.description,
        input.tenantId,
        input.tenantName,
        input.tenantEmail,
        input.priority ?? 'medium',
        input.category,
        now,
        now,
      ]
    );

    if (!result.ok) throw result.error;
    const row = result.value.rows[0];
    if (!row) throw new Error('Failed to create ticket');
    logger.info('Ticket created', { ticketId: id, tenantId: input.tenantId });

    return this.mapRow(row);
  }

  /* --- Add message ----------------------------------------------- */

  async addMessage(input: AddMessageInput): Promise<SupportTicketMessage> {
    const id = `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const result = await this.db.query<{
      id: string; ticket_id: string; content: string; author: string;
      author_type: string; attachments: string[]; created_at: Date;
    }>(
      `INSERT INTO support_ticket_messages
         (id, ticket_id, content, author, author_type, attachments, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       RETURNING *`,
      [
        id,
        input.ticketId,
        input.content,
        input.author,
        input.authorType,
        JSON.stringify(input.attachments ?? []),
      ]
    );

    // Update ticket's updated_at
    await this.db.query(
      `UPDATE support_tickets SET updated_at = NOW() WHERE id = $1`,
      [input.ticketId]
    );

    if (!result.ok) throw result.error;
    const row = result.value.rows[0];
    if (!row) throw new Error('Failed to add message');
    return {
      id: row.id,
      ticketId: row.ticket_id,
      content: row.content,
      author: row.author,
      authorType: row.author_type as 'customer' | 'support' | 'bot',
      attachments: row.attachments ?? [],
      createdAt: row.created_at,
    };
  }

  /* --- Update ---------------------------------------------------- */

  async update(ticketId: string, input: UpdateTicketInput): Promise<SupportTicket | null> {
    const setClauses: string[] = ['updated_at = NOW()'];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (input.status !== undefined) {
      setClauses.push(`status = $${paramIdx++}`);
      params.push(input.status);
    }
    if (input.priority !== undefined) {
      setClauses.push(`priority = $${paramIdx++}`);
      params.push(input.priority);
    }
    if (input.assignee !== undefined) {
      setClauses.push(`assignee = $${paramIdx++}`);
      params.push(input.assignee);
    }
    if (input.category !== undefined) {
      setClauses.push(`category = $${paramIdx++}`);
      params.push(input.category);
    }

    params.push(ticketId);

    const result = await this.db.query<{
      id: string; subject: string; description: string;
      tenant_id: string; tenant_name: string; tenant_email: string;
      status: TicketStatus; priority: TicketPriority; category: TicketCategory;
      assignee: string | null; created_at: Date; updated_at: Date;
    }>(
      `UPDATE support_tickets SET ${setClauses.join(', ')} WHERE id = $${paramIdx} RETURNING *`,
      params
    );

    if (!result.ok) throw result.error;
    if (result.value.rowCount === 0) return null;
    return this.mapRow(result.value.rows[0]!);
  }

  /* --- Read ------------------------------------------------------ */

  async findById(ticketId: string): Promise<SupportTicket | null> {
    const result = await this.db.query<{
      id: string; subject: string; description: string;
      tenant_id: string; tenant_name: string; tenant_email: string;
      status: TicketStatus; priority: TicketPriority; category: TicketCategory;
      assignee: string | null; created_at: Date; updated_at: Date;
    }>(
      `SELECT * FROM support_tickets WHERE id = $1`,
      [ticketId]
    );
    if (!result.ok) throw result.error;
    if (result.value.rowCount === 0) return null;
    return this.mapRow(result.value.rows[0]!);
  }

  async findByTenantId(tenantId: string, limit = 50, offset = 0): Promise<SupportTicket[]> {
    const result = await this.db.query<{
      id: string; subject: string; description: string;
      tenant_id: string; tenant_name: string; tenant_email: string;
      status: TicketStatus; priority: TicketPriority; category: TicketCategory;
      assignee: string | null; created_at: Date; updated_at: Date;
    }>(
      `SELECT * FROM support_tickets
       WHERE tenant_id = $1
       ORDER BY
         CASE status
           WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1
           WHEN 'waiting_on_customer' THEN 2 WHEN 'resolved' THEN 3 ELSE 4
         END,
         updated_at DESC
       LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset]
    );
    if (!result.ok) throw result.error;
    return result.value.rows.map(r => this.mapRow(r));
  }

  async countByTenantId(tenantId: string): Promise<number> {
    const result = await this.db.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM support_tickets WHERE tenant_id = $1`,
      [tenantId]
    );
    if (!result.ok) throw result.error;
    return parseInt(result.value.rows[0]?.count ?? '0', 10);
  }

  async findAll(limit = 100, offset = 0): Promise<SupportTicket[]> {
    const result = await this.db.query<{
      id: string; subject: string; description: string;
      tenant_id: string; tenant_name: string; tenant_email: string;
      status: TicketStatus; priority: TicketPriority; category: TicketCategory;
      assignee: string | null; created_at: Date; updated_at: Date;
    }>(
      `SELECT * FROM support_tickets
       ORDER BY
         CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
         updated_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    if (!result.ok) throw result.error;
    return result.value.rows.map(r => this.mapRow(r));
  }

  async getMessages(ticketId: string): Promise<SupportTicketMessage[]> {
    const result = await this.db.query<{
      id: string; ticket_id: string; content: string; author: string;
      author_type: string; attachments: string[]; created_at: Date;
    }>(
      `SELECT * FROM support_ticket_messages
       WHERE ticket_id = $1
       ORDER BY created_at ASC`,
      [ticketId]
    );
    if (!result.ok) throw result.error;
    return result.value.rows.map(r => ({
      id: r.id,
      ticketId: r.ticket_id,
      content: r.content,
      author: r.author,
      authorType: r.author_type as 'customer' | 'support' | 'bot',
      attachments: r.attachments ?? [],
      createdAt: r.created_at,
    }));
  }

  /* --- Analytics ------------------------------------------------- */

  async getAnalytics(days = 30): Promise<TicketAnalytics> {
    const since = new Date();
    since.setDate(since.getDate() - days);

    const [statusRes, categoryRes, priorityRes, timelineRes, topTenantsRes, avgRes] = await Promise.all([
      this.db.query<{ status: string; count: string }>(
        `SELECT status, COUNT(*)::text AS count FROM support_tickets GROUP BY status`
      ),
      this.db.query<{ category: string; count: string }>(
        `SELECT COALESCE(category, 'general') AS category, COUNT(*)::text AS count
         FROM support_tickets GROUP BY category`
      ),
      this.db.query<{ priority: string; count: string }>(
        `SELECT priority, COUNT(*)::text AS count FROM support_tickets GROUP BY priority`
      ),
      this.db.query<{ date: string; count: string }>(
        `SELECT DATE(created_at)::text AS date, COUNT(*)::text AS count
         FROM support_tickets
         WHERE created_at >= $1
         GROUP BY DATE(created_at)
         ORDER BY date`,
        [since]
      ),
      this.db.query<{ tenant_name: string; count: string }>(
        `SELECT tenant_name, COUNT(*)::text AS count
         FROM support_tickets
         GROUP BY tenant_name
         ORDER BY COUNT(*) DESC
         LIMIT 10`
      ),
      this.db.query<{ avg_hours: string }>(
        `SELECT COALESCE(
           AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600), 0
         )::text AS avg_hours
         FROM support_tickets
         WHERE status IN ('resolved', 'closed')`
      ),
    ]);

    const statusRows = statusRes.ok ? statusRes.value.rows : [];
    const categoryRows = categoryRes.ok ? categoryRes.value.rows : [];
    const priorityRows = priorityRes.ok ? priorityRes.value.rows : [];
    const timelineRows = timelineRes.ok ? timelineRes.value.rows : [];
    const topTenantsRows = topTenantsRes.ok ? topTenantsRes.value.rows : [];
    const avgRows = avgRes.ok ? avgRes.value.rows : [];

    const statusMap: Record<string, number> = {};
    for (const row of statusRows) statusMap[row.status] = parseInt(row.count, 10);

    const categoryMap: Record<string, number> = {};
    for (const row of categoryRows) categoryMap[row.category] = parseInt(row.count, 10);

    const priorityMap: Record<string, number> = {};
    for (const row of priorityRows) priorityMap[row.priority] = parseInt(row.count, 10);

    return {
      totalTickets: Object.values(statusMap).reduce((a, b) => a + b, 0),
      openTickets: statusMap['open'] ?? 0,
      inProgressTickets: statusMap['in_progress'] ?? 0,
      resolvedTickets: statusMap['resolved'] ?? 0,
      closedTickets: statusMap['closed'] ?? 0,
      urgentTickets: priorityMap['urgent'] ?? 0,
      avgResolutionHours: parseFloat(avgRows[0]?.avg_hours ?? '0'),
      ticketsByCategory: categoryMap,
      ticketsByPriority: priorityMap,
      ticketsOverTime: timelineRows.map(r => ({ date: r.date, count: parseInt(r.count, 10) })),
      topTenants: topTenantsRows.map(r => ({ tenantName: r.tenant_name, count: parseInt(r.count, 10) })),
    };
  }

  /* --- Helper ---------------------------------------------------- */

  private mapRow(row: {
    id: string; subject: string; description: string;
    tenant_id: string; tenant_name: string; tenant_email: string;
    status: TicketStatus; priority: TicketPriority; category: TicketCategory;
    assignee: string | null; created_at: Date; updated_at: Date;
  }): SupportTicket {
    return {
      id: row.id,
      subject: row.subject,
      description: row.description,
      tenantId: row.tenant_id,
      tenantName: row.tenant_name,
      tenantEmail: row.tenant_email,
      status: row.status,
      priority: row.priority,
      category: row.category ?? 'general',
      assignee: row.assignee,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
