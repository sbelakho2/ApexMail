/**
 * Support Tickets API
 *
 * FIX-500-141: DB-backed support ticket management — no demo data.
 * Queries support_tickets + support_ticket_messages tables.
 * Now with full CRUD: GET (list), POST (reply), PUT (update status/assignee).
 */

import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

const ALLOWED_STATUS = new Set(['open', 'in_progress', 'pending_customer', 'resolved', 'closed']);
const ALLOWED_PRIORITY = new Set(['low', 'medium', 'high', 'urgent']);

type SupportStatus = 'open' | 'in_progress' | 'pending_customer' | 'resolved' | 'closed';
type SupportPriority = 'low' | 'medium' | 'high' | 'urgent';

function parseStatus(value: unknown): SupportStatus | undefined {
    if (typeof value !== 'string') return undefined;
    const normalized = value === 'waiting_on_customer' ? 'pending_customer' : value;
    return ALLOWED_STATUS.has(normalized)
        ? (normalized as SupportStatus)
        : undefined;
}

function parsePriority(value: unknown): SupportPriority | undefined {
    if (typeof value !== 'string') return undefined;
    return ALLOWED_PRIORITY.has(value)
        ? (value as SupportPriority)
        : undefined;
}

interface TicketRow {
    id: string;
    subject: string;
    description: string;
    tenant_id: string | null;
    tenant_name: string | null;
    tenant_email: string | null;
    status: string;
    priority: string;
    category: string | null;
    assignee: string | null;
    created_at: string;
    updated_at: string;
}

interface MessageRow {
    id: string;
    ticket_id: string;
    content: string;
    author: string;
    author_type: string;
    attachments: string[];
    created_at: string;
}

export async function GET(request: NextRequest) {
    try {
        const rawLimit = parseInt(request.nextUrl.searchParams.get('limit') ?? '50', 10);
        const rawOffset = parseInt(request.nextUrl.searchParams.get('offset') ?? '0', 10);
        const ticketLimit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 100) : 50;
        const ticketOffset = Number.isFinite(rawOffset) ? Math.max(rawOffset, 0) : 0;

        const tickets = await query<TicketRow>(
            `SELECT id, subject, description, tenant_id, tenant_name, tenant_email,
                    status, priority, category, assignee, created_at, updated_at
             FROM support_tickets
             ORDER BY
                CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                updated_at DESC
             LIMIT $1 OFFSET $2`,
            [ticketLimit, ticketOffset]
        );

        if (tickets.length === 0) {
            return NextResponse.json([]);
        }

        const ticketIds = tickets.map((t) => t.id);
        const messages = await query<MessageRow>(
            `SELECT id, ticket_id, content, author, author_type, attachments, created_at
             FROM (
                SELECT
                    stm.*,
                    ROW_NUMBER() OVER (PARTITION BY stm.ticket_id ORDER BY stm.created_at DESC) AS rn
                FROM support_ticket_messages stm
                WHERE stm.ticket_id = ANY($1)
             ) limited
             WHERE rn <= 50
             ORDER BY created_at ASC`,
            [ticketIds]
        );

        const messagesByTicket = new Map<string, MessageRow[]>();
        for (const m of messages) {
            const arr = messagesByTicket.get(m.ticket_id) ?? [];
            arr.push(m);
            messagesByTicket.set(m.ticket_id, arr);
        }

        return NextResponse.json(tickets.map((t) => ({
            id: t.id,
            subject: t.subject,
            description: t.description,
            tenantId: t.tenant_id,
            tenantName: t.tenant_name,
            tenantEmail: t.tenant_email,
            status: t.status,
            priority: t.priority,
            category: t.category,
            assignee: t.assignee,
            createdAt: t.created_at,
            updatedAt: t.updated_at,
            messages: (messagesByTicket.get(t.id) ?? []).map((m) => ({
                id: m.id,
                content: m.content,
                author: m.author,
                authorType: m.author_type,
                attachments: m.attachments,
                createdAt: m.created_at,
            })),
        })));
    } catch (error) {
        console.error('Support API error:', error);
        return NextResponse.json({ error: 'Failed to fetch support tickets' }, { status: 500 });
    }
}

/**
 * POST /api/support — Add a reply to a ticket
 * Body: { ticketId: string, content: string, author: string, setStatus?: string }
 */
export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { ticketId, content, setStatus } = body as {
            ticketId?: string;
            content?: string;
            setStatus?: string;
        };
        const author = 'Control Plane Support';

        if (!ticketId || !content) {
            return NextResponse.json(
                { error: 'ticketId and content are required' },
                { status: 400 }
            );
        }

        if (setStatus && !ALLOWED_STATUS.has(setStatus)) {
            return NextResponse.json({ error: 'Invalid status value' }, { status: 400 });
        }

        const msgId = `msg-${crypto.randomUUID()}`;

        await query(
            `INSERT INTO support_ticket_messages (id, ticket_id, content, author, author_type, attachments, created_at)
             VALUES ($1, $2, $3, $4, 'support', '[]', NOW())`,
            [msgId, ticketId, content, author]
        );

        // Update ticket's updated_at and optionally status
        if (setStatus) {
            await query(
                `UPDATE support_tickets SET updated_at = NOW(), status = $1 WHERE id = $2`,
                [setStatus, ticketId]
            );
        } else {
            await query(
                `UPDATE support_tickets SET updated_at = NOW() WHERE id = $1`,
                [ticketId]
            );
        }

        return NextResponse.json({
            id: msgId,
            ticketId,
            content,
            author,
            authorType: 'support',
            createdAt: new Date().toISOString(),
        }, { status: 201 });
    } catch (error) {
        console.error('Support reply error:', error);
        return NextResponse.json({ error: 'Failed to add reply' }, { status: 500 });
    }
}

/**
 * PUT /api/support — Update ticket status, priority, or assignee
 * Body: { ticketId: string, status?: string, priority?: string, assignee?: string | null }
 */
export async function PUT(request: NextRequest) {
    try {
        const body = await request.json();
        const { ticketId, status: rawStatus, priority: rawPriority, assignee } = body as {
            ticketId?: string;
            status?: unknown;
            priority?: unknown;
            assignee?: string | null;
        };
        const status = parseStatus(rawStatus);
        const priority = parsePriority(rawPriority);

        if (!ticketId) {
            return NextResponse.json({ error: 'ticketId is required' }, { status: 400 });
        }

        if (rawStatus !== undefined && status === undefined) {
            return NextResponse.json({ error: 'Invalid status value' }, { status: 400 });
        }

        if (rawPriority !== undefined && priority === undefined) {
            return NextResponse.json({ error: 'Invalid priority value' }, { status: 400 });
        }

        if (assignee !== undefined && assignee !== null && typeof assignee !== 'string') {
            return NextResponse.json({ error: 'Invalid assignee value' }, { status: 400 });
        }

        const setClauses: string[] = ['updated_at = NOW()'];
        const params: unknown[] = [];
        let idx = 1;

        if (status !== undefined) {
            setClauses.push(`status = $${idx++}`);
            params.push(status);
        }
        if (priority !== undefined) {
            setClauses.push(`priority = $${idx++}`);
            params.push(priority);
        }
        if (assignee !== undefined) {
            setClauses.push(`assignee = $${idx++}`);
            params.push(assignee);
        }

        params.push(ticketId);

        const result = await query<TicketRow>(
            `UPDATE support_tickets SET ${setClauses.join(', ')} WHERE id = $${idx} RETURNING *`,
            params
        );

        if (result.length === 0) {
            return NextResponse.json({ error: 'Ticket not found' }, { status: 404 });
        }

        const t = result[0];
        return NextResponse.json({
            id: t.id,
            subject: t.subject,
            status: t.status,
            priority: t.priority,
            assignee: t.assignee,
            updatedAt: t.updated_at,
        });
    } catch (error) {
        console.error('Support update error:', error);
        return NextResponse.json({ error: 'Failed to update ticket' }, { status: 500 });
    }
}
