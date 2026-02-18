/**
 * Support Tickets API
 *
 * FIX-500-141: DB-backed support ticket management — no demo data.
 * Queries support_tickets + support_ticket_messages tables.
 * Now with full CRUD: GET (list), POST (reply), PUT (update status/assignee).
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

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

export async function GET() {
    try {
        const tickets = await query<TicketRow>(
            `SELECT id, subject, description, tenant_id, tenant_name, tenant_email,
                    status, priority, category, assignee, created_at, updated_at
             FROM support_tickets
             ORDER BY
                CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                updated_at DESC
             LIMIT 200`
        );

        if (tickets.length === 0) {
            return NextResponse.json([]);
        }

        const ticketIds = tickets.map((t) => t.id);
        const messages = await query<MessageRow>(
            `SELECT id, ticket_id, content, author, author_type, attachments, created_at
             FROM support_ticket_messages
             WHERE ticket_id = ANY($1)
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
        const { ticketId, content, author, setStatus } = body;

        if (!ticketId || !content || !author) {
            return NextResponse.json(
                { error: 'ticketId, content, and author are required' },
                { status: 400 }
            );
        }

        const msgId = `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

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
        const { ticketId, status, priority, assignee } = body;

        if (!ticketId) {
            return NextResponse.json({ error: 'ticketId is required' }, { status: 400 });
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
