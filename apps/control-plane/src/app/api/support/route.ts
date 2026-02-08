/**
 * Support Tickets API
 *
 * FIX-500-141: DB-backed support ticket management — no demo data.
 * Queries support_tickets + support_ticket_messages tables.
 */

import { NextResponse } from 'next/server';
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
             LIMIT 100`
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
