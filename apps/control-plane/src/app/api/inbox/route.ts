/**
 * Inbox Sentinel API
 *
 * FIX-500-141: DB-backed inbox message management — no demo data.
 * Queries autopilot_inbox_messages table.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface InboxRow {
    id: string;
    tenant_id: string | null;
    message_id: string | null;
    from_address: string;
    to_address: string;
    subject: string;
    body_preview: string | null;
    classification: string;
    confidence: number;
    action_taken: string | null;
    is_read: boolean;
    is_archived: boolean;
    received_at: string;
    created_at: string;
}

export async function GET(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const classification = searchParams.get('classification');
        const archived = searchParams.get('archived') === 'true';
        const rawLimit = parseInt(searchParams.get('limit') ?? '50', 10);
        const limit = Math.min(Math.max(Number.isFinite(rawLimit) ? rawLimit : 50, 1), 200);

        let sql = `SELECT id, tenant_id, message_id, from_address, to_address,
                           subject, body_preview, classification, confidence,
                           action_taken, is_read, is_archived, received_at, created_at
                    FROM autopilot_inbox_messages
                    WHERE is_archived = $1`;
        const params: unknown[] = [archived];
        let paramIdx = 2;

        if (classification) {
            sql += ` AND classification = $${paramIdx}`;
            params.push(classification);
            paramIdx++;
        }

        sql += ` ORDER BY received_at DESC LIMIT $${paramIdx}`;
        params.push(limit);

        const rows = await query<InboxRow>(sql, params);

        return NextResponse.json(rows.map((r) => ({
            id: r.id,
            tenantId: r.tenant_id,
            messageId: r.message_id,
            from: r.from_address,
            to: r.to_address,
            subject: r.subject,
            bodyPreview: r.body_preview,
            classification: r.classification,
            confidence: r.confidence,
            actionTaken: r.action_taken,
            isRead: r.is_read,
            isArchived: r.is_archived,
            receivedAt: r.received_at,
            createdAt: r.created_at,
        })));
    } catch (error) {
        console.error('Inbox API error:', error);
        return NextResponse.json({ error: 'Failed to fetch inbox messages' }, { status: 500 });
    }
}

export async function PATCH(request: Request) {
    try {
        const body = await request.json();
        const { id, isRead, isArchived, actionTaken } = body;

        if (!id) {
            return NextResponse.json({ error: 'Message id required' }, { status: 400 });
        }

        const setClauses: string[] = [];
        const params: unknown[] = [];
        let paramIdx = 1;

        if (typeof isRead === 'boolean') {
            setClauses.push(`is_read = $${paramIdx}`);
            params.push(isRead);
            paramIdx++;
        }
        if (typeof isArchived === 'boolean') {
            setClauses.push(`is_archived = $${paramIdx}`);
            params.push(isArchived);
            paramIdx++;
        }
        if (actionTaken !== undefined) {
            setClauses.push(`action_taken = $${paramIdx}`);
            params.push(actionTaken);
            paramIdx++;
        }

        if (setClauses.length === 0) {
            return NextResponse.json({ error: 'No fields to update' }, { status: 400 });
        }

        params.push(id);
        const updated = await query<InboxRow>(
            `UPDATE autopilot_inbox_messages SET ${setClauses.join(', ')}
             WHERE id = $${paramIdx}
             RETURNING id, tenant_id, message_id, from_address, to_address,
                       subject, body_preview, classification, confidence,
                       action_taken, is_read, is_archived, received_at, created_at`,
            params
        );

        if (updated.length === 0) {
            return NextResponse.json({ error: 'Message not found' }, { status: 404 });
        }

        const r = updated[0];
        return NextResponse.json({
            id: r.id,
            tenantId: r.tenant_id,
            messageId: r.message_id,
            from: r.from_address,
            to: r.to_address,
            subject: r.subject,
            bodyPreview: r.body_preview,
            classification: r.classification,
            confidence: r.confidence,
            actionTaken: r.action_taken,
            isRead: r.is_read,
            isArchived: r.is_archived,
            receivedAt: r.received_at,
            createdAt: r.created_at,
        });
    } catch (error) {
        console.error('Inbox PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update message' }, { status: 500 });
    }
}
