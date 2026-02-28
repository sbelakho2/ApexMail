/**
 * Sales Lead Update API Route
 *
 * PATCH: Update lead fields (status, notes, assignedTo, tags, etc.)
 * Supports single-lead and bulk updates.
 *
 * Improvement #41: Persistent lead status changes
 * Improvement #42: Persistent notes editing
 * Improvement #43: Bulk status update API
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface LeadUpdate {
    id: string;
    status?: string;
    notes?: string;
    assignedTo?: string | null;
    tags?: string[];
    contactEmail?: string | null;
    contactName?: string | null;
    contactTitle?: string | null;
    estimatedDealValue?: number | null;
    nextFollowUpAt?: string | null;
}

const VALID_STATUSES = [
    'new', 'enriching', 'contacted', 'opened', 'replied', 'qualified',
    'demo_scheduled', 'proposal_sent', 'negotiation', 'nurturing',
    'closed_won', 'closed_lost', 'unsubscribed', 'do_not_contact',
];

export async function PATCH(request: NextRequest) {
    try {
        const body = await request.json();

        // Support single or bulk updates
        const updates: LeadUpdate[] = Array.isArray(body.updates) ? body.updates : body.id ? [body] : [];

        if (updates.length === 0) {
            return NextResponse.json(
                { error: 'No updates provided. Send { id, ...fields } or { updates: [...] }' },
                { status: 400 }
            );
        }

        if (updates.length > 200) {
            return NextResponse.json(
                { error: 'Maximum 200 leads per batch update' },
                { status: 400 }
            );
        }

        const results: Array<{ id: string; success: boolean; error?: string }> = [];

        for (const update of updates) {
            if (!update.id) {
                results.push({ id: 'unknown', success: false, error: 'Missing lead id' });
                continue;
            }

            if (update.status && !VALID_STATUSES.includes(update.status)) {
                results.push({ id: update.id, success: false, error: `Invalid status: ${update.status}` });
                continue;
            }

            try {
                const setClauses: string[] = [];
                const values: unknown[] = [];
                let paramIndex = 1;

                if (update.status !== undefined) {
                    setClauses.push(`status = $${paramIndex++}`);
                    values.push(update.status);
                }
                if (update.notes !== undefined) {
                    setClauses.push(`notes = $${paramIndex++}`);
                    values.push(update.notes);
                }
                if (update.tags !== undefined) {
                    setClauses.push(`tags = $${paramIndex++}`);
                    values.push(JSON.stringify(update.tags));
                }
                if (update.contactEmail !== undefined) {
                    setClauses.push(`contact_email = $${paramIndex++}`);
                    values.push(update.contactEmail);
                }
                if (update.contactName !== undefined) {
                    setClauses.push(`contact_name = $${paramIndex++}`);
                    values.push(update.contactName);
                }
                if (update.contactTitle !== undefined) {
                    setClauses.push(`contact_title = $${paramIndex++}`);
                    values.push(update.contactTitle);
                }
                if (update.estimatedDealValue !== undefined) {
                    setClauses.push(`estimated_deal_value = $${paramIndex++}`);
                    values.push(update.estimatedDealValue);
                }
                if (update.nextFollowUpAt !== undefined) {
                    setClauses.push(`next_follow_up_at = $${paramIndex++}`);
                    values.push(update.nextFollowUpAt);
                }
                if (update.assignedTo !== undefined) {
                    setClauses.push(`assigned_to = $${paramIndex++}`);
                    values.push(update.assignedTo);
                }

                if (setClauses.length === 0) {
                    results.push({ id: update.id, success: false, error: 'No fields to update' });
                    continue;
                }

                setClauses.push(`updated_at = NOW()`);
                values.push(update.id);

                await query(
                    `UPDATE sales_leads SET ${setClauses.join(', ')} WHERE id = $${paramIndex}`,
                    values
                );

                results.push({ id: update.id, success: true });
            } catch (err) {
                console.error(`Failed to update lead ${update.id}:`, err);
                results.push({ id: update.id, success: false, error: 'Database error' });
            }
        }

        const successCount = results.filter(r => r.success).length;
        const failCount = results.filter(r => !r.success).length;

        return NextResponse.json({
            success: failCount === 0,
            updated: successCount,
            failed: failCount,
            results,
        });
    } catch (error) {
        console.error('Lead update API error:', error);
        return NextResponse.json(
            { error: 'Failed to update leads' },
            { status: 500 }
        );
    }
}
