/**
 * Sales Outreach Start API Route
 * 
 * Starts a personalized outreach campaign for selected leads.
 * Uses the competitor migration template with specific offers.
 */

import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const AUTOPILOT_BASE = process.env.AUTOPILOT_API_URL || 'http://localhost:3010';

// Map offer IDs to template configurations
const OFFER_CONFIGS: Record<string, {
    templateId: string;
    subject: string;
    variables: Record<string, string>;
}> = {
    deliverability_audit: {
        templateId: 'tmpl_competitor_migration',
        subject: 'Free deliverability audit for {{domain}}',
        variables: {
            audit_link: 'https://apexmail.ee/audit',
            primary_offer: 'deliverability_audit',
        },
    },
    webhook_migration: {
        templateId: 'tmpl_competitor_migration',
        subject: 'Webhook migration guide for {{current_provider}}',
        variables: {
            webhook_guide_link: 'https://apexmail.ee/docs/webhooks/migration',
            primary_offer: 'webhook_migration',
        },
    },
    free_migration_support: {
        templateId: 'tmpl_competitor_migration',
        subject: 'Free migration support for {{company_name}}',
        variables: {
            calendar_link: 'https://cal.com/apexmail/migration',
            primary_offer: 'free_migration_support',
        },
    },
};

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { leadIds, offerId } = body;

        if (!leadIds || !Array.isArray(leadIds) || leadIds.length === 0) {
            return NextResponse.json(
                { error: 'At least one lead must be selected' },
                { status: 400 }
            );
        }

        if (!offerId || !OFFER_CONFIGS[offerId]) {
            return NextResponse.json(
                { error: 'Invalid offer ID' },
                { status: 400 }
            );
        }

        const offerConfig = OFFER_CONFIGS[offerId];

        // Create campaign via Sales Autopilot backend
        const response = await fetch(`${AUTOPILOT_BASE}/api/v1/campaigns/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenantId: 'apexmail-owner',
                name: `${offerId.replace('_', ' ')} - ${new Date().toISOString().split('T')[0]}`,
                templateId: offerConfig.templateId,
                leadIds,
                variables: offerConfig.variables,
                startImmediately: true,
            }),
            signal: AbortSignal.timeout(30000),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            return NextResponse.json(
                { error: 'Failed to create outreach campaign', details: error },
                { status: response.status }
            );
        }

        const result = await response.json();
        
        return NextResponse.json({
            success: true,
            campaignId: result.data?.campaignId || result.campaignId,
            leadsEnrolled: leadIds.length,
            offer: offerId,
        });
    } catch (error) {
        console.error('Outreach start API error:', error);
        return NextResponse.json(
            { error: 'Failed to start outreach campaign' },
            { status: 500 }
        );
    }
}
