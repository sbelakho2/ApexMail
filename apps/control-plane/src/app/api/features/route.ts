/**
 * Feature Flags API
 * 
 * Returns feature flags and tenant overrides.
 * Used by the /features page.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with DB query against a feature_flags table
const DEMO_FLAGS = [
    { id: 'f1', key: 'ai_reply_suggestions', name: 'AI Reply Suggestions', description: 'Show AI-generated reply suggestions in compose view', type: 'percentage', enabled: true, percentage: 25, category: 'beta', createdAt: '2025-01-15T00:00:00Z', updatedAt: '2025-01-20T14:30:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f2', key: 'advanced_analytics', name: 'Advanced Analytics', description: 'Enhanced analytics dashboard with ML-powered insights', type: 'percentage', enabled: true, percentage: 50, category: 'beta', createdAt: '2025-01-10T00:00:00Z', updatedAt: '2025-01-18T10:15:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f3', key: 'smart_scheduling', name: 'Smart Send Time', description: 'AI-optimized send time recommendations', type: 'boolean', enabled: true, category: 'core', createdAt: '2024-12-01T00:00:00Z', updatedAt: '2025-01-05T09:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f4', key: 'webhook_v2', name: 'Webhook API v2', description: 'New webhook payload format with additional metadata', type: 'allowlist', enabled: true, allowlist: ['tenant-001', 'tenant-002', 'tenant-003'], category: 'beta', createdAt: '2025-01-08T00:00:00Z', updatedAt: '2025-01-19T16:45:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f5', key: 'email_preview_render', name: 'Email Preview Rendering', description: 'Server-side email preview rendering', type: 'boolean', enabled: true, category: 'core', createdAt: '2024-11-15T00:00:00Z', updatedAt: '2024-12-10T11:30:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f6', key: 'bulk_import_v2', name: 'Bulk Import v2', description: 'New bulk contact import with streaming support', type: 'percentage', enabled: true, percentage: 75, category: 'beta', createdAt: '2025-01-05T00:00:00Z', updatedAt: '2025-01-17T08:20:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f7', key: 'experimental_editor', name: 'Experimental Email Editor', description: 'Next-gen drag-and-drop email editor', type: 'allowlist', enabled: true, allowlist: ['tenant-001'], category: 'experimental', createdAt: '2025-01-20T00:00:00Z', updatedAt: '2025-01-20T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f8', key: 'ks_disable_sends', name: '[KS] Disable All Sends', description: 'KILLSWITCH: Immediately halt all email sending', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f9', key: 'ks_disable_webhooks', name: '[KS] Disable Webhooks', description: 'KILLSWITCH: Stop all webhook deliveries', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f10', key: 'ks_maintenance_mode', name: '[KS] Maintenance Mode', description: 'KILLSWITCH: Show maintenance page to all users', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
];

const DEMO_OVERRIDES = [
    { tenantId: 'tenant-001', tenantName: 'Acme Corp', flagKey: 'ai_reply_suggestions', value: true, reason: 'Early beta partner', createdAt: '2025-01-15T00:00:00Z' },
    { tenantId: 'tenant-002', tenantName: 'TechStart Inc', flagKey: 'ai_reply_suggestions', value: true, reason: 'Requested beta access', createdAt: '2025-01-16T00:00:00Z' },
    { tenantId: 'tenant-005', tenantName: 'Legacy Systems Ltd', flagKey: 'bulk_import_v2', value: false, reason: 'Uses legacy API integration', createdAt: '2025-01-10T00:00:00Z' },
];

export async function GET() {
    try {
        // TODO: Replace with real feature_flags + feature_flag_overrides queries
        return NextResponse.json({
            flags: DEMO_FLAGS,
            overrides: DEMO_OVERRIDES,
        });
    } catch (error) {
        console.error('Features API error:', error);
        return NextResponse.json({
            flags: DEMO_FLAGS,
            overrides: DEMO_OVERRIDES,
        });
    }
}
