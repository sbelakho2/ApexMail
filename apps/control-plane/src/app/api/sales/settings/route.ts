/**
 * Sales Settings API Route
 *
 * GET: Load saved sales settings (scoring weights, schedule, notifications)
 * PUT: Persist sales settings
 *
 * Improvement #47: Persistent scoring weights
 * Improvement #48: Persistent discovery schedule
 * Improvement #49: Persistent notification preferences
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

const OWNER_TENANT_ID = process.env.CONTROL_PLANE_OWNER_TENANT_ID || 'apexmail-owner';

async function tableExists(tableName: string): Promise<boolean> {
    const rows = await query<{ exists: boolean }>(
        `SELECT to_regclass($1) IS NOT NULL as exists`,
        [`public.${tableName}`]
    );
    return rows[0]?.exists ?? false;
}

export async function GET() {
    try {
        const hasSettings = await tableExists('sales_settings');
        if (!hasSettings) {
            // Return defaults
            return NextResponse.json({
                scoringWeights: {
                    competitorUsage: 30,
                    companySize: 20,
                    categoryFit: 20,
                    websiteTraffic: 10,
                    recentFunding: 10,
                    contactAvailability: 10,
                },
                discoveryScheduleId: 'manual',
                notificationPreferences: {
                    newLeadDiscovered: true,
                    leadOpenedEmail: true,
                    leadReplied: true,
                    demoScheduled: true,
                    dealClosed: true,
                    discoveryComplete: false,
                    weeklyPipelineSummary: false,
                },
                enabledSources: ['product_hunt', 'g2', 'capterra', 'crunchbase'],
                defaultCategories: ['Email Marketing', 'Transactional Email', 'Newsletter Platforms'],
                maxPagesPerSource: 3,
            });
        }

        const rows = await query<{
            setting_key: string;
            setting_value: string;
        }>(
            `SELECT setting_key, setting_value FROM sales_settings WHERE tenant_id = $1`,
            [OWNER_TENANT_ID]
        );

        const settings: Record<string, unknown> = {};
        for (const row of rows) {
            try {
                settings[row.setting_key] = JSON.parse(row.setting_value);
            } catch {
                settings[row.setting_key] = row.setting_value;
            }
        }

        return NextResponse.json({
            scoringWeights: settings.scoringWeights ?? {
                competitorUsage: 30,
                companySize: 20,
                categoryFit: 20,
                websiteTraffic: 10,
                recentFunding: 10,
                contactAvailability: 10,
            },
            discoveryScheduleId: settings.discoveryScheduleId ?? 'manual',
            notificationPreferences: settings.notificationPreferences ?? {
                newLeadDiscovered: true,
                leadOpenedEmail: true,
                leadReplied: true,
                demoScheduled: true,
                dealClosed: true,
                discoveryComplete: false,
                weeklyPipelineSummary: false,
            },
            enabledSources: settings.enabledSources ?? ['product_hunt', 'g2', 'capterra', 'crunchbase'],
            defaultCategories: settings.defaultCategories ?? ['Email Marketing', 'Transactional Email', 'Newsletter Platforms'],
            maxPagesPerSource: settings.maxPagesPerSource ?? 3,
        });
    } catch (error) {
        console.error('Sales settings GET error:', error);
        return NextResponse.json({ error: 'Failed to load settings' }, { status: 500 });
    }
}

export async function PUT(request: NextRequest) {
    try {
        const body = await request.json();

        const hasSettings = await tableExists('sales_settings');
        if (!hasSettings) {
            // Auto-create table
            await query(`
                CREATE TABLE IF NOT EXISTS sales_settings (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    setting_key TEXT NOT NULL,
                    setting_value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(tenant_id, setting_key)
                )
            `);
        }

        const settingsToSave: Array<{ key: string; value: unknown }> = [];

        if (body.scoringWeights) {
            settingsToSave.push({ key: 'scoringWeights', value: body.scoringWeights });
        }
        if (body.discoveryScheduleId) {
            settingsToSave.push({ key: 'discoveryScheduleId', value: body.discoveryScheduleId });
        }
        if (body.notificationPreferences) {
            settingsToSave.push({ key: 'notificationPreferences', value: body.notificationPreferences });
        }
        if (body.enabledSources) {
            settingsToSave.push({ key: 'enabledSources', value: body.enabledSources });
        }
        if (body.defaultCategories) {
            settingsToSave.push({ key: 'defaultCategories', value: body.defaultCategories });
        }
        if (body.maxPagesPerSource !== undefined) {
            settingsToSave.push({ key: 'maxPagesPerSource', value: body.maxPagesPerSource });
        }

        if (settingsToSave.length === 0) {
            return NextResponse.json({ error: 'No settings provided' }, { status: 400 });
        }

        for (const setting of settingsToSave) {
            await query(
                `INSERT INTO sales_settings (tenant_id, setting_key, setting_value, updated_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (tenant_id, setting_key)
                 DO UPDATE SET setting_value = $3, updated_at = NOW()`,
                [OWNER_TENANT_ID, setting.key, JSON.stringify(setting.value)]
            );
        }

        return NextResponse.json({
            success: true,
            savedKeys: settingsToSave.map(s => s.key),
        });
    } catch (error) {
        console.error('Sales settings PUT error:', error);
        return NextResponse.json({ error: 'Failed to save settings' }, { status: 500 });
    }
}
