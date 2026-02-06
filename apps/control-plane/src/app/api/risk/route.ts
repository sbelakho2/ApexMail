/**
 * Risk Monitoring API
 * 
 * Returns tenants with risk profiles, flags, and metrics.
 * Used by the /risk page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_TENANTS = [
    {
        tenantId: 'tenant-spammy', tenantName: 'Spammy Marketing Co', domain: 'spammy.io', riskScore: 92, riskLevel: 'critical',
        flags: [
            { id: '1', type: 'high_bounce', severity: 'critical', message: 'Bounce rate exceeds 15%', createdAt: new Date(Date.now() - 86400000).toISOString(), resolved: false },
            { id: '2', type: 'spam_complaints', severity: 'critical', message: 'Spam complaints above 0.5%', createdAt: new Date(Date.now() - 172800000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.18, complaintRate: 0.008, dailyVolume: 45000, monthlyVolume: 890000 },
        limits: { daily: 10000, hourly: 1000 }, lastAssessed: new Date(Date.now() - 3600000).toISOString(),
    },
    {
        tenantId: 'tenant-growth', tenantName: 'GrowthHack Inc', domain: 'growthhack.co', riskScore: 68, riskLevel: 'high',
        flags: [
            { id: '3', type: 'volume_spike', severity: 'warning', message: 'Unusual volume increase (3x normal)', createdAt: new Date(Date.now() - 43200000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.06, complaintRate: 0.002, dailyVolume: 78000, monthlyVolume: 1200000 },
        limits: { daily: null, hourly: null }, lastAssessed: new Date(Date.now() - 7200000).toISOString(),
    },
    {
        tenantId: 'tenant-newsletter', tenantName: 'Newsletter Pro', domain: 'newsletter.pro', riskScore: 42, riskLevel: 'medium',
        flags: [
            { id: '4', type: 'missing_dmarc', severity: 'warning', message: 'DMARC policy not configured', createdAt: new Date(Date.now() - 604800000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.025, complaintRate: 0.0005, dailyVolume: 12000, monthlyVolume: 320000 },
        limits: { daily: null, hourly: null }, lastAssessed: new Date(Date.now() - 14400000).toISOString(),
    },
    {
        tenantId: 'tenant-saas', tenantName: 'SaaS Notifications', domain: 'saasnotify.io', riskScore: 15, riskLevel: 'low',
        flags: [],
        metrics: { bounceRate: 0.008, complaintRate: 0.0001, dailyVolume: 85000, monthlyVolume: 2100000 },
        limits: { daily: null, hourly: null }, lastAssessed: new Date(Date.now() - 1800000).toISOString(),
    },
    {
        tenantId: 'tenant-ecommerce', tenantName: 'E-Commerce Store', domain: 'shop.example.com', riskScore: 12, riskLevel: 'low',
        flags: [],
        metrics: { bounceRate: 0.012, complaintRate: 0.0002, dailyVolume: 25000, monthlyVolume: 650000 },
        limits: { daily: null, hourly: null }, lastAssessed: new Date(Date.now() - 900000).toISOString(),
    },
];

export async function GET() {
    try {
        // TODO: Replace with full risk assessment DB query
        const rows = await query<{
            id: string;
            name: string;
            domain: string;
            risk_score: number;
        }>(`
            SELECT id, name, domain, COALESCE(risk_score, 0) as risk_score
            FROM tenants
            WHERE risk_score > 0
            ORDER BY risk_score DESC
        `);

        if (rows.length === 0) {
            return NextResponse.json(DEMO_TENANTS);
        }

        const tenants = rows.map(row => {
            const riskScore = Number(row.risk_score);
            let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (riskScore >= 90) riskLevel = 'critical';
            else if (riskScore >= 70) riskLevel = 'high';
            else if (riskScore >= 40) riskLevel = 'medium';

            return {
                tenantId: row.id,
                tenantName: row.name,
                domain: row.domain,
                riskScore,
                riskLevel,
                flags: [], // TODO: join with risk_flags table
                metrics: { bounceRate: 0, complaintRate: 0, dailyVolume: 0, monthlyVolume: 0 },
                limits: { daily: null, hourly: null },
                lastAssessed: new Date().toISOString(),
            };
        });

        return NextResponse.json(tenants);
    } catch (error) {
        console.error('Risk API error:', error);
        return NextResponse.json(DEMO_TENANTS);
    }
}
