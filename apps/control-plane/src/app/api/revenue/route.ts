/**
 * Revenue Stats API
 * 
 * Returns revenue metrics: MRR, ARR, LTV, churn rate, plan breakdown.
 * Used by the /revenue page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_STATS = {
    mrr: 45890, mrrGrowth: 0.08, arr: 550680, arrGrowth: 0.12,
    ltv: 2450, cac: 180, churnRate: 0.028, expansionRevenue: 4200,
    newCustomers: 24, upgrades: 12, downgrades: 3, churned: 4,
};

const DEMO_MONTHLY = [
    { month: 'Jul', mrr: 38500, newMrr: 2800, expansionMrr: 1200, churnedMrr: 850 },
    { month: 'Aug', mrr: 40200, newMrr: 2400, expansionMrr: 1500, churnedMrr: 1200 },
    { month: 'Sep', mrr: 41800, newMrr: 2900, expansionMrr: 800, churnedMrr: 1100 },
    { month: 'Oct', mrr: 43100, newMrr: 2600, expansionMrr: 1400, churnedMrr: 1700 },
    { month: 'Nov', mrr: 44500, newMrr: 3100, expansionMrr: 1200, churnedMrr: 1900 },
    { month: 'Dec', mrr: 45890, newMrr: 2800, expansionMrr: 1500, churnedMrr: 1910 },
];

const DEMO_BY_PLAN = [
    { plan: 'Enterprise', customers: 15, mrr: 14985, percentage: 0.327 },
    { plan: 'Professional', customers: 89, mrr: 17711, percentage: 0.386 },
    { plan: 'Starter', customers: 156, mrr: 7644, percentage: 0.167 },
    { plan: 'Free', customers: 432, mrr: 0, percentage: 0 },
    { plan: 'Add-ons', customers: 45, mrr: 5550, percentage: 0.121 },
];

export async function GET() {
    try {
        // TODO: Replace with real billing/subscription queries
        const mrrRows = await query<{ mrr: string }>(`
            SELECT COALESCE(SUM(
                CASE 
                    WHEN billing_period = 'monthly' THEN price_cents
                    WHEN billing_period = 'yearly' THEN price_cents / 12
                    ELSE 0 
                END
            ) / 100.0, 0) as mrr
            FROM subscriptions 
            WHERE status = 'active'
        `);

        const currentMrr = parseFloat(mrrRows[0]?.mrr || '0');

        if (currentMrr > 0) {
            // We have real subscription data
            const planRows = await query<{ plan: string; customers: string; mrr: string }>(`
                SELECT 
                    t.plan,
                    COUNT(DISTINCT t.id) as customers,
                    COALESCE(SUM(
                        CASE 
                            WHEN s.billing_period = 'monthly' THEN s.price_cents
                            WHEN s.billing_period = 'yearly' THEN s.price_cents / 12
                            ELSE 0 
                        END
                    ) / 100.0, 0) as mrr
                FROM tenants t
                LEFT JOIN subscriptions s ON s.tenant_id = t.id AND s.status = 'active'
                GROUP BY t.plan
                ORDER BY mrr DESC
            `);

            const totalMrr = planRows.reduce((sum, r) => sum + parseFloat(r.mrr), 0);
            const revenueByPlan = planRows.map(r => ({
                plan: r.plan || 'Free',
                customers: parseInt(r.customers, 10),
                mrr: parseFloat(r.mrr),
                percentage: totalMrr > 0 ? parseFloat(r.mrr) / totalMrr : 0,
            }));

            return NextResponse.json({
                stats: { ...DEMO_STATS, mrr: currentMrr, arr: currentMrr * 12 },
                monthlyData: DEMO_MONTHLY, // TODO: Build from historical data
                revenueByPlan,
            });
        }

        return NextResponse.json({
            stats: DEMO_STATS,
            monthlyData: DEMO_MONTHLY,
            revenueByPlan: DEMO_BY_PLAN,
        });
    } catch (error) {
        console.error('Revenue API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch revenue data' }, { status: 500 });
    }
}
