/**
 * Revenue Stats API
 * 
 * Returns revenue metrics: MRR, ARR, LTV, churn rate, plan breakdown.
 * Used by the /revenue page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET() {
    try {
        const [currentMrrRows, previousMrrRows, planRows, monthlyRows, customerRows, movementRows] = await Promise.all([
            query<{ mrr: string }>(`
            SELECT COALESCE(SUM(
                CASE 
                    WHEN billing_interval = 'year' THEN amount / 12.0
                    ELSE 0 
                END
            ) / 100.0, 0) as mrr
            FROM stripe_subscriptions
            WHERE status IN ('active', 'trialing', 'past_due')
              AND canceled_at IS NULL
        `),
            query<{ mrr: string }>(`
            SELECT COALESCE(SUM(
                CASE 
                    WHEN billing_interval = 'year' THEN amount / 12.0
                    ELSE amount
                END
            ) / 100.0, 0) as mrr
            FROM stripe_subscriptions
            WHERE status IN ('active', 'trialing', 'past_due')
              AND created_at < NOW() - INTERVAL '30 days'
              AND (canceled_at IS NULL OR canceled_at >= NOW() - INTERVAL '30 days')
        `),
            query<{ plan: string; customers: string; mrr: string }>(`
                SELECT 
                    t.plan,
                    COUNT(DISTINCT t.id) as customers,
                    COALESCE(SUM(
                        CASE 
                            WHEN s.billing_interval = 'year' THEN s.amount / 12.0
                            WHEN s.billing_interval = 'month' THEN s.amount
                            ELSE 0 
                        END
                    ) / 100.0, 0) as mrr
                FROM tenants t
                LEFT JOIN stripe_subscriptions s
                  ON s.tenant_id = t.id
                 AND s.status IN ('active', 'trialing', 'past_due')
                 AND s.canceled_at IS NULL
                GROUP BY t.plan
                ORDER BY mrr DESC
        `),
            query<{ month: string; mrr: string }>(`
            WITH months AS (
                SELECT generate_series(
                    date_trunc('month', NOW()) - INTERVAL '5 months',
                    date_trunc('month', NOW()),
                    INTERVAL '1 month'
                ) AS month_start
            )
            SELECT
                to_char(month_start, 'Mon') as month,
                COALESCE(SUM(i.total) / 100.0, 0) as mrr
            FROM months m
            LEFT JOIN invoices i
              ON date_trunc('month', COALESCE(i.issued_at, i.created_at)) = m.month_start
             AND i.status IN ('paid', 'open')
            GROUP BY month_start
            ORDER BY month_start
        `),
            query<{ new_customers: string }>(`
            SELECT COUNT(*)::text as new_customers
            FROM tenants
            WHERE created_at >= NOW() - INTERVAL '30 days'
        `),
            query<{ churned: string; active: string }>(`
            SELECT
                COUNT(*) FILTER (WHERE canceled_at >= NOW() - INTERVAL '30 days')::text as churned,
                COUNT(*) FILTER (WHERE status IN ('active', 'trialing', 'past_due') AND canceled_at IS NULL)::text as active
            FROM stripe_subscriptions
        `),
        ]);

        const currentMrr = parseFloat(currentMrrRows[0]?.mrr || '0');
        const previousMrr = parseFloat(previousMrrRows[0]?.mrr || '0');
        const mrrGrowth = previousMrr > 0 ? (currentMrr - previousMrr) / previousMrr : 0;
        const arr = currentMrr * 12;
        const previousArr = previousMrr * 12;
        const arrGrowth = previousArr > 0 ? (arr - previousArr) / previousArr : 0;

        const totalMrrByPlan = planRows.reduce((sum, row) => sum + parseFloat(row.mrr || '0'), 0);
        const revenueByPlan = planRows.map((row) => {
            const planMrr = parseFloat(row.mrr || '0');
            return {
                plan: row.plan || 'free',
                customers: parseInt(row.customers || '0', 10),
                mrr: planMrr,
                percentage: totalMrrByPlan > 0 ? planMrr / totalMrrByPlan : 0,
            };
        });

        const monthlyData = monthlyRows.map((row) => ({
            month: row.month,
            mrr: parseFloat(row.mrr || '0'),
            newMrr: 0,
            expansionMrr: 0,
            churnedMrr: 0,
        }));

        const churned = parseInt(movementRows[0]?.churned || '0', 10);
        const active = parseInt(movementRows[0]?.active || '0', 10);
        const newCustomers = parseInt(customerRows[0]?.new_customers || '0', 10);

        return NextResponse.json({
            stats: {
                mrr: currentMrr,
                mrrGrowth,
                arr,
                arrGrowth,
                ltv: 0,
                cac: 0,
                churnRate: active > 0 ? churned / active : 0,
                expansionRevenue: 0,
                newCustomers,
                upgrades: 0,
                downgrades: 0,
                churned,
            },
            monthlyData,
            revenueByPlan,
        });
    } catch (error) {
        console.error('Revenue API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch revenue data' }, { status: 500 });
    }
}
