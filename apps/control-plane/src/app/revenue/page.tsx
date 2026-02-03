'use client';

import { useState, useEffect } from 'react';
import { formatNumber, formatCurrency, cn } from '../../lib/utils';

/**
 * Revenue Metrics - Business financial dashboard
 * 
 * The owner can:
 * - Monitor MRR, ARR, and revenue trends
 * - View subscription metrics (churn, upgrades, downgrades)
 * - Track customer lifetime value
 * - Analyze revenue by plan type
 */

interface RevenueStats {
    mrr: number;
    mrrGrowth: number;
    arr: number;
    arrGrowth: number;
    ltv: number;
    cac: number;
    churnRate: number;
    expansionRevenue: number;
    newCustomers: number;
    upgrades: number;
    downgrades: number;
    churned: number;
}

interface MonthlyRevenue {
    month: string;
    mrr: number;
    newMrr: number;
    expansionMrr: number;
    churnedMrr: number;
}

interface RevenueByPlan {
    plan: string;
    customers: number;
    mrr: number;
    percentage: number;
}

const DEMO_STATS: RevenueStats = {
    mrr: 45890,
    mrrGrowth: 0.08,
    arr: 550680,
    arrGrowth: 0.12,
    ltv: 2450,
    cac: 180,
    churnRate: 0.028,
    expansionRevenue: 4200,
    newCustomers: 24,
    upgrades: 12,
    downgrades: 3,
    churned: 4,
};

const MONTHLY_DATA: MonthlyRevenue[] = [
    { month: 'Jul', mrr: 38500, newMrr: 2800, expansionMrr: 1200, churnedMrr: 850 },
    { month: 'Aug', mrr: 40200, newMrr: 2400, expansionMrr: 1500, churnedMrr: 1200 },
    { month: 'Sep', mrr: 41800, newMrr: 2900, expansionMrr: 800, churnedMrr: 1100 },
    { month: 'Oct', mrr: 43100, newMrr: 2600, expansionMrr: 1400, churnedMrr: 1700 },
    { month: 'Nov', mrr: 44500, newMrr: 3100, expansionMrr: 1200, churnedMrr: 1900 },
    { month: 'Dec', mrr: 45890, newMrr: 2800, expansionMrr: 1500, churnedMrr: 1910 },
];

const REVENUE_BY_PLAN: RevenueByPlan[] = [
    { plan: 'Enterprise', customers: 15, mrr: 14985, percentage: 0.327 },
    { plan: 'Professional', customers: 89, mrr: 17711, percentage: 0.386 },
    { plan: 'Starter', customers: 156, mrr: 7644, percentage: 0.167 },
    { plan: 'Free', customers: 432, mrr: 0, percentage: 0 },
    { plan: 'Add-ons', customers: 45, mrr: 5550, percentage: 0.121 },
];

export default function RevenuePage() {
    const [stats, setStats] = useState<RevenueStats | null>(null);
    const [monthlyData, setMonthlyData] = useState<MonthlyRevenue[]>([]);
    const [revenueByPlan, setRevenueByPlan] = useState<RevenueByPlan[]>([]);
    const [loading, setLoading] = useState(true);
    const [period, setPeriod] = useState<'month' | 'quarter' | 'year'>('month');

    useEffect(() => {
        loadRevenueData();
    }, []);

    async function loadRevenueData() {
        try {
            // In production: fetch from Billing API
            setStats(DEMO_STATS);
            setMonthlyData(MONTHLY_DATA);
            setRevenueByPlan(REVENUE_BY_PLAN);
        } finally {
            setLoading(false);
        }
    }

    if (loading || !stats) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    const maxMrr = Math.max(...monthlyData.map(m => m.mrr));

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Revenue Metrics</h1>
                    <p className="text-surface-600 mt-1">
                        Financial performance and subscription analytics
                    </p>
                </div>
                <div className="flex gap-2">
                    {(['month', 'quarter', 'year'] as const).map((p) => (
                        <button
                            key={p}
                            onClick={() => setPeriod(p)}
                            className={cn(
                                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                                period === p
                                    ? 'bg-blue-600 text-white'
                                    : 'bg-surface-0 border border-surface-200 text-surface-700 hover:bg-surface-50'
                            )}
                        >
                            {p === 'month' ? 'This Month' : p === 'quarter' ? 'This Quarter' : 'This Year'}
                        </button>
                    ))}
                </div>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="text-sm text-surface-500 mb-1">Monthly Recurring Revenue</div>
                    <div className="text-3xl font-bold text-surface-900">{formatCurrency(stats.mrr)}</div>
                    <div className={cn('text-sm mt-1 font-medium', stats.mrrGrowth >= 0 ? 'text-emerald-600' : 'text-red-600')}>
                        {stats.mrrGrowth >= 0 ? '↑' : '↓'} {Math.abs(stats.mrrGrowth * 100).toFixed(1)}% vs last month
                    </div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="text-sm text-surface-500 mb-1">Annual Recurring Revenue</div>
                    <div className="text-3xl font-bold text-surface-900">{formatCurrency(stats.arr)}</div>
                    <div className={cn('text-sm mt-1 font-medium', stats.arrGrowth >= 0 ? 'text-emerald-600' : 'text-red-600')}>
                        {stats.arrGrowth >= 0 ? '↑' : '↓'} {Math.abs(stats.arrGrowth * 100).toFixed(1)}% YoY
                    </div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="text-sm text-surface-500 mb-1">Customer Lifetime Value</div>
                    <div className="text-3xl font-bold text-surface-900">{formatCurrency(stats.ltv)}</div>
                    <div className="text-sm text-surface-500 mt-1">
                        LTV/CAC: {(stats.ltv / stats.cac).toFixed(1)}x
                    </div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="text-sm text-surface-500 mb-1">Monthly Churn Rate</div>
                    <div className="text-3xl font-bold text-surface-900">{(stats.churnRate * 100).toFixed(2)}%</div>
                    <div className="text-sm text-surface-500 mt-1">
                        {stats.churned} customers churned
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                {/* MRR Trend Chart */}
                <div className="lg:col-span-2 bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <h2 className="text-lg font-bold text-surface-900 mb-4">MRR Trend</h2>
                    <div className="flex items-end gap-2 h-48">
                        {monthlyData.map((month) => (
                            <div key={month.month} className="flex-1 flex flex-col items-center group">
                                <div
                                    className="w-full bg-blue-500 rounded-t group-hover:bg-blue-600 transition-colors"
                                    style={{ height: `${(month.mrr / maxMrr) * 160}px` }}
                                />
                                <div className="text-xs text-surface-500 mt-2 font-medium">{month.month}</div>
                                <div className="text-xs font-medium text-surface-900 mt-1 opacity-0 group-hover:opacity-100 transition-opacity absolute bottom-8 bg-surface-0 shadow-md p-1 rounded border border-surface-200 pointer-events-none transform -translate-y-full">{formatCurrency(month.mrr)}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Customer Movement */}
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <h2 className="text-lg font-bold text-surface-900 mb-4">Customer Movement</h2>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-emerald-100 rounded-full flex items-center justify-center text-emerald-600">
                                    ➕
                                </span>
                                <span className="text-surface-700 font-medium">New Customers</span>
                            </div>
                            <span className="font-bold text-emerald-600">+{stats.newCustomers}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-600">
                                    ⬆️
                                </span>
                                <span className="text-surface-700 font-medium">Upgrades</span>
                            </div>
                            <span className="font-bold text-blue-600">+{stats.upgrades}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-amber-100 rounded-full flex items-center justify-center text-amber-600">
                                    ⬇️
                                </span>
                                <span className="text-surface-700 font-medium">Downgrades</span>
                            </div>
                            <span className="font-bold text-amber-600">-{stats.downgrades}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center text-red-600">
                                    🚪
                                </span>
                                <span className="text-surface-700 font-medium">Churned</span>
                            </div>
                            <span className="font-bold text-red-600">-{stats.churned}</span>
                        </div>
                    </div>
                    <div className="mt-6 pt-4 border-t border-surface-100">
                        <div className="flex items-center justify-between">
                            <span className="text-surface-500 font-medium">Expansion Revenue</span>
                            <span className="font-bold text-emerald-600">+{formatCurrency(stats.expansionRevenue)}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Revenue by Plan */}
            <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                <h2 className="text-lg font-bold text-surface-900 mb-4">Revenue by Plan</h2>
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-surface-200 text-left">
                                <th className="pb-3 text-sm font-semibold text-surface-500">Plan</th>
                                <th className="pb-3 text-sm font-semibold text-surface-500">Customers</th>
                                <th className="pb-3 text-sm font-semibold text-surface-500">MRR</th>
                                <th className="pb-3 text-sm font-semibold text-surface-500">% of Total</th>
                                <th className="pb-3 text-sm font-semibold text-surface-500">Distribution</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-surface-100">
                            {revenueByPlan.map((plan) => (
                                <tr key={plan.plan}>
                                    <td className="py-4 font-medium text-surface-900">{plan.plan}</td>
                                    <td className="py-4 text-surface-700">{formatNumber(plan.customers)}</td>
                                    <td className="py-4 font-medium text-surface-900">{formatCurrency(plan.mrr)}</td>
                                    <td className="py-4 text-surface-700">{(plan.percentage * 100).toFixed(1)}%</td>
                                    <td className="py-4">
                                        <div className="w-32 bg-surface-100 rounded-full h-2 overflow-hidden">
                                            <div
                                                className="h-full bg-blue-500 rounded-full"
                                                style={{ width: `${plan.percentage * 100}%` }}
                                            />
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* MRR Breakdown */}
            <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-emerald-50 rounded-xl border border-emerald-200 p-4">
                    <div className="text-sm text-emerald-700 mb-1 font-medium">New MRR</div>
                    <div className="text-2xl font-bold text-emerald-900">
                        +{formatCurrency(monthlyData[monthlyData.length - 1].newMrr)}
                    </div>
                    <div className="text-xs text-emerald-600 mt-1 font-medium">From new customers</div>
                </div>
                <div className="bg-blue-50 rounded-xl border border-blue-200 p-4">
                    <div className="text-sm text-blue-700 mb-1 font-medium">Expansion MRR</div>
                    <div className="text-2xl font-bold text-blue-900">
                        +{formatCurrency(monthlyData[monthlyData.length - 1].expansionMrr)}
                    </div>
                    <div className="text-xs text-blue-600 mt-1 font-medium">From upgrades</div>
                </div>
                <div className="bg-red-50 rounded-xl border border-red-200 p-4">
                    <div className="text-sm text-red-700 mb-1 font-medium">Churned MRR</div>
                    <div className="text-2xl font-bold text-red-900">
                        -{formatCurrency(monthlyData[monthlyData.length - 1].churnedMrr)}
                    </div>
                    <div className="text-xs text-red-600 mt-1 font-medium">From cancellations</div>
                </div>
            </div>
        </div>
    );
}
