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
            const response = await fetch('/api/revenue', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch revenue: ${response.status}`);
            const data = await response.json();
            setStats(data.stats);
            setMonthlyData(data.monthlyData);
            setRevenueByPlan(data.revenueByPlan);
        } catch (err) {
            console.error('Failed to load revenue data:', err);
        } finally {
            setLoading(false);
        }
    }

    if (loading || !stats) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    const maxMrr = Math.max(...monthlyData.map(m => m.mrr));

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Revenue Metrics</h1>
                    <p className="text-muted-foreground mt-1">
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
                                    ? 'bg-primary text-primary-foreground'
                                    : 'bg-card border border-border text-muted-foreground hover:bg-muted/50'
                            )}
                        >
                            {p === 'month' ? 'This Month' : p === 'quarter' ? 'This Quarter' : 'This Year'}
                        </button>
                    ))}
                </div>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Monthly Recurring Revenue</div>
                    <div className="text-3xl font-bold text-foreground">{formatCurrency(stats.mrr)}</div>
                    <div className={cn('text-sm mt-1 font-medium', stats.mrrGrowth >= 0 ? 'text-success' : 'text-destructive')}>
                        {stats.mrrGrowth >= 0 ? '↑' : '↓'} {Math.abs(stats.mrrGrowth * 100).toFixed(1)}% vs last month
                    </div>
                </div>
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Annual Recurring Revenue</div>
                    <div className="text-3xl font-bold text-foreground">{formatCurrency(stats.arr)}</div>
                    <div className={cn('text-sm mt-1 font-medium', stats.arrGrowth >= 0 ? 'text-success' : 'text-destructive')}>
                        {stats.arrGrowth >= 0 ? '↑' : '↓'} {Math.abs(stats.arrGrowth * 100).toFixed(1)}% YoY
                    </div>
                </div>
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Customer Lifetime Value</div>
                    <div className="text-3xl font-bold text-foreground">{formatCurrency(stats.ltv)}</div>
                    <div className="text-sm text-muted-foreground mt-1">
                        LTV/CAC: {(stats.ltv / stats.cac).toFixed(1)}x
                    </div>
                </div>
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Monthly Churn Rate</div>
                    <div className="text-3xl font-bold text-foreground">{(stats.churnRate * 100).toFixed(2)}%</div>
                    <div className="text-sm text-muted-foreground mt-1">
                        {stats.churned} customers churned
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                {/* MRR Trend Chart */}
                <div className="lg:col-span-2 bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-bold text-foreground mb-4">MRR Trend</h2>
                    <div className="flex items-end gap-2 h-48">
                        {monthlyData.map((month) => (
                            <div key={month.month} className="flex-1 flex flex-col items-center group">
                                <div
                                    className="w-full bg-primary rounded-t group-hover:bg-primary/90 transition-colors"
                                    style={{ height: `${(month.mrr / maxMrr) * 160}px` }}
                                />
                                <div className="text-xs text-muted-foreground mt-2 font-medium">{month.month}</div>
                                <div className="text-xs font-medium text-foreground mt-1 opacity-0 group-hover:opacity-100 transition-opacity absolute bottom-8 bg-card shadow-md p-1 rounded border border-border pointer-events-none transform -translate-y-full">{formatCurrency(month.mrr)}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Customer Movement */}
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-bold text-foreground mb-4">Customer Movement</h2>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-success/10 rounded-full flex items-center justify-center text-success">
                                    New
                                </span>
                                <span className="text-muted-foreground font-medium">New Customers</span>
                            </div>
                            <span className="font-bold text-success">+{stats.newCustomers}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-info/10 rounded-full flex items-center justify-center text-info">
                                    Up
                                </span>
                                <span className="text-muted-foreground font-medium">Upgrades</span>
                            </div>
                            <span className="font-bold text-info">+{stats.upgrades}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-warning/10 rounded-full flex items-center justify-center text-warning">
                                    Down
                                </span>
                                <span className="text-muted-foreground font-medium">Downgrades</span>
                            </div>
                            <span className="font-bold text-warning">-{stats.downgrades}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-8 bg-destructive/10 rounded-full flex items-center justify-center text-destructive">
                                    Exit
                                </span>
                                <span className="text-muted-foreground font-medium">Churned</span>
                            </div>
                            <span className="font-bold text-destructive">-{stats.churned}</span>
                        </div>
                    </div>
                    <div className="mt-6 pt-4 border-t border-border">
                        <div className="flex items-center justify-between">
                            <span className="text-muted-foreground font-medium">Expansion Revenue</span>
                            <span className="font-bold text-success">+{formatCurrency(stats.expansionRevenue)}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Revenue by Plan */}
            <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                <h2 className="text-lg font-bold text-foreground mb-4">Revenue by Plan</h2>
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-border text-left">
                                <th className="pb-3 text-sm font-semibold text-muted-foreground">Plan</th>
                                <th className="pb-3 text-sm font-semibold text-muted-foreground">Customers</th>
                                <th className="pb-3 text-sm font-semibold text-muted-foreground">MRR</th>
                                <th className="pb-3 text-sm font-semibold text-muted-foreground">% of Total</th>
                                <th className="pb-3 text-sm font-semibold text-muted-foreground">Distribution</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {revenueByPlan.map((plan) => (
                                <tr key={plan.plan}>
                                    <td className="py-4 font-medium text-foreground">{plan.plan}</td>
                                    <td className="py-4 text-muted-foreground">{formatNumber(plan.customers)}</td>
                                    <td className="py-4 font-medium text-foreground">{formatCurrency(plan.mrr)}</td>
                                    <td className="py-4 text-muted-foreground">{(plan.percentage * 100).toFixed(1)}%</td>
                                    <td className="py-4">
                                        <div className="w-32 bg-muted rounded-full h-2 overflow-hidden">
                                            <div
                                                className="h-full bg-primary rounded-full"
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
                <div className="bg-success/5 rounded-xl border border-success/10 p-4">
                    <div className="text-sm text-success mb-1 font-medium">New MRR</div>
                    <div className="text-2xl font-bold text-success">
                        +{formatCurrency(monthlyData[monthlyData.length - 1].newMrr)}
                    </div>
                    <div className="text-xs text-success/80 mt-1 font-medium">From new customers</div>
                </div>
                <div className="bg-info/5 rounded-xl border border-info/10 p-4">
                    <div className="text-sm text-info mb-1 font-medium">Expansion MRR</div>
                    <div className="text-2xl font-bold text-info">
                        +{formatCurrency(monthlyData[monthlyData.length - 1].expansionMrr)}
                    </div>
                    <div className="text-xs text-info/80 mt-1 font-medium">From upgrades</div>
                </div>
                <div className="bg-destructive/5 rounded-xl border border-destructive/10 p-4">
                    <div className="text-sm text-destructive mb-1 font-medium">Churned MRR</div>
                    <div className="text-2xl font-bold text-destructive">
                        -{formatCurrency(monthlyData[monthlyData.length - 1].churnedMrr)}
                    </div>
                    <div className="text-xs text-destructive/80 mt-1 font-medium">From cancellations</div>
                </div>
            </div>
        </div>
    );
}
