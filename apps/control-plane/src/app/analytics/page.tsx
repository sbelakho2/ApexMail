'use client';

import { useState, useRef } from 'react';
import { cn } from '../../lib/utils';
import {
    StatCard,
    DonutChart,
    BarChart,
    LineChart,
    MultiLineChart,
    FunnelChart,
    HeatMap,
    Sparkline,
    ProgressBar,
    CHART_COLORS,
} from '../../components/ui/charts';

/**
 * Analytics & Insights Dashboard
 * 
 * Provides deep, actionable insights across all business dimensions:
 * - Email Performance & Deliverability
 * - Tenant Health & Growth
 * - Revenue Analytics
 * - Sales Pipeline Performance
 * - Compliance & Risk Metrics
 */

type TimeRange = '24h' | '7d' | '30d' | '90d' | '12m';

// Demo data generators
function generateTimeSeries(days: number, baseValue: number, variance: number) {
    return Array.from({ length: days }, (_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - (days - 1 - i));
        return {
            date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
            value: Math.round(baseValue + (Math.random() - 0.5) * variance * 2),
        };
    });
}

function generateHeatMapData() {
    const data: { day: number; hour: number; value: number }[] = [];
    for (let day = 0; day < 7; day++) {
        for (let hour = 0; hour < 24; hour++) {
            // Simulate higher activity during business hours on weekdays
            const isWeekday = day >= 1 && day <= 5;
            const isBusinessHour = hour >= 9 && hour <= 17;
            const base = isWeekday && isBusinessHour ? 80 : isWeekday ? 30 : 15;
            data.push({ day, hour, value: Math.round(base + Math.random() * 40) });
        }
    }
    return data;
}

export default function AnalyticsPage() {
    const [timeRange, setTimeRange] = useState<TimeRange>('30d');
    const [activeSection, setActiveSection] = useState<'overview' | 'email' | 'tenants' | 'revenue' | 'sales'>('overview');
    const printRef = useRef<HTMLDivElement>(null);

    // Generate demo data
    const emailVolumeData = generateTimeSeries(30, 45000, 15000);
    const _deliveryRateData = generateTimeSeries(30, 98.5, 1.5);
    const revenueData = generateTimeSeries(30, 125000, 25000);
    const heatMapData = generateHeatMapData();

    const multiSeriesData = Array.from({ length: 30 }, (_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - (29 - i));
        return {
            date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
            delivered: Math.round(40000 + Math.random() * 20000),
            opened: Math.round(15000 + Math.random() * 10000),
            clicked: Math.round(3000 + Math.random() * 3000),
        };
    });

    function handlePrint() {
        window.print();
    }

    function handleExport() {
        // In production: generate CSV/PDF export
        alert('Exporting report...');
    }

    return (
        <div className="max-w-7xl mx-auto" ref={printRef}>
            {/* Print Header - Only visible when printing */}
            <div className="hidden print:block print-header mb-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-surface-900">ApexMail Analytics Report</h1>
                        <p className="text-sm text-surface-500">Generated on {new Date().toLocaleDateString()}</p>
                    </div>
                    <div className="text-right">
                        <p className="text-sm font-medium text-surface-700">Control Plane</p>
                        <p className="text-xs text-surface-500">Period: Last {timeRange}</p>
                    </div>
                </div>
            </div>

            {/* Page Header */}
            <div className="flex items-center justify-between mb-6 no-print">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Analytics & Insights</h1>
                    <p className="text-surface-600 mt-1">Deep business intelligence across all operations</p>
                </div>
                <div className="flex items-center gap-3">
                    {/* Time Range Selector */}
                    <div className="flex bg-surface-100 rounded-lg p-1">
                        {(['24h', '7d', '30d', '90d', '12m'] as TimeRange[]).map(range => (
                            <button
                                key={range}
                                onClick={() => setTimeRange(range)}
                                className={cn(
                                    'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                                    timeRange === range
                                        ? 'bg-surface-0 text-surface-900 shadow-sm'
                                        : 'text-surface-600 hover:text-surface-900'
                                )}
                            >
                                {range}
                            </button>
                        ))}
                    </div>
                    <button onClick={handleExport} className="btn-secondary">
                        📊 Export
                    </button>
                    <button onClick={handlePrint} className="btn-primary">
                        🖨️ Print Report
                    </button>
                </div>
            </div>

            {/* Section Tabs */}
            <div className="border-b border-surface-200 mb-6 no-print overflow-x-auto">
                <nav className="flex gap-6 min-w-max">
                    {[
                        { key: 'overview', label: 'Overview', icon: '📈' },
                        { key: 'email', label: 'Email Performance', icon: '✉️' },
                        { key: 'tenants', label: 'Tenant Analytics', icon: '👥' },
                        { key: 'revenue', label: 'Revenue Intelligence', icon: '💰' },
                        { key: 'sales', label: 'Sales Pipeline', icon: '🎯' },
                    ].map(tab => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveSection(tab.key as typeof activeSection)}
                            className={cn(
                                'flex items-center gap-2 pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                                activeSection === tab.key
                                    ? 'border-blue-600 text-blue-600'
                                    : 'border-transparent text-surface-500 hover:text-surface-700'
                            )}
                        >
                            <span>{tab.icon}</span>
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Overview Section */}
            {activeSection === 'overview' && (
                <div className="space-y-6">
                    {/* Key Metrics Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 print-avoid-break">
                        <StatCard label="Monthly Recurring Revenue" value="$847,320" change={12.5} trend="up" changeLabel="vs last month" icon="💰" />
                        <StatCard label="Total Emails Sent" value="12.4M" change={8.2} trend="up" changeLabel="vs last month" icon="📧" />
                        <StatCard label="Active Tenants" value="2,847" change={5.3} trend="up" changeLabel="vs last month" icon="👥" />
                        <StatCard label="Delivery Rate" value="98.7%" change={0.3} trend="up" changeLabel="vs last month" icon="✅" />
                    </div>

                    {/* Email Volume Trend */}
                    <div className="card p-6 print-avoid-break">
                        <div className="flex items-center justify-between mb-4">
                            <div>
                                <h3 className="text-lg font-semibold text-surface-900">Email Volume Trend</h3>
                                <p className="text-sm text-surface-500">Daily email volume over the selected period</p>
                            </div>
                            <div className="flex items-center gap-4">
                                <Sparkline data={emailVolumeData.slice(-7).map(d => d.value)} color={CHART_COLORS.primary} />
                                <span className="text-sm text-emerald-600 font-medium">↑ 8.2%</span>
                            </div>
                        </div>
                        <LineChart data={emailVolumeData} width={800} height={200} showArea showGrid />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Email Engagement Breakdown */}
                        <div className="card p-6 print-avoid-break">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Email Engagement</h3>
                            <MultiLineChart
                                data={multiSeriesData}
                                series={[
                                    { key: 'delivered', label: 'Delivered', color: CHART_COLORS.primary },
                                    { key: 'opened', label: 'Opened', color: CHART_COLORS.success },
                                    { key: 'clicked', label: 'Clicked', color: CHART_COLORS.warning },
                                ]}
                                width={400}
                                height={180}
                            />
                        </div>

                        {/* Revenue Distribution */}
                        <div className="card p-6 print-avoid-break">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Revenue by Plan</h3>
                            <DonutChart
                                data={[
                                    { label: 'Enterprise', value: 485000 },
                                    { label: 'Professional', value: 245000 },
                                    { label: 'Starter', value: 89000 },
                                    { label: 'Free (Trials)', value: 28320 },
                                ]}
                                size={160}
                                centerValue="$847K"
                                centerLabel="Total MRR"
                            />
                        </div>
                    </div>

                    {/* Activity Heatmap */}
                    <div className="card p-6 print-avoid-break">
                        <h3 className="text-lg font-semibold text-surface-900 mb-2">API Activity Heatmap</h3>
                        <p className="text-sm text-surface-500 mb-4">Email sends by day and hour (last 7 days)</p>
                        <HeatMap data={heatMapData} width={700} height={160} />
                    </div>

                    {/* Conversion Funnel */}
                    <div className="card p-6 print-avoid-break">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">Sales Funnel</h3>
                        <div className="flex flex-col lg:flex-row gap-6 lg:gap-8">
                            <div className="flex-1 min-w-0">
                                <FunnelChart
                                    data={[
                                        { label: 'Leads Discovered', value: 12450 },
                                        { label: 'Email Sent', value: 8234 },
                                        { label: 'Replied', value: 1847 },
                                        { label: 'Demo Scheduled', value: 423 },
                                        { label: 'Trial Started', value: 189 },
                                        { label: 'Converted', value: 67 },
                                    ]}
                                />
                            </div>
                            <div className="grid grid-cols-2 lg:grid-cols-1 lg:w-64 gap-4">
                                <div className="bg-emerald-50 rounded-lg p-4">
                                    <p className="text-sm text-emerald-700 font-medium">Overall Conversion</p>
                                    <p className="text-2xl font-bold text-emerald-800">0.54%</p>
                                    <p className="text-xs text-emerald-600">Lead → Customer</p>
                                </div>
                                <div className="bg-blue-50 rounded-lg p-4">
                                    <p className="text-sm text-blue-700 font-medium">Reply Rate</p>
                                    <p className="text-2xl font-bold text-blue-800">22.4%</p>
                                    <p className="text-xs text-blue-600">Above industry avg</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Email Performance Section */}
            {activeSection === 'email' && (
                <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                        <StatCard label="Total Sent" value="12.4M" change={8.2} trend="up" icon="📤" />
                        <StatCard label="Delivered" value="12.2M" change={8.1} trend="up" icon="✅" />
                        <StatCard label="Opened" value="4.8M" change={12.3} trend="up" icon="👁️" />
                        <StatCard label="Clicked" value="892K" change={15.7} trend="up" icon="🖱️" />
                        <StatCard label="Bounced" value="0.8%" change={-0.2} trend="up" icon="🚫" />
                    </div>

                    {/* Deliverability Health */}
                    <div className="card p-6">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">Deliverability Health by ISP</h3>
                        <div className="space-y-4">
                            {[
                                { name: 'Gmail', delivered: 98.9, inbox: 94.2, spam: 3.8, color: CHART_COLORS.danger },
                                { name: 'Microsoft 365', delivered: 99.1, inbox: 96.1, spam: 2.1, color: CHART_COLORS.primary },
                                { name: 'Yahoo/AOL', delivered: 97.8, inbox: 91.5, spam: 5.2, color: CHART_COLORS.purple },
                                { name: 'Apple iCloud', delivered: 99.4, inbox: 97.8, spam: 1.2, color: CHART_COLORS.slate },
                                { name: 'Other', delivered: 98.2, inbox: 93.4, spam: 4.1, color: CHART_COLORS.teal },
                            ].map((isp, i) => (
                                <div key={i} className="flex items-center gap-4">
                                    <div className="w-32 font-medium text-surface-700">{isp.name}</div>
                                    <div className="flex-1">
                                        <div className="flex gap-1 h-6 rounded-lg overflow-hidden">
                                            <div
                                                className="flex items-center justify-center text-xs text-white font-medium"
                                                style={{ width: `${isp.inbox}%`, backgroundColor: CHART_COLORS.success }}
                                            >
                                                {isp.inbox}% Inbox
                                            </div>
                                            <div
                                                className="flex items-center justify-center text-xs text-white font-medium"
                                                style={{ width: `${isp.spam}%`, backgroundColor: CHART_COLORS.warning }}
                                            >
                                                {isp.spam}%
                                            </div>
                                            <div
                                                className="flex items-center justify-center text-xs text-white font-medium"
                                                style={{ width: `${100 - isp.delivered}%`, backgroundColor: CHART_COLORS.danger }}
                                            />
                                        </div>
                                    </div>
                                    <div className="w-24 text-right text-sm text-surface-600">
                                        {isp.delivered}% delivered
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Bounce & Complaint Analysis */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Bounce Reasons</h3>
                            <DonutChart
                                data={[
                                    { label: 'Invalid Address', value: 42 },
                                    { label: 'Mailbox Full', value: 28 },
                                    { label: 'Domain Issues', value: 18 },
                                    { label: 'Policy Rejection', value: 12 },
                                ]}
                                size={140}
                            />
                        </div>
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Engagement by Email Type</h3>
                            <BarChart
                                data={[
                                    { label: 'Transactional', value: 45.2, color: CHART_COLORS.primary },
                                    { label: 'Marketing', value: 22.8, color: CHART_COLORS.success },
                                    { label: 'Notification', value: 38.5, color: CHART_COLORS.warning },
                                    { label: 'Newsletter', value: 18.3, color: CHART_COLORS.info },
                                ]}
                                horizontal
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Tenant Analytics Section */}
            {activeSection === 'tenants' && (
                <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <StatCard label="Total Tenants" value="2,847" change={5.3} trend="up" icon="👥" />
                        <StatCard label="Active (30d)" value="2,412" change={3.1} trend="up" icon="✅" />
                        <StatCard label="New This Month" value="143" change={12.5} trend="up" icon="🆕" />
                        <StatCard label="Churned" value="28" change={-15.2} trend="up" icon="⚠️" />
                    </div>

                    {/* Tenant Health Distribution */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Tenant Health Score Distribution</h3>
                            <BarChart
                                data={[
                                    { label: 'Excellent (90-100)', value: 1245, color: CHART_COLORS.success },
                                    { label: 'Good (70-89)', value: 892, color: CHART_COLORS.primary },
                                    { label: 'Fair (50-69)', value: 423, color: CHART_COLORS.warning },
                                    { label: 'At Risk (<50)', value: 287, color: CHART_COLORS.danger },
                                ]}
                                horizontal
                            />
                        </div>
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Tenants by Plan</h3>
                            <DonutChart
                                data={[
                                    { label: 'Enterprise', value: 156 },
                                    { label: 'Professional', value: 834 },
                                    { label: 'Starter', value: 1245 },
                                    { label: 'Free', value: 612 },
                                ]}
                                size={160}
                                centerValue="2,847"
                                centerLabel="Total"
                            />
                        </div>
                    </div>

                    {/* Top Tenants by Volume */}
                    <div className="card p-6 overflow-hidden">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">Top 10 Tenants by Email Volume</h3>
                        <div className="overflow-x-auto -mx-6 px-6">
                            <table className="data-table min-w-[600px]">
                                <thead>
                                    <tr>
                                        <th>Tenant</th>
                                        <th>Plan</th>
                                        <th>Emails Sent</th>
                                        <th>Delivery Rate</th>
                                        <th>Health Score</th>
                                        <th>MRR</th>
                                    </tr>
                                </thead>
                            <tbody>
                                {[
                                    { name: 'Acme Corp', plan: 'Enterprise', emails: 2450000, delivery: 99.2, health: 95, mrr: 12500 },
                                    { name: 'TechStart Inc', plan: 'Enterprise', emails: 1820000, delivery: 98.8, health: 92, mrr: 8900 },
                                    { name: 'Global Media', plan: 'Professional', emails: 1540000, delivery: 98.5, health: 88, mrr: 4500 },
                                    { name: 'SaaS Company', plan: 'Professional', emails: 1230000, delivery: 99.1, health: 94, mrr: 3200 },
                                    { name: 'E-Commerce Plus', plan: 'Enterprise', emails: 980000, delivery: 97.8, health: 78, mrr: 6800 },
                                ].map((t, i) => (
                                    <tr key={i}>
                                        <td className="font-medium">{t.name}</td>
                                        <td><span className={`badge ${t.plan === 'Enterprise' ? 'badge-primary' : 'badge-neutral'}`}>{t.plan}</span></td>
                                        <td>{(t.emails / 1000000).toFixed(2)}M</td>
                                        <td>{t.delivery}%</td>
                                        <td>
                                            <div className="flex items-center gap-2">
                                                <ProgressBar value={t.health} max={100} showLabel={false} size="sm" color={t.health >= 80 ? CHART_COLORS.success : t.health >= 60 ? CHART_COLORS.warning : CHART_COLORS.danger} />
                                                <span className="text-sm">{t.health}</span>
                                            </div>
                                        </td>
                                        <td className="font-medium">${t.mrr.toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        </div>
                    </div>
                </div>
            )}

            {/* Revenue Intelligence Section */}
            {activeSection === 'revenue' && (
                <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <StatCard label="MRR" value="$847,320" change={12.5} trend="up" icon="💰" />
                        <StatCard label="ARR" value="$10.2M" change={12.5} trend="up" icon="📊" />
                        <StatCard label="ARPU" value="$298" change={6.8} trend="up" icon="👤" />
                        <StatCard label="LTV" value="$8,940" change={4.2} trend="up" icon="⏳" />
                    </div>

                    {/* Revenue Trend */}
                    <div className="card p-6">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">Revenue Growth</h3>
                        <LineChart data={revenueData} width={800} height={200} color={CHART_COLORS.success} showArea showGrid />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* MRR Movement */}
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">MRR Movement (This Month)</h3>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center p-3 bg-surface-50 rounded-lg">
                                    <span className="text-surface-600">Starting MRR</span>
                                    <span className="font-semibold">$752,450</span>
                                </div>
                                <div className="flex justify-between items-center p-3 bg-emerald-50 rounded-lg">
                                    <span className="text-emerald-700">+ New MRR</span>
                                    <span className="font-semibold text-emerald-700">+$42,800</span>
                                </div>
                                <div className="flex justify-between items-center p-3 bg-blue-50 rounded-lg">
                                    <span className="text-blue-700">+ Expansion</span>
                                    <span className="font-semibold text-blue-700">+$28,450</span>
                                </div>
                                <div className="flex justify-between items-center p-3 bg-amber-50 rounded-lg">
                                    <span className="text-amber-700">- Contraction</span>
                                    <span className="font-semibold text-amber-700">-$12,380</span>
                                </div>
                                <div className="flex justify-between items-center p-3 bg-red-50 rounded-lg">
                                    <span className="text-red-700">- Churn</span>
                                    <span className="font-semibold text-red-700">-$34,000</span>
                                </div>
                                <div className="flex justify-between items-center p-3 bg-surface-900 rounded-lg text-white">
                                    <span>Ending MRR</span>
                                    <span className="font-bold">$847,320</span>
                                </div>
                            </div>
                        </div>

                        {/* Churn Analysis */}
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Churn Analysis</h3>
                            <DonutChart
                                data={[
                                    { label: 'Price', value: 35, color: CHART_COLORS.danger },
                                    { label: 'Features', value: 25, color: CHART_COLORS.warning },
                                    { label: 'Support', value: 15, color: CHART_COLORS.info },
                                    { label: 'Business Closed', value: 15, color: CHART_COLORS.slate },
                                    { label: 'Other', value: 10, color: CHART_COLORS.purple },
                                ]}
                                size={160}
                                centerValue="4.0%"
                                centerLabel="Churn Rate"
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Sales Pipeline Section */}
            {activeSection === 'sales' && (
                <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <StatCard label="Pipeline Value" value="$1.2M" change={18.5} trend="up" icon="💎" />
                        <StatCard label="Active Deals" value="234" change={12.3} trend="up" icon="🤝" />
                        <StatCard label="Win Rate" value="34.2%" change={2.5} trend="up" icon="🏆" />
                        <StatCard label="Avg Deal Size" value="$4,230" change={8.1} trend="up" icon="📈" />
                    </div>

                    {/* Sales Funnel */}
                    <div className="card p-6">
                        <h3 className="text-lg font-semibold text-surface-900 mb-4">Sales Pipeline Funnel</h3>
                        <FunnelChart
                            data={[
                                { label: 'Leads', value: 12450, color: CHART_COLORS.slate },
                                { label: 'Qualified', value: 4823, color: CHART_COLORS.info },
                                { label: 'Demo Scheduled', value: 1245, color: CHART_COLORS.primary },
                                { label: 'Proposal Sent', value: 534, color: CHART_COLORS.warning },
                                { label: 'Negotiation', value: 234, color: CHART_COLORS.purple },
                                { label: 'Closed Won', value: 80, color: CHART_COLORS.success },
                            ]}
                        />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Lead Sources */}
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Lead Sources Performance</h3>
                            <BarChart
                                data={[
                                    { label: 'LinkedIn', value: 4520, color: CHART_COLORS.primary },
                                    { label: 'Organic', value: 3240, color: CHART_COLORS.success },
                                    { label: 'Referral', value: 2180, color: CHART_COLORS.warning },
                                    { label: 'Paid Ads', value: 1560, color: CHART_COLORS.danger },
                                    { label: 'Events', value: 950, color: CHART_COLORS.purple },
                                ]}
                                horizontal
                            />
                        </div>

                        {/* Campaign Performance */}
                        <div className="card p-6">
                            <h3 className="text-lg font-semibold text-surface-900 mb-4">Top Performing Campaigns</h3>
                            <div className="space-y-3">
                                {[
                                    { name: 'SaaS Founders Q1', sent: 8234, replies: 1847, meetings: 423, conversion: 5.1 },
                                    { name: 'Enterprise IT Leaders', sent: 5420, replies: 892, meetings: 245, conversion: 4.5 },
                                    { name: 'Product Hunt Followers', sent: 3200, replies: 534, meetings: 156, conversion: 4.9 },
                                ].map((c, i) => (
                                    <div key={i} className="p-3 bg-surface-50 rounded-lg">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="font-medium text-surface-800">{c.name}</span>
                                            <span className="text-sm text-emerald-600 font-medium">{c.conversion}% conv.</span>
                                        </div>
                                        <div className="flex gap-4 text-xs text-surface-500">
                                            <span>📧 {c.sent.toLocaleString()} sent</span>
                                            <span>💬 {c.replies} replies</span>
                                            <span>📅 {c.meetings} meetings</span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Print Footer */}
            <div className="hidden print:block mt-8 pt-4 border-t border-surface-200 text-xs text-surface-500">
                <div className="flex justify-between">
                    <span>ApexMail Control Plane - Confidential</span>
                    <span>Page 1 of 1</span>
                </div>
            </div>
        </div>
    );
}
