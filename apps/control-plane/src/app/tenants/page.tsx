'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { formatNumber, formatDate, formatCurrency, cn, getRiskColor } from '../../lib/utils';

/**
 * Tenants Overview - Platform-wide tenant management
 * 
 * The owner can:
 * - View all tenants and their status
 * - Access tenant details and metrics
 * - Manage tenant subscriptions
 * - Suspend/unsuspend tenants
 */

interface Tenant {
    id: string;
    name: string;
    domain: string;
    email: string;
    plan: 'free' | 'starter' | 'professional' | 'enterprise';
    status: 'active' | 'suspended' | 'churned' | 'trialing';
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    metrics: {
        emailsSentMonth: number;
        emailsSentTotal: number;
        domainsVerified: number;
        apiKeys: number;
        teamMembers: number;
    };
    billing: {
        mrr: number;
        nextBillingDate: string | null;
        paymentMethod: string | null;
    };
    createdAt: string;
    lastActiveAt: string;
}

const DEMO_TENANTS: Tenant[] = [
    { id: 'tenant-1', name: 'TechCorp Solutions', domain: 'techcorp.io', email: 'admin@techcorp.io', plan: 'enterprise', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 2500000, emailsSentTotal: 45000000, domainsVerified: 5, apiKeys: 8, teamMembers: 12 }, billing: { mrr: 999, nextBillingDate: new Date(Date.now() + 1209600000).toISOString(), paymentMethod: 'Visa •••• 4242' }, createdAt: new Date(Date.now() - 31536000000).toISOString(), lastActiveAt: new Date(Date.now() - 300000).toISOString() },
    { id: 'tenant-2', name: 'Newsletter Pro', domain: 'newsletter.pro', email: 'team@newsletter.pro', plan: 'professional', status: 'active', riskLevel: 'medium', metrics: { emailsSentMonth: 320000, emailsSentTotal: 8900000, domainsVerified: 2, apiKeys: 3, teamMembers: 4 }, billing: { mrr: 199, nextBillingDate: new Date(Date.now() + 604800000).toISOString(), paymentMethod: 'Mastercard •••• 5555' }, createdAt: new Date(Date.now() - 15768000000).toISOString(), lastActiveAt: new Date(Date.now() - 3600000).toISOString() },
    { id: 'tenant-3', name: 'StartupXYZ', domain: 'startupxyz.com', email: 'founder@startupxyz.com', plan: 'starter', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 45000, emailsSentTotal: 890000, domainsVerified: 1, apiKeys: 2, teamMembers: 2 }, billing: { mrr: 49, nextBillingDate: new Date(Date.now() + 1814400000).toISOString(), paymentMethod: 'PayPal' }, createdAt: new Date(Date.now() - 7884000000).toISOString(), lastActiveAt: new Date(Date.now() - 7200000).toISOString() },
    { id: 'tenant-4', name: 'E-Commerce Store', domain: 'shop.example.com', email: 'admin@shop.example.com', plan: 'professional', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 650000, emailsSentTotal: 12500000, domainsVerified: 3, apiKeys: 4, teamMembers: 6 }, billing: { mrr: 199, nextBillingDate: new Date(Date.now() + 2419200000).toISOString(), paymentMethod: 'Visa •••• 1234' }, createdAt: new Date(Date.now() - 23652000000).toISOString(), lastActiveAt: new Date(Date.now() - 1800000).toISOString() },
    { id: 'tenant-5', name: 'Spammy Marketing', domain: 'spammy.io', email: 'marketing@spammy.io', plan: 'starter', status: 'suspended', riskLevel: 'critical', metrics: { emailsSentMonth: 0, emailsSentTotal: 890000, domainsVerified: 1, apiKeys: 1, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: null, paymentMethod: 'Visa •••• 9999' }, createdAt: new Date(Date.now() - 5256000000).toISOString(), lastActiveAt: new Date(Date.now() - 604800000).toISOString() },
    { id: 'tenant-6', name: 'GrowthHack Inc', domain: 'growthhack.co', email: 'team@growthhack.co', plan: 'professional', status: 'active', riskLevel: 'high', metrics: { emailsSentMonth: 1200000, emailsSentTotal: 15600000, domainsVerified: 2, apiKeys: 5, teamMembers: 3 }, billing: { mrr: 199, nextBillingDate: new Date(Date.now() + 1209600000).toISOString(), paymentMethod: 'Amex •••• 8888' }, createdAt: new Date(Date.now() - 10512000000).toISOString(), lastActiveAt: new Date(Date.now() - 600000).toISOString() },
    { id: 'tenant-7', name: 'New Startup', domain: 'newstartup.dev', email: 'hello@newstartup.dev', plan: 'free', status: 'trialing', riskLevel: 'low', metrics: { emailsSentMonth: 1200, emailsSentTotal: 1200, domainsVerified: 1, apiKeys: 1, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: new Date(Date.now() + 604800000).toISOString(), paymentMethod: null }, createdAt: new Date(Date.now() - 604800000).toISOString(), lastActiveAt: new Date(Date.now() - 43200000).toISOString() },
    { id: 'tenant-8', name: 'Old Company', domain: 'oldcompany.biz', email: 'info@oldcompany.biz', plan: 'starter', status: 'churned', riskLevel: 'low', metrics: { emailsSentMonth: 0, emailsSentTotal: 234000, domainsVerified: 1, apiKeys: 0, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: null, paymentMethod: null }, createdAt: new Date(Date.now() - 31536000000).toISOString(), lastActiveAt: new Date(Date.now() - 7776000000).toISOString() },
];

const PLAN_COLORS: Record<string, string> = {
    free: 'bg-gray-100 text-gray-700',
    starter: 'bg-blue-100 text-blue-700',
    professional: 'bg-purple-100 text-purple-700',
    enterprise: 'bg-amber-100 text-amber-700',
};

const STATUS_COLORS: Record<string, string> = {
    active: 'bg-green-100 text-green-700',
    suspended: 'bg-red-100 text-red-700',
    churned: 'bg-gray-100 text-gray-500',
    trialing: 'bg-blue-100 text-blue-700',
};

export default function TenantsPage() {
    const [tenants, setTenants] = useState<Tenant[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterPlan, setFilterPlan] = useState('');
    const [filterStatus, setFilterStatus] = useState('');

    useEffect(() => {
        loadTenants();
    }, []);

    async function loadTenants() {
        try {
            // In production: fetch from API/Billing
            setTenants(DEMO_TENANTS);
        } finally {
            setLoading(false);
        }
    }

    function toggleSuspension(tenantId: string) {
        setTenants(prev => prev.map(t => 
            t.id === tenantId
                ? { ...t, status: t.status === 'suspended' ? 'active' : 'suspended' as Tenant['status'] }
                : t
        ));
    }

    const filteredTenants = tenants.filter(t => {
        if (searchQuery && !t.name.toLowerCase().includes(searchQuery.toLowerCase()) && !t.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
        if (filterPlan && t.plan !== filterPlan) return false;
        if (filterStatus && t.status !== filterStatus) return false;
        return true;
    });

    const totalMRR = tenants.filter(t => t.status === 'active').reduce((acc, t) => acc + t.billing.mrr, 0);
    const activeTenants = tenants.filter(t => t.status === 'active').length;

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Tenant Overview</h1>
                    <p className="text-gray-600 mt-1">
                        {activeTenants} active tenants • {formatCurrency(totalMRR)}/mo MRR
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                        <input
                            type="text"
                            placeholder="Search tenants..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        />
                    </div>
                    <div>
                        <select
                            value={filterPlan}
                            onChange={(e) => setFilterPlan(e.target.value)}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        >
                            <option value="">All Plans</option>
                            <option value="free">Free</option>
                            <option value="starter">Starter</option>
                            <option value="professional">Professional</option>
                            <option value="enterprise">Enterprise</option>
                        </select>
                    </div>
                    <div>
                        <select
                            value={filterStatus}
                            onChange={(e) => setFilterStatus(e.target.value)}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        >
                            <option value="">All Statuses</option>
                            <option value="active">Active</option>
                            <option value="suspended">Suspended</option>
                            <option value="trialing">Trialing</option>
                            <option value="churned">Churned</option>
                        </select>
                    </div>
                    <div>
                        <button
                            onClick={() => { setSearchQuery(''); setFilterPlan(''); setFilterStatus(''); }}
                            className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900"
                        >
                            Clear Filters
                        </button>
                    </div>
                </div>
            </div>

            {/* Tenant List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-gray-200 text-left">
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Tenant</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Plan</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Risk</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Emails/Mo</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">MRR</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Last Active</th>
                                <th className="px-4 py-3 text-xs font-medium text-gray-500 uppercase">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                            {filteredTenants.map(tenant => (
                                <tr key={tenant.id} className="hover:bg-gray-50">
                                    <td className="px-4 py-4">
                                        <div className="font-medium text-gray-900">{tenant.name}</div>
                                        <div className="text-sm text-gray-500">{tenant.domain}</div>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2 py-1 rounded text-xs font-medium', PLAN_COLORS[tenant.plan])}>
                                            {tenant.plan}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2 py-1 rounded text-xs font-medium', STATUS_COLORS[tenant.status])}>
                                            {tenant.status}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2 py-1 rounded text-xs font-medium', getRiskColor(tenant.riskLevel))}>
                                            {tenant.riskLevel}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4 font-medium">
                                        {formatNumber(tenant.metrics.emailsSentMonth)}
                                    </td>
                                    <td className="px-4 py-4 font-medium">
                                        {tenant.billing.mrr > 0 ? formatCurrency(tenant.billing.mrr) : '—'}
                                    </td>
                                    <td className="px-4 py-4 text-sm text-gray-500">
                                        {formatDate(tenant.lastActiveAt)}
                                    </td>
                                    <td className="px-4 py-4">
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => setSelectedTenant(tenant)}
                                                className="text-indigo-600 hover:text-indigo-800 text-sm"
                                            >
                                                View
                                            </button>
                                            <Link
                                                href={`/risk?tenant=${tenant.id}`}
                                                className="text-gray-500 hover:text-gray-700 text-sm"
                                            >
                                                Risk
                                            </Link>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Tenant Detail Modal */}
            {selectedTenant && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedTenant(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div>
                                <h2 className="text-xl font-bold text-gray-900">{selectedTenant.name}</h2>
                                <div className="text-gray-500">{selectedTenant.domain}</div>
                            </div>
                            <button onClick={() => setSelectedTenant(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-3 gap-4 mb-6">
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-gray-900">{formatNumber(selectedTenant.metrics.emailsSentMonth)}</div>
                                <div className="text-xs text-gray-500">Emails This Month</div>
                            </div>
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-gray-900">{selectedTenant.metrics.domainsVerified}</div>
                                <div className="text-xs text-gray-500">Verified Domains</div>
                            </div>
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-gray-900">{selectedTenant.metrics.teamMembers}</div>
                                <div className="text-xs text-gray-500">Team Members</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-6">
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Plan</label>
                                <div className={cn('inline-block px-2 py-1 rounded text-sm font-medium', PLAN_COLORS[selectedTenant.plan])}>
                                    {selectedTenant.plan}
                                </div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Status</label>
                                <div className={cn('inline-block px-2 py-1 rounded text-sm font-medium', STATUS_COLORS[selectedTenant.status])}>
                                    {selectedTenant.status}
                                </div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">MRR</label>
                                <div className="font-medium">{selectedTenant.billing.mrr > 0 ? formatCurrency(selectedTenant.billing.mrr) : 'N/A'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Payment Method</label>
                                <div className="font-medium">{selectedTenant.billing.paymentMethod || 'None'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Contact Email</label>
                                <div className="font-medium">{selectedTenant.email}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Customer Since</label>
                                <div className="font-medium">{formatDate(selectedTenant.createdAt)}</div>
                            </div>
                        </div>

                        <div className="flex gap-2">
                            <Link
                                href={`/risk?tenant=${selectedTenant.id}`}
                                className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg text-center hover:bg-indigo-700"
                            >
                                View Risk Profile
                            </Link>
                            <Link
                                href={`/audit?tenant=${selectedTenant.id}`}
                                className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
                            >
                                Audit Logs
                            </Link>
                            <button
                                onClick={() => toggleSuspension(selectedTenant.id)}
                                className={cn(
                                    'px-4 py-2 rounded-lg',
                                    selectedTenant.status === 'suspended'
                                        ? 'bg-green-100 text-green-700 hover:bg-green-200'
                                        : 'bg-red-100 text-red-700 hover:bg-red-200'
                                )}
                            >
                                {selectedTenant.status === 'suspended' ? 'Unsuspend' : 'Suspend'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
