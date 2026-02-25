'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { formatNumber, formatDate, formatCurrency, cn, getRiskColor, getStatusChipClasses } from '../../lib/utils';

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



const PLAN_COLORS: Record<string, string> = {
    free: 'bg-muted text-muted-foreground',
    starter: 'bg-primary/10 text-primary border border-primary/20',
    professional: 'bg-primary/20 text-primary border border-primary/30',
    enterprise: 'bg-primary text-primary-foreground shadow-sm',
};

export default function TenantsPage() {
    const [tenants, setTenants] = useState<Tenant[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterPlan, setFilterPlan] = useState('');
    const [filterStatus, setFilterStatus] = useState('');
    const [currentRole] = useState<'viewer' | 'operator' | 'admin' | 'owner'>('operator');
    const [virtualStart, setVirtualStart] = useState(0);

    const canExecuteTenantActions = currentRole === 'owner' || currentRole === 'admin';
    const VIRTUAL_ROWS = 30;
    const ROW_HEIGHT = 74;

    useEffect(() => {
        loadTenants();
    }, []);

    async function loadTenants() {
        try {
            const response = await fetch('/api/tenants', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch tenants: ${response.status}`);
            const data = await response.json();
            setTenants(data);
        } catch (err) {
            console.error('Failed to load tenants:', err);
        } finally {
            setLoading(false);
        }
    }

    async function toggleSuspension(tenantId: string) {
        const tenant = tenants.find(t => t.id === tenantId);
        if (!tenant) return;
        const action = tenant.status === 'suspended' ? 'unsuspend' : 'suspend';
        try {
            const res = await fetch('/api/tenants', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: tenantId, action }),
            });
            if (res.ok) {
                setTenants(prev => prev.map(t =>
                    t.id === tenantId
                        ? { ...t, status: action === 'suspend' ? 'suspended' : 'active' as Tenant['status'] }
                        : t
                ));
            }
        } catch (err) {
            console.error(`Failed to ${action} tenant:`, err);
        }
    }

    const filteredTenants = tenants.filter(t => {
        if (searchQuery && !t.name.toLowerCase().includes(searchQuery.toLowerCase()) && !t.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
        if (filterPlan && t.plan !== filterPlan) return false;
        if (filterStatus && t.status !== filterStatus) return false;
        return true;
    });

    const totalMRR = tenants.filter(t => t.status === 'active').reduce((acc, t) => acc + t.billing.mrr, 0);
    const activeTenants = tenants.filter(t => t.status === 'active').length;
    const virtualizedTenants = filteredTenants.slice(virtualStart, virtualStart + VIRTUAL_ROWS);
    const topSpacer = virtualStart * ROW_HEIGHT;
    const bottomSpacer = Math.max(0, (filteredTenants.length - (virtualStart + virtualizedTenants.length)) * ROW_HEIGHT);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Tenant Overview</h1>
                    <p className="text-muted-foreground mt-1">
                        {activeTenants} active tenants • {formatCurrency(totalMRR)}/mo MRR
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-card rounded-lg border border-border p-4 mb-6 shadow-sm">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                        <input
                            type="text"
                            placeholder="Search tenants..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full px-3 py-2 min-h-[44px] bg-background border border-border rounded-sm text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all text-foreground placeholder:text-muted-foreground"
                        />
                    </div>
                    <div>
                        <select
                            value={filterPlan}
                            onChange={(e) => setFilterPlan(e.target.value)}
                            className="w-full px-3 py-2 min-h-[44px] bg-background border border-border rounded-sm text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all text-foreground"
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
                            className="w-full px-3 py-2 min-h-[44px] bg-background border border-border rounded-sm text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all text-foreground"
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
                            className="px-4 py-2 min-h-[44px] text-sm text-muted-foreground hover:text-foreground font-medium"
                        >
                            Clear Filters
                        </button>
                    </div>
                </div>
            </div>

            {/* Tenant List */}
            <div className="bg-card rounded-lg border border-border shadow-sm">
                <div
                    className="overflow-x-auto overflow-y-auto max-h-[70vh]"
                    onScroll={(event) => {
                        const target = event.currentTarget;
                        const nextStart = Math.max(0, Math.floor(target.scrollTop / ROW_HEIGHT) - 5);
                        if (nextStart !== virtualStart) setVirtualStart(nextStart);
                    }}
                >
                    <table className="w-full">
                        <thead className="sticky top-0 z-10">
                            <tr className="border-b border-border text-left bg-muted/50">
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Tenant</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Plan</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Status</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Risk</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Emails/Mo</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">MRR</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Last active</th>
                                <th className="px-4 py-3 text-sm font-semibold text-muted-foreground">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {filteredTenants.length === 0 && (
                                <tr>
                                    <td colSpan={8} className="px-4 py-10 text-center text-sm text-muted-foreground">
                                        No tenants found. For onboarding-first admin accounts, tenant rows appear after the first workspace signup completes.
                                    </td>
                                </tr>
                            )}
                            {topSpacer > 0 && (
                                <tr aria-hidden="true" className="border-0">
                                    <td colSpan={8} style={{ height: `${topSpacer}px` }} />
                                </tr>
                            )}
                            {virtualizedTenants.map(tenant => (
                                <tr key={tenant.id} className="hover:bg-muted/50 transition-colors">
                                    <td className="px-4 py-4">
                                        <div className="font-medium text-foreground">{tenant.name}</div>
                                        <div className="text-sm text-muted-foreground font-mono">{tenant.domain}</div>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', PLAN_COLORS[tenant.plan] || 'bg-muted text-muted-foreground')}>
                                            {tenant.plan}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', getStatusChipClasses(tenant.status))}>
                                            {tenant.status}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', getRiskColor(tenant.riskLevel))}>
                                            {tenant.riskLevel}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4 font-medium text-foreground/80 apex-metric-number">
                                        {formatNumber(tenant.metrics.emailsSentMonth)}
                                    </td>
                                    <td className="px-4 py-4 font-medium text-foreground/80 apex-metric-number">
                                        {tenant.billing.mrr > 0 ? formatCurrency(tenant.billing.mrr) : '—'}
                                    </td>
                                    <td className="px-4 py-4 text-sm text-muted-foreground">
                                        {formatDate(tenant.lastActiveAt)}
                                    </td>
                                    <td className="px-4 py-4">
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => setSelectedTenant(tenant)}
                                                className="text-primary hover:text-primary/80 text-sm font-medium min-w-[44px] min-h-[44px] inline-flex items-center justify-center"
                                                aria-label={`View tenant ${tenant.name}`}
                                            >
                                                View
                                            </button>
                                            <Link
                                                href={`/risk?tenant=${tenant.id}`}
                                                className="text-muted-foreground hover:text-foreground text-sm font-medium min-w-[44px] min-h-[44px] inline-flex items-center justify-center"
                                                aria-label={`View risk profile for ${tenant.name}`}
                                            >
                                                Risk
                                            </Link>
                                            <button
                                                onClick={() => toggleSuspension(tenant.id)}
                                                disabled={!canExecuteTenantActions}
                                                className={cn(
                                                    'text-sm font-medium min-w-[44px] min-h-[44px] inline-flex items-center justify-center px-2 rounded',
                                                    canExecuteTenantActions
                                                        ? 'text-warning hover:text-warning/80'
                                                        : 'text-muted-foreground cursor-not-allowed opacity-60'
                                                )}
                                                title={canExecuteTenantActions ? '' : 'Only admin/owner can suspend or unsuspend tenants'}
                                            >
                                                {tenant.status === 'suspended' ? 'Unsuspend' : 'Suspend'}
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {bottomSpacer > 0 && (
                                <tr aria-hidden="true" className="border-0">
                                    <td colSpan={8} style={{ height: `${bottomSpacer}px` }} />
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Tenant Detail Modal */}
            {selectedTenant && (
                <div className="fixed inset-0 bg-background/80 flex items-center justify-center z-50 backdrop-blur-sm" onClick={() => setSelectedTenant(null)}>
                    <div className="bg-card rounded-lg p-6 w-full max-w-2xl shadow-xl border border-border max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div>
                                <h2 className="text-xl font-bold text-foreground">{selectedTenant.name}</h2>
                                <div className="text-muted-foreground">{selectedTenant.domain}</div>
                            </div>
                            <button 
                                onClick={() => setSelectedTenant(null)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                            <div className="bg-muted rounded-lg p-3 text-center border border-border">
                                <div className="text-xl font-bold text-foreground apex-metric-number">{formatNumber(selectedTenant.metrics.emailsSentMonth)}</div>
                                <div className="text-sm text-muted-foreground font-medium">Emails this month</div>
                            </div>
                            <div className="bg-muted rounded-lg p-3 text-center border border-border">
                                <div className="text-xl font-bold text-foreground apex-metric-number">{selectedTenant.metrics.domainsVerified}</div>
                                <div className="text-sm text-muted-foreground font-medium">Verified domains</div>
                            </div>
                            <div className="bg-muted rounded-lg p-3 text-center border border-border">
                                <div className="text-xl font-bold text-foreground apex-metric-number">{selectedTenant.metrics.teamMembers}</div>
                                <div className="text-sm text-muted-foreground font-medium">Team members</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">Plan</label>
                                <div className="mt-1">
                                    <div className={cn('inline-block px-2.5 py-0.5 rounded-full text-sm font-medium', PLAN_COLORS[selectedTenant.plan] || 'bg-muted text-muted-foreground')}>
                                        {selectedTenant.plan}
                                    </div>
                                </div>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">Status</label>
                                <div className="mt-1">
                                    <div className={cn('inline-block px-2.5 py-0.5 rounded-full text-sm font-medium', STATUS_COLORS[selectedTenant.status])}>
                                        {selectedTenant.status}
                                    </div>
                                </div>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">MRR</label>
                                <div className="font-medium text-foreground mt-1 apex-metric-number">{selectedTenant.billing.mrr > 0 ? formatCurrency(selectedTenant.billing.mrr) : 'N/A'}</div>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">Payment method</label>
                                <div className="font-medium text-surface-900 mt-1">{selectedTenant.billing.paymentMethod || 'None'}</div>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">Contact email</label>
                                <div className="font-medium text-foreground mt-1">{selectedTenant.email}</div>
                            </div>
                            <div>
                                <label className="text-sm text-muted-foreground font-semibold">Customer since</label>
                                <div className="font-medium text-foreground mt-1">{formatDate(selectedTenant.createdAt)}</div>
                            </div>
                        </div>

                        <div className="flex gap-3 pt-6 border-t border-border">
                            <button
                                onClick={async () => {
                                    // Generate impersonation token via API
                                    try {
                                        const response = await fetch('/api/impersonate', {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({
                                                tenantId: selectedTenant.id,
                                                tenantName: selectedTenant.name,
                                            }),
                                        });
                                        
                                        if (response.ok) {
                                            const data = await response.json();
                                            // Open console in new tab with impersonation token
                                            window.open(data.url, '_blank');
                                        } else {
                                            console.error('Failed to generate impersonation token');
                                            // Fallback to direct URL (dev mode)
                                            const impersonateUrl = `${process.env.NEXT_PUBLIC_CONSOLE_URL || 'http://localhost:3000'}?impersonate=${selectedTenant.id}`;
                                            window.open(impersonateUrl, '_blank');
                                        }
                                    } catch (error) {
                                        console.error('Impersonation error:', error);
                                        // Fallback to direct URL
                                        const impersonateUrl = `${process.env.NEXT_PUBLIC_CONSOLE_URL || 'http://localhost:3000'}?impersonate=${selectedTenant.id}`;
                                        window.open(impersonateUrl, '_blank');
                                    }
                                }}
                                className="flex-1 px-4 py-2 min-h-[44px] bg-warning text-warning-foreground rounded-sm text-center hover:bg-warning/90 font-medium transition-colors flex items-center justify-center gap-2"
                            >
                                Impersonate User
                            </button>
                            <Link
                                href={`/support?tenant=${selectedTenant.id}`}
                                className="px-4 py-2 min-h-[44px] bg-primary text-primary-foreground rounded-sm hover:bg-primary/90 font-medium transition-colors inline-flex items-center"
                            >
                                Support
                            </Link>
                        </div>
                        <div className="flex gap-3 pt-3">
                            <Link
                                href={`/risk?tenant=${selectedTenant.id}`}
                                className="flex-1 px-4 py-2 min-h-[44px] bg-secondary text-secondary-foreground rounded-sm text-center hover:bg-secondary/80 font-medium transition-colors inline-flex items-center justify-center"
                            >
                                Risk Profile
                            </Link>
                            <Link
                                href={`/audit?tenant=${selectedTenant.id}`}
                                className="px-4 py-2 min-h-[44px] bg-secondary text-secondary-foreground rounded-sm hover:bg-secondary/80 font-medium transition-colors inline-flex items-center"
                            >
                                Audit Logs
                            </Link>
                            <button
                                onClick={() => toggleSuspension(selectedTenant.id)}
                                className={cn(
                                    'px-4 py-2 min-h-[44px] rounded-sm font-medium transition-colors',
                                    selectedTenant.status === 'suspended'
                                        ? 'bg-success/10 text-success hover:bg-success/20'
                                        : 'bg-destructive/10 text-destructive hover:bg-destructive/20'
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
