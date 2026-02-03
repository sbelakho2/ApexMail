'use client';

import { useState, useEffect } from 'react';
import { formatNumber, formatDate, cn } from '../../lib/utils';

/**
 * Risk Monitoring - Tenant risk assessment and management
 * 
 * The owner can:
 * - View all tenants by risk level
 * - Drill down into individual tenant risk profiles
 * - Apply sending limits or restrictions
 * - Resolve risk flags
 * - Configure risk thresholds
 */

interface TenantRisk {
    tenantId: string;
    tenantName: string;
    domain: string;
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    flags: RiskFlag[];
    metrics: {
        bounceRate: number;
        complaintRate: number;
        dailyVolume: number;
        monthlyVolume: number;
    };
    limits: {
        daily: number | null;
        hourly: number | null;
    };
    lastAssessed: string;
}

interface RiskFlag {
    id: string;
    type: string;
    severity: 'warning' | 'critical';
    message: string;
    createdAt: string;
    resolved: boolean;
}

const DEMO_TENANTS: TenantRisk[] = [
    {
        tenantId: 'tenant-spammy',
        tenantName: 'Spammy Marketing Co',
        domain: 'spammy.io',
        riskScore: 92,
        riskLevel: 'critical',
        flags: [
            { id: '1', type: 'high_bounce', severity: 'critical', message: 'Bounce rate exceeds 15%', createdAt: new Date(Date.now() - 86400000).toISOString(), resolved: false },
            { id: '2', type: 'spam_complaints', severity: 'critical', message: 'Spam complaints above 0.5%', createdAt: new Date(Date.now() - 172800000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.18, complaintRate: 0.008, dailyVolume: 45000, monthlyVolume: 890000 },
        limits: { daily: 10000, hourly: 1000 },
        lastAssessed: new Date(Date.now() - 3600000).toISOString(),
    },
    {
        tenantId: 'tenant-growth',
        tenantName: 'GrowthHack Inc',
        domain: 'growthhack.co',
        riskScore: 68,
        riskLevel: 'high',
        flags: [
            { id: '3', type: 'volume_spike', severity: 'warning', message: 'Unusual volume increase (3x normal)', createdAt: new Date(Date.now() - 43200000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.06, complaintRate: 0.002, dailyVolume: 78000, monthlyVolume: 1200000 },
        limits: { daily: null, hourly: null },
        lastAssessed: new Date(Date.now() - 7200000).toISOString(),
    },
    {
        tenantId: 'tenant-newsletter',
        tenantName: 'Newsletter Pro',
        domain: 'newsletter.pro',
        riskScore: 42,
        riskLevel: 'medium',
        flags: [
            { id: '4', type: 'missing_dmarc', severity: 'warning', message: 'DMARC policy not configured', createdAt: new Date(Date.now() - 604800000).toISOString(), resolved: false },
        ],
        metrics: { bounceRate: 0.025, complaintRate: 0.0005, dailyVolume: 12000, monthlyVolume: 320000 },
        limits: { daily: null, hourly: null },
        lastAssessed: new Date(Date.now() - 14400000).toISOString(),
    },
    {
        tenantId: 'tenant-saas',
        tenantName: 'SaaS Notifications',
        domain: 'saasnotify.io',
        riskScore: 15,
        riskLevel: 'low',
        flags: [],
        metrics: { bounceRate: 0.008, complaintRate: 0.0001, dailyVolume: 85000, monthlyVolume: 2100000 },
        limits: { daily: null, hourly: null },
        lastAssessed: new Date(Date.now() - 1800000).toISOString(),
    },
    {
        tenantId: 'tenant-ecommerce',
        tenantName: 'E-Commerce Store',
        domain: 'shop.example.com',
        riskScore: 12,
        riskLevel: 'low',
        flags: [],
        metrics: { bounceRate: 0.012, complaintRate: 0.0002, dailyVolume: 25000, monthlyVolume: 650000 },
        limits: { daily: null, hourly: null },
        lastAssessed: new Date(Date.now() - 900000).toISOString(),
    },
];

export default function RiskMonitoringPage() {
    const [tenants, setTenants] = useState<TenantRisk[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTenant, setSelectedTenant] = useState<TenantRisk | null>(null);
    const [filterLevel, setFilterLevel] = useState<string>('all');

    useEffect(() => {
        loadTenants();
    }, []);

    async function loadTenants() {
        try {
            // In production: fetch from Compliance API
            setTenants(DEMO_TENANTS);
        } finally {
            setLoading(false);
        }
    }

    function applyLimit(tenantId: string, limitType: 'daily' | 'hourly', value: number | null) {
        setTenants(prev => prev.map(t => 
            t.tenantId === tenantId
                ? { ...t, limits: { ...t.limits, [limitType]: value } }
                : t
        ));
        if (selectedTenant?.tenantId === tenantId) {
            setSelectedTenant(prev => prev ? { ...prev, limits: { ...prev.limits, [limitType]: value } } : null);
        }
    }

    function resolveFlag(tenantId: string, flagId: string) {
        setTenants(prev => prev.map(t => 
            t.tenantId === tenantId
                ? { ...t, flags: t.flags.map(f => f.id === flagId ? { ...f, resolved: true } : f) }
                : t
        ));
        if (selectedTenant?.tenantId === tenantId) {
            setSelectedTenant(prev => prev ? {
                ...prev,
                flags: prev.flags.map(f => f.id === flagId ? { ...f, resolved: true } : f)
            } : null);
        }
    }

    const filteredTenants = filterLevel === 'all'
        ? tenants
        : tenants.filter(t => t.riskLevel === filterLevel);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    const riskCounts = {
        critical: tenants.filter(t => t.riskLevel === 'critical').length,
        high: tenants.filter(t => t.riskLevel === 'high').length,
        medium: tenants.filter(t => t.riskLevel === 'medium').length,
        low: tenants.filter(t => t.riskLevel === 'low').length,
    };

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Risk Monitoring</h1>
                    <p className="text-surface-500 mt-1">
                        Monitor and manage tenant sending behavior and compliance risks
                    </p>
                </div>
                <button className="px-5 py-2.5 bg-blue-600 text-white rounded-lg font-medium shadow-sm hover:bg-blue-700 transition-all hover:shadow-md">
                    Run Risk Assessment
                </button>
            </div>

            {/* Risk Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                {[
                    { level: 'critical', label: 'Critical', count: riskCounts.critical, color: 'bg-red-50 border-red-200 text-red-700 hover:bg-red-100' },
                    { level: 'high', label: 'High Risk', count: riskCounts.high, color: 'bg-orange-50 border-orange-200 text-orange-700 hover:bg-orange-100' },
                    { level: 'medium', label: 'Medium', count: riskCounts.medium, color: 'bg-amber-50 border-amber-200 text-amber-700 hover:bg-amber-100' },
                    { level: 'low', label: 'Low Risk', count: riskCounts.low, color: 'bg-emerald-50 border-emerald-200 text-emerald-700 hover:bg-emerald-100' },
                ].map(({ level, label, count, color }) => (
                    <button
                        key={level}
                        onClick={() => setFilterLevel(filterLevel === level ? 'all' : level)}
                        className={cn(
                            'rounded-xl border p-5 text-left transition-all',
                            color,
                            filterLevel === level ? 'ring-2 ring-offset-2 ring-blue-500 scale-105' : 'hover:scale-102'
                        )}
                    >
                        <div className="text-3xl font-bold mb-1">{count}</div>
                        <div className="text-sm font-medium opacity-90">{label}</div>
                    </button>
                ))}
            </div>

            {/* Tenant List */}
            <div className="bg-surface-0 rounded-xl border border-surface-200 shadow-sm overflow-hidden">
                <div className="p-4 border-b border-surface-100 bg-surface-50/50">
                    <div className="flex items-center justify-between">
                        <h2 className="font-semibold text-surface-900">Monitored Tenants</h2>
                        {filterLevel !== 'all' && (
                            <button
                                onClick={() => setFilterLevel('all')}
                                className="text-sm font-medium text-blue-600 hover:text-blue-700 hover:underline"
                            >
                                Clear filter
                            </button>
                        )}
                    </div>
                </div>
                <div className="divide-y divide-surface-100">
                    {filteredTenants.map(tenant => (
                        <div
                            key={tenant.tenantId}
                            className="p-5 hover:bg-surface-50/80 cursor-pointer transition-colors"
                            onClick={() => setSelectedTenant(tenant)}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className={cn(
                                        'w-12 h-12 rounded-full flex items-center justify-center font-bold text-lg border-2 bg-surface-0', 
                                        tenant.riskLevel === 'critical' ? 'border-red-500 text-red-600' :
                                        tenant.riskLevel === 'high' ? 'border-orange-500 text-orange-600' :
                                        tenant.riskLevel === 'medium' ? 'border-amber-400 text-amber-600' :
                                        'border-emerald-500 text-emerald-600'
                                    )}>
                                        {tenant.riskScore}
                                    </div>
                                    <div>
                                        <div className="font-bold text-surface-900 text-lg">{tenant.tenantName}</div>
                                        <div className="text-sm text-surface-500 font-mono">{tenant.domain}</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-8">
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-surface-400 uppercase tracking-wider mb-0.5">Daily Volume</div>
                                        <div className="font-semibold text-surface-900">{formatNumber(tenant.metrics.dailyVolume)}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-surface-400 uppercase tracking-wider mb-0.5">Bounce Rate</div>
                                        <div className={cn(
                                            'font-semibold px-1.5 rounded',
                                            tenant.metrics.bounceRate > 0.1 ? 'text-red-600 bg-red-50' :
                                            tenant.metrics.bounceRate > 0.05 ? 'text-amber-600 bg-amber-50' :
                                            'text-emerald-600 bg-emerald-50'
                                        )}>
                                            {(tenant.metrics.bounceRate * 100).toFixed(2)}%
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-surface-400 uppercase tracking-wider mb-0.5">Flags</div>
                                        <div className={cn(
                                            'font-semibold',
                                            tenant.flags.filter(f => !f.resolved).length > 0 ? 'text-red-600' : 'text-surface-400'
                                        )}>
                                            {tenant.flags.filter(f => !f.resolved).length} active
                                        </div>
                                    </div>
                                    {tenant.limits.daily && (
                                        <span className="px-2.5 py-1 bg-amber-100 text-amber-800 rounded-md text-xs font-bold border border-amber-200">
                                            LIMITED
                                        </span>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Tenant Detail Modal */}
            {selectedTenant && (
                <div className="fixed inset-0 bg-surface-900/40 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedTenant(null)}>
                    <div className="bg-surface-0 rounded-2xl p-6 w-full max-w-2xl shadow-2xl border border-surface-200 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-8 border-b border-surface-100 pb-6">
                            <div className="flex items-center gap-5">
                                <div className={cn(
                                    'w-16 h-16 rounded-full flex items-center justify-center font-bold text-2xl border-4 bg-surface-0 shadow-sm',
                                    selectedTenant.riskLevel === 'critical' ? 'border-red-500 text-red-600' :
                                    selectedTenant.riskLevel === 'high' ? 'border-orange-500 text-orange-600' :
                                    selectedTenant.riskLevel === 'medium' ? 'border-amber-400 text-amber-600' :
                                    'border-emerald-500 text-emerald-600'
                                )}>
                                    {selectedTenant.riskScore}
                                </div>
                                <div>
                                    <h2 className="text-2xl font-bold text-surface-900">{selectedTenant.tenantName}</h2>
                                    <div className="text-surface-500 font-mono mt-1">{selectedTenant.domain}</div>
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedTenant(null)} 
                                className="text-surface-400 hover:text-surface-600 p-2 rounded-lg hover:bg-surface-100 transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        {/* Metrics */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                            <div className="bg-surface-50 rounded-xl p-4 text-center border border-surface-200">
                                <div className={cn("text-xl font-bold", selectedTenant.metrics.bounceRate > 0.1 ? "text-red-600" : "text-surface-900")}>{(selectedTenant.metrics.bounceRate * 100).toFixed(2)}%</div>
                                <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mt-1">Bounce Rate</div>
                            </div>
                            <div className="bg-surface-50 rounded-xl p-4 text-center border border-surface-200">
                                <div className="text-xl font-bold text-surface-900">{(selectedTenant.metrics.complaintRate * 100).toFixed(3)}%</div>
                                <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mt-1">Complaint Rate</div>
                            </div>
                            <div className="bg-surface-50 rounded-xl p-4 text-center border border-surface-200">
                                <div className="text-xl font-bold text-surface-900">{formatNumber(selectedTenant.metrics.dailyVolume)}</div>
                                <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mt-1">Daily Volume</div>
                            </div>
                            <div className="bg-surface-50 rounded-xl p-4 text-center border border-surface-200">
                                <div className="text-xl font-bold text-surface-900">{formatNumber(selectedTenant.metrics.monthlyVolume)}</div>
                                <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mt-1">Monthly Volume</div>
                            </div>
                        </div>

                        {/* Active Flags */}
                        {selectedTenant.flags.filter(f => !f.resolved).length > 0 && (
                            <div className="mb-8">
                                <h3 className="font-semibold text-surface-900 mb-4 flex items-center gap-2">
                                    <span>Active Risk Flags</span>
                                    <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded-full text-xs">{selectedTenant.flags.filter(f => !f.resolved).length}</span>
                                </h3>
                                <div className="space-y-3">
                                    {selectedTenant.flags.filter(f => !f.resolved).map(flag => (
                                        <div key={flag.id} className="flex items-center justify-between p-4 bg-surface-0 rounded-xl border border-red-200 shadow-sm relative overflow-hidden group">
                                            <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500"></div>
                                            <div>
                                                <div className="flex items-center gap-3">
                                                    <span className={cn(
                                                        'px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide border',
                                                        flag.severity === 'critical' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-700 border-amber-200'
                                                    )}>
                                                        {flag.severity}
                                                    </span>
                                                    <span className="font-medium text-surface-900">{flag.message}</span>
                                                </div>
                                                <div className="text-xs text-surface-500 mt-1.5 ml-1">
                                                    Detected {formatDate(flag.createdAt)}
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => resolveFlag(selectedTenant.tenantId, flag.id)}
                                                className="px-4 py-2 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-lg text-sm font-medium hover:bg-emerald-100 transition-colors shadow-sm"
                                            >
                                                Resolve
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Sending Limits */}
                        <div className="mb-8 p-6 bg-surface-50 rounded-xl border border-surface-200">
                            <h3 className="font-semibold text-surface-900 mb-4">Enforcement & Limits</h3>
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                <div>
                                    <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-2">Daily Limit</div>
                                    <div className="flex items-center gap-2 bg-surface-0 p-1 rounded-lg border border-surface-300 focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500 transition-all">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.daily || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'daily', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 bg-transparent outline-none text-surface-900 font-medium placeholder:text-surface-300"
                                        />
                                        <span className="text-surface-400 text-sm pr-3">/day</span>
                                    </div>
                                </div>
                                <div>
                                    <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-2">Hourly Limit</div>
                                    <div className="flex items-center gap-2 bg-surface-0 p-1 rounded-lg border border-surface-300 focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500 transition-all">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.hourly || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'hourly', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 bg-transparent outline-none text-surface-900 font-medium placeholder:text-surface-300"
                                        />
                                        <span className="text-surface-400 text-sm pr-3">/hr</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-3 pt-4 border-t border-surface-100">
                            <button className="flex-1 px-5 py-2.5 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 shadow-sm transition-all hover:shadow-md">
                                View Full Audit History
                            </button>
                            <button className="px-5 py-2.5 bg-surface-0 border border-red-200 text-red-700 rounded-lg font-medium hover:bg-red-50 hover:border-red-300 shadow-sm transition-all">
                                Suspend Tenant
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
