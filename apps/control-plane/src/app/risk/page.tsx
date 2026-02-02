'use client';

import { useState, useEffect } from 'react';
import { formatNumber, formatDate, cn, getRiskColor } from '../../lib/utils';

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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
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
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Risk Monitoring</h1>
                    <p className="text-gray-600 mt-1">
                        Monitor and manage tenant sending behavior and compliance risks
                    </p>
                </div>
                <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">
                    Run Risk Assessment
                </button>
            </div>

            {/* Risk Summary */}
            <div className="grid grid-cols-4 gap-4 mb-6">
                {[
                    { level: 'critical', label: 'Critical', count: riskCounts.critical, color: 'bg-red-50 border-red-200 text-red-700' },
                    { level: 'high', label: 'High Risk', count: riskCounts.high, color: 'bg-orange-50 border-orange-200 text-orange-700' },
                    { level: 'medium', label: 'Medium', count: riskCounts.medium, color: 'bg-yellow-50 border-yellow-200 text-yellow-700' },
                    { level: 'low', label: 'Low Risk', count: riskCounts.low, color: 'bg-green-50 border-green-200 text-green-700' },
                ].map(({ level, label, count, color }) => (
                    <button
                        key={level}
                        onClick={() => setFilterLevel(filterLevel === level ? 'all' : level)}
                        className={cn(
                            'rounded-xl border p-4 text-left transition-all',
                            color,
                            filterLevel === level && 'ring-2 ring-offset-2 ring-indigo-500'
                        )}
                    >
                        <div className="text-3xl font-bold">{count}</div>
                        <div className="text-sm">{label}</div>
                    </button>
                ))}
            </div>

            {/* Tenant List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="p-4 border-b border-gray-200">
                    <div className="flex items-center justify-between">
                        <h2 className="font-semibold">Monitored Tenants</h2>
                        {filterLevel !== 'all' && (
                            <button
                                onClick={() => setFilterLevel('all')}
                                className="text-sm text-indigo-600 hover:underline"
                            >
                                Clear filter
                            </button>
                        )}
                    </div>
                </div>
                <div className="divide-y divide-gray-100">
                    {filteredTenants.map(tenant => (
                        <div
                            key={tenant.tenantId}
                            className="p-4 hover:bg-gray-50 cursor-pointer"
                            onClick={() => setSelectedTenant(tenant)}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className={cn(
                                        'w-12 h-12 rounded-full flex items-center justify-center font-bold text-lg',
                                        getRiskColor(tenant.riskLevel)
                                    )}>
                                        {tenant.riskScore}
                                    </div>
                                    <div>
                                        <div className="font-medium text-gray-900">{tenant.tenantName}</div>
                                        <div className="text-sm text-gray-500">{tenant.domain}</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-6">
                                    <div className="text-right">
                                        <div className="text-sm text-gray-500">Daily Volume</div>
                                        <div className="font-medium">{formatNumber(tenant.metrics.dailyVolume)}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-sm text-gray-500">Bounce Rate</div>
                                        <div className={cn(
                                            'font-medium',
                                            tenant.metrics.bounceRate > 0.1 && 'text-red-600',
                                            tenant.metrics.bounceRate > 0.05 && tenant.metrics.bounceRate <= 0.1 && 'text-yellow-600',
                                            tenant.metrics.bounceRate <= 0.05 && 'text-green-600'
                                        )}>
                                            {(tenant.metrics.bounceRate * 100).toFixed(2)}%
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-sm text-gray-500">Flags</div>
                                        <div className={cn(
                                            'font-medium',
                                            tenant.flags.filter(f => !f.resolved).length > 0 ? 'text-red-600' : 'text-green-600'
                                        )}>
                                            {tenant.flags.filter(f => !f.resolved).length} active
                                        </div>
                                    </div>
                                    {tenant.limits.daily && (
                                        <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-xs">
                                            Limited
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
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedTenant(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div className="flex items-center gap-4">
                                <div className={cn(
                                    'w-16 h-16 rounded-full flex items-center justify-center font-bold text-2xl',
                                    getRiskColor(selectedTenant.riskLevel)
                                )}>
                                    {selectedTenant.riskScore}
                                </div>
                                <div>
                                    <h2 className="text-xl font-bold text-gray-900">{selectedTenant.tenantName}</h2>
                                    <div className="text-gray-500">{selectedTenant.domain}</div>
                                </div>
                            </div>
                            <button onClick={() => setSelectedTenant(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        {/* Metrics */}
                        <div className="grid grid-cols-4 gap-4 mb-6">
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-lg font-bold">{(selectedTenant.metrics.bounceRate * 100).toFixed(2)}%</div>
                                <div className="text-xs text-gray-500">Bounce Rate</div>
                            </div>
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-lg font-bold">{(selectedTenant.metrics.complaintRate * 100).toFixed(3)}%</div>
                                <div className="text-xs text-gray-500">Complaint Rate</div>
                            </div>
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-lg font-bold">{formatNumber(selectedTenant.metrics.dailyVolume)}</div>
                                <div className="text-xs text-gray-500">Daily Volume</div>
                            </div>
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-lg font-bold">{formatNumber(selectedTenant.metrics.monthlyVolume)}</div>
                                <div className="text-xs text-gray-500">Monthly Volume</div>
                            </div>
                        </div>

                        {/* Active Flags */}
                        {selectedTenant.flags.filter(f => !f.resolved).length > 0 && (
                            <div className="mb-6">
                                <h3 className="font-semibold mb-3">Active Risk Flags</h3>
                                <div className="space-y-2">
                                    {selectedTenant.flags.filter(f => !f.resolved).map(flag => (
                                        <div key={flag.id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-200">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className={cn(
                                                        'px-2 py-0.5 rounded text-xs font-medium',
                                                        flag.severity === 'critical' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'
                                                    )}>
                                                        {flag.severity}
                                                    </span>
                                                    <span className="font-medium text-gray-900">{flag.message}</span>
                                                </div>
                                                <div className="text-xs text-gray-500 mt-1">
                                                    Created {formatDate(flag.createdAt)}
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => resolveFlag(selectedTenant.tenantId, flag.id)}
                                                className="px-3 py-1 bg-green-100 text-green-700 rounded text-sm hover:bg-green-200"
                                            >
                                                Resolve
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Sending Limits */}
                        <div className="mb-6">
                            <h3 className="font-semibold mb-3">Sending Limits</h3>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-4 border border-gray-200 rounded-lg">
                                    <div className="text-sm text-gray-500 mb-2">Daily Limit</div>
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.daily || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'daily', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 border border-gray-200 rounded"
                                        />
                                        <span className="text-gray-500">/day</span>
                                    </div>
                                </div>
                                <div className="p-4 border border-gray-200 rounded-lg">
                                    <div className="text-sm text-gray-500 mb-2">Hourly Limit</div>
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.hourly || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'hourly', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 border border-gray-200 rounded"
                                        />
                                        <span className="text-gray-500">/hr</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-2">
                            <button className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                                View Full Audit History
                            </button>
                            <button className="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200">
                                Suspend Tenant
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
