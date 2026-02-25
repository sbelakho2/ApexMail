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



export default function RiskMonitoringPage() {
    const [tenants, setTenants] = useState<TenantRisk[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTenant, setSelectedTenant] = useState<TenantRisk | null>(null);
    const [filterLevel, setFilterLevel] = useState<string>('all');
    const [thresholds, setThresholds] = useState({
        bounceRateWarn: 5,
        bounceRateCritical: 10,
        complaintRateWarn: 1,
        complaintRateCritical: 3,
    });
    const [thresholdError, setThresholdError] = useState<string | null>(null);

    useEffect(() => {
        loadTenants();
    }, []);

    async function loadTenants() {
        try {
            const response = await fetch('/api/risk', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch risk data: ${response.status}`);
            const data = await response.json();
            setTenants(data);
        } catch (err) {
            console.error('Failed to load risk data:', err);
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
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
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
                    <h1 className="text-2xl font-bold text-foreground">Risk Monitoring</h1>
                    <p className="text-muted-foreground mt-1">
                        Monitor and manage tenant sending behavior and compliance risks
                    </p>
                </div>
                <button className="px-5 py-2.5 bg-primary text-primary-foreground rounded-lg font-medium shadow-sm hover:bg-primary/90 transition-all hover:shadow-md">
                    Run Risk Assessment
                </button>
            </div>

            <div className="mb-6 rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-sm font-semibold text-foreground">Risk Thresholds</h2>
                    <span className="text-xs text-muted-foreground">Units: percentages (%)</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <label className="text-xs text-muted-foreground">
                        Bounce warn
                        <input
                            type="number"
                            value={thresholds.bounceRateWarn}
                            onChange={(event) => {
                                const next = Number(event.target.value);
                                setThresholds(prev => ({ ...prev, bounceRateWarn: next }));
                                setThresholdError(null);
                            }}
                            title="Warn threshold for bounce rate percentage"
                            className="mt-1 w-full px-3 py-2 border border-border rounded-lg bg-background text-sm"
                        />
                    </label>
                    <label className="text-xs text-muted-foreground">
                        Bounce critical
                        <input
                            type="number"
                            value={thresholds.bounceRateCritical}
                            onChange={(event) => {
                                const next = Number(event.target.value);
                                setThresholds(prev => ({ ...prev, bounceRateCritical: next }));
                                setThresholdError(null);
                            }}
                            title="Critical threshold for bounce rate percentage"
                            className="mt-1 w-full px-3 py-2 border border-border rounded-lg bg-background text-sm"
                        />
                    </label>
                    <label className="text-xs text-muted-foreground">
                        Complaint warn
                        <input
                            type="number"
                            value={thresholds.complaintRateWarn}
                            onChange={(event) => {
                                const next = Number(event.target.value);
                                setThresholds(prev => ({ ...prev, complaintRateWarn: next }));
                                setThresholdError(null);
                            }}
                            title="Warn threshold for complaint rate percentage"
                            className="mt-1 w-full px-3 py-2 border border-border rounded-lg bg-background text-sm"
                        />
                    </label>
                    <label className="text-xs text-muted-foreground">
                        Complaint critical
                        <input
                            type="number"
                            value={thresholds.complaintRateCritical}
                            onChange={(event) => {
                                const next = Number(event.target.value);
                                setThresholds(prev => ({ ...prev, complaintRateCritical: next }));
                                setThresholdError(null);
                            }}
                            title="Critical threshold for complaint rate percentage"
                            className="mt-1 w-full px-3 py-2 border border-border rounded-lg bg-background text-sm"
                        />
                    </label>
                </div>
                <div className="mt-3 flex items-center gap-2">
                    <button
                        onClick={() => {
                            if (
                                thresholds.bounceRateWarn < 0 ||
                                thresholds.bounceRateCritical < 0 ||
                                thresholds.complaintRateWarn < 0 ||
                                thresholds.complaintRateCritical < 0 ||
                                thresholds.bounceRateWarn >= thresholds.bounceRateCritical ||
                                thresholds.complaintRateWarn >= thresholds.complaintRateCritical
                            ) {
                                setThresholdError('Thresholds invalid: warning must be lower than critical and all values must be non-negative.');
                                return;
                            }
                            setThresholdError(null);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium"
                    >
                        Validate Thresholds
                    </button>
                    {thresholdError && <span className="text-xs text-destructive">{thresholdError}</span>}
                </div>
            </div>

            {/* Risk Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                {[
                    { level: 'critical', label: 'Critical', count: riskCounts.critical, color: 'bg-destructive/10 border-destructive/20 text-destructive hover:bg-destructive/20' },
                    { level: 'high', label: 'High Risk', count: riskCounts.high, color: 'bg-orange-500/10 border-orange-500/20 text-orange-600 hover:bg-orange-500/20' },
                    { level: 'medium', label: 'Medium', count: riskCounts.medium, color: 'bg-amber-500/10 border-amber-500/20 text-amber-600 hover:bg-amber-500/20' },
                    { level: 'low', label: 'Low Risk', count: riskCounts.low, color: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 hover:bg-emerald-500/20' },
                ].map(({ level, label, count, color }) => (
                    <button
                        key={level}
                        onClick={() => setFilterLevel(filterLevel === level ? 'all' : level)}
                        className={cn(
                            'rounded-xl border p-5 text-left transition-all',
                            color,
                            filterLevel === level ? 'ring-2 ring-offset-2 ring-primary scale-105' : 'hover:scale-102'
                        )}
                    >
                        <div className="text-3xl font-bold mb-1">{count}</div>
                        <div className="text-sm font-medium opacity-90">{label}</div>
                    </button>
                ))}
            </div>

            {/* Tenant List */}
            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                <div className="p-4 border-b border-border bg-muted/50">
                    <div className="flex items-center justify-between">
                        <h2 className="font-semibold text-foreground">Monitored Tenants</h2>
                        {filterLevel !== 'all' && (
                            <button
                                onClick={() => setFilterLevel('all')}
                                className="text-sm font-medium text-primary hover:text-primary/90 hover:underline"
                            >
                                Clear filter
                            </button>
                        )}
                    </div>
                </div>
                <div className="divide-y divide-border">
                    {filteredTenants.length === 0 && (
                        <div className="p-8 text-center text-muted-foreground">
                            No tenants are available for risk scoring yet. Complete onboarding for your first tenant to start risk monitoring.
                        </div>
                    )}
                    {filteredTenants.map(tenant => (
                        <div
                            key={tenant.tenantId}
                            className="p-5 hover:bg-muted/50 cursor-pointer transition-colors"
                            onClick={() => setSelectedTenant(tenant)}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className={cn(
                                        'w-12 h-12 rounded-full flex items-center justify-center font-bold text-lg border-2 bg-card', 
                                        tenant.riskLevel === 'critical' ? 'border-destructive text-destructive' :
                                        tenant.riskLevel === 'high' ? 'border-orange-500 text-orange-600' :
                                        tenant.riskLevel === 'medium' ? 'border-amber-500 text-amber-600' :
                                        'border-emerald-500 text-emerald-600'
                                    )}>
                                        {tenant.riskScore}
                                    </div>
                                    <div>
                                        <div className="font-bold text-foreground text-lg">{tenant.tenantName}</div>
                                        <div className="text-sm text-muted-foreground font-mono">{tenant.domain}</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-8">
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-0.5">Daily Volume</div>
                                        <div className="font-semibold text-foreground">{formatNumber(tenant.metrics.dailyVolume)}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-0.5">Bounce Rate</div>
                                        <div className={cn(
                                            'font-semibold px-1.5 rounded',
                                            tenant.metrics.bounceRate * 100 > thresholds.bounceRateCritical ? 'text-destructive bg-destructive/10' :
                                            tenant.metrics.bounceRate * 100 > thresholds.bounceRateWarn ? 'text-amber-600 bg-amber-500/10' :
                                            'text-emerald-600 bg-emerald-500/10'
                                        )}>
                                            {(tenant.metrics.bounceRate * 100).toFixed(2)}%
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-0.5">Flags</div>
                                        <div className={cn(
                                            'font-semibold',
                                            tenant.flags.filter(f => !f.resolved).length > 0 ? 'text-destructive' : 'text-muted-foreground'
                                        )}>
                                            {tenant.flags.filter(f => !f.resolved).length} active
                                        </div>
                                    </div>
                                    {tenant.limits.daily && (
                                        <span className="px-2.5 py-1 bg-amber-500/10 text-amber-600 rounded-md text-xs font-bold border border-amber-500/20">
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
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedTenant(null)}>
                    <div className="bg-card rounded-2xl p-6 w-full max-w-2xl shadow-2xl border border-border max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-8 border-b border-border pb-6">
                            <div className="flex items-center gap-5">
                                <div className={cn(
                                    'w-16 h-16 rounded-full flex items-center justify-center font-bold text-2xl border-4 bg-card shadow-sm',
                                    selectedTenant.riskLevel === 'critical' ? 'border-destructive text-destructive' :
                                    selectedTenant.riskLevel === 'high' ? 'border-orange-500 text-orange-600' :
                                    selectedTenant.riskLevel === 'medium' ? 'border-amber-500 text-amber-600' :
                                    'border-emerald-500 text-emerald-600'
                                )}>
                                    {selectedTenant.riskScore}
                                </div>
                                <div>
                                    <h2 className="text-2xl font-bold text-foreground">{selectedTenant.tenantName}</h2>
                                    <div className="text-muted-foreground font-mono mt-1">{selectedTenant.domain}</div>
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedTenant(null)} 
                                className="text-muted-foreground hover:text-foreground p-2 rounded-lg hover:bg-muted transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        {/* Metrics */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                            <div className="bg-muted/50 rounded-xl p-4 text-center border border-border">
                                <div className={cn("text-xl font-bold", selectedTenant.metrics.bounceRate > 0.1 ? "text-destructive" : "text-foreground")}>{(selectedTenant.metrics.bounceRate * 100).toFixed(2)}%</div>
                                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-1">Bounce Rate</div>
                            </div>
                            <div className="bg-muted/50 rounded-xl p-4 text-center border border-border">
                                <div className="text-xl font-bold text-foreground">{(selectedTenant.metrics.complaintRate * 100).toFixed(3)}%</div>
                                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-1">Complaint Rate</div>
                            </div>
                            <div className="bg-muted/50 rounded-xl p-4 text-center border border-border">
                                <div className="text-xl font-bold text-foreground">{formatNumber(selectedTenant.metrics.dailyVolume)}</div>
                                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-1">Daily Volume</div>
                            </div>
                            <div className="bg-muted/50 rounded-xl p-4 text-center border border-border">
                                <div className="text-xl font-bold text-foreground">{formatNumber(selectedTenant.metrics.monthlyVolume)}</div>
                                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-1">Monthly Volume</div>
                            </div>
                        </div>

                        {/* Active Flags */}
                        {selectedTenant.flags.filter(f => !f.resolved).length > 0 && (
                            <div className="mb-8">
                                <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                                    <span>Active Risk Flags</span>
                                    <span className="bg-destructive/10 text-destructive px-2.5 py-0.5 rounded-full text-xs">{selectedTenant.flags.filter(f => !f.resolved).length}</span>
                                </h3>
                                <div className="space-y-3">
                                    {selectedTenant.flags.filter(f => !f.resolved).map(flag => (
                                        <div key={flag.id} className="flex items-center justify-between p-4 bg-card rounded-xl border border-destructive/20 shadow-sm relative overflow-hidden group">
                                            <div className="absolute left-0 top-0 bottom-0 w-1 bg-destructive"></div>
                                            <div>
                                                <div className="flex items-center gap-3">
                                                    <span className={cn(
                                                        'px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide border',
                                                        flag.severity === 'critical' ? 'bg-destructive/10 text-destructive border-destructive/20' : 'bg-amber-500/10 text-amber-600 border-amber-500/20'
                                                    )}>
                                                        {flag.severity}
                                                    </span>
                                                    <span className="font-medium text-foreground">{flag.message}</span>
                                                </div>
                                                <div className="text-xs text-muted-foreground mt-1.5 ml-1">
                                                    Detected {formatDate(flag.createdAt)}
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => resolveFlag(selectedTenant.tenantId, flag.id)}
                                                className="px-4 py-2 bg-emerald-500/10 text-emerald-600 border border-emerald-500/20 rounded-lg text-sm font-medium hover:bg-emerald-500/20 transition-colors shadow-sm"
                                            >
                                                Resolve
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Sending Limits */}
                        <div className="mb-8 p-6 bg-muted/30 rounded-xl border border-border">
                            <h3 className="font-semibold text-foreground mb-4">Enforcement & Limits</h3>
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                <div>
                                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Daily Limit</div>
                                    <div className="flex items-center gap-2 bg-card p-1 rounded-lg border border-border focus-within:ring-2 focus-within:ring-primary/20 focus-within:border-primary transition-all">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.daily || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'daily', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 bg-transparent outline-none text-foreground font-medium placeholder:text-muted-foreground"
                                        />
                                        <span className="text-muted-foreground text-sm pr-3">/day</span>
                                    </div>
                                </div>
                                <div>
                                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Hourly Limit</div>
                                    <div className="flex items-center gap-2 bg-card p-1 rounded-lg border border-border focus-within:ring-2 focus-within:ring-primary/20 focus-within:border-primary transition-all">
                                        <input
                                            type="number"
                                            value={selectedTenant.limits.hourly || ''}
                                            placeholder="Unlimited"
                                            onChange={(e) => applyLimit(selectedTenant.tenantId, 'hourly', e.target.value ? parseInt(e.target.value) : null)}
                                            className="flex-1 px-3 py-2 bg-transparent outline-none text-foreground font-medium placeholder:text-muted-foreground"
                                        />
                                        <span className="text-muted-foreground text-sm pr-3">/hr</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-3 pt-4 border-t border-border">
                            <button className="flex-1 px-5 py-2.5 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 shadow-sm transition-all hover:shadow-md">
                                View Full Audit History
                            </button>
                            <button className="px-5 py-2.5 bg-card border border-destructive/30 text-destructive rounded-lg font-medium hover:bg-destructive/10 hover:border-destructive/50 shadow-sm transition-all">
                                Suspend Tenant
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
