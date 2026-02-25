'use client';

import { useState, useEffect, useCallback, Suspense } from 'react';
import { cn, timeAgo } from '../../lib/utils';
import { useSearchParams } from 'next/navigation';

export const dynamic = 'force-dynamic';

/**
 * Feature Flags Management - Control feature rollout
 * 
 * The owner can:
 * - Toggle global feature flags
 * - Manage beta access for tenants
 * - Configure killswitches for emergencies
 * - Set percentage rollouts
 * - Override flags per tenant
 */

interface FeatureFlag {
    id: string;
    key: string;
    name: string;
    description: string;
    type: 'boolean' | 'percentage' | 'allowlist';
    enabled: boolean;
    percentage?: number;
    allowlist?: string[]; // tenant IDs
    category: 'core' | 'beta' | 'experimental' | 'killswitch';
    createdAt: string;
    updatedAt: string;
    updatedBy: string;
}

interface TenantOverride {
    tenantId: string;
    tenantName: string;
    flagKey: string;
    value: boolean;
    reason: string;
    createdAt: string;
}



const CATEGORY_CONFIG: Record<string, { label: string; bg: string; text: string; icon: string }> = {
    core: { label: 'Core', bg: 'bg-info/10', text: 'text-info', icon: 'Core' },
    beta: { label: 'Beta', bg: 'bg-purple-500/10', text: 'text-purple-600', icon: 'Beta' },
    experimental: { label: 'Experimental', bg: 'bg-warning/10', text: 'text-warning', icon: 'Exp' },
    killswitch: { label: 'Killswitch', bg: 'bg-destructive/10', text: 'text-destructive', icon: 'Kill' },
};

function FeatureFlagsPageContent() {
    const searchParams = useSearchParams();
    const [flags, setFlags] = useState<FeatureFlag[]>([]);
    const [overrides, setOverrides] = useState<TenantOverride[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'flags' | 'overrides'>('flags');
    const [categoryFilter, setCategoryFilter] = useState<string>(searchParams.get('category') || 'all');
    const [searchQuery, setSearchQuery] = useState('');
    
    // Modal states
    const [editingFlag, setEditingFlag] = useState<FeatureFlag | null>(null);
    const [showAddOverride, setShowAddOverride] = useState(false);

    const loadData = useCallback(async () => {
        try {
            const response = await fetch('/api/features', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch features: ${response.status}`);
            const data = await response.json();
            setFlags(data.flags);
            setOverrides(data.overrides);
        } catch (err) {
            console.error('Failed to load feature flags:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
    }, [loadData]);

    function toggleFlag(flagId: string) {
        setFlags(prev => prev.map(f => 
            f.id === flagId 
                ? { ...f, enabled: !f.enabled, updatedAt: new Date().toISOString() }
                : f
        ));
    }

    function updatePercentage(flagId: string, percentage: number) {
        setFlags(prev => prev.map(f => 
            f.id === flagId 
                ? { ...f, percentage, updatedAt: new Date().toISOString() }
                : f
        ));
    }

    function deleteOverride(tenantId: string, flagKey: string) {
        const confirmed = window.confirm(
            'Remove this tenant override? The tenant will immediately fall back to default flag behavior. Recreate the override if this was accidental.'
        );
        if (!confirmed) return;

        setOverrides(prev => prev.filter(o => !(o.tenantId === tenantId && o.flagKey === flagKey)));
    }

    const filteredFlags = flags.filter(flag => {
        const matchesCategory = categoryFilter === 'all' || flag.category === categoryFilter;
        const matchesSearch = searchQuery === '' || 
            flag.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            flag.key.toLowerCase().includes(searchQuery.toLowerCase()) ||
            flag.description.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesCategory && matchesSearch;
    });

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Feature Flags</h1>
                    <p className="text-muted-foreground mt-1">
                        Control feature rollout and beta access
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={() => setShowAddOverride(true)}
                        className="px-4 py-2 bg-muted text-foreground rounded-lg text-sm hover:bg-muted/80 font-medium transition-colors"
                    >
                        + Add Override
                    </button>
                </div>
            </div>

            {/* Killswitch Warning */}
            {flags.some(f => f.category === 'killswitch' && f.enabled) && (
                <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-destructive font-medium">
                        Active Killswitches Detected
                    </div>
                    <div className="mt-2 space-y-1">
                        {flags.filter(f => f.category === 'killswitch' && f.enabled).map(f => (
                            <div key={f.id} className="text-sm text-destructive">{f.name}: {f.description}</div>
                        ))}
                    </div>
                </div>
            )}

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Total Flags</div>
                    <div className="text-2xl font-bold text-foreground mt-1">{flags.length}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Enabled</div>
                    <div className="text-2xl font-bold text-success mt-1">
                        {flags.filter(f => f.enabled).length}
                    </div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">In Beta</div>
                    <div className="text-2xl font-bold text-purple-600 mt-1">
                        {flags.filter(f => f.category === 'beta').length}
                    </div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Overrides</div>
                    <div className="text-2xl font-bold text-foreground mt-1">{overrides.length}</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-border mb-6 overflow-x-auto">
                <nav className="flex gap-6 min-w-max">
                    {[
                        { key: 'flags', label: 'Feature Flags', count: flags.length },
                        { key: 'overrides', label: 'Tenant Overrides', count: overrides.length },
                    ].map(tab => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as typeof activeTab)}
                            className={cn(
                                'flex items-center gap-2 pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                                activeTab === tab.key
                                    ? 'border-primary text-primary'
                                    : 'border-transparent text-muted-foreground hover:text-foreground'
                            )}
                        >
                            {tab.label}
                            <span className={cn(
                                'px-2.5 py-0.5 rounded-full text-xs',
                                activeTab === tab.key ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
                            )}>
                                {tab.count}
                            </span>
                        </button>
                    ))}
                </nav>
            </div>

            {/* Flags Tab */}
            {activeTab === 'flags' && (
                <>
                    {/* Filters */}
                    <div className="flex flex-col sm:flex-row gap-4 mb-6">
                        <div className="flex-1">
                            <input
                                type="text"
                                placeholder="Search flags..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full px-4 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground placeholder:text-muted-foreground"
                            />
                        </div>
                        <div className="flex gap-2 flex-wrap">
                            {['all', 'core', 'beta', 'experimental', 'killswitch'].map(cat => (
                                <button
                                    key={cat}
                                    onClick={() => setCategoryFilter(cat)}
                                    className={cn(
                                        'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                                        categoryFilter === cat
                                            ? 'bg-primary/10 text-primary'
                                            : 'bg-muted text-muted-foreground hover:bg-muted/80'
                                    )}
                                >
                                    {cat === 'all' ? 'All' : CATEGORY_CONFIG[cat]?.label || cat}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Flags List */}
                    <div className="space-y-4">
                        {filteredFlags.map(flag => {
                            const catConfig = CATEGORY_CONFIG[flag.category];
                            const flagOverrides = overrides.filter(o => o.flagKey === flag.key);
                            
                            return (
                                <div 
                                    key={flag.id}
                                    className={cn(
                                        'bg-card rounded-xl border border-border p-4 shadow-sm',
                                        flag.category === 'killswitch' && flag.enabled && 'border-destructive/30 bg-destructive/5'
                                    )}
                                >
                                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-3 mb-1">
                                                <h3 className="font-semibold text-foreground">{flag.name}</h3>
                                                <span className={cn(
                                                    'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                    catConfig.bg,
                                                    catConfig.text
                                                )}>
                                                    {catConfig.label}
                                                </span>
                                                {flagOverrides.length > 0 && (
                                                    <span className="px-2.5 py-0.5 bg-warning/10 text-warning rounded-full text-xs font-medium">
                                                        {flagOverrides.length} override{flagOverrides.length > 1 ? 's' : ''}
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-sm text-muted-foreground mb-2">{flag.description}</p>
                                            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                                <span className="font-mono bg-muted px-2.5 py-1 rounded">{flag.key}</span>
                                                <span>Updated {timeAgo(flag.updatedAt)}</span>
                                            </div>
                                        </div>
                                        
                                        <div className="flex items-center gap-4">
                                            {/* Type-specific controls */}
                                            {flag.type === 'percentage' && flag.enabled && (
                                                <div className="flex items-center gap-2">
                                                    <input
                                                        type="range"
                                                        min="0"
                                                        max="100"
                                                        value={flag.percentage || 0}
                                                        onChange={(e) => updatePercentage(flag.id, parseInt(e.target.value))}
                                                        className="w-24 h-2 bg-muted rounded-lg appearance-none cursor-pointer"
                                                    />
                                                    <span className="text-sm font-medium text-muted-foreground w-10">
                                                        {flag.percentage}%
                                                    </span>
                                                </div>
                                            )}
                                            
                                            {flag.type === 'allowlist' && flag.enabled && (
                                                <span className="text-sm text-muted-foreground">
                                                    {flag.allowlist?.length || 0} tenant{(flag.allowlist?.length || 0) !== 1 ? 's' : ''}
                                                </span>
                                            )}
                                            
                                            {/* Toggle */}
                                            <button
                                                onClick={() => toggleFlag(flag.id)}
                                                className={cn(
                                                    'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2',
                                                    flag.enabled 
                                                        ? flag.category === 'killswitch' ? 'bg-destructive' : 'bg-success'
                                                        : 'bg-muted'
                                                )}
                                            >
                                                <span
                                                    className={cn(
                                                        'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                                                        flag.enabled ? 'translate-x-5' : 'translate-x-0'
                                                    )}
                                                />
                                            </button>
                                            
                                            {/* Edit button for allowlist */}
                                            {flag.type === 'allowlist' && (
                                                <button
                                                    onClick={() => setEditingFlag(flag)}
                                                    className="p-2 text-muted-foreground hover:text-foreground transition-colors"
                                                >
                                                    Edit
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                        
                        {filteredFlags.length === 0 && (
                            <div className="text-center py-12 text-muted-foreground">
                                No feature flags match your filters
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* Overrides Tab */}
            {activeTab === 'overrides' && (
                <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[700px]">
                            <thead className="bg-muted/50 border-b border-border">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Tenant</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Flag</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Value</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Reason</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Created</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {overrides.map(override => (
                                    <tr key={`${override.tenantId}-${override.flagKey}`} className="hover:bg-muted/50">
                                        <td className="px-4 py-4">
                                            <div className="font-medium text-foreground">{override.tenantName}</div>
                                            <div className="text-xs text-muted-foreground font-mono">{override.tenantId}</div>
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className="font-mono text-sm bg-muted px-2.5 py-1 rounded">
                                                {override.flagKey}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className={cn(
                                                'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                override.value 
                                                    ? 'bg-success/10 text-success'
                                                    : 'bg-muted text-muted-foreground'
                                            )}>
                                                {override.value ? 'Enabled' : 'Disabled'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4 text-sm text-muted-foreground">
                                            {override.reason}
                                        </td>
                                        <td className="px-4 py-4 text-sm text-muted-foreground">
                                            {timeAgo(override.createdAt)}
                                        </td>
                                        <td className="px-4 py-4 text-right">
                                            <button
                                                onClick={() => deleteOverride(override.tenantId, override.flagKey)}
                                                className="text-destructive hover:text-destructive/90 text-sm font-medium"
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {overrides.length === 0 && (
                                    <tr>
                                        <td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">
                                            No tenant overrides configured
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Edit Allowlist Modal */}
            {editingFlag && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="bg-card rounded-xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto border border-border">
                        <div className="p-6 border-b border-border">
                            <h2 className="text-lg font-semibold text-foreground">
                                Edit Allowlist: {editingFlag.name}
                            </h2>
                        </div>
                        <div className="p-6">
                            <p className="text-sm text-muted-foreground mb-4">
                                Tenant IDs with access to this feature:
                            </p>
                            <div className="space-y-2 mb-4">
                                {editingFlag.allowlist?.map(tenantId => (
                                    <div key={tenantId} className="flex items-center justify-between bg-muted/30 px-3 py-2 rounded-lg border border-border">
                                        <span className="font-mono text-sm text-foreground">{tenantId}</span>
                                        <button
                                            onClick={() => {
                                                const newList = editingFlag.allowlist?.filter(id => id !== tenantId) || [];
                                                setFlags(prev => prev.map(f => 
                                                    f.id === editingFlag.id 
                                                        ? { ...f, allowlist: newList }
                                                        : f
                                                ));
                                                setEditingFlag({ ...editingFlag, allowlist: newList });
                                            }}
                                            className="text-destructive hover:text-destructive/90 text-sm"
                                        >
                                            Remove
                                        </button>
                                    </div>
                                ))}
                                {(!editingFlag.allowlist || editingFlag.allowlist.length === 0) && (
                                    <p className="text-sm text-muted-foreground text-center py-4">No tenants in allowlist</p>
                                )}
                            </div>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    placeholder="Add tenant ID..."
                                    id="new-tenant-id"
                                    className="flex-1 px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground placeholder:text-muted-foreground"
                                />
                                <button
                                    onClick={() => {
                                        const input = document.getElementById('new-tenant-id') as HTMLInputElement;
                                        const tenantId = input.value.trim();
                                        if (tenantId && !editingFlag.allowlist?.includes(tenantId)) {
                                            const newList = [...(editingFlag.allowlist || []), tenantId];
                                            setFlags(prev => prev.map(f => 
                                                f.id === editingFlag.id 
                                                    ? { ...f, allowlist: newList }
                                                    : f
                                            ));
                                            setEditingFlag({ ...editingFlag, allowlist: newList });
                                            input.value = '';
                                        }
                                    }}
                                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
                                >
                                    Add
                                </button>
                            </div>
                        </div>
                        <div className="p-6 border-t border-border bg-muted/10 flex justify-end">
                            <button
                                onClick={() => setEditingFlag(null)}
                                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
                            >
                                Done
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Add Override Modal */}
            {showAddOverride && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="bg-card rounded-xl shadow-xl max-w-lg w-full border border-border">
                        <div className="p-6 border-b border-border">
                            <h2 className="text-lg font-semibold text-foreground">Add Tenant Override</h2>
                        </div>
                        <form 
                            className="p-6 space-y-4"
                            onSubmit={(e) => {
                                e.preventDefault();
                                const form = e.target as HTMLFormElement;
                                const formData = new FormData(form);
                                const newOverride: TenantOverride = {
                                    tenantId: formData.get('tenantId') as string,
                                    tenantName: formData.get('tenantName') as string,
                                    flagKey: formData.get('flagKey') as string,
                                    value: formData.get('value') === 'true',
                                    reason: formData.get('reason') as string,
                                    createdAt: new Date().toISOString(),
                                };
                                setOverrides(prev => [...prev, newOverride]);
                                setShowAddOverride(false);
                            }}
                        >
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">Tenant ID</label>
                                <input
                                    name="tenantId"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground placeholder:text-muted-foreground"
                                    placeholder="tenant-xxx"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">Tenant Name</label>
                                <input
                                    name="tenantName"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground placeholder:text-muted-foreground"
                                    placeholder="Company Name"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">Feature Flag</label>
                                <select
                                    name="flagKey"
                                    required
                                    className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground"
                                >
                                    {flags.map(flag => (
                                        <option key={flag.key} value={flag.key}>{flag.name}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">Override Value</label>
                                <select
                                    name="value"
                                    required
                                    className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground"
                                >
                                    <option value="true">Enabled</option>
                                    <option value="false">Disabled</option>
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">Reason</label>
                                <input
                                    name="reason"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 bg-background text-foreground placeholder:text-muted-foreground"
                                    placeholder="Why this override?"
                                />
                            </div>
                            <div className="flex justify-end gap-3 pt-4">
                                <button
                                    type="button"
                                    onClick={() => setShowAddOverride(false)}
                                    className="px-4 py-2 text-muted-foreground hover:text-foreground text-sm font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
                                >
                                    Add Override
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

export default function FeatureFlagsPage() {
    return (
        <Suspense fallback={<div>Loading...</div>}>
            <FeatureFlagsPageContent />
        </Suspense>
    );
}
