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

const DEMO_FLAGS: FeatureFlag[] = [
    { id: 'f1', key: 'ai_reply_suggestions', name: 'AI Reply Suggestions', description: 'Show AI-generated reply suggestions in compose view', type: 'percentage', enabled: true, percentage: 25, category: 'beta', createdAt: '2025-01-15T00:00:00Z', updatedAt: '2025-01-20T14:30:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f2', key: 'advanced_analytics', name: 'Advanced Analytics', description: 'Enhanced analytics dashboard with ML-powered insights', type: 'percentage', enabled: true, percentage: 50, category: 'beta', createdAt: '2025-01-10T00:00:00Z', updatedAt: '2025-01-18T10:15:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f3', key: 'smart_scheduling', name: 'Smart Send Time', description: 'AI-optimized send time recommendations', type: 'boolean', enabled: true, category: 'core', createdAt: '2024-12-01T00:00:00Z', updatedAt: '2025-01-05T09:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f4', key: 'webhook_v2', name: 'Webhook API v2', description: 'New webhook payload format with additional metadata', type: 'allowlist', enabled: true, allowlist: ['tenant-001', 'tenant-002', 'tenant-003'], category: 'beta', createdAt: '2025-01-08T00:00:00Z', updatedAt: '2025-01-19T16:45:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f5', key: 'email_preview_render', name: 'Email Preview Rendering', description: 'Server-side email preview rendering', type: 'boolean', enabled: true, category: 'core', createdAt: '2024-11-15T00:00:00Z', updatedAt: '2024-12-10T11:30:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f6', key: 'bulk_import_v2', name: 'Bulk Import v2', description: 'New bulk contact import with streaming support', type: 'percentage', enabled: true, percentage: 75, category: 'beta', createdAt: '2025-01-05T00:00:00Z', updatedAt: '2025-01-17T08:20:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f7', key: 'experimental_editor', name: 'Experimental Email Editor', description: 'Next-gen drag-and-drop email editor', type: 'allowlist', enabled: true, allowlist: ['tenant-001'], category: 'experimental', createdAt: '2025-01-20T00:00:00Z', updatedAt: '2025-01-20T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f8', key: 'ks_disable_sends', name: '[KS] Disable All Sends', description: 'KILLSWITCH: Immediately halt all email sending', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f9', key: 'ks_disable_webhooks', name: '[KS] Disable Webhooks', description: 'KILLSWITCH: Stop all webhook deliveries', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
    { id: 'f10', key: 'ks_maintenance_mode', name: '[KS] Maintenance Mode', description: 'KILLSWITCH: Show maintenance page to all users', type: 'boolean', enabled: false, category: 'killswitch', createdAt: '2024-10-01T00:00:00Z', updatedAt: '2024-10-01T00:00:00Z', updatedBy: 'admin@apexmail.io' },
];

const DEMO_OVERRIDES: TenantOverride[] = [
    { tenantId: 'tenant-001', tenantName: 'Acme Corp', flagKey: 'ai_reply_suggestions', value: true, reason: 'Early beta partner', createdAt: '2025-01-15T00:00:00Z' },
    { tenantId: 'tenant-002', tenantName: 'TechStart Inc', flagKey: 'ai_reply_suggestions', value: true, reason: 'Requested beta access', createdAt: '2025-01-16T00:00:00Z' },
    { tenantId: 'tenant-005', tenantName: 'Legacy Systems Ltd', flagKey: 'bulk_import_v2', value: false, reason: 'Uses legacy API integration', createdAt: '2025-01-10T00:00:00Z' },
];

const CATEGORY_CONFIG: Record<string, { label: string; bg: string; text: string; icon: string }> = {
    core: { label: 'Core', bg: 'bg-blue-100', text: 'text-blue-700', icon: '🔵' },
    beta: { label: 'Beta', bg: 'bg-violet-100', text: 'text-violet-700', icon: '🟣' },
    experimental: { label: 'Experimental', bg: 'bg-amber-100', text: 'text-amber-700', icon: '🟡' },
    killswitch: { label: 'Killswitch', bg: 'bg-red-100', text: 'text-red-700', icon: '🔴' },
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
            // In production: fetch from API
            setFlags(DEMO_FLAGS);
            setOverrides(DEMO_OVERRIDES);
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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Feature Flags</h1>
                    <p className="text-surface-600 mt-1">
                        Control feature rollout and beta access
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={() => setShowAddOverride(true)}
                        className="px-4 py-2 bg-surface-100 text-surface-700 rounded-lg text-sm hover:bg-surface-200 font-medium transition-colors"
                    >
                        + Add Override
                    </button>
                </div>
            </div>

            {/* Killswitch Warning */}
            {flags.some(f => f.category === 'killswitch' && f.enabled) && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-red-700 font-medium">
                        🚨 Active Killswitches Detected
                    </div>
                    <div className="mt-2 space-y-1">
                        {flags.filter(f => f.category === 'killswitch' && f.enabled).map(f => (
                            <div key={f.id} className="text-sm text-red-600">{f.name}: {f.description}</div>
                        ))}
                    </div>
                </div>
            )}

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Total Flags</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">{flags.length}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Enabled</div>
                    <div className="text-2xl font-bold text-emerald-600 mt-1">
                        {flags.filter(f => f.enabled).length}
                    </div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">In Beta</div>
                    <div className="text-2xl font-bold text-violet-600 mt-1">
                        {flags.filter(f => f.category === 'beta').length}
                    </div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Overrides</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">{overrides.length}</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-surface-200 mb-6 overflow-x-auto">
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
                                    ? 'border-blue-600 text-blue-600'
                                    : 'border-transparent text-surface-500 hover:text-surface-700'
                            )}
                        >
                            {tab.label}
                            <span className={cn(
                                'px-2.5 py-0.5 rounded-full text-xs',
                                activeTab === tab.key ? 'bg-blue-100 text-blue-600' : 'bg-surface-100 text-surface-500'
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
                                className="w-full px-4 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
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
                                            ? 'bg-blue-100 text-blue-700'
                                            : 'bg-surface-100 text-surface-600 hover:bg-surface-200'
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
                                        'bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm',
                                        flag.category === 'killswitch' && flag.enabled && 'border-red-300 bg-red-50/30'
                                    )}
                                >
                                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-3 mb-1">
                                                <h3 className="font-semibold text-surface-900">{flag.name}</h3>
                                                <span className={cn(
                                                    'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                    catConfig.bg,
                                                    catConfig.text
                                                )}>
                                                    {catConfig.label}
                                                </span>
                                                {flagOverrides.length > 0 && (
                                                    <span className="px-2.5 py-0.5 bg-amber-100 text-amber-700 rounded-full text-xs font-medium">
                                                        {flagOverrides.length} override{flagOverrides.length > 1 ? 's' : ''}
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-sm text-surface-500 mb-2">{flag.description}</p>
                                            <div className="flex items-center gap-4 text-xs text-surface-400">
                                                <span className="font-mono bg-surface-100 px-2.5 py-1 rounded">{flag.key}</span>
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
                                                        className="w-24 h-2 bg-surface-200 rounded-lg appearance-none cursor-pointer"
                                                    />
                                                    <span className="text-sm font-medium text-surface-700 w-10">
                                                        {flag.percentage}%
                                                    </span>
                                                </div>
                                            )}
                                            
                                            {flag.type === 'allowlist' && flag.enabled && (
                                                <span className="text-sm text-surface-500">
                                                    {flag.allowlist?.length || 0} tenant{(flag.allowlist?.length || 0) !== 1 ? 's' : ''}
                                                </span>
                                            )}
                                            
                                            {/* Toggle */}
                                            <button
                                                onClick={() => toggleFlag(flag.id)}
                                                className={cn(
                                                    'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
                                                    flag.enabled 
                                                        ? flag.category === 'killswitch' ? 'bg-red-600' : 'bg-emerald-600'
                                                        : 'bg-surface-200'
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
                                                    className="p-2 text-surface-400 hover:text-surface-600 transition-colors"
                                                >
                                                    ✏️
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                        
                        {filteredFlags.length === 0 && (
                            <div className="text-center py-12 text-surface-500">
                                No feature flags match your filters
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* Overrides Tab */}
            {activeTab === 'overrides' && (
                <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[700px]">
                            <thead className="bg-surface-50 border-b border-surface-200">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Tenant</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Flag</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Value</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Reason</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Created</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-surface-100">
                                {overrides.map(override => (
                                    <tr key={`${override.tenantId}-${override.flagKey}`} className="hover:bg-surface-50/50">
                                        <td className="px-4 py-4">
                                            <div className="font-medium text-surface-900">{override.tenantName}</div>
                                            <div className="text-xs text-surface-400 font-mono">{override.tenantId}</div>
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className="font-mono text-sm bg-surface-100 px-2.5 py-1 rounded">
                                                {override.flagKey}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className={cn(
                                                'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                override.value 
                                                    ? 'bg-emerald-100 text-emerald-700'
                                                    : 'bg-surface-100 text-surface-600'
                                            )}>
                                                {override.value ? 'Enabled' : 'Disabled'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4 text-sm text-surface-600">
                                            {override.reason}
                                        </td>
                                        <td className="px-4 py-4 text-sm text-surface-500">
                                            {timeAgo(override.createdAt)}
                                        </td>
                                        <td className="px-4 py-4 text-right">
                                            <button
                                                onClick={() => deleteOverride(override.tenantId, override.flagKey)}
                                                className="text-red-600 hover:text-red-700 text-sm font-medium"
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {overrides.length === 0 && (
                                    <tr>
                                        <td colSpan={6} className="px-4 py-12 text-center text-surface-500">
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
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-surface-0 rounded-xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto">
                        <div className="p-6 border-b border-surface-200">
                            <h2 className="text-lg font-semibold text-surface-900">
                                Edit Allowlist: {editingFlag.name}
                            </h2>
                        </div>
                        <div className="p-6">
                            <p className="text-sm text-surface-600 mb-4">
                                Tenant IDs with access to this feature:
                            </p>
                            <div className="space-y-2 mb-4">
                                {editingFlag.allowlist?.map(tenantId => (
                                    <div key={tenantId} className="flex items-center justify-between bg-surface-50 px-3 py-2 rounded-lg">
                                        <span className="font-mono text-sm">{tenantId}</span>
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
                                            className="text-red-600 hover:text-red-700 text-sm"
                                        >
                                            Remove
                                        </button>
                                    </div>
                                ))}
                                {(!editingFlag.allowlist || editingFlag.allowlist.length === 0) && (
                                    <p className="text-sm text-surface-400 text-center py-4">No tenants in allowlist</p>
                                )}
                            </div>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    placeholder="Add tenant ID..."
                                    id="new-tenant-id"
                                    className="flex-1 px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
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
                                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                                >
                                    Add
                                </button>
                            </div>
                        </div>
                        <div className="p-6 border-t border-surface-200 bg-surface-50 flex justify-end">
                            <button
                                onClick={() => setEditingFlag(null)}
                                className="px-4 py-2 bg-surface-900 text-white rounded-lg text-sm font-medium hover:bg-surface-800"
                            >
                                Done
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Add Override Modal */}
            {showAddOverride && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-surface-0 rounded-xl shadow-xl max-w-lg w-full">
                        <div className="p-6 border-b border-surface-200">
                            <h2 className="text-lg font-semibold text-surface-900">Add Tenant Override</h2>
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
                                <label className="block text-sm font-medium text-surface-700 mb-1">Tenant ID</label>
                                <input
                                    name="tenantId"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="tenant-xxx"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-surface-700 mb-1">Tenant Name</label>
                                <input
                                    name="tenantName"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="Company Name"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-surface-700 mb-1">Feature Flag</label>
                                <select
                                    name="flagKey"
                                    required
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    {flags.map(flag => (
                                        <option key={flag.key} value={flag.key}>{flag.name}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-surface-700 mb-1">Override Value</label>
                                <select
                                    name="value"
                                    required
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    <option value="true">Enabled</option>
                                    <option value="false">Disabled</option>
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-surface-700 mb-1">Reason</label>
                                <input
                                    name="reason"
                                    type="text"
                                    required
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="Why this override?"
                                />
                            </div>
                            <div className="flex justify-end gap-3 pt-4">
                                <button
                                    type="button"
                                    onClick={() => setShowAddOverride(false)}
                                    className="px-4 py-2 text-surface-600 hover:text-surface-900 text-sm font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
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
