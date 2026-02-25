'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn } from '../../lib/utils';

/**
 * Secrets Vault - Secure credential management
 * 
 * The owner can:
 * - Manage API keys and credentials
 * - View/rotate secrets
 * - Configure access policies
 * - Audit secret access
 */

interface Secret {
    id: string;
    name: string;
    type: 'api_key' | 'database' | 'oauth' | 'certificate' | 'encryption';
    description: string;
    createdAt: string;
    lastRotated: string;
    expiresAt: string | null;
    rotationPolicy: 'manual' | '30d' | '60d' | '90d' | 'never';
    status: 'active' | 'expiring_soon' | 'expired' | 'revoked';
    accessCount: number;
    lastAccessed: string;
}

const SECRET_TYPES: Record<string, { label: string; icon: string; color: string }> = {
    api_key: { label: 'API Key', icon: 'API', color: 'bg-blue-500/10 text-blue-700 border border-blue-500/20' },
    database: { label: 'Database', icon: 'DB', color: 'bg-emerald-500/10 text-emerald-700 border border-emerald-500/20' },
    oauth: { label: 'OAuth', icon: 'OAuth', color: 'bg-violet-500/10 text-violet-700 border border-violet-500/20' },
    certificate: { label: 'Certificate', icon: 'Cert', color: 'bg-amber-500/10 text-amber-700 border border-amber-500/20' },
    encryption: { label: 'Encryption', icon: 'Encrypt', color: 'bg-muted text-muted-foreground border border-border' },
};

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
    active: { label: 'Active', color: 'bg-success/10 text-success border border-success/20' },
    expiring_soon: { label: 'Expiring Soon', color: 'bg-warning/10 text-warning border border-warning/20' },
    expired: { label: 'Expired', color: 'bg-destructive/10 text-destructive border border-destructive/20' },
    revoked: { label: 'Revoked', color: 'bg-muted text-muted-foreground border border-border' },
};



export default function SecretsPage() {
    const [secrets, setSecrets] = useState<Secret[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedSecret, setSelectedSecret] = useState<Secret | null>(null);
    const [filterType, setFilterType] = useState<string>('');
    const [showAddModal, setShowAddModal] = useState(false);

    useEffect(() => {
        loadSecrets();
    }, []);

    async function loadSecrets() {
        try {
            const response = await fetch('/api/secrets', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch secrets: ${response.status}`);
            const data = await response.json();
            setSecrets(data);
        } catch (err) {
            console.error('Failed to load secrets:', err);
        } finally {
            setLoading(false);
        }
    }

    async function rotateSecret(secretId: string) {
        try {
            const res = await fetch('/api/secrets', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: secretId, action: 'rotate' }),
            });
            if (res.ok) {
                const data = await res.json();
                setSecrets(prev => prev.map(s =>
                    s.id === secretId ? {
                        ...s,
                        lastRotated: data.lastRotated ?? new Date().toISOString(),
                        status: 'active' as const,
                    } : s
                ));
            }
        } catch (err) {
            console.error('Failed to rotate secret:', err);
        }
        setSelectedSecret(null);
    }

    async function revokeSecret(secretId: string) {
        const confirmed = window.confirm(
            'Revoke this secret now? Clients using it will immediately lose access. You can rotate/create a new secret if revoked by mistake.'
        );
        if (!confirmed) return;

        try {
            const res = await fetch('/api/secrets', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: secretId, action: 'revoke' }),
            });
            if (res.ok) {
                setSecrets(prev => prev.map(s =>
                    s.id === secretId ? { ...s, status: 'revoked' as const } : s
                ));
            }
        } catch (err) {
            console.error('Failed to revoke secret:', err);
        }
        setSelectedSecret(null);
    }

    const filteredSecrets = filterType
        ? secrets.filter(s => s.type === filterType)
        : secrets;

    const activeCount = secrets.filter(s => s.status === 'active').length;
    const expiringCount = secrets.filter(s => s.status === 'expiring_soon').length;
    const expiredCount = secrets.filter(s => s.status === 'expired').length;

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Secrets Vault</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage API keys, credentials, and encryption keys
                    </p>
                </div>
                <button
                    onClick={() => setShowAddModal(true)}
                    className="px-4 py-2 min-h-[44px] bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 font-medium transition-colors"
                >
                    + Add Secret
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-card rounded-lg border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Total Secrets</div>
                    <div className="text-2xl font-bold text-foreground apex-metric-number">{secrets.length}</div>
                </div>
                <div className="bg-card rounded-lg border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Active</div>
                    <div className="text-2xl font-bold text-emerald-600 apex-metric-number">{activeCount}</div>
                </div>
                <div className="bg-card rounded-lg border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Expiring Soon</div>
                    <div className="text-2xl font-bold text-amber-600 apex-metric-number">{expiringCount}</div>
                </div>
                <div className="bg-card rounded-lg border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Expired/Revoked</div>
                    <div className="text-2xl font-bold text-destructive apex-metric-number">{expiredCount + secrets.filter(s => s.status === 'revoked').length}</div>
                </div>
            </div>

            {/* Alerts */}
            {expiringCount > 0 && (
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 mb-6">
                    <div className="flex items-center gap-2 text-amber-600">
                        <span>Warning</span>
                        <span className="font-medium">{expiringCount} secret(s) expiring soon - rotation recommended</span>
                    </div>
                </div>
            )}

            {/* Type Filters */}
            <div className="flex flex-wrap gap-2 mb-6">
                <button
                    onClick={() => setFilterType('')}
                    className={cn(
                        'px-3 py-2 min-h-[44px] rounded-sm text-sm font-medium transition-colors',
                        !filterType
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted text-muted-foreground hover:bg-muted/80'
                    )}
                >
                    All Types
                </button>
                {Object.entries(SECRET_TYPES).map(([key, config]) => (
                    <button
                        key={key}
                        onClick={() => setFilterType(filterType === key ? '' : key)}
                        className={cn(
                            'px-3 py-2 min-h-[44px] rounded-sm text-sm font-medium transition-colors',
                            filterType === key
                                ? 'bg-primary text-primary-foreground'
                                : `${config.color} hover:opacity-80`
                        )}
                    >
                        {config.icon} {config.label}
                    </button>
                ))}
            </div>

            {/* Secrets Table */}
            <div className="bg-card rounded-lg border border-border overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="w-full min-w-[800px]">
                        <thead className="bg-muted/50 border-b border-border sticky top-0 z-10">
                            <tr>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Name</th>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Type</th>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Status</th>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Last Rotated</th>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Expires</th>
                                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Access</th>
                                <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">Actions</th>
                            </tr>
                        </thead>
                    <tbody className="divide-y divide-border">
                        {filteredSecrets.map(secret => {
                            const typeConfig = SECRET_TYPES[secret.type];
                            const statusConfig = STATUS_CONFIG[secret.status];
                            return (
                                <tr key={secret.id} className="hover:bg-muted/50 transition-colors">
                                    <td className="px-4 py-3">
                                        <div className="font-medium text-foreground font-mono text-sm">{secret.name}</div>
                                        <div className="text-xs text-muted-foreground">{secret.description}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', typeConfig.color)}>
                                            {typeConfig.icon} {typeConfig.label}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', statusConfig.color)}>
                                            {statusConfig.label}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground">
                                        {formatDate(secret.lastRotated)}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground">
                                        {secret.expiresAt ? formatDate(secret.expiresAt) : 'Never'}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground apex-metric-number">
                                        {secret.accessCount.toLocaleString()} accesses
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <button
                                            onClick={() => setSelectedSecret(secret)}
                                            className="text-primary hover:text-primary/80 text-sm font-medium transition-colors min-w-[44px] min-h-[44px] inline-flex items-center justify-center"
                                            aria-label={`Manage secret ${secret.name}`}
                                        >
                                            Manage
                                        </button>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
                </div>
            </div>

            {/* Secret Detail Modal */}
            {selectedSecret && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedSecret(null)}>
                    <div className="bg-card rounded-lg p-6 w-full max-w-lg shadow-xl border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-foreground font-mono">{selectedSecret.name}</h2>
                                <div className="text-sm text-muted-foreground mt-1">{selectedSecret.description}</div>
                            </div>
                            <button 
                                onClick={() => setSelectedSecret(null)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        <div className="space-y-4 mb-6">
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Type</span>
                                <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', SECRET_TYPES[selectedSecret.type].color)}>
                                    {SECRET_TYPES[selectedSecret.type].icon} {SECRET_TYPES[selectedSecret.type].label}
                                </span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Status</span>
                                <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', STATUS_CONFIG[selectedSecret.status].color)}>
                                    {STATUS_CONFIG[selectedSecret.status].label}
                                </span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Created</span>
                                <span className="text-foreground">{formatDate(selectedSecret.createdAt)}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Last Rotated</span>
                                <span className="text-foreground">{formatDate(selectedSecret.lastRotated)}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Expires</span>
                                <span className="text-foreground">{selectedSecret.expiresAt ? formatDate(selectedSecret.expiresAt) : 'Never'}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Rotation Policy</span>
                                <span className="text-foreground">{selectedSecret.rotationPolicy === 'manual' ? 'Manual' : `Every ${selectedSecret.rotationPolicy}`}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-border">
                                <span className="text-muted-foreground">Access count</span>
                                <span className="text-foreground apex-metric-number">{selectedSecret.accessCount.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between py-2">
                                <span className="text-muted-foreground">Last Accessed</span>
                                <span className="text-foreground">{formatDate(selectedSecret.lastAccessed)}</span>
                            </div>
                        </div>

                        <div className="flex gap-2">
                            <button
                                onClick={() => navigator.clipboard.writeText(`${selectedSecret.name}=***MASKED***`)}
                                className="flex-1 px-4 py-2 min-h-[44px] bg-secondary text-secondary-foreground rounded-sm hover:bg-secondary/80 font-medium transition-colors"
                                aria-label="Copy secret reference to clipboard"
                            >
                                Copy Reference
                            </button>
                            {selectedSecret.status !== 'revoked' && (
                                <>
                                    <button
                                        onClick={() => rotateSecret(selectedSecret.id)}
                                        className="flex-1 px-4 py-2 min-h-[44px] bg-primary text-primary-foreground rounded-sm hover:bg-primary/90 font-medium transition-colors"
                                        aria-label="Rotate secret"
                                    >
                                        Rotate
                                    </button>
                                    <button
                                        onClick={() => revokeSecret(selectedSecret.id)}
                                        className="px-4 py-2 min-h-[44px] bg-destructive/10 text-destructive border border-destructive/20 rounded-sm hover:bg-destructive/20 font-medium transition-colors"
                                        aria-label="Revoke secret"
                                    >
                                        Revoke
                                    </button>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Add Secret Modal */}
            {showAddModal && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowAddModal(false)}>
                    <div className="bg-card rounded-lg p-6 w-full max-w-lg shadow-xl border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <h2 className="text-xl font-bold text-foreground">Add New Secret</h2>
                            <button 
                                onClick={() => setShowAddModal(false)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Name</label>
                                <input
                                    type="text"
                                    placeholder="MY_API_KEY"
                                    className="w-full px-3 py-2 min-h-[44px] border border-border rounded-sm text-sm font-mono bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all text-foreground"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Type</label>
                                <select className="w-full px-3 py-2 min-h-[44px] border border-border rounded-sm text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all text-foreground">
                                    {Object.entries(SECRET_TYPES).map(([key, config]) => (
                                        <option key={key} value={key}>{config.icon} {config.label}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Description</label>
                                <input
                                    type="text"
                                    placeholder="What is this secret used for?"
                                    className="w-full px-3 py-2 min-h-[44px] border border-border rounded-sm text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all text-foreground"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Value</label>
                                <textarea
                                    placeholder="Paste secret value here..."
                                    rows={3}
                                    className="w-full px-3 py-2 min-h-[44px] border border-border rounded-sm text-sm font-mono bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all text-foreground"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Rotation Policy</label>
                                <select className="w-full px-3 py-2 min-h-[44px] border border-border rounded-sm text-sm bg-background focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all text-foreground">
                                    <option value="manual">Manual</option>
                                    <option value="30d">Every 30 days</option>
                                    <option value="60d">Every 60 days</option>
                                    <option value="90d">Every 90 days</option>
                                    <option value="never">Never (certificate)</option>
                                </select>
                            </div>
                        </div>

                        <div className="flex gap-2 mt-6">
                            <button
                                onClick={() => setShowAddModal(false)}
                                className="flex-1 px-4 py-2 min-h-[44px] bg-secondary text-secondary-foreground rounded-sm hover:bg-secondary/80 font-medium transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={() => setShowAddModal(false)}
                                className="flex-1 px-4 py-2 min-h-[44px] bg-primary text-primary-foreground rounded-sm hover:bg-primary/90 font-medium transition-colors"
                            >
                                Add Secret
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
