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
    api_key: { label: 'API Key', icon: '🔑', color: 'bg-blue-100 text-blue-700' },
    database: { label: 'Database', icon: '🗄️', color: 'bg-green-100 text-green-700' },
    oauth: { label: 'OAuth', icon: '🔐', color: 'bg-purple-100 text-purple-700' },
    certificate: { label: 'Certificate', icon: '📜', color: 'bg-yellow-100 text-yellow-700' },
    encryption: { label: 'Encryption', icon: '🔒', color: 'bg-gray-100 text-gray-700' },
};

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
    active: { label: 'Active', color: 'bg-green-100 text-green-700' },
    expiring_soon: { label: 'Expiring Soon', color: 'bg-yellow-100 text-yellow-700' },
    expired: { label: 'Expired', color: 'bg-red-100 text-red-700' },
    revoked: { label: 'Revoked', color: 'bg-gray-100 text-gray-500' },
};

const DEMO_SECRETS: Secret[] = [
    { id: '1', name: 'STRIPE_SECRET_KEY', type: 'api_key', description: 'Stripe payment processing', createdAt: '2024-01-15T00:00:00Z', lastRotated: '2024-11-01T00:00:00Z', expiresAt: '2025-11-01T00:00:00Z', rotationPolicy: '90d', status: 'active', accessCount: 15420, lastAccessed: new Date(Date.now() - 300000).toISOString() },
    { id: '2', name: 'DATABASE_URL', type: 'database', description: 'Primary PostgreSQL connection', createdAt: '2024-01-01T00:00:00Z', lastRotated: '2024-12-01T00:00:00Z', expiresAt: null, rotationPolicy: 'manual', status: 'active', accessCount: 892341, lastAccessed: new Date(Date.now() - 60000).toISOString() },
    { id: '3', name: 'GOOGLE_OAUTH_SECRET', type: 'oauth', description: 'Google Calendar integration', createdAt: '2024-03-10T00:00:00Z', lastRotated: '2024-09-10T00:00:00Z', expiresAt: '2025-01-10T00:00:00Z', rotationPolicy: '60d', status: 'expiring_soon', accessCount: 2341, lastAccessed: new Date(Date.now() - 3600000).toISOString() },
    { id: '4', name: 'TLS_CERTIFICATE', type: 'certificate', description: 'Main domain TLS cert', createdAt: '2024-06-01T00:00:00Z', lastRotated: '2024-06-01T00:00:00Z', expiresAt: '2025-06-01T00:00:00Z', rotationPolicy: 'never', status: 'active', accessCount: 0, lastAccessed: '2024-06-01T00:00:00Z' },
    { id: '5', name: 'ENCRYPTION_KEY', type: 'encryption', description: 'Data at rest encryption', createdAt: '2024-01-01T00:00:00Z', lastRotated: '2024-10-01T00:00:00Z', expiresAt: null, rotationPolicy: '90d', status: 'active', accessCount: 423891, lastAccessed: new Date(Date.now() - 120000).toISOString() },
    { id: '6', name: 'SENDGRID_API_KEY_OLD', type: 'api_key', description: 'Legacy SendGrid key (deprecated)', createdAt: '2023-06-01T00:00:00Z', lastRotated: '2023-06-01T00:00:00Z', expiresAt: '2024-06-01T00:00:00Z', rotationPolicy: 'never', status: 'revoked', accessCount: 0, lastAccessed: '2024-05-15T00:00:00Z' },
];

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
            // In production: fetch from Compliance API
            setSecrets(DEMO_SECRETS);
        } finally {
            setLoading(false);
        }
    }

    function rotateSecret(secretId: string) {
        setSecrets(prev => prev.map(s =>
            s.id === secretId ? {
                ...s,
                lastRotated: new Date().toISOString(),
                status: 'active' as const
            } : s
        ));
        setSelectedSecret(null);
    }

    function revokeSecret(secretId: string) {
        setSecrets(prev => prev.map(s =>
            s.id === secretId ? { ...s, status: 'revoked' as const } : s
        ));
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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Secrets Vault</h1>
                    <p className="text-gray-600 mt-1">
                        Manage API keys, credentials, and encryption keys
                    </p>
                </div>
                <button
                    onClick={() => setShowAddModal(true)}
                    className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700"
                >
                    + Add Secret
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500">Total Secrets</div>
                    <div className="text-2xl font-bold text-gray-900">{secrets.length}</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500">Active</div>
                    <div className="text-2xl font-bold text-green-600">{activeCount}</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500">Expiring Soon</div>
                    <div className="text-2xl font-bold text-yellow-600">{expiringCount}</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500">Expired/Revoked</div>
                    <div className="text-2xl font-bold text-red-600">{expiredCount + secrets.filter(s => s.status === 'revoked').length}</div>
                </div>
            </div>

            {/* Alerts */}
            {expiringCount > 0 && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                    <div className="flex items-center gap-2 text-yellow-700">
                        <span>⚠️</span>
                        <span className="font-medium">{expiringCount} secret(s) expiring soon - rotation recommended</span>
                    </div>
                </div>
            )}

            {/* Type Filters */}
            <div className="flex flex-wrap gap-2 mb-6">
                <button
                    onClick={() => setFilterType('')}
                    className={cn(
                        'px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
                        !filterType
                            ? 'bg-indigo-600 text-white'
                            : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    )}
                >
                    All Types
                </button>
                {Object.entries(SECRET_TYPES).map(([key, config]) => (
                    <button
                        key={key}
                        onClick={() => setFilterType(filterType === key ? '' : key)}
                        className={cn(
                            'px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
                            filterType === key
                                ? 'bg-indigo-600 text-white'
                                : `${config.color} hover:opacity-80`
                        )}
                    >
                        {config.icon} {config.label}
                    </button>
                ))}
            </div>

            {/* Secrets Table */}
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                <table className="w-full">
                    <thead className="bg-gray-50 border-b border-gray-200">
                        <tr>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Name</th>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Type</th>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Status</th>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Last Rotated</th>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Expires</th>
                            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Access</th>
                            <th className="px-4 py-3 text-right text-sm font-medium text-gray-500">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                        {filteredSecrets.map(secret => {
                            const typeConfig = SECRET_TYPES[secret.type];
                            const statusConfig = STATUS_CONFIG[secret.status];
                            return (
                                <tr key={secret.id} className="hover:bg-gray-50">
                                    <td className="px-4 py-3">
                                        <div className="font-medium text-gray-900 font-mono text-sm">{secret.name}</div>
                                        <div className="text-xs text-gray-500">{secret.description}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={cn('px-2 py-1 rounded text-xs font-medium', typeConfig.color)}>
                                            {typeConfig.icon} {typeConfig.label}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={cn('px-2 py-1 rounded text-xs font-medium', statusConfig.color)}>
                                            {statusConfig.label}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-500">
                                        {formatDate(secret.lastRotated)}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-500">
                                        {secret.expiresAt ? formatDate(secret.expiresAt) : 'Never'}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-500">
                                        {secret.accessCount.toLocaleString()} accesses
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <button
                                            onClick={() => setSelectedSecret(secret)}
                                            className="text-indigo-600 hover:text-indigo-800 text-sm font-medium"
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

            {/* Secret Detail Modal */}
            {selectedSecret && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedSecret(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-lg shadow-xl" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-gray-900 font-mono">{selectedSecret.name}</h2>
                                <div className="text-sm text-gray-500 mt-1">{selectedSecret.description}</div>
                            </div>
                            <button onClick={() => setSelectedSecret(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="space-y-4 mb-6">
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Type</span>
                                <span className={cn('px-2 py-0.5 rounded text-xs font-medium', SECRET_TYPES[selectedSecret.type].color)}>
                                    {SECRET_TYPES[selectedSecret.type].icon} {SECRET_TYPES[selectedSecret.type].label}
                                </span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Status</span>
                                <span className={cn('px-2 py-0.5 rounded text-xs font-medium', STATUS_CONFIG[selectedSecret.status].color)}>
                                    {STATUS_CONFIG[selectedSecret.status].label}
                                </span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Created</span>
                                <span className="text-gray-900">{formatDate(selectedSecret.createdAt)}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Last Rotated</span>
                                <span className="text-gray-900">{formatDate(selectedSecret.lastRotated)}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Expires</span>
                                <span className="text-gray-900">{selectedSecret.expiresAt ? formatDate(selectedSecret.expiresAt) : 'Never'}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Rotation Policy</span>
                                <span className="text-gray-900">{selectedSecret.rotationPolicy === 'manual' ? 'Manual' : `Every ${selectedSecret.rotationPolicy}`}</span>
                            </div>
                            <div className="flex justify-between py-2 border-b border-gray-100">
                                <span className="text-gray-500">Access Count</span>
                                <span className="text-gray-900">{selectedSecret.accessCount.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between py-2">
                                <span className="text-gray-500">Last Accessed</span>
                                <span className="text-gray-900">{formatDate(selectedSecret.lastAccessed)}</span>
                            </div>
                        </div>

                        <div className="flex gap-2">
                            <button
                                onClick={() => navigator.clipboard.writeText(`${selectedSecret.name}=***MASKED***`)}
                                className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
                            >
                                📋 Copy Reference
                            </button>
                            {selectedSecret.status !== 'revoked' && (
                                <>
                                    <button
                                        onClick={() => rotateSecret(selectedSecret.id)}
                                        className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                                    >
                                        🔄 Rotate
                                    </button>
                                    <button
                                        onClick={() => revokeSecret(selectedSecret.id)}
                                        className="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200"
                                    >
                                        ⛔ Revoke
                                    </button>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Add Secret Modal */}
            {showAddModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowAddModal(false)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-lg shadow-xl" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <h2 className="text-xl font-bold text-gray-900">Add New Secret</h2>
                            <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                                <input
                                    type="text"
                                    placeholder="MY_API_KEY"
                                    className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">Type</label>
                                <select className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm">
                                    {Object.entries(SECRET_TYPES).map(([key, config]) => (
                                        <option key={key} value={key}>{config.icon} {config.label}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">Description</label>
                                <input
                                    type="text"
                                    placeholder="What is this secret used for?"
                                    className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">Value</label>
                                <textarea
                                    placeholder="Paste secret value here..."
                                    rows={3}
                                    className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">Rotation Policy</label>
                                <select className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm">
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
                                className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={() => setShowAddModal(false)}
                                className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
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
