'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn, getStatusColor } from '../../lib/utils';

/**
 * GDPR Requests - Data subject request management
 * 
 * The owner can:
 * - View and process data subject requests (access, deletion, portability)
 * - Track SLA compliance
 * - Generate data exports
 * - Manage consent records
 */

interface GDPRRequest {
    id: string;
    type: 'access' | 'deletion' | 'portability' | 'rectification' | 'restriction';
    status: 'pending' | 'verified' | 'processing' | 'completed' | 'rejected';
    email: string;
    tenantId: string;
    tenantName: string;
    createdAt: string;
    verifiedAt: string | null;
    completedAt: string | null;
    slaDeadline: string;
    notes: string | null;
}

const REQUEST_TYPE_LABELS: Record<string, { label: string; icon: string; description: string }> = {
    access: { label: 'Data Access', icon: '👁️', description: 'Subject wants to know what data is stored' },
    deletion: { label: 'Data Deletion', icon: '🗑️', description: 'Subject wants all data deleted' },
    portability: { label: 'Data Portability', icon: '📦', description: 'Subject wants data exported' },
    rectification: { label: 'Rectification', icon: '✏️', description: 'Subject wants data corrected' },
    restriction: { label: 'Processing Restriction', icon: '🚫', description: 'Subject wants processing limited' },
};

const DEMO_REQUESTS: GDPRRequest[] = [
    { id: 'gdpr-001', type: 'deletion', status: 'pending', email: 'user1@example.com', tenantId: 'tenant-saas', tenantName: 'SaaS Notifications', createdAt: new Date(Date.now() - 172800000).toISOString(), verifiedAt: null, completedAt: null, slaDeadline: new Date(Date.now() + 2419200000).toISOString(), notes: null },
    { id: 'gdpr-002', type: 'access', status: 'verified', email: 'user2@corp.com', tenantId: 'tenant-newsletter', tenantName: 'Newsletter Pro', createdAt: new Date(Date.now() - 259200000).toISOString(), verifiedAt: new Date(Date.now() - 86400000).toISOString(), completedAt: null, slaDeadline: new Date(Date.now() + 2160000000).toISOString(), notes: 'User verified via double opt-in' },
    { id: 'gdpr-003', type: 'deletion', status: 'processing', email: 'john.doe@test.com', tenantId: 'tenant-ecommerce', tenantName: 'E-Commerce Store', createdAt: new Date(Date.now() - 604800000).toISOString(), verifiedAt: new Date(Date.now() - 518400000).toISOString(), completedAt: null, slaDeadline: new Date(Date.now() + 1814400000).toISOString(), notes: 'Deleting from all systems' },
    { id: 'gdpr-004', type: 'portability', status: 'completed', email: 'jane@startup.io', tenantId: 'tenant-growth', tenantName: 'GrowthHack Inc', createdAt: new Date(Date.now() - 1209600000).toISOString(), verifiedAt: new Date(Date.now() - 1123200000).toISOString(), completedAt: new Date(Date.now() - 864000000).toISOString(), slaDeadline: new Date(Date.now() + 1209600000).toISOString(), notes: 'Data export sent to user' },
    { id: 'gdpr-005', type: 'rectification', status: 'completed', email: 'mike@company.com', tenantId: 'tenant-saas', tenantName: 'SaaS Notifications', createdAt: new Date(Date.now() - 2592000000).toISOString(), verifiedAt: new Date(Date.now() - 2505600000).toISOString(), completedAt: new Date(Date.now() - 2419200000).toISOString(), slaDeadline: new Date(Date.now() - 172800000).toISOString(), notes: 'Updated email address per request' },
];

export default function GDPRPage() {
    const [requests, setRequests] = useState<GDPRRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedRequest, setSelectedRequest] = useState<GDPRRequest | null>(null);
    const [filterStatus, setFilterStatus] = useState<string>('');

    useEffect(() => {
        loadRequests();
    }, []);

    async function loadRequests() {
        try {
            // In production: fetch from Compliance API
            setRequests(DEMO_REQUESTS);
        } finally {
            setLoading(false);
        }
    }

    function updateRequestStatus(requestId: string, newStatus: GDPRRequest['status']) {
        const updates: Partial<GDPRRequest> = { status: newStatus };
        if (newStatus === 'verified') {
            updates.verifiedAt = new Date().toISOString();
        }
        if (newStatus === 'completed') {
            updates.completedAt = new Date().toISOString();
        }
        
        setRequests(prev => prev.map(r => 
            r.id === requestId ? { ...r, ...updates } : r
        ));
        if (selectedRequest?.id === requestId) {
            setSelectedRequest(prev => prev ? { ...prev, ...updates } : null);
        }
    }

    function isOverdue(request: GDPRRequest): boolean {
        if (request.status === 'completed' || request.status === 'rejected') return false;
        return new Date(request.slaDeadline) < new Date();
    }

    function getDaysRemaining(deadline: string): number {
        const diff = new Date(deadline).getTime() - Date.now();
        return Math.ceil(diff / (1000 * 60 * 60 * 24));
    }

    const filteredRequests = filterStatus
        ? requests.filter(r => r.status === filterStatus)
        : requests;

    const statusCounts = {
        pending: requests.filter(r => r.status === 'pending').length,
        verified: requests.filter(r => r.status === 'verified').length,
        processing: requests.filter(r => r.status === 'processing').length,
        completed: requests.filter(r => r.status === 'completed').length,
    };

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
                    <h1 className="text-2xl font-bold text-gray-900">GDPR Requests</h1>
                    <p className="text-gray-600 mt-1">
                        Manage data subject requests for GDPR compliance
                    </p>
                </div>
                <div className="text-sm text-gray-500">
                    SLA: 30 days to complete requests
                </div>
            </div>

            {/* Status Overview */}
            <div className="grid grid-cols-4 gap-4 mb-6">
                {[
                    { status: 'pending', label: 'Pending Verification', count: statusCounts.pending, color: 'bg-yellow-50 border-yellow-200 text-yellow-700' },
                    { status: 'verified', label: 'Verified', count: statusCounts.verified, color: 'bg-blue-50 border-blue-200 text-blue-700' },
                    { status: 'processing', label: 'Processing', count: statusCounts.processing, color: 'bg-indigo-50 border-indigo-200 text-indigo-700' },
                    { status: 'completed', label: 'Completed', count: statusCounts.completed, color: 'bg-green-50 border-green-200 text-green-700' },
                ].map(({ status, label, count, color }) => (
                    <button
                        key={status}
                        onClick={() => setFilterStatus(filterStatus === status ? '' : status)}
                        className={cn(
                            'rounded-xl border p-4 text-left transition-all',
                            color,
                            filterStatus === status && 'ring-2 ring-offset-2 ring-indigo-500'
                        )}
                    >
                        <div className="text-2xl font-bold">{count}</div>
                        <div className="text-sm">{label}</div>
                    </button>
                ))}
            </div>

            {/* Overdue Alert */}
            {requests.some(r => isOverdue(r)) && (
                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <div className="flex items-center gap-2 text-red-800 font-medium">
                        ⚠️ {requests.filter(r => isOverdue(r)).length} request(s) have exceeded the 30-day SLA deadline
                    </div>
                </div>
            )}

            {/* Request List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="p-4 border-b border-gray-200 flex items-center justify-between">
                    <h2 className="font-semibold">Data Subject Requests</h2>
                    {filterStatus && (
                        <button
                            onClick={() => setFilterStatus('')}
                            className="text-sm text-indigo-600 hover:underline"
                        >
                            Clear filter
                        </button>
                    )}
                </div>
                <div className="divide-y divide-gray-100">
                    {filteredRequests.length === 0 ? (
                        <div className="p-8 text-center text-gray-500">
                            No GDPR requests found
                        </div>
                    ) : (
                        filteredRequests.map(request => {
                            const typeInfo = REQUEST_TYPE_LABELS[request.type];
                            const overdue = isOverdue(request);
                            const daysLeft = getDaysRemaining(request.slaDeadline);

                            return (
                                <div
                                    key={request.id}
                                    className={cn(
                                        'p-4 hover:bg-gray-50 cursor-pointer',
                                        overdue && 'bg-red-50'
                                    )}
                                    onClick={() => setSelectedRequest(request)}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-4">
                                            <span className="text-2xl">{typeInfo.icon}</span>
                                            <div>
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="font-medium text-gray-900">{typeInfo.label}</span>
                                                    <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getStatusColor(request.status))}>
                                                        {request.status}
                                                    </span>
                                                    {overdue && (
                                                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
                                                            OVERDUE
                                                        </span>
                                                    )}
                                                </div>
                                                <div className="text-sm text-gray-500">
                                                    {request.email} • {request.tenantName}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-sm text-gray-900">
                                                {request.status !== 'completed' && request.status !== 'rejected' ? (
                                                    <span className={cn(daysLeft < 7 && 'text-red-600 font-medium')}>
                                                        {daysLeft > 0 ? `${daysLeft} days left` : `${Math.abs(daysLeft)} days overdue`}
                                                    </span>
                                                ) : (
                                                    <span className="text-green-600">Completed</span>
                                                )}
                                            </div>
                                            <div className="text-xs text-gray-500">
                                                Created {formatDate(request.createdAt)}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>
            </div>

            {/* Request Detail Modal */}
            {selectedRequest && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedRequest(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-lg shadow-xl" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div className="flex items-center gap-3">
                                <span className="text-3xl">{REQUEST_TYPE_LABELS[selectedRequest.type].icon}</span>
                                <div>
                                    <h2 className="text-xl font-bold text-gray-900">
                                        {REQUEST_TYPE_LABELS[selectedRequest.type].label}
                                    </h2>
                                    <p className="text-sm text-gray-500">
                                        {REQUEST_TYPE_LABELS[selectedRequest.type].description}
                                    </p>
                                </div>
                            </div>
                            <button onClick={() => setSelectedRequest(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-6">
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Request ID</label>
                                <div className="font-mono text-sm">{selectedRequest.id}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Status</label>
                                <div className={cn('font-medium', getStatusColor(selectedRequest.status).split(' ')[0])}>
                                    {selectedRequest.status}
                                </div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Data Subject</label>
                                <div className="font-medium">{selectedRequest.email}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Tenant</label>
                                <div className="font-medium">{selectedRequest.tenantName}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Created</label>
                                <div>{formatDate(selectedRequest.createdAt)}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">SLA Deadline</label>
                                <div className={cn(isOverdue(selectedRequest) && 'text-red-600 font-medium')}>
                                    {formatDate(selectedRequest.slaDeadline)}
                                </div>
                            </div>
                        </div>

                        {selectedRequest.notes && (
                            <div className="mb-6 p-3 bg-gray-50 rounded-lg">
                                <label className="text-xs text-gray-500 uppercase mb-1 block">Notes</label>
                                <div className="text-sm">{selectedRequest.notes}</div>
                            </div>
                        )}

                        {/* Action Buttons based on status */}
                        <div className="flex gap-2">
                            {selectedRequest.status === 'pending' && (
                                <>
                                    <button
                                        onClick={() => updateRequestStatus(selectedRequest.id, 'verified')}
                                        className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                                    >
                                        ✓ Mark as Verified
                                    </button>
                                    <button
                                        onClick={() => updateRequestStatus(selectedRequest.id, 'rejected')}
                                        className="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200"
                                    >
                                        Reject
                                    </button>
                                </>
                            )}
                            {selectedRequest.status === 'verified' && (
                                <button
                                    onClick={() => updateRequestStatus(selectedRequest.id, 'processing')}
                                    className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                                >
                                    🚀 Start Processing
                                </button>
                            )}
                            {selectedRequest.status === 'processing' && (
                                <button
                                    onClick={() => updateRequestStatus(selectedRequest.id, 'completed')}
                                    className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                                >
                                    ✓ Mark as Completed
                                </button>
                            )}
                            {(selectedRequest.status === 'completed' || selectedRequest.status === 'rejected') && (
                                <div className="flex-1 text-center text-gray-500 py-2">
                                    This request has been {selectedRequest.status}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
