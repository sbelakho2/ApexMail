'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn, getStatusColor } from '../../lib/utils';
import { getCsrfToken } from '../../lib/client-csrf';
import { PageLoadingState } from '../../components/ui/async-state';

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
    access: { label: 'Data Access', icon: 'Access', description: 'Subject wants to know what data is stored' },
    deletion: { label: 'Data Deletion', icon: 'Delete', description: 'Subject wants all data deleted' },
    portability: { label: 'Data Portability', icon: 'Export', description: 'Subject wants data exported' },
    rectification: { label: 'Rectification', icon: 'Fix', description: 'Subject wants data corrected' },
    restriction: { label: 'Processing Restriction', icon: 'Restrict', description: 'Subject wants processing limited' },
};



export default function GDPRPage() {
    const [requests, setRequests] = useState<GDPRRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedRequest, setSelectedRequest] = useState<GDPRRequest | null>(null);
    const [filterStatus, setFilterStatus] = useState<string>('');
    const [now, setNow] = useState(() => new Date());
    const [error, setError] = useState<string | null>(null);
    const [refreshing, setRefreshing] = useState(false);

    useEffect(() => {
        loadRequests();
        const interval = setInterval(() => {
            setNow(new Date());
            void refreshRequests();
        }, 60000);
        return () => clearInterval(interval);
    }, []);

    async function refreshRequests() {
        setRefreshing(true);
        try {
            await loadRequests();
        } finally {
            setRefreshing(false);
        }
    }

    async function loadRequests() {
        try {
            setError(null);
            const response = await fetch('/api/gdpr', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch GDPR requests: ${response.status}`);
            const data = await response.json();
            setRequests(data);
        } catch (err) {
            console.error('Failed to load GDPR requests:', err);
            setError('Failed to load GDPR requests.');
        } finally {
            setLoading(false);
        }
    }

    async function updateRequestStatus(requestId: string, newStatus: GDPRRequest['status']) {
        const updates: Partial<GDPRRequest> = { status: newStatus };
        if (newStatus === 'verified') {
            updates.verifiedAt = new Date().toISOString();
        }
        if (newStatus === 'completed') {
            updates.completedAt = new Date().toISOString();
        }

        const previousRequests = requests;
        const previousSelected = selectedRequest;
        setRequests(prev => prev.map(r => 
            r.id === requestId ? { ...r, ...updates } : r
        ));
        if (selectedRequest?.id === requestId) {
            setSelectedRequest(prev => prev ? { ...prev, ...updates } : null);
        }

        try {
            setError(null);
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/gdpr', {
                method: 'PATCH',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ id: requestId, status: newStatus }),
            });
            if (!response.ok) {
                throw new Error(`Failed to persist GDPR status: ${response.status}`);
            }
        } catch (err) {
            console.error('Failed to persist GDPR status:', err);
            setRequests(previousRequests);
            setSelectedRequest(previousSelected);
            setError('Failed to update request status. Changes were reverted.');
        }
    }

    function isOverdue(request: GDPRRequest): boolean {
        if (request.status === 'completed' || request.status === 'rejected') return false;
        return new Date(request.slaDeadline) < now;
    }

    function getDaysRemaining(deadline: string): number {
        const diff = new Date(deadline).getTime() - now.getTime();
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
        return <PageLoadingState label="Loading GDPR requests..." />;
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">GDPR Requests</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage data subject requests for GDPR compliance
                    </p>
                </div>
                <div className="text-sm text-muted-foreground">
                    <div className="flex items-center gap-3">
                        <span>SLA: 30 days to complete requests</span>
                        <button
                            type="button"
                            onClick={() => void refreshRequests()}
                            className="px-2.5 py-1 rounded-md border border-border text-foreground hover:bg-muted transition-colors"
                        >
                            {refreshing ? 'Refreshing…' : 'Refresh'}
                        </button>
                    </div>
                </div>
            </div>

            {error && (
                <div className="mb-4 p-3 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
                    {error}
                </div>
            )}

            {/* Status Overview */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                {[
                    { status: 'pending', label: 'Pending Verification', count: statusCounts.pending, color: 'bg-warning/10 border-warning/20 text-warning' },
                    { status: 'verified', label: 'Verified', count: statusCounts.verified, color: 'bg-info/10 border-info/20 text-info' },
                    { status: 'processing', label: 'Processing', count: statusCounts.processing, color: 'bg-primary/10 border-primary/20 text-primary' },
                    { status: 'completed', label: 'Completed', count: statusCounts.completed, color: 'bg-success/10 border-success/20 text-success' },
                ].map(({ status, label, count, color }) => (
                    <button
                        key={status}
                        onClick={() => setFilterStatus(filterStatus === status ? '' : status)}
                        aria-pressed={filterStatus === status}
                        className={cn(
                            'rounded-xl border p-4 text-left transition-all',
                            color,
                            filterStatus === status && 'ring-2 ring-offset-2 ring-primary'
                        )}
                    >
                        <div className="text-2xl font-bold">{count}</div>
                        <div className="text-sm">{label}</div>
                    </button>
                ))}
            </div>

            {/* Overdue Alert */}
            {requests.some(r => isOverdue(r)) && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                    <div className="flex items-center gap-2 text-destructive font-medium">
                        Warning: {requests.filter(r => isOverdue(r)).length} request(s) have exceeded the 30-day SLA deadline
                    </div>
                </div>
            )}

            {/* Request List */}
            <div className="bg-card rounded-xl border border-border shadow-sm">
                <div className="p-4 border-b border-border flex items-center justify-between">
                    <h2 className="font-semibold text-foreground">Data Subject Requests</h2>
                    {filterStatus && (
                        <button
                            onClick={() => setFilterStatus('')}
                            className="text-sm text-primary hover:underline"
                        >
                            Clear filter
                        </button>
                    )}
                </div>
                <div className="divide-y divide-border">
                    {filteredRequests.length === 0 ? (
                        <div className="p-8 text-center text-muted-foreground">
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
                                        'p-4 hover:bg-muted/50 cursor-pointer transition-colors',
                                        overdue && 'bg-destructive/10'
                                    )}
                                    onClick={() => setSelectedRequest(request)}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-4">
                                            <span className="text-2xl">{typeInfo.icon}</span>
                                            <div>
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="font-medium text-foreground">{typeInfo.label}</span>
                                                    <span className={cn('px-2.5 py-0.5 rounded text-xs font-medium', getStatusColor(request.status))}>
                                                        {request.status}
                                                    </span>
                                                    {overdue && (
                                                        <span className="px-2.5 py-0.5 rounded text-xs font-medium bg-destructive/10 text-destructive">
                                                            OVERDUE
                                                        </span>
                                                    )}
                                                </div>
                                                <div className="text-sm text-muted-foreground">
                                                    {request.email} • {request.tenantName}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-sm text-foreground">
                                                {request.status !== 'completed' && request.status !== 'rejected' ? (
                                                    <span className={cn(daysLeft < 7 && 'text-destructive font-medium')}>
                                                        {daysLeft > 0 ? `${daysLeft} days left` : `${Math.abs(daysLeft)} days overdue`}
                                                    </span>
                                                ) : (
                                                    <span className="text-success font-medium">Completed</span>
                                                )}
                                            </div>
                                            <div className="text-xs text-muted-foreground">
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
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedRequest(null)}>
                    <div className="bg-card rounded-xl p-6 w-full max-w-lg shadow-xl border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div className="flex items-center gap-3">
                                <span className="text-3xl">{REQUEST_TYPE_LABELS[selectedRequest.type].icon}</span>
                                <div>
                                    <h2 className="text-xl font-bold text-foreground">
                                        {REQUEST_TYPE_LABELS[selectedRequest.type].label}
                                    </h2>
                                    <p className="text-sm text-muted-foreground">
                                        {REQUEST_TYPE_LABELS[selectedRequest.type].description}
                                    </p>
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedRequest(null)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">Request ID</label>
                                <div className="font-mono text-sm text-foreground">{selectedRequest.id}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">Status</label>
                                <div className={cn('font-medium', getStatusColor(selectedRequest.status).split(' ')[0])}>
                                    {selectedRequest.status}
                                </div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">Data Subject</label>
                                <div className="font-medium text-foreground">{selectedRequest.email}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">Tenant</label>
                                <div className="font-medium text-foreground">{selectedRequest.tenantName}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">Created</label>
                                <div className="text-foreground">{formatDate(selectedRequest.createdAt)}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground uppercase font-semibold">SLA Deadline</label>
                                <div className={cn('text-foreground', isOverdue(selectedRequest) && 'text-destructive font-medium')}>
                                    {formatDate(selectedRequest.slaDeadline)}
                                </div>
                            </div>
                        </div>

                        {selectedRequest.notes && (
                            <div className="mb-6 p-3 bg-muted/50 rounded-lg border border-border">
                                <label className="text-xs text-muted-foreground uppercase mb-1 block font-semibold">Notes</label>
                                <div className="text-sm text-foreground">{selectedRequest.notes}</div>
                            </div>
                        )}

                        {/* Action Buttons based on status */}
                        <div className="flex gap-2">
                            {selectedRequest.status === 'pending' && (
                                <>
                                    <button
                                        onClick={() => updateRequestStatus(selectedRequest.id, 'verified')}
                                        className="flex-1 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 font-medium transition-colors"
                                    >
                                        Mark as Verified
                                    </button>
                                    <button
                                        onClick={() => updateRequestStatus(selectedRequest.id, 'rejected')}
                                        className="px-4 py-2 bg-destructive/10 text-destructive rounded-lg hover:bg-destructive/20 font-medium transition-colors"
                                    >
                                        Reject
                                    </button>
                                </>
                            )}
                            {selectedRequest.status === 'verified' && (
                                <button
                                    onClick={() => updateRequestStatus(selectedRequest.id, 'processing')}
                                    className="flex-1 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 font-medium transition-colors"
                                >
                                    Start Processing
                                </button>
                            )}
                            {selectedRequest.status === 'processing' && (
                                <button
                                    onClick={() => updateRequestStatus(selectedRequest.id, 'completed')}
                                    className="flex-1 px-4 py-2 bg-success text-success-foreground rounded-lg hover:bg-success/90 font-medium transition-colors"
                                >
                                    Mark as Completed
                                </button>
                            )}
                            {(selectedRequest.status === 'completed' || selectedRequest.status === 'rejected') && (
                                <div className="flex-1 text-center text-muted-foreground py-2">
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
