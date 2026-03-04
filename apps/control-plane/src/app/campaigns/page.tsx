'use client';

import { useState } from 'react';
import { formatNumber, formatDate, cn } from '../../lib/utils';
import { PageLoadingState } from '../../components/ui/async-state';
import { useApiResource } from '../../lib/use-api-resource';
import { getCsrfToken } from '../../lib/client-csrf';
import { useDialog } from '../../components/ui/confirm-dialog';

/**
 * Campaigns Management - Drip campaign automation
 * 
 * The owner can:
 * - Create and manage drip campaigns
 * - View campaign performance metrics
 * - Pause/resume campaigns
 * - Configure email sequences
 */

interface Campaign {
    id: string;
    name: string;
    description: string;
    status: 'draft' | 'active' | 'paused' | 'completed';
    fromEmail: string;
    fromName: string;
    sequence: SequenceStep[];
    stats: {
        enrolled: number;
        emailsSent: number;
        opened: number;
        clicked: number;
        replied: number;
        unsubscribed: number;
    };
    createdAt: string;
    startedAt: string | null;
}

interface SequenceStep {
    id: string;
    type: 'email' | 'delay' | 'condition';
    subject?: string;
    delayDays?: number;
    sent?: number;
    opened?: number;
}

export default function CampaignsPage() {
    const {
        data: campaigns,
        setData: setCampaigns,
        loading,
    } = useApiResource<Campaign[]>('/api/campaigns', {
        initialData: [],
        errorMessage: 'Failed to load campaigns.',
    });
    const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const dialog = useDialog();

    async function toggleCampaignStatus(campaignId: string) {
        const campaign = campaigns.find(c => c.id === campaignId);
        if (!campaign) return;
        const newStatus = campaign.status === 'active' ? 'paused' : campaign.status === 'paused' ? 'active' : campaign.status;
        const isPausing = newStatus === 'paused';

        const confirmed = await dialog.confirm({
            title: isPausing ? 'Pause Campaign' : 'Resume Campaign',
            message: isPausing
                ? `Pause "${campaign.name}"? No further emails will be sent until you resume it.`
                : `Resume "${campaign.name}"? Sending will continue from where it left off.`,
            confirmLabel: isPausing ? 'Pause' : 'Resume',
            variant: isPausing ? 'destructive' : 'default',
        });
        if (!confirmed) return;

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/api/campaigns/${campaignId}`, {
                method: 'PATCH',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ status: newStatus }),
            });
            if (res.ok) {
                setCampaigns(prev => prev.map(c =>
                    c.id === campaignId ? { ...c, status: newStatus } : c
                ));
            } else {
                await dialog.alert({ title: 'Toggle Failed', message: `Failed to change campaign status (${res.status})` });
            }
        } catch (err) {
            await dialog.alert({ title: 'Network Error', message: err instanceof Error ? err.message : 'Failed to toggle campaign status' });
        }
    }

    async function startCampaign(campaignId: string) {
        const confirmed = await dialog.confirm({
            title: 'Start Campaign',
            message: 'Start this campaign? It will begin sending emails to enrolled contacts.',
            confirmLabel: 'Start',
            variant: 'default',
        });
        if (!confirmed) return;
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/api/campaigns/${campaignId}`, {
                method: 'PATCH',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ status: 'active' }),
            });
            if (res.ok) {
                setCampaigns(prev => prev.map(c =>
                    c.id === campaignId ? { ...c, status: 'active' as const, startedAt: new Date().toISOString() } : c
                ));
            } else {
                await dialog.alert({ title: 'Start Failed', message: `Failed to start campaign (${res.status})` });
            }
        } catch (err) {
            await dialog.alert({ title: 'Network Error', message: err instanceof Error ? err.message : 'Failed to start campaign' });
        }
    }

    function getOpenRate(campaign: Campaign): string {
        if (campaign.stats.emailsSent === 0) return '0%';
        return ((campaign.stats.opened / campaign.stats.emailsSent) * 100).toFixed(1) + '%';
    }

    function getReplyRate(campaign: Campaign): string {
        if (campaign.stats.emailsSent === 0) return '0%';
        return ((campaign.stats.replied / campaign.stats.emailsSent) * 100).toFixed(1) + '%';
    }

    if (loading) {
        return <PageLoadingState label="Loading campaigns..." />;
    }

    return (
        <div className="cp-page cp-page--narrow">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Drip Campaigns</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage automated email sequences for lead nurturing
                    </p>
                </div>
                <button aria-label="Create campaign" type="button" onClick={() => setShowCreateModal(true)} className="px-6 py-2.5 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 shadow-sm transition-all hover:shadow-md">
                    + Create Campaign
                </button>
            </div>

            {/* Campaign Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm font-medium text-muted-foreground mb-1">Total Campaigns</div>
                    <div className="text-2xl font-bold text-foreground">{campaigns.length}</div>
                    <div className="text-xs font-semibold text-emerald-600 mt-1 bg-emerald-500/10 inline-block px-1.5 py-0.5 rounded">{campaigns.filter(c => c.status === 'active').length} active</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm font-medium text-muted-foreground mb-1">Total Enrolled</div>
                    <div className="text-2xl font-bold text-foreground">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.enrolled, 0))}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Leads in sequences</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm font-medium text-muted-foreground mb-1">Emails Sent</div>
                    <div className="text-2xl font-bold text-foreground">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.emailsSent, 0))}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Total across all campaigns</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm font-medium text-muted-foreground mb-1">Total Replies</div>
                    <div className="text-2xl font-bold text-emerald-600">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.replied, 0))}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Interested prospects</div>
                </div>
            </div>

            {/* Campaign List */}
            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                <div className="divide-y divide-border">
                    {campaigns.map(campaign => (
                        <div
                            key={campaign.id}
                            className="p-6 hover:bg-muted/50 cursor-pointer transition-colors"
                            onClick={() => setSelectedCampaign(campaign)}
                        >
                            <div className="flex items-start justify-between">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-2">
                                        <h3 className="text-lg font-semibold text-foreground">{campaign.name}</h3>
                                        <span className={cn('px-2.5 py-0.5 rounded-md text-xs font-semibold border', 
                                            campaign.status === 'active' ? 'bg-success/10 text-success border-success/20' :
                                            campaign.status === 'paused' ? 'bg-warning/10 text-warning border-warning/20' :
                                            'bg-muted text-muted-foreground border-border'
                                        )}>
                                            {campaign.status.toUpperCase()}
                                        </span>
                                    </div>
                                    <p className="text-sm text-muted-foreground mb-4">{campaign.description}</p>
                                    <div className="flex items-center gap-8 text-sm">
                                        <div className="flex items-center gap-2">
                                            <span className="text-muted-foreground">Enrolled:</span>
                                            <span className="font-semibold text-foreground">{formatNumber(campaign.stats.enrolled)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-muted-foreground">Sent:</span>
                                            <span className="font-semibold text-foreground">{formatNumber(campaign.stats.emailsSent)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-muted-foreground">Open Rate:</span>
                                            <span className="font-semibold text-emerald-600 bg-emerald-500/10 px-1.5 rounded">{getOpenRate(campaign)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-muted-foreground">Reply Rate:</span>
                                            <span className="font-semibold text-blue-600 bg-blue-500/10 px-1.5 rounded">{getReplyRate(campaign)}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                    {(campaign.status === 'active' || campaign.status === 'paused') && (
                                        <button
                                            aria-label={campaign.status === 'active' ? `Pause campaign ${campaign.name}` : `Resume campaign ${campaign.name}`}
                                            onClick={() => toggleCampaignStatus(campaign.id)}
                                            className={cn(
                                                'px-4 py-2 rounded-lg text-sm font-medium transition-colors border',
                                                campaign.status === 'active'
                                                    ? 'bg-warning/10 text-warning border-warning/20 hover:bg-warning/20'
                                                    : 'bg-success/10 text-success border-success/20 hover:bg-success/20'
                                            )}
                                        >
                                            {campaign.status === 'active' ? 'Pause' : 'Resume'}
                                        </button>
                                    )}
                                    {campaign.status === 'draft' && (
                                        <button aria-label={`Start campaign ${campaign.name}`} type="button" onClick={() => startCampaign(campaign.id)} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 shadow-sm">
                                            Start
                                        </button>
                                    )}
                                    <button aria-label={`Open settings for ${campaign.name}`} type="button" onClick={() => setSelectedCampaign(campaign)} className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors">
                                        Settings
                                    </button>
                                </div>
                            </div>

                            {/* Sequence Preview */}
                            <div className="mt-5 flex items-center gap-2 overflow-x-auto pb-2 scrollbar-hide">
                                {campaign.sequence.map((step, index) => (
                                    <div key={step.id} className="flex items-center flex-shrink-0">
                                        {index > 0 && <div className="w-6 h-px bg-border mx-2" />}
                                        {step.type === 'email' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-card border border-primary/20 rounded-lg text-xs font-medium text-foreground shadow-sm flex items-center gap-1.5">
                                                <span className="text-primary">Email</span> {step.subject?.substring(0, 25)}...
                                            </div>
                                        ) : step.type === 'delay' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-muted/50 border border-border rounded-lg text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                                                <span>Delay</span> {step.delayDays}d
                                            </div>
                                        ) : null}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Campaign Detail Modal */}
            {selectedCampaign && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedCampaign(null)}>
                    <div className="bg-card rounded-2xl p-6 w-full max-w-2xl shadow-2xl border border-border max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6 border-b border-border pb-4">
                            <div>
                                <h2 className="text-xl font-bold text-foreground">{selectedCampaign.name}</h2>
                                <p className="text-sm text-muted-foreground mt-1">{selectedCampaign.description}</p>
                            </div>
                            <button 
                                type="button"
                                onClick={() => setSelectedCampaign(null)} 
                                className="text-muted-foreground hover:text-foreground p-1 rounded-lg hover:bg-muted transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        {/* Stats Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                            <div className="bg-muted/30 rounded-xl p-4 text-center border border-border">
                                <div className="text-2xl font-bold text-foreground">{formatNumber(selectedCampaign.stats.emailsSent)}</div>
                                <div className="text-xs font-medium text-muted-foreground mt-1">Emails Sent</div>
                            </div>
                            <div className="bg-success/10 rounded-xl p-4 text-center border border-success/20">
                                <div className="text-2xl font-bold text-success">{getOpenRate(selectedCampaign)}</div>
                                <div className="text-xs font-medium text-success/80 mt-1">Open Rate</div>
                            </div>
                            <div className="bg-info/10 rounded-xl p-4 text-center border border-info/20">
                                <div className="text-2xl font-bold text-info">{getReplyRate(selectedCampaign)}</div>
                                <div className="text-xs font-medium text-info/80 mt-1">Reply Rate</div>
                            </div>
                        </div>

                        {/* Sequence Details */}
                        <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                            <span>Sequence Flow</span>
                            <span className="text-xs font-normal text-muted-foreground bg-muted px-2.5 py-0.5 rounded-full">{selectedCampaign.sequence.length} steps</span>
                        </h3>
                        <div className="space-y-4 mb-8">
                            {selectedCampaign.sequence.map((step, index) => (
                                <div key={step.id} className="relative pl-8">
                                    {/* Connectivity Line */}
                                    {index < selectedCampaign.sequence.length - 1 && (
                                        <div className="absolute left-3 top-8 bottom-[-24px] w-0.5 bg-border"></div>
                                    )}
                                    
                                    <div className="absolute left-0 top-0 w-6 h-6 rounded-full bg-muted border border-border flex items-center justify-center text-xs font-medium text-muted-foreground z-10">
                                        {index + 1}
                                    </div>
                                    
                                    {step.type === 'email' ? (
                                        <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                                            <div className="flex items-start justify-between">
                                                <div>
                                                    <div className="text-xs font-semibold text-primary mb-1 uppercase tracking-wider">Email</div>
                                                    <div className="font-medium text-foreground">{step.subject}</div>
                                                </div>
                                                <div className="text-xs text-muted-foreground text-right bg-muted/50 px-2.5 py-1 rounded border border-border">
                                                    <div><span className="font-medium text-foreground">{formatNumber(step.sent || 0)}</span> sent</div>
                                                    <div><span className="font-medium text-foreground">{formatNumber(step.opened || 0)}</span> opened</div>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="bg-muted/30 rounded-xl border border-border p-3 flex items-center gap-3 text-muted-foreground">
                                            <span className="text-lg">Delay</span>
                                            <span className="font-medium">Wait {step.delayDays} days</span>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Campaign Info */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 text-sm bg-muted/30 p-4 rounded-xl border border-border">
                            <div>
                                <label className="text-muted-foreground font-medium block mb-1">From Sender</label>
                                <div className="font-medium text-foreground">{selectedCampaign.fromName} &lt;{selectedCampaign.fromEmail}&gt;</div>
                            </div>
                            <div>
                                <label className="text-muted-foreground font-medium block mb-1">Created Date</label>
                                <div className="font-medium text-foreground">{formatDate(selectedCampaign.createdAt)}</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Create Campaign Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowCreateModal(false)}>
                    <div className="bg-card rounded-2xl shadow-xl border border-border w-full max-w-lg mx-4 p-6" onClick={e => e.stopPropagation()}>
                        <h2 className="text-lg font-bold text-foreground mb-4">Create New Campaign</h2>
                        <form onSubmit={async (e) => {
                            e.preventDefault();
                            const form = e.target as HTMLFormElement;
                            const formData = new FormData(form);
                            const name = (formData.get('name') as string).trim();
                            const description = (formData.get('description') as string).trim();
                            const fromName = (formData.get('fromName') as string).trim();
                            const fromEmail = (formData.get('fromEmail') as string).trim();
                            if (!name || !fromEmail) return;
                            try {
                                const csrfToken = await getCsrfToken();
                                const res = await fetch('/api/campaigns', {
                                    method: 'POST',
                                    credentials: 'include',
                                    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                                    body: JSON.stringify({ name, description, fromName, fromEmail }),
                                });
                                if (!res.ok) throw new Error('Failed to create campaign');
                                const newCampaign = await res.json();
                                setCampaigns(prev => [newCampaign, ...prev]);
                                setShowCreateModal(false);
                            } catch (err) {
                                await dialog.alert({ title: 'Create Failed', message: err instanceof Error ? err.message : 'Failed to create campaign' });
                            }
                        }} className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-muted-foreground mb-1">Campaign Name</label>
                                <input name="name" required className="w-full px-3 py-2 border border-border rounded-lg text-sm bg-background text-foreground focus:ring-2 focus:ring-primary focus:border-primary outline-none" placeholder="My outreach campaign" />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-muted-foreground mb-1">Description</label>
                                <textarea name="description" rows={2} className="w-full px-3 py-2 border border-border rounded-lg text-sm bg-background text-foreground focus:ring-2 focus:ring-primary focus:border-primary outline-none resize-none" placeholder="Brief description…" />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">From Name</label>
                                    <input name="fromName" required className="w-full px-3 py-2 border border-border rounded-lg text-sm bg-background text-foreground focus:ring-2 focus:ring-primary focus:border-primary outline-none" placeholder="John Doe" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">From Email</label>
                                    <input name="fromEmail" type="email" required className="w-full px-3 py-2 border border-border rounded-lg text-sm bg-background text-foreground focus:ring-2 focus:ring-primary focus:border-primary outline-none" placeholder="john@company.com" />
                                </div>
                            </div>
                            <div className="flex justify-end gap-3 pt-2">
                                <button type="button" onClick={() => setShowCreateModal(false)} className="px-4 py-2 bg-muted text-foreground rounded-lg text-sm hover:bg-muted/80 font-medium transition-colors">Cancel</button>
                                <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors">Create Campaign</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
