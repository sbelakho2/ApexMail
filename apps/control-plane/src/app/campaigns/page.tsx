'use client';

import { useState, useEffect } from 'react';
import { formatNumber, formatDate, cn } from '../../lib/utils';

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

const DEMO_CAMPAIGNS: Campaign[] = [
    {
        id: '1',
        name: 'SaaS Founders Outreach',
        description: 'Cold outreach to newly funded SaaS startups',
        status: 'active',
        fromEmail: 'alex@apexmail.eu',
        fromName: 'Alex from ApexMail',
        sequence: [
            { id: '1a', type: 'email', subject: 'Quick question about your email infrastructure', sent: 450, opened: 180 },
            { id: '1b', type: 'delay', delayDays: 3 },
            { id: '1c', type: 'email', subject: 'Following up on email deliverability', sent: 380, opened: 152 },
            { id: '1d', type: 'delay', delayDays: 5 },
            { id: '1e', type: 'email', subject: 'Last chance: Free email audit offer', sent: 290, opened: 87 },
        ],
        stats: { enrolled: 500, emailsSent: 1120, opened: 419, clicked: 87, replied: 32, unsubscribed: 12 },
        createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 25).toISOString(),
    },
    {
        id: '2',
        name: 'Product Hunt Launch Follow-up',
        description: 'Follow-up sequence for Product Hunt visitors',
        status: 'active',
        fromEmail: 'team@apexmail.eu',
        fromName: 'ApexMail Team',
        sequence: [
            { id: '2a', type: 'email', subject: 'Thanks for checking out ApexMail!', sent: 890, opened: 534 },
            { id: '2b', type: 'delay', delayDays: 1 },
            { id: '2c', type: 'email', subject: 'Your exclusive 30% discount code', sent: 720, opened: 360 },
        ],
        stats: { enrolled: 920, emailsSent: 1610, opened: 894, clicked: 234, replied: 67, unsubscribed: 8 },
        createdAt: new Date(Date.now() - 86400000 * 14).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 12).toISOString(),
    },
    {
        id: '3',
        name: 'Enterprise Nurture Sequence',
        description: 'Long-term nurture for enterprise prospects',
        status: 'paused',
        fromEmail: 'enterprise@apexmail.eu',
        fromName: 'Enterprise Team',
        sequence: [
            { id: '3a', type: 'email', subject: 'Enterprise email at scale', sent: 120, opened: 48 },
            { id: '3b', type: 'delay', delayDays: 7 },
            { id: '3c', type: 'email', subject: 'Case study: How TechCorp scaled', sent: 85, opened: 34 },
        ],
        stats: { enrolled: 150, emailsSent: 205, opened: 82, clicked: 18, replied: 5, unsubscribed: 2 },
        createdAt: new Date(Date.now() - 86400000 * 45).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 40).toISOString(),
    },
    {
        id: '4',
        name: 'New Feature Announcement',
        description: 'Announce new AI features to existing leads',
        status: 'draft',
        fromEmail: 'updates@apexmail.eu',
        fromName: 'ApexMail Updates',
        sequence: [
            { id: '4a', type: 'email', subject: 'Introducing AI-powered email insights', sent: 0, opened: 0 },
        ],
        stats: { enrolled: 0, emailsSent: 0, opened: 0, clicked: 0, replied: 0, unsubscribed: 0 },
        createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
        startedAt: null,
    },
];

export default function CampaignsPage() {
    const [campaigns, setCampaigns] = useState<Campaign[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);

    useEffect(() => {
        loadCampaigns();
    }, []);

    async function loadCampaigns() {
        try {
            // In production: fetch from Sales Autopilot API
            setCampaigns(DEMO_CAMPAIGNS);
        } finally {
            setLoading(false);
        }
    }

    function toggleCampaignStatus(campaignId: string) {
        setCampaigns(prev => prev.map(c => {
            if (c.id !== campaignId) return c;
            const newStatus = c.status === 'active' ? 'paused' : c.status === 'paused' ? 'active' : c.status;
            return { ...c, status: newStatus };
        }));
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
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Drip Campaigns</h1>
                    <p className="text-surface-500 mt-1">
                        Manage automated email sequences for lead nurturing
                    </p>
                </div>
                <button className="px-6 py-2.5 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 shadow-sm transition-all hover:shadow-md">
                    + Create Campaign
                </button>
            </div>

            {/* Campaign Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm">
                    <div className="text-sm font-medium text-surface-500 mb-1">Total Campaigns</div>
                    <div className="text-2xl font-bold text-surface-900">{campaigns.length}</div>
                    <div className="text-xs font-semibold text-emerald-600 mt-1 bg-emerald-50 inline-block px-1.5 py-0.5 rounded">{campaigns.filter(c => c.status === 'active').length} active</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm">
                    <div className="text-sm font-medium text-surface-500 mb-1">Total Enrolled</div>
                    <div className="text-2xl font-bold text-surface-900">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.enrolled, 0))}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Leads in sequences</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm">
                    <div className="text-sm font-medium text-surface-500 mb-1">Emails Sent</div>
                    <div className="text-2xl font-bold text-surface-900">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.emailsSent, 0))}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Total across all campaigns</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm">
                    <div className="text-sm font-medium text-surface-500 mb-1">Total Replies</div>
                    <div className="text-2xl font-bold text-emerald-600">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.replied, 0))}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Interested prospects</div>
                </div>
            </div>

            {/* Campaign List */}
            <div className="bg-surface-0 rounded-xl border border-surface-200 shadow-sm overflow-hidden">
                <div className="divide-y divide-surface-100">
                    {campaigns.map(campaign => (
                        <div
                            key={campaign.id}
                            className="p-6 hover:bg-surface-50/80 cursor-pointer transition-colors"
                            onClick={() => setSelectedCampaign(campaign)}
                        >
                            <div className="flex items-start justify-between">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-2">
                                        <h3 className="text-lg font-semibold text-surface-900">{campaign.name}</h3>
                                        <span className={cn('px-2.5 py-0.5 rounded-md text-xs font-semibold border', 
                                            campaign.status === 'active' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                                            campaign.status === 'paused' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                                            'bg-surface-100 text-surface-600 border-surface-200'
                                        )}>
                                            {campaign.status.toUpperCase()}
                                        </span>
                                    </div>
                                    <p className="text-sm text-surface-600 mb-4">{campaign.description}</p>
                                    <div className="flex items-center gap-8 text-sm">
                                        <div className="flex items-center gap-2">
                                            <span className="text-surface-500">Enrolled:</span>
                                            <span className="font-semibold text-surface-900">{formatNumber(campaign.stats.enrolled)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-surface-500">Sent:</span>
                                            <span className="font-semibold text-surface-900">{formatNumber(campaign.stats.emailsSent)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-surface-500">Open Rate:</span>
                                            <span className="font-semibold text-emerald-600 bg-emerald-50 px-1.5 rounded">{getOpenRate(campaign)}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-surface-500">Reply Rate:</span>
                                            <span className="font-semibold text-blue-600 bg-blue-50 px-1.5 rounded">{getReplyRate(campaign)}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                    {(campaign.status === 'active' || campaign.status === 'paused') && (
                                        <button
                                            onClick={() => toggleCampaignStatus(campaign.id)}
                                            className={cn(
                                                'px-4 py-2 rounded-lg text-sm font-medium transition-colors border',
                                                campaign.status === 'active'
                                                    ? 'bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100'
                                                    : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                                            )}
                                        >
                                            {campaign.status === 'active' ? 'Pause' : 'Resume'}
                                        </button>
                                    )}
                                    {campaign.status === 'draft' && (
                                        <button className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 shadow-sm">
                                            Start
                                        </button>
                                    )}
                                    <button className="p-2 text-surface-400 hover:text-surface-600 hover:bg-surface-100 rounded-lg transition-colors">
                                        ⚙️
                                    </button>
                                </div>
                            </div>

                            {/* Sequence Preview */}
                            <div className="mt-5 flex items-center gap-2 overflow-x-auto pb-2 scrollbar-hide">
                                {campaign.sequence.map((step, index) => (
                                    <div key={step.id} className="flex items-center flex-shrink-0">
                                        {index > 0 && <div className="w-6 h-px bg-surface-300 mx-2" />}
                                        {step.type === 'email' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-surface-0 border border-blue-200 rounded-lg text-xs font-medium text-surface-700 shadow-sm flex items-center gap-1.5">
                                                <span className="text-blue-500">📧</span> {step.subject?.substring(0, 25)}...
                                            </div>
                                        ) : step.type === 'delay' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-surface-50 border border-surface-200 rounded-lg text-xs font-medium text-surface-500 flex items-center gap-1.5">
                                                <span>⏱️</span> {step.delayDays}d
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
                <div className="fixed inset-0 bg-surface-900/40 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedCampaign(null)}>
                    <div className="bg-surface-0 rounded-2xl p-6 w-full max-w-2xl shadow-2xl border border-surface-200 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6 border-b border-surface-100 pb-4">
                            <div>
                                <h2 className="text-xl font-bold text-surface-900">{selectedCampaign.name}</h2>
                                <p className="text-sm text-surface-500 mt-1">{selectedCampaign.description}</p>
                            </div>
                            <button 
                                onClick={() => setSelectedCampaign(null)} 
                                className="text-surface-400 hover:text-surface-600 p-1 rounded-lg hover:bg-surface-100 transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        {/* Stats Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                            <div className="bg-surface-50 rounded-xl p-4 text-center border border-surface-100">
                                <div className="text-2xl font-bold text-surface-900">{formatNumber(selectedCampaign.stats.emailsSent)}</div>
                                <div className="text-xs font-medium text-surface-500 mt-1">Emails Sent</div>
                            </div>
                            <div className="bg-emerald-50 rounded-xl p-4 text-center border border-emerald-100">
                                <div className="text-2xl font-bold text-emerald-700">{getOpenRate(selectedCampaign)}</div>
                                <div className="text-xs font-medium text-emerald-600 mt-1">Open Rate</div>
                            </div>
                            <div className="bg-blue-50 rounded-xl p-4 text-center border border-blue-100">
                                <div className="text-2xl font-bold text-blue-700">{getReplyRate(selectedCampaign)}</div>
                                <div className="text-xs font-medium text-blue-600 mt-1">Reply Rate</div>
                            </div>
                        </div>

                        {/* Sequence Details */}
                        <h3 className="font-semibold text-surface-900 mb-4 flex items-center gap-2">
                            <span>Sequence Flow</span>
                            <span className="text-xs font-normal text-surface-500 bg-surface-100 px-2.5 py-0.5 rounded-full">{selectedCampaign.sequence.length} steps</span>
                        </h3>
                        <div className="space-y-4 mb-8">
                            {selectedCampaign.sequence.map((step, index) => (
                                <div key={step.id} className="relative pl-8">
                                    {/* Connectivity Line */}
                                    {index < selectedCampaign.sequence.length - 1 && (
                                        <div className="absolute left-3 top-8 bottom-[-24px] w-0.5 bg-surface-200"></div>
                                    )}
                                    
                                    <div className="absolute left-0 top-0 w-6 h-6 rounded-full bg-surface-100 border border-surface-200 flex items-center justify-center text-xs font-medium text-surface-600 z-10">
                                        {index + 1}
                                    </div>
                                    
                                    {step.type === 'email' ? (
                                        <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                                            <div className="flex items-start justify-between">
                                                <div>
                                                    <div className="text-xs font-semibold text-blue-600 mb-1 uppercase tracking-wider">Email</div>
                                                    <div className="font-medium text-surface-900">{step.subject}</div>
                                                </div>
                                                <div className="text-xs text-surface-600 text-right bg-surface-50 px-2.5 py-1 rounded border border-surface-100">
                                                    <div><span className="font-medium text-surface-700">{formatNumber(step.sent || 0)}</span> sent</div>
                                                    <div><span className="font-medium text-surface-700">{formatNumber(step.opened || 0)}</span> opened</div>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="bg-surface-50 rounded-xl border border-surface-200 p-3 flex items-center gap-3 text-surface-600">
                                            <span className="text-lg">⏱️</span>
                                            <span className="font-medium">Wait {step.delayDays} days</span>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Campaign Info */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 text-sm bg-surface-50 p-4 rounded-xl border border-surface-200">
                            <div>
                                <label className="text-surface-500 font-medium block mb-1">From Sender</label>
                                <div className="font-medium text-surface-900">{selectedCampaign.fromName} &lt;{selectedCampaign.fromEmail}&gt;</div>
                            </div>
                            <div>
                                <label className="text-surface-500 font-medium block mb-1">Created Date</label>
                                <div className="font-medium text-surface-900">{formatDate(selectedCampaign.createdAt)}</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
