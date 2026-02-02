'use client';

import { useState, useEffect } from 'react';
import { formatNumber, formatDate, cn, getStatusColor } from '../../lib/utils';

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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Drip Campaigns</h1>
                    <p className="text-gray-600 mt-1">
                        Manage automated email sequences for lead nurturing
                    </p>
                </div>
                <button className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700">
                    + Create Campaign
                </button>
            </div>

            {/* Campaign Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500 mb-1">Total Campaigns</div>
                    <div className="text-2xl font-bold text-gray-900">{campaigns.length}</div>
                    <div className="text-xs text-green-600">{campaigns.filter(c => c.status === 'active').length} active</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500 mb-1">Total Enrolled</div>
                    <div className="text-2xl font-bold text-gray-900">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.enrolled, 0))}
                    </div>
                    <div className="text-xs text-gray-500">Leads in sequences</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500 mb-1">Emails Sent</div>
                    <div className="text-2xl font-bold text-gray-900">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.emailsSent, 0))}
                    </div>
                    <div className="text-xs text-gray-500">Total across all campaigns</div>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                    <div className="text-sm text-gray-500 mb-1">Total Replies</div>
                    <div className="text-2xl font-bold text-green-600">
                        {formatNumber(campaigns.reduce((acc, c) => acc + c.stats.replied, 0))}
                    </div>
                    <div className="text-xs text-gray-500">Interested prospects</div>
                </div>
            </div>

            {/* Campaign List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="divide-y divide-gray-100">
                    {campaigns.map(campaign => (
                        <div
                            key={campaign.id}
                            className="p-6 hover:bg-gray-50 cursor-pointer"
                            onClick={() => setSelectedCampaign(campaign)}
                        >
                            <div className="flex items-start justify-between">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-2">
                                        <h3 className="font-semibold text-gray-900">{campaign.name}</h3>
                                        <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getStatusColor(campaign.status))}>
                                            {campaign.status}
                                        </span>
                                    </div>
                                    <p className="text-sm text-gray-600 mb-3">{campaign.description}</p>
                                    <div className="flex items-center gap-6 text-sm">
                                        <div className="flex items-center gap-1">
                                            <span className="text-gray-500">Enrolled:</span>
                                            <span className="font-medium">{formatNumber(campaign.stats.enrolled)}</span>
                                        </div>
                                        <div className="flex items-center gap-1">
                                            <span className="text-gray-500">Sent:</span>
                                            <span className="font-medium">{formatNumber(campaign.stats.emailsSent)}</span>
                                        </div>
                                        <div className="flex items-center gap-1">
                                            <span className="text-gray-500">Open Rate:</span>
                                            <span className="font-medium text-green-600">{getOpenRate(campaign)}</span>
                                        </div>
                                        <div className="flex items-center gap-1">
                                            <span className="text-gray-500">Reply Rate:</span>
                                            <span className="font-medium text-indigo-600">{getReplyRate(campaign)}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                    {(campaign.status === 'active' || campaign.status === 'paused') && (
                                        <button
                                            onClick={() => toggleCampaignStatus(campaign.id)}
                                            className={cn(
                                                'px-4 py-2 rounded-lg text-sm font-medium',
                                                campaign.status === 'active'
                                                    ? 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200'
                                                    : 'bg-green-100 text-green-700 hover:bg-green-200'
                                            )}
                                        >
                                            {campaign.status === 'active' ? 'Pause' : 'Resume'}
                                        </button>
                                    )}
                                    {campaign.status === 'draft' && (
                                        <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700">
                                            Start
                                        </button>
                                    )}
                                    <button className="px-3 py-2 text-gray-400 hover:text-gray-600">
                                        ⚙️
                                    </button>
                                </div>
                            </div>

                            {/* Sequence Preview */}
                            <div className="mt-4 flex items-center gap-2 overflow-x-auto pb-2">
                                {campaign.sequence.map((step, index) => (
                                    <div key={step.id} className="flex items-center">
                                        {index > 0 && <div className="w-4 h-px bg-gray-300 mx-1" />}
                                        {step.type === 'email' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-blue-50 border border-blue-200 rounded text-xs">
                                                📧 {step.subject?.substring(0, 25)}...
                                            </div>
                                        ) : step.type === 'delay' ? (
                                            <div className="flex-shrink-0 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded text-xs text-gray-600">
                                                ⏱️ {step.delayDays}d
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
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedCampaign(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div>
                                <h2 className="text-xl font-bold text-gray-900">{selectedCampaign.name}</h2>
                                <p className="text-sm text-gray-600">{selectedCampaign.description}</p>
                            </div>
                            <button onClick={() => setSelectedCampaign(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        {/* Stats Grid */}
                        <div className="grid grid-cols-3 gap-4 mb-6">
                            <div className="bg-gray-50 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-gray-900">{formatNumber(selectedCampaign.stats.emailsSent)}</div>
                                <div className="text-xs text-gray-500">Emails Sent</div>
                            </div>
                            <div className="bg-green-50 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-green-600">{getOpenRate(selectedCampaign)}</div>
                                <div className="text-xs text-gray-500">Open Rate</div>
                            </div>
                            <div className="bg-indigo-50 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-indigo-600">{getReplyRate(selectedCampaign)}</div>
                                <div className="text-xs text-gray-500">Reply Rate</div>
                            </div>
                        </div>

                        {/* Sequence Details */}
                        <h3 className="font-semibold mb-4">Email Sequence</h3>
                        <div className="space-y-3 mb-6">
                            {selectedCampaign.sequence.map((step, index) => (
                                <div key={step.id} className="flex items-center gap-4">
                                    <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center text-sm font-medium text-gray-600">
                                        {index + 1}
                                    </div>
                                    {step.type === 'email' ? (
                                        <div className="flex-1 p-3 bg-blue-50 rounded-lg border border-blue-200">
                                            <div className="font-medium text-gray-900">{step.subject}</div>
                                            <div className="text-xs text-gray-500 mt-1">
                                                Sent: {formatNumber(step.sent || 0)} • Opened: {formatNumber(step.opened || 0)}
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="flex-1 p-3 bg-gray-50 rounded-lg border border-gray-200">
                                            <div className="text-gray-600">Wait {step.delayDays} days</div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Campaign Info */}
                        <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                                <label className="text-gray-500">From</label>
                                <div className="font-medium">{selectedCampaign.fromName} &lt;{selectedCampaign.fromEmail}&gt;</div>
                            </div>
                            <div>
                                <label className="text-gray-500">Created</label>
                                <div className="font-medium">{formatDate(selectedCampaign.createdAt)}</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
