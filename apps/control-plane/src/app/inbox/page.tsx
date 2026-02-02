'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn } from '../../lib/utils';

/**
 * Inbox Sentinel - AI-powered email reply management
 * 
 * The owner can:
 * - View incoming replies from campaigns
 * - Classify replies (interested, not interested, out of office, etc.)
 * - Take action on promising replies
 * - Train the AI classifier
 */

interface InboxMessage {
    id: string;
    from: string;
    fromName: string;
    subject: string;
    preview: string;
    receivedAt: string;
    classification: 'interested' | 'not_interested' | 'out_of_office' | 'unsubscribe' | 'question' | 'spam' | 'unclassified';
    confidence: number;
    campaignId: string | null;
    campaignName: string | null;
    leadId: string | null;
    read: boolean;
    starred: boolean;
}

const CLASSIFICATION_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
    interested: { label: 'Interested', color: 'bg-green-100 text-green-700', icon: '🎯' },
    not_interested: { label: 'Not Interested', color: 'bg-red-100 text-red-700', icon: '👎' },
    out_of_office: { label: 'Out of Office', color: 'bg-yellow-100 text-yellow-700', icon: '🏖️' },
    unsubscribe: { label: 'Unsubscribe', color: 'bg-orange-100 text-orange-700', icon: '🚫' },
    question: { label: 'Question', color: 'bg-blue-100 text-blue-700', icon: '❓' },
    spam: { label: 'Spam', color: 'bg-gray-100 text-gray-700', icon: '🗑️' },
    unclassified: { label: 'Unclassified', color: 'bg-purple-100 text-purple-700', icon: '📋' },
};

const DEMO_MESSAGES: InboxMessage[] = [
    { id: '1', from: 'john@techcorp.io', fromName: 'John Smith', subject: 'Re: Quick question about your email infrastructure', preview: "Hi Alex, thanks for reaching out! We're actually looking to switch providers and would love to schedule a call...", receivedAt: new Date(Date.now() - 1800000).toISOString(), classification: 'interested', confidence: 0.95, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-1', read: false, starred: true },
    { id: '2', from: 'jane@startup.com', fromName: 'Jane Doe', subject: 'Re: Following up on email deliverability', preview: "I appreciate the follow-up, but we're not looking to change our email provider at this time...", receivedAt: new Date(Date.now() - 3600000).toISOString(), classification: 'not_interested', confidence: 0.88, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-2', read: true, starred: false },
    { id: '3', from: 'mike@enterprise.co', fromName: 'Mike Johnson', subject: 'Re: Enterprise email at scale', preview: "I'm out of the office until January 15th with limited access to email. For urgent matters...", receivedAt: new Date(Date.now() - 7200000).toISOString(), classification: 'out_of_office', confidence: 0.99, campaignId: 'camp-2', campaignName: 'Enterprise Nurture', leadId: 'lead-3', read: true, starred: false },
    { id: '4', from: 'sarah@growth.io', fromName: 'Sarah Williams', subject: 'Re: Thanks for checking out ApexMail!', preview: "What's the pricing for your team plan? We have about 50 users and send around 100k emails monthly...", receivedAt: new Date(Date.now() - 14400000).toISOString(), classification: 'question', confidence: 0.82, campaignId: 'camp-3', campaignName: 'Product Hunt Follow-up', leadId: 'lead-4', read: false, starred: false },
    { id: '5', from: 'no-reply@spam.net', fromName: 'Marketing Team', subject: 'Re: Your email', preview: "Click here to claim your prize! You've been selected for...", receivedAt: new Date(Date.now() - 21600000).toISOString(), classification: 'spam', confidence: 0.97, campaignId: null, campaignName: null, leadId: null, read: true, starred: false },
    { id: '6', from: 'tom@newcompany.dev', fromName: 'Tom Harris', subject: 'Re: Quick question', preview: "Please remove me from your mailing list...", receivedAt: new Date(Date.now() - 28800000).toISOString(), classification: 'unsubscribe', confidence: 0.91, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-5', read: true, starred: false },
];

export default function InboxPage() {
    const [messages, setMessages] = useState<InboxMessage[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedMessage, setSelectedMessage] = useState<InboxMessage | null>(null);
    const [filterClassification, setFilterClassification] = useState<string>('');

    useEffect(() => {
        loadMessages();
    }, []);

    async function loadMessages() {
        try {
            // In production: fetch from Sales Autopilot API
            setMessages(DEMO_MESSAGES);
        } finally {
            setLoading(false);
        }
    }

    function toggleStar(messageId: string) {
        setMessages(prev => prev.map(m => 
            m.id === messageId ? { ...m, starred: !m.starred } : m
        ));
    }

    function markAsRead(messageId: string) {
        setMessages(prev => prev.map(m => 
            m.id === messageId ? { ...m, read: true } : m
        ));
    }

    function reclassify(messageId: string, newClassification: InboxMessage['classification']) {
        setMessages(prev => prev.map(m => 
            m.id === messageId ? { ...m, classification: newClassification, confidence: 1.0 } : m
        ));
        if (selectedMessage?.id === messageId) {
            setSelectedMessage(prev => prev ? { ...prev, classification: newClassification, confidence: 1.0 } : null);
        }
    }

    const filteredMessages = filterClassification
        ? messages.filter(m => m.classification === filterClassification)
        : messages;

    const unreadCount = messages.filter(m => !m.read).length;
    const interestedCount = messages.filter(m => m.classification === 'interested').length;

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
                    <h1 className="text-2xl font-bold text-gray-900">Inbox Sentinel</h1>
                    <p className="text-gray-600 mt-1">
                        AI-classified campaign replies • {unreadCount} unread • {interestedCount} interested
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
                        🔄 Sync Inbox
                    </button>
                    <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">
                        ⚙️ Configure AI
                    </button>
                </div>
            </div>

            {/* Classification Filters */}
            <div className="flex flex-wrap gap-2 mb-6">
                <button
                    onClick={() => setFilterClassification('')}
                    className={cn(
                        'px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
                        !filterClassification
                            ? 'bg-indigo-600 text-white'
                            : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    )}
                >
                    All ({messages.length})
                </button>
                {Object.entries(CLASSIFICATION_CONFIG).map(([key, config]) => {
                    const count = messages.filter(m => m.classification === key).length;
                    if (count === 0) return null;
                    return (
                        <button
                            key={key}
                            onClick={() => setFilterClassification(filterClassification === key ? '' : key)}
                            className={cn(
                                'px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
                                filterClassification === key
                                    ? 'bg-indigo-600 text-white'
                                    : `${config.color} hover:opacity-80`
                            )}
                        >
                            {config.icon} {config.label} ({count})
                        </button>
                    );
                })}
            </div>

            {/* Message List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="divide-y divide-gray-100">
                    {filteredMessages.length === 0 ? (
                        <div className="p-8 text-center text-gray-500">
                            No messages found
                        </div>
                    ) : (
                        filteredMessages.map(message => {
                            const classConfig = CLASSIFICATION_CONFIG[message.classification];
                            return (
                                <div
                                    key={message.id}
                                    className={cn(
                                        'p-4 hover:bg-gray-50 cursor-pointer flex items-start gap-4',
                                        !message.read && 'bg-blue-50/50'
                                    )}
                                    onClick={() => { setSelectedMessage(message); markAsRead(message.id); }}
                                >
                                    <button
                                        onClick={(e) => { e.stopPropagation(); toggleStar(message.id); }}
                                        className={cn('text-lg', message.starred ? 'text-yellow-500' : 'text-gray-300 hover:text-yellow-400')}
                                    >
                                        {message.starred ? '★' : '☆'}
                                    </button>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className={cn('font-medium', !message.read && 'text-gray-900')}>
                                                {message.fromName}
                                            </span>
                                            <span className="text-gray-400 text-sm">&lt;{message.from}&gt;</span>
                                            <span className={cn('px-2 py-0.5 rounded text-xs font-medium', classConfig.color)}>
                                                {classConfig.icon} {classConfig.label}
                                            </span>
                                            {message.confidence < 0.8 && (
                                                <span className="text-xs text-orange-500">Low confidence</span>
                                            )}
                                        </div>
                                        <div className={cn('text-sm mb-1', !message.read ? 'font-medium text-gray-900' : 'text-gray-700')}>
                                            {message.subject}
                                        </div>
                                        <div className="text-sm text-gray-500 truncate">{message.preview}</div>
                                        {message.campaignName && (
                                            <div className="text-xs text-indigo-600 mt-1">📧 {message.campaignName}</div>
                                        )}
                                    </div>
                                    <div className="text-sm text-gray-500">
                                        {formatDate(message.receivedAt)}
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>
            </div>

            {/* Message Detail Modal */}
            {selectedMessage && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedMessage(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-gray-900">{selectedMessage.subject}</h2>
                                <div className="text-sm text-gray-500 mt-1">
                                    From: {selectedMessage.fromName} &lt;{selectedMessage.from}&gt;
                                </div>
                            </div>
                            <button onClick={() => setSelectedMessage(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="flex items-center gap-2 mb-4">
                            <span className={cn('px-2 py-1 rounded text-sm font-medium', CLASSIFICATION_CONFIG[selectedMessage.classification].color)}>
                                {CLASSIFICATION_CONFIG[selectedMessage.classification].icon} {CLASSIFICATION_CONFIG[selectedMessage.classification].label}
                            </span>
                            <span className="text-sm text-gray-500">
                                ({(selectedMessage.confidence * 100).toFixed(0)}% confidence)
                            </span>
                        </div>

                        <div className="bg-gray-50 rounded-lg p-4 mb-6">
                            <p className="text-gray-700 whitespace-pre-wrap">{selectedMessage.preview}</p>
                        </div>

                        {/* Reclassify */}
                        <div className="mb-6">
                            <label className="text-sm text-gray-500 mb-2 block">Reclassify this message:</label>
                            <div className="flex flex-wrap gap-2">
                                {Object.entries(CLASSIFICATION_CONFIG).map(([key, config]) => (
                                    <button
                                        key={key}
                                        onClick={() => reclassify(selectedMessage.id, key as InboxMessage['classification'])}
                                        className={cn(
                                            'px-3 py-1.5 rounded text-sm font-medium',
                                            selectedMessage.classification === key
                                                ? 'ring-2 ring-indigo-500'
                                                : '',
                                            config.color
                                        )}
                                    >
                                        {config.icon} {config.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-2">
                            {selectedMessage.classification === 'interested' && (
                                <button className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
                                    📅 Schedule Demo
                                </button>
                            )}
                            <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                                ↩️ Reply
                            </button>
                            {selectedMessage.leadId && (
                                <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200">
                                    👤 View Lead
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
