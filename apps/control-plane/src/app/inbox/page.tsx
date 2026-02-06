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
    interested: { label: 'Interested', color: 'bg-success/10 text-success', icon: '🎯' },
    not_interested: { label: 'Not Interested', color: 'bg-destructive/10 text-destructive', icon: '👎' },
    out_of_office: { label: 'Out of Office', color: 'bg-warning/10 text-warning', icon: '🏖️' },
    unsubscribe: { label: 'Unsubscribe', color: 'bg-orange-500/10 text-orange-600', icon: '🚫' },
    question: { label: 'Question', color: 'bg-info/10 text-info', icon: '❓' },
    spam: { label: 'Spam', color: 'bg-muted text-muted-foreground', icon: '🗑️' },
    unclassified: { label: 'Unclassified', color: 'bg-purple-500/10 text-purple-600', icon: '📋' },
};



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
            const response = await fetch('/api/inbox', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch inbox: ${response.status}`);
            const data = await response.json();
            setMessages(data);
        } catch (err) {
            console.error('Failed to load inbox:', err);
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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Inbox Sentinel</h1>
                    <p className="text-muted-foreground mt-1">
                        AI-classified campaign replies • {unreadCount} unread • {interestedCount} interested
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-card border border-border rounded-lg text-sm hover:bg-muted/50 font-medium text-muted-foreground transition-colors">
                        🔄 Sync Inbox
                    </button>
                    <button className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors">
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
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted text-muted-foreground hover:bg-muted/80'
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
                                    ? 'bg-primary text-primary-foreground'
                                    : `${config.color} hover:opacity-80`
                            )}
                        >
                            {config.icon} {config.label} ({count})
                        </button>
                    );
                })}
            </div>

            {/* Message List */}
            <div className="bg-card rounded-xl border border-border shadow-sm">
                <div className="divide-y divide-border">
                    {filteredMessages.length === 0 ? (
                        <div className="p-8 text-center text-muted-foreground">
                            No messages found
                        </div>
                    ) : (
                        filteredMessages.map(message => {
                            const classConfig = CLASSIFICATION_CONFIG[message.classification];
                            return (
                                <div
                                    key={message.id}
                                    className={cn(
                                        'p-4 hover:bg-muted/50 cursor-pointer flex items-start gap-4 transition-colors',
                                        !message.read && 'bg-primary/5'
                                    )}
                                    onClick={() => { setSelectedMessage(message); markAsRead(message.id); }}
                                >
                                    <button
                                        onClick={(e) => { e.stopPropagation(); toggleStar(message.id); }}
                                        className={cn('text-lg transition-colors', message.starred ? 'text-warning' : 'text-muted-foreground/30 hover:text-warning/80')}
                                    >
                                        {message.starred ? '★' : '☆'}
                                    </button>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex flex-wrap items-center gap-2 mb-1">
                                            <span className={cn('font-medium', !message.read && 'text-foreground', message.read && 'text-muted-foreground')}>
                                                {message.fromName}
                                            </span>
                                            <span className="text-muted-foreground text-sm">&lt;{message.from}&gt;</span>
                                            <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', classConfig.color)}>
                                                {classConfig.icon} {classConfig.label}
                                            </span>
                                            {message.confidence < 0.8 && (
                                                <span className="text-xs text-warning font-medium">Low confidence</span>
                                            )}
                                        </div>
                                        <div className={cn('text-sm mb-1', !message.read ? 'font-medium text-foreground' : 'text-muted-foreground')}>
                                            {message.subject}
                                        </div>
                                        <div className="text-sm text-muted-foreground truncate">{message.preview}</div>
                                        {message.campaignName && (
                                            <div className="text-xs text-primary mt-1 font-medium">📧 {message.campaignName}</div>
                                        )}
                                    </div>
                                    <div className="text-sm text-muted-foreground">
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
                <div className="fixed inset-0 bg-background/80 flex items-center justify-center z-50 backdrop-blur-sm" onClick={() => setSelectedMessage(null)}>
                    <div className="bg-card rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-foreground">{selectedMessage.subject}</h2>
                                <div className="text-sm text-muted-foreground mt-1">
                                    From: {selectedMessage.fromName} &lt;{selectedMessage.from}&gt;
                                </div>
                            </div>
                            <button 
                                onClick={() => setSelectedMessage(null)} 
                                className="text-muted-foreground hover:text-foreground transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        <div className="flex items-center gap-2 mb-4">
                            <span className={cn('px-2.5 py-0.5 rounded-full text-sm font-medium', CLASSIFICATION_CONFIG[selectedMessage.classification].color)}>
                                {CLASSIFICATION_CONFIG[selectedMessage.classification].icon} {CLASSIFICATION_CONFIG[selectedMessage.classification].label}
                            </span>
                            <span className="text-sm text-muted-foreground font-medium">
                                ({(selectedMessage.confidence * 100).toFixed(0)}% confidence)
                            </span>
                        </div>

                        <div className="bg-muted/30 rounded-lg p-4 mb-6 border border-border">
                            <p className="text-foreground whitespace-pre-wrap">{selectedMessage.preview}</p>
                        </div>

                        {/* Reclassify */}
                        <div className="mb-6">
                            <label className="text-sm text-muted-foreground mb-2 block font-medium">Reclassify this message:</label>
                            <div className="flex flex-wrap gap-2">
                                {Object.entries(CLASSIFICATION_CONFIG).map(([key, config]) => (
                                    <button
                                        key={key}
                                        onClick={() => reclassify(selectedMessage.id, key as InboxMessage['classification'])}
                                        className={cn(
                                            'px-3 py-1.5 rounded text-sm font-medium transition-all',
                                            selectedMessage.classification === key
                                                ? 'ring-2 ring-primary shadow-sm'
                                                : 'hover:opacity-80',
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
                                <button className="flex-1 px-4 py-2 bg-success text-success-foreground rounded-lg hover:bg-success/90 font-medium transition-colors">
                                    📅 Schedule Demo
                                </button>
                            )}
                            <button className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 font-medium transition-colors">
                                ↩️ Reply
                            </button>
                            {selectedMessage.leadId && (
                                <button className="px-4 py-2 bg-muted text-muted-foreground rounded-lg hover:bg-muted/80 font-medium transition-colors">
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
