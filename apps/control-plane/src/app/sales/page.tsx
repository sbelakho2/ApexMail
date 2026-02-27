'use client';

import { useState, useEffect, useCallback } from 'react';
import { cn, formatDate } from '../../lib/utils';
import {
    COMPETITOR_PROVIDERS,
    DiscoverySource,
    DiscoveryStats,
    DiscoveredLead,
    DISCOVERY_SOURCES,
    getFilteredLeads,
    getProviderCounts,
    getScoreColor,
    OUTREACH_OFFERS,
    SALES_TABS,
    TabKey,
    TARGET_CATEGORIES,
} from './sales-config';

/**
 * Automated Sales System - Comprehensive Lead Discovery & Outreach
 * 
 * This page enables:
 * - SaaS directory scraping (Product Hunt, G2, Capterra, Crunchbase)
 * - DNS-based provider detection (SendGrid, Mailgun, Resend, etc.)
 * - Automated, highly personalized outreach campaigns
 * - Offers: Deliverability Audit, Webhook Migration, Free Migration Support
 */

// ── Main Component ──

export default function AutomatedSalesPage() {
    const [activeTab, setActiveTab] = useState<TabKey>('discovery');
    const [loading, setLoading] = useState(false);
    
    // Discovery State
    const [sources, setSources] = useState<DiscoverySource[]>(DISCOVERY_SOURCES);
    const [selectedCategories, setSelectedCategories] = useState<string[]>(['Email Marketing', 'Transactional Email', 'Newsletter Platforms']);
    const [maxPages, setMaxPages] = useState(3);
    const [isRunning, setIsRunning] = useState(false);
    
    // Leads State
    const [leads, setLeads] = useState<DiscoveredLead[]>([]);
    const [providerFilter, setProviderFilter] = useState<string | null>(null);
    const [selectedLeads, setSelectedLeads] = useState<Set<string>>(new Set());
    
    // Stats State
    const [stats, setStats] = useState<DiscoveryStats | null>(null);

    // Load initial data
    useEffect(() => {
        loadLeads();
    }, []);

    async function loadLeads() {
        setLoading(true);
        try {
            const response = await fetch('/api/sales/leads', { credentials: 'include' });
            if (response.ok) {
                const data = await response.json();
                setLeads(data.leads || []);
                setStats(data.stats || null);
            }
        } catch (err) {
            console.error('Failed to load leads:', err);
        } finally {
            setLoading(false);
        }
    }

    const toggleSource = useCallback((sourceId: string) => {
        setSources(prev => prev.map(s => 
            s.id === sourceId ? { ...s, enabled: !s.enabled } : s
        ));
    }, []);

    const toggleCategory = useCallback((category: string) => {
        setSelectedCategories(prev => 
            prev.includes(category) ? prev.filter(c => c !== category) : [...prev, category]
        );
    }, []);

    const toggleLeadSelection = useCallback((leadId: string) => {
        setSelectedLeads(prev => {
            const next = new Set(prev);
            if (next.has(leadId)) {
                next.delete(leadId);
            } else {
                next.add(leadId);
            }
            return next;
        });
    }, []);

    const selectAllFiltered = useCallback(() => {
        const filtered = getFilteredLeads(leads, providerFilter);
        setSelectedLeads(new Set(filtered.map(l => l.id)));
    }, [leads, providerFilter]);

    const clearSelection = useCallback(() => {
        setSelectedLeads(new Set());
    }, []);

    async function runDiscovery() {
        setIsRunning(true);
        try {
            const enabledSources = sources.filter(s => s.enabled).map(s => s.id);
            
            const response = await fetch('/api/sales/discovery/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    sources: enabledSources,
                    categories: selectedCategories,
                    maxPagesPerSource: maxPages,
                }),
            });

            if (response.ok) {
                const result = await response.json();
                setStats(result.stats);
                await loadLeads();
                setActiveTab('leads');
            }
        } catch (err) {
            console.error('Discovery failed:', err);
        } finally {
            setIsRunning(false);
        }
    }

    async function startOutreach(offerId: string) {
        if (selectedLeads.size === 0) return;

        try {
            const response = await fetch('/api/sales/outreach/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    leadIds: Array.from(selectedLeads),
                    offerId,
                }),
            });

            if (response.ok) {
                await loadLeads();
                clearSelection();
            }
        } catch (err) {
            console.error('Failed to start outreach:', err);
        }
    }

    const filteredLeads = getFilteredLeads(leads, providerFilter);
    const providerCounts = getProviderCounts(leads);
    const competitorLeads = leads.filter(l => l.emailProvider && COMPETITOR_PROVIDERS.includes(l.emailProvider));

    if (loading && leads.length === 0) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-foreground">Automated Sales System</h1>
                <p className="text-muted-foreground mt-1">
                    Discover leads, identify competitor users via DNS, and run personalized outreach campaigns
                </p>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Total Leads</div>
                    <div className="text-2xl font-bold text-foreground">{leads.length}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Competitor Users</div>
                    <div className="text-2xl font-bold text-primary">{competitorLeads.length}</div>
                    <div className="text-xs text-muted-foreground mt-1">SendGrid, Mailgun, Resend</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Selected</div>
                    <div className="text-2xl font-bold text-foreground">{selectedLeads.size}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Avg. Score</div>
                    <div className="text-2xl font-bold text-success">
                        {leads.length > 0 ? Math.round(leads.reduce((a, l) => a + l.score, 0) / leads.length) : 0}
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 mb-6 bg-muted/50 p-1 rounded-xl w-fit">
                {SALES_TABS.map(tab => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={cn(
                            'px-4 py-2 rounded-lg text-sm font-medium transition-all capitalize',
                            activeTab === tab
                                ? 'bg-card text-foreground shadow-sm'
                                : 'text-muted-foreground hover:text-foreground'
                        )}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            {activeTab === 'discovery' && (
                <div className="space-y-6">
                    {/* Discovery Sources */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">SaaS Directory Sources</h2>
                        <p className="text-sm text-muted-foreground mb-4">
                            Select directories to scrape for potential leads. Robots.txt compliant with ethical rate limiting.
                        </p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {sources.map(source => (
                                <div
                                    key={source.id}
                                    className={cn(
                                        'flex items-center justify-between p-4 rounded-xl border transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
                                        source.enabled
                                            ? 'border-primary/20 bg-primary/5'
                                            : 'border-border bg-muted/30 hover:bg-muted/50'
                                    )}
                                    onClick={() => toggleSource(source.id)}
                                    role="checkbox"
                                    aria-checked={source.enabled}
                                    tabIndex={0}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' || e.key === ' ') {
                                            e.preventDefault();
                                            toggleSource(source.id);
                                        }
                                    }}
                                >
                                    <div className="flex items-center gap-4">
                                        <span className="text-2xl">{source.icon}</span>
                                        <div>
                                            <div className="font-semibold text-foreground">{source.name}</div>
                                            <div className="text-xs text-muted-foreground">{source.description}</div>
                                        </div>
                                    </div>
                                    <div className={cn(
                                        'w-12 h-6 rounded-full transition-colors relative',
                                        source.enabled ? 'bg-primary' : 'bg-muted'
                                    )}>
                                        <span className={cn(
                                            'absolute top-1 w-4 h-4 rounded-full bg-background transition-transform shadow-sm',
                                            source.enabled ? 'translate-x-7' : 'translate-x-1'
                                        )} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Target Categories */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">Target Categories</h2>
                        <p className="text-sm text-muted-foreground mb-4">
                            Focus on categories where companies are likely to need email infrastructure.
                        </p>
                        <div className="flex flex-wrap gap-2">
                            {TARGET_CATEGORIES.map(category => (
                                <button
                                    key={category}
                                    onClick={() => toggleCategory(category)}
                                    className={cn(
                                        'px-3.5 py-1.5 rounded-full text-sm font-medium transition-colors border',
                                        selectedCategories.includes(category)
                                            ? 'bg-primary text-primary-foreground border-primary shadow-sm'
                                            : 'bg-card text-muted-foreground border-border hover:bg-muted hover:border-muted-foreground'
                                    )}
                                >
                                    {category}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Discovery Settings */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">Discovery Settings</h2>
                        <div className="flex items-center gap-6">
                            <div>
                                <label className="text-sm font-medium text-foreground block mb-2">
                                    Max pages per source
                                </label>
                                <input
                                    type="number"
                                    min={1}
                                    max={10}
                                    value={maxPages}
                                    onChange={(e) => setMaxPages(Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))}
                                    className="w-24 px-3 py-2 rounded-lg border border-border bg-background text-foreground focus:ring-2 focus:ring-primary/20 focus:border-primary"
                                />
                            </div>
                            <div className="flex-1" />
                            <button
                                onClick={runDiscovery}
                                disabled={isRunning || sources.filter(s => s.enabled).length === 0 || selectedCategories.length === 0}
                                className={cn(
                                    'px-8 py-3 rounded-xl font-semibold transition-all shadow-sm',
                                    isRunning || sources.filter(s => s.enabled).length === 0 || selectedCategories.length === 0
                                        ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                        : 'bg-primary text-primary-foreground hover:bg-primary/90 hover:shadow-md'
                                )}
                            >
                                {isRunning ? (
                                    <span className="flex items-center gap-2">
                                        <span className="animate-spin">⟳</span> Running Discovery...
                                    </span>
                                ) : (
                                    '🔍 Run Discovery'
                                )}
                            </button>
                        </div>
                    </div>

                    {/* What happens during discovery */}
                    <div className="bg-info/5 border border-info/20 rounded-xl p-5">
                        <h3 className="font-semibold text-foreground mb-2">What happens during discovery?</h3>
                        <ul className="text-sm text-muted-foreground space-y-1">
                            <li>• Scrapes selected SaaS directories for companies in target categories</li>
                            <li>• Resolves MX records to identify email providers (SendGrid, Mailgun, Resend, etc.)</li>
                            <li>• Calculates lead scores based on company profile and fit</li>
                            <li>• Stores leads with provider tags for targeted outreach</li>
                        </ul>
                    </div>
                </div>
            )}

            {activeTab === 'leads' && (
                <div className="space-y-6">
                    {/* Provider Filters */}
                    <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                        <div className="flex items-center gap-4 flex-wrap">
                            <span className="text-sm font-medium text-foreground">Filter by provider:</span>
                            <button
                                onClick={() => setProviderFilter(null)}
                                className={cn(
                                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border',
                                    !providerFilter
                                        ? 'bg-primary text-primary-foreground border-primary'
                                        : 'bg-card text-muted-foreground border-border hover:bg-muted'
                                )}
                            >
                                All ({leads.length})
                            </button>
                            {COMPETITOR_PROVIDERS.map(provider => {
                                const count = providerCounts[provider] || 0;
                                if (count === 0) return null;
                                return (
                                    <button
                                        key={provider}
                                        onClick={() => setProviderFilter(provider)}
                                        className={cn(
                                            'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border',
                                            providerFilter === provider
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'bg-card text-muted-foreground border-border hover:bg-muted'
                                        )}
                                    >
                                        {provider} ({count})
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* Selection Actions */}
                    {selectedLeads.size > 0 && (
                        <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 flex items-center justify-between">
                            <div className="text-sm text-foreground">
                                <strong>{selectedLeads.size}</strong> leads selected
                            </div>
                            <div className="flex gap-2">
                                <button
                                    onClick={clearSelection}
                                    className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
                                >
                                    Clear selection
                                </button>
                                <button
                                    onClick={() => setActiveTab('outreach')}
                                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 shadow-sm"
                                >
                                    Start Outreach →
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Leads Table */}
                    <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                        <div className="flex items-center justify-between p-4 border-b border-border bg-muted/30">
                            <h2 className="font-semibold text-foreground">
                                Discovered Leads ({filteredLeads.length})
                            </h2>
                            <button
                                onClick={selectAllFiltered}
                                className="text-sm text-primary hover:underline"
                            >
                                Select all {providerFilter ? `${providerFilter} leads` : ''}
                            </button>
                        </div>
                        <div className="divide-y divide-border">
                            {filteredLeads.length === 0 ? (
                                <div className="p-12 text-center text-muted-foreground">
                                    {leads.length === 0
                                        ? 'No leads discovered yet. Run a discovery job to find prospects.'
                                        : 'No leads match the current filter.'}
                                </div>
                            ) : (
                                filteredLeads.map(lead => (
                                    <div
                                        key={lead.id}
                                        className={cn(
                                            'p-4 hover:bg-muted/30 transition-colors flex items-center gap-4',
                                            selectedLeads.has(lead.id) && 'bg-primary/5'
                                        )}
                                    >
                                        <input
                                            type="checkbox"
                                            checked={selectedLeads.has(lead.id)}
                                            onChange={() => toggleLeadSelection(lead.id)}
                                            className="w-4 h-4 rounded border-border text-primary focus:ring-primary/20"
                                        />
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-3 mb-1">
                                                <span className="font-semibold text-foreground truncate">{lead.companyName}</span>
                                                <span className={cn('px-2 py-0.5 rounded-md text-xs font-bold', getScoreColor(lead.score))}>
                                                    {lead.score}
                                                </span>
                                                {lead.emailProvider && COMPETITOR_PROVIDERS.includes(lead.emailProvider) && (
                                                    <span className="px-2 py-0.5 bg-warning/10 text-warning border border-warning/20 rounded-md text-xs font-medium">
                                                        🎯 {lead.emailProvider}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="text-sm text-muted-foreground">
                                                {lead.domain} · {lead.source} · {lead.category}
                                            </div>
                                        </div>
                                        <div className="text-xs text-muted-foreground">
                                            {formatDate(lead.foundAt)}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>
            )}

            {activeTab === 'outreach' && (
                <div className="space-y-6">
                    {selectedLeads.size === 0 ? (
                        <div className="bg-warning/5 border border-warning/20 rounded-xl p-8 text-center">
                            <div className="text-4xl mb-4">📭</div>
                            <h3 className="text-lg font-semibold text-foreground mb-2">No leads selected</h3>
                            <p className="text-muted-foreground mb-4">
                                Go to the Leads tab and select the companies you want to reach out to.
                            </p>
                            <button
                                onClick={() => setActiveTab('leads')}
                                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90"
                            >
                                Select Leads
                            </button>
                        </div>
                    ) : (
                        <>
                            <div className="bg-success/5 border border-success/20 rounded-xl p-4">
                                <span className="font-semibold text-foreground">{selectedLeads.size} leads</span>
                                <span className="text-muted-foreground"> ready for outreach</span>
                            </div>

                            <h2 className="text-lg font-semibold text-foreground">Choose Your Offer</h2>
                            <p className="text-sm text-muted-foreground -mt-4">
                                Each offer uses a personalized email sequence optimized for conversion.
                            </p>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                {OUTREACH_OFFERS.map(offer => (
                                    <div
                                        key={offer.id}
                                        className="bg-card rounded-xl border border-border p-6 shadow-sm hover:shadow-md transition-shadow"
                                    >
                                        <div className="text-3xl mb-4">{offer.icon}</div>
                                        <h3 className="text-lg font-semibold text-foreground mb-2">{offer.name}</h3>
                                        <p className="text-sm text-muted-foreground mb-6">{offer.description}</p>
                                        <button
                                            onClick={() => startOutreach(offer.id)}
                                            className="w-full px-4 py-2.5 bg-primary text-primary-foreground rounded-xl font-semibold hover:bg-primary/90 shadow-sm transition-all"
                                        >
                                            Start Campaign
                                        </button>
                                    </div>
                                ))}
                            </div>

                            <div className="bg-info/5 border border-info/20 rounded-xl p-5">
                                <h3 className="font-semibold text-foreground mb-2">Personalization Details</h3>
                                <ul className="text-sm text-muted-foreground space-y-1">
                                    <li>• Each email references the lead's domain and detected email provider</li>
                                    <li>• Provider-specific migration guides are automatically linked</li>
                                    <li>• Emails are sent via the sales-autopilot drip engine with intelligent pacing</li>
                                    <li>• Replies are monitored via Inbox Sentinel for automatic engagement detection</li>
                                </ul>
                            </div>
                        </>
                    )}
                </div>
            )}

            {activeTab === 'analytics' && (
                <div className="space-y-6">
                    {stats ? (
                        <>
                            {/* Discovery Stats */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">Total Scraped</h3>
                                    <div className="text-3xl font-bold text-foreground">{stats.totalScraped}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">With MX Records</h3>
                                    <div className="text-3xl font-bold text-success">{stats.totalWithMx}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">Competitor Users</h3>
                                    <div className="text-3xl font-bold text-primary">{competitorLeads.length}</div>
                                </div>
                            </div>

                            {/* By Provider */}
                            <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                <h2 className="text-lg font-semibold text-foreground mb-4">Leads by Email Provider</h2>
                                <div className="space-y-3">
                                    {Object.entries(stats.byProvider)
                                        .sort(([, a], [, b]) => b - a)
                                        .map(([provider, count]) => (
                                            <div key={provider} className="flex items-center gap-4">
                                                <div className="w-32 text-sm font-medium text-foreground">{provider}</div>
                                                <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden">
                                                    <svg width="100%" height="100%" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">
                                                        <rect
                                                            x="0"
                                                            y="0"
                                                            width={Math.max(0, Math.min(100, (count / Math.max(stats.totalScraped, 1)) * 100))}
                                                            height="16"
                                                            className={cn(
                                                                COMPETITOR_PROVIDERS.includes(provider) ? 'fill-primary' : 'fill-muted-foreground/30'
                                                            )}
                                                            rx="999"
                                                            ry="999"
                                                        />
                                                    </svg>
                                                </div>
                                                <div className="w-12 text-sm text-muted-foreground text-right">{count}</div>
                                            </div>
                                        ))}
                                </div>
                            </div>

                            {/* By Source */}
                            <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                <h2 className="text-lg font-semibold text-foreground mb-4">Leads by Source</h2>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    {Object.entries(stats.bySource).map(([source, count]) => (
                                        <div key={source} className="text-center p-4 bg-muted/30 rounded-xl">
                                            <div className="text-2xl font-bold text-foreground">{count}</div>
                                            <div className="text-sm text-muted-foreground capitalize">{source.replace('_', ' ')}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="bg-muted/30 rounded-xl p-12 text-center">
                            <div className="text-4xl mb-4">📊</div>
                            <h3 className="text-lg font-semibold text-foreground mb-2">No analytics yet</h3>
                            <p className="text-muted-foreground">
                                Run a discovery job to see detailed analytics about your leads.
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
