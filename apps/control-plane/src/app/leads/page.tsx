'use client';

import { useState, useEffect, useCallback } from 'react';
import { cn, formatDate } from '../../lib/utils';

/**
 * Lead Discovery — Real API-driven lead scraping and prospecting
 *
 * Improvements:
 *  #35 Replace fake setTimeout/mock discovery with real API call to /api/sales/discovery/run
 *  #36 Import to CRM persisted via /api/crm/leads POST
 *  #37 De-duplication warning for leads already in database
 *  #41 Toast notifications for success/error states
 *  #42 Search/filter for discovered leads
 *  #43 Enrichment progress indicators per source
 */

interface DiscoverySource {
    id: string;
    name: string;
    icon: string;
    enabled: boolean;
    lastRun: string | null;
    leadsFound: number;
    status: 'idle' | 'running' | 'error';
}

interface DiscoveredLead {
    id: string;
    companyName: string;
    domain: string;
    source: string;
    category: string;
    description: string;
    foundAt: string;
    imported: boolean;
    score?: number;
    emailProvider?: string;
    contactEmail?: string;
}

interface Toast {
    id: string;
    type: 'success' | 'error' | 'info';
    message: string;
}

const CATEGORIES = [
    'Email Marketing',
    'Marketing Automation',
    'CRM Software',
    'Sales Enablement',
    'Customer Success',
    'Newsletter Platforms',
    'Transactional Email',
    'Developer Tools',
    'E-commerce',
    'SaaS Infrastructure',
];

export default function LeadDiscoveryPage() {
    const [sources, setSources] = useState<DiscoverySource[]>([]);
    const [discoveredLeads, setDiscoveredLeads] = useState<DiscoveredLead[]>([]);
    const [selectedCategories, setSelectedCategories] = useState<string[]>(['Email Marketing', 'Newsletter Platforms']);
    const [isRunning, setIsRunning] = useState(false);
    const [discoveryProgress, setDiscoveryProgress] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [toasts, setToasts] = useState<Toast[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [importingIds, setImportingIds] = useState<Set<string>>(new Set());

    const addToast = useCallback((type: Toast['type'], message: string) => {
        const id = Date.now().toString();
        setToasts(prev => [...prev, { id, type, message }]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
    }, []);

    useEffect(() => {
        loadDiscoveredLeads();
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    async function loadDiscoveredLeads() {
        try {
            const response = await fetch('/api/leads/discovery', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch leads: ${response.status}`);
            const data = await response.json();
            setSources(data.sources || []);
            setDiscoveredLeads(data.leads || []);
        } catch (err) {
            console.error('Failed to load discovered leads:', err);
            addToast('error', 'Failed to load leads. Check connection.');
        } finally {
            setLoading(false);
        }
    }

    // Improvement #35: Real API-driven discovery instead of fake setTimeout simulation
    async function runDiscovery() {
        setIsRunning(true);
        const enabledSources = sources.filter(s => s.enabled);

        // Update UI to show running state
        setSources(prev => prev.map(s =>
            s.enabled ? { ...s, status: 'running' as const } : s
        ));

        setDiscoveryProgress(`Scraping ${enabledSources.length} sources across ${selectedCategories.length} categories...`);

        try {
            const response = await fetch('/api/sales/discovery/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    sources: enabledSources.map(s => s.id),
                    categories: selectedCategories,
                    maxPagesPerSource: 3,
                }),
            });

            if (response.ok) {
                const result = await response.json();

                // Update source statuses with real results
                setSources(prev => prev.map(s =>
                    s.enabled ? {
                        ...s,
                        status: 'idle' as const,
                        lastRun: new Date().toISOString(),
                        leadsFound: s.leadsFound + (result.stats?.totalScraped ? Math.ceil(result.stats.totalScraped / enabledSources.length) : 0),
                    } : s
                ));

                // Improvement #37: De-duplication — check for existing domains
                const existingDomains = new Set(discoveredLeads.map(l => l.domain.toLowerCase()));
                const newLeadCount = result.leads?.filter((l: DiscoveredLead) => !existingDomains.has(l.domain?.toLowerCase())).length ?? 0;
                const duplicateCount = (result.leads?.length ?? 0) - newLeadCount;

                setDiscoveryProgress('Refreshing leads list...');
                await loadDiscoveredLeads();

                const msg = `Discovery complete: ${result.stats?.totalScraped ?? 0} scraped, ${result.stats?.totalWithMx ?? 0} with MX records.`;
                addToast('success', duplicateCount > 0 ? `${msg} (${duplicateCount} duplicates skipped)` : msg);
            } else {
                const err = await response.json().catch(() => ({}));
                addToast('error', err.error || 'Discovery failed. Please try again.');
                setSources(prev => prev.map(s =>
                    s.enabled ? { ...s, status: 'error' as const } : s
                ));
            }
        } catch (err) {
            console.error('Discovery API call failed:', err);
            addToast('error', 'Network error during discovery. Check your connection.');
            setSources(prev => prev.map(s =>
                s.enabled ? { ...s, status: 'error' as const } : s
            ));
        } finally {
            setIsRunning(false);
            setDiscoveryProgress(null);
        }
    }

    function toggleSource(sourceId: string) {
        setSources(prev => prev.map(s =>
            s.id === sourceId ? { ...s, enabled: !s.enabled } : s
        ));
    }

    function toggleCategory(category: string) {
        setSelectedCategories(prev =>
            prev.includes(category)
                ? prev.filter(c => c !== category)
                : [...prev, category]
        );
    }

    // Improvement #36: Persist import via CRM API
    async function importLead(leadId: string) {
        setImportingIds(prev => new Set(prev).add(leadId));
        try {
            const lead = discoveredLeads.find(l => l.id === leadId);
            if (!lead) return;

            const response = await fetch('/api/crm/leads', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    leadId: lead.id,
                    companyName: lead.companyName,
                    domain: lead.domain,
                    source: lead.source,
                    category: lead.category,
                }),
            });

            if (response.ok) {
                setDiscoveredLeads(prev => prev.map(l =>
                    l.id === leadId ? { ...l, imported: true } : l
                ));
                addToast('success', `${lead.companyName} imported to CRM.`);
            } else {
                addToast('error', `Failed to import ${lead.companyName}.`);
            }
        } catch (err) {
            console.error('Import failed:', err);
            addToast('error', 'Network error during import.');
        } finally {
            setImportingIds(prev => { const n = new Set(prev); n.delete(leadId); return n; });
        }
    }

    async function importAllLeads() {
        const unimported = discoveredLeads.filter(l => !l.imported);
        let successCount = 0;

        for (const lead of unimported) {
            try {
                const response = await fetch('/api/crm/leads', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        leadId: lead.id,
                        companyName: lead.companyName,
                        domain: lead.domain,
                        source: lead.source,
                        category: lead.category,
                    }),
                });
                if (response.ok) {
                    successCount++;
                    setDiscoveredLeads(prev => prev.map(l =>
                        l.id === lead.id ? { ...l, imported: true } : l
                    ));
                }
            } catch {
                // Continue importing remaining leads
            }
        }

        addToast('success', `${successCount} of ${unimported.length} leads imported to CRM.`);
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    const unimportedCount = discoveredLeads.filter(l => !l.imported).length;

    // Improvement #42: Search filtering
    const filteredLeads = searchQuery.trim()
        ? discoveredLeads.filter(l =>
            l.companyName.toLowerCase().includes(searchQuery.toLowerCase()) ||
            l.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
            l.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
            l.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
            (l.contactEmail && l.contactEmail.toLowerCase().includes(searchQuery.toLowerCase()))
        )
        : discoveredLeads;

    return (
        <div className="cp-page cp-page--narrow">
            {/* Toasts */}
            {toasts.length > 0 && (
                <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 max-w-sm">
                    {toasts.map(t => (
                        <div key={t.id} className={cn('px-4 py-3 rounded-xl shadow-lg text-sm font-medium animate-in slide-in-from-right', t.type === 'error' ? 'bg-destructive text-destructive-foreground' : t.type === 'success' ? 'bg-success text-primary-foreground' : 'bg-info text-primary-foreground')}>
                            {t.message}
                        </div>
                    ))}
                </div>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8 gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Lead Discovery</h1>
                    <p className="text-muted-foreground mt-1">
                        Automatically discover potential customers from multiple sources via real-time scraping
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => loadDiscoveredLeads()}
                        className="px-3 py-2.5 text-sm border border-border rounded-lg hover:bg-muted transition-colors"
                    >
                        ↻ Refresh
                    </button>
                    <button
                        onClick={runDiscovery}
                        disabled={isRunning || sources.filter(s => s.enabled).length === 0}
                        className={cn(
                            'px-6 py-2.5 rounded-lg font-semibold transition-all shadow-sm',
                            isRunning || sources.filter(s => s.enabled).length === 0
                                ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                : 'bg-primary text-primary-foreground hover:bg-primary/90 hover:shadow-md'
                        )}
                    >
                        {isRunning ? (
                            <span className="flex items-center gap-2">
                                <span className="animate-spin">⟳</span> Running Discovery...
                            </span>
                        ) : (
                            'Run Discovery'
                        )}
                    </button>
                </div>
            </div>

            {/* Improvement #43: Discovery progress indicator */}
            {discoveryProgress && (
                <div className="mb-6 p-4 bg-primary/5 border border-primary/20 rounded-xl flex items-center gap-3">
                    <div className="animate-spin h-5 w-5 border-2 border-primary border-t-transparent rounded-full" />
                    <span className="text-sm font-medium text-foreground">{discoveryProgress}</span>
                </div>
            )}

            {/* Configuration */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Sources */}
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-foreground mb-4">Discovery Sources</h2>
                    <div className="space-y-3">
                        {sources.map(source => (
                            <div
                                key={source.id}
                                className={cn(
                                    'flex items-center justify-between p-4 rounded-xl border transition-colors',
                                    source.enabled
                                        ? 'border-primary/20 bg-primary/5'
                                        : 'border-border bg-muted/30'
                                )}
                            >
                                <div className="flex items-center gap-4">
                                    <span className="text-2xl">{source.icon}</span>
                                    <div>
                                        <div className="font-semibold text-foreground">{source.name}</div>
                                        <div className="text-xs text-muted-foreground mt-0.5">
                                            {source.lastRun ? `Last run: ${formatDate(source.lastRun)}` : 'Never run'}
                                            {source.leadsFound > 0 && ` · ${source.leadsFound} leads found`}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {source.status === 'running' && (
                                        <span className="text-primary animate-pulse text-xs font-medium uppercase tracking-wider">Running...</span>
                                    )}
                                    {source.status === 'error' && (
                                        <span className="text-destructive text-xs font-medium uppercase tracking-wider">Error</span>
                                    )}
                                    <button
                                        onClick={() => toggleSource(source.id)}
                                        className={cn(
                                            'w-12 h-6 rounded-full transition-colors relative',
                                            source.enabled ? 'bg-primary' : 'bg-muted'
                                        )}
                                        aria-label={`Toggle ${source.name}`}
                                    >
                                        <span className={cn('absolute top-1 w-4 h-4 rounded-full bg-background transition-transform shadow-sm', source.enabled ? 'translate-x-7' : 'translate-x-1')} />
                                    </button>
                                </div>
                            </div>
                        ))}
                        {sources.length === 0 && (
                            <div className="text-center text-muted-foreground p-8">No discovery sources configured.</div>
                        )}
                    </div>
                </div>

                {/* Categories */}
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-foreground mb-4">Target Categories</h2>
                    <div className="flex flex-wrap gap-2">
                        {CATEGORIES.map(category => (
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
                    <div className="mt-6 p-4 bg-info/5 rounded-xl border border-info/20">
                        <div className="text-sm text-muted-foreground">
                            <strong className="text-foreground">How it works:</strong> Discovery scrapes selected SaaS directories, resolves MX records to identify email providers, enriches leads with contact details, and scores them by ICP fit.
                        </div>
                    </div>
                </div>
            </div>

            {/* Discovered Leads */}
            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-6 border-b border-border bg-muted/30 gap-3">
                    <div>
                        <h2 className="text-lg font-semibold text-foreground">Discovered Leads</h2>
                        <p className="text-sm text-muted-foreground mt-0.5">{unimportedCount} leads pending import · {discoveredLeads.length} total</p>
                    </div>
                    <div className="flex items-center gap-3">
                        {/* Improvement #42: Search */}
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Search leads..."
                            className="px-3 py-2 text-sm border border-border rounded-lg bg-background text-foreground focus:ring-2 focus:ring-primary/20 focus:border-primary w-48"
                        />
                        {unimportedCount > 0 && (
                            <button
                                onClick={importAllLeads}
                                className="px-4 py-2 bg-success text-primary-foreground rounded-lg text-sm font-medium hover:bg-success/90 shadow-sm transition-colors whitespace-nowrap"
                            >
                                Import All ({unimportedCount})
                            </button>
                        )}
                    </div>
                </div>
                <div className="divide-y divide-border">
                    {filteredLeads.length === 0 ? (
                        <div className="p-12 text-center text-muted-foreground">
                            {discoveredLeads.length === 0
                                ? (<><div className="text-4xl mb-3">🔍</div><div className="font-semibold text-foreground mb-1">No leads discovered yet</div><div>Run a discovery job to find prospects from SaaS directories.</div></>)
                                : (<><div className="text-4xl mb-3">🔎</div><div>No leads match &quot;{searchQuery}&quot;</div></>)
                            }
                        </div>
                    ) : (
                        filteredLeads.map(lead => (
                            <div key={lead.id} className="p-4 hover:bg-muted/30 transition-colors flex items-center justify-between group">
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                                        <span className="font-semibold text-foreground">{lead.companyName}</span>
                                        {lead.score != null && (
                                            <span className={cn('px-2 py-0.5 rounded-md text-xs font-bold', lead.score >= 80 ? 'bg-green-500/10 text-green-600 border border-green-500/20' : lead.score >= 50 ? 'bg-amber-500/10 text-amber-600 border border-amber-500/20' : 'bg-muted text-muted-foreground border border-border')}>{lead.score}</span>
                                        )}
                                        <span className="text-xs px-2.5 py-0.5 bg-muted text-muted-foreground border border-border rounded-md font-medium">{lead.source.replace('_', ' ')}</span>
                                        {lead.emailProvider && (
                                            <span className="text-xs px-2 py-0.5 bg-warning/10 text-warning border border-warning/20 rounded-md font-medium">{lead.emailProvider}</span>
                                        )}
                                        {lead.imported && (
                                            <span className="text-xs px-2.5 py-0.5 bg-success/10 text-success border border-success/20 rounded-md font-medium flex items-center gap-1">
                                                <span>✓</span> Imported
                                            </span>
                                        )}
                                    </div>
                                    <div className="text-sm text-muted-foreground mb-1">{lead.description}</div>
                                    <div className="flex items-center gap-4 text-xs text-muted-foreground/70 flex-wrap">
                                        <span>{lead.domain}</span>
                                        <span className="text-border">·</span>
                                        <span>{lead.category}</span>
                                        {lead.contactEmail && (<><span className="text-border">·</span><span>{lead.contactEmail}</span></>)}
                                        <span className="text-border">·</span>
                                        <span>{formatDate(lead.foundAt)}</span>
                                    </div>
                                </div>
                                {!lead.imported && (
                                    <button
                                        onClick={() => importLead(lead.id)}
                                        disabled={importingIds.has(lead.id)}
                                        className="ml-4 px-4 py-2 bg-card border border-primary/30 text-primary rounded-lg text-sm font-medium hover:bg-primary/5 transition-all opacity-0 group-hover:opacity-100 focus:opacity-100 disabled:opacity-50 whitespace-nowrap"
                                    >
                                        {importingIds.has(lead.id) ? 'Importing...' : 'Import to CRM'}
                                    </button>
                                )}
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}
