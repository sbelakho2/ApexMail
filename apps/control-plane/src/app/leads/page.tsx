'use client';

import { useState, useEffect } from 'react';
import { cn } from '../../lib/utils';

/**
 * Lead Discovery - Automated lead scraping and prospecting
 * 
 * The owner can:
 * - Run discovery jobs across multiple sources
 * - Configure scraping sources (Product Hunt, G2, Capterra, Crunchbase)
 * - View discovered leads before importing to CRM
 * - Set up automatic discovery schedules
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
}



const CATEGORIES = [
    'Email Marketing',
    'Marketing Automation',
    'CRM Software',
    'Sales Enablement',
    'Customer Success',
    'Newsletter Platforms',
    'Transactional Email',
];

export default function LeadDiscoveryPage() {
    const [sources, setSources] = useState<DiscoverySource[]>([]);
    const [discoveredLeads, setDiscoveredLeads] = useState<DiscoveredLead[]>([]);
    const [selectedCategories, setSelectedCategories] = useState<string[]>(['Email Marketing', 'Newsletter Platforms']);
    const [isRunning, setIsRunning] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadDiscoveredLeads();
    }, []);

    async function loadDiscoveredLeads() {
        try {
            const response = await fetch('/api/leads/discovery', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch leads: ${response.status}`);
            const data = await response.json();
            setSources(data.sources);
            setDiscoveredLeads(data.leads);
        } catch (err) {
            console.error('Failed to load discovered leads:', err);
        } finally {
            setLoading(false);
        }
    }

    async function runDiscovery() {
        setIsRunning(true);
        const enabledSources = sources.filter(s => s.enabled);
        
        // Update status to running
        setSources(prev => prev.map(s => 
            s.enabled ? { ...s, status: 'running' as const } : s
        ));

        // Simulate discovery process
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Update with new results
        setSources(prev => prev.map(s => 
            s.enabled ? {
                ...s,
                status: 'idle' as const,
                lastRun: new Date().toISOString(),
                leadsFound: s.leadsFound + Math.floor(Math.random() * 10) + 1
            } : s
        ));

        // Add new discovered lead
        const newLead: DiscoveredLead = {
            id: Date.now().toString(),
            companyName: 'NewlyFound Corp',
            domain: 'newlyfound.io',
            source: enabledSources[0]?.id || 'product_hunt',
            category: selectedCategories[0] || 'Email Marketing',
            description: 'Just discovered this promising prospect',
            foundAt: new Date().toISOString(),
            imported: false,
        };
        setDiscoveredLeads(prev => [newLead, ...prev]);

        setIsRunning(false);
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

    async function importLead(leadId: string) {
        setDiscoveredLeads(prev => prev.map(l => 
            l.id === leadId ? { ...l, imported: true } : l
        ));
        // In production: call Sales Autopilot API to import lead to CRM
    }

    async function importAllLeads() {
        setDiscoveredLeads(prev => prev.map(l => ({ ...l, imported: true })));
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    const unimportedCount = discoveredLeads.filter(l => !l.imported).length;

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Lead Discovery</h1>
                    <p className="text-muted-foreground mt-1">
                        Automatically discover potential customers from multiple sources
                    </p>
                </div>
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
                                            {source.lastRun ? `Last run: ${new Date(source.lastRun).toLocaleString()}` : 'Never run'}
                                            {source.leadsFound > 0 && ` • ${source.leadsFound} leads found`}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {source.status === 'running' && (
                                        <span className="text-primary animate-pulse text-xs font-medium uppercase tracking-wider">Running...</span>
                                    )}
                                    <button
                                        onClick={() => toggleSource(source.id)}
                                        className={cn(
                                            'w-12 h-6 rounded-full transition-colors relative',
                                            source.enabled ? 'bg-primary' : 'bg-muted'
                                        )}
                                    >
                                        <span
                                            className={cn(
                                                'absolute top-1 w-4 h-4 rounded-full bg-background transition-transform shadow-sm',
                                                source.enabled ? 'translate-x-7' : 'translate-x-1'
                                            )}
                                        />
                                    </button>
                                </div>
                            </div>
                        ))}
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
                    <div className="mt-6 p-4 bg-warning/10 rounded-xl border border-warning/20">
                        <div className="flex gap-3">
                            <span className="text-warning">Tip</span>
                            <div className="text-sm text-warning/90">
                                <strong>Tip:</strong> Select categories related to email marketing to find prospects who may benefit from ApexMail.
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Discovered Leads */}
            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                <div className="flex items-center justify-between p-6 border-b border-border bg-muted/30">
                    <div>
                        <h2 className="text-lg font-semibold text-foreground">Discovered Leads</h2>
                        <p className="text-sm text-muted-foreground mt-0.5">{unimportedCount} leads pending import</p>
                    </div>
                    {unimportedCount > 0 && (
                        <button
                            onClick={importAllLeads}
                            className="px-4 py-2 bg-success text-primary-foreground rounded-lg text-sm font-medium hover:bg-success/90 shadow-sm transition-colors"
                        >
                            Import All ({unimportedCount})
                        </button>
                    )}
                </div>
                <div className="divide-y divide-border">
                    {discoveredLeads.length === 0 ? (
                        <div className="p-12 text-center text-muted-foreground">
                            No leads discovered yet. Run a discovery job to find prospects.
                        </div>
                    ) : (
                        discoveredLeads.map(lead => (
                            <div key={lead.id} className="p-4 hover:bg-muted/30 transition-colors flex items-center justify-between group">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-1.5">
                                        <span className="font-semibold text-foreground">{lead.companyName}</span>
                                        <span className="text-xs px-2.5 py-0.5 bg-muted text-muted-foreground border border-border rounded-md font-medium">{lead.source.replace('_', ' ')}</span>
                                        {lead.imported && (
                                            <span className="text-xs px-2.5 py-0.5 bg-success/10 text-success border border-success/20 rounded-md font-medium flex items-center gap-1">
                                                <span>OK</span> Imported
                                            </span>
                                        )}
                                    </div>
                                    <div className="text-sm text-muted-foreground mb-2">{lead.description}</div>
                                    <div className="flex items-center gap-4 text-xs text-muted-foreground/70">
                                        <span className="flex items-center gap-1"><span className="opacity-70">Domain</span> {lead.domain}</span>
                                        <span className="flex items-center gap-1"><span className="opacity-70">Category</span> {lead.category}</span>
                                        <span className="flex items-center gap-1"><span className="opacity-70">Found</span> {new Date(lead.foundAt).toLocaleString()}</span>
                                    </div>
                                </div>
                                {!lead.imported && (
                                    <button
                                        onClick={() => importLead(lead.id)}
                                        className="ml-4 px-4 py-2 bg-card border border-primary/30 text-primary rounded-lg text-sm font-medium hover:bg-primary/5 transition-all opacity-0 group-hover:opacity-100 focus:opacity-100"
                                    >
                                        Import to CRM
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
