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

const SOURCES: DiscoverySource[] = [
    { id: 'product_hunt', name: 'Product Hunt', icon: '🚀', enabled: true, lastRun: new Date(Date.now() - 3600000).toISOString(), leadsFound: 47, status: 'idle' },
    { id: 'g2', name: 'G2 Crowd', icon: '⭐', enabled: true, lastRun: new Date(Date.now() - 7200000).toISOString(), leadsFound: 89, status: 'idle' },
    { id: 'capterra', name: 'Capterra', icon: '📊', enabled: true, lastRun: new Date(Date.now() - 14400000).toISOString(), leadsFound: 63, status: 'idle' },
    { id: 'crunchbase', name: 'Crunchbase', icon: '💼', enabled: false, lastRun: null, leadsFound: 0, status: 'idle' },
];

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
    const [sources, setSources] = useState<DiscoverySource[]>(SOURCES);
    const [discoveredLeads, setDiscoveredLeads] = useState<DiscoveredLead[]>([]);
    const [selectedCategories, setSelectedCategories] = useState<string[]>(['Email Marketing', 'Newsletter Platforms']);
    const [isRunning, setIsRunning] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadDiscoveredLeads();
    }, []);

    async function loadDiscoveredLeads() {
        try {
            // Demo data
            setDiscoveredLeads([
                { id: '1', companyName: 'EmailNinja Pro', domain: 'emailninja.io', source: 'product_hunt', category: 'Email Marketing', description: 'AI-powered email scheduling for busy professionals', foundAt: new Date(Date.now() - 1800000).toISOString(), imported: false },
                { id: '2', companyName: 'NewsletterOS', domain: 'newsletteros.com', source: 'g2', category: 'Newsletter Platforms', description: 'Complete newsletter management platform', foundAt: new Date(Date.now() - 3600000).toISOString(), imported: false },
                { id: '3', companyName: 'SendMetrics', domain: 'sendmetrics.co', source: 'capterra', category: 'Email Marketing', description: 'Email analytics and reporting dashboard', foundAt: new Date(Date.now() - 7200000).toISOString(), imported: true },
                { id: '4', companyName: 'AutoMailer Hub', domain: 'automailerhub.com', source: 'product_hunt', category: 'Marketing Automation', description: 'Automated email sequences for SaaS', foundAt: new Date(Date.now() - 14400000).toISOString(), imported: false },
                { id: '5', companyName: 'ColdReach AI', domain: 'coldreach.ai', source: 'g2', category: 'Sales Enablement', description: 'AI cold email personalization', foundAt: new Date(Date.now() - 21600000).toISOString(), imported: false },
            ]);
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
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    const unimportedCount = discoveredLeads.filter(l => !l.imported).length;

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900">Lead Discovery</h1>
                    <p className="text-slate-500 mt-1">
                        Automatically discover potential customers from multiple sources
                    </p>
                </div>
                <button
                    onClick={runDiscovery}
                    disabled={isRunning || sources.filter(s => s.enabled).length === 0}
                    className={cn(
                        'px-6 py-2.5 rounded-lg font-semibold transition-all shadow-sm',
                        isRunning || sources.filter(s => s.enabled).length === 0
                            ? 'bg-slate-200 text-slate-500 cursor-not-allowed'
                            : 'bg-blue-600 text-white hover:bg-blue-700 hover:shadow-md'
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

            {/* Configuration */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Sources */}
                <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-slate-900 mb-4">Discovery Sources</h2>
                    <div className="space-y-3">
                        {sources.map(source => (
                            <div
                                key={source.id}
                                className={cn(
                                    'flex items-center justify-between p-4 rounded-xl border transition-colors',
                                    source.enabled 
                                        ? 'border-blue-200 bg-blue-50/50' 
                                        : 'border-slate-200 bg-slate-50'
                                )}
                            >
                                <div className="flex items-center gap-4">
                                    <span className="text-2xl">{source.icon}</span>
                                    <div>
                                        <div className="font-semibold text-slate-900">{source.name}</div>
                                        <div className="text-xs text-slate-500 mt-0.5">
                                            {source.lastRun ? `Last run: ${new Date(source.lastRun).toLocaleString()}` : 'Never run'}
                                            {source.leadsFound > 0 && ` • ${source.leadsFound} leads found`}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {source.status === 'running' && (
                                        <span className="text-blue-600 animate-pulse text-xs font-medium uppercase tracking-wider">Running...</span>
                                    )}
                                    <button
                                        onClick={() => toggleSource(source.id)}
                                        className={cn(
                                            'w-12 h-6 rounded-full transition-colors relative',
                                            source.enabled ? 'bg-blue-600' : 'bg-slate-300'
                                        )}
                                    >
                                        <span
                                            className={cn(
                                                'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform shadow-sm',
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
                <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-slate-900 mb-4">Target Categories</h2>
                    <div className="flex flex-wrap gap-2">
                        {CATEGORIES.map(category => (
                            <button
                                key={category}
                                onClick={() => toggleCategory(category)}
                                className={cn(
                                    'px-3.5 py-1.5 rounded-full text-sm font-medium transition-colors border',
                                    selectedCategories.includes(category)
                                        ? 'bg-blue-600 text-white border-blue-600 shadow-sm'
                                        : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50 hover:border-slate-300'
                                )}
                            >
                                {category}
                            </button>
                        ))}
                    </div>
                    <div className="mt-6 p-4 bg-amber-50 rounded-xl border border-amber-200">
                        <div className="flex gap-3">
                            <span className="text-amber-600">💡</span>
                            <div className="text-sm text-amber-800">
                                <strong>Tip:</strong> Select categories related to email marketing to find prospects who may benefit from ApexMail.
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Discovered Leads */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                <div className="flex items-center justify-between p-6 border-b border-slate-200 bg-slate-50/50">
                    <div>
                        <h2 className="text-lg font-semibold text-slate-900">Discovered Leads</h2>
                        <p className="text-sm text-slate-500 mt-0.5">{unimportedCount} leads pending import</p>
                    </div>
                    {unimportedCount > 0 && (
                        <button
                            onClick={importAllLeads}
                            className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 shadow-sm transition-colors"
                        >
                            Import All ({unimportedCount})
                        </button>
                    )}
                </div>
                <div className="divide-y divide-slate-100">
                    {discoveredLeads.length === 0 ? (
                        <div className="p-12 text-center text-slate-500">
                            No leads discovered yet. Run a discovery job to find prospects.
                        </div>
                    ) : (
                        discoveredLeads.map(lead => (
                            <div key={lead.id} className="p-4 hover:bg-slate-50 transition-colors flex items-center justify-between group">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-1.5">
                                        <span className="font-semibold text-slate-900">{lead.companyName}</span>
                                        <span className="text-xs px-2 py-0.5 bg-slate-100 text-slate-600 border border-slate-200 rounded-md font-medium">{lead.source.replace('_', ' ')}</span>
                                        {lead.imported && (
                                            <span className="text-xs px-2 py-0.5 bg-green-50 text-green-700 border border-green-200 rounded-md font-medium flex items-center gap-1">
                                                <span>✓</span> Imported
                                            </span>
                                        )}
                                    </div>
                                    <div className="text-sm text-slate-600 mb-2">{lead.description}</div>
                                    <div className="flex items-center gap-4 text-xs text-slate-400">
                                        <span className="flex items-center gap-1"><span className="opacity-70">🌐</span> {lead.domain}</span>
                                        <span className="flex items-center gap-1"><span className="opacity-70">📁</span> {lead.category}</span>
                                        <span className="flex items-center gap-1"><span className="opacity-70">⏰</span> {new Date(lead.foundAt).toLocaleString()}</span>
                                    </div>
                                </div>
                                {!lead.imported && (
                                    <button
                                        onClick={() => importLead(lead.id)}
                                        className="ml-4 px-4 py-2 bg-white border border-blue-200 text-blue-600 rounded-lg text-sm font-medium hover:bg-blue-50 transition-all opacity-0 group-hover:opacity-100 focus:opacity-100"
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
