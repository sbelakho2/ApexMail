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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    const unimportedCount = discoveredLeads.filter(l => !l.imported).length;

    return (
        <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Lead Discovery</h1>
                    <p className="text-gray-600 mt-1">
                        Automatically discover potential customers from multiple sources
                    </p>
                </div>
                <button
                    onClick={runDiscovery}
                    disabled={isRunning || sources.filter(s => s.enabled).length === 0}
                    className={cn(
                        'px-6 py-2 rounded-lg font-medium transition-colors',
                        isRunning || sources.filter(s => s.enabled).length === 0
                            ? 'bg-gray-200 text-gray-500 cursor-not-allowed'
                            : 'bg-indigo-600 text-white hover:bg-indigo-700'
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
                <div className="bg-white rounded-xl border border-gray-200 p-6">
                    <h2 className="text-lg font-semibold mb-4">Discovery Sources</h2>
                    <div className="space-y-3">
                        {sources.map(source => (
                            <div
                                key={source.id}
                                className={cn(
                                    'flex items-center justify-between p-3 rounded-lg border',
                                    source.enabled ? 'border-indigo-200 bg-indigo-50' : 'border-gray-200 bg-gray-50'
                                )}
                            >
                                <div className="flex items-center gap-3">
                                    <span className="text-2xl">{source.icon}</span>
                                    <div>
                                        <div className="font-medium text-gray-900">{source.name}</div>
                                        <div className="text-xs text-gray-500">
                                            {source.lastRun ? `Last run: ${new Date(source.lastRun).toLocaleString()}` : 'Never run'}
                                            {source.leadsFound > 0 && ` • ${source.leadsFound} leads found`}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {source.status === 'running' && (
                                        <span className="text-indigo-600 animate-pulse text-sm">Running...</span>
                                    )}
                                    <button
                                        onClick={() => toggleSource(source.id)}
                                        className={cn(
                                            'w-12 h-6 rounded-full transition-colors relative',
                                            source.enabled ? 'bg-indigo-600' : 'bg-gray-300'
                                        )}
                                    >
                                        <span
                                            className={cn(
                                                'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform',
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
                <div className="bg-white rounded-xl border border-gray-200 p-6">
                    <h2 className="text-lg font-semibold mb-4">Target Categories</h2>
                    <div className="flex flex-wrap gap-2">
                        {CATEGORIES.map(category => (
                            <button
                                key={category}
                                onClick={() => toggleCategory(category)}
                                className={cn(
                                    'px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
                                    selectedCategories.includes(category)
                                        ? 'bg-indigo-600 text-white'
                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                )}
                            >
                                {category}
                            </button>
                        ))}
                    </div>
                    <div className="mt-4 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                        <div className="text-sm text-yellow-800">
                            💡 <strong>Tip:</strong> Select categories related to email marketing to find prospects who may benefit from ApexMail.
                        </div>
                    </div>
                </div>
            </div>

            {/* Discovered Leads */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="flex items-center justify-between p-6 border-b border-gray-200">
                    <div>
                        <h2 className="text-lg font-semibold">Discovered Leads</h2>
                        <p className="text-sm text-gray-500">{unimportedCount} leads pending import</p>
                    </div>
                    {unimportedCount > 0 && (
                        <button
                            onClick={importAllLeads}
                            className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm hover:bg-green-700"
                        >
                            Import All ({unimportedCount})
                        </button>
                    )}
                </div>
                <div className="divide-y divide-gray-100">
                    {discoveredLeads.length === 0 ? (
                        <div className="p-8 text-center text-gray-500">
                            No leads discovered yet. Run a discovery job to find prospects.
                        </div>
                    ) : (
                        discoveredLeads.map(lead => (
                            <div key={lead.id} className="p-4 hover:bg-gray-50 flex items-center justify-between">
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className="font-medium text-gray-900">{lead.companyName}</span>
                                        <span className="text-xs px-2 py-0.5 bg-gray-100 rounded text-gray-600">{lead.source}</span>
                                        {lead.imported && (
                                            <span className="text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded">Imported</span>
                                        )}
                                    </div>
                                    <div className="text-sm text-gray-600 mb-1">{lead.description}</div>
                                    <div className="flex items-center gap-4 text-xs text-gray-500">
                                        <span>🌐 {lead.domain}</span>
                                        <span>📁 {lead.category}</span>
                                        <span>⏰ {new Date(lead.foundAt).toLocaleString()}</span>
                                    </div>
                                </div>
                                {!lead.imported && (
                                    <button
                                        onClick={() => importLead(lead.id)}
                                        className="ml-4 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700"
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
