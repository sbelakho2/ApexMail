'use client';

import { useState, useEffect } from 'react';
import { formatDate, truncate, cn } from '../../lib/utils';

/**
 * CRM Pipeline - Kanban-style lead management
 * 
 * The owner can:
 * - View leads in pipeline stages
 * - Drag and drop leads between stages
 * - Update lead details
 * - Assign leads to campaigns
 */

interface Lead {
    id: string;
    companyName: string;
    domain: string;
    contactEmail: string | null;
    contactName: string | null;
    stage: PipelineStage;
    score: number;
    source: string;
    lastActivity: string;
    createdAt: string;
    tags: string[];
}

type PipelineStage = 'prospect' | 'outreach' | 'engaged' | 'demo_scheduled' | 'proposal' | 'negotiation' | 'closed_won' | 'closed_lost';

const STAGES: { key: PipelineStage; label: string; color: string }[] = [
    { key: 'prospect', label: 'Prospects', color: 'bg-surface-50 border-surface-200' },
    { key: 'outreach', label: 'Outreach', color: 'bg-blue-50 border-blue-200' },
    { key: 'engaged', label: 'Engaged', color: 'bg-amber-50 border-amber-200' },
    { key: 'demo_scheduled', label: 'Demo Scheduled', color: 'bg-violet-50 border-violet-200' },
    { key: 'proposal', label: 'Proposal', color: 'bg-sky-50 border-sky-200' },
    { key: 'negotiation', label: 'Negotiation', color: 'bg-orange-50 border-orange-200' },
    { key: 'closed_won', label: 'Closed Won', color: 'bg-emerald-50 border-emerald-200' },
    { key: 'closed_lost', label: 'Lost', color: 'bg-red-50 border-red-200' },
];

export default function CRMPipelinePage() {
    const [leads, setLeads] = useState<Lead[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedLead, setSelectedLead] = useState<Lead | null>(null);
    const [draggedLead, setDraggedLead] = useState<Lead | null>(null);

    useEffect(() => {
        loadLeads();
    }, []);

    async function loadLeads() {
        try {
            // In production: fetch from Sales Autopilot API
            // const response = await fetch('/api/v1/pipeline/apexmail');
            // const data = await response.json();
            
            // Demo data showing realistic leads
            setLeads([
                { id: '1', companyName: 'TechCorp Inc', domain: 'techcorp.io', contactEmail: 'ceo@techcorp.io', contactName: 'John Smith', stage: 'prospect', score: 85, source: 'Product Hunt', lastActivity: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 3).toISOString(), tags: ['SaaS', 'Series A'] },
                { id: '2', companyName: 'StartupXYZ', domain: 'startupxyz.com', contactEmail: 'founder@startupxyz.com', contactName: 'Jane Doe', stage: 'outreach', score: 72, source: 'G2', lastActivity: new Date(Date.now() - 7200000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 5).toISOString(), tags: ['MarTech'] },
                { id: '3', companyName: 'GrowthCo', domain: 'growthco.io', contactEmail: 'sales@growthco.io', contactName: 'Mike Johnson', stage: 'engaged', score: 91, source: 'Capterra', lastActivity: new Date(Date.now() - 1800000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 7).toISOString(), tags: ['Enterprise', 'High Value'] },
                { id: '4', companyName: 'DataDriven Ltd', domain: 'datadriven.co', contactEmail: 'cto@datadriven.co', contactName: 'Sarah Williams', stage: 'demo_scheduled', score: 88, source: 'Crunchbase', lastActivity: new Date(Date.now() - 900000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 10).toISOString(), tags: ['Data', 'Analytics'] },
                { id: '5', companyName: 'CloudFirst', domain: 'cloudfirst.dev', contactEmail: 'hello@cloudfirst.dev', contactName: 'Alex Chen', stage: 'proposal', score: 94, source: 'G2', lastActivity: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 14).toISOString(), tags: ['Cloud', 'DevOps'] },
                { id: '6', companyName: 'ScaleUp Hub', domain: 'scaleup.io', contactEmail: null, contactName: null, stage: 'prospect', score: 65, source: 'Product Hunt', lastActivity: new Date(Date.now() - 86400000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 2).toISOString(), tags: ['SMB'] },
                { id: '7', companyName: 'MailPro Systems', domain: 'mailpro.net', contactEmail: 'team@mailpro.net', contactName: 'Lisa Brown', stage: 'negotiation', score: 96, source: 'Referral', lastActivity: new Date(Date.now() - 1800000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 20).toISOString(), tags: ['Enterprise', 'Priority'] },
                { id: '8', companyName: 'FastGrow Inc', domain: 'fastgrow.com', contactEmail: 'sales@fastgrow.com', contactName: 'Tom Harris', stage: 'closed_won', score: 98, source: 'Demo Request', lastActivity: new Date(Date.now() - 86400000 * 2).toISOString(), createdAt: new Date(Date.now() - 86400000 * 30).toISOString(), tags: ['Converted'] },
                { id: '9', companyName: 'OldSchool Ltd', domain: 'oldschool.biz', contactEmail: 'info@oldschool.biz', contactName: 'Bob Wilson', stage: 'closed_lost', score: 45, source: 'Cold Outreach', lastActivity: new Date(Date.now() - 86400000 * 5).toISOString(), createdAt: new Date(Date.now() - 86400000 * 25).toISOString(), tags: ['Lost - Pricing'] },
            ]);
        } finally {
            setLoading(false);
        }
    }

    function handleDragStart(e: React.DragEvent, lead: Lead) {
        setDraggedLead(lead);
        e.dataTransfer.effectAllowed = 'move';
    }

    function handleDragOver(e: React.DragEvent) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
    }

    function handleDrop(e: React.DragEvent, newStage: PipelineStage) {
        e.preventDefault();
        if (!draggedLead) return;

        setLeads(prevLeads =>
            prevLeads.map(lead =>
                lead.id === draggedLead.id
                    ? { ...lead, stage: newStage, lastActivity: new Date().toISOString() }
                    : lead
            )
        );
        setDraggedLead(null);
    }

    function getLeadsByStage(stage: PipelineStage): Lead[] {
        return leads.filter(lead => lead.stage === stage);
    }

    function getScoreColor(score: number): string {
        if (score >= 90) return 'text-emerald-700 bg-emerald-50 border border-emerald-100';
        if (score >= 70) return 'text-amber-700 bg-amber-50 border border-amber-100';
        if (score >= 50) return 'text-orange-700 bg-orange-50 border border-orange-100';
        return 'text-red-700 bg-red-50 border border-red-100';
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-full">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">CRM Pipeline</h1>
                    <p className="text-surface-500 mt-1">
                        Manage your sales pipeline • {leads.length} total leads
                    </p>
                </div>
                <div className="flex gap-3">
                    <button className="px-4 py-2 bg-white border border-surface-200 text-surface-700 font-medium rounded-lg text-sm hover:bg-surface-50 shadow-sm transition-colors">
                        Export CSV
                    </button>
                    <button className="px-4 py-2 bg-blue-600 text-white font-medium rounded-lg text-sm hover:bg-blue-700 shadow-sm transition-colors">
                        + Add Lead
                    </button>
                </div>
            </div>

            {/* Pipeline Kanban */}
            <div className="overflow-x-auto pb-6">
                <div className="flex gap-6 min-w-max px-1">
                    {STAGES.map(stage => {
                        const stageLeads = getLeadsByStage(stage.key);
                        return (
                            <div
                                key={stage.key}
                                className={cn(
                                    'w-80 rounded-2xl border-2 p-4 min-h-[calc(100vh-200px)]',
                                    stage.color
                                )}
                                onDragOver={handleDragOver}
                                onDrop={(e) => handleDrop(e, stage.key)}
                            >
                                <div className="flex items-center justify-between mb-4 px-1">
                                    <h3 className="font-semibold text-surface-700">{stage.label}</h3>
                                    <span className="px-2.5 py-0.5 bg-white/60 rounded-full text-xs font-bold text-surface-600 shadow-sm border border-black/5">
                                        {stageLeads.length}
                                    </span>
                                </div>
                                <div className="space-y-3">
                                    {stageLeads.map(lead => (
                                        <div
                                            key={lead.id}
                                            draggable
                                            onDragStart={(e) => handleDragStart(e, lead)}
                                            onClick={() => setSelectedLead(lead)}
                                            role="button"
                                            tabIndex={0}
                                            aria-label={`Lead: ${lead.companyName}, Score: ${lead.score}`}
                                            className={cn(
                                                'bg-white rounded-xl p-4 shadow-sm border border-surface-100 cursor-pointer',
                                                'hover:shadow-md transition-all duration-200 group',
                                                draggedLead?.id === lead.id && 'opacity-50'
                                            )}
                                        >
                                            <div className="flex items-start justify-between mb-2">
                                                <div className="font-semibold text-surface-900 text-sm line-clamp-1 group-hover:text-blue-600 transition-colors">
                                                    {truncate(lead.companyName, 20)}
                                                </div>
                                                <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold', getScoreColor(lead.score))}>
                                                    {lead.score}
                                                </span>
                                            </div>
                                            <div className="text-xs text-surface-500 mb-3 flex items-center gap-1">
                                                <span>🌐</span> {lead.domain}
                                            </div>
                                            {lead.contactName && (
                                                <div className="text-xs text-surface-600 mb-3 flex items-center gap-1">
                                                    <span className="w-5 h-5 rounded-full bg-surface-100 flex items-center justify-center text-[10px]">👤</span>
                                                    {lead.contactName}
                                                </div>
                                            )}
                                            <div className="flex flex-wrap gap-1.5 mb-3">
                                                {lead.tags.slice(0, 2).map(tag => (
                                                    <span key={tag} className="px-2.5 py-0.5 bg-surface-50 border border-surface-200 rounded text-[10px] text-surface-600 font-medium">
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>
                                            <div className="text-[10px] text-surface-400 flex items-center gap-1 border-t border-surface-50 pt-2 mt-2">
                                                <span>🕒</span> {formatDate(lead.lastActivity)}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Lead Detail Modal */}
            {selectedLead && (
                <div className="fixed inset-0 bg-surface-900/40 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedLead(null)} role="dialog" aria-modal="true" aria-labelledby="lead-modal-title">
                    <div className="bg-white rounded-2xl p-6 w-full max-w-lg shadow-2xl border border-surface-200" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6 border-b border-surface-100 pb-4">
                            <div>
                                <h2 id="lead-modal-title" className="text-xl font-bold text-surface-900">{selectedLead.companyName}</h2>
                                <a href={`https://${selectedLead.domain}`} target="_blank" rel="noopener noreferrer" className="text-blue-600 text-sm hover:underline font-medium inline-flex items-center gap-1">
                                    {selectedLead.domain} <span>↗</span>
                                </a>
                            </div>
                            <button 
                                onClick={() => setSelectedLead(null)} 
                                className="text-surface-400 hover:text-surface-600 p-1 rounded-lg hover:bg-surface-100 transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
                            <div>
                                <label className="text-xs font-semibold text-surface-600 uppercase tracking-wider mb-1 block">Lead Score</label>
                                <div className={cn('text-lg font-bold inline-block px-2.5 py-0.5 rounded', getScoreColor(selectedLead.score))}>
                                    {selectedLead.score}/100
                                </div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-surface-600 uppercase tracking-wider mb-1 block">Source</label>
                                <div className="text-surface-900 font-medium">{selectedLead.source}</div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-surface-600 uppercase tracking-wider mb-1 block">Contact</label>
                                <div className="text-surface-900 font-medium">{selectedLead.contactName || 'Unknown'}</div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-surface-600 uppercase tracking-wider mb-1 block">Email</label>
                                <div className="text-surface-900 font-medium">{selectedLead.contactEmail || 'Not found'}</div>
                            </div>
                        </div>

                        <div className="mb-8">
                            <label className="text-xs font-semibold text-surface-600 uppercase tracking-wider mb-2 block">Tags</label>
                            <div className="flex flex-wrap gap-2">
                                {selectedLead.tags.map(tag => (
                                    <span key={tag} className="px-2.5 py-1 bg-blue-50 text-blue-700 border border-blue-100 rounded-md text-sm font-medium">
                                        {tag}
                                    </span>
                                ))}
                            </div>
                        </div>

                        <div className="flex gap-3">
                            <button className="flex-1 px-4 py-2.5 bg-blue-600 text-white rounded-xl font-semibold hover:bg-blue-700 shadow-md transition-all hover:shadow-lg">
                                Add to Campaign
                            </button>
                            <button className="px-4 py-2.5 bg-white border border-surface-200 text-surface-700 rounded-xl font-medium hover:bg-surface-50 shadow-sm">
                                Edit
                            </button>
                            <button className="px-4 py-2.5 bg-white border border-red-200 text-red-600 rounded-xl font-medium hover:bg-red-50 shadow-sm">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
