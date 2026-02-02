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
    { key: 'prospect', label: 'Prospects', color: 'bg-gray-100 border-gray-300' },
    { key: 'outreach', label: 'Outreach', color: 'bg-blue-50 border-blue-300' },
    { key: 'engaged', label: 'Engaged', color: 'bg-yellow-50 border-yellow-300' },
    { key: 'demo_scheduled', label: 'Demo Scheduled', color: 'bg-purple-50 border-purple-300' },
    { key: 'proposal', label: 'Proposal', color: 'bg-indigo-50 border-indigo-300' },
    { key: 'negotiation', label: 'Negotiation', color: 'bg-orange-50 border-orange-300' },
    { key: 'closed_won', label: 'Closed Won', color: 'bg-green-50 border-green-300' },
    { key: 'closed_lost', label: 'Lost', color: 'bg-red-50 border-red-300' },
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
        if (score >= 90) return 'text-green-600 bg-green-50';
        if (score >= 70) return 'text-yellow-600 bg-yellow-50';
        if (score >= 50) return 'text-orange-600 bg-orange-50';
        return 'text-red-600 bg-red-50';
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-full">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">CRM Pipeline</h1>
                    <p className="text-gray-600 mt-1">
                        Manage your sales pipeline • {leads.length} total leads
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
                        Export CSV
                    </button>
                    <button className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">
                        + Add Lead
                    </button>
                </div>
            </div>

            {/* Pipeline Kanban */}
            <div className="overflow-x-auto pb-4">
                <div className="flex gap-4 min-w-max">
                    {STAGES.map(stage => {
                        const stageLeads = getLeadsByStage(stage.key);
                        return (
                            <div
                                key={stage.key}
                                className={cn(
                                    'w-72 rounded-xl border-2 p-4 min-h-[600px]',
                                    stage.color
                                )}
                                onDragOver={handleDragOver}
                                onDrop={(e) => handleDrop(e, stage.key)}
                            >
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="font-semibold text-gray-700">{stage.label}</h3>
                                    <span className="px-2 py-0.5 bg-white rounded-full text-xs font-medium text-gray-600">
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
                                            className={cn(
                                                'bg-white rounded-lg p-4 shadow-sm border border-gray-100 cursor-pointer',
                                                'hover:shadow-md transition-shadow',
                                                draggedLead?.id === lead.id && 'opacity-50'
                                            )}
                                        >
                                            <div className="flex items-start justify-between mb-2">
                                                <div className="font-medium text-gray-900 text-sm">
                                                    {truncate(lead.companyName, 20)}
                                                </div>
                                                <span className={cn('px-1.5 py-0.5 rounded text-xs font-medium', getScoreColor(lead.score))}>
                                                    {lead.score}
                                                </span>
                                            </div>
                                            <div className="text-xs text-gray-500 mb-2">{lead.domain}</div>
                                            {lead.contactName && (
                                                <div className="text-xs text-gray-600 mb-2">
                                                    👤 {lead.contactName}
                                                </div>
                                            )}
                                            <div className="flex flex-wrap gap-1 mb-2">
                                                {lead.tags.slice(0, 2).map(tag => (
                                                    <span key={tag} className="px-1.5 py-0.5 bg-gray-100 rounded text-xs text-gray-600">
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>
                                            <div className="text-xs text-gray-400">
                                                {formatDate(lead.lastActivity)}
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
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedLead(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-lg shadow-xl" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-gray-900">{selectedLead.companyName}</h2>
                                <a href={`https://${selectedLead.domain}`} target="_blank" rel="noopener noreferrer" className="text-indigo-600 text-sm hover:underline">
                                    {selectedLead.domain} ↗
                                </a>
                            </div>
                            <button onClick={() => setSelectedLead(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-6">
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Lead Score</label>
                                <div className={cn('text-lg font-bold', getScoreColor(selectedLead.score).split(' ')[0])}>
                                    {selectedLead.score}/100
                                </div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Source</label>
                                <div className="text-gray-900">{selectedLead.source}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Contact</label>
                                <div className="text-gray-900">{selectedLead.contactName || 'Unknown'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Email</label>
                                <div className="text-gray-900">{selectedLead.contactEmail || 'Not found'}</div>
                            </div>
                        </div>

                        <div className="mb-6">
                            <label className="text-xs text-gray-500 uppercase mb-2 block">Tags</label>
                            <div className="flex flex-wrap gap-2">
                                {selectedLead.tags.map(tag => (
                                    <span key={tag} className="px-2 py-1 bg-indigo-50 text-indigo-700 rounded text-sm">
                                        {tag}
                                    </span>
                                ))}
                            </div>
                        </div>

                        <div className="flex gap-2">
                            <button className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                                Add to Campaign
                            </button>
                            <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200">
                                Edit
                            </button>
                            <button className="px-4 py-2 bg-red-50 text-red-600 rounded-lg hover:bg-red-100">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
