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
    { key: 'prospect', label: 'Prospects', color: 'bg-muted/50 border-border' },
    { key: 'outreach', label: 'Outreach', color: 'bg-primary/5 border-primary/20' },
    { key: 'engaged', label: 'Engaged', color: 'bg-warning/5 border-warning/20' },
    { key: 'demo_scheduled', label: 'Demo Scheduled', color: 'bg-accent/5 border-accent/20' },
    { key: 'proposal', label: 'Proposal', color: 'bg-secondary/10 border-secondary/20' },
    { key: 'negotiation', label: 'Negotiation', color: 'bg-warning/10 border-warning/30' },
    { key: 'closed_won', label: 'Closed Won', color: 'bg-success/5 border-success/20' },
    { key: 'closed_lost', label: 'Lost', color: 'bg-destructive/5 border-destructive/20' },
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
            const response = await fetch('/api/crm/leads', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch leads: ${response.status}`);
            const data = await response.json();
            setLeads(data);
        } catch (err) {
            console.error('Failed to load leads:', err);
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
        if (score >= 90) return 'text-success bg-success/10 border border-success/20';
        if (score >= 70) return 'text-warning bg-warning/10 border border-warning/20';
        if (score >= 50) return 'text-orange-600 bg-orange-500/10 border border-orange-500/20'; // Using orange as warning-variant
        return 'text-destructive bg-destructive/10 border border-destructive/20';
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-full">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">CRM Pipeline</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage your sales pipeline • {leads.length} total leads
                    </p>
                </div>
                <div className="flex gap-3">
                    <button className="px-4 py-2 bg-card border border-border text-foreground font-medium rounded-lg text-sm hover:bg-muted/50 shadow-sm transition-colors">
                        Export CSV
                    </button>
                    <button className="px-4 py-2 bg-primary text-primary-foreground font-medium rounded-lg text-sm hover:opacity-90 shadow-sm transition-colors">
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
                                    <h3 className="font-semibold text-foreground">{stage.label}</h3>
                                    <span className="px-2.5 py-0.5 bg-background/60 rounded-full text-xs font-bold text-muted-foreground shadow-sm border border-border">
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
                                                'bg-card rounded-xl p-4 shadow-sm border border-border cursor-pointer',
                                                'hover:shadow-md transition-all duration-200 group',
                                                draggedLead?.id === lead.id && 'opacity-50'
                                            )}
                                        >
                                            <div className="flex items-start justify-between mb-2">
                                                <div className="font-semibold text-foreground text-sm line-clamp-1 group-hover:text-primary transition-colors">
                                                    {truncate(lead.companyName, 20)}
                                                </div>
                                                <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold', getScoreColor(lead.score))}>
                                                    {lead.score}
                                                </span>
                                            </div>
                                            <div className="text-xs text-muted-foreground mb-3 flex items-center gap-1">
                                                <span>🌐</span> {lead.domain}
                                            </div>
                                            {lead.contactName && (
                                                <div className="text-xs text-muted-foreground mb-3 flex items-center gap-1">
                                                    <span className="w-5 h-5 rounded-full bg-muted flex items-center justify-center text-[10px]">👤</span>
                                                    {lead.contactName}
                                                </div>
                                            )}
                                            <div className="flex flex-wrap gap-1.5 mb-3">
                                                {lead.tags.slice(0, 2).map(tag => (
                                                    <span key={tag} className="px-2.5 py-0.5 bg-muted border border-border rounded text-[10px] text-muted-foreground font-medium">
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>
                                            <div className="text-[10px] text-muted-foreground flex items-center gap-1 border-t border-border pt-2 mt-2">
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
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedLead(null)} role="dialog" aria-modal="true" aria-labelledby="lead-modal-title">
                    <div className="bg-card rounded-2xl p-6 w-full max-w-lg shadow-2xl border border-border" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6 border-b border-border pb-4">
                            <div>
                                <h2 id="lead-modal-title" className="text-xl font-bold text-foreground">{selectedLead.companyName}</h2>
                                <a href={`https://${selectedLead.domain}`} target="_blank" rel="noopener noreferrer" className="text-primary text-sm hover:underline font-medium inline-flex items-center gap-1">
                                    {selectedLead.domain} <span>↗</span>
                                </a>
                            </div>
                            <button 
                                onClick={() => setSelectedLead(null)} 
                                className="text-muted-foreground hover:text-foreground p-1 rounded-lg hover:bg-muted transition-colors"
                                aria-label="Close modal"
                            >
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Lead Score</label>
                                <div className={cn('text-lg font-bold inline-block px-2.5 py-0.5 rounded', getScoreColor(selectedLead.score))}>
                                    {selectedLead.score}/100
                                </div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Source</label>
                                <div className="text-foreground font-medium">{selectedLead.source}</div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Contact</label>
                                <div className="text-foreground font-medium">{selectedLead.contactName || 'Unknown'}</div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Email</label>
                                <div className="text-foreground font-medium">{selectedLead.contactEmail || 'Not found'}</div>
                            </div>
                        </div>

                        <div className="mb-8">
                            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 block">Tags</label>
                            <div className="flex flex-wrap gap-2">
                                {selectedLead.tags.map(tag => (
                                    <span key={tag} className="px-2.5 py-1 bg-primary/10 text-primary border border-primary/20 rounded-md text-sm font-medium">
                                        {tag}
                                    </span>
                                ))}
                            </div>
                        </div>

                        <div className="flex gap-3">
                            <button className="flex-1 px-4 py-2.5 bg-primary text-primary-foreground rounded-xl font-semibold hover:opacity-90 shadow-md transition-all hover:shadow-lg">
                                Add to Campaign
                            </button>
                            <button className="px-4 py-2.5 bg-card border border-border text-foreground rounded-xl font-medium hover:bg-muted shadow-sm">
                                Edit
                            </button>
                            <button className="px-4 py-2.5 bg-card border border-destructive/20 text-destructive rounded-xl font-medium hover:bg-destructive/10 shadow-sm">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
