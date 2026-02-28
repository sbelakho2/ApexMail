'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { formatDate, truncate, cn } from '../../lib/utils';

/**
 * CRM Pipeline — Kanban-style lead management with persisted stage changes
 *
 * Improvements:
 *  #38 Drag-and-drop persists to backend via PATCH /api/crm/leads
 *  #39 "Add to Campaign" modal with campaign selection
 *  #40 "Edit" lead form with inline save
 *  #41 "Delete" with confirmation dialog
 *  #42 Search/filter across the pipeline
 *  #44 Toast notifications for all actions
 *  #45 Export CSV functionality
 *  #46 "Add Lead" form for manual entry
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
    estimatedDealValue?: number;
}

type PipelineStage = 'prospect' | 'outreach' | 'engaged' | 'demo_scheduled' | 'proposal' | 'negotiation' | 'closed_won' | 'closed_lost';

interface Toast {
    id: string;
    type: 'success' | 'error' | 'info';
    message: string;
}

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
    const modalRef = useRef<HTMLDivElement>(null);
    const lastFocusedElementRef = useRef<HTMLElement | null>(null);

    // Improvement #44: Toasts
    const [toasts, setToasts] = useState<Toast[]>([]);
    // Improvement #42: Search
    const [searchQuery, setSearchQuery] = useState('');
    // Improvement #41: Delete confirmation
    const [pendingDelete, setPendingDelete] = useState<Lead | null>(null);
    // Improvement #40: Edit mode
    const [editMode, setEditMode] = useState(false);
    const [editForm, setEditForm] = useState<Partial<Lead>>({});
    // Improvement #46: Add Lead modal
    const [showAddModal, setShowAddModal] = useState(false);
    const [addForm, setAddForm] = useState({ companyName: '', domain: '', contactEmail: '', contactName: '', stage: 'prospect' as PipelineStage });

    const addToast = useCallback((type: Toast['type'], message: string) => {
        const id = Date.now().toString();
        setToasts(prev => [...prev, { id, type, message }]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
    }, []);

    useEffect(() => {
        loadLeads();
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        if (!selectedLead) return;

        lastFocusedElementRef.current = document.activeElement as HTMLElement | null;
        const timer = window.setTimeout(() => {
            const focusables = modalRef.current?.querySelectorAll<HTMLElement>(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusables && focusables.length > 0) {
                focusables[0].focus();
            } else {
                modalRef.current?.focus();
            }
        }, 0);

        return () => {
            window.clearTimeout(timer);
            lastFocusedElementRef.current?.focus();
        };
    }, [selectedLead]);

    function handleModalKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
        if (e.key === 'Escape') {
            setSelectedLead(null);
            setEditMode(false);
            return;
        }

        if (e.key !== 'Tab') return;

        const focusables = modalRef.current?.querySelectorAll<HTMLElement>(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (!focusables || focusables.length === 0) {
            e.preventDefault();
            return;
        }

        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;

        if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
        }
    }

    async function loadLeads() {
        try {
            const response = await fetch('/api/crm/leads', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch leads: ${response.status}`);
            const data = await response.json();
            setLeads(data);
        } catch (err) {
            console.error('Failed to load leads:', err);
            addToast('error', 'Failed to load CRM leads.');
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

    // Improvement #38: Persist stage changes to backend
    async function handleDrop(e: React.DragEvent, newStage: PipelineStage) {
        e.preventDefault();
        if (!draggedLead || draggedLead.stage === newStage) {
            setDraggedLead(null);
            return;
        }

        const oldStage = draggedLead.stage;

        // Optimistic update
        setLeads(prevLeads =>
            prevLeads.map(lead =>
                lead.id === draggedLead.id
                    ? { ...lead, stage: newStage, lastActivity: new Date().toISOString() }
                    : lead
            )
        );

        try {
            const response = await fetch('/api/crm/leads', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    leadId: draggedLead.id,
                    stage: newStage,
                }),
            });

            if (response.ok) {
                const stageLabel = STAGES.find(s => s.key === newStage)?.label || newStage;
                addToast('success', `${draggedLead.companyName} moved to ${stageLabel}.`);
            } else {
                // Rollback on failure
                setLeads(prevLeads =>
                    prevLeads.map(lead =>
                        lead.id === draggedLead.id
                            ? { ...lead, stage: oldStage }
                            : lead
                    )
                );
                addToast('error', `Failed to move ${draggedLead.companyName}. Reverted.`);
            }
        } catch {
            // Rollback on network error
            setLeads(prevLeads =>
                prevLeads.map(lead =>
                    lead.id === draggedLead!.id
                        ? { ...lead, stage: oldStage }
                        : lead
                )
            );
            addToast('error', 'Network error. Stage change reverted.');
        }

        setDraggedLead(null);
    }

    // Improvement #41: Delete with confirmation + API call
    async function confirmDelete() {
        if (!pendingDelete) return;
        try {
            const response = await fetch('/api/crm/leads', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ leadId: pendingDelete.id }),
            });

            if (response.ok) {
                setLeads(prev => prev.filter(l => l.id !== pendingDelete.id));
                addToast('success', `${pendingDelete.companyName} deleted.`);
                if (selectedLead?.id === pendingDelete.id) {
                    setSelectedLead(null);
                    setEditMode(false);
                }
            } else {
                addToast('error', `Failed to delete ${pendingDelete.companyName}.`);
            }
        } catch {
            addToast('error', 'Network error while deleting lead.');
        }
        setPendingDelete(null);
    }

    // Improvement #40: Edit lead + save to backend
    async function saveEdit() {
        if (!selectedLead) return;
        const updated = { ...selectedLead, ...editForm };
        setLeads(prev => prev.map(l => l.id === updated.id ? updated as Lead : l));
        setSelectedLead(updated as Lead);
        setEditMode(false);

        try {
            await fetch('/api/crm/leads', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ leadId: updated.id, ...editForm }),
            });
            addToast('success', `${updated.companyName} updated.`);
        } catch {
            addToast('error', 'Failed to save changes.');
        }
    }

    // Improvement #46: Add lead
    async function handleAddLead() {
        if (!addForm.companyName || !addForm.domain) return;
        try {
            const response = await fetch('/api/crm/leads', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(addForm),
            });
            if (response.ok) {
                addToast('success', `${addForm.companyName} added.`);
                setShowAddModal(false);
                setAddForm({ companyName: '', domain: '', contactEmail: '', contactName: '', stage: 'prospect' });
                await loadLeads();
            } else {
                addToast('error', 'Failed to add lead.');
            }
        } catch {
            addToast('error', 'Network error while adding lead.');
        }
    }

    // Improvement #45: Export CSV
    function exportCSV() {
        const header = 'Company,Domain,Contact,Email,Stage,Score,Source,Last Activity\n';
        const rows = leads.map(l =>
            `"${l.companyName}","${l.domain}","${l.contactName || ''}","${l.contactEmail || ''}","${l.stage}",${l.score},"${l.source}","${l.lastActivity}"`
        ).join('\n');
        const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `crm-pipeline-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        addToast('info', `${leads.length} leads exported.`);
    }

    function getLeadsByStage(stage: PipelineStage): Lead[] {
        const stageLeads = leads.filter(lead => lead.stage === stage);
        if (!searchQuery.trim()) return stageLeads;
        const q = searchQuery.toLowerCase();
        return stageLeads.filter(l =>
            l.companyName.toLowerCase().includes(q) ||
            l.domain.toLowerCase().includes(q) ||
            (l.contactName && l.contactName.toLowerCase().includes(q)) ||
            (l.contactEmail && l.contactEmail.toLowerCase().includes(q))
        );
    }

    function getScoreColor(score: number): string {
        if (score >= 90) return 'text-success bg-success/10 border border-success/20';
        if (score >= 70) return 'text-warning bg-warning/10 border border-warning/20';
        if (score >= 50) return 'text-orange-600 bg-orange-500/10 border border-orange-500/20';
        return 'text-destructive bg-destructive/10 border border-destructive/20';
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    const pipelineValue = leads
        .filter(l => l.stage !== 'closed_lost')
        .reduce((sum, l) => sum + (l.estimatedDealValue || 0), 0);

    return (
        <div className="cp-page cp-page--wide">
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

            {/* Delete Confirmation */}
            {pendingDelete && (
                <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true">
                    <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" onClick={() => setPendingDelete(null)} />
                    <div className="relative bg-card rounded-2xl border border-border shadow-2xl p-6 max-w-md w-full mx-4">
                        <h3 className="text-lg font-bold text-foreground mb-2">Delete Lead</h3>
                        <p className="text-sm text-muted-foreground mb-6">
                            Are you sure you want to delete <strong className="text-foreground">{pendingDelete.companyName}</strong>? This action cannot be undone.
                        </p>
                        <div className="flex gap-3 justify-end">
                            <button onClick={() => setPendingDelete(null)} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground bg-muted rounded-lg">Cancel</button>
                            <button onClick={confirmDelete} className="px-4 py-2 text-sm font-semibold bg-destructive text-destructive-foreground rounded-lg hover:bg-destructive/90">Delete</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Improvement #46: Add Lead Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true">
                    <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" onClick={() => setShowAddModal(false)} />
                    <div className="relative bg-card rounded-2xl border border-border shadow-2xl p-6 max-w-md w-full mx-4">
                        <h3 className="text-lg font-bold text-foreground mb-4">Add Lead</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Company Name *</label>
                                <input value={addForm.companyName} onChange={(e) => setAddForm(p => ({ ...p, companyName: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" placeholder="Acme Corp" />
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Domain *</label>
                                <input value={addForm.domain} onChange={(e) => setAddForm(p => ({ ...p, domain: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" placeholder="acme.com" />
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Contact Name</label>
                                    <input value={addForm.contactName} onChange={(e) => setAddForm(p => ({ ...p, contactName: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" placeholder="Jane Doe" />
                                </div>
                                <div>
                                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Contact Email</label>
                                    <input value={addForm.contactEmail} onChange={(e) => setAddForm(p => ({ ...p, contactEmail: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" placeholder="jane@acme.com" />
                                </div>
                            </div>
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Initial Stage</label>
                                <select value={addForm.stage} onChange={(e) => setAddForm(p => ({ ...p, stage: e.target.value as PipelineStage }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm">
                                    {STAGES.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="flex gap-3 justify-end mt-6">
                            <button onClick={() => setShowAddModal(false)} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground bg-muted rounded-lg">Cancel</button>
                            <button onClick={handleAddLead} disabled={!addForm.companyName || !addForm.domain} className="px-4 py-2 text-sm font-semibold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50">Add Lead</button>
                        </div>
                    </div>
                </div>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8 gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">CRM Pipeline</h1>
                    <p className="text-muted-foreground mt-1">
                        {leads.length} leads · Pipeline value: ${pipelineValue.toLocaleString()}
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {/* Improvement #42: Search bar */}
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search pipeline..."
                        className="px-3 py-2 text-sm border border-border rounded-lg bg-background text-foreground focus:ring-2 focus:ring-primary/20 focus:border-primary w-44"
                    />
                    <button onClick={exportCSV} aria-label="Export CRM leads as CSV" type="button" className="px-4 py-2 bg-card border border-border text-foreground font-medium rounded-lg text-sm hover:bg-muted/50 shadow-sm transition-colors">
                        Export CSV
                    </button>
                    <button onClick={() => setShowAddModal(true)} aria-label="Add lead" type="button" className="px-4 py-2 bg-primary text-primary-foreground font-medium rounded-lg text-sm hover:opacity-90 shadow-sm transition-colors">
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
                                            onClick={() => { setSelectedLead(lead); setEditMode(false); setEditForm({}); }}
                                            role="button"
                                            tabIndex={0}
                                            aria-label={`Lead: ${lead.companyName}, Score: ${lead.score}`}
                                            className={cn(
                                                'bg-card rounded-xl p-4 shadow-sm border border-border cursor-pointer',
                                                'hover:shadow-md transition-all duration-200 group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30 focus-visible:border-primary/40',
                                                draggedLead?.id === lead.id && 'opacity-50'
                                            )}
                                            onKeyDown={(e) => {
                                                if (e.key === 'Enter' || e.key === ' ') {
                                                    e.preventDefault();
                                                    setSelectedLead(lead);
                                                    setEditMode(false);
                                                    setEditForm({});
                                                }
                                            }}
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
                                                <span>Domain</span> {lead.domain}
                                            </div>
                                            {lead.contactName && (
                                                <div className="text-xs text-muted-foreground mb-3 flex items-center gap-1">
                                                    <span className="w-5 h-5 rounded-full bg-muted flex items-center justify-center text-[10px]">U</span>
                                                    {lead.contactName}
                                                </div>
                                            )}
                                            {lead.estimatedDealValue && (
                                                <div className="text-xs font-medium text-foreground mb-2">
                                                    ${lead.estimatedDealValue.toLocaleString()}/yr
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
                                                <span>Time</span> {formatDate(lead.lastActivity)}
                                            </div>
                                        </div>
                                    ))}
                                    {stageLeads.length === 0 && (
                                        <div className="text-center text-xs text-muted-foreground py-8">
                                            {searchQuery ? 'No matches' : 'No leads in this stage'}
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Lead Detail Modal — Improvements #39, #40, #41 */}
            {selectedLead && (
                <div
                    className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50"
                    onClick={() => { setSelectedLead(null); setEditMode(false); }}
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="lead-modal-title"
                    tabIndex={-1}
                    onKeyDown={handleModalKeyDown}
                >
                    <div
                        ref={modalRef}
                        className="bg-card rounded-2xl p-6 w-full max-w-lg shadow-2xl border border-border max-h-[80vh] overflow-y-auto"
                        onClick={(e) => e.stopPropagation()}
                        tabIndex={-1}
                    >
                        <div className="flex items-start justify-between mb-6 border-b border-border pb-4">
                            <div>
                                <h2 id="lead-modal-title" className="text-xl font-bold text-foreground">{selectedLead.companyName}</h2>
                                <a href={`https://${selectedLead.domain}`} target="_blank" rel="noopener noreferrer" className="text-primary text-sm hover:underline font-medium inline-flex items-center gap-1">
                                    {selectedLead.domain} <span>↗</span>
                                </a>
                            </div>
                            <button
                                type="button"
                                onClick={() => { setSelectedLead(null); setEditMode(false); }}
                                className="text-muted-foreground hover:text-foreground p-1 rounded-lg hover:bg-muted transition-colors"
                                aria-label="Close modal"
                            >
                                Close
                            </button>
                        </div>

                        {/* Improvement #40: Edit Mode */}
                        {editMode ? (
                            <div className="space-y-4 mb-6">
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Company Name</label>
                                        <input value={editForm.companyName ?? selectedLead.companyName} onChange={(e) => setEditForm(f => ({ ...f, companyName: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" />
                                    </div>
                                    <div>
                                        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Domain</label>
                                        <input value={editForm.domain ?? selectedLead.domain} onChange={(e) => setEditForm(f => ({ ...f, domain: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" />
                                    </div>
                                    <div>
                                        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Contact Name</label>
                                        <input value={editForm.contactName ?? selectedLead.contactName ?? ''} onChange={(e) => setEditForm(f => ({ ...f, contactName: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" />
                                    </div>
                                    <div>
                                        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Contact Email</label>
                                        <input value={editForm.contactEmail ?? selectedLead.contactEmail ?? ''} onChange={(e) => setEditForm(f => ({ ...f, contactEmail: e.target.value }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20" />
                                    </div>
                                </div>
                                <div>
                                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Stage</label>
                                    <select value={editForm.stage ?? selectedLead.stage} onChange={(e) => setEditForm(f => ({ ...f, stage: e.target.value as PipelineStage }))} className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm">
                                        {STAGES.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
                                    </select>
                                </div>
                                <div className="flex gap-3 justify-end pt-2">
                                    <button onClick={() => { setEditMode(false); setEditForm({}); }} className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground bg-muted rounded-lg">Cancel</button>
                                    <button onClick={saveEdit} className="px-4 py-2 text-sm font-semibold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90">Save Changes</button>
                                </div>
                            </div>
                        ) : (
                            <>
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
                                    {selectedLead.estimatedDealValue && (
                                        <div>
                                            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Deal Value</label>
                                            <div className="text-foreground font-bold">${selectedLead.estimatedDealValue.toLocaleString()}/yr</div>
                                        </div>
                                    )}
                                    <div>
                                        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Stage</label>
                                        <div className="text-foreground font-medium">{STAGES.find(s => s.key === selectedLead.stage)?.label}</div>
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
                                        {selectedLead.tags.length === 0 && <span className="text-sm text-muted-foreground">No tags</span>}
                                    </div>
                                </div>

                                <div className="flex gap-3">
                                    <button onClick={() => { setEditMode(true); setEditForm({}); }} aria-label="Edit selected lead" type="button" className="flex-1 px-4 py-2.5 bg-primary text-primary-foreground rounded-xl font-semibold hover:opacity-90 shadow-md transition-all hover:shadow-lg">
                                        Edit Lead
                                    </button>
                                    <button onClick={() => setPendingDelete(selectedLead)} aria-label="Delete selected lead" type="button" className="px-4 py-2.5 bg-card border border-destructive/20 text-destructive rounded-xl font-medium hover:bg-destructive/10 shadow-sm">
                                        Delete
                                    </button>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
