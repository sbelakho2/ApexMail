'use client';

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { cn, formatDate } from '../../lib/utils';
import {
    COMPETITOR_PROVIDERS,
    COMPETITOR_DETAILS,
    DiscoverySource,
    DiscoveryStats,
    DiscoveredLead,
    DISCOVERY_SOURCES,
    DISCOVERY_SCHEDULES,
    DEFAULT_SCORING_WEIGHTS,
    getFilteredLeads,
    getProviderCounts,
    getScoreColor,
    getEnrichmentStatus,
    sortLeads,
    exportLeadsToCSV,
    forecastPipelineRevenue,
    OUTREACH_OFFERS,
    SALES_TABS,
    LEAD_SORT_OPTIONS,
    LEAD_STATUS_CONFIG,
    ICP_FIT_CONFIG,
    CAMPAIGN_STATUS_CONFIG,
    TabKey,
    TARGET_CATEGORIES,
    type Campaign,
    type LeadStatus,
    type ICPFitScore,
    type LeadSortConfig,
    type ScoringWeights,
    type SalesNotification,
} from './sales-config';

/**
 * Automated Sales System — Comprehensive Lead Discovery & Outreach
 *
 * Improvements implemented:
 *  #21 Toast notification system
 *  #22 Search + multi-dimensional filtering
 *  #23 Sortable leads list
 *  #24 Pagination with configurable page size
 *  #25 Lead detail slide-over panel
 *  #26 CSV export
 *  #27 Confirmation dialog before outreach
 *  #28 Discovery progress indicator with step details
 *  #29 Pipeline tab with revenue forecast
 *  #30 Settings tab with scoring weights & schedule
 *  #31 Bulk status change
 *  #32 Lead notes inline editing
 *  #33 Competitor intelligence display
 *  #34 ICP fit badges
 *  #35 Enrichment completeness indicator
 *  #36 Keyboard shortcuts (Escape to deselect, / to search)
 *  #37 Empty state illustrations per tab
 *  #38 Offer cards show sequence length + expected conversion
 *  #39 Quick-actions context menu from lead rows
 *  #40 Responsive mobile layout improvements
 */

// ── Improvement #21: Toast notification system ──

function ToastContainer({ toasts, onDismiss }: { toasts: SalesNotification[]; onDismiss: (id: string) => void }) {
    if (toasts.length === 0) return null;
    const bgMap: Record<string, string> = {
        error: 'bg-destructive text-destructive-foreground',
        discovery_complete: 'bg-success text-primary-foreground',
        outreach_sent: 'bg-primary text-primary-foreground',
        lead_discovered: 'bg-info text-primary-foreground',
    };
    return (
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 max-w-sm">
            {toasts.map(t => (
                <div key={t.id} className={cn('px-4 py-3 rounded-xl shadow-lg flex items-start gap-3 animate-in slide-in-from-right', bgMap[t.type] || 'bg-card text-foreground border border-border')}>
                    <div className="flex-1 min-w-0">
                        <div className="font-semibold text-sm">{t.title}</div>
                        <div className="text-xs opacity-90 mt-0.5">{t.message}</div>
                    </div>
                    <button onClick={() => onDismiss(t.id)} className="text-xs opacity-70 hover:opacity-100 shrink-0 mt-0.5" aria-label="Dismiss notification">Close</button>
                </div>
            ))}
        </div>
    );
}

// ── Improvement #25: Lead detail slide-over ──

function LeadDetailPanel({ lead, onClose, onUpdateNotes }: {
    lead: DiscoveredLead;
    onClose: () => void;
    onUpdateNotes: (id: string, notes: string) => void;
}) {
    const [notes, setNotes] = useState(lead.notes);
    const enrichment = getEnrichmentStatus(lead);
    const competitor = lead.emailProvider ? COMPETITOR_DETAILS[lead.emailProvider] : null;
    const statusConfig = LEAD_STATUS_CONFIG[lead.status];

    return (
        <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-label="Lead details">
            <div className="absolute inset-0 bg-background/60 backdrop-blur-sm" onClick={onClose} />
            <div className="relative w-full max-w-lg bg-card border-l border-border shadow-2xl overflow-y-auto">
                <div className="sticky top-0 bg-card border-b border-border p-4 flex items-center justify-between z-10">
                    <h2 className="text-lg font-bold text-foreground truncate">{lead.companyName}</h2>
                    <button onClick={onClose} className="p-2 hover:bg-muted rounded-lg text-muted-foreground hover:text-foreground" aria-label="Close panel">Close</button>
                </div>

                <div className="p-6 space-y-6">
                    {/* Score & Status */}
                    <div className="flex items-center gap-3 flex-wrap">
                        <span className={cn('px-3 py-1 rounded-lg text-sm font-bold border', getScoreColor(lead.score))}>Score: {lead.score}</span>
                        <span className={cn('px-3 py-1 rounded-lg text-xs font-semibold border', statusConfig?.color)}>{statusConfig?.icon} {statusConfig?.label}</span>
                        <span className={cn('px-3 py-1 rounded-lg text-xs font-semibold border', ICP_FIT_CONFIG[lead.icpFit]?.color)}>{ICP_FIT_CONFIG[lead.icpFit]?.label}</span>
                    </div>

                    {/* Contact Info */}
                    <div className="bg-muted/30 rounded-xl p-4 space-y-2 border border-border">
                        <h3 className="text-sm font-semibold text-foreground">Contact Information</h3>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                            <div><span className="text-muted-foreground">Domain:</span> <a href={`https://${lead.domain}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{lead.domain}</a></div>
                            <div><span className="text-muted-foreground">Email:</span> <span className="text-foreground">{lead.contactEmail || 'Not found'}</span></div>
                            <div><span className="text-muted-foreground">Contact:</span> <span className="text-foreground">{lead.contactName || 'Unknown'}</span></div>
                            <div><span className="text-muted-foreground">Title:</span> <span className="text-foreground">{lead.contactTitle || 'Unknown'}</span></div>
                            <div><span className="text-muted-foreground">Company Size:</span> <span className="text-foreground">{lead.companySize || 'Unknown'}</span></div>
                            <div><span className="text-muted-foreground">Deal Value:</span> <span className="text-foreground font-medium">{lead.estimatedDealValue ? `$${lead.estimatedDealValue.toLocaleString()}/yr` : 'Unestimated'}</span></div>
                        </div>
                    </div>

                    {/* Improvement #35: Enrichment completeness */}
                    <div className="bg-muted/30 rounded-xl p-4 border border-border">
                        <div className="flex items-center justify-between mb-2">
                            <h3 className="text-sm font-semibold text-foreground">Data Enrichment</h3>
                            <span className="text-xs font-bold text-muted-foreground">{enrichment.completeness}%</span>
                        </div>
                        <div className="w-full h-2 bg-muted rounded-full overflow-hidden mb-3">
                            <div className={cn('h-full rounded-full transition-all', enrichment.completeness >= 80 ? 'bg-green-500' : enrichment.completeness >= 50 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${enrichment.completeness}%` }} />
                        </div>
                        <div className="grid grid-cols-2 gap-1.5 text-xs">
                            <div className={enrichment.mxResolved ? 'text-green-600' : 'text-muted-foreground'}>
                                {enrichment.mxResolved ? '✓' : '○'} MX Records
                            </div>
                            <div className={enrichment.contactFound ? 'text-green-600' : 'text-muted-foreground'}>
                                {enrichment.contactFound ? '✓' : '○'} Contact Email
                            </div>
                            <div className={enrichment.companySizeResolved ? 'text-green-600' : 'text-muted-foreground'}>
                                {enrichment.companySizeResolved ? '✓' : '○'} Company Size
                            </div>
                            <div className={enrichment.trafficEstimated ? 'text-green-600' : 'text-muted-foreground'}>
                                {enrichment.trafficEstimated ? '✓' : '○'} Traffic Estimate
                            </div>
                            <div className={enrichment.linkedinFound ? 'text-green-600' : 'text-muted-foreground'}>
                                {enrichment.linkedinFound ? '✓' : '○'} LinkedIn Profile
                            </div>
                        </div>
                    </div>

                    {/* Improvement #33: Competitor intelligence */}
                    {competitor && lead.emailProvider && (
                        <div className="bg-warning/5 border border-warning/20 rounded-xl p-4">
                            <h3 className="text-sm font-semibold text-foreground mb-2">Competitor Intel: {lead.emailProvider}</h3>
                            <div className="text-xs text-muted-foreground space-y-1">
                                <div className="flex gap-2"><span className="text-foreground font-medium">Migration:</span> <span className={cn(competitor.migrationComplexity === 'easy' ? 'text-green-600' : competitor.migrationComplexity === 'medium' ? 'text-amber-600' : 'text-red-600')}>{competitor.migrationComplexity} ({competitor.avgMigrationDays} days avg)</span></div>
                                <div className="text-foreground font-medium mt-2">Known Weaknesses:</div>
                                {competitor.weaknesses.map((w, i) => <div key={i}>• {w}</div>)}
                            </div>
                        </div>
                    )}

                    {/* Provider / MX */}
                    <div className="text-sm space-y-2">
                        <h3 className="font-semibold text-foreground">Email Infrastructure</h3>
                        <div><span className="text-muted-foreground">Provider:</span>{' '}
                            {lead.emailProvider ? (
                                <span className={cn('px-2 py-0.5 rounded text-xs font-semibold', COMPETITOR_PROVIDERS.includes(lead.emailProvider) ? 'bg-warning/10 text-warning border border-warning/20' : 'bg-muted text-muted-foreground border border-border')}>{lead.emailProvider}</span>
                            ) : <span className="text-muted-foreground">Unknown</span>}
                        </div>
                        {lead.mxRecords.length > 0 && (
                            <div><span className="text-muted-foreground">MX Records:</span>
                                <div className="mt-1 text-xs font-mono bg-muted/50 p-2 rounded border border-border">{lead.mxRecords.join('\n')}</div>
                            </div>
                        )}
                    </div>

                    {/* Tags */}
                    <div>
                        <h3 className="text-sm font-semibold text-foreground mb-2">Tags</h3>
                        <div className="flex flex-wrap gap-1.5">
                            {lead.tags.length > 0 ? lead.tags.map(tag => (
                                <span key={tag} className="px-2.5 py-0.5 bg-primary/10 text-primary border border-primary/20 rounded-md text-xs font-medium">{tag}</span>
                            )) : <span className="text-xs text-muted-foreground">No tags</span>}
                        </div>
                    </div>

                    {/* Improvement #32: Notes editing */}
                    <div>
                        <h3 className="text-sm font-semibold text-foreground mb-2">Notes</h3>
                        <textarea
                            value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                            onBlur={() => onUpdateNotes(lead.id, notes)}
                            rows={4}
                            className="w-full px-3 py-2 text-sm bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary/20 focus:border-primary resize-none"
                            placeholder="Add notes about this lead..."
                        />
                    </div>

                    {/* Engagement Timeline */}
                    {lead.engagementHistory.length > 0 && (
                        <div>
                            <h3 className="text-sm font-semibold text-foreground mb-2">Activity Timeline</h3>
                            <div className="space-y-2">
                                {lead.engagementHistory.slice(0, 10).map((event, i) => (
                                    <div key={i} className="flex items-start gap-2 text-xs">
                                        <span className="text-muted-foreground shrink-0 w-28">{formatDate(event.timestamp)}</span>
                                        <span className="text-foreground">{event.detail}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// ── Improvement #27: Confirmation dialog ──

function ConfirmDialog({ title, message, confirmLabel, onConfirm, onCancel }: {
    title: string; message: string; confirmLabel: string;
    onConfirm: () => void; onCancel: () => void;
}) {
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true">
            <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" onClick={onCancel} />
            <div className="relative bg-card rounded-2xl border border-border shadow-2xl p-6 max-w-md w-full mx-4">
                <h3 className="text-lg font-bold text-foreground mb-2">{title}</h3>
                <p className="text-sm text-muted-foreground mb-6">{message}</p>
                <div className="flex gap-3 justify-end">
                    <button onClick={onCancel} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground bg-muted rounded-lg">Cancel</button>
                    <button onClick={onConfirm} className="px-4 py-2 text-sm font-semibold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 shadow-sm">{confirmLabel}</button>
                </div>
            </div>
        </div>
    );
}

// ── Main Component ──

export default function AutomatedSalesPage() {
    const [activeTab, setActiveTab] = useState<TabKey>('discovery');
    const [loading, setLoading] = useState(false);

    // Discovery State
    const [sources, setSources] = useState<DiscoverySource[]>(DISCOVERY_SOURCES);
    const [selectedCategories, setSelectedCategories] = useState<string[]>(['Email Marketing', 'Transactional Email', 'Newsletter Platforms']);
    const [maxPages, setMaxPages] = useState(3);
    const [isRunning, setIsRunning] = useState(false);
    const [discoveryProgress, setDiscoveryProgress] = useState<string | null>(null);

    // Leads State
    const [leads, setLeads] = useState<DiscoveredLead[]>([]);
    const [providerFilter, setProviderFilter] = useState<string | null>(null);
    const [selectedLeads, setSelectedLeads] = useState<Set<string>>(new Set());

    // Improvement #22: Search + status/ICP filters
    const [searchQuery, setSearchQuery] = useState('');
    const [statusFilter, setStatusFilter] = useState<LeadStatus | null>(null);
    const [icpFilter, setICPFilter] = useState<ICPFitScore | null>(null);
    const searchInputRef = useRef<HTMLInputElement>(null);

    // Improvement #23: Sorting
    const [sortConfig, setSortConfig] = useState<LeadSortConfig>(LEAD_SORT_OPTIONS[0]);

    // Improvement #24: Pagination
    const [currentPage, setCurrentPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    // Improvement #25: Lead detail panel
    const [selectedLeadDetail, setSelectedLeadDetail] = useState<DiscoveredLead | null>(null);

    // Stats State
    const [stats, setStats] = useState<DiscoveryStats | null>(null);

    // Improvement #21: Toasts
    const [toasts, setToasts] = useState<SalesNotification[]>([]);

    // Improvement #27: Confirmation dialog
    const [pendingOutreach, setPendingOutreach] = useState<string | null>(null);

    // Improvement #30: Settings
    const [scoringWeights, setScoringWeights] = useState<ScoringWeights>(DEFAULT_SCORING_WEIGHTS);
    const [scheduleId, setScheduleId] = useState('manual');

    // Improvement #44: Campaigns state
    const [campaigns, setCampaigns] = useState<Campaign[]>([]);
    const [campaignsLoading, setCampaignsLoading] = useState(false);

    // Improvement #47: Settings dirty tracking
    const [settingsDirty, setSettingsDirty] = useState(false);
    const [settingsSaving, setSettingsSaving] = useState(false);

    // Improvement #49: Notification preferences state
    const [notifPrefs, setNotifPrefs] = useState<Record<string, boolean>>({
        newLeadDiscovered: true,
        leadOpenedEmail: true,
        leadReplied: true,
        demoScheduled: true,
        dealClosed: true,
        discoveryComplete: false,
        weeklyPipelineSummary: false,
    });

    // ── Helpers ──

    const addToast = useCallback((type: SalesNotification['type'], title: string, message: string) => {
        const id = Date.now().toString();
        setToasts(prev => [...prev, { id, type, title, message, timestamp: new Date().toISOString(), read: false }]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
    }, []);

    const dismissToast = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    // ── Data Loading ──

    useEffect(() => { loadLeads(); loadCampaigns(); loadSettings(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

    async function loadLeads() {
        setLoading(true);
        try {
            const response = await fetch('/api/sales/leads', { credentials: 'include' });
            if (response.ok) {
                const data = await response.json();
                setLeads(data.leads || []);
                setStats(data.stats || null);
            } else {
                addToast('error', 'Load Failed', 'Could not load sales leads.');
            }
        } catch (err) {
            console.error('Failed to load leads:', err);
            addToast('error', 'Network Error', 'Failed to connect. Check your connection.');
        } finally {
            setLoading(false);
        }
    }

    // Improvement #44: Load campaigns
    async function loadCampaigns() {
        setCampaignsLoading(true);
        try {
            const response = await fetch('/api/sales/campaigns', { credentials: 'include' });
            if (response.ok) {
                const data = await response.json();
                setCampaigns(data.campaigns || []);
            }
        } catch (err) {
            console.error('Failed to load campaigns:', err);
        } finally {
            setCampaignsLoading(false);
        }
    }

    // Improvement #47: Load saved settings
    async function loadSettings() {
        try {
            const response = await fetch('/api/sales/settings', { credentials: 'include' });
            if (response.ok) {
                const data = await response.json();
                if (data.scoringWeights) setScoringWeights(data.scoringWeights);
                if (data.discoveryScheduleId) setScheduleId(data.discoveryScheduleId);
                if (data.notificationPreferences) setNotifPrefs(data.notificationPreferences);
            }
        } catch (err) {
            console.error('Failed to load settings:', err);
        }
    }

    // ── Callbacks ──

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
            next.has(leadId) ? next.delete(leadId) : next.add(leadId);
            return next;
        });
    }, []);

    const selectAllFiltered = useCallback(() => {
        const filtered = getFilteredLeads(leads, providerFilter, searchQuery, statusFilter, icpFilter);
        setSelectedLeads(new Set(filtered.map(l => l.id)));
    }, [leads, providerFilter, searchQuery, statusFilter, icpFilter]);

    const clearSelection = useCallback(() => { setSelectedLeads(new Set()); }, []);

    // Improvement #32: Notes update — persists to API
    const updateLeadNotes = useCallback(async (leadId: string, notes: string) => {
        setLeads(prev => prev.map(l => l.id === leadId ? { ...l, notes } : l));
        try {
            await fetch('/api/sales/leads/update', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ id: leadId, notes }),
            });
        } catch (err) {
            console.error('Failed to persist notes:', err);
        }
    }, []);

    // ── Improvement #28: Discovery with progress ──

    async function runDiscovery() {
        setIsRunning(true);
        setDiscoveryProgress('Preparing discovery job...');
        try {
            const enabledSources = sources.filter(s => s.enabled).map(s => s.id);

            setDiscoveryProgress(`Scraping ${enabledSources.length} sources across ${selectedCategories.length} categories...`);

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
                setDiscoveryProgress('Refreshing leads...');
                await loadLeads();
                setActiveTab('leads');
                addToast('discovery_complete', 'Discovery Complete', `Found ${result.stats?.totalScraped ?? 0} companies, ${result.stats?.totalWithMx ?? 0} with MX records.`);
            } else {
                const err = await response.json().catch(() => ({}));
                addToast('error', 'Discovery Failed', err.error || 'Unknown error occurred.');
            }
        } catch (err) {
            console.error('Discovery failed:', err);
            addToast('error', 'Discovery Error', 'Network error during discovery job.');
        } finally {
            setIsRunning(false);
            setDiscoveryProgress(null);
        }
    }

    // ── Improvement #27: Outreach with confirmation ──

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
                const result = await response.json();
                addToast('outreach_sent', 'Outreach Started', `Campaign created for ${result.leadsEnrolled ?? selectedLeads.size} leads.`);
                await loadLeads();
                clearSelection();
                setPendingOutreach(null);
            } else {
                const err = await response.json().catch(() => ({}));
                addToast('error', 'Outreach Failed', err.error || 'Failed to start campaign.');
                setPendingOutreach(null);
            }
        } catch (err) {
            console.error('Failed to start outreach:', err);
            addToast('error', 'Outreach Error', 'Network error while starting outreach.');
            setPendingOutreach(null);
        }
    }

    // Improvement #31: Bulk status change — persists to API
    async function bulkUpdateStatus(newStatus: LeadStatus) {
        // Optimistic update
        setLeads(prev => prev.map(l =>
            selectedLeads.has(l.id) ? { ...l, status: newStatus } : l
        ));
        addToast('lead_discovered', 'Status Updated', `${selectedLeads.size} leads moved to ${LEAD_STATUS_CONFIG[newStatus]?.label}.`);

        // Persist to API
        try {
            const updates = Array.from(selectedLeads).map(id => ({ id, status: newStatus }));
            await fetch('/api/sales/leads/update', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ updates }),
            });
        } catch (err) {
            console.error('Failed to persist status change:', err);
            addToast('error', 'Save Failed', 'Status changed locally but failed to save to server.');
        }
        clearSelection();
    }

    // Improvement #45: Campaign action (pause/resume/archive)
    async function handleCampaignAction(campaignId: string, action: 'pause' | 'resume' | 'archive' | 'cancel') {
        try {
            const response = await fetch('/api/sales/campaigns', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ campaignId, action }),
            });
            if (response.ok) {
                const result = await response.json();
                setCampaigns(prev => prev.map(c =>
                    c.id === campaignId ? { ...c, status: result.newStatus } : c
                ));
                addToast('outreach_sent', 'Campaign Updated', `Campaign ${action}d successfully.`);
            } else {
                addToast('error', 'Action Failed', `Could not ${action} the campaign.`);
            }
        } catch (err) {
            console.error('Campaign action failed:', err);
            addToast('error', 'Network Error', `Failed to ${action} campaign.`);
        }
    }

    // Improvement #47: Save settings
    async function saveSettings() {
        setSettingsSaving(true);
        try {
            const response = await fetch('/api/sales/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    scoringWeights,
                    discoveryScheduleId: scheduleId,
                    notificationPreferences: notifPrefs,
                    enabledSources: sources.filter(s => s.enabled).map(s => s.id),
                    maxPagesPerSource: maxPages,
                }),
            });
            if (response.ok) {
                addToast('discovery_complete', 'Settings Saved', 'Your sales settings have been saved.');
                setSettingsDirty(false);
            } else {
                addToast('error', 'Save Failed', 'Could not save settings.');
            }
        } catch (err) {
            console.error('Failed to save settings:', err);
            addToast('error', 'Network Error', 'Failed to save settings.');
        } finally {
            setSettingsSaving(false);
        }
    }

    // Improvement #50: Trigger enrichment for selected leads
    async function enrichSelectedLeads() {
        if (selectedLeads.size === 0) return;
        try {
            const response = await fetch('/api/sales/leads/enrich', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ leadIds: Array.from(selectedLeads) }),
            });
            if (response.ok) {
                const result = await response.json();
                addToast('lead_discovered', 'Enrichment Started', `Enriching ${result.enriched ?? selectedLeads.size} leads with contact data...`);
                // Refresh leads after a brief delay for enrichment to complete
                setTimeout(() => loadLeads(), 3000);
            } else {
                addToast('error', 'Enrichment Failed', 'Could not start lead enrichment.');
            }
        } catch (err) {
            console.error('Enrichment failed:', err);
            addToast('error', 'Network Error', 'Failed to contact enrichment service.');
        }
    }

    // Improvement #26: CSV export
    function handleExportCSV() {
        const filtered = getFilteredLeads(leads, providerFilter, searchQuery, statusFilter, icpFilter);
        const csv = exportLeadsToCSV(filtered);
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `apexmail-leads-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        addToast('lead_discovered', 'Export Complete', `${filtered.length} leads exported to CSV.`);
    }

    // ── Improvement #36: Keyboard shortcuts ──

    useEffect(() => {
        function handleKeyDown(e: KeyboardEvent) {
            if (e.key === 'Escape') {
                if (selectedLeadDetail) { setSelectedLeadDetail(null); return; }
                if (pendingOutreach) { setPendingOutreach(null); return; }
                if (selectedLeads.size > 0) { clearSelection(); return; }
            }
            if (e.key === '/' && !e.metaKey && !e.ctrlKey && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
                e.preventDefault();
                searchInputRef.current?.focus();
            }
        }
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [selectedLeadDetail, pendingOutreach, selectedLeads, clearSelection]);

    // ── Computed ──

    const filteredLeads = useMemo(() =>
        getFilteredLeads(leads, providerFilter, searchQuery, statusFilter, icpFilter),
        [leads, providerFilter, searchQuery, statusFilter, icpFilter]
    );

    const sortedLeads = useMemo(() => sortLeads(filteredLeads, sortConfig), [filteredLeads, sortConfig]);

    // Improvement #24: Pagination
    const totalPages = Math.max(1, Math.ceil(sortedLeads.length / pageSize));
    const paginatedLeads = useMemo(() => {
        const start = (currentPage - 1) * pageSize;
        return sortedLeads.slice(start, start + pageSize);
    }, [sortedLeads, currentPage, pageSize]);

    // Reset page when filters change
    useEffect(() => { setCurrentPage(1); }, [providerFilter, searchQuery, statusFilter, icpFilter, sortConfig]);

    const providerCounts = useMemo(() => getProviderCounts(leads), [leads]);
    const competitorLeads = useMemo(() => leads.filter(l => l.emailProvider && COMPETITOR_PROVIDERS.includes(l.emailProvider)), [leads]);
    const pipelineForecast = useMemo(() => forecastPipelineRevenue(leads), [leads]);

    if (loading && leads.length === 0) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    const enabledSourceCount = sources.filter(s => s.enabled).length;

    return (
        <div className="cp-page">
            {/* Toasts */}
            <ToastContainer toasts={toasts} onDismiss={dismissToast} />

            {/* Confirmation Dialog */}
            {pendingOutreach && (
                <ConfirmDialog
                    title="Start Outreach Campaign"
                    message={`You are about to start a "${OUTREACH_OFFERS.find(o => o.id === pendingOutreach)?.name}" campaign for ${selectedLeads.size} leads. Emails will be sent via the autopilot drip engine. Continue?`}
                    confirmLabel={`Start for ${selectedLeads.size} Leads`}
                    onConfirm={() => startOutreach(pendingOutreach)}
                    onCancel={() => setPendingOutreach(null)}
                />
            )}

            {/* Lead Detail Panel */}
            {selectedLeadDetail && (
                <LeadDetailPanel
                    lead={selectedLeadDetail}
                    onClose={() => setSelectedLeadDetail(null)}
                    onUpdateNotes={updateLeadNotes}
                />
            )}

            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8 gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Automated Sales System</h1>
                    <p className="text-muted-foreground mt-1">
                        Discover leads, identify competitor users via DNS, and run personalized outreach campaigns
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button onClick={() => loadLeads()} disabled={loading} className="px-3 py-2 text-sm border border-border rounded-lg hover:bg-muted transition-colors disabled:opacity-50">
                        {loading ? '⟳ Loading...' : '↻ Refresh'}
                    </button>
                    <button onClick={handleExportCSV} disabled={leads.length === 0} className="px-3 py-2 text-sm border border-border rounded-lg hover:bg-muted transition-colors disabled:opacity-50">
                        Export CSV
                    </button>
                </div>
            </div>

            {/* Summary Cards — Improvement #29: includes pipeline value */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Total Leads</div>
                    <div className="text-2xl font-bold text-foreground">{leads.length}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Competitor Users</div>
                    <div className="text-2xl font-bold text-primary">{competitorLeads.length}</div>
                    <div className="text-xs text-muted-foreground mt-1">{COMPETITOR_PROVIDERS.slice(0, 3).join(', ')}</div>
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
                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                    <div className="text-sm text-muted-foreground mb-1">Pipeline Value</div>
                    <div className="text-2xl font-bold text-foreground">${Math.round(pipelineForecast.weightedForecast).toLocaleString()}</div>
                    <div className="text-xs text-muted-foreground mt-1">weighted forecast</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 mb-6 bg-muted/50 p-1 rounded-xl w-fit overflow-x-auto">
                {SALES_TABS.map(tab => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={cn(
                            'px-4 py-2 rounded-lg text-sm font-medium transition-all capitalize whitespace-nowrap',
                            activeTab === tab
                                ? 'bg-card text-foreground shadow-sm'
                                : 'text-muted-foreground hover:text-foreground'
                        )}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* ═══════════════ DISCOVERY TAB ═══════════════ */}
            {activeTab === 'discovery' && (
                <div className="space-y-6">
                    {/* Discovery Sources — shows tier badges */}
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
                                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleSource(source.id); } }}
                                >
                                    <div className="flex items-center gap-4">
                                        <span className="text-2xl">{source.icon}</span>
                                        <div>
                                            <div className="font-semibold text-foreground flex items-center gap-2">
                                                {source.name}
                                                {source.tier === 'premium' && <span className="text-[10px] px-1.5 py-0.5 bg-amber-100 text-amber-700 rounded font-bold uppercase">Premium</span>}
                                            </div>
                                            <div className="text-xs text-muted-foreground">{source.description}</div>
                                            <div className="text-xs text-muted-foreground mt-0.5">~{source.avgLeadsPerRun} leads/run</div>
                                        </div>
                                    </div>
                                    <div className={cn('w-12 h-6 rounded-full transition-colors relative', source.enabled ? 'bg-primary' : 'bg-muted')}>
                                        <span className={cn('absolute top-1 w-4 h-4 rounded-full bg-background transition-transform shadow-sm', source.enabled ? 'translate-x-7' : 'translate-x-1')} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Target Categories */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">Target Categories</h2>
                        <p className="text-sm text-muted-foreground mb-4">Focus on categories where companies are likely to need email infrastructure.</p>
                        <div className="flex flex-wrap gap-2">
                            {TARGET_CATEGORIES.map(category => (
                                <button key={category} onClick={() => toggleCategory(category)} className={cn('px-3.5 py-1.5 rounded-full text-sm font-medium transition-colors border', selectedCategories.includes(category) ? 'bg-primary text-primary-foreground border-primary shadow-sm' : 'bg-card text-muted-foreground border-border hover:bg-muted hover:border-muted-foreground')}>
                                    {category}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Discovery Settings */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">Discovery Settings</h2>
                        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                            <div>
                                <label className="text-sm font-medium text-foreground block mb-2">Max pages per source</label>
                                <input type="number" min={1} max={10} value={maxPages} onChange={(e) => setMaxPages(Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))} className="w-24 px-3 py-2 rounded-lg border border-border bg-background text-foreground focus:ring-2 focus:ring-primary/20 focus:border-primary" />
                            </div>
                            <div className="flex-1" />
                            <button
                                onClick={runDiscovery}
                                disabled={isRunning || enabledSourceCount === 0 || selectedCategories.length === 0}
                                className={cn('px-8 py-3 rounded-xl font-semibold transition-all shadow-sm', isRunning || enabledSourceCount === 0 || selectedCategories.length === 0 ? 'bg-muted text-muted-foreground cursor-not-allowed' : 'bg-primary text-primary-foreground hover:bg-primary/90 hover:shadow-md')}
                            >
                                {isRunning ? (
                                    <span className="flex items-center gap-2"><span className="animate-spin">⟳</span> Running Discovery...</span>
                                ) : (
                                    `Run Discovery (${enabledSourceCount} sources)`
                                )}
                            </button>
                        </div>
                        {/* Improvement #28: Progress bar */}
                        {discoveryProgress && (
                            <div className="mt-4 p-3 bg-primary/5 border border-primary/20 rounded-lg">
                                <div className="flex items-center gap-3">
                                    <div className="animate-spin h-4 w-4 border-2 border-primary border-t-transparent rounded-full" />
                                    <span className="text-sm text-foreground">{discoveryProgress}</span>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* What happens */}
                    <div className="bg-info/5 border border-info/20 rounded-xl p-5">
                        <h3 className="font-semibold text-foreground mb-2">What happens during discovery?</h3>
                        <ul className="text-sm text-muted-foreground space-y-1">
                            <li>• Scrapes selected SaaS directories for companies in target categories</li>
                            <li>• Resolves MX records to identify email providers (SendGrid, Mailgun, Resend, etc.)</li>
                            <li>• Enriches leads with contact info, company size, and traffic estimates</li>
                            <li>• Calculates lead scores based on configurable ICP weights</li>
                            <li>• De-duplicates against existing leads by domain</li>
                            <li>• Stores leads with provider tags for targeted outreach</li>
                        </ul>
                    </div>
                </div>
            )}

            {/* ═══════════════ LEADS TAB ═══════════════ */}
            {activeTab === 'leads' && (
                <div className="space-y-4">
                    {/* Improvement #22: Search bar + filters */}
                    <div className="bg-card rounded-xl border border-border p-4 shadow-sm space-y-3">
                        <div className="flex flex-col sm:flex-row gap-3">
                            <div className="relative flex-1">
                                <input
                                    ref={searchInputRef}
                                    type="text"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    placeholder="Search leads by company, domain, email, contact... (press / to focus)"
                                    className="w-full px-4 py-2.5 pl-10 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary"
                                />
                                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-sm">🔍</span>
                            </div>
                            {/* Improvement #23: Sort dropdown */}
                            <select
                                value={LEAD_SORT_OPTIONS.indexOf(sortConfig)}
                                onChange={(e) => setSortConfig(LEAD_SORT_OPTIONS[parseInt(e.target.value)])}
                                className="px-3 py-2.5 rounded-lg border border-border bg-background text-foreground text-sm focus:ring-2 focus:ring-primary/20"
                            >
                                {LEAD_SORT_OPTIONS.map((opt, i) => (
                                    <option key={i} value={i}>{opt.label}</option>
                                ))}
                            </select>
                        </div>

                        {/* Multi-filter row */}
                        <div className="flex items-center gap-3 flex-wrap">
                            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Filters:</span>

                            {/* Provider filter */}
                            <select
                                value={providerFilter ?? ''}
                                onChange={(e) => setProviderFilter(e.target.value || null)}
                                className="px-2 py-1.5 rounded-lg border border-border bg-background text-foreground text-xs"
                            >
                                <option value="">All providers ({leads.length})</option>
                                {COMPETITOR_PROVIDERS.map(p => {
                                    const count = providerCounts[p] || 0;
                                    return count > 0 ? <option key={p} value={p}>{p} ({count})</option> : null;
                                })}
                            </select>

                            {/* Status filter */}
                            <select
                                value={statusFilter ?? ''}
                                onChange={(e) => setStatusFilter((e.target.value || null) as LeadStatus | null)}
                                className="px-2 py-1.5 rounded-lg border border-border bg-background text-foreground text-xs"
                            >
                                <option value="">All statuses</option>
                                {Object.entries(LEAD_STATUS_CONFIG).map(([key, cfg]) => (
                                    <option key={key} value={key}>{cfg.icon} {cfg.label}</option>
                                ))}
                            </select>

                            {/* ICP filter */}
                            <select
                                value={icpFilter ?? ''}
                                onChange={(e) => setICPFilter((e.target.value || null) as ICPFitScore | null)}
                                className="px-2 py-1.5 rounded-lg border border-border bg-background text-foreground text-xs"
                            >
                                <option value="">All ICP fits</option>
                                {Object.entries(ICP_FIT_CONFIG).map(([key, cfg]) => (
                                    <option key={key} value={key}>{cfg.label}</option>
                                ))}
                            </select>

                            {(providerFilter || statusFilter || icpFilter || searchQuery) && (
                                <button onClick={() => { setProviderFilter(null); setStatusFilter(null); setICPFilter(null); setSearchQuery(''); }} className="text-xs text-primary hover:underline">
                                    Clear all filters
                                </button>
                            )}
                        </div>
                    </div>

                    {/* Selection Actions — Improvement #31: includes bulk status change */}
                    {selectedLeads.size > 0 && (
                        <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                            <div className="text-sm text-foreground">
                                <strong>{selectedLeads.size}</strong> leads selected
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <select
                                    onChange={(e) => { if (e.target.value) { bulkUpdateStatus(e.target.value as LeadStatus); e.target.value = ''; } }}
                                    className="px-2 py-1.5 rounded-lg border border-border bg-background text-foreground text-xs"
                                    defaultValue=""
                                >
                                    <option value="" disabled>Move to status...</option>
                                    {Object.entries(LEAD_STATUS_CONFIG).map(([key, cfg]) => (
                                        <option key={key} value={key}>{cfg.icon} {cfg.label}</option>
                                    ))}
                                </select>
                                <button onClick={clearSelection} className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground border border-border rounded-lg">Clear</button>
                                <button onClick={enrichSelectedLeads} className="px-4 py-1.5 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 shadow-sm">
                                    Enrich Data
                                </button>
                                <button onClick={() => setActiveTab('outreach')} className="px-4 py-1.5 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 shadow-sm">
                                    Start Outreach →
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Leads Table */}
                    <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                        <div className="flex items-center justify-between p-4 border-b border-border bg-muted/30">
                            <h2 className="font-semibold text-foreground">
                                Leads ({filteredLeads.length}{filteredLeads.length !== leads.length ? ` of ${leads.length}` : ''})
                            </h2>
                            <div className="flex items-center gap-3">
                                <button onClick={selectAllFiltered} className="text-sm text-primary hover:underline">Select all</button>
                                {/* Improvement #24: Page size selector */}
                                <select
                                    value={pageSize}
                                    onChange={(e) => { setPageSize(parseInt(e.target.value)); setCurrentPage(1); }}
                                    className="px-2 py-1 text-xs border border-border rounded bg-background text-foreground"
                                >
                                    {[10, 25, 50, 100].map(n => <option key={n} value={n}>{n}/page</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="divide-y divide-border">
                            {paginatedLeads.length === 0 ? (
                                <div className="p-12 text-center text-muted-foreground">
                                    {leads.length === 0
                                        ? (<><div className="text-4xl mb-3">🔍</div><div className="text-lg font-semibold text-foreground mb-1">No leads discovered yet</div><div>Run a discovery job from the Discovery tab to find prospects.</div></>)
                                        : (<><div className="text-4xl mb-3">🔎</div><div>No leads match the current filters.</div></>)}
                                </div>
                            ) : (
                                paginatedLeads.map(lead => {
                                    const statusCfg = LEAD_STATUS_CONFIG[lead.status];
                                    const icpCfg = ICP_FIT_CONFIG[lead.icpFit];
                                    return (
                                        <div
                                            key={lead.id}
                                            className={cn(
                                                'p-4 hover:bg-muted/30 transition-colors flex items-center gap-4 cursor-pointer',
                                                selectedLeads.has(lead.id) && 'bg-primary/5'
                                            )}
                                            onClick={() => setSelectedLeadDetail(lead)}
                                        >
                                            <input
                                                type="checkbox"
                                                checked={selectedLeads.has(lead.id)}
                                                onChange={(e) => { e.stopPropagation(); toggleLeadSelection(lead.id); }}
                                                onClick={(e) => e.stopPropagation()}
                                                className="w-4 h-4 rounded border-border text-primary focus:ring-primary/20"
                                            />
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                    <span className="font-semibold text-foreground truncate">{lead.companyName}</span>
                                                    <span className={cn('px-2 py-0.5 rounded-md text-xs font-bold', getScoreColor(lead.score))}>{lead.score}</span>
                                                    {/* Improvement #34: ICP fit badge */}
                                                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-semibold border', icpCfg?.color)}>{icpCfg?.label}</span>
                                                    {/* Status badge */}
                                                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-semibold border', statusCfg?.color)}>{statusCfg?.icon} {statusCfg?.label}</span>
                                                    {lead.emailProvider && COMPETITOR_PROVIDERS.includes(lead.emailProvider) && (
                                                        <span className="px-2 py-0.5 bg-warning/10 text-warning border border-warning/20 rounded-md text-xs font-medium">🎯 {lead.emailProvider}</span>
                                                    )}
                                                </div>
                                                <div className="text-sm text-muted-foreground flex items-center gap-2 flex-wrap">
                                                    <span>{lead.domain}</span>
                                                    <span className="text-border">·</span>
                                                    <span>{lead.source}</span>
                                                    {lead.contactEmail && (<><span className="text-border">·</span><span>{lead.contactEmail}</span></>)}
                                                    {lead.estimatedDealValue && (<><span className="text-border">·</span><span className="font-medium text-foreground">${lead.estimatedDealValue.toLocaleString()}/yr</span></>)}
                                                </div>
                                            </div>
                                            <div className="text-xs text-muted-foreground text-right shrink-0">
                                                <div>{formatDate(lead.foundAt)}</div>
                                                {lead.lastContactedAt && <div className="mt-0.5 text-primary">Contacted {formatDate(lead.lastContactedAt)}</div>}
                                            </div>
                                        </div>
                                    );
                                })
                            )}
                        </div>

                        {/* Improvement #24: Pagination controls */}
                        {totalPages > 1 && (
                            <div className="flex items-center justify-between p-4 border-t border-border bg-muted/20">
                                <div className="text-xs text-muted-foreground">
                                    Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, sortedLeads.length)} of {sortedLeads.length}
                                </div>
                                <div className="flex items-center gap-1">
                                    <button onClick={() => setCurrentPage(1)} disabled={currentPage === 1} className="px-2 py-1 text-xs border border-border rounded hover:bg-muted disabled:opacity-30">First</button>
                                    <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="px-2 py-1 text-xs border border-border rounded hover:bg-muted disabled:opacity-30">Prev</button>
                                    <span className="px-3 py-1 text-xs font-medium">{currentPage} / {totalPages}</span>
                                    <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="px-2 py-1 text-xs border border-border rounded hover:bg-muted disabled:opacity-30">Next</button>
                                    <button onClick={() => setCurrentPage(totalPages)} disabled={currentPage === totalPages} className="px-2 py-1 text-xs border border-border rounded hover:bg-muted disabled:opacity-30">Last</button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ═══════════════ OUTREACH TAB ═══════════════ */}
            {activeTab === 'outreach' && (
                <div className="space-y-6">
                    {selectedLeads.size === 0 ? (
                        <div className="bg-warning/5 border border-warning/20 rounded-xl p-8 text-center">
                            <div className="text-4xl mb-4">📭</div>
                            <h3 className="text-lg font-semibold text-foreground mb-2">No leads selected</h3>
                            <p className="text-muted-foreground mb-4">Go to the Leads tab and select companies to reach out to.</p>
                            <button onClick={() => setActiveTab('leads')} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90">Select Leads</button>
                        </div>
                    ) : (
                        <>
                            <div className="bg-success/5 border border-success/20 rounded-xl p-4 flex items-center justify-between">
                                <div>
                                    <span className="font-semibold text-foreground">{selectedLeads.size} leads</span>
                                    <span className="text-muted-foreground"> ready for outreach</span>
                                </div>
                                <button onClick={clearSelection} className="text-xs text-muted-foreground hover:text-foreground">Clear selection</button>
                            </div>

                            <h2 className="text-lg font-semibold text-foreground">Choose Your Offer</h2>
                            <p className="text-sm text-muted-foreground -mt-4">Each offer uses a distinct email sequence optimized for different conversion goals.</p>

                            {/* Improvement #38: Offer cards with sequence length + conversion rate */}
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {OUTREACH_OFFERS.map(offer => (
                                    <div key={offer.id} className="bg-card rounded-xl border border-border p-6 shadow-sm hover:shadow-md transition-shadow flex flex-col">
                                        <div className="text-3xl mb-3">{offer.icon}</div>
                                        <h3 className="text-lg font-semibold text-foreground mb-1">{offer.name}</h3>
                                        <p className="text-sm text-muted-foreground mb-3 flex-1">{offer.description}</p>
                                        <div className="flex items-center gap-4 text-xs text-muted-foreground mb-4">
                                            <span className="px-2 py-0.5 bg-muted rounded">{offer.sequenceLength} emails</span>
                                            <span className="px-2 py-0.5 bg-green-500/10 text-green-600 rounded">{(offer.expectedConversionRate * 100).toFixed(0)}% conv.</span>
                                        </div>
                                        <div className="mb-4">
                                            <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Best for:</div>
                                            <div className="flex flex-wrap gap-1">{offer.bestFor.map(b => <span key={b} className="text-[10px] px-1.5 py-0.5 bg-muted border border-border rounded">{b}</span>)}</div>
                                        </div>
                                        <button
                                            onClick={() => setPendingOutreach(offer.id)}
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
                                    <li>• Each email references the lead&apos;s domain, detected email provider, and competitor weaknesses</li>
                                    <li>• Provider-specific migration guides are automatically linked based on MX detection</li>
                                    <li>• Emails are sent via the sales-autopilot drip engine with intelligent pacing</li>
                                    <li>• Replies are monitored via Inbox Sentinel for automatic engagement detection</li>
                                    <li>• Follow-up sequences adapt based on open/click behavior</li>
                                </ul>
                            </div>
                        </>
                    )}
                </div>
            )}

            {/* ═══════════════ Improvement #44: CAMPAIGNS TAB ═══════════════ */}
            {activeTab === 'campaigns' && (
                <div className="space-y-6">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-semibold text-foreground">Outreach Campaigns</h2>
                        <button onClick={loadCampaigns} disabled={campaignsLoading} className="px-3 py-2 text-sm border border-border rounded-lg hover:bg-muted transition-colors disabled:opacity-50">
                            {campaignsLoading ? '⟳ Loading...' : '↻ Refresh'}
                        </button>
                    </div>

                    {campaigns.length === 0 ? (
                        <div className="bg-muted/30 rounded-xl p-12 text-center border border-border">
                            <div className="text-4xl mb-4">📬</div>
                            <h3 className="text-lg font-semibold text-foreground mb-2">No campaigns yet</h3>
                            <p className="text-muted-foreground mb-4">Select leads and start an outreach campaign from the Outreach tab.</p>
                            <button onClick={() => setActiveTab('outreach')} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90">
                                Create a Campaign
                            </button>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {/* Campaign summary cards */}
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                                    <div className="text-sm text-muted-foreground mb-1">Total Campaigns</div>
                                    <div className="text-2xl font-bold text-foreground">{campaigns.length}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                                    <div className="text-sm text-muted-foreground mb-1">Active</div>
                                    <div className="text-2xl font-bold text-green-600">{campaigns.filter(c => c.status === 'active').length}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                                    <div className="text-sm text-muted-foreground mb-1">Total Leads Enrolled</div>
                                    <div className="text-2xl font-bold text-primary">{campaigns.reduce((sum, c) => sum + c.leads, 0)}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-5 shadow-sm">
                                    <div className="text-sm text-muted-foreground mb-1">Avg Open Rate</div>
                                    <div className="text-2xl font-bold text-foreground">
                                        {campaigns.length > 0 ? (
                                            (() => {
                                                const totalSent = campaigns.reduce((s, c) => s + c.metrics.sent, 0);
                                                const totalOpened = campaigns.reduce((s, c) => s + c.metrics.opened, 0);
                                                return totalSent > 0 ? `${((totalOpened / totalSent) * 100).toFixed(1)}%` : '—';
                                            })()
                                        ) : '—'}
                                    </div>
                                </div>
                            </div>

                            {/* Campaign list */}
                            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                                <div className="divide-y divide-border">
                                    {campaigns.map(campaign => {
                                        const statusCfg = CAMPAIGN_STATUS_CONFIG[campaign.status] || CAMPAIGN_STATUS_CONFIG.draft;
                                        const offer = OUTREACH_OFFERS.find(o => o.id === campaign.offerId);
                                        const openRate = campaign.metrics.sent > 0 ? ((campaign.metrics.opened / campaign.metrics.sent) * 100).toFixed(1) : '0';
                                        const replyRate = campaign.metrics.sent > 0 ? ((campaign.metrics.replied / campaign.metrics.sent) * 100).toFixed(1) : '0';
                                        return (
                                            <div key={campaign.id} className="p-5 hover:bg-muted/20 transition-colors">
                                                <div className="flex items-start justify-between gap-4 mb-3">
                                                    <div className="min-w-0 flex-1">
                                                        <div className="flex items-center gap-3 mb-1">
                                                            <h3 className="font-semibold text-foreground truncate">{campaign.name}</h3>
                                                            <span className={cn('px-2 py-0.5 rounded-md text-xs font-semibold border shrink-0', statusCfg.color)}>{statusCfg.icon} {statusCfg.label}</span>
                                                        </div>
                                                        <div className="text-sm text-muted-foreground flex items-center gap-3 flex-wrap">
                                                            {offer && <span>{offer.icon} {offer.name}</span>}
                                                            <span className="text-border">·</span>
                                                            <span>{campaign.leads} leads</span>
                                                            <span className="text-border">·</span>
                                                            <span>Created {new Date(campaign.createdAt).toLocaleDateString()}</span>
                                                        </div>
                                                    </div>
                                                    <div className="flex gap-2 shrink-0">
                                                        {campaign.status === 'active' && (
                                                            <button onClick={() => handleCampaignAction(campaign.id, 'pause')} className="px-3 py-1.5 text-xs font-medium border border-amber-200 bg-amber-50 text-amber-700 rounded-lg hover:bg-amber-100">
                                                                Pause
                                                            </button>
                                                        )}
                                                        {campaign.status === 'paused' && (
                                                            <button onClick={() => handleCampaignAction(campaign.id, 'resume')} className="px-3 py-1.5 text-xs font-medium border border-green-200 bg-green-50 text-green-700 rounded-lg hover:bg-green-100">
                                                                Resume
                                                            </button>
                                                        )}
                                                        {(campaign.status === 'active' || campaign.status === 'paused') && (
                                                            <button onClick={() => handleCampaignAction(campaign.id, 'cancel')} className="px-3 py-1.5 text-xs font-medium border border-destructive/20 bg-destructive/10 text-destructive rounded-lg hover:bg-destructive/20">
                                                                Cancel
                                                            </button>
                                                        )}
                                                        {(campaign.status === 'completed' || campaign.status === 'cancelled') && (
                                                            <button onClick={() => handleCampaignAction(campaign.id, 'archive')} className="px-3 py-1.5 text-xs font-medium border border-border bg-muted text-muted-foreground rounded-lg hover:bg-muted/80">
                                                                Archive
                                                            </button>
                                                        )}
                                                    </div>
                                                </div>

                                                {/* Metrics bar */}
                                                <div className="grid grid-cols-5 gap-4">
                                                    <div className="text-center">
                                                        <div className="text-lg font-bold text-foreground">{campaign.metrics.sent}</div>
                                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Sent</div>
                                                    </div>
                                                    <div className="text-center">
                                                        <div className="text-lg font-bold text-blue-600">{campaign.metrics.opened}</div>
                                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Opened ({openRate}%)</div>
                                                    </div>
                                                    <div className="text-center">
                                                        <div className="text-lg font-bold text-purple-600">{campaign.metrics.clicked}</div>
                                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Clicked</div>
                                                    </div>
                                                    <div className="text-center">
                                                        <div className="text-lg font-bold text-green-600">{campaign.metrics.replied}</div>
                                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Replied ({replyRate}%)</div>
                                                    </div>
                                                    <div className="text-center">
                                                        <div className="text-lg font-bold text-destructive">{campaign.metrics.bounced}</div>
                                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Bounced</div>
                                                    </div>
                                                </div>

                                                {/* Progress bar for active campaigns */}
                                                {campaign.status === 'active' && campaign.leads > 0 && (
                                                    <div className="mt-3">
                                                        <div className="flex justify-between text-[10px] text-muted-foreground mb-1">
                                                            <span>Sending progress</span>
                                                            <span>{campaign.metrics.sent} / {campaign.leads}</span>
                                                        </div>
                                                        <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                                                            <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${Math.min(100, (campaign.metrics.sent / campaign.leads) * 100)}%` }} />
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ═══════════════ Improvement #29: PIPELINE TAB ═══════════════ */}
            {activeTab === 'pipeline' && (
                <div className="space-y-6">
                    {/* Revenue forecast */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                            <div className="text-sm text-muted-foreground mb-1">Total Pipeline Value</div>
                            <div className="text-3xl font-bold text-foreground">${pipelineForecast.totalPipelineValue.toLocaleString()}</div>
                        </div>
                        <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                            <div className="text-sm text-muted-foreground mb-1">Weighted Forecast</div>
                            <div className="text-3xl font-bold text-success">${Math.round(pipelineForecast.weightedForecast).toLocaleString()}</div>
                            <div className="text-xs text-muted-foreground mt-1">probability-adjusted</div>
                        </div>
                        <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                            <div className="text-sm text-muted-foreground mb-1">Active Stages</div>
                            <div className="text-3xl font-bold text-foreground">{Object.keys(pipelineForecast.byStage).length}</div>
                        </div>
                    </div>

                    {/* Pipeline by stage */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-4">Pipeline by Stage</h2>
                        <div className="space-y-3">
                            {Object.entries(LEAD_STATUS_CONFIG)
                                .filter(([key]) => pipelineForecast.byStage[key])
                                .sort(([, a], [, b]) => a.order - b.order)
                                .map(([key, cfg]) => {
                                    const stage = pipelineForecast.byStage[key];
                                    if (!stage) return null;
                                    const widthPct = leads.length > 0 ? (stage.count / leads.length) * 100 : 0;
                                    return (
                                        <div key={key} className="flex items-center gap-4">
                                            <div className="w-36 text-sm font-medium text-foreground flex items-center gap-2">
                                                <span>{cfg.icon}</span> {cfg.label}
                                            </div>
                                            <div className="flex-1 h-6 bg-muted rounded-full overflow-hidden">
                                                <div className={cn('h-full rounded-full transition-all', cfg.color.split(' ')[1]?.replace('/10', '/30') || 'bg-primary/30')} style={{ width: `${Math.max(2, widthPct)}%` }} />
                                            </div>
                                            <div className="w-12 text-sm font-bold text-foreground text-right">{stage.count}</div>
                                            <div className="w-28 text-xs text-muted-foreground text-right">${stage.value.toLocaleString()} ({(stage.probability * 100).toFixed(0)}%)</div>
                                        </div>
                                    );
                                })}
                        </div>
                    </div>

                    {/* Quick link to CRM */}
                    <div className="bg-muted/30 rounded-xl p-4 border border-border text-center">
                        <p className="text-sm text-muted-foreground">For drag-and-drop pipeline management, visit the <a href="/crm" className="text-primary hover:underline font-medium">CRM Pipeline</a> page.</p>
                    </div>
                </div>
            )}

            {/* ═══════════════ ANALYTICS TAB ═══════════════ */}
            {activeTab === 'analytics' && (
                <div className="space-y-6">
                    {stats ? (
                        <>
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">Total Scraped</h3>
                                    <div className="text-3xl font-bold text-foreground">{stats.totalScraped}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">With MX Records</h3>
                                    <div className="text-3xl font-bold text-success">{stats.totalWithMx}</div>
                                    <div className="text-xs text-muted-foreground mt-1">{stats.totalScraped > 0 ? `${((stats.totalWithMx / stats.totalScraped) * 100).toFixed(1)}%` : '0%'} resolution rate</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">Competitor Users</h3>
                                    <div className="text-3xl font-bold text-primary">{competitorLeads.length}</div>
                                </div>
                                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                    <h3 className="text-sm text-muted-foreground mb-2">Avg Lead Score</h3>
                                    <div className="text-3xl font-bold text-foreground">{leads.length > 0 ? Math.round(leads.reduce((a, l) => a + l.score, 0) / leads.length) : 0}</div>
                                </div>
                            </div>

                            {/* By Provider */}
                            <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                                <h2 className="text-lg font-semibold text-foreground mb-4">Leads by Email Provider</h2>
                                <div className="space-y-3">
                                    {Object.entries(stats.byProvider).sort(([, a], [, b]) => b - a).map(([provider, count]) => (
                                        <div key={provider} className="flex items-center gap-4">
                                            <div className="w-40 text-sm font-medium text-foreground flex items-center gap-2">
                                                {provider}
                                                {COMPETITOR_PROVIDERS.includes(provider) && <span className="text-[10px] px-1 bg-warning/10 text-warning rounded">target</span>}
                                            </div>
                                            <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden">
                                                <svg width="100%" height="100%" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">
                                                    <rect x="0" y="0" width={Math.max(0, Math.min(100, (count / Math.max(stats.totalScraped, 1)) * 100))} height="16" className={cn(COMPETITOR_PROVIDERS.includes(provider) ? 'fill-primary' : 'fill-muted-foreground/30')} rx="999" ry="999" />
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
                                        <div key={source} className="text-center p-4 bg-muted/30 rounded-xl border border-border">
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
                            <p className="text-muted-foreground">Run a discovery job to see detailed analytics about your leads.</p>
                        </div>
                    )}
                </div>
            )}

            {/* ═══════════════ Improvement #30: SETTINGS TAB ═══════════════ */}
            {activeTab === 'settings' && (
                <div className="space-y-6">
                    {/* Save Bar */}
                    <div className="bg-card rounded-xl border border-border p-4 shadow-sm flex items-center justify-between">
                        <div>
                            <h2 className="font-semibold text-foreground">Sales Settings</h2>
                            <p className="text-xs text-muted-foreground">Configure scoring, scheduling, and notification preferences</p>
                        </div>
                        <button
                            onClick={saveSettings}
                            disabled={settingsSaving}
                            className={cn(
                                'px-6 py-2.5 rounded-xl font-semibold text-sm transition-all shadow-sm',
                                settingsSaving
                                    ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                    : 'bg-primary text-primary-foreground hover:bg-primary/90'
                            )}
                        >
                            {settingsSaving ? '⟳ Saving...' : 'Save Settings'}
                        </button>
                    </div>

                    {/* Scoring Weights */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-2">Lead Scoring Weights</h2>
                        <p className="text-sm text-muted-foreground mb-4">Configure how leads are scored to prioritize your ideal customer profile (ICP). Weights should sum to 100.</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {(Object.entries(scoringWeights) as [keyof ScoringWeights, number][]).map(([key, value]) => (
                                <div key={key} className="flex items-center gap-4">
                                    <label className="text-sm font-medium text-foreground w-48 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</label>
                                    <input
                                        type="range"
                                        min={0}
                                        max={50}
                                        value={value}
                                        onChange={(e) => { setScoringWeights(prev => ({ ...prev, [key]: parseInt(e.target.value) })); setSettingsDirty(true); }}
                                        className="flex-1"
                                    />
                                    <span className="w-10 text-sm font-bold text-foreground text-right">{value}</span>
                                </div>
                            ))}
                        </div>
                        <div className="mt-4 text-xs text-muted-foreground">
                            Total: <span className={cn('font-bold', Object.values(scoringWeights).reduce((a, b) => a + b, 0) === 100 ? 'text-green-600' : 'text-red-600')}>
                                {Object.values(scoringWeights).reduce((a, b) => a + b, 0)}
                            </span>/100
                        </div>
                    </div>

                    {/* Discovery Schedule */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-2">Automated Discovery Schedule</h2>
                        <p className="text-sm text-muted-foreground mb-4">Set up recurring discovery jobs to continuously find new leads.</p>
                        <div className="space-y-3">
                            {DISCOVERY_SCHEDULES.map(sched => (
                                <label key={sched.id} className={cn('flex items-center gap-4 p-4 rounded-xl border cursor-pointer transition-colors', scheduleId === sched.id ? 'border-primary/30 bg-primary/5' : 'border-border hover:bg-muted/30')}>
                                    <input type="radio" name="schedule" checked={scheduleId === sched.id} onChange={() => { setScheduleId(sched.id); setSettingsDirty(true); }} className="text-primary focus:ring-primary/20" />
                                    <div>
                                        <div className="font-medium text-foreground">{sched.label}</div>
                                        <div className="text-xs text-muted-foreground">{sched.description}</div>
                                    </div>
                                    {sched.cronExpression && <code className="ml-auto text-[10px] text-muted-foreground bg-muted px-2 py-0.5 rounded font-mono">{sched.cronExpression}</code>}
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* Notification Preferences — persistent */}
                    <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                        <h2 className="text-lg font-semibold text-foreground mb-2">Notification Preferences</h2>
                        <p className="text-sm text-muted-foreground mb-4">Configure when you get notified about sales events.</p>
                        <div className="space-y-3">
                            {[
                                { key: 'newLeadDiscovered', label: 'New lead discovered' },
                                { key: 'leadOpenedEmail', label: 'Lead opened email' },
                                { key: 'leadReplied', label: 'Lead replied to outreach' },
                                { key: 'demoScheduled', label: 'Demo scheduled' },
                                { key: 'dealClosed', label: 'Deal closed (won or lost)' },
                                { key: 'discoveryComplete', label: 'Discovery job completed' },
                                { key: 'weeklyPipelineSummary', label: 'Weekly pipeline summary' },
                            ].map(pref => (
                                <label key={pref.key} className="flex items-center justify-between p-3 rounded-lg border border-border hover:bg-muted/30 cursor-pointer">
                                    <span className="text-sm text-foreground">{pref.label}</span>
                                    <input
                                        type="checkbox"
                                        checked={notifPrefs[pref.key] ?? false}
                                        onChange={(e) => { setNotifPrefs(prev => ({ ...prev, [pref.key]: e.target.checked })); setSettingsDirty(true); }}
                                        className="rounded text-primary focus:ring-primary/20"
                                    />
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* Danger Zone */}
                    <div className="bg-destructive/10 rounded-xl border border-destructive/20 p-6">
                        <h2 className="text-lg font-semibold text-destructive mb-2">Danger Zone</h2>
                        <p className="text-sm text-destructive/80 mb-4">These actions cannot be undone. Proceed with caution.</p>
                        <div className="flex gap-3">
                            <button className="px-4 py-2 text-sm font-medium border border-destructive/30 text-destructive rounded-lg hover:bg-destructive/20 transition-colors">
                                Reset All Scoring Weights
                            </button>
                            <button className="px-4 py-2 text-sm font-medium border border-destructive/30 text-destructive rounded-lg hover:bg-destructive/20 transition-colors">
                                Clear All Leads
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
