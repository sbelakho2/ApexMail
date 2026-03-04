'use client';

import * as React from 'react';
import { APIError, getCsrfToken, useCampaigns, useDeleteCampaign, useAPIMutation, type Campaign } from '@/hooks/use-api';

export interface CampaignDisplay {
    id: string;
    name: string;
    subject: string;
    status: 'draft' | 'scheduled' | 'sending' | 'sent' | 'paused';
    listName: string;
    sentAt?: string;
    scheduledAt?: string;
    stats: { sent: number; openRate: number; clickRate: number; bounceRate: number };
}

function toCampaignDisplay(campaign: Campaign): CampaignDisplay {
    const stats = campaign.stats || {
        sent: 0,
        delivered: 0,
        opens: 0,
        uniqueOpens: 0,
        clicks: 0,
        uniqueClicks: 0,
        bounces: 0,
        complaints: 0,
        unsubscribes: 0,
        openRate: 0,
        clickRate: 0,
        bounceRate: 0,
    };

    return {
        id: campaign.id,
        name: campaign.name,
        subject: campaign.subject,
        status: campaign.status,
        listName: campaign.listId ? 'Linked audience' : 'No audience selected',
        sentAt: campaign.sentAt,
        scheduledAt: campaign.scheduledAt,
        stats: {
            sent: stats.sent,
            openRate: stats.openRate,
            clickRate: stats.clickRate,
            bounceRate:
                stats.bounceRate ??
                (stats.bounces && stats.sent ? (stats.bounces / stats.sent) * 100 : 0),
        },
    };
}

type CampaignFilterPreset = 'all_campaigns' | 'scheduled_queue' | 'sent_top_open';
type SortField = 'name' | 'sentAt' | 'openRate';
type SortOrder = 'asc' | 'desc';
const MAX_AUTO_FETCH_RETRIES = 3;

export function useCampaignsController() {
    const [page, setPage] = React.useState(1);
    const [selectedIds, setSelectedIds] = React.useState<string[]>([]);
    const [statusFilter, setStatusFilter] = React.useState<string>('all');
    const [searchInput, setSearchInput] = React.useState('');
    const [searchQuery, setSearchQuery] = React.useState('');
    const [sortField, setSortField] = React.useState<SortField>('sentAt');
    const [sortOrder, setSortOrder] = React.useState<SortOrder>('desc');
    const [activePreset, setActivePreset] = React.useState<CampaignFilterPreset>('all_campaigns');
    const [deleteDialogOpen, setDeleteDialogOpen] = React.useState(false);
    const [campaignToDelete, setCampaignToDelete] = React.useState<string | null>(null);
    const [bulkDeleteDialogOpen, setBulkDeleteDialogOpen] = React.useState(false);
    const [bulkPauseDialogOpen, setBulkPauseDialogOpen] = React.useState(false);
    const [actionError, setActionError] = React.useState<string | null>(null);
    const [retryAfterSeconds, setRetryAfterSeconds] = React.useState(0);
    const [retryFetchIn, setRetryFetchIn] = React.useState(0);
    const [retryAttempts, setRetryAttempts] = React.useState(0);
    const [isCloningId, setIsCloningId] = React.useState<string | null>(null);
    const [cloneError, setCloneError] = React.useState<string | null>(null);
    const [optimisticCampaigns, setOptimisticCampaigns] = React.useState<CampaignDisplay[]>([]);
    const [recentlyDeleted, setRecentlyDeleted] = React.useState<CampaignDisplay | null>(null);
    const [showUndoDelete, setShowUndoDelete] = React.useState(false);
    const [resendDialogOpen, setResendDialogOpen] = React.useState(false);
    const [campaignToResend, setCampaignToResend] = React.useState<CampaignDisplay | null>(null);

    const { data: campaignsData, error, isLoading, mutate } = useCampaigns(page, 25);
    const deleteCampaign = useDeleteCampaign();
    const cloneMutation = useAPIMutation<Campaign, { campaignId: string }>('/v1/campaigns/clone');
    const resendMutation = useAPIMutation<Campaign, { campaignId: string }>('/v1/campaigns/resend');
    const bulkDeleteMutation = useAPIMutation<{ success: boolean }, { ids: string[] }>('/v1/campaigns/bulk/delete');
    const bulkPauseMutation = useAPIMutation<{ success: boolean }, { ids: string[] }>('/v1/campaigns/bulk/pause');

    const applyPreset = React.useCallback((preset: CampaignFilterPreset) => {
        setActivePreset(preset);
        if (typeof window !== 'undefined') {
            window.localStorage.setItem('campaigns.filterPreset', preset);
        }

        if (preset === 'scheduled_queue') {
            setStatusFilter('scheduled');
            setSearchQuery('');
            setSortField('sentAt');
            setSortOrder('asc');
            return;
        }

        if (preset === 'sent_top_open') {
            setStatusFilter('sent');
            setSearchQuery('');
            setSortField('openRate');
            setSortOrder('desc');
            return;
        }

        setStatusFilter('all');
        setSearchQuery('');
        setSortField('sentAt');
        setSortOrder('desc');
    }, []);

    React.useEffect(() => {
        if (typeof window === 'undefined') return;
        const preset = window.localStorage.getItem('campaigns.filterPreset') as CampaignFilterPreset | null;
        if (!preset) return;
        applyPreset(preset);
    }, [applyPreset]);

    React.useEffect(() => {
        const timer = window.setTimeout(() => setSearchQuery(searchInput), 300);
        return () => window.clearTimeout(timer);
    }, [searchInput]);

    React.useEffect(() => {
        if (retryAfterSeconds <= 0) return;
        const interval = window.setInterval(() => {
            setRetryAfterSeconds((prev) => Math.max(0, prev - 1));
        }, 1000);
        return () => window.clearInterval(interval);
    }, [retryAfterSeconds]);

    React.useEffect(() => {
        if (typeof window === 'undefined') return;
        const params = new URLSearchParams(window.location.search);
        const initialPage = Number.parseInt(params.get('page') || '1', 10);
        if (!Number.isNaN(initialPage) && initialPage > 0) {
            setPage(initialPage);
        }

        const savedScroll = window.sessionStorage.getItem('campaigns.scrollY');
        if (savedScroll) {
            window.requestAnimationFrame(() => {
                window.scrollTo(0, Number(savedScroll));
            });
            window.sessionStorage.removeItem('campaigns.scrollY');
        }
    }, []);

    React.useEffect(() => {
        if (typeof window === 'undefined') return;
        const params = new URLSearchParams(window.location.search);
        params.set('page', String(page));
        window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`);
    }, [page]);

    React.useEffect(() => {
        if (retryFetchIn <= 0) return;
        const interval = window.setInterval(() => {
            setRetryFetchIn((prev) => Math.max(0, prev - 1));
        }, 1000);
        return () => window.clearInterval(interval);
    }, [retryFetchIn]);

    React.useEffect(() => {
        if (retryFetchIn === 0 && retryAttempts > 0) {
            mutate();
        }
    }, [retryAttempts, retryFetchIn, mutate]);

    React.useEffect(() => {
        if (!error) {
            setRetryAttempts(0);
            return;
        }

        if (retryFetchIn === 0) {
            if (retryAttempts >= MAX_AUTO_FETCH_RETRIES) {
                setActionError('Automatic retries exhausted. Please retry manually.');
                return;
            }
            setRetryAttempts((prev) => prev + 1);
            setRetryFetchIn(5);
        }
    }, [error, retryAttempts, retryFetchIn]);

    const campaigns = React.useMemo(() => {
        if (!campaignsData?.data) return [];
        return [...optimisticCampaigns, ...campaignsData.data.map(toCampaignDisplay)];
    }, [campaignsData, optimisticCampaigns]);

    const filteredCampaigns = React.useMemo(() => {
        let result = campaigns;

        if (statusFilter !== 'all') {
            result = result.filter((campaign) => campaign.status === statusFilter);
        }

        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            result = result.filter(
                (campaign) =>
                    campaign.name.toLowerCase().includes(query) ||
                    campaign.subject.toLowerCase().includes(query)
            );
        }

        result = [...result].sort((campaignA, campaignB) => {
            let comparison = 0;
            if (sortField === 'name') {
                comparison = campaignA.name.localeCompare(campaignB.name);
            } else if (sortField === 'sentAt') {
                const dateA = campaignA.sentAt || campaignA.scheduledAt || '';
                const dateB = campaignB.sentAt || campaignB.scheduledAt || '';
                comparison = dateA.localeCompare(dateB);
            } else if (sortField === 'openRate') {
                comparison = campaignA.stats.openRate - campaignB.stats.openRate;
            }
            return sortOrder === 'asc' ? comparison : -comparison;
        });

        return result;
    }, [campaigns, searchQuery, sortField, sortOrder, statusFilter]);

    const statusCounts = React.useMemo(() => {
        const counts: Record<string, number> = { all: campaigns.length };
        campaigns.forEach((campaign) => {
            counts[campaign.status] = (counts[campaign.status] || 0) + 1;
        });
        return counts;
    }, [campaigns]);

    const toggleSelectAll = React.useCallback(() => {
        if (selectedIds.length === filteredCampaigns.length) {
            setSelectedIds([]);
        } else {
            setSelectedIds(filteredCampaigns.map((campaign) => campaign.id));
        }
    }, [filteredCampaigns, selectedIds.length]);

    const toggleSelect = React.useCallback((id: string) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((itemId) => itemId !== id) : [...prev, id]
        );
    }, []);

    const handleSort = React.useCallback((field: SortField) => {
        if (sortField === field) {
            setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
        } else {
            setSortField(field);
            setSortOrder('desc');
        }
    }, [sortField]);

    const handleDelete = React.useCallback((id: string) => {
        setCampaignToDelete(id);
        setDeleteDialogOpen(true);
    }, []);

    const handleClone = React.useCallback(async (campaign: CampaignDisplay) => {
        setCloneError(null);
        setIsCloningId(campaign.id);
        try {
            const cloned = await cloneMutation.trigger({ campaignId: campaign.id });
            if (cloned) {
                const cloneDisplay: CampaignDisplay = toCampaignDisplay(cloned);
                setOptimisticCampaigns((prev) => [cloneDisplay, ...prev]);
            }
            mutate();
        } catch {
            setCloneError('Campaign cloning failed. Please retry.');
        } finally {
            setIsCloningId(null);
        }
    }, [cloneMutation, mutate]);

    const confirmDelete = React.useCallback(async () => {
        if (campaignToDelete) {
            try {
                setActionError(null);
                await deleteCampaign.trigger(campaignToDelete);
                const deletedCampaign =
                    campaigns.find((campaign) => campaign.id === campaignToDelete) || null;
                setRecentlyDeleted(deletedCampaign);
                setShowUndoDelete(Boolean(deletedCampaign));
                if (deletedCampaign) {
                    window.setTimeout(() => setShowUndoDelete(false), 8000);
                }
                mutate();
            } catch (err) {
                if (err instanceof APIError && err.status === 429) {
                    setRetryAfterSeconds(30);
                    setActionError(
                        'Rate limited while deleting campaign. Please wait before retrying.'
                    );
                } else {
                    setActionError('Failed to delete campaign. Please try again.');
                }
            }
        }
        setDeleteDialogOpen(false);
        setCampaignToDelete(null);
    }, [campaignToDelete, campaigns, deleteCampaign, mutate]);

    const handleUndoDelete = React.useCallback(async () => {
        if (!recentlyDeleted) return;
        try {
            // Try to restore via API first
            const csrfToken = await getCsrfToken();

            const res = await fetch(`/v1/campaigns/${recentlyDeleted.id}/restore`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });

            if (!res.ok) {
                // If restore endpoint doesn't exist, show error
                setActionError('Unable to undo deletion. The campaign may have been permanently removed.');
            } else {
                mutate();
            }
        } catch {
            setActionError('Unable to undo deletion. Please try again.');
        }
        setShowUndoDelete(false);
        setRecentlyDeleted(null);
    }, [recentlyDeleted, mutate]);

    const handleBulkDelete = React.useCallback(async () => {
        if (selectedIds.length === 0) return;
        if (retryAfterSeconds > 0) {
            setActionError(`Rate limited. Try again in ${retryAfterSeconds}s.`);
            return;
        }

        try {
            await bulkDeleteMutation.trigger({ ids: selectedIds });
            const removed = campaigns.filter((campaign) => selectedIds.includes(campaign.id));
            if (removed.length > 0) {
                setRecentlyDeleted(removed[0]);
                setShowUndoDelete(true);
                window.setTimeout(() => setShowUndoDelete(false), 8000);
            }
            setSelectedIds([]);
            setBulkDeleteDialogOpen(false);
            mutate();
        } catch (err) {
            if (err instanceof APIError && err.status === 429) {
                setRetryAfterSeconds(30);
                setActionError('Rate limited while deleting campaigns. Please wait before retrying.');
            } else {
                setActionError('Bulk delete failed. Please try again.');
            }
        }
    }, [bulkDeleteMutation, campaigns, mutate, retryAfterSeconds, selectedIds]);

    const handleBulkPause = React.useCallback(async () => {
        if (selectedIds.length === 0) return;
        try {
            await bulkPauseMutation.trigger({ ids: selectedIds });
            setSelectedIds([]);
            setBulkPauseDialogOpen(false);
            mutate();
        } catch {
            setActionError('Bulk pause failed. Please try again.');
        }
    }, [bulkPauseMutation, mutate, selectedIds]);

    const handleResend = React.useCallback((campaign: CampaignDisplay) => {
        setCampaignToResend(campaign);
        setResendDialogOpen(true);
    }, []);

    const confirmResend = React.useCallback(async () => {
        if (campaignToResend) {
            try {
                await resendMutation.trigger({ campaignId: campaignToResend.id });
                mutate();
            } catch {
                setActionError(`Failed to resend campaign "${campaignToResend.name}". Please try again.`);
            }
        }
        setResendDialogOpen(false);
        setCampaignToResend(null);
    }, [campaignToResend, mutate, resendMutation]);

    const handleSelectionKeyDown = React.useCallback(
        (event: React.KeyboardEvent<HTMLDivElement>) => {
            if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'a') {
                event.preventDefault();
                setSelectedIds(filteredCampaigns.map((campaign) => campaign.id));
                return;
            }

            if (event.key === 'Escape') {
                setSelectedIds([]);
            }
        },
        [filteredCampaigns]
    );

    const clearSearch = React.useCallback(() => {
        setSearchInput('');
        setSearchQuery('');
    }, []);

    const handleRetryLoad = React.useCallback(() => {
        setActionError(null);
        setRetryAttempts(0);
        setRetryFetchIn(0);
        mutate();
    }, [mutate]);

    return {
        page,
        setPage,
        selectedIds,
        statusFilter,
        setStatusFilter,
        searchInput,
        setSearchInput,
        sortField,
        sortOrder,
        activePreset,
        deleteDialogOpen,
        setDeleteDialogOpen,
        bulkDeleteDialogOpen,
        setBulkDeleteDialogOpen,
        bulkPauseDialogOpen,
        setBulkPauseDialogOpen,
        resendDialogOpen,
        setResendDialogOpen,
        isCloningId,
        actionError,
        cloneError,
        showUndoDelete,
        recentlyDeleted,
        retryFetchIn,
        campaignsData,
        campaigns,
        filteredCampaigns,
        statusCounts,
        isLoading,
        error,
        toggleSelectAll,
        toggleSelect,
        handleSort,
        applyPreset,
        clearSearch,
        handleDelete,
        handleClone,
        confirmDelete,
        handleUndoDelete,
        handleBulkDelete,
        handleBulkPause,
        handleResend,
        confirmResend,
        handleSelectionKeyDown,
        handleRetryLoad,
    };
}