'use client';

import Link from 'next/link';
import {
    Plus,
    Search,
    X,
    MoreHorizontal,
    Send,
    Eye,
    Copy,
    Pencil,
    Trash2,
    Pause,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { PageEmptyState, PageErrorState, PageLoadingState } from '@/components/ui/async-state';
import { PaginationControls } from '@/components/ui/pagination-controls';
import { SortableTableHead } from '@/components/ui/sortable-table-head';
import { StatusIndicator } from '@/components/ui/status-indicator';
import { cn, formatNumber, formatPercent, formatRelativeTime } from '@/lib/utils';
import { useCampaignsController } from './use-campaigns-controller';

export default function CampaignsPage() {
    const {
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
    } = useCampaignsController();

    // Loading state
    if (isLoading) {
        return <PageLoadingState label="Loading campaigns..." />;
    }

    // Error state
    if (error) {
        const isRouteMismatch = error.status === 404 || error.status === 502 || error.status === 503;
        return (
            <PageErrorState
                title="Failed to load campaigns"
                description={isRouteMismatch ? 'Campaign endpoint may be unreachable or mismatched. Verify /api/campaigns mapping to backend /v1/campaigns.' : `We couldn't fetch your campaign list. Retrying in ${retryFetchIn}s...`}
                onRetry={handleRetryLoad}
            />
        );
    }

    return (
        <div className="space-y-6">
            <PageHeader
                title="Campaigns"
                description="Create, manage, and track your email campaigns."
                breadcrumbs={[{ label: 'Campaigns' }]}
                actions={
                    <Button asChild>
                        <Link href="/campaigns/new">
                            <Plus className="mr-2 h-4 w-4" />
                            New Campaign
                        </Link>
                    </Button>
                }
            />

            {/* Filters */}
            <Card>
                <CardContent className="p-4">
                    {actionError ? (
                        <div className="mb-4 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                            {actionError}
                        </div>
                    ) : null}
                    {cloneError ? (
                        <div className="mb-4 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                            {cloneError}
                        </div>
                    ) : null}
                    {showUndoDelete && recentlyDeleted ? (
                        <div className="mb-4 rounded-lg border border-border bg-muted/40 p-3 text-sm text-foreground flex items-center justify-between gap-3">
                            <span>Campaign deleted. You can undo this action.</span>
                            <Button size="sm" variant="outline" onClick={handleUndoDelete}>Undo</Button>
                        </div>
                    ) : null}

                    <div className="mb-3 flex flex-wrap items-center gap-2">
                        <span className="text-xs font-medium text-muted-foreground">Saved views</span>
                        <Button
                            variant={activePreset === 'all_campaigns' ? 'default' : 'outline'}
                            size="sm"
                            onClick={() => applyPreset('all_campaigns')}
                        >
                            All campaigns
                        </Button>
                        <Button
                            variant={activePreset === 'scheduled_queue' ? 'default' : 'outline'}
                            size="sm"
                            onClick={() => applyPreset('scheduled_queue')}
                        >
                            Scheduled queue
                        </Button>
                        <Button
                            variant={activePreset === 'sent_top_open' ? 'default' : 'outline'}
                            size="sm"
                            onClick={() => applyPreset('sent_top_open')}
                        >
                            Top open rate
                        </Button>
                    </div>

                    <div className="mb-4 rounded-lg border border-border bg-muted/20 p-3">
                        <p className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">Lifecycle legend</p>
                        <div className="grid gap-2 text-xs text-muted-foreground md:grid-cols-5">
                            <div className="flex items-center gap-2"><StatusIndicator status="draft" /><span>Drafting</span></div>
                            <div className="flex items-center gap-2"><StatusIndicator status="scheduled" /><span>Queued for send</span></div>
                            <div className="flex items-center gap-2"><StatusIndicator status="sending" /><span>Delivery in progress</span></div>
                            <div className="flex items-center gap-2"><StatusIndicator status="sent" /><span>Completed</span></div>
                            <div className="flex items-center gap-2"><StatusIndicator status="paused" /><span>Temporarily paused</span></div>
                        </div>
                    </div>

                    <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                        {/* Status Tabs */}
                        <Tabs
                            value={statusFilter}
                            onValueChange={setStatusFilter}
                            className="w-full md:w-auto"
                        >
                            <TabsList>
                                <TabsTrigger value="all">
                                    All ({statusCounts.all})
                                </TabsTrigger>
                                <TabsTrigger value="draft">
                                    Draft ({statusCounts.draft || 0})
                                </TabsTrigger>
                                <TabsTrigger value="scheduled">
                                    Scheduled ({statusCounts.scheduled || 0})
                                </TabsTrigger>
                                <TabsTrigger value="sent">
                                    Sent ({statusCounts.sent || 0})
                                </TabsTrigger>
                            </TabsList>
                        </Tabs>

                        {/* Search & Actions */}
                        <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center">
                            <div className="relative w-full sm:w-auto">
                                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                <Input
                                    placeholder="Search campaigns..."
                                    value={searchInput}
                                    onChange={(e) => setSearchInput(e.target.value)}
                                    className="w-full sm:w-64 pl-9 pr-10"
                                />
                                {searchInput && (
                                    <button
                                        type="button"
                                        onClick={clearSearch}
                                        className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground"
                                        aria-label="Clear campaign search"
                                    >
                                        <X className="h-4 w-4" />
                                    </button>
                                )}
                            </div>
                            {selectedIds.length > 0 && (
                                <>
                                    <Button variant="outline" size="sm" onClick={() => setBulkPauseDialogOpen(true)}>
                                        <Pause className="mr-2 h-4 w-4" />
                                        Pause ({selectedIds.length})
                                    </Button>
                                    <Button variant="destructive" size="sm" onClick={() => setBulkDeleteDialogOpen(true)}>
                                        <Trash2 className="mr-2 h-4 w-4" />
                                        Delete ({selectedIds.length})
                                    </Button>
                                </>
                            )}
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Campaigns Table */}
            <Card onKeyDown={handleSelectionKeyDown} tabIndex={0} aria-label="Campaigns table. Use Command/Control+A to select all and Escape to clear selection.">
                <CardContent className="p-0 overflow-x-auto">
                    <Table className="min-w-[800px]">
                        <TableHeader className="sticky top-0 z-10 bg-card">
                            <TableRow>
                                <TableHead className="w-12">
                                    <Checkbox
                                        checked={
                                            selectedIds.length === filteredCampaigns.length &&
                                            filteredCampaigns.length > 0
                                        }
                                        indeterminate={
                                            selectedIds.length > 0 &&
                                            selectedIds.length < filteredCampaigns.length
                                        }
                                        onCheckedChange={toggleSelectAll}
                                    />
                                </TableHead>
                                <TableHead aria-sort={sortField === 'name' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                    <SortableTableHead
                                        label="Campaign"
                                        active={sortField === 'name'}
                                        direction={sortOrder}
                                        onClick={() => handleSort('name')}
                                        className="-ml-2"
                                    />
                                </TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>List</TableHead>
                                <TableHead aria-sort={sortField === 'sentAt' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                    <SortableTableHead
                                        label="Date"
                                        active={sortField === 'sentAt'}
                                        direction={sortOrder}
                                        onClick={() => handleSort('sentAt')}
                                        className="-ml-2"
                                    />
                                </TableHead>
                                <TableHead className="text-right">Sent</TableHead>
                                <TableHead className="text-right" aria-sort={sortField === 'openRate' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                    <SortableTableHead
                                        label="Open Rate"
                                        active={sortField === 'openRate'}
                                        direction={sortOrder}
                                        onClick={() => handleSort('openRate')}
                                        className="justify-end"
                                    />
                                </TableHead>
                                <TableHead className="text-right">CTR</TableHead>
                                <TableHead className="w-12" />
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filteredCampaigns.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={9} className="h-32 text-center">
                                        <PageEmptyState
                                            title="No campaigns found"
                                            description="No results match the current filters. Clear filters/search or create your first campaign."
                                            action={{
                                                label: 'Create your first campaign',
                                                onClick: () => {
                                                    window.location.href = '/campaigns/new';
                                                },
                                            }}
                                        />
                                    </TableCell>
                                </TableRow>
                            ) : (
                                filteredCampaigns.map((campaign) => {
                                    return (
                                        <TableRow
                                            key={campaign.id}
                                            className={cn(
                                                selectedIds.includes(campaign.id) && 'bg-muted/50'
                                            )}
                                        >
                                            <TableCell>
                                                <Checkbox
                                                    checked={selectedIds.includes(campaign.id)}
                                                    onCheckedChange={() => toggleSelect(campaign.id)}
                                                />
                                            </TableCell>
                                            <TableCell>
                                                <Link
                                                    href={`/campaigns/${campaign.id}`}
                                                    className="block"
                                                    onClick={() => {
                                                        if (typeof window !== 'undefined') {
                                                            window.sessionStorage.setItem('campaigns.scrollY', String(window.scrollY));
                                                        }
                                                    }}
                                                >
                                                    <p className="font-medium hover:text-primary">
                                                        {campaign.name || 'Untitled Campaign'}
                                                    </p>
                                                    <p className="text-sm text-muted-foreground line-clamp-1">
                                                        {campaign.subject || 'No subject'}
                                                    </p>
                                                </Link>
                                            </TableCell>
                                            <TableCell>
                                                <StatusIndicator status={campaign.status} />
                                            </TableCell>
                                            <TableCell>
                                                <span className="text-sm">{campaign.listName}</span>
                                            </TableCell>
                                            <TableCell>
                                                <span className="text-sm text-muted-foreground">
                                                    {campaign.sentAt
                                                        ? formatRelativeTime(new Date(campaign.sentAt))
                                                        : campaign.scheduledAt
                                                          ? formatRelativeTime(
                                                                new Date(campaign.scheduledAt)
                                                            )
                                                          : '-'}
                                                </span>
                                            </TableCell>
                                            <TableCell className="text-right apex-metric-number">
                                                {campaign.stats.sent > 0
                                                    ? formatNumber(campaign.stats.sent)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell className="text-right apex-metric-number">
                                                {campaign.stats.openRate > 0
                                                    ? formatPercent(campaign.stats.openRate / 100)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell className="text-right apex-metric-number">
                                                {campaign.stats.clickRate > 0
                                                    ? formatPercent(campaign.stats.clickRate / 100)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell>
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <Button variant="ghost" size="icon" aria-label="Campaign actions" aria-haspopup="menu">
                                                            <MoreHorizontal className="h-4 w-4" />
                                                        </Button>
                                                    </DropdownMenuTrigger>
                                                    <DropdownMenuContent align="end">
                                                        <DropdownMenuItem
                                                            onClick={() => window.location.href = `/campaigns/${campaign.id}`}
                                                        >
                                                            <Eye className="mr-2 h-4 w-4" />
                                                            View Details
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem onClick={() => handleClone(campaign)} disabled={isCloningId === campaign.id}>
                                                            <Copy className="mr-2 h-4 w-4" />
                                                            {isCloningId === campaign.id ? 'Duplicating…' : 'Duplicate'}
                                                        </DropdownMenuItem>
                                                        {campaign.status === 'draft' && (
                                                            <DropdownMenuItem
                                                                onClick={() => window.location.href = `/campaigns/${campaign.id}/edit`}
                                                            >
                                                                <Pencil className="mr-2 h-4 w-4" />
                                                                Edit
                                                            </DropdownMenuItem>
                                                        )}
                                                        <DropdownMenuSeparator />
                                                        {(campaign.status === 'scheduled' || campaign.status === 'sent') && (
                                                            <DropdownMenuItem onClick={() => handleResend(campaign)}>
                                                                <Send className="mr-2 h-4 w-4" />
                                                                Re-send
                                                            </DropdownMenuItem>
                                                        )}
                                                        <DropdownMenuItem
                                                            destructive
                                                            onClick={() => handleDelete(campaign.id)}
                                                        >
                                                            <Trash2 className="mr-2 h-4 w-4" />
                                                            Delete
                                                        </DropdownMenuItem>
                                                    </DropdownMenuContent>
                                                </DropdownMenu>
                                            </TableCell>
                                        </TableRow>
                                    );
                                })
                            )}
                        </TableBody>
                    </Table>
                </CardContent>

                {/* Pagination */}
                <div className="flex items-center justify-between border-t px-4 py-4">
                    <p className="text-sm text-muted-foreground">
                        Showing {filteredCampaigns.length} of {campaigns.length} campaigns
                    </p>
                    <PaginationControls
                        page={page}
                        totalPages={campaignsData?.totalPages ?? 1}
                        onPageChange={setPage}
                    />
                </div>
            </Card>

            {/* Delete Confirmation Dialog */}
            <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Campaign</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to delete this campaign? This action cannot be
                            undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
                            Cancel
                        </Button>
                        <Button variant="destructive" onClick={confirmDelete}>
                            Delete
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={resendDialogOpen} onOpenChange={setResendDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Confirm duplicate-send risk</DialogTitle>
                        <DialogDescription>
                            This campaign is already sent or scheduled. Confirm re-send only if you intend to send another copy to recipients.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setResendDialogOpen(false)}>
                            Cancel
                        </Button>
                        <Button onClick={confirmResend}>
                            Confirm re-send
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={bulkDeleteDialogOpen} onOpenChange={setBulkDeleteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete selected campaigns</DialogTitle>
                        <DialogDescription>
                            This will delete {selectedIds.length} selected campaigns. You can undo briefly after deletion.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setBulkDeleteDialogOpen(false)}>Cancel</Button>
                        <Button variant="destructive" onClick={handleBulkDelete}>Confirm delete</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={bulkPauseDialogOpen} onOpenChange={setBulkPauseDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Pause selected campaigns</DialogTitle>
                        <DialogDescription>
                            This will pause {selectedIds.length} selected campaigns.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setBulkPauseDialogOpen(false)}>Cancel</Button>
                        <Button onClick={handleBulkPause}>Confirm pause</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
