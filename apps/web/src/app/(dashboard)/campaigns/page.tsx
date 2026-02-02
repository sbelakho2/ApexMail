'use client';

import * as React from 'react';
import Link from 'next/link';
import {
    Plus,
    Search,
    MoreHorizontal,
    Send,
    Eye,
    Copy,
    Pencil,
    Trash2,
    Play,
    Pause,
    Calendar,
    ArrowUpDown,
    ChevronLeft,
    ChevronRight,
} from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
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
import { cn, formatNumber, formatPercent, formatRelativeTime } from '@/lib/utils';

// Mock campaigns data
const mockCampaigns = [
    {
        id: '1',
        name: 'Summer Sale Announcement',
        subject: '☀️ Summer Sale is HERE! Up to 50% off',
        status: 'sent' as const,
        listName: 'All Subscribers',
        sentAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        stats: { sent: 12458, openRate: 28.4, clickRate: 4.2, bounceRate: 0.8 },
    },
    {
        id: '2',
        name: 'Weekly Newsletter #42',
        subject: 'This Week in Tech: AI Updates & More',
        status: 'sent' as const,
        listName: 'Newsletter',
        sentAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        stats: { sent: 34521, openRate: 22.1, clickRate: 2.8, bounceRate: 1.2 },
    },
    {
        id: '3',
        name: 'Product Launch Teaser',
        subject: 'Something big is coming...',
        status: 'scheduled' as const,
        listName: 'VIP Customers',
        scheduledAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        stats: { sent: 0, openRate: 0, clickRate: 0, bounceRate: 0 },
    },
    {
        id: '4',
        name: 'Re-engagement Campaign',
        subject: 'We miss you! Come back for 20% off',
        status: 'sending' as const,
        listName: 'Inactive Users',
        sentAt: new Date().toISOString(),
        stats: { sent: 4521, openRate: 18.5, clickRate: 1.9, bounceRate: 2.1 },
    },
    {
        id: '5',
        name: 'Black Friday Preview',
        subject: 'Early access to Black Friday deals',
        status: 'draft' as const,
        listName: 'All Subscribers',
        stats: { sent: 0, openRate: 0, clickRate: 0, bounceRate: 0 },
    },
    {
        id: '6',
        name: 'Holiday Gift Guide',
        subject: '🎁 The Ultimate Holiday Gift Guide',
        status: 'draft' as const,
        listName: 'VIP Customers',
        stats: { sent: 0, openRate: 0, clickRate: 0, bounceRate: 0 },
    },
    {
        id: '7',
        name: 'Year in Review',
        subject: 'Your 2024 Year in Review',
        status: 'paused' as const,
        listName: 'All Subscribers',
        sentAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        stats: { sent: 8234, openRate: 15.2, clickRate: 1.1, bounceRate: 0.9 },
    },
];

const statusStyles = {
    sent: { label: 'Sent', variant: 'success' as const, icon: Send },
    sending: { label: 'Sending', variant: 'warning' as const, icon: Play },
    scheduled: { label: 'Scheduled', variant: 'info' as const, icon: Calendar },
    draft: { label: 'Draft', variant: 'secondary' as const, icon: Pencil },
    paused: { label: 'Paused', variant: 'default' as const, icon: Pause },
};

export default function CampaignsPage() {
    const [selectedIds, setSelectedIds] = React.useState<string[]>([]);
    const [statusFilter, setStatusFilter] = React.useState<string>('all');
    const [searchQuery, setSearchQuery] = React.useState('');
    const [sortField, setSortField] = React.useState<'name' | 'sentAt' | 'openRate'>('sentAt');
    const [sortOrder, setSortOrder] = React.useState<'asc' | 'desc'>('desc');
    const [deleteDialogOpen, setDeleteDialogOpen] = React.useState(false);
    const [campaignToDelete, setCampaignToDelete] = React.useState<string | null>(null);

    // Filter and sort campaigns
    const filteredCampaigns = React.useMemo(() => {
        let result = mockCampaigns;

        // Filter by status
        if (statusFilter !== 'all') {
            result = result.filter((c) => c.status === statusFilter);
        }

        // Filter by search
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            result = result.filter(
                (c) =>
                    c.name.toLowerCase().includes(query) ||
                    c.subject.toLowerCase().includes(query)
            );
        }

        // Sort
        result = [...result].sort((a, b) => {
            let comparison = 0;
            if (sortField === 'name') {
                comparison = a.name.localeCompare(b.name);
            } else if (sortField === 'sentAt') {
                const dateA = a.sentAt || a.scheduledAt || '';
                const dateB = b.sentAt || b.scheduledAt || '';
                comparison = dateA.localeCompare(dateB);
            } else if (sortField === 'openRate') {
                comparison = a.stats.openRate - b.stats.openRate;
            }
            return sortOrder === 'asc' ? comparison : -comparison;
        });

        return result;
    }, [statusFilter, searchQuery, sortField, sortOrder]);

    const toggleSelectAll = () => {
        if (selectedIds.length === filteredCampaigns.length) {
            setSelectedIds([]);
        } else {
            setSelectedIds(filteredCampaigns.map((c) => c.id));
        }
    };

    const toggleSelect = (id: string) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
        );
    };

    const handleSort = (field: typeof sortField) => {
        if (sortField === field) {
            setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
        } else {
            setSortField(field);
            setSortOrder('desc');
        }
    };

    const handleDelete = (id: string) => {
        setCampaignToDelete(id);
        setDeleteDialogOpen(true);
    };

    const confirmDelete = () => {
        // In production, this would call the API
        void campaignToDelete; // Use the variable to satisfy linter
        setDeleteDialogOpen(false);
        setCampaignToDelete(null);
    };

    const statusCounts = React.useMemo(() => {
        const counts: Record<string, number> = { all: mockCampaigns.length };
        mockCampaigns.forEach((c) => {
            counts[c.status] = (counts[c.status] || 0) + 1;
        });
        return counts;
    }, []);

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
                        <div className="flex items-center gap-2">
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                <Input
                                    placeholder="Search campaigns..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-64 pl-9"
                                />
                            </div>
                            {selectedIds.length > 0 && (
                                <Button variant="destructive" size="sm">
                                    <Trash2 className="mr-2 h-4 w-4" />
                                    Delete ({selectedIds.length})
                                </Button>
                            )}
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Campaigns Table */}
            <Card>
                <CardContent className="p-0">
                    <Table>
                        <TableHeader>
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
                                <TableHead>
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="-ml-3 h-8 data-[state=open]:bg-accent"
                                        onClick={() => handleSort('name')}
                                    >
                                        Campaign
                                        <ArrowUpDown className="ml-2 h-4 w-4" />
                                    </Button>
                                </TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>List</TableHead>
                                <TableHead>
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="-ml-3 h-8"
                                        onClick={() => handleSort('sentAt')}
                                    >
                                        Date
                                        <ArrowUpDown className="ml-2 h-4 w-4" />
                                    </Button>
                                </TableHead>
                                <TableHead className="text-right">Sent</TableHead>
                                <TableHead className="text-right">
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-8"
                                        onClick={() => handleSort('openRate')}
                                    >
                                        Open Rate
                                        <ArrowUpDown className="ml-2 h-4 w-4" />
                                    </Button>
                                </TableHead>
                                <TableHead className="text-right">CTR</TableHead>
                                <TableHead className="w-12" />
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filteredCampaigns.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={9} className="h-32 text-center">
                                        <div className="flex flex-col items-center gap-2 text-muted-foreground">
                                            <Send className="h-8 w-8" />
                                            <p>No campaigns found</p>
                                            <Button asChild size="sm">
                                                <Link href="/campaigns/new">Create your first campaign</Link>
                                            </Button>
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ) : (
                                filteredCampaigns.map((campaign) => {
                                    const status = statusStyles[campaign.status];
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
                                                >
                                                    <p className="font-medium hover:text-primary">
                                                        {campaign.name}
                                                    </p>
                                                    <p className="text-sm text-muted-foreground line-clamp-1">
                                                        {campaign.subject}
                                                    </p>
                                                </Link>
                                            </TableCell>
                                            <TableCell>
                                                <Badge variant={status.variant}>
                                                    <status.icon className="mr-1 h-3 w-3" />
                                                    {status.label}
                                                </Badge>
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
                                            <TableCell className="text-right tabular-nums">
                                                {campaign.stats.sent > 0
                                                    ? formatNumber(campaign.stats.sent)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell className="text-right tabular-nums">
                                                {campaign.stats.openRate > 0
                                                    ? formatPercent(campaign.stats.openRate / 100)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell className="text-right tabular-nums">
                                                {campaign.stats.clickRate > 0
                                                    ? formatPercent(campaign.stats.clickRate / 100)
                                                    : '-'}
                                            </TableCell>
                                            <TableCell>
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <Button variant="ghost" size="icon">
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
                                                        <DropdownMenuItem>
                                                            <Copy className="mr-2 h-4 w-4" />
                                                            Duplicate
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
                        Showing {filteredCampaigns.length} of {mockCampaigns.length} campaigns
                    </p>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" disabled>
                            <ChevronLeft className="h-4 w-4" />
                            Previous
                        </Button>
                        <Button variant="outline" size="sm" disabled>
                            Next
                            <ChevronRight className="h-4 w-4" />
                        </Button>
                    </div>
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
        </div>
    );
}
