'use client';

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
    ArrowLeft,
    Send,
    Eye,
    MousePointer,
    AlertTriangle,
    X,
    Mail,
    Clock,
    CheckCircle2,
    Copy,
    Pencil,
    Trash2,
    RefreshCw,
    Users,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { StatusIndicator } from '@/components/ui/status-indicator';
import { PageLoadingState, PageErrorState } from '@/components/ui/async-state';
import { cn, formatNumber, formatPercent, formatRelativeTime } from '@/lib/utils';
import { useCampaign, useDeleteCampaign, useAPIMutation, type Campaign } from '@/hooks/use-api';
import { toast } from '@/hooks/use-toast';

export default function CampaignDetailPage() {
    const params = useParams<{ id: string }>();
    const router = useRouter();
    const { data: campaign, error, isLoading, mutate } = useCampaign(params.id);
    const { trigger: deleteTrigger } = useDeleteCampaign();
    const { trigger: resendTrigger, isMutating: isResending } = useAPIMutation<Campaign, { campaignId: string }>('/v1/campaigns/resend');

    const [deleteDialogOpen, setDeleteDialogOpen] = React.useState(false);
    const [resendDialogOpen, setResendDialogOpen] = React.useState(false);

    const handleDelete = React.useCallback(async () => {
        if (!params.id) return;
        try {
            await deleteTrigger(params.id);
            toast({ title: 'Campaign deleted' });
            router.push('/campaigns');
        } catch {
            toast({ title: 'Failed to delete campaign', variant: 'destructive' });
        } finally {
            setDeleteDialogOpen(false);
        }
    }, [params.id, deleteTrigger, router]);

    const handleResend = React.useCallback(async () => {
        if (!params.id) return;
        try {
            await resendTrigger({ campaignId: params.id });
            toast({ title: 'Campaign queued for re-send' });
            mutate();
        } catch {
            toast({ title: 'Failed to re-send campaign', variant: 'destructive' });
        } finally {
            setResendDialogOpen(false);
        }
    }, [params.id, resendTrigger, mutate]);

    if (isLoading) {
        return <PageLoadingState label="Loading campaign…" />;
    }

    if (error || !campaign) {
        return (
            <PageErrorState
                title="Campaign not found"
                description={error?.message ?? 'The campaign you are looking for does not exist or you don\'t have permission to view it.'}
                retryLabel="Back to Campaigns"
                onRetry={() => router.push('/campaigns')}
            />
        );
    }

    const stats = campaign.stats;
    const hasStats = stats && stats.sent > 0;

    return (
        <div className="space-y-8">
            <PageHeader
                title={campaign.name || 'Untitled Campaign'}
                description={campaign.subject || 'No subject'}
                breadcrumbs={[
                    { label: 'Campaigns', href: '/campaigns' },
                    { label: campaign.name || 'Untitled' },
                ]}
                actions={
                    <div className="flex items-center gap-2">
                        {campaign.status === 'draft' && (
                            <Button variant="outline" size="sm" onClick={() => router.push(`/campaigns/${params.id}/edit`)}>
                                <Pencil className="mr-2 h-4 w-4" />
                                Edit
                            </Button>
                        )}
                        {(campaign.status === 'sent' || campaign.status === 'scheduled') && (
                            <Button variant="outline" size="sm" onClick={() => setResendDialogOpen(true)}>
                                <Send className="mr-2 h-4 w-4" />
                                Re-send
                            </Button>
                        )}
                        <Button
                            variant="outline"
                            size="sm"
                            className="text-destructive hover:bg-destructive/10"
                            onClick={() => setDeleteDialogOpen(true)}
                        >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                        </Button>
                    </div>
                }
            />

            {/* Status Bar */}
            <Card className="border-none shadow-premium bg-white overflow-hidden">
                <CardContent className="py-6">
                    <div className="flex flex-wrap items-center gap-6">
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-muted-foreground">Status</span>
                            <StatusIndicator status={campaign.status} className="font-bold" />
                        </div>
                        <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-muted-foreground">
                                Created {formatRelativeTime(new Date(campaign.createdAt))}
                            </span>
                        </div>
                        {campaign.sentAt && (
                            <div className="flex items-center gap-2">
                                <Send className="h-4 w-4 text-muted-foreground" />
                                <span className="text-sm text-muted-foreground">
                                    Sent {formatRelativeTime(new Date(campaign.sentAt))}
                                </span>
                            </div>
                        )}
                        {campaign.scheduledAt && campaign.status === 'scheduled' && (
                            <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-brand-600" />
                                <span className="text-sm font-medium text-brand-600">
                                    Scheduled for {new Date(campaign.scheduledAt).toLocaleString()}
                                </span>
                            </div>
                        )}
                        <div className="flex items-center gap-2">
                            <Mail className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-muted-foreground">
                                From: {campaign.fromName} &lt;{campaign.fromEmail}&gt;
                            </span>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Stats Grid */}
            {hasStats ? (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                    <StatCard label="Sent" value={formatNumber(stats.sent)} icon={<Send className="h-4 w-4" />} />
                    <StatCard label="Delivered" value={formatNumber(stats.delivered)} icon={<CheckCircle2 className="h-4 w-4" />} />
                    <StatCard label="Opens" value={formatNumber(stats.uniqueOpens)} sub={`${stats.openRate.toFixed(1)}% rate`} icon={<Eye className="h-4 w-4" />} />
                    <StatCard label="Clicks" value={formatNumber(stats.uniqueClicks)} sub={`${stats.clickRate.toFixed(1)}% rate`} icon={<MousePointer className="h-4 w-4" />} />
                    <StatCard label="Bounces" value={formatNumber(stats.bounces)} sub={`${stats.bounceRate.toFixed(1)}% rate`} icon={<AlertTriangle className="h-4 w-4" />} variant="warning" />
                    <StatCard label="Complaints" value={formatNumber(stats.complaints)} icon={<X className="h-4 w-4" />} variant="error" />
                </div>
            ) : (
                <Card className="border-none shadow-premium bg-white">
                    <CardContent className="py-12 text-center">
                        <Mail className="mx-auto h-10 w-10 text-muted-foreground/50 mb-3" />
                        <p className="text-sm text-muted-foreground">
                            {campaign.status === 'draft'
                                ? 'This campaign hasn\'t been sent yet. Stats will appear after sending.'
                                : campaign.status === 'scheduled'
                                  ? 'This campaign is scheduled. Stats will appear after it\'s sent.'
                                  : 'No delivery data available yet.'}
                        </p>
                    </CardContent>
                </Card>
            )}

            {/* Delivery Funnel */}
            {hasStats && (
                <Card className="border-none shadow-premium bg-white overflow-hidden">
                    <CardHeader>
                        <CardTitle className="text-lg font-bold">Delivery Funnel</CardTitle>
                        <CardDescription>Conversion through each stage</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {[
                            { label: 'Delivered', value: stats.delivered, total: stats.sent, variant: 'success' as const },
                            { label: 'Opened', value: stats.uniqueOpens, total: stats.delivered || stats.sent, variant: 'default' as const },
                            { label: 'Clicked', value: stats.uniqueClicks, total: stats.uniqueOpens || stats.sent, variant: 'default' as const },
                        ].map((step) => {
                            const pct = step.total > 0 ? (step.value / step.total) * 100 : 0;
                            return (
                                <div key={step.label} className="space-y-1.5">
                                    <div className="flex items-center justify-between text-sm">
                                        <span className="font-medium">{step.label}</span>
                                        <span className="tabular-nums text-muted-foreground">
                                            {formatNumber(step.value)} ({pct.toFixed(1)}%)
                                        </span>
                                    </div>
                                    <Progress value={pct} size="sm" indicatorVariant={step.variant} />
                                </div>
                            );
                        })}
                    </CardContent>
                </Card>
            )}

            {/* Campaign Details */}
            <Card className="border-none shadow-premium bg-white overflow-hidden">
                <CardHeader>
                    <CardTitle className="text-lg font-bold">Campaign Details</CardTitle>
                </CardHeader>
                <CardContent>
                    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
                        <DetailRow label="Campaign Name" value={campaign.name || '—'} />
                        <DetailRow label="Subject Line" value={campaign.subject || '—'} />
                        <DetailRow label="From Name" value={campaign.fromName || '—'} />
                        <DetailRow label="From Email" value={campaign.fromEmail || '—'} />
                        <DetailRow label="Audience" value={campaign.listId || 'No audience selected'} />
                        <DetailRow label="Template" value={campaign.templateId || 'Custom content'} />
                        <DetailRow label="Created" value={new Date(campaign.createdAt).toLocaleString()} />
                        <DetailRow label="Last Updated" value={new Date(campaign.updatedAt).toLocaleString()} />
                    </dl>
                </CardContent>
            </Card>

            {/* Delete Confirmation */}
            <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Campaign</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to delete &ldquo;{campaign.name}&rdquo;? This action cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
                        <Button variant="destructive" onClick={handleDelete}>Delete</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Re-send Confirmation */}
            <Dialog open={resendDialogOpen} onOpenChange={setResendDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Confirm Re-send</DialogTitle>
                        <DialogDescription>
                            This will send another copy of this campaign to all recipients. Are you sure?
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setResendDialogOpen(false)}>Cancel</Button>
                        <Button onClick={handleResend} disabled={isResending}>
                            {isResending ? 'Sending…' : 'Confirm Re-send'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}

function StatCard({ label, value, sub, icon, variant = 'default' }: {
    label: string;
    value: string;
    sub?: string;
    icon: React.ReactNode;
    variant?: 'default' | 'warning' | 'error';
}) {
    return (
        <Card className="border-none shadow-premium bg-white">
            <CardContent className="pt-6 pb-4 px-5">
                <div className={cn(
                    'inline-flex items-center justify-center h-9 w-9 rounded-lg mb-3',
                    variant === 'error' ? 'bg-red-100 text-red-600' :
                    variant === 'warning' ? 'bg-amber-100 text-amber-600' :
                    'bg-brand-100 text-brand-600'
                )}>
                    {icon}
                </div>
                <p className="text-2xl font-bold tabular-nums">{value}</p>
                <p className="text-xs font-medium text-muted-foreground mt-0.5">{label}</p>
                {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
            </CardContent>
        </Card>
    );
}

function DetailRow({ label, value }: { label: string; value: string }) {
    return (
        <div>
            <dt className="text-xs font-bold uppercase tracking-wider text-muted-foreground">{label}</dt>
            <dd className="mt-1 text-sm font-medium">{value}</dd>
        </div>
    );
}
