"use client";

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from '@/hooks/use-toast';
import { useCampaign, useUpdateCampaign, getCsrfToken } from '@/hooks/use-api';
import { Loader2, ArrowLeft } from '@/components/ui/icons';
import { PageLoadingState, PageErrorState } from '@/components/ui/async-state';

export default function EditCampaignPage() {
    const params = useParams<{ id: string }>();
    const router = useRouter();
    const { data: campaign, isLoading, error } = useCampaign(params.id);
    const { trigger: updateCampaign, isMutating } = useUpdateCampaign(params.id);

    const [campaignName, setCampaignName] = React.useState('');
    const [subject, setSubject] = React.useState('');
    const [audience, setAudience] = React.useState('all');
    const [content, setContent] = React.useState('');
    const [formError, setFormError] = React.useState('');
    const [initialized, setInitialized] = React.useState(false);

    // Fetch audience lists
    const [audienceLists, setAudienceLists] = React.useState<{ id: string; name: string; count: number }[]>([]);
    const [listsError, setListsError] = React.useState(false);
    React.useEffect(() => {
        const controller = new AbortController();
        fetch('/v1/lists', { credentials: 'include', signal: controller.signal })
            .then(res => res.ok ? res.json() : { lists: [] })
            .then(data => {
                const lists = Array.isArray(data) ? data : (data.lists ?? data.data ?? []);
                if (lists.length > 0) {
                    setAudienceLists(lists.map((l: any) => ({ id: l.id ?? l.slug ?? l.name, name: l.name, count: l.subscriberCount ?? l.count ?? 0 })));
                }
            })
            .catch((err) => { if (!controller.signal.aborted) setListsError(true); });
        return () => controller.abort();
    }, []);

    // Unsaved changes warning
    React.useEffect(() => {
        if (!initialized) return;
        const original = campaign;
        const dirty = (original && (
            campaignName !== (original.name || '') ||
            subject !== (original.subject || '') ||
            content !== (original.content || '')
        ));
        const handler = (e: BeforeUnloadEvent) => { if (dirty) { e.preventDefault(); } };
        window.addEventListener('beforeunload', handler);
        return () => window.removeEventListener('beforeunload', handler);
    }, [campaignName, subject, content, campaign, initialized]);

    // Pre-fill form with campaign data
    React.useEffect(() => {
        if (campaign && !initialized) {
            setCampaignName(campaign.name || '');
            setSubject(campaign.subject || '');
            setAudience(campaign.listId || 'all');
            setContent(campaign.content || '');
            setInitialized(true);
        }
    }, [campaign, initialized]);

    if (isLoading) {
        return <PageLoadingState label="Loading campaign…" />;
    }

    if (error || !campaign) {
        return (
            <PageErrorState
                title="Campaign not found"
                description="The campaign you're trying to edit does not exist."
                retryLabel="Back to Campaigns"
                onRetry={() => router.push('/campaigns')}
            />
        );
    }

    if (campaign.status !== 'draft') {
        return (
            <PageErrorState
                title="Cannot edit campaign"
                description="Only draft campaigns can be edited. This campaign has already been sent or scheduled."
                retryLabel="View Campaign"
                onRetry={() => router.push(`/campaigns/${params.id}`)}
            />
        );
    }

    const handleSave = async () => {
        if (!campaignName.trim()) {
            setFormError('Campaign name is required.');
            return;
        }
        if (!subject.trim()) {
            setFormError('Subject line is required.');
            return;
        }

        setFormError('');
        try {
            await updateCampaign({
                name: campaignName,
                subject,
                listId: audience,
                content,
            });

            toast({ title: 'Campaign Updated', description: `"${campaignName}" has been saved.` });
            router.push(`/campaigns/${params.id}`);
        } catch (err) {
            setFormError(err instanceof Error ? err.message : 'Failed to save campaign changes.');
        }
    };

    return (
        <div className="space-y-6">
            <PageHeader
                title="Edit Campaign"
                description={`Editing "${campaign.name}"`}
                breadcrumbs={[
                    { label: 'Campaigns', href: '/campaigns' },
                    { label: campaign.name || 'Untitled', href: `/campaigns/${params.id}` },
                    { label: 'Edit' },
                ]}
                actions={
                    <Button variant="ghost" size="sm" onClick={() => router.push(`/campaigns/${params.id}`)}>
                        <ArrowLeft className="mr-2 h-4 w-4" />
                        Back to Campaign
                    </Button>
                }
            />

            {formError && (
                <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-4 text-sm text-destructive">
                    {formError}
                </div>
            )}

            <Card>
                <CardHeader>
                    <CardTitle>Campaign Details</CardTitle>
                    <CardDescription>Update the campaign name, subject, and audience.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="campaign-name">Campaign Name</Label>
                        <Input
                            id="campaign-name"
                            placeholder="My Campaign"
                            value={campaignName}
                            onChange={(e) => setCampaignName(e.target.value)}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="subject">Subject Line</Label>
                        <Input
                            id="subject"
                            placeholder="Hello {{first_name}}, check this out!"
                            value={subject}
                            onChange={(e) => setSubject(e.target.value)}
                        />
                        <p className="text-xs text-muted-foreground">
                            Supports merge tags: {'{{first_name}}'}, {'{{company}}'}, etc.
                        </p>
                    </div>
                    <div className="space-y-2">
                        <Label>Audience</Label>
                        <Select value={audience} onValueChange={setAudience}>
                            <SelectTrigger>
                                <SelectValue placeholder="Select audience" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Subscribers</SelectItem>
                                {audienceLists.map((list) => (
                                    <SelectItem key={list.id} value={list.id}>
                                        {list.name} ({list.count.toLocaleString()})
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Email Content</CardTitle>
                    <CardDescription>Edit the HTML content of this campaign.</CardDescription>
                </CardHeader>
                <CardContent>
                    <Textarea
                        value={content}
                        onChange={(e) => setContent(e.target.value)}
                        rows={16}
                        className="font-mono text-sm"
                        placeholder="<html>...</html>"
                    />
                </CardContent>
            </Card>

            <div className="flex items-center justify-end gap-3 pb-8">
                <Button variant="outline" onClick={() => router.push(`/campaigns/${params.id}`)}>
                    Cancel
                </Button>
                <Button onClick={handleSave} disabled={isMutating}>
                    {isMutating ? (
                        <>
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            Saving...
                        </>
                    ) : (
                        'Save Changes'
                    )}
                </Button>
            </div>
        </div>
    );
}
