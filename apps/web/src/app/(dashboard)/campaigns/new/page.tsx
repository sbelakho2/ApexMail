"use client";

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from '@/hooks/use-toast';
import { useAPIMutation, getCsrfToken } from '@/hooks/use-api';
import { Loader2 } from '@/components/ui/icons';

export default function NewCampaignPage() {
    const router = useRouter();
    const [campaignName, setCampaignName] = React.useState('');
    const [subject, setSubject] = React.useState('');
    const [audience, setAudience] = React.useState('all');
    const [content, setContent] = React.useState('');
    const [timezoneConfirmed, setTimezoneConfirmed] = React.useState(false);
    const [previewDevice, setPreviewDevice] = React.useState<'mobile' | 'tablet' | 'desktop'>('desktop');
    const [showPlainTextPreview, setShowPlainTextPreview] = React.useState(false);
    const [error, setError] = React.useState('');
    const [isSaving, setIsSaving] = React.useState(false);
    const [isScheduling, setIsScheduling] = React.useState(false);

    // Fetch audience lists from API
    const [audienceLists, setAudienceLists] = React.useState<{ id: string; name: string; count: number }[]>([]);
    const [listsLoading, setListsLoading] = React.useState(true);
    const [listsError, setListsError] = React.useState(false);
    React.useEffect(() => {
        const controller = new AbortController();
        fetch('/v1/lists', { credentials: 'include', signal: controller.signal })
            .then(res => res.ok ? res.json() : { lists: [] })
            .then(data => {
                const lists = Array.isArray(data) ? data : (data.lists ?? data.data ?? []);
                if (lists.length > 0) {
                    setAudienceLists(lists.map((l: Record<string, string | number | undefined>) => ({ id: String(l.id ?? l.slug ?? l.name ?? ''), name: String(l.name ?? ''), count: Number(l.subscriberCount ?? l.count ?? 0) })));
                }
            })
            .catch((err) => { if (!controller.signal.aborted) setListsError(true); })
            .finally(() => setListsLoading(false));
        return () => controller.abort();
    }, []);

    // Unsaved changes warning
    React.useEffect(() => {
        const dirty = campaignName.trim() !== '' || subject.trim() !== '' || content.trim() !== '';
        const handler = (e: BeforeUnloadEvent) => { if (dirty) { e.preventDefault(); } };
        window.addEventListener('beforeunload', handler);
        return () => window.removeEventListener('beforeunload', handler);
    }, [campaignName, subject, content]);

    const audienceEstimates: Record<string, number> = Object.fromEntries(
        audienceLists.map(l => [l.id, l.count])
    );

    const checklist = [
        { id: 'subject', label: 'Subject is set', done: subject.trim().length > 0 },
        { id: 'audience', label: 'Audience is selected', done: audience.trim().length > 0 },
        { id: 'content', label: 'Message content is present', done: content.trim().length > 0 },
        { id: 'unsubscribe', label: 'Includes unsubscribe link', done: /unsubscribe|manage preferences/i.test(content) },
    ];

    const plainTextPreview = content
        .replace(/<[^>]*>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    const handleSchedule = async () => {
        setError('');

        if (!campaignName.trim()) {
            setError('Please enter a campaign name.');
            return;
        }

        if (!subject.trim()) {
            setError('Please enter an email subject line.');
            return;
        }

        if (!audience) {
            setError('Select an audience before scheduling this campaign.');
            return;
        }

        if ((audienceEstimates[audience] ?? 0) === 0) {
            setError('Selected audience resolves to zero recipients. Choose a different audience or broaden filters.');
            return;
        }

        if (!/unsubscribe|manage preferences/i.test(content)) {
            setError('Content must include an unsubscribe or manage-preferences link before scheduling.');
            return;
        }

        if (!timezoneConfirmed) {
            setError('Confirm the campaign send timezone before scheduling.');
            return;
        }

        setIsScheduling(true);
        try {
            const csrfToken = await getCsrfToken();
            if (!csrfToken) throw new Error('CSRF token unavailable');

            const res = await fetch('/v1/campaigns', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({
                    name: campaignName,
                    subject,
                    audience,
                    content,
                    status: 'scheduled',
                }),
            });

            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Failed to schedule campaign');
            }

            toast({ title: 'Campaign Scheduled', description: `"${campaignName}" scheduled for ${(audienceEstimates[audience] ?? 0).toLocaleString()} recipients.` });
            router.push('/campaigns');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to schedule campaign. Please try again.');
        } finally {
            setIsScheduling(false);
        }
    };

    const handleSaveDraft = async () => {
        if (!campaignName.trim()) {
            setError('Please enter a campaign name to save.');
            return;
        }

        setIsSaving(true);
        setError('');
        try {
            const csrfToken = await getCsrfToken();
            if (!csrfToken) throw new Error('CSRF token unavailable');

            const res = await fetch('/v1/campaigns', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({
                    name: campaignName,
                    subject,
                    audience,
                    content,
                    status: 'draft',
                }),
            });

            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Failed to save draft');
            }

            toast({ title: 'Draft Saved', description: `"${campaignName}" saved as draft.` });
            router.push('/campaigns');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to save draft. Please try again.');
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="space-y-6">
            <PageHeader
                title="New Campaign"
                description="Create and configure your next campaign."
                breadcrumbs={[{ label: 'Campaigns', href: '/campaigns' }, { label: 'New Campaign' }]}
            />

            {error ? (
                <Card className="border-destructive/30 bg-destructive/10">
                    <CardContent className="p-4 text-sm text-destructive">{error}</CardContent>
                </Card>
            ) : null}

            <Card>
                <CardHeader>
                    <CardTitle>Campaign Setup</CardTitle>
                    <CardDescription>Define audience, message, and scheduling.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-5">
                    <div className="grid gap-2">
                        <Label htmlFor="name">Campaign Name</Label>
                        <Input id="name" value={campaignName} onChange={(e) => setCampaignName(e.target.value)} />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="subject">Email Subject</Label>
                        <Input id="subject" value={subject} onChange={(e) => setSubject(e.target.value)} />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="audience">Audience</Label>
                        <Select value={audience} onValueChange={setAudience}>
                            <SelectTrigger id="audience">
                                <SelectValue placeholder={listsLoading ? 'Loading lists…' : 'Select audience'} />
                            </SelectTrigger>
                            <SelectContent>
                                {audienceLists.length > 0 ? (
                                    audienceLists.map(l => (
                                        <SelectItem key={l.id} value={l.id}>
                                            {l.name} ({l.count.toLocaleString()})
                                        </SelectItem>
                                    ))
                                ) : (
                                    <SelectItem value="all">All Subscribers</SelectItem>
                                )}
                            </SelectContent>
                        </Select>
                        {listsError && (
                            <p className="text-xs text-destructive">Failed to load audience lists. Using default audience.</p>
                        )}
                        <p className="text-xs text-muted-foreground">
                            Estimated recipients: {(audienceEstimates[audience] ?? 0).toLocaleString()}
                        </p>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="content">Content Preview</Label>
                        <Textarea id="content" rows={6} value={content} onChange={(e) => setContent(e.target.value)} />
                    </div>

                    <div className="rounded-lg border border-border p-4 space-y-3">
                        <p className="text-sm font-semibold">Template preview</p>
                        <div className="flex flex-wrap gap-2">
                            {(['mobile', 'tablet', 'desktop'] as const).map((device) => (
                                <Button
                                    key={device}
                                    type="button"
                                    size="sm"
                                    variant={previewDevice === device ? 'default' : 'outline'}
                                    onClick={() => setPreviewDevice(device)}
                                >
                                    {device.charAt(0).toUpperCase() + device.slice(1)}
                                </Button>
                            ))}
                            <Button type="button" size="sm" variant="outline" onClick={() => setShowPlainTextPreview((prev) => !prev)}>
                                {showPlainTextPreview ? 'Hide Plain Text' : 'Show Plain Text'}
                            </Button>
                        </div>
                        <div className={`rounded border bg-muted/20 p-3 text-sm text-muted-foreground ${previewDevice === 'mobile' ? 'max-w-xs' : previewDevice === 'tablet' ? 'max-w-md' : 'max-w-2xl'}`}>
                            <p className="text-xs uppercase tracking-wide mb-2">{previewDevice} preview</p>
                            <p>{content}</p>
                        </div>
                        {showPlainTextPreview ? (
                            <div className="rounded border bg-muted/20 p-3 text-sm text-muted-foreground">
                                <p className="text-xs uppercase tracking-wide mb-2">Plain-text preview</p>
                                <p>{plainTextPreview || 'No plain-text content available yet.'}</p>
                            </div>
                        ) : null}
                    </div>

                    <div className="rounded-lg border border-border bg-muted/20 p-4">
                        <p className="text-sm font-semibold mb-2">Pre-send checklist</p>
                        <ul className="space-y-1 text-sm text-muted-foreground">
                            {checklist.map((item) => (
                                <li key={item.id} className="flex items-center gap-2">
                                    <span className={`inline-block h-2 w-2 rounded-full ${item.done ? 'bg-success' : 'bg-warning'}`} aria-hidden="true" />
                                    <span>{item.label}</span>
                                </li>
                            ))}
                        </ul>
                    </div>

                    <div className="rounded-lg border border-border p-4">
                        <p className="text-sm font-semibold">Send-time timezone confirmation</p>
                        <p className="text-xs text-muted-foreground mt-1">Campaign send time will use your workspace timezone: UTC.</p>
                        <label className="mt-3 inline-flex items-center gap-2 text-sm text-muted-foreground">
                            <input
                                type="checkbox"
                                checked={timezoneConfirmed}
                                onChange={(e) => setTimezoneConfirmed(e.target.checked)}
                                className="h-4 w-4"
                            />
                            I confirm the timezone for this send.
                        </label>
                    </div>

                    <div className="sticky bottom-4 z-20 -mx-2 mt-2 rounded-xl border bg-background/95 p-3 backdrop-blur">
                        <div className="flex justify-end gap-3">
                            <Button variant="outline" onClick={handleSaveDraft} disabled={isSaving || isScheduling}>
                                {isSaving ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Saving...</> : 'Save Draft'}
                            </Button>
                            <Button onClick={handleSchedule} disabled={isSaving || isScheduling}>
                                {isScheduling ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Scheduling...</> : 'Schedule Campaign'}
                            </Button>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}