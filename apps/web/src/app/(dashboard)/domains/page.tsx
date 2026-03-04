'use client';

import * as React from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from '@/components/ui/dialog';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Globe,
    Plus,
    RefreshCw,
    Shield,
    Check,
    AlertTriangle,
    Copy,
    Trash2,
    Loader2,
    ChevronDown,
    ChevronRight,
} from '@/components/ui/icons';
import { useAPI, getCsrfToken, globalMutate } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import { cn, formatDate } from '@/lib/utils';

interface Domain {
    id: string;
    domain: string;
    status: 'pending' | 'verified' | 'failed' | 'expired';
    verifiedAt?: string;
    healthStatus?: 'healthy' | 'warning' | 'critical' | 'unknown';
    createdAt: string;
}

interface DnsRecord {
    type: string;
    name: string;
    value: string;
    purpose: string;
}

interface AuthStatus {
    domain: string;
    score: number;
    grade: string;
    recommendations: string[];
    breakdown: Record<string, { status: string; points: number; maxPoints: number }>;
}

interface DomainsResponse {
    domains: Domain[];
    pagination: { total: number; limit: number; offset: number; hasMore: boolean };
}

const statusColors: Record<string, string> = {
    verified: 'success',
    pending: 'warning',
    failed: 'destructive',
    expired: 'secondary',
};

const healthColors: Record<string, string> = {
    healthy: 'text-green-600',
    warning: 'text-amber-600',
    critical: 'text-red-600',
    unknown: 'text-muted-foreground',
};

export default function DomainsPage() {
    const { toast } = useToast();
    const { data, isLoading, mutate } = useAPI<DomainsResponse>('/v1/domains?limit=100');
    const [addDialogOpen, setAddDialogOpen] = React.useState(false);
    const [domainInput, setDomainInput] = React.useState('');
    const [addLoading, setAddLoading] = React.useState(false);
    const [verifyingId, setVerifyingId] = React.useState<string | null>(null);
    const [deletingId, setDeletingId] = React.useState<string | null>(null);
    const [deleteConfirmId, setDeleteConfirmId] = React.useState<string | null>(null);
    const [expandedId, setExpandedId] = React.useState<string | null>(null);
    const [dnsRecords, setDnsRecords] = React.useState<Record<string, DnsRecord[]>>({});
    const [authStatuses, setAuthStatuses] = React.useState<Record<string, AuthStatus>>({});
    const [loadingDns, setLoadingDns] = React.useState<string | null>(null);
    const [dnsError, setDnsError] = React.useState<string | null>(null);

    const domains = data?.domains ?? [];

    const handleAddDomain = async () => {
        const domain = domainInput.trim();
        if (!domain) return;

        // Client-side domain format validation
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domain)) {
            toast({ title: 'Invalid domain', description: 'Enter a valid domain name (e.g., example.com or mail.example.com)', variant: 'destructive' });
            return;
        }

        setAddLoading(true);
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/domains', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ domain }),
            });

            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || data.message || 'Failed to add domain');
            }

            toast({ title: 'Domain added', description: `${domainInput} has been added. Configure your DNS records below.` });
            setDomainInput('');
            setAddDialogOpen(false);
            await mutate();
        } catch (err) {
            toast({ title: 'Error', description: err instanceof Error ? err.message : 'Failed to add domain', variant: 'destructive' });
        } finally {
            setAddLoading(false);
        }
    };

    const handleVerify = async (id: string) => {
        setVerifyingId(id);
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/domains/${encodeURIComponent(id)}/verify`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });

            const data = await res.json().catch(() => ({}));

            if (data.verified) {
                toast({ title: 'Domain verified!', description: 'Your domain has been successfully verified.' });
            } else {
                toast({ title: 'Verification pending', description: data.message || 'DNS records not yet detected. Please wait for propagation (up to 48 hours).', variant: 'destructive' });
            }
            await mutate();
        } catch {
            toast({ title: 'Error', description: 'Failed to verify domain', variant: 'destructive' });
        } finally {
            setVerifyingId(null);
        }
    };

    const handleDelete = async (id: string) => {
        setDeletingId(id);
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/domains/${encodeURIComponent(id)}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });

            if (!res.ok) throw new Error('Failed to delete domain');
            toast({ title: 'Domain removed' });
            await mutate();
        } catch {
            toast({ title: 'Error', description: 'Failed to remove domain', variant: 'destructive' });
        } finally {
            setDeletingId(null);
        }
    };

    const handleExpand = async (id: string) => {
        if (expandedId === id) {
            setExpandedId(null);
            return;
        }

        setExpandedId(id);

        // Fetch DNS records + auth status if not already loaded
        if (!dnsRecords[id]) {
            setLoadingDns(id);
            setDnsError(null);
            try {
                const [dnsRes, authRes] = await Promise.all([
                    fetch(`/v1/domains/${encodeURIComponent(id)}/dns-records`, { credentials: 'include' }),
                    fetch(`/v1/domains/${encodeURIComponent(id)}/auth-status`, { credentials: 'include' }),
                ]);

                if (dnsRes.ok) {
                    const dnsData = await dnsRes.json();
                    setDnsRecords(prev => ({ ...prev, [id]: dnsData.records ?? [] }));
                }
                if (authRes.ok) {
                    const authData = await authRes.json();
                    setAuthStatuses(prev => ({ ...prev, [id]: authData }));
                }
                if (!dnsRes.ok && !authRes.ok) {
                    setDnsError('Failed to load DNS configuration. Expand again to retry.');
                }
            } catch {
                setDnsError('Failed to load DNS configuration. Expand again to retry.');
            } finally {
                setLoadingDns(null);
            }
        }
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text).catch(() => {});
        toast({ title: 'Copied to clipboard' });
    };

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Domains"
                description="Manage your sending domains and DNS configuration."
                breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Domains' }]}
                actions={
                    <Button onClick={() => setAddDialogOpen(true)}>
                        <Plus className="mr-2 h-4 w-4" />Add Domain
                    </Button>
                }
            />

            {/* Domain Setup Guide */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Domain Authentication
                    </CardTitle>
                    <CardDescription>
                        Authenticate your sending domains with SPF, DKIM, and DMARC to improve deliverability and prevent spoofing.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid gap-4 sm:grid-cols-3">
                        <div className="rounded-lg border p-4">
                            <div className="text-sm font-medium mb-1">1. Add Domain</div>
                            <p className="text-xs text-muted-foreground">Enter your sending domain to get DNS records</p>
                        </div>
                        <div className="rounded-lg border p-4">
                            <div className="text-sm font-medium mb-1">2. Configure DNS</div>
                            <p className="text-xs text-muted-foreground">Add the provided SPF, DKIM, and DMARC records</p>
                        </div>
                        <div className="rounded-lg border p-4">
                            <div className="text-sm font-medium mb-1">3. Verify</div>
                            <p className="text-xs text-muted-foreground">Click verify once DNS has propagated (up to 48h)</p>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Domains List */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <CardTitle>Sending Domains ({domains.length})</CardTitle>
                        <Button variant="outline" size="sm" onClick={() => mutate()}>
                            <RefreshCw className="mr-2 h-4 w-4" />Refresh
                        </Button>
                    </div>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="flex items-center justify-center py-12">
                            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                        </div>
                    ) : domains.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-center">
                            <Globe className="h-10 w-10 text-muted-foreground mb-3" />
                            <p className="text-sm font-medium">No domains configured</p>
                            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                                Add a domain to start sending emails. You&apos;ll need access to your domain&apos;s DNS settings.
                            </p>
                            <Button className="mt-4" onClick={() => setAddDialogOpen(true)}>
                                <Plus className="mr-2 h-4 w-4" />Add Your First Domain
                            </Button>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {domains.map(domain => (
                                <div key={domain.id} className="rounded-lg border">
                                    <div
                                        className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/50 transition-colors"
                                        onClick={() => handleExpand(domain.id)}
                                    >
                                        <div className="flex items-center gap-3">
                                            {expandedId === domain.id ? (
                                                <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                            ) : (
                                                <ChevronRight className="h-4 w-4 text-muted-foreground" />
                                            )}
                                            <Globe className="h-4 w-4" />
                                            <span className="font-mono text-sm font-medium">{domain.domain}</span>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            {domain.healthStatus && (
                                                <span className={cn('text-xs font-medium capitalize', healthColors[domain.healthStatus])}>
                                                    {domain.healthStatus}
                                                </span>
                                            )}
                                            <Badge variant={statusColors[domain.status] as 'success' | 'warning' | 'destructive' | 'secondary'}>
                                                {domain.status}
                                            </Badge>
                                            {domain.status === 'pending' && (
                                                <Button
                                                    size="sm"
                                                    variant="outline"
                                                    disabled={verifyingId === domain.id}
                                                    onClick={(e) => { e.stopPropagation(); handleVerify(domain.id); }}
                                                >
                                                    {verifyingId === domain.id ? (
                                                        <Loader2 className="h-3 w-3 animate-spin" />
                                                    ) : (
                                                        'Verify'
                                                    )}
                                                </Button>
                                            )}
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                className="text-destructive"
                                                disabled={deletingId === domain.id}
                                                onClick={(e) => { e.stopPropagation(); setDeleteConfirmId(domain.id); }}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>

                                    {/* Expanded DNS Records & Auth Status */}
                                    {expandedId === domain.id && (
                                        <div className="border-t px-4 py-4 space-y-4 bg-muted/20">
                                            {loadingDns === domain.id ? (
                                                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                                    <Loader2 className="h-4 w-4 animate-spin" />Loading DNS configuration...
                                                </div>
                                            ) : dnsError && !dnsRecords[domain.id] ? (
                                                <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive flex items-center justify-between">
                                                    <span>{dnsError}</span>
                                                    <Button variant="ghost" size="sm" onClick={() => { setDnsRecords(prev => { const next = { ...prev }; delete next[domain.id]; return next; }); handleExpand(domain.id); handleExpand(domain.id); }}>
                                                        <RefreshCw className="h-3 w-3 mr-1" />Retry
                                                    </Button>
                                                </div>
                                            ) : (
                                                <>
                                                    {/* Auth Score */}
                                                    {authStatuses[domain.id] && (
                                                        <div className="rounded-lg border p-4">
                                                            <div className="flex items-center justify-between mb-3">
                                                                <h4 className="text-sm font-medium">Authentication Score</h4>
                                                                <div className="flex items-center gap-2">
                                                                    <span className={cn(
                                                                        'text-2xl font-bold',
                                                                        authStatuses[domain.id].score >= 80 ? 'text-green-600' :
                                                                        authStatuses[domain.id].score >= 50 ? 'text-amber-600' : 'text-red-600'
                                                                    )}>
                                                                        {authStatuses[domain.id].grade}
                                                                    </span>
                                                                    <span className="text-sm text-muted-foreground">
                                                                        ({authStatuses[domain.id].score}/100)
                                                                    </span>
                                                                </div>
                                                            </div>
                                                            {authStatuses[domain.id].recommendations.length > 0 && (
                                                                <div className="space-y-1">
                                                                    <p className="text-xs font-medium text-muted-foreground">Recommendations:</p>
                                                                    {authStatuses[domain.id].recommendations.map((rec, i) => (
                                                                        <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                                                                            <AlertTriangle className="h-3 w-3 text-amber-500 mt-0.5 flex-shrink-0" />
                                                                            {rec}
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}

                                                    {/* DNS Records */}
                                                    {dnsRecords[domain.id] && dnsRecords[domain.id].length > 0 && (
                                                        <div>
                                                            <h4 className="text-sm font-medium mb-2">DNS Records to Configure</h4>
                                                            <Table>
                                                                <TableHeader>
                                                                    <TableRow>
                                                                        <TableHead className="w-24">Type</TableHead>
                                                                        <TableHead className="w-32">Purpose</TableHead>
                                                                        <TableHead>Name</TableHead>
                                                                        <TableHead>Value</TableHead>
                                                                        <TableHead className="w-12"></TableHead>
                                                                    </TableRow>
                                                                </TableHeader>
                                                                <TableBody>
                                                                    {dnsRecords[domain.id].map((record, i) => (
                                                                        <TableRow key={i}>
                                                                            <TableCell>
                                                                                <Badge variant="outline">{record.type}</Badge>
                                                                            </TableCell>
                                                                            <TableCell className="text-xs font-medium">{record.purpose}</TableCell>
                                                                            <TableCell className="font-mono text-xs break-all">{record.name}</TableCell>
                                                                            <TableCell className="font-mono text-xs break-all max-w-xs truncate" title={record.value}>
                                                                                {record.value}
                                                                            </TableCell>
                                                                            <TableCell>
                                                                                <Button
                                                                                    variant="ghost"
                                                                                    size="sm"
                                                                                    onClick={() => copyToClipboard(record.value)}
                                                                                >
                                                                                    <Copy className="h-3 w-3" />
                                                                                </Button>
                                                                            </TableCell>
                                                                        </TableRow>
                                                                    ))}
                                                                </TableBody>
                                                            </Table>
                                                        </div>
                                                    )}

                                                    {/* Domain Info */}
                                                    <div className="text-xs text-muted-foreground space-y-1">
                                                        <p>Added: {formatDate(domain.createdAt)}</p>
                                                        {domain.verifiedAt && <p>Verified: {formatDate(domain.verifiedAt)}</p>}
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Add Domain Dialog */}
            <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Add Sending Domain</DialogTitle>
                        <DialogDescription>
                            Enter the domain you want to send emails from. You&apos;ll need to add DNS records to verify ownership.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                        <div className="space-y-2">
                            <Label htmlFor="domain-input">Domain Name</Label>
                            <Input
                                id="domain-input"
                                placeholder="example.com"
                                value={domainInput}
                                onChange={(e) => setDomainInput(e.target.value)}
                                onKeyDown={(e) => { if (e.key === 'Enter') handleAddDomain(); }}
                            />
                            <p className="text-xs text-muted-foreground">
                                Enter the root domain or subdomain (e.g. mail.example.com) you want to send from.
                            </p>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button>
                        <Button onClick={handleAddDomain} disabled={addLoading || !domainInput.trim()}>
                            {addLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Adding...</> : 'Add Domain'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Delete Confirmation Dialog */}
            <Dialog open={!!deleteConfirmId} onOpenChange={(open) => { if (!open) setDeleteConfirmId(null); }}>
                <DialogContent className="sm:max-w-[420px]">
                    <DialogHeader>
                        <DialogTitle>Delete Domain</DialogTitle>
                        <DialogDescription>
                            Are you sure you want to remove <strong>{domains.find(d => d.id === deleteConfirmId)?.domain}</strong>? This will stop all email sending from this domain and cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteConfirmId(null)}>Cancel</Button>
                        <Button
                            variant="destructive"
                            disabled={deletingId === deleteConfirmId}
                            onClick={async () => {
                                if (deleteConfirmId) {
                                    await handleDelete(deleteConfirmId);
                                    setDeleteConfirmId(null);
                                }
                            }}
                        >
                            {deletingId === deleteConfirmId ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Deleting...</> : 'Delete Domain'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
