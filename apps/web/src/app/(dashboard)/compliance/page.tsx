'use client';

import * as React from 'react';
import { Shield, Search, Plus, Download, Upload, Trash2, MoreHorizontal, ChevronLeft, ChevronRight } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import {
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { formatNumber, formatRelativeTime } from '@/lib/utils';
import { useAPI, deleteFetcher, postFetcher } from '@/hooks/use-api';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from '@/hooks/use-toast';

interface Suppression {
    id: string;
    email: string;
    reason: string;
    source: string;
    createdAt: string;
}

interface SuppressionStats {
    total: number;
    bounces: number;
    complaints: number;
    unsubscribes: number;
    manual: number;
}

export default function CompliancePage() {
    const [page, setPage] = React.useState(1);
    const pageSize = 50;
    const { data: supData, isLoading: supLoading, mutate: mutateSup } = useAPI<{ suppressions?: Suppression[]; data?: Suppression[]; total?: number; pagination?: { total: number } }>(`/v1/suppressions?limit=${pageSize}&offset=${(page - 1) * pageSize}`);
    const { data: dashData, isLoading: dashLoading } = useAPI<{ dashboard?: { suppressions?: SuppressionStats } }>('/v1/analytics/dashboard');

    const suppressions = supData?.suppressions ?? supData?.data ?? [];
    const totalSuppressions = supData?.pagination?.total ?? supData?.total ?? suppressions.length;
    const totalPages = Math.max(1, Math.ceil(totalSuppressions / pageSize));
    const stats = dashData?.dashboard?.suppressions ?? null;
    const loading = supLoading || dashLoading;

    const [search, setSearch] = React.useState('');
    const [removeTarget, setRemoveTarget] = React.useState<Suppression | null>(null);
    const [addDialogOpen, setAddDialogOpen] = React.useState(false);
    const [addEmail, setAddEmail] = React.useState('');
    const [addReason, setAddReason] = React.useState('manual');
    const [addLoading, setAddLoading] = React.useState(false);

    const [removeError, setRemoveError] = React.useState<string | null>(null);

    const filtered = suppressions.filter(s => !search || s.email.toLowerCase().includes(search.toLowerCase()));

    async function confirmRemoveSuppression() {
        if (!removeTarget) return;
        setRemoveError(null);
        try {
            await deleteFetcher(`/v1/suppressions/${removeTarget.id}`);
            await mutateSup();
        } catch {
            setRemoveError('Failed to remove suppression. Please try again.');
        }
        setRemoveTarget(null);
    }

    async function handleAddSuppression() {
        if (!addEmail.trim()) return;
        setAddLoading(true);
        try {
            await postFetcher('/v1/suppressions', { arg: { email: addEmail.trim(), reason: addReason, source: 'manual' } });
            await mutateSup();
            setAddDialogOpen(false);
            setAddEmail('');
            setAddReason('manual');
            toast({ title: 'Suppression added' });
        } catch {
            toast({ title: 'Failed to add suppression', variant: 'destructive' });
        } finally {
            setAddLoading(false);
        }
    }

    function handleExport() {
        const sanitizeCell = (val: string) => {
            if (/^[=+\-@\t\r]/.test(val)) val = "'" + val;
            if (/[,"\n\r]/.test(val)) return '"' + val.replace(/"/g, '""') + '"';
            return val;
        };
        const header = 'email,reason,source,created_at';
        const rows = suppressions.map(s =>
            [s.email, s.reason, s.source, s.createdAt].map(sanitizeCell).join(',')
        );
        const csv = [header, ...rows].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `suppressions-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }

    const fileInputRef = React.useRef<HTMLInputElement>(null);
    async function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
        const file = e.target.files?.[0];
        if (!file) return;
        const text = await file.text();
        const lines = text.trim().split('\n').slice(1); // skip header
        const rows = lines
            .map((line) => {
                const [email, reason] = line.split(',').map(s => s.trim());
                if (!email) return null;
                return { email, reason: reason || 'manual', source: 'import' as const };
            })
            .filter((row): row is { email: string; reason: string; source: 'import' } => row !== null);

        let imported = 0;
        let failed = 0;
        const chunkSize = 50;
        for (let i = 0; i < rows.length; i += chunkSize) {
            const chunk = rows.slice(i, i + chunkSize);
            const results = await Promise.allSettled(
                chunk.map((row) => postFetcher('/v1/suppressions', { arg: row }))
            );
            imported += results.filter((r) => r.status === 'fulfilled').length;
            failed += results.filter((r) => r.status === 'rejected').length;
        }
        await mutateSup();
        toast({
            title: `Imported ${imported} suppression${imported !== 1 ? 's' : ''}${failed > 0 ? ` • ${failed} failed` : ''}`,
            variant: failed > 0 ? 'destructive' : 'default',
        });
        if (fileInputRef.current) fileInputRef.current.value = '';
    }

    return (
        <div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Compliance"
                description="Manage suppressions, bounces, and regulatory compliance."
                breadcrumbs={[{ label: 'Compliance' }]}
                actions={
                    <>
                    <input ref={fileInputRef} type="file" accept=".csv" className="hidden" onChange={handleImport} />
                    <Button variant="outline" onClick={handleExport} disabled={suppressions.length === 0}><Download className="mr-2 h-4 w-4" />Export</Button>
                    <Button variant="outline" onClick={() => fileInputRef.current?.click()}><Upload className="mr-2 h-4 w-4" />Import</Button>
                    <Button onClick={() => setAddDialogOpen(true)}><Plus className="mr-2 h-4 w-4" />Add Suppression</Button>
                    </>
                }
            />

            {removeError ? (
                <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive" role="alert">
                    {removeError}
                    <button className="ml-2 underline text-xs" onClick={() => setRemoveError(null)}>Dismiss</button>
                </div>
            ) : null}

            {stats && (
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    {[
                        { label: 'Total Suppressions', value: stats.total },
                        { label: 'Bounces', value: stats.bounces },
                        { label: 'Complaints', value: stats.complaints },
                        { label: 'Unsubscribes', value: stats.unsubscribes },
                        { label: 'Manual', value: stats.manual },
                    ].map(s => (
                        <Card key={s.label}>
                            <CardContent className="p-4 text-center">
                                <p className="text-sm text-muted-foreground">{s.label}</p>
                                <p className="text-2xl apex-metric-number mt-1">{formatNumber(s.value)}</p>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )}

            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div><CardTitle>Suppression List</CardTitle><CardDescription>Emails that will not receive future messages</CardDescription></div>
                        <div className="relative w-64">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input placeholder="Search email..." className="pl-9" aria-label="Search suppression list" value={search} onChange={e => setSearch(e.target.value)} />
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    {loading ? (
                        <div className="space-y-3">{Array.from({ length: 3 }, (_, i) => `compliance-skeleton-${i}`).map((skeletonId) => <Skeleton key={skeletonId} className="h-14 w-full" />)}</div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16">
                            <Shield className="h-10 w-10 text-muted-foreground mb-4" />
                            <p className="text-muted-foreground">No suppressions found.</p>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader><TableRow>
                                <TableHead>Email</TableHead><TableHead>Reason</TableHead>
                                <TableHead>Source</TableHead><TableHead>Added</TableHead><TableHead />
                            </TableRow></TableHeader>
                            <TableBody>
                                {filtered.map(s => (
                                    <TableRow key={s.id}>
                                        <TableCell className="font-mono text-sm">{s.email}</TableCell>
                                        <TableCell><Badge variant="secondary">{s.reason}</Badge></TableCell>
                                        <TableCell className="text-muted-foreground">{s.source}</TableCell>
                                        <TableCell className="text-muted-foreground text-sm">{formatRelativeTime(new Date(s.createdAt))}</TableCell>
                                        <TableCell>
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="Suppression actions"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem destructive onClick={() => setRemoveTarget(s)}><Trash2 className="mr-2 h-4 w-4" />Remove</DropdownMenuItem>
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {((page - 1) * pageSize) + 1}–{Math.min(page * pageSize, totalSuppressions)} of {totalSuppressions}
                    </p>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                            <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                        </Button>
                        <span className="text-sm text-muted-foreground">Page {page} of {totalPages}</span>
                        <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                            Next <ChevronRight className="h-4 w-4 ml-1" />
                        </Button>
                    </div>
                </div>
            )}

            <Dialog open={Boolean(removeTarget)} onOpenChange={(open) => !open && setRemoveTarget(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Remove Suppression</DialogTitle>
                        <DialogDescription>
                            Remove the suppression for <span className="font-mono">{removeTarget?.email}</span>? Email delivery to this
                            recipient may resume immediately. Re-add the suppression if this was accidental.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setRemoveTarget(null)}>Cancel</Button>
                        <Button variant="destructive" onClick={confirmRemoveSuppression}>Remove</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Add Suppression</DialogTitle>
                        <DialogDescription>
                            Manually suppress an email address. This address will not receive future messages.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-2">
                        <div className="space-y-2">
                            <Label htmlFor="sup-email">Email address</Label>
                            <Input id="sup-email" type="email" placeholder="user@example.com" value={addEmail} onChange={e => setAddEmail(e.target.value)} />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="sup-reason">Reason</Label>
                            <Select value={addReason} onValueChange={setAddReason}>
                                <SelectTrigger id="sup-reason"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="manual">Manual</SelectItem>
                                    <SelectItem value="bounce">Bounce</SelectItem>
                                    <SelectItem value="complaint">Complaint</SelectItem>
                                    <SelectItem value="unsubscribe">Unsubscribe</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button>
                        <Button onClick={handleAddSuppression} disabled={addLoading || !addEmail.trim()}>
                            {addLoading ? 'Adding…' : 'Add Suppression'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
