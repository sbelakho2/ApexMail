'use client';

import * as React from 'react';
import { Shield, Search, Plus, Download, Upload, Trash2, MoreHorizontal } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { formatNumber, formatRelativeTime } from '@/lib/utils';

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
    const [suppressions, setSuppressions] = React.useState<Suppression[]>([]);
    const [stats, setStats] = React.useState<SuppressionStats | null>(null);
    const [loading, setLoading] = React.useState(true);
    const [search, setSearch] = React.useState('');

    React.useEffect(() => {
        Promise.allSettled([
            fetch('/v1/suppressions?limit=50'),
            fetch('/v1/analytics/dashboard'),
        ]).then(async ([supRes, dashRes]) => {
            if (supRes.status === 'fulfilled' && supRes.value.ok) {
                const json = await supRes.value.json();
                setSuppressions(json.suppressions ?? json.data ?? []);
            }
            if (dashRes.status === 'fulfilled' && dashRes.value.ok) {
                const json = await dashRes.value.json();
                setStats(json.dashboard?.suppressions ?? null);
            }
        }).finally(() => setLoading(false));
    }, []);

    const filtered = suppressions.filter(s => !search || s.email.toLowerCase().includes(search.toLowerCase()));

    async function removeSuppression(id: string) {
        const confirmed = window.confirm(
            'Remove this suppression entry? Email delivery to this recipient may resume immediately. Re-add the suppression if this was accidental.'
        );
        if (!confirmed) return;

        const res = await fetch(`/v1/suppressions/${id}`, { method: 'DELETE' });
        if (res.ok) setSuppressions(prev => prev.filter(s => s.id !== id));
    }

    return (
        <div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Compliance"
                description="Manage suppressions, bounces, and regulatory compliance."
                breadcrumbs={[{ label: 'Compliance' }]}
                actions={
                    <><Button variant="outline"><Download className="mr-2 h-4 w-4" />Export</Button>
                    <Button variant="outline"><Upload className="mr-2 h-4 w-4" />Import</Button>
                    <Button><Plus className="mr-2 h-4 w-4" />Add Suppression</Button></>
                }
            />

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
                            <Input placeholder="Search email..." className="pl-9" value={search} onChange={e => setSearch(e.target.value)} />
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    {loading ? (
                        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}</div>
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
                                                    <DropdownMenuItem destructive onClick={() => removeSuppression(s.id)}><Trash2 className="mr-2 h-4 w-4" />Remove</DropdownMenuItem>
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
        </div>
    );
}
