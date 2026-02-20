'use client';

import * as React from 'react';
import { Plus, Search, Users, Upload, MoreHorizontal, Trash2, Pencil } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { formatNumber, formatRelativeTime } from '@/lib/utils';

interface ContactList {
    id: string;
    name: string;
    description: string;
    subscriberCount: number;
    status: 'active' | 'archived';
    createdAt: string;
    updatedAt: string;
}

export default function ListsPage() {
    const [lists, setLists] = React.useState<ContactList[]>([]);
    const [loading, setLoading] = React.useState(true);
    const [search, setSearch] = React.useState('');

    React.useEffect(() => {
        // Fetch from events endpoint as a proxy for subscriber data
        fetch('/api/v1/events/lists')
            .then(r => r.ok ? r.json() : Promise.reject())
            .then(json => setLists(json.lists ?? json.data ?? []))
            .catch(() => setLists([]))
            .finally(() => setLoading(false));
    }, []);

    const filtered = lists.filter(l => !search || l.name.toLowerCase().includes(search.toLowerCase()));

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Lists"
                description="Manage your contact lists and segments."
                breadcrumbs={[{ label: 'Lists' }]}
                actions={
                    <><Button variant="outline"><Upload className="mr-2 h-4 w-4" />Import CSV</Button>
                    <Button><Plus className="mr-2 h-4 w-4" />New List</Button></>
                }
            />

            <Card>
                <CardHeader>
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input placeholder="Search lists..." className="pl-9" value={search} onChange={e => setSearch(e.target.value)} />
                    </div>
                </CardHeader>
                <CardContent>
                    {loading ? (
                        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}</div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16">
                            <Users className="h-10 w-10 text-muted-foreground mb-4" />
                            <h3 className="font-semibold text-lg">No contact lists yet</h3>
                            <p className="text-muted-foreground text-sm mt-1 mb-4">Create your first list or import contacts to get started.</p>
                            <div className="flex items-center gap-3">
                                <Button variant="outline"><Upload className="mr-2 h-4 w-4" />Import CSV</Button>
                                <Button><Plus className="mr-2 h-4 w-4" />Create List</Button>
                            </div>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader><TableRow>
                                <TableHead>Name</TableHead><TableHead>Subscribers</TableHead>
                                <TableHead>Status</TableHead><TableHead>Updated</TableHead><TableHead />
                            </TableRow></TableHeader>
                            <TableBody>
                                {filtered.map(l => (
                                    <TableRow key={l.id}>
                                        <TableCell><p className="font-medium">{l.name}</p><p className="text-sm text-muted-foreground">{l.description || '—'}</p></TableCell>
                                        <TableCell className="apex-metric-number">{formatNumber(l.subscriberCount)}</TableCell>
                                        <TableCell><Badge variant={l.status === 'active' ? 'success' : 'secondary'}>{l.status}</Badge></TableCell>
                                        <TableCell className="text-muted-foreground text-sm">{formatRelativeTime(new Date(l.updatedAt))}</TableCell>
                                        <TableCell>
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="List actions"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem><Pencil className="mr-2 h-4 w-4" />Edit</DropdownMenuItem>
                                                    <DropdownMenuItem destructive><Trash2 className="mr-2 h-4 w-4" />Delete</DropdownMenuItem>
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
