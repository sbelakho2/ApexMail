'use client';

import * as React from 'react';
import { Mail, Plus, Search, MoreHorizontal, Copy, Trash2, Eye, Pencil } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
    DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { formatRelativeTime } from '@/lib/utils';

interface Template {
    id: string;
    name: string;
    subject: string;
    status: string;
    version: number;
    createdAt: string;
    updatedAt: string;
}

export default function TemplatesPage() {
    const [templates, setTemplates] = React.useState<Template[]>([]);
    const [loading, setLoading] = React.useState(true);
    const [search, setSearch] = React.useState('');

    React.useEffect(() => {
        fetch('/api/v1/templates')
            .then(r => r.ok ? r.json() : Promise.reject(r.statusText))
            .then(json => setTemplates(json.templates ?? json.data ?? []))
            .catch(() => setTemplates([]))
            .finally(() => setLoading(false));
    }, []);

    const filtered = templates.filter(t =>
        !search || t.name.toLowerCase().includes(search.toLowerCase()) || t.subject.toLowerCase().includes(search.toLowerCase())
    );

    async function duplicateTemplate(id: string) {
        const res = await fetch(`/api/v1/templates/${id}/duplicate`, { method: 'POST' });
        if (res.ok) {
            const json = await res.json();
            setTemplates(prev => [json.template ?? json, ...prev]);
        }
    }

    async function deleteTemplate(id: string) {
        const res = await fetch(`/api/v1/templates/${id}`, { method: 'DELETE' });
        if (res.ok) setTemplates(prev => prev.filter(t => t.id !== id));
    }

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Templates"
                description="Design and manage your email templates."
                breadcrumbs={[{ label: 'Templates' }]}
                actions={
                    <Button><Plus className="mr-2 h-4 w-4" />New Template</Button>
                }
            />

            <Card>
                <CardHeader>
                    <div className="flex items-center gap-4">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input placeholder="Search templates..." className="pl-9" value={search} onChange={e => setSearch(e.target.value)} />
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    {loading ? (
                        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}</div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16">
                            <Mail className="h-10 w-10 text-muted-foreground mb-4" />
                            <h3 className="font-semibold text-lg">No templates yet</h3>
                            <p className="text-muted-foreground text-sm mt-1 mb-4">Create your first email template to get started.</p>
                            <Button><Plus className="mr-2 h-4 w-4" />Create Template</Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader><TableRow>
                                <TableHead>Name</TableHead><TableHead>Subject</TableHead>
                                <TableHead>Status</TableHead><TableHead>Version</TableHead>
                                <TableHead>Updated</TableHead><TableHead />
                            </TableRow></TableHeader>
                            <TableBody>
                                {filtered.map(t => (
                                    <TableRow key={t.id}>
                                        <TableCell className="font-medium">{t.name}</TableCell>
                                        <TableCell className="text-muted-foreground">{t.subject || '—'}</TableCell>
                                        <TableCell><Badge variant={t.status === 'published' ? 'success' : 'secondary'}>{t.status}</Badge></TableCell>
                                        <TableCell className="apex-metric-number">v{t.version}</TableCell>
                                        <TableCell className="text-muted-foreground text-sm">{formatRelativeTime(new Date(t.updatedAt))}</TableCell>
                                        <TableCell>
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="Template actions"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem><Eye className="mr-2 h-4 w-4" />Preview</DropdownMenuItem>
                                                    <DropdownMenuItem><Pencil className="mr-2 h-4 w-4" />Edit</DropdownMenuItem>
                                                    <DropdownMenuItem onClick={() => duplicateTemplate(t.id)}><Copy className="mr-2 h-4 w-4" />Duplicate</DropdownMenuItem>
                                                    <DropdownMenuItem destructive onClick={() => deleteTemplate(t.id)}><Trash2 className="mr-2 h-4 w-4" />Delete</DropdownMenuItem>
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
