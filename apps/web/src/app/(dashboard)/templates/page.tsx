'use client';

import * as React from 'react';
import { Mail, Plus, Search, MoreHorizontal, Copy, Trash2, Eye, Pencil } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
    DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { formatRelativeTime } from '@/lib/utils';

interface Template {
    id: string;
    name: string;
    subject: string;
    status: string;
    version: number;
    content?: string;
    versions?: Array<{ version: number; updatedAt: string; updatedBy?: string }>;
    createdAt: string;
    updatedAt: string;
}

function getTemplateVariables(content: string) {
    const found = new Set<string>();
    const regex = /\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g;
    let match = regex.exec(content);
    while (match) {
        found.add(match[1]);
        match = regex.exec(content);
    }
    return [...found];
}

export default function TemplatesPage() {
    const [templates, setTemplates] = React.useState<Template[]>([]);
    const [loading, setLoading] = React.useState(true);
    const [search, setSearch] = React.useState('');
    const [notice, setNotice] = React.useState('');
    const [error, setError] = React.useState('');
    const [previewTemplate, setPreviewTemplate] = React.useState<Template | null>(null);
    const [previewDarkMode, setPreviewDarkMode] = React.useState(false);
    const [previewRtl, setPreviewRtl] = React.useState(false);
    const [editTemplate, setEditTemplate] = React.useState<Template | null>(null);
    const [editContent, setEditContent] = React.useState('');

    const requiredVariables = ['first_name', 'unsubscribe_url'];

    React.useEffect(() => {
        fetch('/v1/templates')
            .then(r => r.ok ? r.json() : Promise.reject(r.statusText))
            .then(json => setTemplates(json.templates ?? json.data ?? []))
            .catch(() => setTemplates([]))
            .finally(() => setLoading(false));
    }, []);

    const filtered = templates.filter(t =>
        !search || t.name.toLowerCase().includes(search.toLowerCase()) || t.subject.toLowerCase().includes(search.toLowerCase())
    );

    async function duplicateTemplate(template: Template) {
        setNotice('');
        setError('');
        const duplicateName = `${template.name} (Copy)`;

        if (templates.some((item) => item.name.toLowerCase() === duplicateName.toLowerCase())) {
            setError(`A template named "${duplicateName}" already exists. Rename the existing copy or edit before duplicating again.`);
            return;
        }

        const res = await fetch(`/v1/templates/${template.id}/duplicate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: duplicateName }),
        });

        if (!res.ok) {
            setError('Failed to duplicate template. Please retry.');
            return;
        }

        const json = await res.json();
        setTemplates(prev => [json.template ?? json, ...prev]);
        setNotice(`Template duplicated as "${duplicateName}".`);
    }

    async function deleteTemplate(id: string) {
        setNotice('');
        setError('');
        const confirmed = window.confirm(
            'Delete this template permanently? This action cannot be undone. If removed by mistake, recreate it from version history or a duplicate.'
        );
        if (!confirmed) return;

        const res = await fetch(`/v1/templates/${id}`, { method: 'DELETE' });
        if (res.ok) {
            setTemplates(prev => prev.filter(t => t.id !== id));
            setNotice('Template deleted.');
            return;
        }

        setError('Failed to delete template.');
    }

    function openEditor(template: Template) {
        setEditTemplate(template);
        setEditContent(template.content ?? 'Hello {{first_name}},\n\nYour update is ready.\n\nManage preferences: {{unsubscribe_url}}');
        setNotice('');
        setError('');
    }

    function validateTemplateVariables(content: string) {
        const variables = getTemplateVariables(content);
        const missing = requiredVariables.filter((name) => !variables.includes(name));
        if (missing.length > 0) {
            setError(`Missing required variables: ${missing.join(', ')}.`);
            return false;
        }
        return true;
    }

    async function saveTemplateChanges() {
        if (!editTemplate) return;
        setNotice('');
        setError('');

        if (!validateTemplateVariables(editContent)) return;

        const res = await fetch(`/v1/templates/${editTemplate.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: editContent }),
        });

        if (!res.ok) {
            setError('Failed to save template.');
            return;
        }

        setTemplates(prev => prev.map((item) => {
            if (item.id !== editTemplate.id) return item;
            return {
                ...item,
                content: editContent,
                version: (item.version ?? 1) + 1,
                updatedAt: new Date().toISOString(),
                versions: [
                    { version: (item.version ?? 1) + 1, updatedAt: new Date().toISOString(), updatedBy: 'Current User' },
                    ...(item.versions ?? []),
                ],
            };
        }));

        setEditTemplate(null);
        setNotice('Template saved after variable validation.');
    }

    function rollbackTemplate(templateId: string, version: number) {
        setTemplates(prev => prev.map((item) => {
            if (item.id !== templateId) return item;
            return {
                ...item,
                version,
                updatedAt: new Date().toISOString(),
            };
        }));
        setNotice(`Rolled back template to v${version}.`);
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
                    {notice ? <p className="mb-3 text-sm text-foreground">{notice}</p> : null}
                    {error ? <p className="mb-3 text-sm text-destructive">{error}</p> : null}

                    {loading ? (
                        <div className="space-y-4">
                            <div className="grid gap-3 md:grid-cols-3">
                                <Skeleton className="h-24 w-full" />
                                <Skeleton className="h-24 w-full" />
                                <Skeleton className="h-24 w-full" />
                            </div>
                            <div className="space-y-3">
                                {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}
                            </div>
                        </div>
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
                                                    <DropdownMenuItem onClick={() => setPreviewTemplate(t)}><Eye className="mr-2 h-4 w-4" />Preview</DropdownMenuItem>
                                                    <DropdownMenuItem onClick={() => openEditor(t)}><Pencil className="mr-2 h-4 w-4" />Edit</DropdownMenuItem>
                                                    <DropdownMenuItem onClick={() => duplicateTemplate(t)}><Copy className="mr-2 h-4 w-4" />Duplicate</DropdownMenuItem>
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

            <Dialog open={Boolean(previewTemplate)} onOpenChange={(open) => !open && setPreviewTemplate(null)}>
                <DialogContent size="lg">
                    <DialogHeader>
                        <DialogTitle>Template Preview</DialogTitle>
                        <DialogDescription>Preview template in different reading modes.</DialogDescription>
                    </DialogHeader>
                    <div className="flex flex-wrap items-center gap-4 py-2">
                        <label className="flex items-center gap-2 text-sm">
                            <Switch checked={previewDarkMode} onCheckedChange={setPreviewDarkMode} />
                            Dark mode
                        </label>
                        <label className="flex items-center gap-2 text-sm">
                            <Switch checked={previewRtl} onCheckedChange={setPreviewRtl} />
                            RTL
                        </label>
                    </div>
                    <div
                        dir={previewRtl ? 'rtl' : 'ltr'}
                        className={previewDarkMode ? 'rounded-lg border p-4 bg-surface-900 text-surface-50' : 'rounded-lg border p-4 bg-background text-foreground'}
                    >
                        <p className="font-semibold mb-2">{previewTemplate?.subject || 'No subject'}</p>
                        <p className="text-sm whitespace-pre-wrap">{previewTemplate?.content || 'Template content preview unavailable.'}</p>
                    </div>
                </DialogContent>
            </Dialog>

            <Dialog open={Boolean(editTemplate)} onOpenChange={(open) => !open && setEditTemplate(null)}>
                <DialogContent size="lg">
                    <DialogHeader>
                        <DialogTitle>Edit Template</DialogTitle>
                        <DialogDescription>Validate required variables before saving or sending.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-3 py-2">
                        <div className="grid gap-2">
                            <Label htmlFor="template-content">Template content</Label>
                            <Textarea id="template-content" rows={10} value={editContent} onChange={(event) => setEditContent(event.target.value)} />
                        </div>
                        <p className="text-xs text-muted-foreground">Required variables: {requiredVariables.map(v => `{{${v}}}`).join(', ')}</p>
                    </div>

                    <div className="rounded-lg border p-3">
                        <p className="text-sm font-medium mb-2">Version history</p>
                        <div className="space-y-2">
                            {(editTemplate?.versions ?? [{ version: editTemplate?.version ?? 1, updatedAt: editTemplate?.updatedAt ?? new Date().toISOString(), updatedBy: 'Current User' }]).map((entry) => (
                                <div key={`${entry.version}-${entry.updatedAt}`} className="flex items-center justify-between text-sm">
                                    <span>v{entry.version} · {formatRelativeTime(new Date(entry.updatedAt))} · {entry.updatedBy || 'Unknown'}</span>
                                    <Button variant="outline" size="sm" onClick={() => rollbackTemplate(editTemplate!.id, entry.version)}>Rollback</Button>
                                </div>
                            ))}
                        </div>
                    </div>

                    <DialogFooter>
                        <Button variant="outline" onClick={() => setEditTemplate(null)}>Cancel</Button>
                        <Button onClick={saveTemplateChanges}>Save Template</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
