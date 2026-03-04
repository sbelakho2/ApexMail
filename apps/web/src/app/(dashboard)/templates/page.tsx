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
import { useAPI, getCsrfToken } from '@/hooks/use-api';

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
    return Array.from(found);
}

export default function TemplatesPage() {
    const { data: templatesData, isLoading: loading, mutate: mutateTemplates } = useAPI<{ templates?: Template[]; data?: Template[] }>('/v1/templates');
    const templates = templatesData?.templates ?? templatesData?.data ?? [];
    const [search, setSearch] = React.useState('');
    const [templatePage, setTemplatePage] = React.useState(1);
    const templatesPerPage = 20;
    const [notice, setNotice] = React.useState('');
    const [error, setError] = React.useState('');
    const [previewTemplate, setPreviewTemplate] = React.useState<Template | null>(null);
    const [previewDarkMode, setPreviewDarkMode] = React.useState(false);
    const [previewRtl, setPreviewRtl] = React.useState(false);
    const [editTemplate, setEditTemplate] = React.useState<Template | null>(null);
    const [editContent, setEditContent] = React.useState('');
    const [deleteTarget, setDeleteTarget] = React.useState<Template | null>(null);
    const [showCreateDialog, setShowCreateDialog] = React.useState(false);
    const [createName, setCreateName] = React.useState('');
    const [createSubject, setCreateSubject] = React.useState('');

    const requiredVariables = ['first_name', 'unsubscribe_url'];

    const filtered = templates.filter(t =>
        !search || t.name.toLowerCase().includes(search.toLowerCase()) || t.subject.toLowerCase().includes(search.toLowerCase())
    );
    const totalTemplatePages = Math.max(1, Math.ceil(filtered.length / templatesPerPage));
    const paginatedTemplates = filtered.slice((templatePage - 1) * templatesPerPage, templatePage * templatesPerPage);

    async function duplicateTemplate(template: Template) {
        setNotice('');
        setError('');
        const duplicateName = `${template.name} (Copy)`;

        if (templates.some((item) => item.name.toLowerCase() === duplicateName.toLowerCase())) {
            setError(`A template named "${duplicateName}" already exists. Rename the existing copy or edit before duplicating again.`);
            return;
        }

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/templates/${template.id}/duplicate`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ name: duplicateName }),
            });

            if (!res.ok) {
                setError('Failed to duplicate template. Please retry.');
                return;
            }

            await mutateTemplates();
            setNotice(`Template duplicated as "${duplicateName}".`);
        } catch {
            setError('Network error. Please check your connection and retry.');
        }
    }

    async function confirmDeleteTemplate() {
        if (!deleteTarget) return;
        setNotice('');
        setError('');

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/templates/${deleteTarget.id}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
            });
            if (res.ok) {
                await mutateTemplates();
                setNotice('Template deleted.');
                setDeleteTarget(null);
                return;
            }

            setError('Failed to delete template.');
            setDeleteTarget(null);
        } catch {
            setError('Network error. Please check your connection and retry.');
            setDeleteTarget(null);
        }
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

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/templates/${editTemplate.id}`, {
                method: 'PUT',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ content: editContent }),
            });

            if (!res.ok) {
                setError('Failed to save template.');
                return;
            }

            await mutateTemplates();
            setEditTemplate(null);
            setNotice('Template saved after variable validation.');
        } catch {
            setError('Network error. Please check your connection and retry.');
        }
    }

    async function rollbackTemplate(templateId: string, version: number) {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/templates/${templateId}/rollback`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ version }),
            });
            if (res.ok) {
                await mutateTemplates();
                setNotice(`Rolled back template to v${version}.`);
            } else {
                setError('Failed to rollback template.');
            }
        } catch {
            setError('Network error. Please check your connection and retry.');
        }
    }

    async function createTemplate() {
        if (!createName.trim()) {
            setError('Template name is required.');
            return;
        }
        setNotice('');
        setError('');
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/templates', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({
                    name: createName.trim(),
                    subject: createSubject.trim() || 'Untitled',
                    content: 'Hello {{first_name}},\n\nYour update is ready.\n\nManage preferences: {{unsubscribe_url}}',
                }),
            });
            if (!res.ok) {
                setError('Failed to create template. Please try again.');
                return;
            }
            await mutateTemplates();
            setNotice(`Template "${createName.trim()}" created.`);
            setShowCreateDialog(false);
            setCreateName('');
            setCreateSubject('');
        } catch {
            setError('Failed to create template. Please try again.');
        }
    }

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Templates"
                description="Design and manage your email templates."
                breadcrumbs={[{ label: 'Templates' }]}
                actions={
                    <Button onClick={() => setShowCreateDialog(true)}><Plus className="mr-2 h-4 w-4" />New Template</Button>
                }
            />

            <Card>
                <CardHeader>
                    <div className="flex items-center gap-4">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input placeholder="Search templates..." className="pl-9" aria-label="Search templates" value={search} onChange={e => setSearch(e.target.value)} />
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
                                {Array.from({ length: 5 }, (_, i) => `templates-skeleton-${i}`).map((skeletonId) => <Skeleton key={skeletonId} className="h-14 w-full" />)}
                            </div>
                        </div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16">
                            <Mail className="h-10 w-10 text-muted-foreground mb-4" />
                            <h3 className="font-semibold text-lg">No templates yet</h3>
                            <p className="text-muted-foreground text-sm mt-1 mb-4">Create your first email template to get started.</p>
                            <Button onClick={() => setShowCreateDialog(true)}><Plus className="mr-2 h-4 w-4" />Create Template</Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader><TableRow>
                                <TableHead>Name</TableHead><TableHead>Subject</TableHead>
                                <TableHead>Status</TableHead><TableHead>Version</TableHead>
                                <TableHead>Updated</TableHead><TableHead />
                            </TableRow></TableHeader>
                            <TableBody>
                                {paginatedTemplates.map(t => (
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
                                                    <DropdownMenuItem destructive onClick={() => setDeleteTarget(t)}><Trash2 className="mr-2 h-4 w-4" />Delete</DropdownMenuItem>
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
            {totalTemplatePages > 1 && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {((templatePage - 1) * templatesPerPage) + 1}–{Math.min(templatePage * templatesPerPage, filtered.length)} of {filtered.length}
                    </p>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" disabled={templatePage <= 1} onClick={() => setTemplatePage(p => p - 1)}>
                            Previous
                        </Button>
                        <span className="text-sm text-muted-foreground">Page {templatePage} of {totalTemplatePages}</span>
                        <Button variant="outline" size="sm" disabled={templatePage >= totalTemplatePages} onClick={() => setTemplatePage(p => p + 1)}>
                            Next
                        </Button>
                    </div>
                </div>
            )}

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

            <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Template</DialogTitle>
                        <DialogDescription>
                            Delete &ldquo;{deleteTarget?.name}&rdquo; permanently? This action cannot be undone.
                            If removed by mistake, recreate it from version history or a duplicate.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
                        <Button variant="destructive" onClick={confirmDeleteTemplate}>Delete</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={showCreateDialog} onOpenChange={(open) => { if (!open) { setShowCreateDialog(false); setCreateName(''); setCreateSubject(''); } }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Create New Template</DialogTitle>
                        <DialogDescription>
                            Enter a name and subject line for your new email template.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-2">
                        <div className="space-y-2">
                            <Label htmlFor="create-name">Template Name</Label>
                            <Input id="create-name" value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Welcome Email" />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="create-subject">Subject Line</Label>
                            <Input id="create-subject" value={createSubject} onChange={(e) => setCreateSubject(e.target.value)} placeholder="Welcome to our platform" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => { setShowCreateDialog(false); setCreateName(''); setCreateSubject(''); }}>Cancel</Button>
                        <Button onClick={createTemplate}>Create Template</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
