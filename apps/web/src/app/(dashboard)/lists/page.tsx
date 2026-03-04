'use client';

import * as React from 'react';
import { Plus, Search, Users, Upload, MoreHorizontal, Trash2, Pencil } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import {
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { formatNumber, formatRelativeTime } from '@/lib/utils';
import { useAPI, getCsrfToken } from '@/hooks/use-api';

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
    const { data: listsData, isLoading: loading, mutate: mutateLists } = useAPI<{ lists?: ContactList[]; data?: ContactList[] }>('/v1/lists');
    const lists = listsData?.lists ?? listsData?.data ?? [];
    const [search, setSearch] = React.useState('');
    const [listPage, setListPage] = React.useState(1);
    const listsPerPage = 20;
    const [notice, setNotice] = React.useState('');
    const [error, setError] = React.useState('');

    // Create / edit dialog state
    const [dialogMode, setDialogMode] = React.useState<'create' | 'edit' | null>(null);
    const [editTarget, setEditTarget] = React.useState<ContactList | null>(null);
    const [formName, setFormName] = React.useState('');
    const [formDescription, setFormDescription] = React.useState('');
    const [formSubmitting, setFormSubmitting] = React.useState(false);

    // Delete confirmation
    const [deleteTarget, setDeleteTarget] = React.useState<ContactList | null>(null);

    // Import CSV dialog
    const [importOpen, setImportOpen] = React.useState(false);
    const [importFile, setImportFile] = React.useState<File | null>(null);
    const [importListId, setImportListId] = React.useState('');
    const [importSubmitting, setImportSubmitting] = React.useState(false);
    const fileInputRef = React.useRef<HTMLInputElement>(null);

    const filtered = lists.filter(l => !search || l.name.toLowerCase().includes(search.toLowerCase()));
    const totalListPages = Math.max(1, Math.ceil(filtered.length / listsPerPage));
    const paginatedLists = filtered.slice((listPage - 1) * listsPerPage, listPage * listsPerPage);

    function openCreateDialog() {
        setDialogMode('create');
        setEditTarget(null);
        setFormName('');
        setFormDescription('');
        setError('');
    }

    function openEditDialog(list: ContactList) {
        setDialogMode('edit');
        setEditTarget(list);
        setFormName(list.name);
        setFormDescription(list.description ?? '');
        setError('');
    }

    function closeFormDialog() {
        setDialogMode(null);
        setEditTarget(null);
    }

    async function handleFormSubmit() {
        if (!formName.trim()) {
            setError('List name is required.');
            return;
        }
        setFormSubmitting(true);
        setError('');
        try {
            const csrfToken = await getCsrfToken();
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
            };
            const body = JSON.stringify({ name: formName.trim(), description: formDescription.trim() });

            if (dialogMode === 'create') {
                const res = await fetch('/v1/lists', {
                    method: 'POST', credentials: 'include', headers, body,
                });
                if (!res.ok) throw new Error('Create failed');
                await mutateLists();
                setNotice('List created successfully.');
            } else if (dialogMode === 'edit' && editTarget) {
                const res = await fetch(`/v1/lists/${editTarget.id}`, {
                    method: 'PUT', credentials: 'include', headers, body,
                });
                if (!res.ok) throw new Error('Update failed');
                await mutateLists();
                setNotice('List updated successfully.');
            }
            closeFormDialog();
        } catch {
            setError(dialogMode === 'create' ? 'Failed to create list.' : 'Failed to update list.');
        } finally {
            setFormSubmitting(false);
        }
    }

    async function confirmDelete() {
        if (!deleteTarget) return;
        setError('');
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/lists/${deleteTarget.id}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
            });
            if (!res.ok) throw new Error('Delete failed');
            await mutateLists();
            setNotice(`List "${deleteTarget.name}" deleted.`);
        } catch {
            setError('Failed to delete list.');
        }
        setDeleteTarget(null);
    }

    function openImportDialog() {
        setImportOpen(true);
        setImportFile(null);
        setImportListId(lists[0]?.id ?? '');
        setError('');
    }

    async function handleImportSubmit() {
        if (!importFile || !importListId) {
            setError('Select a CSV file and a target list.');
            return;
        }
        setImportSubmitting(true);
        setError('');
        try {
            const csrfToken = await getCsrfToken();
            const formData = new FormData();
            formData.append('file', importFile);
            const res = await fetch(`/v1/lists/${importListId}/import`, {
                method: 'POST',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
                body: formData,
            });
            if (!res.ok) throw new Error('Import failed');
            await mutateLists();
            setNotice('CSV imported successfully.');
            setImportOpen(false);
        } catch {
            setError('Failed to import CSV.');
        } finally {
            setImportSubmitting(false);
        }
    }

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Lists"
                description="Manage your contact lists and segments."
                breadcrumbs={[{ label: 'Lists' }]}
                actions={
                    <>
                        <Button variant="outline" onClick={openImportDialog}><Upload className="mr-2 h-4 w-4" />Import CSV</Button>
                        <Button onClick={openCreateDialog}><Plus className="mr-2 h-4 w-4" />New List</Button>
                    </>
                }
            />

            <Card>
                <CardHeader>
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input placeholder="Search lists..." className="pl-9" aria-label="Search lists" value={search} onChange={e => setSearch(e.target.value)} />
                    </div>
                </CardHeader>
                <CardContent>
                    {notice ? <p className="mb-3 text-sm text-foreground">{notice}</p> : null}
                    {error ? <p className="mb-3 text-sm text-destructive">{error}</p> : null}

                    {loading ? (
                        <div className="space-y-3">{Array.from({ length: 3 }, (_, i) => `lists-skeleton-${i}`).map((skeletonId) => <Skeleton key={skeletonId} className="h-14 w-full" />)}</div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16">
                            <Users className="h-10 w-10 text-muted-foreground mb-4" />
                            <h3 className="font-semibold text-lg">No contact lists yet</h3>
                            <p className="text-muted-foreground text-sm mt-1 mb-4">Create your first list or import contacts to get started.</p>
                            <div className="flex items-center gap-3">
                                <Button variant="outline" onClick={openImportDialog}><Upload className="mr-2 h-4 w-4" />Import CSV</Button>
                                <Button onClick={openCreateDialog}><Plus className="mr-2 h-4 w-4" />Create List</Button>
                            </div>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader><TableRow>
                                <TableHead>Name</TableHead><TableHead>Subscribers</TableHead>
                                <TableHead>Status</TableHead><TableHead>Updated</TableHead><TableHead />
                            </TableRow></TableHeader>
                            <TableBody>
                                {paginatedLists.map(l => (
                                    <TableRow key={l.id}>
                                        <TableCell><p className="font-medium">{l.name}</p><p className="text-sm text-muted-foreground">{l.description || '—'}</p></TableCell>
                                        <TableCell className="apex-metric-number">{formatNumber(l.subscriberCount)}</TableCell>
                                        <TableCell><Badge variant={l.status === 'active' ? 'success' : 'secondary'}>{l.status}</Badge></TableCell>
                                        <TableCell className="text-muted-foreground text-sm">{formatRelativeTime(new Date(l.updatedAt))}</TableCell>
                                        <TableCell>
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="List actions"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem onClick={() => openEditDialog(l)}><Pencil className="mr-2 h-4 w-4" />Edit</DropdownMenuItem>
                                                    <DropdownMenuItem destructive onClick={() => setDeleteTarget(l)}><Trash2 className="mr-2 h-4 w-4" />Delete</DropdownMenuItem>
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
            {totalListPages > 1 && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {((listPage - 1) * listsPerPage) + 1}–{Math.min(listPage * listsPerPage, filtered.length)} of {filtered.length}
                    </p>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" disabled={listPage <= 1} onClick={() => setListPage(p => p - 1)}>
                            Previous
                        </Button>
                        <span className="text-sm text-muted-foreground">Page {listPage} of {totalListPages}</span>
                        <Button variant="outline" size="sm" disabled={listPage >= totalListPages} onClick={() => setListPage(p => p + 1)}>
                            Next
                        </Button>
                    </div>
                </div>
            )}

            {/* Create / Edit List Dialog */}
            <Dialog open={dialogMode !== null} onOpenChange={(open) => !open && closeFormDialog()}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{dialogMode === 'create' ? 'Create New List' : 'Edit List'}</DialogTitle>
                        <DialogDescription>
                            {dialogMode === 'create'
                                ? 'Give your new contact list a name and optional description.'
                                : 'Update the list name or description.'}
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-2">
                        <div className="grid gap-2">
                            <Label htmlFor="list-name">Name</Label>
                            <Input id="list-name" value={formName} onChange={e => setFormName(e.target.value)} placeholder="e.g. Newsletter Subscribers" />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="list-desc">Description (optional)</Label>
                            <Textarea id="list-desc" rows={3} value={formDescription} onChange={e => setFormDescription(e.target.value)} placeholder="What is this list for?" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={closeFormDialog} disabled={formSubmitting}>Cancel</Button>
                        <Button onClick={handleFormSubmit} disabled={formSubmitting}>
                            {formSubmitting ? 'Saving...' : dialogMode === 'create' ? 'Create List' : 'Save Changes'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Delete Confirmation Dialog */}
            <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete List</DialogTitle>
                        <DialogDescription>
                            Delete &ldquo;{deleteTarget?.name}&rdquo; and all its subscriber associations? This cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
                        <Button variant="destructive" onClick={confirmDelete}>Delete</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Import CSV Dialog */}
            <Dialog open={importOpen} onOpenChange={(open) => !open && setImportOpen(false)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Import CSV</DialogTitle>
                        <DialogDescription>Upload a CSV file to import contacts into an existing list.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-2">
                        <div className="grid gap-2">
                            <Label htmlFor="import-list">Target list</Label>
                            <select
                                id="import-list"
                                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                                value={importListId}
                                onChange={e => setImportListId(e.target.value)}
                            >
                                {lists.length === 0 && <option value="">No lists — create one first</option>}
                                {lists.map(l => <option key={l.id} value={l.id}>{l.name}</option>)}
                            </select>
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="import-file">CSV file</Label>
                            <Input
                                ref={fileInputRef}
                                id="import-file"
                                type="file"
                                accept=".csv,text/csv"
                                onChange={e => setImportFile(e.target.files?.[0] ?? null)}
                            />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setImportOpen(false)} disabled={importSubmitting}>Cancel</Button>
                        <Button onClick={handleImportSubmit} disabled={importSubmitting || !importFile || !importListId}>
                            {importSubmitting ? 'Importing...' : 'Import'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
