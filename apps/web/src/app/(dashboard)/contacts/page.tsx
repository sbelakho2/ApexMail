'use client';

import {
    Plus,
    Search,
    X,
    MoreHorizontal,
    Users,
    Upload,
    Trash2,
    Pencil,
    Eye,
    Tag,
    Mail,
    UserPlus,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { PaginationControls } from '@/components/ui/pagination-controls';
import { SortableTableHead } from '@/components/ui/sortable-table-head';
import { StatusIndicator } from '@/components/ui/status-indicator';
import { cn, formatNumber, formatRelativeTime, getInitials } from '@/lib/utils';
import { useContactsController } from './use-contacts-controller';

export default function ContactsPage() {
    const {
        page,
        setPage,
        selectedIds,
        selectedList,
        statusFilter,
        searchInput,
        setSearchInput,
        sortField,
        sortOrder,
        activePreset,
        addContactOpen,
        setAddContactOpen,
        editContactOpen,
        setEditContactOpen,
        importOpen,
        createListOpen,
        setCreateListOpen,
        deleteConfirmOpen,
        setDeleteConfirmOpen,
        selectedContact,
        setSelectedContact,
        setRowDeleteId,
        notice,
        combinedErrorNotice,
        isFilterRefreshing,
        importProgress,
        importResult,
        importDuplicates,
        duplicateStrategy,
        setDuplicateStrategy,
        resolveLoading,
        newListName,
        setNewListName,
        contactForm,
        setContactForm,
        isLoading,
        filteredContacts,
        lists,
        totalPages,
        totalContacts,
        currentListMeta,
        handleSort,
        applyPreset,
        toggleSelectAll,
        toggleSelect,
        handleSelectionKeyDown,
        handleBulkAddTag,
        handleBulkDelete,
        handleUndoDelete,
        handleBulkSendEmail,
        handleSendEmailToContact,
        handleCreateList,
        handleCreateContact,
        handleOpenEdit,
        handleUpdateContact,
        handleRowDelete,
        handleImportContacts,
        handleResolveImport,
        clearSearch,
        clearFilters,
        closeImportDialog,
        setStatusFilterAndResetPage,
        setSelectedListAndResetPage,
        setImportOpen,
    } = useContactsController();

    return (
        <div className="space-y-6">
            <PageHeader
                title="Contacts"
                description="Manage your subscriber list and contact information."
                breadcrumbs={[{ label: 'Contacts' }]}
                actions={
                    <div className="flex items-center gap-2">
                        <Button variant="outline" onClick={() => setImportOpen(true)}>
                            <Upload className="mr-2 h-4 w-4" />
                            Import
                        </Button>
                        <Button onClick={() => setAddContactOpen(true)}>
                            <UserPlus className="mr-2 h-4 w-4" />
                            Add Contact
                        </Button>
                    </div>
                }
            />

            {process.env.NODE_ENV !== 'production' ? (
                <Badge variant="outline" className="w-fit">data source: live</Badge>
            ) : null}

            {notice ? (
                <Card className="border-success/30 bg-success/10">
                    <CardContent className="p-3 text-sm text-foreground flex items-center justify-between gap-3">
                        <span>{notice}</span>
                        <Button variant="outline" size="sm" onClick={handleUndoDelete}>Undo</Button>
                    </CardContent>
                </Card>
            ) : null}

            {combinedErrorNotice ? (
                <Card className="border-destructive/30 bg-destructive/10">
                    <CardContent className="p-3 text-sm text-destructive">
                        {combinedErrorNotice}
                    </CardContent>
                </Card>
            ) : null}

            <div className="grid gap-6 lg:grid-cols-4">
                <Card className="lg:col-span-1">
                    <CardHeader>
                        <CardTitle className="text-base">Lists</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                        <nav className="space-y-1 px-3 pb-3">
                            {lists.map((list) => (
                                <button
                                    key={list.id}
                                    onClick={() => setSelectedListAndResetPage(list.id)}
                                    className={cn(
                                        'flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm transition-colors',
                                        selectedList === list.id
                                            ? 'bg-primary/10 text-primary'
                                            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                                    )}
                                >
                                    <span>{list.name}</span>
                                    <Badge variant="secondary" size="sm">
                                        {formatNumber(list.count)}
                                    </Badge>
                                </button>
                            ))}
                        </nav>
                        <div className="border-t p-3 space-y-3">
                            {currentListMeta ? (
                                <div className="rounded-md border bg-muted/20 p-2 text-xs text-muted-foreground space-y-1">
                                    <p>Growth: {formatNumber(currentListMeta.subscriberCount)} active</p>
                                    <p>Churn: {formatNumber(currentListMeta.unsubscribedCount)} unsubscribed</p>
                                    <p>Suppression: {formatNumber(currentListMeta.bouncedCount)} bounced</p>
                                </div>
                            ) : null}
                            <Button variant="outline" size="sm" className="w-full" onClick={() => setCreateListOpen(true)}>
                                <Plus className="mr-2 h-4 w-4" />
                                Create List
                            </Button>
                        </div>
                    </CardContent>
                </Card>

                <Card
                    className="lg:col-span-3"
                    onKeyDown={handleSelectionKeyDown}
                    tabIndex={0}
                    aria-label="Contacts table. Use Command/Control+A to select all and Escape to clear selection."
                >
                    <CardContent className="p-4">
                        <div className="mb-3 flex flex-wrap items-center gap-2">
                            <span className="text-xs font-medium text-muted-foreground">Saved views</span>
                            <Button variant={activePreset === 'all_contacts' ? 'default' : 'outline'} size="sm" onClick={() => applyPreset('all_contacts')}>All contacts</Button>
                            <Button variant={activePreset === 'high_intent' ? 'default' : 'outline'} size="sm" onClick={() => applyPreset('high_intent')}>High intent</Button>
                            <Button variant={activePreset === 'bounced_followup' ? 'default' : 'outline'} size="sm" onClick={() => applyPreset('bounced_followup')}>Bounced follow-up</Button>
                        </div>

                        <div className="mb-4 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                            <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center">
                                <div className="relative">
                                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                    <Input
                                        placeholder="Search contacts..."
                                        value={searchInput}
                                        onChange={(event) => setSearchInput(event.target.value)}
                                        className="w-full sm:w-64 pl-9 pr-10"
                                    />
                                    {searchInput && (
                                        <button
                                            type="button"
                                            onClick={clearSearch}
                                            className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground"
                                            aria-label="Clear contacts search"
                                        >
                                            <X className="h-4 w-4" />
                                        </button>
                                    )}
                                </div>
                                <Select value={statusFilter} onValueChange={setStatusFilterAndResetPage}>
                                    <SelectTrigger className="w-full sm:w-44">
                                        <SelectValue placeholder="Status" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="all">All Status</SelectItem>
                                        <SelectItem value="subscribed">Subscribed</SelectItem>
                                        <SelectItem value="unsubscribed">Unsubscribed</SelectItem>
                                        <SelectItem value="bounced">Bounced</SelectItem>
                                        <SelectItem value="complained">Complained</SelectItem>
                                    </SelectContent>
                                </Select>
                                <Button
                                    size="sm"
                                    variant={statusFilter === 'bounced' ? 'default' : 'outline'}
                                    title="Quick filter: bounced contacts needing remediation"
                                    onClick={() => setStatusFilterAndResetPage('bounced')}
                                >
                                    Bounced
                                </Button>
                                <Button
                                    size="sm"
                                    variant={statusFilter === 'complained' ? 'default' : 'outline'}
                                    title="Quick filter: complaint contacts to avoid sender reputation issues"
                                    onClick={() => setStatusFilterAndResetPage('complained')}
                                >
                                    Complained
                                </Button>
                            </div>

                            {selectedIds.length > 0 ? (
                                <div className="flex items-center gap-2">
                                    <span className="text-sm text-muted-foreground">{selectedIds.length} selected</span>
                                    <Button variant="outline" size="sm" onClick={handleBulkAddTag}>
                                        <Tag className="mr-2 h-4 w-4" />
                                        Add Tag
                                    </Button>
                                    <Button variant="outline" size="sm" onClick={handleBulkSendEmail}>
                                        <Mail className="mr-2 h-4 w-4" />
                                        Send Email
                                    </Button>
                                    <Button variant="destructive" size="sm" onClick={handleBulkDelete}>
                                        <Trash2 className="mr-2 h-4 w-4" />
                                        Delete
                                    </Button>
                                </div>
                            ) : null}
                        </div>

                        {isFilterRefreshing ? (
                            <p className="mb-3 text-xs text-muted-foreground">Updating contacts…</p>
                        ) : null}

                        <div className="overflow-x-auto">
                            <Table className="min-w-[900px]">
                                <TableHeader className="sticky top-0 z-10 bg-card">
                                    <TableRow>
                                        <TableHead className="w-12">
                                            <Checkbox
                                                checked={selectedIds.length === filteredContacts.length && filteredContacts.length > 0}
                                                onCheckedChange={toggleSelectAll}
                                            />
                                        </TableHead>
                                        <TableHead aria-sort={sortField === 'name' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                            <SortableTableHead
                                                label="Contact"
                                                active={sortField === 'name'}
                                                direction={sortOrder}
                                                onClick={() => handleSort('name')}
                                                className="-ml-2"
                                            />
                                        </TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Tags</TableHead>
                                        <TableHead className="text-right" aria-sort={sortField === 'score' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                            <SortableTableHead
                                                label="Score"
                                                active={sortField === 'score'}
                                                direction={sortOrder}
                                                onClick={() => handleSort('score')}
                                                className="justify-end"
                                            />
                                        </TableHead>
                                        <TableHead aria-sort={sortField === 'lastActivity' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
                                            <SortableTableHead
                                                label="Last Activity"
                                                active={sortField === 'lastActivity'}
                                                direction={sortOrder}
                                                onClick={() => handleSort('lastActivity')}
                                                className="-ml-2"
                                            />
                                        </TableHead>
                                        <TableHead className="w-12" />
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {!isLoading && filteredContacts.length === 0 ? (
                                        <TableRow>
                                            <TableCell colSpan={7} className="h-32 text-center">
                                                <div className="flex flex-col items-center gap-2 text-muted-foreground">
                                                    <Users className="h-8 w-8" />
                                                    <p>No contacts found</p>
                                                    <button
                                                        type="button"
                                                        onClick={clearFilters}
                                                        className="text-xs text-primary hover:underline"
                                                    >
                                                        Clear filters and broaden terms
                                                    </button>
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ) : (
                                        filteredContacts.map((contact) => {
                                            const fullName = [contact.firstName, contact.lastName].filter(Boolean).join(' ');
                                            return (
                                                <TableRow key={contact.id} className={selectedContact?.id === contact.id ? 'bg-muted/40' : undefined}>
                                                    <TableCell>
                                                        <Checkbox
                                                            checked={selectedIds.includes(contact.id)}
                                                            onCheckedChange={() => toggleSelect(contact.id)}
                                                        />
                                                    </TableCell>
                                                    <TableCell>
                                                        <div className="flex items-center gap-3">
                                                            <Avatar size="sm">
                                                                <AvatarFallback>{getInitials(fullName || contact.email)}</AvatarFallback>
                                                            </Avatar>
                                                            <div>
                                                                <p className="font-medium">{fullName || contact.email}</p>
                                                                {fullName ? <p className="text-sm text-muted-foreground">{contact.email}</p> : null}
                                                                {contact.company ? <p className="text-xs text-muted-foreground">{contact.company}</p> : null}
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell>
                                                        <StatusIndicator status={contact.status} />
                                                    </TableCell>
                                                    <TableCell>
                                                        <div className="flex flex-wrap gap-1">
                                                            {contact.tags.length > 0 ? (
                                                                contact.tags.map((tag) => (
                                                                    <Badge key={tag} variant="outline" size="sm">{tag}</Badge>
                                                                ))
                                                            ) : (
                                                                <span className="text-sm text-muted-foreground">-</span>
                                                            )}
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="text-right">{contact.score > 0 ? <Badge variant={contact.score >= 80 ? 'success' : contact.score >= 50 ? 'warning' : 'secondary'}>{contact.score}</Badge> : '-'}</TableCell>
                                                    <TableCell>
                                                        <span className="text-sm text-muted-foreground">{formatRelativeTime(new Date(contact.lastActivity))}</span>
                                                    </TableCell>
                                                    <TableCell>
                                                        <DropdownMenu>
                                                            <DropdownMenuTrigger asChild>
                                                                <Button variant="ghost" size="icon" aria-label="Contact row actions">
                                                                    <MoreHorizontal className="h-4 w-4" />
                                                                </Button>
                                                            </DropdownMenuTrigger>
                                                            <DropdownMenuContent align="end">
                                                                <DropdownMenuItem onClick={() => setSelectedContact(contact)}>
                                                                    <Eye className="mr-2 h-4 w-4" />
                                                                    View Profile
                                                                </DropdownMenuItem>
                                                                <DropdownMenuItem onClick={() => handleOpenEdit(contact)}>
                                                                    <Pencil className="mr-2 h-4 w-4" />
                                                                    Edit
                                                                </DropdownMenuItem>
                                                                <DropdownMenuItem onClick={() => handleSendEmailToContact(contact.id)}>
                                                                    <Mail className="mr-2 h-4 w-4" />
                                                                    Send Email
                                                                </DropdownMenuItem>
                                                                <DropdownMenuSeparator />
                                                                <DropdownMenuItem
                                                                    destructive
                                                                    onClick={() => {
                                                                        setRowDeleteId(contact.id);
                                                                        setDeleteConfirmOpen(true);
                                                                    }}
                                                                >
                                                                    <Trash2 className="mr-2 h-4 w-4" />
                                                                    Delete
                                                                </DropdownMenuItem>
                                                            </DropdownMenuContent>
                                                        </DropdownMenu>
                                                    </TableCell>
                                                </TableRow>
                                            );
                                        })
                                    )}
                                </TableBody>
                            </Table>
                        </div>

                        <div className="mt-4 flex items-center justify-between">
                            <p className="text-sm text-muted-foreground">Showing {filteredContacts.length} of {formatNumber(totalContacts)} contacts</p>
                            <PaginationControls page={page} totalPages={totalPages} onPageChange={setPage} />
                        </div>
                    </CardContent>
                </Card>
            </div>

            {selectedContact ? (
                <Card>
                    <CardHeader>
                        <CardTitle className="text-base">Contact details</CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-muted-foreground grid gap-1 sm:grid-cols-2 lg:grid-cols-4">
                        <p><span className="font-medium text-foreground">Email:</span> {selectedContact.email}</p>
                        <p><span className="font-medium text-foreground">Status:</span> {selectedContact.status}</p>
                        <p><span className="font-medium text-foreground">Created:</span> {formatRelativeTime(new Date(selectedContact.createdAt))}</p>
                        <p><span className="font-medium text-foreground">Last activity:</span> {formatRelativeTime(new Date(selectedContact.lastActivity))}</p>
                    </CardContent>
                </Card>
            ) : null}

            <Dialog open={addContactOpen} onOpenChange={setAddContactOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Add Contact</DialogTitle>
                        <DialogDescription>Add a new contact to your subscriber list.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="contact-email">Email *</Label>
                            <Input id="contact-email" type="email" value={contactForm.email} onChange={(event) => setContactForm((prev) => ({ ...prev, email: event.target.value }))} />
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="grid gap-2">
                                <Label htmlFor="contact-first">First Name</Label>
                                <Input id="contact-first" value={contactForm.firstName} onChange={(event) => setContactForm((prev) => ({ ...prev, firstName: event.target.value }))} />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="contact-last">Last Name</Label>
                                <Input id="contact-last" value={contactForm.lastName} onChange={(event) => setContactForm((prev) => ({ ...prev, lastName: event.target.value }))} />
                            </div>
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="contact-company">Company</Label>
                            <Input id="contact-company" value={contactForm.company} onChange={(event) => setContactForm((prev) => ({ ...prev, company: event.target.value }))} />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="contact-tags">Tags</Label>
                            <Input id="contact-tags" value={contactForm.tags} onChange={(event) => setContactForm((prev) => ({ ...prev, tags: event.target.value }))} placeholder="vip, customer" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setAddContactOpen(false)}>Cancel</Button>
                        <Button onClick={handleCreateContact}>Add Contact</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={editContactOpen} onOpenChange={setEditContactOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Edit Contact</DialogTitle>
                        <DialogDescription>Update contact details and tags.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="edit-contact-email">Email</Label>
                            <Input id="edit-contact-email" type="email" value={contactForm.email} onChange={(event) => setContactForm((prev) => ({ ...prev, email: event.target.value }))} />
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="grid gap-2">
                                <Label htmlFor="edit-contact-first">First Name</Label>
                                <Input id="edit-contact-first" value={contactForm.firstName} onChange={(event) => setContactForm((prev) => ({ ...prev, firstName: event.target.value }))} />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="edit-contact-last">Last Name</Label>
                                <Input id="edit-contact-last" value={contactForm.lastName} onChange={(event) => setContactForm((prev) => ({ ...prev, lastName: event.target.value }))} />
                            </div>
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="edit-contact-company">Company</Label>
                            <Input id="edit-contact-company" value={contactForm.company} onChange={(event) => setContactForm((prev) => ({ ...prev, company: event.target.value }))} />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="edit-contact-tags">Tags</Label>
                            <Input id="edit-contact-tags" value={contactForm.tags} onChange={(event) => setContactForm((prev) => ({ ...prev, tags: event.target.value }))} />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setEditContactOpen(false)}>Cancel</Button>
                        <Button onClick={handleUpdateContact}>Save Changes</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={createListOpen} onOpenChange={setCreateListOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Create List</DialogTitle>
                        <DialogDescription>Create a new contact list for segmentation.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-2 py-2">
                        <Label htmlFor="new-list-name">List name</Label>
                        <Input id="new-list-name" value={newListName} onChange={(event) => setNewListName(event.target.value)} placeholder="VIP Leads" />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setCreateListOpen(false)}>Cancel</Button>
                        <Button onClick={handleCreateList}>Create</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Contact</DialogTitle>
                        <DialogDescription>This will remove the selected contact from active audiences.</DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDeleteConfirmOpen(false)}>Cancel</Button>
                        <Button variant="destructive" onClick={handleRowDelete}>Delete</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={importOpen} onOpenChange={setImportOpen}>
                <DialogContent size="lg">
                    <DialogHeader>
                        <DialogTitle>Import Contacts</DialogTitle>
                        <DialogDescription>
                            Upload a CSV file to import contacts. Required: email. Optional: first_name, last_name, company, phone, tags.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        {importDuplicates.length === 0 ? (
                            <>
                                <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8">
                                    <Upload className="mb-4 h-10 w-10 text-muted-foreground" />
                                    <p className="mb-2 text-sm font-medium">Drag and drop your CSV file here</p>
                                    <Button variant="outline" size="sm">Choose File</Button>
                                </div>
                                {importProgress > 0 && importProgress < 100 ? (
                                    <div className="space-y-1">
                                        <p className="text-sm text-muted-foreground">Importing… {importProgress}%</p>
                                        <div className="h-2 rounded-full bg-muted overflow-hidden">
                                            <div
                                                className="h-full rounded-full bg-primary transition-all duration-300"
                                                style={{ width: `${importProgress}%` }}
                                            />
                                        </div>
                                    </div>
                                ) : null}
                                {importResult ? (
                                    <p className="text-sm text-muted-foreground">{importResult}</p>
                                ) : null}
                            </>
                        ) : (
                            /* Item 121: Duplicate-contact conflict resolution UI */
                            <div className="space-y-4">
                                <div className="rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950/30">
                                    <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                                        {importDuplicates.length} duplicate contact{importDuplicates.length !== 1 ? 's' : ''} detected
                                    </p>
                                    <p className="text-xs text-amber-700 dark:text-amber-400 mt-0.5">
                                        These emails already exist in your contacts. Choose how to handle them.
                                    </p>
                                </div>

                                <div className="space-y-2">
                                    <Label className="text-sm font-medium">Conflict resolution strategy</Label>
                                    <div className="grid gap-2">
                                        {(
                                            [
                                                { key: 'skip', label: 'Skip duplicates', description: 'Keep existing contacts unchanged; discard incoming rows.' },
                                                { key: 'merge', label: 'Merge fields', description: 'Fill empty fields on existing contacts with incoming data.' },
                                                { key: 'overwrite', label: 'Overwrite with new data', description: 'Replace all fields on existing contacts with incoming data.' },
                                            ] as const
                                        ).map(({ key, label, description }) => (
                                            <button
                                                key={key}
                                                type="button"
                                                onClick={() => setDuplicateStrategy(key)}
                                                className={cn(
                                                    'flex items-start gap-3 rounded-md border p-3 text-left transition-colors',
                                                    duplicateStrategy === key
                                                        ? 'border-primary bg-primary/5'
                                                        : 'border-border hover:border-primary/50',
                                                )}
                                            >
                                                <div
                                                    className={cn(
                                                        'mt-0.5 h-4 w-4 shrink-0 rounded-full border-2',
                                                        duplicateStrategy === key ? 'border-primary bg-primary' : 'border-muted-foreground',
                                                    )}
                                                />
                                                <div>
                                                    <p className="text-sm font-medium">{label}</p>
                                                    <p className="text-xs text-muted-foreground">{description}</p>
                                                </div>
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                <div className="space-y-1.5">
                                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Affected contacts</p>
                                    <div className="rounded-md border divide-y max-h-40 overflow-y-auto">
                                        {importDuplicates.map((dup) => (
                                            <div key={dup.email} className="flex items-center justify-between px-3 py-2 text-sm">
                                                <span className="font-medium truncate">{dup.email}</span>
                                                <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0 ml-4">
                                                    <span className="truncate max-w-[90px]">{dup.existingName}</span>
                                                    <span>→</span>
                                                    <span className="truncate max-w-[90px]">{dup.incomingName}</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={closeImportDialog}>
                            Close
                        </Button>
                        {importDuplicates.length > 0 ? (
                            <Button onClick={handleResolveImport} disabled={resolveLoading}>
                                {resolveLoading ? 'Applying…' : `Apply – ${duplicateStrategy}`}
                            </Button>
                        ) : (
                            <Button onClick={handleImportContacts} disabled={importProgress > 0 && importProgress < 100}>
                                Import Contacts
                            </Button>
                        )}
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
