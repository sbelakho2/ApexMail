import * as React from 'react';
import { useRouter } from 'next/navigation';
import {
    APIError,
    useContacts,
    useLists,
    useCreateContact,
    useCreateList,
    useUpdateContact,
    useDeleteContact,
    useAPIMutation,
    useAPI,
    getCsrfToken,
    type Contact,
    type PaginatedResponse,
} from '@/hooks/use-api';

interface ContactDisplay {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    company?: string;
    status: 'subscribed' | 'unsubscribed' | 'bounced' | 'complained';
    tags: string[];
    score: number;
    createdAt: string;
    lastActivity: string;
}

type ContactsFilterPreset = 'all_contacts' | 'high_intent' | 'bounced_followup';

type SortField = 'name' | 'score' | 'lastActivity';

interface ImportDuplicate {
    email: string;
    existingName: string;
    incomingName: string;
}

interface ContactFormState {
    email: string;
    firstName: string;
    lastName: string;
    company: string;
    tags: string;
}

function mapContactsApiError(error: unknown, operation: string) {
    if (error instanceof APIError) {
        if (error.status === 429) return `${operation} is rate-limited. Please retry in a few moments.`;
        if (error.status >= 500) return `${operation} failed due to a temporary server issue. Please retry.`;
        if (error.status === 404) return `${operation} failed because the requested resource no longer exists.`;
        if (error.status === 400) return `${operation} failed due to invalid request data. Check inputs and retry.`;
    }
    return `${operation} failed. Please try again.`;
}

function toContactDisplay(contact: Contact): ContactDisplay {
    return {
        id: contact.id,
        email: contact.email,
        firstName: contact.firstName,
        lastName: contact.lastName,
        company: contact.company,
        status: contact.status,
        tags: contact.tags ?? [],
        score: contact.score ?? 0,
        createdAt: contact.createdAt,
        lastActivity: contact.updatedAt,
    };
}

export function useContactsController() {
    const router = useRouter();

    const [page, setPage] = React.useState(1);
    const [selectedIds, setSelectedIds] = React.useState<string[]>([]);
    const [selectedList, setSelectedList] = React.useState('all');
    const [statusFilter, setStatusFilter] = React.useState<string>('all');
    const [searchInput, setSearchInput] = React.useState('');
    const [searchQuery, setSearchQuery] = React.useState('');
    const [sortField, setSortField] = React.useState<SortField>('lastActivity');
    const [sortOrder, setSortOrder] = React.useState<'asc' | 'desc'>('desc');
    const [activePreset, setActivePreset] = React.useState<ContactsFilterPreset>('all_contacts');

    const [addContactOpen, setAddContactOpen] = React.useState(false);
    const [editContactOpen, setEditContactOpen] = React.useState(false);
    const [importOpen, setImportOpen] = React.useState(false);
    const [createListOpen, setCreateListOpen] = React.useState(false);
    const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false);

    const [selectedContact, setSelectedContact] = React.useState<ContactDisplay | null>(null);
    const [rowDeleteId, setRowDeleteId] = React.useState<string | null>(null);
    const [editTargetId, setEditTargetId] = React.useState<string | null>(null);

    const [notice, setNotice] = React.useState('');
    const [errorNotice, setErrorNotice] = React.useState('');
    const [lastDeletedIds, setLastDeletedIds] = React.useState<string[]>([]);
    const [isFilterRefreshing, setIsFilterRefreshing] = React.useState(false);
    const [importProgress, setImportProgress] = React.useState(0);
    const [importResult, setImportResult] = React.useState<string>('');

    const [importDuplicates, setImportDuplicates] = React.useState<ImportDuplicate[]>([]);
    const [duplicateStrategy, setDuplicateStrategy] = React.useState<'skip' | 'merge' | 'overwrite'>('skip');
    const [resolveLoading, setResolveLoading] = React.useState(false);
    const [newListName, setNewListName] = React.useState('');

    const [contactForm, setContactForm] = React.useState<ContactFormState>({
        email: '',
        firstName: '',
        lastName: '',
        company: '',
        tags: '',
    });

    const createContact = useCreateContact();
    const createList = useCreateList();
    const updateContact = useUpdateContact();
    const deleteContact = useDeleteContact();

    const bulkTagMutation = useAPIMutation<{ success: boolean }, { ids: string[]; tag: string }>('/v1/contacts/bulk/tag');
    const bulkDeleteMutation = useAPIMutation<{ success: boolean }, { ids: string[] }>('/v1/contacts/bulk/delete');
    const bulkRestoreMutation = useAPIMutation<{ restored: number }, { ids: string[] }>('/v1/contacts/bulk/restore');
    const resolveDuplicatesMutation = useAPIMutation<{ resolved: number }, { strategy: 'skip' | 'merge' | 'overwrite' }>('/v1/contacts/bulk/resolve-duplicates');

    const { data: contactsData, error: contactsError, isLoading, mutate } = useContacts(
        page,
        50,
        selectedList === 'all' ? undefined : selectedList,
        {
            status: statusFilter,
            search: searchQuery,
            sortField,
            sortOrder,
        }
    );

    const statusCountBaseQuery = React.useMemo(() => {
        const params = new URLSearchParams();

        if (selectedList !== 'all') {
            params.set('listId', selectedList);
        }

        if (searchQuery) {
            params.set('search', searchQuery);
        }

        return params.toString();
    }, [searchQuery, selectedList]);

    const { data: statusCountsData } = useAPI<{
        total: number;
        subscribed: number;
        unsubscribed: number;
        bounced: number;
        complained: number;
    }>(
        `/v1/contacts/counts?${statusCountBaseQuery}`
    );

    const { data: listsData, error: listsError } = useLists();

    const applyPreset = React.useCallback((preset: ContactsFilterPreset) => {
        setActivePreset(preset);
        setPage(1);

        if (typeof window !== 'undefined') {
            window.localStorage.setItem('contacts.filterPreset', preset);
        }

        if (preset === 'high_intent') {
            setStatusFilter('subscribed');
            setSearchInput('');
            setSearchQuery('');
            setSortField('score');
            setSortOrder('desc');
            return;
        }

        if (preset === 'bounced_followup') {
            setStatusFilter('bounced');
            setSearchInput('');
            setSearchQuery('');
            setSortField('lastActivity');
            setSortOrder('asc');
            return;
        }

        setStatusFilter('all');
        setSearchInput('');
        setSearchQuery('');
        setSortField('lastActivity');
        setSortOrder('desc');
    }, []);

    React.useEffect(() => {
        if (typeof window === 'undefined') return;
        const preset = window.localStorage.getItem('contacts.filterPreset') as ContactsFilterPreset | null;
        if (!preset) return;
        applyPreset(preset);
    }, [applyPreset]);

    React.useEffect(() => {
        const timer = window.setTimeout(() => {
            setSearchQuery(searchInput.trim());
            setPage(1);
        }, 350);
        return () => window.clearTimeout(timer);
    }, [searchInput]);

    React.useEffect(() => {
        setIsFilterRefreshing(true);
    }, [statusFilter, searchQuery, selectedList, sortField, sortOrder, page]);

    React.useEffect(() => {
        if (!isLoading) {
            setIsFilterRefreshing(false);
        }
    }, [isLoading, contactsData]);

    const filteredContacts = React.useMemo<ContactDisplay[]>(() => {
        const rows = contactsData?.data ?? [];
        return rows.map(toContactDisplay);
    }, [contactsData]);

    const lists = React.useMemo(() => {
        const apiLists = listsData ?? [];
        const total = contactsData?.total ?? 0;
        return [
            { id: 'all', name: 'All Contacts', count: total },
            ...apiLists.map((list) => ({
                id: list.id,
                name: list.name,
                count: list.subscriberCount ?? 0,
                unsubscribedCount: list.unsubscribedCount ?? 0,
                bouncedCount: list.bouncedCount ?? 0,
            })),
        ];
    }, [listsData, contactsData?.total]);

    const statusCounts = React.useMemo(() => {
        return {
            all: contactsData?.total ?? 0,
            subscribed: statusCountsData?.subscribed ?? 0,
            unsubscribed: statusCountsData?.unsubscribed ?? 0,
            bounced: statusCountsData?.bounced ?? 0,
            complained: statusCountsData?.complained ?? 0,
        };
    }, [
        contactsData?.total,
        statusCountsData,
    ]);

    const totalPages = contactsData?.totalPages ?? 1;
    const totalContacts = contactsData?.total ?? filteredContacts.length;

    const currentListMeta = React.useMemo(() => {
        if (selectedList === 'all') return null;
        return (listsData ?? []).find((list) => list.id === selectedList) ?? null;
    }, [listsData, selectedList]);

    const handleSort = (field: SortField) => {
        setPage(1);
        if (sortField === field) {
            setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
            return;
        }
        setSortField(field);
        setSortOrder('asc');
    };

    const toggleSelectAll = () => {
        if (selectedIds.length === filteredContacts.length) {
            setSelectedIds([]);
            return;
        }
        setSelectedIds(filteredContacts.map((contact) => contact.id));
    };

    const toggleSelect = (id: string) => {
        setSelectedIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
    };

    const handleSelectionKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
        if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'a') {
            event.preventDefault();
            setSelectedIds(filteredContacts.map((contact) => contact.id));
            return;
        }

        if (event.key === 'Escape') {
            setSelectedIds([]);
        }
    };

    const resetNotices = () => {
        setNotice('');
        setErrorNotice('');
    };

    const handleBulkAddTag = async () => {
        if (selectedIds.length === 0) return;
        resetNotices();
        try {
            await bulkTagMutation.trigger({ ids: selectedIds, tag: 'needs-followup' });
            setNotice(`Added tag to ${selectedIds.length} contacts.`);
            setSelectedIds([]);
            mutate();
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Adding tags'));
        }
    };

    const handleBulkDelete = async () => {
        if (selectedIds.length === 0) return;
        resetNotices();

        const ids = [...selectedIds];
        try {
            await bulkDeleteMutation.trigger({ ids });
            setLastDeletedIds(ids);
            setSelectedIds([]);
            setNotice(`Deleted ${ids.length} contacts. You can undo this action.`);
            mutate();

            const undoTimer = window.setTimeout(() => {
                setNotice('');
            }, 10000);

            // Store cleanup so callers needing it can use it
            void undoTimer;
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Bulk delete'));
        }
    };

    const handleUndoDelete = async () => {
        resetNotices();
        if (lastDeletedIds.length === 0) {
            setErrorNotice('No recent delete action to undo.');
            return;
        }
        try {
            await bulkRestoreMutation.trigger({ ids: lastDeletedIds });
            setLastDeletedIds([]);
            setNotice('Restored recently deleted contacts.');
            mutate();
        } catch {
            setErrorNotice('Undo window expired or restore endpoint unavailable.');
        }
    };

    const handleBulkSendEmail = () => {
        if (selectedIds.length === 0) return;
        const params = new URLSearchParams();
        params.set('contacts', selectedIds.join(','));
        router.push(`/campaigns/new?${params.toString()}`);
    };

    const handleSendEmailToContact = (contactId: string) => {
        router.push(`/campaigns/new?contacts=${contactId}`);
    };

    const handleCreateList = async () => {
        resetNotices();
        if (!newListName.trim()) {
            setErrorNotice('List name is required.');
            return;
        }

        try {
            await createList.trigger({ name: newListName.trim() });
            setCreateListOpen(false);
            setNewListName('');
            setNotice('List created successfully.');
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Creating list'));
        }
    };

    const handleCreateContact = async () => {
        resetNotices();
        if (!contactForm.email.trim()) {
            setErrorNotice('Email is required.');
            return;
        }

        // Validate email format
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(contactForm.email.trim())) {
            setErrorNotice('Please enter a valid email address.');
            return;
        }

        try {
            await createContact.trigger({
                email: contactForm.email.trim(),
                firstName: contactForm.firstName.trim() || undefined,
                lastName: contactForm.lastName.trim() || undefined,
                company: contactForm.company.trim() || undefined,
                tags: contactForm.tags
                    .split(',')
                    .map((tag) => tag.trim())
                    .filter(Boolean),
            });

            setAddContactOpen(false);
            setContactForm({ email: '', firstName: '', lastName: '', company: '', tags: '' });
            setNotice('Contact created successfully.');
            mutate();
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Creating contact'));
        }
    };

    const handleOpenEdit = (contact: ContactDisplay) => {
        setEditTargetId(contact.id);
        setContactForm({
            email: contact.email,
            firstName: contact.firstName ?? '',
            lastName: contact.lastName ?? '',
            company: contact.company ?? '',
            tags: contact.tags.join(', '),
        });
        setEditContactOpen(true);
    };

    const handleUpdateContact = async () => {
        if (!editTargetId) return;
        resetNotices();
        try {
            await updateContact.trigger({
                id: editTargetId,
                data: {
                    email: contactForm.email.trim(),
                    firstName: contactForm.firstName.trim() || undefined,
                    lastName: contactForm.lastName.trim() || undefined,
                    company: contactForm.company.trim() || undefined,
                    tags: contactForm.tags
                        .split(',')
                        .map((tag) => tag.trim())
                        .filter(Boolean),
                },
            });
            setEditContactOpen(false);
            setNotice('Contact updated successfully.');
            mutate();
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Updating contact'));
        }
    };

    const handleRowDelete = async () => {
        if (!rowDeleteId) return;
        resetNotices();
        try {
            await deleteContact.trigger(rowDeleteId);
            setDeleteConfirmOpen(false);
            setRowDeleteId(null);
            setNotice('Contact deleted successfully.');
            mutate();
        } catch (error) {
            setErrorNotice(mapContactsApiError(error, 'Deleting contact'));
        }
    };

    const handleImportContacts = async (file?: File) => {
        setImportProgress(5);
        setImportResult('');
        setImportDuplicates([]);

        if (!file) {
            setImportResult('No file selected.');
            setImportProgress(0);
            return;
        }

        try {
            const csrfToken = await getCsrfToken();

            const formData = new FormData();
            formData.append('file', file);
            if (selectedList !== 'all') {
                formData.append('listId', selectedList);
            }

            setImportProgress(30);

            const res = await fetch('/v1/contacts/import', {
                method: 'POST',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
                body: formData,
            });

            setImportProgress(80);

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error?.message || 'Import failed');
            }

            const data = await res.json().catch(() => ({}));
            setImportProgress(100);

            if (data.duplicates && data.duplicates.length > 0) {
                setImportDuplicates(data.duplicates);
            } else {
                const imported = data.imported ?? 0;
                setImportResult(`Import complete. ${imported} contact${imported !== 1 ? 's' : ''} imported successfully.`);
            }

            mutate();
        } catch (err) {
            setImportProgress(0);
            setImportResult(err instanceof Error ? err.message : 'Import failed. Please try again.');
        }
    };

    const handleResolveImport = async () => {
        setResolveLoading(true);
        try {
            const result = await resolveDuplicatesMutation.trigger({ strategy: duplicateStrategy });
            const resolvedCount = result?.resolved ?? importDuplicates.length;
            setImportDuplicates([]);
            setImportResult(`Import complete. ${resolvedCount} duplicate${resolvedCount !== 1 ? 's' : ''} resolved using "${duplicateStrategy}" strategy.`);
            mutate();
        } catch {
            setImportResult('Duplicate resolution failed. Please retry or contact support.');
        } finally {
            setResolveLoading(false);
        }
    };

    const clearSearch = () => {
        setSearchInput('');
        setSearchQuery('');
    };

    const clearFilters = () => {
        setStatusFilter('all');
        setSearchInput('');
        setSearchQuery('');
        setSelectedList('all');
    };

    const closeImportDialog = () => {
        setImportOpen(false);
        setImportDuplicates([]);
        setImportProgress(0);
        setImportResult('');
    };

    const setStatusFilterAndResetPage = (value: string) => {
        setStatusFilter(value);
        setPage(1);
    };

    const setSelectedListAndResetPage = (value: string) => {
        setSelectedList(value);
        setPage(1);
    };

    const combinedErrorNotice = errorNotice || (contactsError || listsError ? mapContactsApiError(contactsError ?? listsError, 'Loading contacts') : '');

    return {
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
        contactsError,
        listsError,
        combinedErrorNotice,
        isFilterRefreshing,
        importProgress,
        importResult,
        importDuplicates,
        setImportDuplicates,
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
        statusCounts,
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
    };
}
