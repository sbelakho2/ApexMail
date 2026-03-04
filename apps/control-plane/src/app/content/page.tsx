'use client';

import { useState, useEffect, useCallback, Suspense } from 'react';
import { cn, formatDateOnly, timeAgo } from '../../lib/utils';
import { useSearchParams } from 'next/navigation';
import { useDialog } from '../../components/ui/confirm-dialog';
import { PageLoadingState, PageErrorState } from '../../components/ui/async-state';
import { getCsrfToken } from '../../lib/client-csrf';

export const dynamic = 'force-dynamic';

/**
 * Content & CMS - Manage marketing content
 * 
 * The owner can:
 * - Create/edit blog posts
 * - Manage changelog entries
 * - Update documentation pages
 * - Schedule content publishing
 * - Preview content before publish
 */

interface ContentItem {
    id: string;
    title: string;
    slug: string;
    type: 'blog' | 'changelog' | 'docs' | 'announcement';
    status: 'draft' | 'scheduled' | 'published' | 'archived';
    excerpt: string;
    content: string;
    author: string;
    category?: string;
    tags: string[];
    featuredImage?: string;
    publishedAt?: string;
    scheduledFor?: string;
    createdAt: string;
    updatedAt: string;
    views?: number;
}



const TYPE_CONFIG: Record<string, { label: string; bg: string; text: string; icon: string }> = {
    blog: { label: 'Blog Post', bg: 'bg-blue-500/10', text: 'text-blue-500', icon: 'Blog' },
    changelog: { label: 'Changelog', bg: 'bg-violet-500/10', text: 'text-violet-500', icon: 'Log' },
    docs: { label: 'Documentation', bg: 'bg-emerald-500/10', text: 'text-emerald-500', icon: 'Docs' },
    announcement: { label: 'Announcement', bg: 'bg-amber-500/10', text: 'text-amber-500', icon: 'News' },
};

const STATUS_CONFIG: Record<string, { label: string; bg: string; text: string; dot: string }> = {
    draft: { label: 'Draft', bg: 'bg-muted', text: 'text-muted-foreground', dot: 'bg-muted-foreground' },
    scheduled: { label: 'Scheduled', bg: 'bg-warning/10', text: 'text-warning', dot: 'bg-warning' },
    published: { label: 'Published', bg: 'bg-success/10', text: 'text-success', dot: 'bg-success' },
    archived: { label: 'Archived', bg: 'bg-muted/50', text: 'text-muted-foreground', dot: 'bg-muted-foreground/50' },
};

const CONTENT_FORM_SCHEMA = {
    minTitleLength: 3,
    slugPattern: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    minAuthorLength: 2,
    minExcerptLength: 10,
    minContentLength: 20,
};

function ContentPageContent() {
    const dialog = useDialog();
    const searchParams = useSearchParams();
    const [content, setContent] = useState<ContentItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [typeFilter, setTypeFilter] = useState<string>(searchParams.get('type') || 'all');
    const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || 'all');
    const [searchQuery, setSearchQuery] = useState('');
    
    // Editor state
    const [editingItem, setEditingItem] = useState<ContentItem | null>(null);
    const [isCreating, setIsCreating] = useState(false);
    const [editorFormError, setEditorFormError] = useState('');
    const [loadError, setLoadError] = useState<string | null>(null);

    const loadData = useCallback(async () => {
        try {
            const response = await fetch('/api/content', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch content: ${response.status}`);
            const data = await response.json();
            setContent(data);
            setLoadError(null);
        } catch (err) {
            setLoadError(err instanceof Error ? err.message : 'Failed to load content');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
    }, [loadData]);

    async function publishItem(itemId: string) {
        const confirmed = await dialog.confirm({
            title: 'Publish Content',
            message: 'This will make the content publicly visible. Continue?',
            confirmLabel: 'Publish',
        });
        if (!confirmed) return;
        const previousContent = [...content];
        setContent(prev => prev.map(item => 
            item.id === itemId 
                ? { ...item, status: 'published' as const, publishedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }
                : item
        ));
        getCsrfToken().then(csrfToken => {
            fetch('/api/content', {
                method: 'PATCH',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                body: JSON.stringify({ id: itemId, status: 'published' }),
            }).then(res => {
                if (!res.ok) throw new Error('Failed');
            }).catch(() => {
                setContent(previousContent);
                dialog.alert({ title: 'Publish Failed', message: 'Could not publish the item. The change has been reverted.' });
            });
        });
    }

    async function archiveItem(itemId: string) {
        const confirmed = await dialog.confirm({
            title: 'Archive Content',
            message: 'This will remove the content from public view. Continue?',
            confirmLabel: 'Archive',
            variant: 'destructive',
        });
        if (!confirmed) return;
        const previousContent = [...content];
        setContent(prev => prev.map(item => 
            item.id === itemId 
                ? { ...item, status: 'archived' as const, updatedAt: new Date().toISOString() }
                : item
        ));
        getCsrfToken().then(csrfToken => {
            fetch('/api/content', {
                method: 'PATCH',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                body: JSON.stringify({ id: itemId, status: 'archived' }),
            }).then(res => {
                if (!res.ok) throw new Error('Failed');
            }).catch(() => {
                setContent(previousContent);
                dialog.alert({ title: 'Archive Failed', message: 'Could not archive the item. The change has been reverted.' });
            });
        });
    }

    function duplicateItem(item: ContentItem) {
        const newItem: ContentItem = {
            ...item,
            id: `c${Date.now()}`,
            title: `${item.title} (Copy)`,
            slug: `${item.slug}-copy`,
            status: 'draft',
            publishedAt: undefined,
            scheduledFor: undefined,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            views: 0,
        };
        const previousContent = [...content];
        setContent(prev => [newItem, ...prev]);
        getCsrfToken().then(csrfToken => {
            fetch('/api/content', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                body: JSON.stringify({ sourceId: item.id, title: newItem.title, slug: newItem.slug }),
            }).then(res => {
                if (!res.ok) throw new Error('Failed');
            }).catch(() => {
                setContent(previousContent);
                dialog.alert({ title: 'Duplicate Failed', message: 'Could not duplicate the item. The change has been reverted.' });
            });
        });
    }

    async function deleteItem(itemId: string) {
        const confirmed = await dialog.confirm({
            title: 'Delete Content',
            message: 'Are you sure you want to delete this content?',
            confirmLabel: 'Delete',
            variant: 'destructive',
        });
        if (confirmed) {
            const previousContent = content;
            setContent(prev => prev.filter(item => item.id !== itemId));
            const csrfToken = await getCsrfToken();
            try {
                const res = await fetch('/api/content', {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                    body: JSON.stringify({ id: itemId }),
                });
                if (!res.ok) throw new Error(`Delete failed: ${res.status}`);
            } catch (err) {
                console.error('Failed to persist delete:', err);
                setContent(previousContent);
                dialog.alert({ title: 'Delete Failed', message: 'Could not delete the item. The change has been reverted.' });
            }
        }
    }

    const filteredContent = content.filter(item => {
        const matchesType = typeFilter === 'all' || item.type === typeFilter;
        const matchesStatus = statusFilter === 'all' || item.status === statusFilter;
        const matchesSearch = searchQuery === '' || 
            item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
            item.excerpt.toLowerCase().includes(searchQuery.toLowerCase()) ||
            item.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
        return matchesType && matchesStatus && matchesSearch;
    });

    const stats = {
        total: content.length,
        published: content.filter(c => c.status === 'published').length,
        drafts: content.filter(c => c.status === 'draft').length,
        scheduled: content.filter(c => c.status === 'scheduled').length,
    };

    if (loading) {
        return <PageLoadingState label="Loading content..." />;
    }

    if (loadError) {
        return <PageErrorState description={loadError} onRetry={() => { setLoading(true); setLoadError(null); loadData(); }} />;
    }

    return (
        <div className="cp-page">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Content & CMS</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage blog posts, changelog, and documentation
                    </p>
                </div>
                <button 
                    type="button"
                    onClick={() => setIsCreating(true)}
                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors"
                >
                    + New Content
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Total Content</div>
                    <div className="text-2xl font-bold text-foreground mt-1">{stats.total}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Published</div>
                    <div className="text-2xl font-bold text-success mt-1">{stats.published}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Drafts</div>
                    <div className="text-2xl font-bold text-muted-foreground mt-1">{stats.drafts}</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Scheduled</div>
                    <div className="text-2xl font-bold text-warning mt-1">{stats.scheduled}</div>
                </div>
            </div>

            {/* Filters */}
            <div className="flex flex-col lg:flex-row gap-4 mb-6">
                <div className="flex-1">
                    <input
                        type="text"
                        placeholder="Search content..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full px-4 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground"
                    />
                </div>
                <div className="flex gap-2 flex-wrap">
                    <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        className="px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground"
                    >
                        <option value="all">All Types</option>
                        <option value="blog">Blog Posts</option>
                        <option value="changelog">Changelog</option>
                        <option value="docs">Documentation</option>
                        <option value="announcement">Announcements</option>
                    </select>
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground"
                    >
                        <option value="all">All Status</option>
                        <option value="draft">Draft</option>
                        <option value="scheduled">Scheduled</option>
                        <option value="published">Published</option>
                        <option value="archived">Archived</option>
                    </select>
                </div>
            </div>

            {/* Content List */}
            <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                <div className="divide-y divide-border">
                    {filteredContent.map(item => {
                        const typeConfig = TYPE_CONFIG[item.type];
                        const statusConfig = STATUS_CONFIG[item.status];
                        
                        return (
                            <div key={item.id} className="p-4 hover:bg-muted/50 transition-colors">
                                <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                                    {/* Icon */}
                                    <div className="hidden sm:flex w-12 h-12 rounded-lg bg-muted items-center justify-center text-2xl flex-shrink-0">
                                        {typeConfig.icon}
                                    </div>
                                    
                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                                            <span className="sm:hidden text-lg">{typeConfig.icon}</span>
                                            <h3 className="font-semibold text-foreground truncate">{item.title}</h3>
                                            <span className={cn(
                                                'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                typeConfig.bg,
                                                typeConfig.text
                                            )}>
                                                {typeConfig.label}
                                            </span>
                                            <span className={cn(
                                                'px-2.5 py-0.5 rounded-full text-xs font-medium flex items-center gap-1',
                                                statusConfig.bg,
                                                statusConfig.text
                                            )}>
                                                <span className={cn('w-1.5 h-1.5 rounded-full', statusConfig.dot)} />
                                                {statusConfig.label}
                                            </span>
                                        </div>
                                        <p className="text-sm text-muted-foreground line-clamp-2 mb-2">{item.excerpt}</p>
                                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                                            <span>By {item.author}</span>
                                            {item.publishedAt && (
                                                <span>Published {timeAgo(item.publishedAt)}</span>
                                            )}
                                            {item.scheduledFor && item.status === 'scheduled' && (
                                                <span className="text-warning">
                                                    Scheduled for {formatDateOnly(item.scheduledFor)}
                                                </span>
                                            )}
                                            {item.views !== undefined && item.status === 'published' && (
                                                <span>{item.views.toLocaleString()} views</span>
                                            )}
                                            <span className="font-mono text-muted-foreground/50">/{item.slug}</span>
                                        </div>
                                        {item.tags.length > 0 && (
                                            <div className="flex gap-1 mt-2 flex-wrap">
                                                {item.tags.map(tag => (
                                                    <span 
                                                        key={tag}
                                                        className="px-2.5 py-0.5 bg-muted text-muted-foreground rounded text-xs"
                                                    >
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Actions */}
                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <button
                                            onClick={() => setEditingItem(item)}
                                            className="px-3 py-1.5 text-sm font-medium text-muted-foreground bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                                        >
                                            Edit
                                        </button>
                                        {item.status === 'draft' && (
                                            <button
                                                onClick={() => publishItem(item.id)}
                                                className="px-3 py-1.5 text-sm font-medium text-success bg-success/10 hover:bg-success/20 rounded-lg transition-colors"
                                            >
                                                Publish
                                            </button>
                                        )}
                                        <div className="relative group">
                                            <button type="button" aria-label="Content item actions" className="p-1.5 text-muted-foreground hover:text-foreground transition-colors">
                                                ⋮
                                            </button>
                                            <div className="absolute right-0 top-full mt-1 w-40 bg-popover border border-border rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                                                <button
                                                    onClick={() => duplicateItem(item)}
                                                    className="w-full px-3 py-2 text-left text-sm text-muted-foreground hover:bg-muted/50"
                                                >
                                                    Duplicate
                                                </button>
                                                <button
                                                    onClick={() => window.open(`/preview/${item.slug}`, '_blank')}
                                                    className="w-full px-3 py-2 text-left text-sm text-muted-foreground hover:bg-muted/50"
                                                >
                                                    Preview
                                                </button>
                                                {item.status !== 'archived' && (
                                                    <button
                                                        onClick={() => archiveItem(item.id)}
                                                        className="w-full px-3 py-2 text-left text-sm text-muted-foreground hover:bg-muted/50"
                                                    >
                                                        Archive
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => deleteItem(item.id)}
                                                    className="w-full px-3 py-2 text-left text-sm text-destructive hover:bg-destructive/10"
                                                >
                                                    Delete
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                    
                    {filteredContent.length === 0 && (
                        <div className="p-12 text-center text-muted-foreground">
                            No content matches your filters
                        </div>
                    )}
                </div>
            </div>

            {/* Create/Edit Modal */}
            {(isCreating || editingItem) && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="bg-card rounded-xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-border">
                        <div className="p-6 border-b border-border sticky top-0 bg-card z-10">
                            <h2 className="text-lg font-semibold text-foreground">
                                {editingItem ? 'Edit Content' : 'Create New Content'}
                            </h2>
                        </div>
                        <form 
                            className="p-6 space-y-4"
                            onSubmit={(e) => {
                                e.preventDefault();
                                const form = e.target as HTMLFormElement;
                                const formData = new FormData(form);
                                const title = (formData.get('title') as string).trim();
                                const slug = (formData.get('slug') as string).trim();
                                const author = (formData.get('author') as string).trim();
                                const excerpt = (formData.get('excerpt') as string).trim();
                                const contentBody = (formData.get('content') as string).trim();

                                if (title.length < CONTENT_FORM_SCHEMA.minTitleLength) {
                                    setEditorFormError(`Title must be at least ${CONTENT_FORM_SCHEMA.minTitleLength} characters.`);
                                    return;
                                }
                                if (!CONTENT_FORM_SCHEMA.slugPattern.test(slug)) {
                                    setEditorFormError('Slug must be lowercase and use hyphens only.');
                                    return;
                                }
                                if (author.length < CONTENT_FORM_SCHEMA.minAuthorLength) {
                                    setEditorFormError(`Author must be at least ${CONTENT_FORM_SCHEMA.minAuthorLength} characters.`);
                                    return;
                                }
                                if (excerpt.length < CONTENT_FORM_SCHEMA.minExcerptLength) {
                                    setEditorFormError(`Excerpt must be at least ${CONTENT_FORM_SCHEMA.minExcerptLength} characters.`);
                                    return;
                                }
                                if (contentBody.length < CONTENT_FORM_SCHEMA.minContentLength) {
                                    setEditorFormError(`Content must be at least ${CONTENT_FORM_SCHEMA.minContentLength} characters.`);
                                    return;
                                }
                                setEditorFormError('');
                                
                                const itemData = {
                                    id: editingItem?.id || `c${Date.now()}`,
                                    title,
                                    slug,
                                    type: formData.get('type') as ContentItem['type'],
                                    status: formData.get('status') as ContentItem['status'],
                                    excerpt,
                                    content: contentBody,
                                    author,
                                    category: formData.get('category') as string || undefined,
                                    tags: (formData.get('tags') as string).split(',').map(t => t.trim()).filter(Boolean),
                                    publishedAt: editingItem?.publishedAt,
                                    scheduledFor: formData.get('scheduledFor') as string || undefined,
                                    createdAt: editingItem?.createdAt || new Date().toISOString(),
                                    updatedAt: new Date().toISOString(),
                                    views: editingItem?.views || 0,
                                };
                                
                                if (editingItem) {
                                    setContent(prev => prev.map(item => 
                                        item.id === editingItem.id ? itemData : item
                                    ));
                                } else {
                                    setContent(prev => [itemData, ...prev]);
                                }
                                
                                // Persist create/edit to API
                                getCsrfToken().then(csrfToken => {
                                    fetch('/api/content', {
                                        method: editingItem ? 'PUT' : 'POST',
                                        credentials: 'include',
                                        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
                                        body: JSON.stringify(itemData),
                                    }).then(res => {
                                        if (!res.ok) throw new Error('Failed');
                                    }).catch(() => {
                                        if (editingItem) {
                                            setContent(prev => prev.map(item => item.id === editingItem.id ? editingItem : item));
                                        } else {
                                            setContent(prev => prev.filter(item => item.id !== itemData.id));
                                        }
                                        dialog.alert({ title: 'Save Failed', message: 'Could not save content to the server. Your changes have been reverted.' });
                                    });
                                });

                                setEditingItem(null);
                                setIsCreating(false);
                            }}
                        >
                            {editorFormError ? (
                                <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive" role="alert">
                                    {editorFormError}
                                </div>
                            ) : null}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Title</label>
                                    <input
                                        name="title"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.title || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground"
                                        placeholder="Content title"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Slug</label>
                                    <input
                                        name="slug"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.slug || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground font-mono"
                                        placeholder="url-friendly-slug"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Author</label>
                                    <input
                                        name="author"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.author || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground"
                                        placeholder="Author name"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Type</label>
                                    <select
                                        name="type"
                                        required
                                        defaultValue={editingItem?.type || 'blog'}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground"
                                    >
                                        <option value="blog">Blog Post</option>
                                        <option value="changelog">Changelog</option>
                                        <option value="docs">Documentation</option>
                                        <option value="announcement">Announcement</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Status</label>
                                    <select
                                        name="status"
                                        required
                                        defaultValue={editingItem?.status || 'draft'}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground"
                                    >
                                        <option value="draft">Draft</option>
                                        <option value="scheduled">Scheduled</option>
                                        <option value="published">Published</option>
                                        <option value="archived">Archived</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Category</label>
                                    <input
                                        name="category"
                                        type="text"
                                        defaultValue={editingItem?.category || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground"
                                        placeholder="Optional category"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Schedule For</label>
                                    <input
                                        name="scheduledFor"
                                        type="datetime-local"
                                        defaultValue={editingItem?.scheduledFor?.slice(0, 16) || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Tags (comma-separated)</label>
                                    <input
                                        name="tags"
                                        type="text"
                                        defaultValue={editingItem?.tags.join(', ') || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground"
                                        placeholder="tag1, tag2, tag3"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Excerpt</label>
                                    <textarea
                                        name="excerpt"
                                        required
                                        rows={2}
                                        defaultValue={editingItem?.excerpt || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground resize-none"
                                        placeholder="Brief summary for previews and SEO"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Content (Markdown)</label>
                                    <textarea
                                        name="content"
                                        required
                                        rows={12}
                                        defaultValue={editingItem?.content || ''}
                                        className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring bg-background text-foreground placeholder:text-muted-foreground font-mono resize-none"
                                        placeholder="# Heading&#10;&#10;Content in markdown format..."
                                    />
                                </div>
                            </div>
                            
                            <div className="flex justify-end gap-3 pt-4 border-t border-border">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setEditingItem(null);
                                        setIsCreating(false);
                                    }}
                                    className="px-4 py-2 text-muted-foreground hover:text-foreground text-sm font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
                                >
                                    {editingItem ? 'Save Changes' : 'Create Content'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

export default function ContentPage() {
    return (
        <Suspense fallback={<div>Loading...</div>}>
            <ContentPageContent />
        </Suspense>
    );
}
