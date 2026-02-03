'use client';

import { useState, useEffect, useCallback } from 'react';
import { cn, timeAgo } from '../../lib/utils';
import { useSearchParams } from 'next/navigation';

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

const DEMO_CONTENT: ContentItem[] = [
    { 
        id: 'c1', 
        title: 'Introducing AI-Powered Email Insights', 
        slug: 'ai-powered-email-insights',
        type: 'blog', 
        status: 'published',
        excerpt: 'Unlock deeper understanding of your email performance with our new AI analytics dashboard.',
        content: '# AI-Powered Email Insights\n\nWe are excited to announce...',
        author: 'Sarah Chen',
        category: 'Product Updates',
        tags: ['AI', 'Analytics', 'New Feature'],
        featuredImage: '/images/blog/ai-insights.jpg',
        publishedAt: '2025-01-18T10:00:00Z',
        createdAt: '2025-01-15T08:00:00Z',
        updatedAt: '2025-01-18T09:45:00Z',
        views: 3420
    },
    { 
        id: 'c2', 
        title: 'Q1 2025 Product Roadmap', 
        slug: 'q1-2025-roadmap',
        type: 'blog', 
        status: 'scheduled',
        excerpt: 'A preview of what we have planned for the first quarter of 2025.',
        content: '# Q1 2025 Product Roadmap\n\nAs we enter the new year...',
        author: 'Michael Torres',
        category: 'Company News',
        tags: ['Roadmap', 'Planning'],
        scheduledFor: '2025-01-25T09:00:00Z',
        createdAt: '2025-01-20T14:00:00Z',
        updatedAt: '2025-01-21T11:30:00Z'
    },
    { 
        id: 'c3', 
        title: 'Version 2.4.0 Release Notes', 
        slug: 'v2-4-0-release',
        type: 'changelog', 
        status: 'published',
        excerpt: 'New features: Bulk import improvements, Webhook v2 beta, Performance optimizations',
        content: '## Version 2.4.0\n\n### New Features\n- Bulk import...',
        author: 'DevOps Team',
        tags: ['Release', 'v2.4'],
        publishedAt: '2025-01-15T16:00:00Z',
        createdAt: '2025-01-15T12:00:00Z',
        updatedAt: '2025-01-15T15:30:00Z',
        views: 1856
    },
    { 
        id: 'c4', 
        title: 'Version 2.3.2 Hotfix', 
        slug: 'v2-3-2-hotfix',
        type: 'changelog', 
        status: 'published',
        excerpt: 'Fixed: Rate limiting edge case, Webhook retry logic, Dashboard timezone display',
        content: '## Version 2.3.2\n\n### Bug Fixes\n- Fixed rate limiting...',
        author: 'DevOps Team',
        tags: ['Release', 'Hotfix', 'v2.3'],
        publishedAt: '2025-01-10T12:00:00Z',
        createdAt: '2025-01-10T09:00:00Z',
        updatedAt: '2025-01-10T11:45:00Z',
        views: 892
    },
    { 
        id: 'c5', 
        title: 'API Authentication Guide', 
        slug: 'api-authentication',
        type: 'docs', 
        status: 'published',
        excerpt: 'Learn how to authenticate with the ApexMail API using API keys and OAuth.',
        content: '# API Authentication\n\n## Getting Started\n...',
        author: 'Documentation Team',
        category: 'API Reference',
        tags: ['API', 'Authentication', 'Security'],
        publishedAt: '2024-12-01T00:00:00Z',
        createdAt: '2024-11-15T10:00:00Z',
        updatedAt: '2025-01-05T14:20:00Z',
        views: 12450
    },
    { 
        id: 'c6', 
        title: 'Webhook Integration Best Practices', 
        slug: 'webhook-best-practices',
        type: 'docs', 
        status: 'draft',
        excerpt: 'Best practices for implementing reliable webhook integrations.',
        content: '# Webhook Best Practices\n\n## Overview\n...',
        author: 'Documentation Team',
        category: 'Guides',
        tags: ['Webhooks', 'Integration', 'Best Practices'],
        createdAt: '2025-01-18T09:00:00Z',
        updatedAt: '2025-01-20T16:00:00Z'
    },
    { 
        id: 'c7', 
        title: 'Scheduled Maintenance - January 28', 
        slug: 'maintenance-jan-28',
        type: 'announcement', 
        status: 'scheduled',
        excerpt: 'Planned maintenance window for infrastructure upgrades.',
        content: '# Scheduled Maintenance\n\nWe will be performing...',
        author: 'Infrastructure Team',
        tags: ['Maintenance', 'Infrastructure'],
        scheduledFor: '2025-01-26T18:00:00Z',
        createdAt: '2025-01-20T10:00:00Z',
        updatedAt: '2025-01-20T10:00:00Z'
    },
];

const TYPE_CONFIG: Record<string, { label: string; bg: string; text: string; icon: string }> = {
    blog: { label: 'Blog Post', bg: 'bg-blue-100', text: 'text-blue-700', icon: '📝' },
    changelog: { label: 'Changelog', bg: 'bg-violet-100', text: 'text-violet-700', icon: '📋' },
    docs: { label: 'Documentation', bg: 'bg-emerald-100', text: 'text-emerald-700', icon: '📚' },
    announcement: { label: 'Announcement', bg: 'bg-amber-100', text: 'text-amber-700', icon: '📢' },
};

const STATUS_CONFIG: Record<string, { label: string; bg: string; text: string; dot: string }> = {
    draft: { label: 'Draft', bg: 'bg-surface-100', text: 'text-surface-600', dot: 'bg-surface-400' },
    scheduled: { label: 'Scheduled', bg: 'bg-amber-100', text: 'text-amber-700', dot: 'bg-amber-500' },
    published: { label: 'Published', bg: 'bg-emerald-100', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    archived: { label: 'Archived', bg: 'bg-surface-100', text: 'text-surface-500', dot: 'bg-surface-300' },
};

export default function ContentPage() {
    const searchParams = useSearchParams();
    const [content, setContent] = useState<ContentItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [typeFilter, setTypeFilter] = useState<string>(searchParams.get('type') || 'all');
    const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || 'all');
    const [searchQuery, setSearchQuery] = useState('');
    
    // Editor state
    const [editingItem, setEditingItem] = useState<ContentItem | null>(null);
    const [isCreating, setIsCreating] = useState(false);

    const loadData = useCallback(async () => {
        try {
            // In production: fetch from CMS API
            setContent(DEMO_CONTENT);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
    }, [loadData]);

    function publishItem(itemId: string) {
        setContent(prev => prev.map(item => 
            item.id === itemId 
                ? { ...item, status: 'published' as const, publishedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }
                : item
        ));
    }

    function archiveItem(itemId: string) {
        setContent(prev => prev.map(item => 
            item.id === itemId 
                ? { ...item, status: 'archived' as const, updatedAt: new Date().toISOString() }
                : item
        ));
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
        setContent(prev => [newItem, ...prev]);
    }

    function deleteItem(itemId: string) {
        if (confirm('Are you sure you want to delete this content?')) {
            setContent(prev => prev.filter(item => item.id !== itemId));
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
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Content & CMS</h1>
                    <p className="text-surface-600 mt-1">
                        Manage blog posts, changelog, and documentation
                    </p>
                </div>
                <button 
                    onClick={() => setIsCreating(true)}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 font-medium transition-colors"
                >
                    + New Content
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Total Content</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">{stats.total}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Published</div>
                    <div className="text-2xl font-bold text-emerald-600 mt-1">{stats.published}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Drafts</div>
                    <div className="text-2xl font-bold text-surface-600 mt-1">{stats.drafts}</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Scheduled</div>
                    <div className="text-2xl font-bold text-amber-600 mt-1">{stats.scheduled}</div>
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
                        className="w-full px-4 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
                <div className="flex gap-2 flex-wrap">
                    <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        className="px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-surface-0"
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
                        className="px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-surface-0"
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
            <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                <div className="divide-y divide-surface-100">
                    {filteredContent.map(item => {
                        const typeConfig = TYPE_CONFIG[item.type];
                        const statusConfig = STATUS_CONFIG[item.status];
                        
                        return (
                            <div key={item.id} className="p-4 hover:bg-surface-50/50 transition-colors">
                                <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                                    {/* Icon */}
                                    <div className="hidden sm:flex w-12 h-12 rounded-lg bg-surface-100 items-center justify-center text-2xl flex-shrink-0">
                                        {typeConfig.icon}
                                    </div>
                                    
                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                                            <span className="sm:hidden text-lg">{typeConfig.icon}</span>
                                            <h3 className="font-semibold text-surface-900 truncate">{item.title}</h3>
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
                                        <p className="text-sm text-surface-500 line-clamp-2 mb-2">{item.excerpt}</p>
                                        <div className="flex items-center gap-4 text-xs text-surface-400 flex-wrap">
                                            <span>By {item.author}</span>
                                            {item.publishedAt && (
                                                <span>Published {timeAgo(item.publishedAt)}</span>
                                            )}
                                            {item.scheduledFor && item.status === 'scheduled' && (
                                                <span className="text-amber-600">
                                                    Scheduled for {new Date(item.scheduledFor).toLocaleDateString()}
                                                </span>
                                            )}
                                            {item.views !== undefined && item.status === 'published' && (
                                                <span>{item.views.toLocaleString()} views</span>
                                            )}
                                            <span className="font-mono text-surface-300">/{item.slug}</span>
                                        </div>
                                        {item.tags.length > 0 && (
                                            <div className="flex gap-1 mt-2 flex-wrap">
                                                {item.tags.map(tag => (
                                                    <span 
                                                        key={tag}
                                                        className="px-2.5 py-0.5 bg-surface-100 text-surface-600 rounded text-xs"
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
                                            className="px-3 py-1.5 text-sm font-medium text-surface-600 bg-surface-100 hover:bg-surface-200 rounded-lg transition-colors"
                                        >
                                            Edit
                                        </button>
                                        {item.status === 'draft' && (
                                            <button
                                                onClick={() => publishItem(item.id)}
                                                className="px-3 py-1.5 text-sm font-medium text-emerald-600 bg-emerald-100 hover:bg-emerald-200 rounded-lg transition-colors"
                                            >
                                                Publish
                                            </button>
                                        )}
                                        <div className="relative group">
                                            <button className="p-1.5 text-surface-400 hover:text-surface-600 transition-colors">
                                                ⋮
                                            </button>
                                            <div className="absolute right-0 top-full mt-1 w-40 bg-surface-0 border border-surface-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                                                <button
                                                    onClick={() => duplicateItem(item)}
                                                    className="w-full px-3 py-2 text-left text-sm text-surface-600 hover:bg-surface-50"
                                                >
                                                    Duplicate
                                                </button>
                                                <button
                                                    onClick={() => window.open(`/preview/${item.slug}`, '_blank')}
                                                    className="w-full px-3 py-2 text-left text-sm text-surface-600 hover:bg-surface-50"
                                                >
                                                    Preview
                                                </button>
                                                {item.status !== 'archived' && (
                                                    <button
                                                        onClick={() => archiveItem(item.id)}
                                                        className="w-full px-3 py-2 text-left text-sm text-surface-600 hover:bg-surface-50"
                                                    >
                                                        Archive
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => deleteItem(item.id)}
                                                    className="w-full px-3 py-2 text-left text-sm text-red-600 hover:bg-red-50"
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
                        <div className="p-12 text-center text-surface-500">
                            No content matches your filters
                        </div>
                    )}
                </div>
            </div>

            {/* Create/Edit Modal */}
            {(isCreating || editingItem) && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-surface-0 rounded-xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
                        <div className="p-6 border-b border-surface-200 sticky top-0 bg-surface-0 z-10">
                            <h2 className="text-lg font-semibold text-surface-900">
                                {editingItem ? 'Edit Content' : 'Create New Content'}
                            </h2>
                        </div>
                        <form 
                            className="p-6 space-y-4"
                            onSubmit={(e) => {
                                e.preventDefault();
                                const form = e.target as HTMLFormElement;
                                const formData = new FormData(form);
                                
                                const itemData = {
                                    id: editingItem?.id || `c${Date.now()}`,
                                    title: formData.get('title') as string,
                                    slug: formData.get('slug') as string,
                                    type: formData.get('type') as ContentItem['type'],
                                    status: formData.get('status') as ContentItem['status'],
                                    excerpt: formData.get('excerpt') as string,
                                    content: formData.get('content') as string,
                                    author: formData.get('author') as string,
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
                                
                                setEditingItem(null);
                                setIsCreating(false);
                            }}
                        >
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Title</label>
                                    <input
                                        name="title"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.title || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        placeholder="Content title"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Slug</label>
                                    <input
                                        name="slug"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.slug || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                                        placeholder="url-friendly-slug"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Author</label>
                                    <input
                                        name="author"
                                        type="text"
                                        required
                                        defaultValue={editingItem?.author || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        placeholder="Author name"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Type</label>
                                    <select
                                        name="type"
                                        required
                                        defaultValue={editingItem?.type || 'blog'}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-surface-0"
                                    >
                                        <option value="blog">Blog Post</option>
                                        <option value="changelog">Changelog</option>
                                        <option value="docs">Documentation</option>
                                        <option value="announcement">Announcement</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Status</label>
                                    <select
                                        name="status"
                                        required
                                        defaultValue={editingItem?.status || 'draft'}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-surface-0"
                                    >
                                        <option value="draft">Draft</option>
                                        <option value="scheduled">Scheduled</option>
                                        <option value="published">Published</option>
                                        <option value="archived">Archived</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Category</label>
                                    <input
                                        name="category"
                                        type="text"
                                        defaultValue={editingItem?.category || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        placeholder="Optional category"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Schedule For</label>
                                    <input
                                        name="scheduledFor"
                                        type="datetime-local"
                                        defaultValue={editingItem?.scheduledFor?.slice(0, 16) || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Tags (comma-separated)</label>
                                    <input
                                        name="tags"
                                        type="text"
                                        defaultValue={editingItem?.tags.join(', ') || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        placeholder="tag1, tag2, tag3"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Excerpt</label>
                                    <textarea
                                        name="excerpt"
                                        required
                                        rows={2}
                                        defaultValue={editingItem?.excerpt || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                                        placeholder="Brief summary for previews and SEO"
                                    />
                                </div>
                                <div className="sm:col-span-2">
                                    <label className="block text-sm font-medium text-surface-700 mb-1">Content (Markdown)</label>
                                    <textarea
                                        name="content"
                                        required
                                        rows={12}
                                        defaultValue={editingItem?.content || ''}
                                        className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono resize-none"
                                        placeholder="# Heading&#10;&#10;Content in markdown format..."
                                    />
                                </div>
                            </div>
                            
                            <div className="flex justify-end gap-3 pt-4 border-t border-surface-200">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setEditingItem(null);
                                        setIsCreating(false);
                                    }}
                                    className="px-4 py-2 text-surface-600 hover:text-surface-900 text-sm font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
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
