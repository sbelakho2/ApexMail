/**
 * Content & CMS API
 *
 * FIX-500-141: DB-backed content management — no demo data.
 * Queries the content_items table.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface ContentRow {
    id: string;
    title: string;
    slug: string;
    type: string;
    status: string;
    excerpt: string | null;
    content: string | null;
    author: string | null;
    category: string | null;
    tags: string[];
    featured_image: string | null;
    scheduled_for: string | null;
    published_at: string | null;
    views: string;
    created_at: string;
    updated_at: string;
}

export async function GET(request: Request) {
    try {
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<ContentRow>(
            `SELECT id, title, slug, type, status, excerpt, content, author,
                    category, tags, featured_image, scheduled_for, published_at,
                    views, created_at, updated_at
             FROM content_items
             ORDER BY COALESCE(published_at, created_at) DESC
             LIMIT $1 OFFSET $2`,
            [limit, offset]
        );
        return NextResponse.json(rows.map((r) => ({
            id: r.id,
            title: r.title,
            slug: r.slug,
            type: r.type,
            status: r.status,
            excerpt: r.excerpt,
            content: r.content,
            author: r.author,
            category: r.category,
            tags: r.tags,
            featuredImage: r.featured_image,
            scheduledFor: r.scheduled_for,
            publishedAt: r.published_at,
            views: parseInt(String(r.views), 10),
            createdAt: r.created_at,
            updatedAt: r.updated_at,
        })));
    } catch (error) {
        console.error('Content API error:', error);
        return NextResponse.json({ error: 'Failed to fetch content' }, { status: 500 });
    }
}
