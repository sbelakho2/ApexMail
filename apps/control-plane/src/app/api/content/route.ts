/**
 * Content & CMS API
 * 
 * Returns content items (blog posts, changelogs, docs).
 * Used by the /content page.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with real CMS database or headless CMS integration
const DEMO_CONTENT = [
    {
        id: 'c1', title: 'Introducing AI-Powered Email Insights', slug: 'ai-powered-email-insights',
        type: 'blog', status: 'published',
        excerpt: 'Unlock deeper understanding of your email performance with our new AI analytics dashboard.',
        content: '# AI-Powered Email Insights\n\nWe are excited to announce...',
        author: 'Sarah Chen', category: 'Product Updates', tags: ['AI', 'Analytics', 'New Feature'],
        featuredImage: '/images/blog/ai-insights.jpg',
        publishedAt: '2025-01-18T10:00:00Z', createdAt: '2025-01-15T08:00:00Z', updatedAt: '2025-01-18T09:45:00Z', views: 3420,
    },
    {
        id: 'c2', title: 'Q1 2025 Product Roadmap', slug: 'q1-2025-roadmap',
        type: 'blog', status: 'scheduled',
        excerpt: 'A preview of what we have planned for the first quarter of 2025.',
        content: '# Q1 2025 Product Roadmap\n\nAs we enter the new year...',
        author: 'Michael Torres', category: 'Company News', tags: ['Roadmap', 'Planning'],
        scheduledFor: '2025-01-25T09:00:00Z', createdAt: '2025-01-20T14:00:00Z', updatedAt: '2025-01-21T11:30:00Z',
    },
    {
        id: 'c3', title: 'Version 2.4.0 Release Notes', slug: 'v2-4-0-release',
        type: 'changelog', status: 'published',
        excerpt: 'New features: Bulk import improvements, Webhook v2 beta, Performance optimizations',
        content: '## Version 2.4.0\n\n### New Features\n- Bulk import...',
        author: 'DevOps Team', tags: ['Release', 'v2.4'],
        publishedAt: '2025-01-15T16:00:00Z', createdAt: '2025-01-15T12:00:00Z', updatedAt: '2025-01-15T15:30:00Z', views: 1856,
    },
    {
        id: 'c4', title: 'Version 2.3.2 Hotfix', slug: 'v2-3-2-hotfix',
        type: 'changelog', status: 'published',
        excerpt: 'Fixed: Rate limiting edge case, Webhook retry logic, Dashboard timezone display',
        content: '## Version 2.3.2\n\n### Bug Fixes\n- Fixed rate limiting...',
        author: 'DevOps Team', tags: ['Release', 'Hotfix', 'v2.3'],
        publishedAt: '2025-01-10T12:00:00Z', createdAt: '2025-01-10T09:00:00Z', updatedAt: '2025-01-10T11:45:00Z', views: 892,
    },
];

export async function GET() {
    try {
        // TODO: Replace with real CMS/content table query
        return NextResponse.json(DEMO_CONTENT);
    } catch (error) {
        console.error('Content API error:', error);
        return NextResponse.json(DEMO_CONTENT);
    }
}
