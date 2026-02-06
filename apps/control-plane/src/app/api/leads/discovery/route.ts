/**
 * Lead Discovery API
 * 
 * Returns discovery sources and discovered leads.
 * Used by the /leads page.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with real lead discovery service queries
const DEMO_SOURCES = [
    { id: 'product_hunt', name: 'Product Hunt', icon: '🚀', enabled: true, lastRun: new Date(Date.now() - 3600000).toISOString(), leadsFound: 47, status: 'idle' },
    { id: 'g2', name: 'G2 Crowd', icon: '⭐', enabled: true, lastRun: new Date(Date.now() - 7200000).toISOString(), leadsFound: 89, status: 'idle' },
    { id: 'capterra', name: 'Capterra', icon: '📊', enabled: true, lastRun: new Date(Date.now() - 14400000).toISOString(), leadsFound: 63, status: 'idle' },
    { id: 'crunchbase', name: 'Crunchbase', icon: '💼', enabled: false, lastRun: null, leadsFound: 0, status: 'idle' },
];

const DEMO_LEADS = [
    { id: '1', companyName: 'EmailNinja Pro', domain: 'emailninja.io', source: 'product_hunt', category: 'Email Marketing', description: 'AI-powered email scheduling for busy professionals', foundAt: new Date(Date.now() - 1800000).toISOString(), imported: false },
    { id: '2', companyName: 'NewsletterOS', domain: 'newsletteros.com', source: 'g2', category: 'Newsletter Platforms', description: 'Complete newsletter management platform', foundAt: new Date(Date.now() - 3600000).toISOString(), imported: false },
    { id: '3', companyName: 'SendMetrics', domain: 'sendmetrics.co', source: 'capterra', category: 'Email Marketing', description: 'Email analytics and reporting dashboard', foundAt: new Date(Date.now() - 7200000).toISOString(), imported: true },
    { id: '4', companyName: 'AutoMailer Hub', domain: 'automailerhub.com', source: 'product_hunt', category: 'Marketing Automation', description: 'Automated email sequences for SaaS', foundAt: new Date(Date.now() - 14400000).toISOString(), imported: false },
    { id: '5', companyName: 'ColdReach AI', domain: 'coldreach.ai', source: 'g2', category: 'Sales Enablement', description: 'AI cold email personalization', foundAt: new Date(Date.now() - 21600000).toISOString(), imported: false },
];

export async function GET() {
    try {
        // TODO: Replace with real lead discovery service query
        return NextResponse.json({
            sources: DEMO_SOURCES,
            leads: DEMO_LEADS,
        });
    } catch (error) {
        console.error('Leads discovery API error:', error);
        return NextResponse.json({
            sources: DEMO_SOURCES,
            leads: DEMO_LEADS,
        });
    }
}
