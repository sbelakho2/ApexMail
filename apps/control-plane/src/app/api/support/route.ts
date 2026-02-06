import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with DB query against support_tickets table
const DEMO_TICKETS = [
    {
        id: 'ticket-1',
        subject: 'Cannot access API dashboard',
        description: 'I\'ve been trying to access the API dashboard but keep getting a 403 error. I\'ve checked my permissions and everything seems correct.',
        tenantId: 'tenant-1',
        tenantName: 'TechCorp Solutions',
        tenantEmail: 'admin@techcorp.io',
        status: 'open',
        priority: 'high',
        category: 'technical',
        assignee: null,
        createdAt: new Date(1737000000000 - 3600000).toISOString(),
        updatedAt: new Date(1737000000000 - 3600000).toISOString(),
        messages: [
            { id: 'm1', content: 'I\'ve been trying to access the API dashboard but keep getting a 403 error. I\'ve checked my permissions and everything seems correct.', author: 'John Smith', authorType: 'customer', createdAt: new Date(1737000000000 - 3600000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-2',
        subject: 'Billing discrepancy on last invoice',
        description: 'Our last invoice shows charges for 150k emails but our tracking shows only 120k sent. Can you please review?',
        tenantId: 'tenant-2',
        tenantName: 'Newsletter Pro',
        tenantEmail: 'billing@newsletter.pro',
        status: 'in_progress',
        priority: 'medium',
        category: 'billing',
        assignee: 'Alex (Support)',
        createdAt: new Date(1737000000000 - 86400000).toISOString(),
        updatedAt: new Date(1737000000000 - 7200000).toISOString(),
        messages: [
            { id: 'm2', content: 'Our last invoice shows charges for 150k emails but our tracking shows only 120k sent. Can you please review?', author: 'Jane Doe', authorType: 'customer', createdAt: new Date(1737000000000 - 86400000).toISOString(), attachments: ['invoice-dec.pdf'] },
            { id: 'm3', content: 'Hi Jane, thank you for reaching out. I\'m looking into this now and will get back to you shortly.', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(1737000000000 - 72000000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-3',
        subject: 'Request: Custom webhook headers',
        description: 'We need the ability to add custom headers to our webhooks for authentication with our backend. Is this on the roadmap?',
        tenantId: 'tenant-3',
        tenantName: 'E-Commerce Store',
        tenantEmail: 'dev@shop.example.com',
        status: 'waiting_on_customer',
        priority: 'low',
        category: 'feature_request',
        assignee: 'Alex (Support)',
        createdAt: new Date(1737000000000 - 259200000).toISOString(),
        updatedAt: new Date(1737000000000 - 172800000).toISOString(),
        messages: [
            { id: 'm4', content: 'We need the ability to add custom headers to our webhooks for authentication with our backend. Is this on the roadmap?', author: 'Mike Chen', authorType: 'customer', createdAt: new Date(1737000000000 - 259200000).toISOString(), attachments: [] },
            { id: 'm5', content: 'Great suggestion! This is actually something we\'re considering. Could you share more about your specific use case?', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(1737000000000 - 172800000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-4',
        subject: 'Emails going to spam for gmail recipients',
        description: 'Starting yesterday, our transactional emails are landing in spam for Gmail users. We haven\'t changed anything on our end.',
        tenantId: 'tenant-1',
        tenantName: 'TechCorp Solutions',
        tenantEmail: 'admin@techcorp.io',
        status: 'open',
        priority: 'urgent',
        category: 'bug',
        assignee: null,
        createdAt: new Date(1737000000000 - 1800000).toISOString(),
        updatedAt: new Date(1737000000000 - 1800000).toISOString(),
        messages: [
            { id: 'm6', content: 'Starting yesterday, our transactional emails are landing in spam for Gmail users. We haven\'t changed anything on our end.', author: 'John Smith', authorType: 'customer', createdAt: new Date(1737000000000 - 1800000).toISOString(), attachments: ['email-headers.txt'] },
        ],
    },
    {
        id: 'ticket-5',
        subject: 'How to set up DKIM for subdomain?',
        description: 'We want to send emails from a subdomain. What DKIM records do we need to add?',
        tenantId: 'tenant-4',
        tenantName: 'StartupXYZ',
        tenantEmail: 'founder@startupxyz.com',
        status: 'resolved',
        priority: 'medium',
        category: 'general',
        assignee: 'Alex (Support)',
        createdAt: new Date(1737000000000 - 604800000).toISOString(),
        updatedAt: new Date(1737000000000 - 518400000).toISOString(),
        messages: [
            { id: 'm7', content: 'We want to send emails from a subdomain. What DKIM records do we need to add?', author: 'Sarah Lee', authorType: 'customer', createdAt: new Date(1737000000000 - 604800000).toISOString(), attachments: [] },
            { id: 'm8', content: 'Here\'s a guide for setting up DKIM on subdomains:\n\n1. Go to Settings > Domains\n2. Click "Add Domain" and enter your subdomain\n3. Follow the DNS record instructions\n\nLet me know if you need any clarification!', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(1737000000000 - 518400000).toISOString(), attachments: [] },
            { id: 'm9', content: 'That worked perfectly, thank you!', author: 'Sarah Lee', authorType: 'customer', createdAt: new Date(1737000000000 - 518400000).toISOString(), attachments: [] },
        ],
    },
];

export async function GET() {
    try {
        // TODO: Query support_tickets table with messages
        return NextResponse.json(DEMO_TICKETS);
    } catch {
        return NextResponse.json(DEMO_TICKETS);
    }
}
