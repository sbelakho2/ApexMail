/**
 * Inbox Sentinel API
 * 
 * Returns classified incoming email replies from campaigns.
 * Used by the /inbox page.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with DB query against a campaign_replies or inbox table
const DEMO_MESSAGES = [
    { id: '1', from: 'john@techcorp.io', fromName: 'John Smith', subject: 'Re: Quick question about your email infrastructure', preview: "Hi Alex, thanks for reaching out! We're actually looking to switch providers and would love to schedule a call...", receivedAt: new Date(Date.now() - 1800000).toISOString(), classification: 'interested', confidence: 0.95, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-1', read: false, starred: true },
    { id: '2', from: 'jane@startup.com', fromName: 'Jane Doe', subject: 'Re: Following up on email deliverability', preview: "I appreciate the follow-up, but we're not looking to change our email provider at this time...", receivedAt: new Date(Date.now() - 3600000).toISOString(), classification: 'not_interested', confidence: 0.88, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-2', read: true, starred: false },
    { id: '3', from: 'mike@enterprise.co', fromName: 'Mike Johnson', subject: 'Re: Enterprise email at scale', preview: "I'm out of the office until January 15th with limited access to email. For urgent matters...", receivedAt: new Date(Date.now() - 7200000).toISOString(), classification: 'out_of_office', confidence: 0.99, campaignId: 'camp-2', campaignName: 'Enterprise Nurture', leadId: 'lead-3', read: true, starred: false },
    { id: '4', from: 'sarah@growth.io', fromName: 'Sarah Williams', subject: 'Re: Thanks for checking out ApexMail!', preview: "What's the pricing for your team plan? We have about 50 users and send around 100k emails monthly...", receivedAt: new Date(Date.now() - 14400000).toISOString(), classification: 'question', confidence: 0.82, campaignId: 'camp-3', campaignName: 'Product Hunt Follow-up', leadId: 'lead-4', read: false, starred: false },
    { id: '5', from: 'no-reply@spam.net', fromName: 'Marketing Team', subject: 'Re: Your email', preview: "Click here to claim your prize! You've been selected for...", receivedAt: new Date(Date.now() - 21600000).toISOString(), classification: 'spam', confidence: 0.97, campaignId: null, campaignName: null, leadId: null, read: true, starred: false },
    { id: '6', from: 'tom@newcompany.dev', fromName: 'Tom Harris', subject: 'Re: Quick question', preview: 'Please remove me from your mailing list...', receivedAt: new Date(Date.now() - 28800000).toISOString(), classification: 'unsubscribe', confidence: 0.91, campaignId: 'camp-1', campaignName: 'SaaS Founders Outreach', leadId: 'lead-5', read: true, starred: false },
];

export async function GET() {
    try {
        // TODO: Replace with real inbox/campaign_replies query
        return NextResponse.json(DEMO_MESSAGES);
    } catch (error) {
        console.error('Inbox API error:', error);
        return NextResponse.json(DEMO_MESSAGES);
    }
}
