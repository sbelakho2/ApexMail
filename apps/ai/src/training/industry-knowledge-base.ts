/**
 * @apexmail/ai — Industry Knowledge Base
 *
 * Comprehensive, research-backed email-marketing domain knowledge used to:
 *  1. Seed the Chatbot system prompt with authoritative context
 *  2. Provide the Mailbot with richer natural-language understanding
 *  3. Ground the quality-evaluator in real-world benchmarks
 *  4. Supply the CUDA training pipeline with labelled domain data
 *
 * Every number below is sourced from public 2023-2025 industry reports
 * (GetResponse, Constant Contact, Litmus, Mailchimp, HubSpot, Klaviyo, Omnisend).
 */

// ═══════════════════════════════════════════════════════════════
// 1. GLOSSARY — canonical email-marketing terminology
// ═══════════════════════════════════════════════════════════════

export interface GlossaryEntry {
    term: string;
    aliases: string[];
    definition: string;
    category: GlossaryCategory;
    relatedTerms: string[];
}

export type GlossaryCategory =
    | 'metric'
    | 'deliverability'
    | 'compliance'
    | 'strategy'
    | 'automation'
    | 'list-management'
    | 'content'
    | 'technical'
    | 'analytics';

export const GLOSSARY: GlossaryEntry[] = [
    // ── Metrics ──────────────────────────────────────────────────
    {
        term: 'Open Rate',
        aliases: ['OR', 'open ratio', 'email opens'],
        definition: 'The percentage of delivered emails that were opened by recipients. Calculated as (unique opens / delivered emails) × 100. Affected by Apple MPP since iOS 15 which pre-loads tracking pixels.',
        category: 'metric',
        relatedTerms: ['Click-Through Rate', 'Apple MPP', 'Tracking Pixel'],
    },
    {
        term: 'Click-Through Rate',
        aliases: ['CTR', 'click rate', 'email clicks'],
        definition: 'The percentage of delivered emails where at least one link was clicked. Calculated as (unique clicks / delivered emails) × 100. Industry average is ~2.6%.',
        category: 'metric',
        relatedTerms: ['Open Rate', 'Click-to-Open Rate', 'CTA'],
    },
    {
        term: 'Click-to-Open Rate',
        aliases: ['CTOR'],
        definition: 'The percentage of opened emails where a link was clicked. Calculated as (unique clicks / unique opens) × 100. More accurate than CTR for measuring content engagement since it removes the variability of open rates.',
        category: 'metric',
        relatedTerms: ['Click-Through Rate', 'Open Rate'],
    },
    {
        term: 'Conversion Rate',
        aliases: ['CVR', 'email conversion'],
        definition: 'The percentage of email recipients who completed a desired action (purchase, signup, download) after clicking through. Varies widely by industry—ecommerce averages ~1-5%.',
        category: 'metric',
        relatedTerms: ['Click-Through Rate', 'Revenue Per Email'],
    },
    {
        term: 'Bounce Rate',
        aliases: ['email bounce', 'bounced email', 'bounces', 'hard bounce', 'soft bounce', 'hard and soft bounce', 'bouncing'],
        definition: 'The percentage of sent emails that could not be delivered. Hard bounces (invalid address) should be removed immediately. Soft bounces (full inbox, server down) may resolve. Keep total bounce rate under 2%.',
        category: 'metric',
        relatedTerms: ['Hard Bounce', 'Soft Bounce', 'List Hygiene'],
    },
    {
        term: 'Unsubscribe Rate',
        aliases: ['unsub rate', 'opt-out rate'],
        definition: 'The percentage of recipients who unsubscribed after an email. Industry benchmark is ~0.1-0.5%. Rates above 0.5% suggest content-audience mismatch or excessive frequency.',
        category: 'metric',
        relatedTerms: ['List Hygiene', 'Complaint Rate', 'CAN-SPAM'],
    },
    {
        term: 'Complaint Rate',
        aliases: ['spam complaint rate', 'abuse rate', 'FBL rate'],
        definition: 'The percentage of recipients who marked the email as spam. Must stay below 0.1% (Google) or 0.3% (industry threshold). Measured via Feedback Loops (FBLs) from ISPs.',
        category: 'metric',
        relatedTerms: ['Feedback Loop', 'Sender Reputation', 'Spam'],
    },
    {
        term: 'Revenue Per Email',
        aliases: ['RPE', 'email revenue'],
        definition: 'Total revenue attributed to an email divided by number of delivered emails. Key ecommerce metric. Abandoned cart emails typically generate the highest RPE.',
        category: 'metric',
        relatedTerms: ['Conversion Rate', 'ROI'],
    },
    {
        term: 'List Growth Rate',
        aliases: ['subscriber growth'],
        definition: 'The rate at which your email list is growing. Calculated as ((new subscribers − unsubscribes − bounces) / total list size) × 100. Healthy lists grow 2-5% per month.',
        category: 'metric',
        relatedTerms: ['Opt-in', 'Double Opt-in', 'Lead Magnet'],
    },

    // ── Deliverability ───────────────────────────────────────────
    {
        term: 'Sender Reputation',
        aliases: ['IP reputation', 'domain reputation', 'sender score'],
        definition: 'A score assigned by ISPs based on sending patterns, complaint rates, bounce rates, and engagement. Determines whether emails reach the inbox or spam folder. Ranges from 0-100 (Sender Score by Validity).',
        category: 'deliverability',
        relatedTerms: ['SPF', 'DKIM', 'DMARC', 'IP Warming'],
    },
    {
        term: 'SPF',
        aliases: ['Sender Policy Framework'],
        definition: 'A DNS TXT record that specifies which mail servers are authorized to send email on behalf of your domain. Prevents spoofing. Essential for deliverability.',
        category: 'deliverability',
        relatedTerms: ['DKIM', 'DMARC', 'DNS'],
    },
    {
        term: 'DKIM',
        aliases: ['DomainKeys Identified Mail'],
        definition: 'An email authentication method using a digital signature in the email header that verifies the message was not altered in transit and originated from the claimed domain.',
        category: 'deliverability',
        relatedTerms: ['SPF', 'DMARC', 'Email Authentication'],
    },
    {
        term: 'DMARC',
        aliases: ['Domain-based Message Authentication Reporting and Conformance'],
        definition: 'An email authentication protocol that builds on SPF and DKIM. Tells receiving servers what to do when authentication fails (none, quarantine, reject). Required by Google and Yahoo since Feb 2024.',
        category: 'deliverability',
        relatedTerms: ['SPF', 'DKIM', 'BIMI'],
    },
    {
        term: 'BIMI',
        aliases: ['Brand Indicators for Message Identification'],
        definition: 'A standard that allows brands to display their logo next to authenticated emails in the inbox. Requires DMARC enforcement at p=quarantine or p=reject, plus a Verified Mark Certificate (VMC).',
        category: 'deliverability',
        relatedTerms: ['DMARC', 'Sender Reputation'],
    },
    {
        term: 'IP Warming',
        aliases: ['IP warm-up', 'warming up IP', 'warm up', 'email warm-up', 'warm up a new IP', 'ip warming', 'warm up ip'],
        definition: 'The process of gradually increasing email volume sent from a new IP address to build sender reputation with ISPs. Typically takes 4-8 weeks. Start with engaged subscribers first, then gradually expand to less engaged segments. Begin with 50-100 emails/day and double volume every 2-3 days.',
        category: 'deliverability',
        relatedTerms: ['Sender Reputation', 'Dedicated IP', 'Shared IP'],
    },
    {
        term: 'Feedback Loop',
        aliases: ['FBL', 'complaint feedback loop'],
        definition: 'A service provided by ISPs (Yahoo, Outlook, etc.) that notifies senders when recipients mark their email as spam. Essential for maintaining list hygiene and sender reputation.',
        category: 'deliverability',
        relatedTerms: ['Complaint Rate', 'Sender Reputation', 'ISP'],
    },
    {
        term: 'Spam Trap',
        aliases: ['honeypot', 'spam honeypot'],
        definition: 'Email addresses used by ISPs and anti-spam organizations to identify senders with poor list hygiene. Pristine traps (never opted in) are worse than recycled traps (abandoned addresses). Hitting spam traps severely damages sender reputation.',
        category: 'deliverability',
        relatedTerms: ['List Hygiene', 'Sender Reputation', 'Email Verification'],
    },
    {
        term: 'Apple MPP',
        aliases: ['Mail Privacy Protection', 'Apple Mail Privacy'],
        definition: 'Apple\'s privacy feature (iOS 15+, Sep 2021) that pre-loads tracking pixels and hides IP addresses, inflating open rates. ~60% of email opens now come from Apple readers. Makes open rate less reliable as a standalone metric.',
        category: 'deliverability',
        relatedTerms: ['Open Rate', 'Tracking Pixel', 'Privacy'],
    },
    {
        term: 'Inbox Placement Rate',
        aliases: ['IPR', 'inbox rate'],
        definition: 'The percentage of emails that actually land in the primary inbox (not spam/promotions). Industry average is ~81%. Measured by seed-list testing tools like GlockApps, Litmus, or EmailOnAcid.',
        category: 'deliverability',
        relatedTerms: ['Spam Folder', 'Deliverability', 'Sender Reputation'],
    },

    // ── Compliance ───────────────────────────────────────────────
    {
        term: 'CAN-SPAM',
        aliases: ['CAN-SPAM Act'],
        definition: 'US federal law (2003) requiring commercial emails to include: physical mailing address, clear unsubscribe mechanism (must honor within 10 business days), accurate From/Subject lines. Violations up to $51,744 per email.',
        category: 'compliance',
        relatedTerms: ['GDPR', 'CCPA', 'Unsubscribe'],
    },
    {
        term: 'GDPR',
        aliases: ['General Data Protection Regulation'],
        definition: 'EU regulation (2018) requiring explicit consent before sending marketing emails to EU residents. Requires: lawful basis for processing, right to be forgotten, data portability, 72-hour breach notification. Fines up to €20M or 4% of global revenue.',
        category: 'compliance',
        relatedTerms: ['CAN-SPAM', 'Double Opt-in', 'Data Privacy'],
    },
    {
        term: 'CCPA',
        aliases: ['California Consumer Privacy Act', 'CPRA'],
        definition: 'California privacy law giving consumers rights over their personal data: right to know, right to delete, right to opt out of sale. Amended by CPRA in 2023. Applies to businesses with >$25M revenue or >50K consumer records.',
        category: 'compliance',
        relatedTerms: ['GDPR', 'Data Privacy'],
    },
    {
        term: 'Double Opt-in',
        aliases: ['confirmed opt-in', 'DOI'],
        definition: 'A two-step subscription process where a user signs up and then confirms via a verification email. Produces higher quality lists with lower bounce/complaint rates. Required in Germany and recommended under GDPR.',
        category: 'compliance',
        relatedTerms: ['Single Opt-in', 'GDPR', 'List Quality'],
    },
    {
        term: 'List-Unsubscribe Header',
        aliases: ['one-click unsubscribe', 'RFC 8058'],
        definition: 'An email header (RFC 2369 + RFC 8058) that enables one-click unsubscribe in the email client UI. Required by Google and Yahoo since Feb 2024 for bulk senders (>5000 msgs/day). Must support both mailto: and HTTPS methods.',
        category: 'compliance',
        relatedTerms: ['CAN-SPAM', 'GDPR', 'Unsubscribe Rate'],
    },

    // ── Strategy ─────────────────────────────────────────────────
    {
        term: 'A/B Testing',
        aliases: ['split testing', 'A/B test', 'multivariate testing'],
        definition: 'Sending two or more variants of an email to different segments of your audience to determine which performs better. Test one variable at a time (subject line, CTA, send time, design). Statistical significance requires adequate sample sizes.',
        category: 'strategy',
        relatedTerms: ['Conversion Rate', 'Open Rate', 'CTR'],
    },
    {
        term: 'Segmentation',
        aliases: ['audience segmentation', 'list segmentation'],
        definition: 'Dividing your email list into targeted groups based on demographics, behavior, purchase history, or engagement level. Segmented campaigns see 14% higher open rates and 101% more clicks than non-segmented.',
        category: 'strategy',
        relatedTerms: ['Personalization', 'Dynamic Content', 'Targeting'],
    },
    {
        term: 'Personalization',
        aliases: ['email personalization', 'dynamic personalization'],
        definition: 'Customizing email content for individual recipients using merge tags ({{firstName}}), behavioral data, purchase history, or AI-driven recommendations. Personalized subject lines increase open rates by ~6%.',
        category: 'strategy',
        relatedTerms: ['Segmentation', 'Dynamic Content', 'Merge Tags'],
    },
    {
        term: 'Lead Magnet',
        aliases: ['opt-in incentive', 'content upgrade', 'freebie'],
        definition: 'A valuable resource (ebook, checklist, template, webinar) offered in exchange for an email address. Effective lead magnets solve a specific pain point and are immediately deliverable.',
        category: 'strategy',
        relatedTerms: ['List Growth Rate', 'Landing Page', 'Opt-in'],
    },
    {
        term: 'Email Cadence',
        aliases: ['send frequency', 'email frequency', 'sending cadence'],
        definition: 'The frequency and timing pattern of your email sends. Optimal cadence varies by audience: B2B typically 1-4/month, B2C 2-8/month. Too frequent causes unsubscribes; too infrequent leads to list decay.',
        category: 'strategy',
        relatedTerms: ['Send Time Optimization', 'Unsubscribe Rate'],
    },
    {
        term: 'Re-engagement Campaign',
        aliases: ['win-back campaign', 'reactivation campaign'],
        definition: 'A targeted campaign to inactive subscribers who haven\'t opened/clicked in 60-90+ days. Typical sequence: 1) "We miss you" 2) Special offer 3) "Last chance" 4) Unsubscribe if no engagement. Keeps list healthy.',
        category: 'strategy',
        relatedTerms: ['List Hygiene', 'Sunset Policy', 'Engagement'],
    },
    {
        term: 'Sunset Policy',
        aliases: ['sunsetting', 'list sunset'],
        definition: 'A systematic process for removing persistently unengaged subscribers after re-engagement attempts fail. Typically remove after 6-12 months of inactivity. Improves deliverability and reduces costs.',
        category: 'strategy',
        relatedTerms: ['Re-engagement Campaign', 'List Hygiene', 'Sender Reputation'],
    },

    // ── Automation ───────────────────────────────────────────────
    {
        term: 'Drip Campaign',
        aliases: ['drip sequence', 'autoresponder series', 'nurture sequence'],
        definition: 'A series of pre-written emails sent automatically on a schedule or triggered by user actions. Common drip types: onboarding (5-7 emails), nurture (ongoing), post-purchase (3-5 emails).',
        category: 'automation',
        relatedTerms: ['Marketing Automation', 'Trigger Email', 'Workflow'],
    },
    {
        term: 'Trigger Email',
        aliases: ['behavioral email', 'event-triggered email'],
        definition: 'An email automatically sent in response to a specific user action: signup, purchase, cart abandonment, browse abandonment, milestone, etc. Trigger emails have 8x more opens and 6x more revenue than batch emails.',
        category: 'automation',
        relatedTerms: ['Drip Campaign', 'Abandoned Cart', 'Welcome Email'],
    },
    {
        term: 'Welcome Email',
        aliases: ['welcome series', 'onboarding email'],
        definition: 'The first email(s) sent after subscription. Average open rate of 63.91% (highest of any email type). Best practices: send within 1 hour, set expectations, deliver lead magnet, introduce brand voice.',
        category: 'automation',
        relatedTerms: ['Trigger Email', 'Drip Campaign', 'Onboarding'],
    },
    {
        term: 'Abandoned Cart Email',
        aliases: ['cart recovery email', 'cart abandonment'],
        definition: 'An automated email sent when a customer adds items to cart but doesn\'t complete purchase. Best timing: 1st email at 1 hour, 2nd at 24 hours, 3rd at 72 hours. Conversion rates 3x higher than other automated emails. $60M+ recovered per quarter by top ecommerce brands.',
        category: 'automation',
        relatedTerms: ['Trigger Email', 'Conversion Rate', 'Ecommerce'],
    },

    // ── List Management ──────────────────────────────────────────
    {
        term: 'List Hygiene',
        aliases: ['list cleaning', 'email hygiene', 'list maintenance'],
        definition: 'The practice of regularly removing invalid, bounced, unsubscribed, and unengaged email addresses. Clean lists have lower bounce rates, fewer spam complaints, and better deliverability. Use email verification services (ZeroBounce, NeverBounce).',
        category: 'list-management',
        relatedTerms: ['Bounce Rate', 'Spam Trap', 'Email Verification'],
    },
    {
        term: 'Email Verification',
        aliases: ['email validation', 'list verification'],
        definition: 'The process of verifying email addresses are valid and deliverable before sending. Checks syntax, domain MX records, and mailbox existence. Reduces bounce rates by 95%+. Essential before importing purchased or old lists.',
        category: 'list-management',
        relatedTerms: ['List Hygiene', 'Bounce Rate', 'Hard Bounce'],
    },
    {
        term: 'Preference Center',
        aliases: ['email preferences', 'subscription management'],
        definition: 'A web page where subscribers manage their email preferences: frequency, content types, channels. Reduces unsubscribes by giving subscribers control. Alternative to a binary unsubscribe.',
        category: 'list-management',
        relatedTerms: ['Unsubscribe Rate', 'Email Cadence'],
    },

    // ── Content ──────────────────────────────────────────────────
    {
        term: 'Call-to-Action',
        aliases: ['CTA', 'email CTA'],
        definition: 'A button or link prompting the recipient to take a specific action (Shop Now, Download, Learn More). Best practices: single primary CTA, high contrast button, action-oriented verb, above the fold. CTAs increase click rates by up to 40%.',
        category: 'content',
        relatedTerms: ['Click-Through Rate', 'Conversion Rate'],
    },
    {
        term: 'Preheader',
        aliases: ['preview text', 'preheader text', 'email preview'],
        definition: 'The text displayed after the subject line in the inbox preview (40-130 characters depending on client). Often the first line of email body if not explicitly set. Should complement, not repeat, the subject line.',
        category: 'content',
        relatedTerms: ['Subject Line', 'Open Rate'],
    },
    {
        term: 'Dynamic Content',
        aliases: ['conditional content', 'smart content'],
        definition: 'Email content that changes based on recipient data—showing different products, images, or copy to different segments within the same email. Reduces the need for multiple email versions.',
        category: 'content',
        relatedTerms: ['Personalization', 'Segmentation', 'Merge Tags'],
    },
    {
        term: 'Plain Text Email',
        aliases: ['text-only email'],
        definition: 'An email without HTML formatting. Often has higher deliverability and feels more personal. Best for: transactional emails, founder messages, B2B outreach. Always include as multipart/alternative with HTML version.',
        category: 'content',
        relatedTerms: ['HTML Email', 'Deliverability'],
    },

    // ── Technical ────────────────────────────────────────────────
    {
        term: 'SMTP',
        aliases: ['Simple Mail Transfer Protocol'],
        definition: 'The standard protocol for sending emails between servers. Default port 25 (relay), 587 (submission with STARTTLS), 465 (implicit TLS). Modern senders use port 587 with STARTTLS or 465 with implicit TLS.',
        category: 'technical',
        relatedTerms: ['MTA', 'TLS', 'MX Record'],
    },
    {
        term: 'MTA',
        aliases: ['Mail Transfer Agent', 'mail server'],
        definition: 'Software that transfers email between servers (e.g., Postfix, Exim, Microsoft Exchange). Responsible for routing, queuing, and delivering messages according to MX records.',
        category: 'technical',
        relatedTerms: ['SMTP', 'MX Record', 'Mail Queue'],
    },
    {
        term: 'MX Record',
        aliases: ['Mail Exchange Record'],
        definition: 'A DNS record that specifies the mail server(s) responsible for receiving email for a domain. Lower priority numbers indicate higher preference. Multiple MX records provide redundancy.',
        category: 'technical',
        relatedTerms: ['DNS', 'SMTP', 'MTA'],
    },
    {
        term: 'Tracking Pixel',
        aliases: ['open pixel', 'web beacon', '1x1 pixel'],
        definition: 'A tiny, invisible image embedded in emails to track opens. When the image loads, a request is sent to the tracking server. Less reliable since Apple MPP (pre-loads images). Some email clients block images by default.',
        category: 'technical',
        relatedTerms: ['Open Rate', 'Apple MPP', 'Privacy'],
    },
    {
        term: 'Transactional Email',
        aliases: ['triggered notification', 'system email'],
        definition: 'One-to-one emails triggered by user actions: password resets, order confirmations, shipping notifications, receipts. Have the highest open rates (~80%). Must not contain marketing content. Typically sent via dedicated transactional providers (Postmark, SendGrid, Mailgun).',
        category: 'technical',
        relatedTerms: ['Trigger Email', 'API', 'SMTP Relay'],
    },

    // ── Analytics ────────────────────────────────────────────────
    {
        term: 'Email Heatmap',
        aliases: ['click map', 'click heatmap'],
        definition: 'A visual representation of where recipients click within an email. Reveals which links, CTAs, and content areas get the most engagement. Tools: Litmus, Mailchimp, Campaign Monitor.',
        category: 'analytics',
        relatedTerms: ['Click-Through Rate', 'CTA'],
    },
    {
        term: 'Cohort Analysis',
        aliases: ['subscriber cohort'],
        definition: 'Analyzing subscriber behavior grouped by when they joined (acquisition cohort) or what action they took. Reveals how engagement changes over subscriber lifetime and helps optimize re-engagement timing.',
        category: 'analytics',
        relatedTerms: ['Engagement', 'Lifecycle'],
    },
    {
        term: 'Email Attribution',
        aliases: ['campaign attribution', 'multi-touch attribution'],
        definition: 'The process of determining which email campaigns and touchpoints contributed to a conversion. Models: first-touch, last-touch, linear, time-decay, data-driven. Critical for accurate ROI measurement.',
        category: 'analytics',
        relatedTerms: ['Conversion Rate', 'ROI', 'Revenue Per Email'],
    },
];

// ═══════════════════════════════════════════════════════════════
// 2. INDUSTRY BENCHMARKS — real-world numbers by industry & type
// ═══════════════════════════════════════════════════════════════

export interface IndustryBenchmark {
    industry: string;
    openRate: number;       // %
    clickRate: number;      // %
    bounceRate: number;     // %
    unsubRate: number;      // %
}

/** Source: Constant Contact Industry Averages 2023 */
export const INDUSTRY_BENCHMARKS: IndustryBenchmark[] = [
    { industry: 'Technology', openRate: 18.34, clickRate: 2.67, bounceRate: 1.02, unsubRate: 0.28 },
    { industry: 'Education', openRate: 37.66, clickRate: 1.57, bounceRate: 0.65, unsubRate: 0.19 },
    { industry: 'Financial Services', openRate: 27.76, clickRate: 1.01, bounceRate: 0.55, unsubRate: 0.20 },
    { industry: 'Healthcare', openRate: 34.87, clickRate: 0.91, bounceRate: 0.72, unsubRate: 0.25 },
    { industry: 'Retail', openRate: 31.83, clickRate: 0.93, bounceRate: 0.40, unsubRate: 0.15 },
    { industry: 'Real Estate', openRate: 32.79, clickRate: 0.84, bounceRate: 0.63, unsubRate: 0.18 },
    { industry: 'Travel & Tourism', openRate: 39.15, clickRate: 0.96, bounceRate: 0.48, unsubRate: 0.22 },
    { industry: 'Nonprofit', openRate: 39.13, clickRate: 1.62, bounceRate: 0.53, unsubRate: 0.17 },
    { industry: 'Legal', openRate: 32.84, clickRate: 1.28, bounceRate: 0.78, unsubRate: 0.23 },
    { industry: 'Manufacturing', openRate: 26.54, clickRate: 1.24, bounceRate: 0.85, unsubRate: 0.31 },
    { industry: 'Consulting', openRate: 27.48, clickRate: 1.18, bounceRate: 0.62, unsubRate: 0.25 },
    { industry: 'Food & Dining', openRate: 36.50, clickRate: 0.66, bounceRate: 0.45, unsubRate: 0.14 },
    { industry: 'Entertainment', openRate: 39.13, clickRate: 1.09, bounceRate: 0.58, unsubRate: 0.20 },
    { industry: 'SaaS', openRate: 22.15, clickRate: 2.45, bounceRate: 0.68, unsubRate: 0.32 },
    { industry: 'Ecommerce', openRate: 29.81, clickRate: 1.74, bounceRate: 0.42, unsubRate: 0.19 },
];

export interface EmailTypeBenchmark {
    type: string;
    openRate: number;
    clickRate: number;
    conversionRate: number;
}

/** Source: GetResponse, Omnisend, Klaviyo 2023 */
export const EMAIL_TYPE_BENCHMARKS: EmailTypeBenchmark[] = [
    { type: 'Welcome', openRate: 63.91, clickRate: 14.34, conversionRate: 2.74 },
    { type: 'Newsletter', openRate: 27.90, clickRate: 3.40, conversionRate: 0.80 },
    { type: 'Promotional', openRate: 21.33, clickRate: 2.62, conversionRate: 1.22 },
    { type: 'Transactional', openRate: 80.00, clickRate: 15.00, conversionRate: 8.00 },
    { type: 'Abandoned Cart', openRate: 45.00, clickRate: 8.65, conversionRate: 3.33 },
    { type: 'Browse Abandonment', openRate: 37.00, clickRate: 5.20, conversionRate: 1.50 },
    { type: 'Win-back', openRate: 35.00, clickRate: 4.50, conversionRate: 1.10 },
    { type: 'Post-Purchase', openRate: 52.00, clickRate: 10.50, conversionRate: 3.80 },
    { type: 'Birthday/Anniversary', openRate: 47.00, clickRate: 8.10, conversionRate: 2.90 },
    { type: 'Autoresponder', openRate: 35.91, clickRate: 4.80, conversionRate: 1.40 },
    { type: 'RSS / Digest', openRate: 44.54, clickRate: 3.20, conversionRate: 0.60 },
    { type: 'Cold Outreach', openRate: 44.00, clickRate: 3.50, conversionRate: 0.85 },
    { type: 'Product Update', openRate: 45.00, clickRate: 6.30, conversionRate: 1.80 },
    { type: 'Survey / Feedback', openRate: 30.00, clickRate: 5.10, conversionRate: 4.20 },
];

// ═══════════════════════════════════════════════════════════════
// 3. SUBJECT LINE BEST PRACTICES — empirically validated rules
// ═══════════════════════════════════════════════════════════════

export interface SubjectLineBestPractice {
    rule: string;
    impact: string;
    evidence: string;
    priority: 'critical' | 'high' | 'medium' | 'low';
}

export const SUBJECT_LINE_BEST_PRACTICES: SubjectLineBestPractice[] = [
    {
        rule: 'Keep main message within first 33 characters',
        impact: '+12% visibility across all devices and clients',
        evidence: 'Gmail app on Pixel 7 shows only 33 chars; iPhone 14 shows 48; Outlook ~51',
        priority: 'critical',
    },
    {
        rule: 'Total length should not exceed 50 characters',
        impact: 'Full visibility on 95%+ of email clients',
        evidence: 'EmailToolTester cross-client analysis 2023',
        priority: 'critical',
    },
    {
        rule: 'Personalize with recipient name',
        impact: '+6% open rate (20.66% vs 19.57%)',
        evidence: 'GetResponse 2023 benchmark report',
        priority: 'high',
    },
    {
        rule: 'Use emojis sparingly (1 max)',
        impact: '+3.2% open rate but -2.3% CTOR',
        evidence: 'GetResponse data: 20.37% OR with emoji vs 19.73% without',
        priority: 'medium',
    },
    {
        rule: 'Include numbers or statistics',
        impact: '+12% open rate multiplier',
        evidence: 'Subject lines with numbers create specificity and curiosity',
        priority: 'high',
    },
    {
        rule: 'Ask a question',
        impact: '+15% open rate multiplier',
        evidence: 'Questions create curiosity gaps that drive opens',
        priority: 'high',
    },
    {
        rule: 'Avoid ALL CAPS words',
        impact: '-15% deliverability; triggers spam filters',
        evidence: 'SpamAssassin rules penalize excessive capitalization',
        priority: 'critical',
    },
    {
        rule: 'Avoid spam trigger words (free, winner, act now)',
        impact: 'Reduces spam score by 0.2-0.5 points',
        evidence: 'SpamAssassin, Google Postmaster Tools',
        priority: 'critical',
    },
    {
        rule: 'Use urgency appropriately',
        impact: '+22% open rate when genuine; -30% when overused',
        evidence: 'Genuine scarcity drives FOMO; fake urgency erodes trust',
        priority: 'medium',
    },
    {
        rule: 'A/B test subject lines with minimum 1000 recipients per variant',
        impact: 'Statistical significance requires adequate sample size',
        evidence: 'Minimum detectable effect of ±2% requires ~1000 samples per arm',
        priority: 'high',
    },
];

// ═══════════════════════════════════════════════════════════════
// 4. DELIVERABILITY CHECKLIST — actionable rules
// ═══════════════════════════════════════════════════════════════

export interface DeliverabilityRule {
    rule: string;
    severity: 'must-have' | 'should-have' | 'nice-to-have';
    category: 'authentication' | 'content' | 'infrastructure' | 'list' | 'monitoring';
    details: string;
}

export const DELIVERABILITY_RULES: DeliverabilityRule[] = [
    { rule: 'Set up SPF record', severity: 'must-have', category: 'authentication', details: 'Include your ESP\'s sending IPs in your domain\'s SPF record. Keep under 10 DNS lookups.' },
    { rule: 'Sign with DKIM (2048-bit key)', severity: 'must-have', category: 'authentication', details: 'Use 2048-bit RSA keys. Rotate keys every 6-12 months. Align with From domain.' },
    { rule: 'Publish DMARC policy', severity: 'must-have', category: 'authentication', details: 'Start with p=none, monitor reports, move to p=quarantine then p=reject. Required by Google/Yahoo since Feb 2024.' },
    { rule: 'Keep complaint rate below 0.1%', severity: 'must-have', category: 'monitoring', details: 'Google requires <0.1% spam complaints via Postmaster Tools. Set up FBL processing.' },
    { rule: 'Keep bounce rate below 2%', severity: 'must-have', category: 'list', details: 'Validate email addresses before importing. Remove hard bounces immediately.' },
    { rule: 'Include List-Unsubscribe header', severity: 'must-have', category: 'content', details: 'RFC 8058 one-click unsubscribe. Required for bulk senders (>5000/day) by Google/Yahoo since Feb 2024.' },
    { rule: 'Warm up new IPs gradually', severity: 'must-have', category: 'infrastructure', details: 'Start with 50-100 emails/day to engaged users. Double volume every 2-3 days. Takes 4-8 weeks.' },
    { rule: 'Maintain text-to-image ratio > 60:40', severity: 'should-have', category: 'content', details: 'Emails with mostly images and little text are flagged by spam filters.' },
    { rule: 'Avoid URL shorteners (bit.ly, tinyurl)', severity: 'should-have', category: 'content', details: 'URL shorteners are heavily associated with spam and phishing. Use your own domain.' },
    { rule: 'Monitor Google Postmaster Tools', severity: 'must-have', category: 'monitoring', details: 'Track domain/IP reputation, spam rate, authentication results, and delivery errors.' },
    { rule: 'Use dedicated sending subdomain', severity: 'should-have', category: 'infrastructure', details: 'e.g., mail.yourdomain.com — isolates marketing reputation from corporate domain.' },
    { rule: 'Set up BIMI record', severity: 'nice-to-have', category: 'authentication', details: 'Display brand logo in inbox. Requires DMARC at p=quarantine or p=reject + VMC.' },
    { rule: 'Use TLS 1.2+ for SMTP', severity: 'must-have', category: 'infrastructure', details: 'Ensures email content is encrypted in transit. Required by HIPAA, PCI-DSS.' },
    { rule: 'Remove unengaged subscribers after 6-12 months', severity: 'should-have', category: 'list', details: 'Implement sunset policy after re-engagement campaign fails. Improves all deliverability metrics.' },
];

// ═══════════════════════════════════════════════════════════════
// 5. CHATBOT CONVERSATION PATTERNS — intent→response templates
// ═══════════════════════════════════════════════════════════════

export interface ConversationPattern {
    intent: string;
    keywords: string[];
    sampleQuestions: string[];
    contextualResponse: string;
    suggestedFollowUps: string[];
    relatedGlossaryTerms: string[];
}

export const CONVERSATION_PATTERNS: ConversationPattern[] = [
    {
        intent: 'improve_open_rate',
        keywords: ['open rate', 'opens', 'nobody opens', 'low opens', 'increase opens', 'improve open rate'],
        sampleQuestions: [
            'How do I improve my email open rate?',
            'My open rates are low, what should I do?',
            'What is a good open rate?',
            'Why are my emails not being opened?',
        ],
        contextualResponse: `Here's a data-driven approach to improving your open rates:

**Benchmark:** The average email open rate is ~27% (varies by industry from 18% for tech to 44% for nonprofits).

**Quick Wins:**
1. **Subject lines:** Keep your main message within 33 characters. Personalized subject lines see +6% higher open rates.
2. **Send time:** 21% of emails are opened within the first hour. Test different send times for your audience.
3. **Preheader text:** Complement your subject line—don't repeat it.
4. **Sender name:** Use a recognizable name (person + brand works best).

**Deeper Fixes:**
5. **Segment your list:** Segmented campaigns get 14% higher open rates.
6. **Clean your list:** Remove unengaged subscribers (no opens in 90 days). They drag down your metrics and hurt deliverability.
7. **Check authentication:** Ensure SPF, DKIM, and DMARC are properly configured.
8. **Note about Apple MPP:** Since iOS 15, ~60% of opens come from Apple devices that pre-load tracking pixels. Focus on click rate as a more reliable engagement metric.`,
        suggestedFollowUps: [
            'Write better subject lines for my campaign',
            'How do I segment my audience?',
            'Check my email authentication setup',
            'What is Apple MPP and how does it affect my metrics?',
        ],
        relatedGlossaryTerms: ['Open Rate', 'Subject Line', 'Apple MPP', 'Segmentation', 'Preheader'],
    },
    {
        intent: 'improve_deliverability',
        keywords: ['deliverability', 'spam', 'spam folder', 'not delivered', 'inbox placement', 'blacklist', 'blocked', 'reputation'],
        sampleQuestions: [
            'My emails are going to spam, how do I fix this?',
            'How do I improve email deliverability?',
            'What is a good sender reputation?',
            'I think I am on a blacklist',
        ],
        contextualResponse: `Email deliverability averages 81% across the industry. Here's how to maximize yours:

**Authentication (Critical):**
1. **SPF:** Publish a DNS TXT record authorizing your sending IPs
2. **DKIM:** Sign emails with a 2048-bit key aligned to your From domain
3. **DMARC:** Set up at minimum p=none, then progress to p=quarantine → p=reject
4. **List-Unsubscribe:** Required by Google/Yahoo since Feb 2024 for bulk senders

**Content:**
5. Maintain text-to-image ratio > 60:40
6. Avoid spam trigger words (free, winner, act now, click here)
7. Don't use URL shorteners (bit.ly, tinyurl)
8. Always include a plain-text version

**List Health:**
9. Keep bounce rate < 2% and complaint rate < 0.1%
10. Remove hard bounces immediately
11. Verify email addresses before importing
12. Implement a sunset policy for unengaged subscribers

**Monitoring:**
13. Set up Google Postmaster Tools
14. Process Feedback Loop (FBL) reports
15. Monitor seed-list inbox placement tests`,
        suggestedFollowUps: [
            'Help me set up SPF/DKIM/DMARC',
            'How do I check my sender reputation?',
            'Create a re-engagement campaign for inactive subscribers',
            'What spam trigger words should I avoid?',
        ],
        relatedGlossaryTerms: ['Sender Reputation', 'SPF', 'DKIM', 'DMARC', 'Spam Trap', 'Inbox Placement Rate'],
    },
    {
        intent: 'create_campaign',
        keywords: ['create campaign', 'new campaign', 'start campaign', 'launch campaign', 'set up campaign', 'build campaign'],
        sampleQuestions: [
            'How do I create an email campaign?',
            'Help me set up a new campaign',
            'What should I include in my campaign?',
            'Walk me through creating a campaign',
        ],
        contextualResponse: `I'll help you create a high-converting email campaign. Here's the process:

**1. Define Your Goal**
- What action do you want recipients to take? (Purchase, signup, read, download)
- Set a measurable target (e.g., 3% click rate, 100 signups)

**2. Choose Your Audience**
- Select a segment or create a new one based on engagement, demographics, or behavior
- Segmented campaigns see 101% more clicks than broadcast sends

**3. Craft Your Content**
- **Subject line:** Under 50 chars, personalized, creates curiosity
- **Preheader:** 40-100 chars, complements the subject
- **Body:** Under 200 words for best engagement, scannable with headers
- **CTA:** One primary CTA, high contrast button, action verb

**4. Design for Mobile**
- 43.5% of emails are opened on mobile
- Single-column layout, 14px+ font, large tap targets (44×44px min)

**5. Test Before Sending**
- Preview on multiple email clients
- A/B test subject line with a small segment first
- Check spam score

**6. Schedule Strategically**
- 21% of opens happen in the first hour—time it right for your audience`,
        suggestedFollowUps: [
            'Write subject lines for my campaign',
            'Help me segment my audience',
            'Generate email copy for this campaign',
            'What is the best time to send my campaign?',
        ],
        relatedGlossaryTerms: ['A/B Testing', 'Segmentation', 'Call-to-Action', 'Preheader'],
    },
    {
        intent: 'write_subject_line',
        keywords: ['subject line', 'email subject', 'write subject', 'subject ideas', 'subject suggestions'],
        sampleQuestions: [
            'Write me some subject lines',
            'I need subject line ideas',
            'How do I write a good subject line?',
            'Suggest subject lines for my campaign',
        ],
        contextualResponse: `Great subject lines drive open rates. Here are research-backed principles:

**The Rules:**
- Put your main message in the first 33 characters (Pixel 7 Gmail limit)
- Total length under 50 characters for full visibility
- Personalize with {{firstName}} (+6% open rate)
- Use 1 emoji max (+3% open rate, but can hurt CTOR)
- Include specific numbers when possible (+12% open rate)
- Ask a question for curiosity (+15% open rate)

**Formulas That Work:**
1. **Curiosity Gap:** "The #1 mistake {{industry}} marketers make"
2. **Benefit-Driven:** "Get {{benefit}} in {{timeframe}}"
3. **Question:** "{{firstName}}, ready for {{benefit}}?"
4. **Social Proof:** "Why {{number}}+ {{audience}} switched to {{product}}"
5. **How-To:** "How to {{benefit}} (without {{pain_point}})"
6. **Urgency (genuine):** "{{offer}} ends {{timeframe}}"
7. **Listicle:** "{{number}} ways to {{benefit}}"

**Avoid:** ALL CAPS, excessive punctuation (!!!), spam words (FREE, ACT NOW), clickbait that doesn't match content.

Want me to generate specific subject lines for your campaign? Tell me your topic, audience, and goal.`,
        suggestedFollowUps: [
            'Generate 5 subject lines for my campaign about {{topic}}',
            'A/B test my subject lines',
            'Check my subject line for spam triggers',
            'What are the best emoji to use in subject lines?',
        ],
        relatedGlossaryTerms: ['Open Rate', 'A/B Testing', 'Personalization'],
    },
    {
        intent: 'reduce_unsubscribes',
        keywords: ['unsubscribe', 'people leaving', 'losing subscribers', 'high unsubscribe', 'opt out', 'list shrinking'],
        sampleQuestions: [
            'Why are people unsubscribing?',
            'How do I reduce my unsubscribe rate?',
            'My list is shrinking, what do I do?',
        ],
        contextualResponse: `The average unsubscribe rate is 0.1-0.5%. Here's how to keep it low:

**Diagnose the Cause:**
1. **Too frequent:** Are you emailing more than your audience expects? B2B: 1-4/month, B2C: 2-8/month
2. **Irrelevant content:** Are you segmenting properly? Generic blasts get more unsubs
3. **Broken promise:** Does your content match what subscribers signed up for?
4. **Poor timing:** Wrong send time for your audience?

**Solutions:**
1. **Preference center:** Let subscribers choose frequency and topics instead of binary unsubscribe
2. **Segment and personalize:** Relevant content = fewer unsubs. Segmented campaigns see 14% higher open rates
3. **Set expectations at signup:** Tell them what they'll receive and how often
4. **Re-permission campaign:** Ask long-term subscribers to re-confirm interest
5. **Survey departing subscribers:** Add a one-question survey to your unsubscribe page
6. **Quality over quantity:** Send fewer, better emails rather than more mediocre ones

**Important:** Don't hide the unsubscribe link! It's legally required (CAN-SPAM, GDPR) and hidden links increase spam complaints—which is far worse for deliverability.`,
        suggestedFollowUps: [
            'Set up a preference center',
            'Help me segment my audience',
            'Create a re-engagement campaign',
            'What is a good email frequency for my industry?',
        ],
        relatedGlossaryTerms: ['Unsubscribe Rate', 'Email Cadence', 'Preference Center', 'CAN-SPAM', 'GDPR'],
    },
    {
        intent: 'understand_metrics',
        keywords: ['metrics', 'analytics', 'KPI', 'reporting', 'dashboard', 'performance', 'stats', 'how am I doing'],
        sampleQuestions: [
            'What metrics should I track?',
            'How do I read my email analytics?',
            'What KPIs matter for email marketing?',
            'Is my click rate good?',
        ],
        contextualResponse: `Here are the essential email marketing metrics and what they mean:

**Primary Metrics:**
| Metric | Formula | Good | Caution | Action Needed |
|--------|---------|------|---------|---------------|
| Open Rate | Opens / Delivered | >25% | 15-25% | <15% |
| CTR | Clicks / Delivered | >2.5% | 1-2.5% | <1% |
| CTOR | Clicks / Opens | >12% | 8-12% | <8% |
| Bounce Rate | Bounces / Sent | <2% | 2-5% | >5% |
| Unsub Rate | Unsubs / Delivered | <0.5% | 0.5-1% | >1% |
| Complaint Rate | Complaints / Delivered | <0.1% | 0.1-0.3% | >0.3% |

**Revenue Metrics (Ecommerce):**
- **Revenue Per Email (RPE):** Total revenue / emails delivered
- **Conversion Rate:** Conversions / clicks
- **ROI:** (Revenue − Cost) / Cost × 100 — Email marketing average is 3,600%

**What to Watch For:**
- Open rate declining → Subject line or deliverability issue
- Opens high but clicks low → Content or CTA issue
- Clicks high but conversions low → Landing page issue
- Bounces increasing → List hygiene problem
- Complaints rising → Content relevance or frequency issue

**Important:** With Apple MPP inflating open rates, focus on click-based metrics (CTR, CTOR) for more reliable engagement measurement.`,
        suggestedFollowUps: [
            'Analyze my campaign performance',
            'How do I improve my click rate?',
            'What is Apple MPP?',
            'Export my campaign report',
        ],
        relatedGlossaryTerms: ['Open Rate', 'Click-Through Rate', 'Click-to-Open Rate', 'Bounce Rate', 'Complaint Rate'],
    },
    {
        intent: 'automation_help',
        keywords: ['automation', 'workflow', 'drip', 'automate', 'triggered', 'sequence', 'series', 'flow'],
        sampleQuestions: [
            'How do I set up email automation?',
            'What automations should I have?',
            'Help me build a welcome series',
            'Create a drip campaign',
        ],
        contextualResponse: `Email automation generates 320% more revenue than non-automated emails. Here are the essential automations:

**Must-Have Automations:**

1. **Welcome Series** (Open rate: 63.91%)
   - Email 1 (immediate): Welcome + deliver lead magnet
   - Email 2 (Day 2): Brand story + key benefits
   - Email 3 (Day 4): Social proof + customer stories
   - Email 4 (Day 7): First offer or product recommendation
   - Email 5 (Day 14): Engagement check + preference center

2. **Abandoned Cart** (3x higher conversion than batch emails)
   - Email 1 (1 hour): Reminder with cart items
   - Email 2 (24 hours): Social proof + urgency
   - Email 3 (72 hours): Final reminder + incentive

3. **Post-Purchase** (Open rate: 52%)
   - Email 1 (immediate): Order confirmation
   - Email 2 (delivery day): Usage tips
   - Email 3 (Day 7): Review request
   - Email 4 (Day 30): Cross-sell / replenishment

4. **Re-engagement** (Win-back)
   - Trigger: 60-90 days of inactivity
   - Email 1: "We miss you" + reminder of value
   - Email 2: Special offer
   - Email 3: "Last chance" + unsubscribe option
   - No response → Sunset (remove from list)

5. **Birthday/Anniversary** (Open rate: 47%)
   - Personalized message + exclusive offer
   - Send on or 1 day before the date`,
        suggestedFollowUps: [
            'Set up a welcome series',
            'Create an abandoned cart flow',
            'Build a re-engagement campaign',
            'What triggers should I use?',
        ],
        relatedGlossaryTerms: ['Drip Campaign', 'Trigger Email', 'Welcome Email', 'Abandoned Cart Email'],
    },
    {
        intent: 'compliance_help',
        keywords: ['GDPR', 'CAN-SPAM', 'compliance', 'legal', 'privacy', 'consent', 'unsubscribe law', 'regulation'],
        sampleQuestions: [
            'How do I make my emails GDPR compliant?',
            'What are the CAN-SPAM requirements?',
            'Do I need double opt-in?',
            'What legal requirements do I need to follow?',
        ],
        contextualResponse: `Email compliance is non-negotiable. Here are the key regulations:

**CAN-SPAM (US) — Applies to all commercial emails:**
✅ Include your physical mailing address
✅ Include a clear unsubscribe mechanism
✅ Honor unsubscribe requests within 10 business days
✅ Use accurate From name and subject line
✅ Identify the message as an ad if applicable
⚠️ Fines: Up to $51,744 per violating email

**GDPR (EU/EEA) — Applies when emailing EU residents:**
✅ Obtain explicit, freely given consent before sending marketing emails
✅ Document when and how consent was obtained
✅ Provide right to be forgotten (delete all data on request)
✅ Provide data portability (export subscriber data)
✅ Report data breaches within 72 hours
✅ Double opt-in recommended (required in Germany)
⚠️ Fines: Up to €20 million or 4% of global annual revenue

**Google/Yahoo Requirements (Feb 2024) — For bulk senders (>5000/day):**
✅ SPF and DKIM authentication
✅ DMARC policy published
✅ One-click List-Unsubscribe header (RFC 8058)
✅ Spam rate below 0.1% (Google Postmaster Tools)
✅ Valid forward and reverse DNS records

**Best Practice:** Always use double opt-in, maintain clear records of consent, and make unsubscribing easy and instant.`,
        suggestedFollowUps: [
            'Set up double opt-in for my forms',
            'Add List-Unsubscribe header to my emails',
            'Check my DMARC policy',
            'How do I handle a GDPR data deletion request?',
        ],
        relatedGlossaryTerms: ['CAN-SPAM', 'GDPR', 'CCPA', 'Double Opt-in', 'List-Unsubscribe Header'],
    },
    {
        intent: 'email_roi',
        keywords: ['roi', 'return on investment', 'cost effective', 'email vs social', 'email value', 'email marketing roi', 'worth it', 'email compare'],
        sampleQuestions: [
            'What is the ROI of email marketing?',
            'How does email compare to social media marketing?',
            'Is email marketing worth it?',
            'How much revenue does email marketing generate?',
        ],
        contextualResponse: `Email marketing delivers the **highest ROI** of any digital marketing channel:

**Key ROI Data:**
- **$36 return for every $1 spent** (3,600% ROI) — DMA/Litmus 2023
- For e-commerce, ROI can reach **$45 per $1**
- B2B email ROI averages **$42 per $1**

**Email vs Other Channels:**
| Channel | Avg ROI | Cost per Acquisition |
|---------|---------|---------------------|
| Email | 3,600% | $10 |
| SEO | 2,200% | $31 |
| Social Media | 250% | $57 |
| Paid Ads | 200% | $80 |

**Why Email Wins:**
1. **Owned audience** — You control the channel, no algorithm changes
2. **Personalization at scale** — Segment and tailor to individuals
3. **Automation** — Set up once, earn forever (welcome series, cart abandonment)
4. **Measurability** — Track opens, clicks, conversions, revenue per email
5. **Low cost** — No per-impression fees like paid advertising

**Maximize Your Email ROI:**
- Segment your list (segmented campaigns drive 760% more revenue)
- Implement automation (automated emails generate 320% more revenue)
- A/B test subject lines and CTAs
- Clean your list regularly to improve deliverability`,
        suggestedFollowUps: [
            'How do I set up email automation?',
            'Help me segment my audience',
            'What metrics should I track?',
            'Create an A/B test for my next campaign',
        ],
        relatedGlossaryTerms: ['Revenue Per Email', 'Conversion Rate', 'A/B Testing', 'Segmentation'],
    },

    // ═══════════════════════════════════════════════════════════════
    // SUPPORT / TROUBLESHOOTING PATTERNS — backing playbook KNOWLEDGE intents
    // ═══════════════════════════════════════════════════════════════

    // ── AUTH: SPF/DKIM/DMARC debugging ──
    {
        intent: 'debug_email_authentication',
        keywords: ['spf', 'dkim', 'dmarc', 'authentication', 'spf fail', 'dkim fail', 'dmarc fail', 'permerror', 'softfail', 'alignment', 'spf record', 'dkim selector', 'dmarc policy', 'dns txt record', 'authentication results header'],
        sampleQuestions: [
            'My emails are failing SPF checks',
            'DKIM signature is invalid',
            'How do I fix DMARC alignment?',
            'SPF permerror — too many DNS lookups',
            'What does a DMARC failure report mean?',
        ],
        contextualResponse: `Here's a systematic approach to debugging email authentication issues:

**SPF (Sender Policy Framework):**
- SPF authorizes which IPs can send on behalf of your domain via a DNS TXT record
- **Common failures:**
  - \`permerror\` — Too many DNS lookups (max 10). Flatten your record by replacing \`include:\` with \`ip4:\`/\`ip6:\` ranges
  - \`softfail (~all)\` — Update to \`-all\` (hard fail) after confirming all legitimate senders are listed
  - \`temperror\` — DNS timeout. Check DNS provider reliability
  - Multiple SPF records — You can have only ONE SPF TXT record per domain. Merge them
- **Fix:** \`v=spf1 include:_spf.apexmail.com include:_spf.google.com ~all\`

**DKIM (DomainKeys Identified Mail):**
- Signs emails with a cryptographic key; receiving servers verify via DNS public key
- **Common failures:**
  - \`body hash did not verify\` — Message was modified in transit (mailing list, forwarding, AV scanner)
  - \`no key for signature\` — DKIM DNS record not published or selector mismatch
  - \`key too small\` — Use 2048-bit keys minimum (some older systems use 1024-bit)
  - Selector rotation: Publish the new selector 24-48h before switching to allow DNS propagation
- **Fix:** Run \`dig TXT selector._domainkey.yourdomain.com\` to verify the public key is published

**DMARC (Domain-based Message Authentication, Reporting & Conformance):**
- DMARC requires SPF OR DKIM to pass AND align with the From domain
- **Alignment modes:**
  - \`aspf=r\` / \`adkim=r\` = relaxed (subdomain OK) — recommended for most senders
  - \`aspf=s\` / \`adkim=s\` = strict (exact domain match only)
- **Policy ramp-up:** Start with \`p=none\` → monitor reports → \`p=quarantine pct=10\` → increase pct → \`p=reject\`
- **Forwarding breaks DMARC:** When recipients forward your email, SPF fails for the new server. Solution: Ensure DKIM passes (it survives forwarding) and use relaxed alignment
- **Aggregate reports (rua):** Set \`rua=mailto:dmarc-reports@yourdomain.com\` to receive XML reports showing pass/fail breakdown

**Debugging checklist:**
1. Check Authentication-Results header in a received email
2. Verify DNS records with \`dig TXT\` or MXToolbox
3. Run ApexMail's \`force_dns_recheck\` to clear cached state
4. Check DMARC aggregate reports for unauthorized senders`,
        suggestedFollowUps: [
            'Force a DNS recheck on my domain',
            'Help me flatten my SPF record',
            'Set up DMARC reporting',
            'Rotate my DKIM selector',
        ],
        relatedGlossaryTerms: ['SPF', 'DKIM', 'DMARC', 'Sender Reputation'],
    },
    {
        intent: 'advanced_dns_auth',
        keywords: ['bimi', 'mta-sts', 'tls-rpt', 'tlsa', 'dane', 'rdns', 'ptr', 'reverse dns', 'vmc', 'brand logo', 'tls reporting'],
        sampleQuestions: [
            'How do I set up BIMI for my brand logo?',
            'What is MTA-STS and do I need it?',
            'My reverse DNS / PTR record is wrong',
            'How do I set up DANE/TLSA?',
            'What is TLS-RPT?',
        ],
        contextualResponse: `Advanced DNS authentication enhances security and brand visibility:

**BIMI (Brand Indicators for Message Identification):**
- Displays your brand logo next to emails in supported inboxes (Gmail, Yahoo, Apple Mail)
- **Requirements:**
  1. DMARC at \`p=quarantine\` or \`p=reject\` (not \`p=none\`)
  2. SVG Tiny PS logo (square, specific format)
  3. VMC (Verified Mark Certificate) — required by Gmail, costs ~$1,500/year from DigiCert or Entrust
  4. DNS record: \`default._bimi.yourdomain.com TXT "v=BIMI1; l=https://yourdomain.com/logo.svg; a=https://yourdomain.com/vmc.pem"\`
- Use \`check_bimi_status\` to verify your setup

**MTA-STS (Mail Transfer Agent Strict Transport Security):**
- Enforces TLS encryption for mail delivery to your domain (prevents downgrade attacks)
- **Setup:**
  1. Publish policy file at \`https://mta-sts.yourdomain.com/.well-known/mta-sts.txt\`
  2. Add DNS record: \`_mta-sts.yourdomain.com TXT "v=STSv1; id=20240101"\`
  3. Policy modes: \`testing\` (report only) → \`enforce\` (reject unencrypted)
  4. Set \`max_age\` to 604800 (1 week) initially, increase once stable

**TLS-RPT (TLS Reporting):**
- Receive reports about TLS delivery failures to your domain
- DNS record: \`_smtp._tls.yourdomain.com TXT "v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com"\`

**DANE/TLSA:**
- Pins the TLS certificate in DNS using DNSSEC, preventing MITM attacks
- Requires DNSSEC-signed domain (most registrars support this now)
- Record: \`_25._tcp.mail.yourdomain.com TLSA 3 1 1 <certificate-hash>\`

**Reverse DNS (PTR / rDNS):**
- The PTR record for your sending IP must resolve to a hostname that resolves back to that IP (forward-confirmed rDNS)
- **Why it matters:** Gmail, Microsoft, and other providers check rDNS. Missing or mismatched PTR = spam folder
- Contact your IP provider (hosting/ISP) to set rDNS — it can't be set in your domain's DNS`,
        suggestedFollowUps: [
            'Check my BIMI configuration',
            'Verify my reverse DNS record',
            'Set up MTA-STS for my domain',
            'Check my current DMARC policy level',
        ],
        relatedGlossaryTerms: ['DMARC', 'SPF', 'DKIM', 'Sender Reputation'],
    },

    // ── SEND: SMTP troubleshooting ──
    {
        intent: 'smtp_troubleshooting',
        keywords: ['smtp', 'connection', 'timeout', 'ehlo', 'helo', 'tls', 'starttls', '25', '465', '587', '2525', 'connection refused', 'connection reset', 'rcpt to', 'mail from', 'smtp error', 'smtp code', 'pipeline', 'pipelining'],
        sampleQuestions: [
            'SMTP connection timeout on port 587',
            'Connection refused when sending email',
            'What SMTP port should I use?',
            'EHLO/HELO rejected by server',
            'TLS handshake failed during SMTP',
        ],
        contextualResponse: `Systematic SMTP troubleshooting guide:

**Port Selection:**
| Port | Protocol | Use Case |
|------|----------|----------|
| 587  | STARTTLS | Standard submission port (recommended) |
| 465  | Implicit TLS | Legacy but re-standardized in RFC 8314 |
| 25   | Plain/STARTTLS | Server-to-server relay only (often blocked by ISPs) |
| 2525 | STARTTLS | Alternative when 587 is blocked |

**Common SMTP Errors & Fixes:**

- **Connection timeout** → Firewall blocking outbound port. Check with \`telnet smtp.apexmail.com 587\`. Corporate firewalls often block 587; try 2525
- **Connection refused** → Wrong port, server down, or IP blocked. Verify hostname and port
- **421 Too many connections** → Reduce concurrent SMTP connections (max 10 recommended)
- **450 Requested action not taken** → Temporary failure, retry with exponential backoff
- **550 5.1.1 User unknown** → Invalid recipient address (hard bounce, remove from list)
- **550 5.7.1 Relaying denied** → Authentication required. Send AUTH LOGIN before MAIL FROM
- **552 Message size exceeds limit** → Reduce attachment size or use links instead
- **554 Transaction failed** → Content trigger (spam filter), blocked IP, or policy violation

**TLS Issues:**
- \`SSL routines:ssl3_get_server_certificate:certificate verify failed\` → Update CA certificates on your system
- \`tlsv1 alert protocol version\` → Server requires TLS 1.2+. Update your client library
- STARTTLS on port 465 won't work (465 uses implicit TLS — connect with SSL directly)

**SMTP Pipelining:**
- Sends multiple commands without waiting for individual responses
- Can cause issues with some legacy servers — disable if seeing unexpected 5xx errors after RCPT TO

**Debugging steps:**
1. Run \`get_smtp_transcript\` to see the raw SMTP conversation
2. Check \`trace_message\` for the full delivery pipeline
3. Verify DNS with \`force_dns_recheck\`
4. Test connectivity: \`openssl s_client -connect smtp.apexmail.com:587 -starttls smtp\``,
        suggestedFollowUps: [
            'Show me the SMTP transcript for a failed message',
            'Trace a message through the pipeline',
            'Check if my IP is blocked',
            'What are the SMTP rate limits?',
        ],
        relatedGlossaryTerms: ['Bounce Rate', 'Hard Bounce', 'Soft Bounce', 'Sender Reputation'],
    },

    // ── DLV: Bounce classification & handling ──
    {
        intent: 'bounce_classification',
        keywords: ['bounce', 'hard bounce', 'soft bounce', 'bounce code', 'bounce reason', 'ndr', 'dsn', '550', '421', '452', 'deferred', 'rejected', 'undeliverable', 'mailbox full', 'user unknown', 'over quota'],
        sampleQuestions: [
            'What does bounce code 550 5.1.1 mean?',
            'Difference between hard and soft bounce',
            'Why is Gmail deferring my emails?',
            'Microsoft is blocking all my emails',
            'How do I handle bounce backs?',
        ],
        contextualResponse: `Email bounce classification and handling guide:

**Bounce Categories:**

| Type | Codes | Meaning | Action |
|------|-------|---------|--------|
| **Hard** | 5.1.x | Invalid address, domain doesn't exist | Remove immediately — never retry |
| **Soft (temp)** | 4.2.x | Mailbox full, temporarily unavailable | Retry with backoff, suppress after 3 failures |
| **Block** | 5.7.x | Policy rejection (spam, reputation) | Investigate sender reputation |
| **Content** | 5.6.x | Content rejected (attachment, encoding) | Fix content and resend |
| **System** | 4.4.x | Network/routing failure | Retry automatically |

**Common Bounce Codes Explained:**
- \`550 5.1.1\` — Recipient address doesn't exist (HARD — remove now)
- \`550 5.1.2\` — Domain doesn't exist (HARD — remove now)
- \`550 5.7.1\` — Rejected by policy (blocklist, reputation, content)
- \`550 5.7.25\` — DMARC/authentication failure
- \`421 4.7.0\` — Connection rate limited by recipient server (slow down)
- \`452 4.2.2\` — Mailbox full (SOFT — retry later)
- \`550 5.2.1\` — Account disabled/suspended (HARD — remove)

**Provider-Specific Behavior:**

*Gmail:*
- Uses \`421-4.7.28\` for reputation-based deferrals
- Enforces <0.1% complaint rate (Postmaster Tools)
- Defers heavily if you ramp volume too fast

*Microsoft (Outlook/Hotmail):*
- Uses \`550 5.7.606\` for Sender Reputation filtering
- Requires enrolling in SNDS (Smart Network Data Services)
- Throttles new senders aggressively — warm up slowly

*Yahoo:*
- Blocks senders without List-Unsubscribe header (since Feb 2024)
- Uses \`421 4.7.0\` for temporary blocks

**Best Practices:**
1. Process bounces in real-time — don't batch
2. Hard bounces → immediate suppression
3. Soft bounces → suppress after 3 consecutive failures across 7 days
4. Monitor bounce rate — keep under 2% (ideally <1%)
5. Never re-add bounced addresses without verification
6. Use \`get_bounce_report\` and \`check_suppression_status\` to investigate`,
        suggestedFollowUps: [
            'Show me my bounce report',
            'Check suppression status for an address',
            'Why is Microsoft blocking me?',
            'Clean my list of bounced addresses',
        ],
        relatedGlossaryTerms: ['Bounce Rate', 'Hard Bounce', 'Soft Bounce', 'Suppression List', 'Sender Reputation'],
    },

    // ── SUP: Suppression management ──
    {
        intent: 'suppression_management',
        keywords: ['suppression', 'suppression list', 'suppressed', 'unsuppress', 'remove suppression', 'globally suppressed', 're-add suppressed', 'suppression scope', 'suppressed recipient'],
        sampleQuestions: [
            'Why is this contact suppressed?',
            'How do I remove someone from the suppression list?',
            'What is the difference between campaign and global suppression?',
            'A valid contact is suppressed and I need to re-send',
            'Check if an email address is suppressed',
        ],
        contextualResponse: `Suppression list management guide:

**Types of Suppression:**

| Scope | Trigger | Can Unsuppress? | Risk Level |
|-------|---------|-----------------|------------|
| **Hard bounce** | 5.1.x bounce | Yes (with caution) | High — re-sending to invalid = reputation damage |
| **Spam complaint** | FBL report | No (requires explicit re-consent) | Critical — violates anti-spam law |
| **Manual unsubscribe** | User clicked unsub link | No (requires explicit re-consent) | Critical — violates CAN-SPAM/GDPR |
| **Admin suppression** | Added manually by admin | Yes | Low |
| **List-level** | Bounced on specific list | Yes (can try on different list) | Medium |
| **Global/Tenant** | Bounced/complained on any list | Requires admin approval | High |

**When it's safe to unsuppress:**
1. You **verified the address is valid** (typo was fixed, mailbox was recreated)
2. You have **documented re-consent** from the recipient
3. The suppression was an **admin/manual** addition that is no longer needed
4. The address was a **role address** (info@, support@) that was incorrectly bounced

**When NOT to unsuppress:**
- Spam complaints — NEVER unsuppress without explicit written re-consent
- Unsubscribes — Requires the person to re-subscribe themselves (double opt-in)
- Repeated hard bounces — Address is genuinely invalid

**How to investigate and resolve:**
1. \`check_suppression_status\` — See why and when the address was suppressed
2. \`get_suppression_scope\` — Check if it's per-campaign, per-list, or tenant-wide
3. \`remove_from_suppression\` — After confirming validity and re-consent (requires Editor role)
4. Verify the address is deliverable before re-sending

⚠️ **Compliance warning:** Unsuppressing spam complaints or unsubscribes without proper re-consent violates CAN-SPAM (up to $51,744/email) and GDPR (up to 4% of global revenue).`,
        suggestedFollowUps: [
            'Check if a specific address is suppressed',
            'View suppression scope for an address',
            'Remove an address from suppression (with re-consent)',
            'Export my full suppression list',
        ],
        relatedGlossaryTerms: ['Suppression List', 'Bounce Rate', 'Complaint Rate', 'CAN-SPAM', 'GDPR'],
    },

    // ── EVT: Webhook setup & troubleshooting ──
    {
        intent: 'webhook_troubleshooting',
        keywords: ['webhook', 'webhooks', 'webhook endpoint', 'webhook failure', 'webhook retry', 'webhook signature', 'hmac', 'event notification', 'callback', 'webhook disabled', 'idempotency', 'webhook events', 'webhook delivery'],
        sampleQuestions: [
            'My webhooks are not being delivered',
            'How do I verify webhook signatures?',
            'Webhook endpoint returning 500 errors',
            'What webhook events does ApexMail send?',
            'How do I handle duplicate webhook events?',
        ],
        contextualResponse: `Webhook configuration and troubleshooting guide:

**Available Webhook Events:**
| Event | Trigger | Payload Key |
|-------|---------|-------------|
| \`message.delivered\` | Email accepted by recipient server | messageId, recipient, timestamp |
| \`message.bounced\` | Hard or soft bounce received | messageId, bounceType, code, reason |
| \`message.opened\` | Tracking pixel loaded | messageId, recipient, userAgent, ip |
| \`message.clicked\` | Link clicked | messageId, recipient, url, userAgent |
| \`message.complained\` | Spam complaint (FBL) | messageId, recipient, feedbackType |
| \`message.unsubscribed\` | Unsubscribe action | messageId, recipient, method |
| \`list.subscribed\` | New subscriber added | listId, contact, source |
| \`campaign.sent\` | Campaign finished sending | campaignId, stats |

**Signature Verification (HMAC-SHA256):**
\`\`\`
signature = HMAC-SHA256(webhook_secret, timestamp + "." + raw_body)
Compare: X-ApexMail-Signature header vs computed signature
Reject if timestamp is >5 minutes old (replay protection)
\`\`\`

**Common Failures & Fixes:**

1. **Endpoint returning 4xx/5xx** → Check your server logs. 2xx required within 30 seconds
2. **Webhook disabled after failures** → Re-enable with \`enable_webhook_endpoint\` after fixing the issue
3. **Events not arriving** → Check \`get_webhook_config\` for event type filters and endpoint URL
4. **Duplicate events** → Implement idempotency using the \`eventId\` field. Store processed IDs for 24h
5. **Firewall blocking** → Whitelist ApexMail webhook IPs (available in dashboard)
6. **Signature mismatch** → Verify you're using raw request body (not parsed JSON) for HMAC computation
7. **Timeout** → Respond with 200 immediately, process asynchronously. Don't do heavy work in the handler

**Retry Policy:**
- Failed deliveries are retried with exponential backoff: 1m, 5m, 30m, 2h, 8h, 24h
- After 6 consecutive failures, the endpoint is automatically disabled
- Use \`get_webhook_delivery_log\` to see all delivery attempts and response codes
- Use \`resend_webhook_events\` to manually replay missed events

**Best Practices:**
- Always verify signatures before processing
- Respond 200 before processing (use a queue)
- Handle events idempotently (same event may arrive twice)
- Log all incoming webhooks for debugging
- Set up alerting on webhook failure rates`,
        suggestedFollowUps: [
            'Show me my webhook configuration',
            'View webhook delivery logs',
            'Resend failed webhook events',
            'Re-enable my disabled webhook endpoint',
        ],
        relatedGlossaryTerms: ['Tracking Pixel', 'Feedback Loop'],
    },

    // ── API: Error diagnosis & integration ──
    {
        intent: 'api_error_diagnosis',
        keywords: ['api error', '400', '401', '403', '404', '409', '422', '429', '500', '502', '503', '504', 'rate limit', 'api key', 'authentication failed', 'unauthorized', 'forbidden', 'content-type', 'request body', 'api timeout', 'gateway timeout'],
        sampleQuestions: [
            'I\'m getting a 429 rate limit error',
            'API returns 401 unauthorized',
            'What does a 422 validation error mean?',
            'API is returning 500 internal server error',
            'How do I fix a 403 forbidden error?',
        ],
        contextualResponse: `API error diagnosis guide:

**HTTP Error Codes & Fixes:**

| Code | Meaning | Common Cause | Fix |
|------|---------|-------------|-----|
| **400** | Bad Request | Missing required field, invalid JSON, wrong Content-Type | Check request body schema. Use \`Content-Type: application/json\` |
| **401** | Unauthorized | Invalid, expired, or missing API key | Check \`Authorization: Bearer <key>\` header. Regenerate key if needed |
| **403** | Forbidden | Key lacks required scope, IP not allowlisted, account suspended | Check API key permissions. Verify IP allowlist with \`manage_ip_allowlist\` |
| **404** | Not Found | Wrong endpoint URL, resource doesn't exist | Check API docs for correct endpoint. Verify resource ID exists |
| **409** | Conflict | Duplicate request, resource already exists | Use idempotency key to prevent duplicates. Check existing resources |
| **422** | Unprocessable | Valid JSON but business logic rejection (invalid email, quota exceeded) | Read the error \`details\` field for specific validation failures |
| **429** | Rate Limited | Too many requests | Check \`X-RateLimit-Remaining\` and \`Retry-After\` headers. Implement exponential backoff |
| **500** | Internal Error | Server-side bug | Retry with backoff. If persistent, check \`get_api_health_detailed\` and contact support |
| **502** | Bad Gateway | Upstream service unavailable | Usually transient. Retry after 30 seconds |
| **503** | Service Unavailable | Maintenance or overload | Check status page. Retry with backoff |
| **504** | Gateway Timeout | Request took too long | Reduce batch size. Use async endpoints for large operations |

**Rate Limits:**
| Plan | Requests/second | Burst | Daily |
|------|-----------------|-------|-------|
| Free | 1 | 5 | 1,000 |
| Starter | 10 | 50 | 50,000 |
| Business | 50 | 200 | 500,000 |
| Enterprise | 200 | 1,000 | Unlimited |

**Debugging Steps:**
1. Check \`get_rate_limit_status\` for current quota state
2. Check \`get_api_error_log\` for recent error patterns
3. Verify API key scopes match the endpoint requirements
4. Use \`enable_sdk_debug_mode\` for verbose request/response logging
5. Test with curl before blaming client code

**Idempotency:**
- Include \`Idempotency-Key: <uuid>\` header on POST/PUT requests
- Server returns cached response for duplicate keys (24h window)
- Critical for payment, sending, and contact mutation endpoints`,
        suggestedFollowUps: [
            'Check my current rate limit status',
            'View my API error log',
            'Run an API health check',
            'Enable SDK debug mode',
        ],
        relatedGlossaryTerms: [],
    },

    // ── API: SDK integration ──
    {
        intent: 'sdk_integration_help',
        keywords: ['sdk', 'node sdk', 'python sdk', 'javascript', 'typescript', 'npm', 'pip', 'esm', 'commonjs', 'import', 'require', 'lambda', 'workers', 'cloudflare', 'next.js', 'nextjs', 'proxy', 'retry', 'timeout', 'sdk error'],
        sampleQuestions: [
            'How do I install the Node.js SDK?',
            'Python SDK throwing import errors',
            'ESM vs CommonJS import issue',
            'How to use the SDK in AWS Lambda?',
            'SDK timeout configuration',
        ],
        contextualResponse: `ApexMail SDK integration guide:

**Node.js SDK:**
\`\`\`
npm install @apexmail/sdk
// or
pnpm add @apexmail/sdk
\`\`\`

*ESM (recommended):*
\`\`\`javascript
import { ApexMail } from '@apexmail/sdk';
const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY });
\`\`\`

*CommonJS:*
\`\`\`javascript
const { ApexMail } = require('@apexmail/sdk');
\`\`\`

**Python SDK:**
\`\`\`
pip install apexmail
\`\`\`
\`\`\`python
from apexmail import ApexMailClient
client = ApexMailClient(api_key=os.environ['APEXMAIL_API_KEY'])
\`\`\`

**Configuration Options:**
| Option | Default | Description |
|--------|---------|-------------|
| \`timeout\` | 30000ms | Request timeout (increase for batch operations) |
| \`retries\` | 3 | Auto-retry on 429/5xx with exponential backoff |
| \`baseUrl\` | api.apexmail.com | Override for on-premise or proxy setups |
| \`debug\` | false | Enable verbose logging |

**Platform-Specific Notes:**

*AWS Lambda:*
- Set timeout > 30s to account for cold starts + API latency
- Use connection keep-alive: \`keepAlive: true\`
- Store API key in AWS Secrets Manager, not env vars

*Cloudflare Workers:*
- Use \`fetch\`-based transport (Workers don't support Node.js \`http\` module)
- SDK auto-detects Workers runtime and uses appropriate transport

*Next.js:*
- Use SDK in Server Components or API Routes only (not in client components — API key exposure risk)
- For App Router: use in \`route.ts\` handlers or Server Actions

*Proxy/Corporate Network:*
- Set \`proxy: 'http://proxy.corp.com:8080'\` in SDK config
- Or use \`HTTPS_PROXY\` environment variable

**Troubleshooting:**
- \`ERR_MODULE_NOT_FOUND\` — Check your \`package.json\` has \`"type": "module"\` for ESM
- \`Cannot find module\` — Run \`npm install\` again, check node_modules
- \`ECONNREFUSED\` — Proxy or firewall issue, check network connectivity
- \`ETIMEOUT\` — Increase timeout config, check for Lambda cold start`,
        suggestedFollowUps: [
            'Enable SDK debug mode',
            'Show me a code sample for sending email',
            'How do I handle SDK errors properly?',
            'Check my API key permissions',
        ],
        relatedGlossaryTerms: [],
    },

    // ── TPL: Template & content rendering ──
    {
        intent: 'template_rendering_issues',
        keywords: ['template', 'handlebars', 'mustache', 'variable', 'merge tag', 'render', 'rendering', 'placeholder', 'dynamic content', 'personalization', 'conditional', 'css', 'inline css', 'mobile', 'responsive', 'preheader', 'preview text', 'image', 'inline image', 'emoji', 'dark mode'],
        sampleQuestions: [
            'My template variables are not rendering',
            'Handlebars {{name}} showing as blank',
            'Email looks broken on Outlook',
            'How do I add conditional content?',
            'CSS styles not working in email',
        ],
        contextualResponse: `Email template rendering troubleshooting guide:

**Variable/Merge Tag Issues:**
- \`{{variable}}\` showing as blank → Variable key mismatch. Check the JSON payload key matches exactly (case-sensitive)
- \`{{variable}}\` showing literally → Template engine not processing. Verify the template type is set to Handlebars
- Nested variables: Use \`{{contact.firstName}}\` for nested objects
- Default values: \`{{firstName fallback="there"}}\` to avoid blank greetings
- Conditional blocks: \`{{#if premium}}...{{else}}...{{/if}}\`

**CSS & Rendering:**
- **Always inline CSS** — Most email clients strip \`<style>\` blocks. Use a CSS inliner tool
- **Outlook limitations:** No \`display:flex\`, \`border-radius\`, \`background-image\` on table cells. Use \`<table>\` layout
- **Gmail:** Strips \`<style>\` in \`<head>\`, keeps inline styles. Max width 600px
- **Dark mode:** Use \`@media (prefers-color-scheme: dark)\` but also set explicit background colors on all elements
- **Mobile responsive:** Use \`<meta name="viewport" content="width=device-width">\` and max-width on containers

**Common Rendering Fixes:**
1. **Images not showing** → Use absolute URLs, add \`alt\` text, keep total email size <102KB (Gmail clipping threshold)
2. **Gmail clipping "View entire message"** → Email HTML exceeds 102KB. Reduce HTML, remove unnecessary whitespace
3. **Broken layout in Outlook** → Use \`<!--[if mso]>\` conditional comments for Outlook-specific code
4. **Emoji not rendering** → Use HTML entities (\`&#128522;\`) instead of raw emoji. Test across clients
5. **Preheader text** → Add as the first element in \`<body>\`, then hide with \`display:none; max-height:0; overflow:hidden\`

**Template Validation:**
- Use \`validate_template\` to check for syntax errors, missing variables, and rendering issues
- Use \`get_content_scan_result\` to check if content triggers spam filters
- Test rendering in Litmus or Email on Acid before sending

**Best Practices:**
- 600px max width for email body
- 14px minimum font size for body text
- 44x44px minimum touch targets for mobile CTAs
- Alt text on all images (some clients block images by default)
- Plain-text version always included`,
        suggestedFollowUps: [
            'Validate my email template',
            'Check content scan results',
            'Preview my template on different email clients',
            'Help me fix Outlook rendering issues',
        ],
        relatedGlossaryTerms: ['Preheader', 'Call-to-Action', 'Personalization'],
    },

    // ── EVT: Link tracking & branding ──
    {
        intent: 'link_tracking_branding',
        keywords: ['tracking', 'link tracking', 'click tracking', 'open tracking', 'tracking domain', 'custom tracking', 'link branding', 'cname', 'ssl', 'ssl certificate', 'click rewriting', 'utm', 'utm parameters', 'bot clicks', 'bot filtering', 'prefetch'],
        sampleQuestions: [
            'How does link tracking work?',
            'Set up custom tracking domain',
            'Bot clicks inflating my click metrics',
            'SSL certificate for tracking domain not working',
            'How do I add UTM parameters?',
        ],
        contextualResponse: `Link tracking and branding guide:

**How Tracking Works:**
- **Open tracking:** 1x1 transparent pixel image loaded by email client → fires open event
- **Click tracking:** Links rewritten through tracking domain → records click → redirects to original URL
- **Default domain:** \`trk.apexmail.com\` → professional senders should use custom branded domain

**Custom Tracking Domain Setup:**
1. Choose a subdomain: \`email.yourdomain.com\` or \`links.yourdomain.com\`
2. Add CNAME record: \`email.yourdomain.com → trk.apexmail.com\`
3. SSL certificate is auto-provisioned (Let's Encrypt). Check status with \`check_cert_provisioning_status\`
4. Allow 15-30 minutes for DNS propagation and certificate issuance
5. Verify with \`get_tracking_domain_config\`

**SSL Issues:**
- Certificate pending → DNS not propagated yet. Wait and re-check
- Certificate failed → CNAME record incorrect or CAA record blocking Let's Encrypt
- Certificate expired → Auto-renewal should handle this. If failing, check DNS and run \`check_cert_provisioning_status\`

**Bot Click Filtering:**
- Security bots (Microsoft Defender, Barracuda) pre-fetch links in emails, inflating click metrics
- **ApexMail auto-filters:** Clicks within 2 seconds of delivery, known bot user-agents, same-IP mass clicking
- If bot clicks are still appearing, check your filter settings and review the user-agent patterns

**UTM Parameters:**
- Automatically appended: \`utm_source=apexmail&utm_medium=email&utm_campaign={campaign_name}\`
- Custom UTM: Set in campaign settings or per-link overrides
- UTM tracking is independent of click tracking — both can work together

**Tracking Domain Rotation:**
- Use \`rotate_tracking_domain\` if your current tracking domain is reputation-flagged
- ⚠️ Old links in previously sent emails will still use the old domain — keep it active

**Privacy Considerations:**
- Apple MPP pre-loads tracking pixels (~60% of iOS users) → open tracking is less reliable
- Some corporate email gateways strip tracking pixels — focus on click metrics
- GDPR requires disclosure of tracking in privacy policy`,
        suggestedFollowUps: [
            'Check my tracking domain configuration',
            'Check SSL certificate provisioning status',
            'Set up a custom tracking domain',
            'Show me click tracking analytics',
        ],
        relatedGlossaryTerms: ['Open Rate', 'Click-Through Rate', 'Apple MPP', 'Tracking Pixel'],
    },

    // ── ACC: Billing & quota management ──
    {
        intent: 'billing_quota_understanding',
        keywords: ['quota', 'sending limit', 'plan limit', 'overage', 'what counts', 'send count', 'billing cycle', 'test sends', 'retry billing', 'burst', 'queue sla', 'invoice', 'reconciliation', 'usage breakdown'],
        sampleQuestions: [
            'What counts as a sent email for billing?',
            'Am I being charged for test sends?',
            'My invoice doesn\'t match my actual sends',
            'What happens when I hit my quota limit?',
            'How does burst sending affect my billing?',
        ],
        contextualResponse: `Billing and quota management guide:

**What Counts as a "Send":**
- Each unique recipient = 1 send (a campaign to 1,000 contacts = 1,000 sends)
- Test sends (preview, proof) = YES, they count
- Retries after soft bounce = NO, they don't count (same messageId)
- Webhook event delivery = NO
- Transactional emails = counted separately if on a transactional plan

**Quota Behavior:**
| Scenario | What Happens |
|----------|-------------|
| 80% of quota used | Warning notification |
| 100% of quota reached | New sends queued (not rejected) |
| 24h at 100% | Sends start being rejected with 429 |
| Quota resets | Monthly on billing cycle date |

**Invoice Reconciliation:**
If your invoice doesn't match expectations:
1. Run \`get_usage_breakdown\` — shows hourly/daily breakdown by type
2. Run \`get_invoice_reconciliation\` — compares invoice vs actual API logs
3. Common discrepancies:
   - Test/preview emails counted in billing but not in campaign stats
   - Automation sends not visible in campaign dashboard
   - Multi-recipient API calls counted per recipient, not per API call

**Burst Sending:**
- Burst = sending above your sustained rate temporarily
- Bursts are allowed up to 2x your plan's per-second rate for 60 seconds
- Sustained bursting may trigger rate limiting (429)
- Use \`get_rate_limit_status\` to check remaining burst capacity

**Queue SLA:**
- Campaign emails: delivered within 1 hour of schedule time (99.9% SLA)
- Transactional emails: delivered within 30 seconds of API call (99.95% SLA)
- Check \`get_worker_status\` if queue is backing up`,
        suggestedFollowUps: [
            'Check my current quota status',
            'Show me my usage breakdown',
            'Run an invoice reconciliation',
            'What plan should I be on?',
        ],
        relatedGlossaryTerms: [],
    },

    // ── OPS: IP warmup & infrastructure ──
    {
        intent: 'ip_warmup_infrastructure',
        keywords: ['warmup', 'warm up', 'ip warmup', 'dedicated ip', 'shared ip', 'ip pool', 'ip assignment', 'warmup schedule', 'warmup stalled', 'reputation building', 'new ip', 'ipv6', 'sending infrastructure', 'connection pooling'],
        sampleQuestions: [
            'How do I warm up a new dedicated IP?',
            'My IP warmup seems to have stalled',
            'Should I use dedicated or shared IP?',
            'How do I request a dedicated IP?',
            'What\'s the warmup schedule?',
        ],
        contextualResponse: `IP warmup and sending infrastructure guide:

**Dedicated vs Shared IP:**
| Factor | Shared IP | Dedicated IP |
|--------|-----------|-------------|
| Cost | Included in plan | Free/Starter: N/A, Pro: $30/mo add-on, Growth: 1 included, Scale: 3 included, Enterprise: 10 included |
| Reputation | Shared with other senders | 100% yours to build |
| Volume needed | Any | Minimum 50,000 emails/month recommended |
| Warmup required | No (already warm) | Yes (4-8 weeks) |
| Best for | Low-volume senders | High-volume, reputation-sensitive senders |

**IP Warmup Schedule (Recommended):**
| Week | Daily Volume | Target Recipients |
|------|-------------|------------------|
| 1 | 50-100 | Most engaged subscribers only |
| 2 | 200-500 | Engaged (opened in last 30 days) |
| 3 | 500-1,000 | Engaged (opened in last 60 days) |
| 4 | 1,000-5,000 | Active subscribers |
| 5 | 5,000-10,000 | Full list segments |
| 6 | 10,000-50,000 | Expanding to full list |
| 7-8 | 50,000+ | Full volume |

**Critical Warmup Rules:**
1. **Send to engaged users first** — Opens/clicks signal legitimacy to ISPs
2. **Maintain consistency** — Don't skip days or have huge volume swings
3. **Monitor bounce rate** — If >5% on any day, pause and investigate
4. **Watch for deferrals** — 421 codes are normal during warmup, but excessive deferrals mean slow down
5. **Don't switch IPs mid-warmup** — Stick with the same IP throughout
6. **Authenticate** — SPF, DKIM, DMARC must be perfect before starting

**Warmup Stalled?**
- Check \`get_warmup_status\` — shows current progress, volume targets, and health metrics
- Common causes: volume didn't increase for >3 days, bounce rate spiked, recipient engagement too low
- Fix: Resume with engaged segment, verify list quality, check authentication

**IPv6 Sending:**
- Supported but not required. Gmail and Yahoo accept IPv6
- IPv6 requires separate warmup from IPv4
- PTR records required for IPv6 addresses too`,
        suggestedFollowUps: [
            'Check my IP warmup status',
            'Request a dedicated IP',
            'Show my current IP assignment',
            'What\'s my sending reputation?',
        ],
        relatedGlossaryTerms: ['Sender Reputation', 'SPF', 'DKIM', 'DMARC'],
    },

    // ── SEC: Security best practices ──
    {
        intent: 'security_best_practices',
        keywords: ['api key', 'api key security', 'ip allowlist', 'ip whitelist', 'rbac', 'role', 'permission', 'sso', 'saml', '2fa', 'mfa', 'two factor', 'scim', 'team member', 'audit log', 'access control', 'key rotation', 'least privilege'],
        sampleQuestions: [
            'How do I secure my API keys?',
            'Set up IP allowlisting',
            'What roles and permissions are available?',
            'How do I enable SSO/SAML?',
            'Best practices for API key management',
        ],
        contextualResponse: `Security best practices for ApexMail:

**API Key Security:**
1. **Never expose keys client-side** — Use server-side calls only
2. **Use scoped keys** — Create keys with minimum required permissions (read-only, send-only, etc.)
3. **Rotate keys regularly** — Every 90 days recommended. Old key stays valid for 24h overlap
4. **Use environment variables** — Never hardcode keys in source code or commit to git
5. **IP-restrict keys** — Bind keys to specific IPs with \`manage_ip_allowlist\`
6. **Monitor usage** — Check \`get_api_access_log\` for unusual activity

**Role-Based Access Control (RBAC):**
| Role | Permissions |
|------|------------|
| **Viewer** | Read-only access to campaigns, stats, logs |
| **Editor** | Create/edit campaigns, manage contacts, view reports |
| **Admin** | Full access including billing, API keys, team management |
| **Owner** | Admin + account deletion, plan changes, security settings |

**Team Security:**
- Enforce 2FA/MFA for all team members (especially Admins)
- Use SSO/SAML for enterprise — eliminates password management
- SCIM provisioning for automatic user lifecycle management
- Review team member access quarterly — remove inactive accounts
- Use \`get_user_permissions\` to audit current role assignments

**Account Security Monitoring:**
- Enable webhook for \`security.api_key_created\` and \`security.login\` events
- Review \`get_audit_log\` regularly for unexpected changes
- Set up alerts for API access from new geographic locations
- Use \`get_api_access_log\` to monitor for key compromise indicators

**Emergency Response:**
- Compromised API key → Immediately revoke with \`revoke_api_key\`
- Suspicious sending → Use \`set_emergency_throttle\` to halt sending
- Account takeover → Use \`freeze_account\` to lock everything immediately
- Post-incident → Export audit log for forensic review`,
        suggestedFollowUps: [
            'Check my current user permissions',
            'View my audit log',
            'Set up IP allowlisting',
            'Check API access logs',
        ],
        relatedGlossaryTerms: [],
    },

    // ── CMP: Compliance procedures ──
    {
        intent: 'compliance_procedures',
        keywords: ['gdpr erasure', 'data deletion', 'right to be forgotten', 'data subject request', 'dsar', 'dpa', 'data processing agreement', 'soc 2', 'hipaa', 'baa', 'data residency', 'data retention', 'legal hold', 'litigation hold', 'consent proof', 'opt-in proof', 'google yahoo 2024', 'list-unsubscribe'],
        sampleQuestions: [
            'How do I handle a GDPR data deletion request?',
            'I need a Data Processing Agreement',
            'Do you have SOC 2 certification?',
            'How do I prove opt-in consent?',
            'Google/Yahoo 2024 sender requirements',
        ],
        contextualResponse: `Compliance procedures guide:

**GDPR Data Subject Requests:**
1. **Right to Erasure (Article 17):**
   - Must process within 30 days
   - Use \`execute_gdpr_erasure\` — permanently deletes: contact record, all message content, activity logs, metadata
   - ⚠️ Irreversible — confirm with customer before executing
   - Generates compliance certificate with timestamp and scope

2. **Right to Access (Article 15):**
   - Export all data associated with the email address
   - Includes: profile data, consent records, message history, activity logs
   - Must respond within 30 days

3. **Consent Proof:**
   - Use \`get_consent_record\` — shows timestamp, method (form, API, import), IP address, and exact opt-in text
   - Always use double opt-in — provides strongest consent evidence
   - Store consent proof for the lifetime of the subscriber relationship + 3 years

**Data Processing Agreement (DPA):**
- Required when processing EU personal data
- Use \`request_dpa\` — pre-signed DPA available for download
- Covers: sub-processors, data transfers, security measures, breach notification

**Certifications & Compliance Docs:**
| Document | Status | Request |
|----------|--------|---------|
| SOC 2 Type II | Available | \`request_compliance_doc\` |
| HIPAA BAA | Enterprise only | \`request_compliance_doc\` |
| ISO 27001 | In progress | Contact sales |
| GDPR DPA | Available | \`request_dpa\` |
| CCPA Addendum | Available | \`request_compliance_doc\` |

**Data Retention Policy:**
- Default: Message content retained for 90 days, activity logs for 365 days
- Customizable with \`set_retention_policy\` (minimum 30 days for operational needs)
- \`set_legal_hold\` prevents deletion of specific data during litigation/investigation

**Google/Yahoo 2024 Bulk Sender Requirements (>5,000/day):**
1. ✅ SPF and DKIM authentication on sending domain
2. ✅ DMARC policy published (at minimum p=none)
3. ✅ One-click List-Unsubscribe (RFC 8058) in all marketing emails
4. ✅ Spam rate below 0.3% (target <0.1%)
5. ✅ Valid forward and reverse DNS (PTR) records
6. ✅ TLS encryption for SMTP transmission
7. ✅ From: header domain aligned with SPF or DKIM domain`,
        suggestedFollowUps: [
            'Process a GDPR erasure request',
            'Request a DPA',
            'Check my compliance risk score',
            'Look up consent proof for a subscriber',
        ],
        relatedGlossaryTerms: ['GDPR', 'CAN-SPAM', 'CCPA', 'Double Opt-in', 'List-Unsubscribe Header'],
    },

    // ── SEC: Sending suspended scenarios ──
    {
        intent: 'sending_suspended',
        keywords: ['suspended', 'account suspended', 'sending paused', 'sending disabled', 'sending blocked', 'complaint threshold', 'purchased list', 'content violation', 'phishing', 'abuse', 'tos violation', 'terms of service'],
        sampleQuestions: [
            'Why is my sending suspended?',
            'My account was disabled for high complaints',
            'How do I get my account reactivated?',
            'Sending paused for content violation',
            'I did not send spam, this is a mistake',
        ],
        contextualResponse: `Account suspension and sending pause troubleshooting:

**Common Suspension Reasons:**

| Reason | Trigger | Severity | Resolution |
|--------|---------|----------|------------|
| **High complaint rate** | >0.3% spam complaints | Critical | List cleanup + re-engagement required |
| **High bounce rate** | >10% bounces in a send | High | Verify list, remove invalid addresses |
| **Purchased/scraped list** | Detected spam trap hits | Critical | Remove the list, use only opt-in contacts |
| **Content violation** | Phishing, malware, deceptive content | Critical | Content review required |
| **Billing past due** | Payment failed for >7 days | Medium | Update payment method |
| **TOS violation** | Prohibited content (per AUP) | Critical | Account review required |

**Self-Service Resolution Steps:**
1. \`get_sending_status\` — See exactly why sending was paused and what triggered it
2. Check your bounce and complaint rates with \`get_bounce_report\` and \`get_complaint_rate\`
3. Clean your list — remove all bounced, unsubscribed, and unengaged contacts
4. If billing-related — update payment at billing.apexmail.com

**Escalation Required For:**
- "Purchased list" determination you believe is incorrect
- Content violation you believe is a false positive
- Account suspended for >7 days without resolution
- Request to present evidence of legitimate list building

**Reactivation Process:**
1. Address the root cause (clean list, fix content, update billing)
2. Submit reactivation request with remediation steps taken
3. Support reviews within 24-48 hours
4. If approved: sending resumes on probation (reduced limits for 14 days)
5. Full limits restored after clean sending during probation

**Prevention:**
- Use double opt-in for all signups
- Never import purchased or rented lists
- Monitor complaint rate daily (target <0.1%)
- Implement sunset policy for unengaged subscribers
- Review content against AUP before sending`,
        suggestedFollowUps: [
            'Check my sending status',
            'View my complaint rate',
            'Get my bounce report',
            'Contact support for reactivation',
        ],
        relatedGlossaryTerms: ['Complaint Rate', 'Bounce Rate', 'Spam Trap', 'Sender Reputation', 'Suppression List'],
    },

    // ── OPS: Performance diagnostics ──
    {
        intent: 'performance_diagnostics',
        keywords: ['slow', 'latency', 'performance', 'api slow', 'sending slow', 'queue backed up', 'delayed', 'lag', 'timeout', 'worker', 'redis', 'postgres', 'database slow', 'nginx', 'high cpu', 'memory', 'disk'],
        sampleQuestions: [
            'API responses are slow',
            'My emails are delayed in the queue',
            'System seems sluggish today',
            'Sending is taking longer than usual',
            'Is there a system performance issue?',
        ],
        contextualResponse: `Performance diagnostics guide:

**Symptoms & Diagnostic Actions:**

| Symptom | Check | Action |
|---------|-------|--------|
| API latency >500ms | \`get_api_health_detailed\` | Check if specific endpoints are slow |
| Emails delayed | \`get_worker_status\` | Check queue depth and processing rate |
| Dashboard slow | \`get_system_health\` | Check PostgreSQL and Redis health |
| Sends stalled | \`get_throttle_status\` | Check if rate limiting is active |
| Webhooks delayed | \`get_webhook_delivery_log\` | Check webhook queue separately |

**System Health Checks:**
1. \`get_system_health\` — Overall status of all services (API, MTA, workers, databases)
2. \`get_worker_status\` — Background job queue depth, processing rate, error rate
3. \`get_api_health_detailed\` — Per-endpoint latency percentiles and error rates
4. \`get_throttle_status\` — Any active rate limits or sending throttles

**Common Performance Issues:**
- **API latency spike:** Usually database-related. Check if large queries are running (analytics, exports)
- **Queue backup:** Worker processes may be restarting or overwhelmed. Check \`get_worker_status\`
- **Delayed sends:** Could be warmup throttling, recipient server deferrals, or queue backup
- **Webhook delays:** Separate queue from email sending. Check endpoint response times

**What You Can Do:**
- Large batches → Use async API endpoints to avoid timeout
- Rate limited → Spread sends over longer period or upgrade plan
- Consistently slow → Check your region/datacenter selection
- Intermittent → Check \`get_system_health\` — may be transient maintenance

**Escalation triggers:**
- API p95 latency >2 seconds for >15 minutes
- Email queue depth >100,000 and not decreasing
- Worker error rate >5%
- Multiple service components showing degraded`,
        suggestedFollowUps: [
            'Check system health status',
            'View worker queue status',
            'Run an API health check',
            'Check if rate limiting is active',
        ],
        relatedGlossaryTerms: [],
    },

    // ── SEND: Sender identity & addressing ──
    {
        intent: 'sender_identity_addressing',
        keywords: ['from address', 'from name', 'sender', 'return-path', 'envelope sender', 'via', 'on behalf of', 'subdomain', 'free mailbox', 'gmail from', 'yahoo from', 'custom domain', 'reply-to', 'sender identity'],
        sampleQuestions: [
            'Why does my email show "via apexmail.com"?',
            'Can I use a Gmail address as my From?',
            'What is the Return-Path and why does it matter?',
            'How do I remove the "on behalf of" text?',
            'Should I use a subdomain for sending?',
        ],
        contextualResponse: `Sender identity and addressing guide:

**"via" / "on behalf of" Message:**
- Appears when the envelope sender (Return-Path) domain doesn't match the From header domain
- **Fix:** Verify your custom domain so ApexMail sends with your domain in the Return-Path
- After domain verification: both From and Return-Path use your domain → "via" disappears

**From Address Best Practices:**
- Use your own domain: \`hello@yourdomain.com\` (not a free mailbox)
- ⚠️ **Don't use @gmail.com, @yahoo.com, @outlook.com as From** — these providers enforce strict DMARC (p=reject), so your emails will be rejected by all DMARC-enforcing receivers
- Sender name: Use "Person at Company" format for best recognition and open rates

**Return-Path / Envelope Sender:**
- The address that receives bounce notifications (NDRs)
- Should be on your verified domain for DMARC SPF alignment
- ApexMail sets this automatically after domain verification

**Reply-To:**
- Set a different reply-to if you want replies going to a different inbox
- Common: From: marketing@co.com, Reply-To: support@co.com
- Reply-To does NOT affect authentication — SPF/DKIM check the From and Return-Path

**Subdomain Strategy:**
- Recommended: Use a subdomain for marketing email (\`mail.yourdomain.com\`)
- **Why?** Isolates marketing reputation from your corporate domain
- If marketing reputation takes a hit, corporate email (\`yourdomain.com\`) is unaffected
- Use separate subdomains for transactional vs marketing if volume is significant

**RFC 5322 Compliance:**
- From address must be syntactically valid (local-part@domain)
- Display name can include UTF-8 characters
- Multiple From addresses NOT supported (use Sender header instead)`,
        suggestedFollowUps: [
            'Verify my custom domain',
            'Check my sender reputation',
            'Set up a subdomain for sending',
            'Check my DMARC alignment',
        ],
        relatedGlossaryTerms: ['SPF', 'DKIM', 'DMARC', 'Sender Reputation'],
    },

    // ── DLV: Inbound email & processing ──
    {
        intent: 'inbound_email_setup',
        keywords: ['inbound', 'receive email', 'incoming email', 'mx record', 'inbound parse', 'inbound webhook', 'email to webhook', 'receive and parse', 'reply processing', 'inbound routing'],
        sampleQuestions: [
            'How do I set up inbound email processing?',
            'Can ApexMail receive emails?',
            'How do I parse incoming emails?',
            'Set up MX records for inbound',
            'Route incoming emails to my webhook',
        ],
        contextualResponse: `Inbound email processing guide:

**How Inbound Works:**
1. Set MX record for your domain (or subdomain) to point to ApexMail's inbound servers
2. ApexMail receives the email, parses it, and forwards as a webhook to your endpoint
3. Your endpoint receives structured JSON with: from, to, subject, text body, HTML body, attachments

**Setup Steps:**
1. **DNS:** Add MX record: \`inbound.yourdomain.com MX 10 mx.apexmail.com\`
2. **Configure endpoint:** Set your webhook URL in ApexMail inbound settings
3. **Define routing rules:** Route by recipient address pattern, subject, or sender
4. **Test:** Send an email to your inbound address and verify webhook delivery

**Inbound Webhook Payload:**
| Field | Type | Description |
|-------|------|-------------|
| \`from\` | string | Sender email address |
| \`to\` | string[] | Recipient addresses |
| \`subject\` | string | Email subject line |
| \`text\` | string | Plain-text body |
| \`html\` | string | HTML body |
| \`attachments\` | object[] | File attachments (base64 encoded) |
| \`headers\` | object | Full email headers |
| \`spf\` | string | SPF check result |
| \`dkim\` | string | DKIM verification result |

**Use Cases:**
- Reply processing (track replies to campaigns)
- Support ticket creation
- Lead capture from email
- Email-to-task/CRM integration
- Automated email parsing (invoices, notifications)

**Limitations:**
- Max inbound email size: 25MB (including attachments)
- Attachment types can be filtered (block executables, etc.)
- Rate limit: 100 inbound emails/minute (contact sales for higher limits)`,
        suggestedFollowUps: [
            'Set up inbound email for my domain',
            'Configure inbound webhook',
            'Test my inbound email setup',
            'View inbound processing logs',
        ],
        relatedGlossaryTerms: ['SPF', 'DKIM'],
    },

    // ── LLM: AI chatbot diagnostics ──
    {
        intent: 'chatbot_diagnostics',
        keywords: ['chatbot', 'ai', 'bot', 'assistant', 'wrong answer', 'not helpful', 'slow response', 'cut off', 'truncated', 'context window', 'hallucination', 'made up', 'irrelevant answer', 'broken chatbot', 'ai broken'],
        sampleQuestions: [
            'The chatbot gave me a wrong answer',
            'AI response was cut off mid-sentence',
            'The bot keeps misunderstanding my question',
            'Chatbot is slow to respond',
            'The AI made up information that is incorrect',
        ],
        contextualResponse: `AI assistant diagnostics guide:

**Common Issues & Fixes:**

| Issue | Cause | Diagnostic | Fix |
|-------|-------|-----------|-----|
| Wrong answer | Intent misclassification | \`get_intent_debug\` | Rephrase question more specifically |
| Cut off response | Token limit reached | \`get_llm_config\` | Break complex questions into smaller parts |
| Slow response | Model inference time | \`get_llm_session_log\` | Normal is 2-8 seconds. If consistently >15s, report |
| Irrelevant info | RAG retrieval miss | \`get_rag_debug\` | Use more specific terminology |
| Wrong action | Tool call misrouted | \`get_intent_debug\` | Specify exactly what action you want |
| Hallucination | Model confabulation | \`get_llm_session_log\` | Verify information through actions (check status, get report) |

**How the AI Assistant Works:**
1. **Intent Detection** — Your message is classified into a category (support, billing, domain, etc.) and specific action
2. **Security Check** — Your permissions are verified for the detected action
3. **Response Generation** — The model generates a response with context from your account
4. **Action Execution** — If an action is identified, it's executed (with confirmation for risky operations)
5. **Verification** — Response quality is checked before delivery

**Tips for Getting Better Answers:**
- Be specific: "Check my SPF record for example.com" vs "email not working"
- Provide context: Include error codes, message IDs, domain names
- One question at a time: Complex multi-part questions may confuse intent detection
- Use the correct terminology: "DMARC alignment" vs "that authentication thing"

**When to Escalate:**
- The assistant consistently gives wrong answers for your specific question
- A critical action needs to be performed that the assistant can't handle
- You need real-time human support for an urgent production issue`,
        suggestedFollowUps: [
            'Check the AI configuration',
            'Debug the last intent classification',
            'View the AI session log',
            'Debug RAG retrieval quality',
        ],
        relatedGlossaryTerms: [],
    },
];

// ═══════════════════════════════════════════════════════════════
// 6. APEXMAIL SYSTEM CONTEXT — platform-specific terminology
// ═══════════════════════════════════════════════════════════════

export interface SystemCapability {
    feature: string;
    description: string;
    commands: string[];
    apiEndpoints: string[];
}

export const APEXMAIL_CAPABILITIES: SystemCapability[] = [
    {
        feature: 'Campaign Management',
        description: 'Create, schedule, send, pause, and delete email campaigns. Supports A/B testing, scheduling, and multi-segment targeting.',
        commands: ['create campaign', 'send campaign', 'schedule campaign', 'pause campaign', 'delete campaign'],
        apiEndpoints: ['POST /api/campaigns', 'PUT /api/campaigns/:id', 'POST /api/campaigns/:id/send'],
    },
    {
        feature: 'Contact & List Management',
        description: 'Manage subscriber lists, add/remove contacts, import/export contacts, create segments, and manage tags.',
        commands: ['create list', 'add contact', 'remove contact', 'import contacts', 'create segment', 'tag contacts'],
        apiEndpoints: ['POST /api/lists', 'POST /api/contacts', 'POST /api/contacts/import', 'POST /api/segments'],
    },
    {
        feature: 'Analytics & Reporting',
        description: 'View campaign performance metrics, export reports, analyze trends, compare campaigns, and get AI-powered insights.',
        commands: ['show stats', 'export report', 'analyze performance', 'compare campaigns'],
        apiEndpoints: ['GET /api/analytics/campaigns/:id', 'GET /api/analytics/overview', 'POST /api/reports/export'],
    },
    {
        feature: 'Content Generation',
        description: 'AI-powered generation of subject lines, email bodies, CTAs, preheaders, and product descriptions. Includes quality scoring and optimization.',
        commands: ['generate subject lines', 'write email', 'generate content', 'suggest CTAs'],
        apiEndpoints: ['POST /api/ai/content/generate', 'POST /api/ai/content/subject-lines', 'POST /api/ai/content/analyze'],
    },
    {
        feature: 'Automation & Workflows',
        description: 'Set up automated email sequences triggered by events, time delays, or subscriber behavior. Includes welcome series, abandoned cart, and re-engagement.',
        commands: ['set automation', 'create workflow', 'create welcome series', 'set up drip campaign'],
        apiEndpoints: ['POST /api/automations', 'PUT /api/automations/:id', 'POST /api/automations/:id/activate'],
    },
    {
        feature: 'Deliverability Tools',
        description: 'Email authentication setup (SPF/DKIM/DMARC), IP warming, inbox placement testing, spam score checking, and sender reputation monitoring.',
        commands: ['check deliverability', 'run inbox test', 'check spam score', 'check authentication'],
        apiEndpoints: ['GET /api/deliverability/score', 'POST /api/deliverability/test', 'GET /api/domains/:id/auth'],
    },
    {
        feature: 'Send Time Optimization',
        description: 'AI-powered optimal send time prediction based on subscriber engagement patterns. Considers timezone, historical behavior, and email type.',
        commands: ['optimize send time', 'best time to send', 'schedule optimal'],
        apiEndpoints: ['POST /api/ai/sto/predict', 'GET /api/ai/sto/recommendations'],
    },
    {
        feature: 'Compliance Management',
        description: 'GDPR/CAN-SPAM/CCPA compliance tools: consent management, preference centers, data export, suppression lists, and audit trails.',
        commands: ['check compliance', 'export subscriber data', 'manage consent', 'view suppression list'],
        apiEndpoints: ['GET /api/compliance/status', 'POST /api/compliance/export', 'GET /api/suppressions'],
    },
];

// ═══════════════════════════════════════════════════════════════
// 7. QUALITY SCORING — calibrated weights from industry data
// ═══════════════════════════════════════════════════════════════

/** Real engagement multipliers calibrated from industry research */
export const CALIBRATED_ENGAGEMENT_MULTIPLIERS = {
    subjectLine: {
        personalization: 1.06,   // GetResponse: 20.66% vs 19.57% = 1.056x
        question: 1.15,          // Curiosity gap research
        emoji: 1.032,            // GetResponse: 20.37% vs 19.73% = 1.032x
        number: 1.12,            // Specificity research
        under50Chars: 1.08,      // Full visibility on most clients
        under33Chars: 1.12,      // Full visibility on all mobile clients
    },
    body: {
        personalization: 1.06,   // Body personalization: 2.48% vs 2.33% CTR
        hasCTA: 1.40,            // CTA presence drives clicks
        socialProof: 1.15,       // Trust indicators
        under200Words: 1.15,     // HubSpot data
        readability60Plus: 1.10, // Flesch-Kincaid 60-70 optimal
        images: 1.40,            // 21% OR with images vs 15% without
        headers: 1.27,           // 14% CTOR with headers vs 11% without
    },
};

// ═══════════════════════════════════════════════════════════════
// 8. LOOKUP HELPERS
// ═══════════════════════════════════════════════════════════════

/** Fuzzy-search the glossary by term or alias.
 *  Handles natural-language wrappers like "What is X?", "Explain X",
 *  "Tell me about X", and "Define X" by stripping common prefixes/suffixes
 *  before matching.  Also checks if any term or alias appears as a
 *  substring inside the query for broader recall. */
export function lookupGlossaryTerm(query: string): GlossaryEntry | undefined {
    const lower = query.toLowerCase().trim();

    // 1. Exact match on full query (original behaviour)
    const exact = GLOSSARY.find(
        (entry) =>
            entry.term.toLowerCase() === lower ||
            entry.aliases.some((a) => a.toLowerCase() === lower),
    );
    if (exact) return exact;

    // 2. Strip natural-language wrappers to extract the "core term"
    const stripped = lower
        .replace(/^(?:what(?:'s| is| are)?|explain|define|tell me about|describe|how (?:does|do)|what does)\s+/i, '')
        .replace(/[?.!]+$/g, '')
        .replace(/^(?:a |an |the )\s*/i, '')
        .trim();

    if (stripped.length > 0 && stripped !== lower) {
        const termMatch = GLOSSARY.find(
            (entry) =>
                entry.term.toLowerCase() === stripped ||
                entry.aliases.some((a) => a.toLowerCase() === stripped),
        );
        if (termMatch) return termMatch;
    }

    // 3. Substring containment — check if any glossary term/alias appears inside the query.
    //    Prefer the longest match to avoid false positives.
    let bestSubstring: GlossaryEntry | undefined;
    let bestLen = 0;

    for (const entry of GLOSSARY) {
        const termLower = entry.term.toLowerCase();
        if (lower.includes(termLower) && termLower.length > bestLen) {
            bestLen = termLower.length;
            bestSubstring = entry;
        }
        for (const alias of entry.aliases) {
            const aliasLower = alias.toLowerCase();
            if (aliasLower.length >= 3 && lower.includes(aliasLower) && aliasLower.length > bestLen) {
                bestLen = aliasLower.length;
                bestSubstring = entry;
            }
        }
    }

    return bestSubstring;
}

/** Find the best-matching conversation pattern for a user message */
export function matchConversationPattern(message: string): ConversationPattern | undefined {
    const lower = message.toLowerCase();
    let bestMatch: ConversationPattern | undefined;
    let bestScore = 0;

    for (const pattern of CONVERSATION_PATTERNS) {
        let score = 0;
        for (const kw of pattern.keywords) {
            if (lower.includes(kw.toLowerCase())) {
                score += kw.length; // Longer keyword matches are worth more
            }
        }
        if (score > bestScore) {
            bestScore = score;
            bestMatch = pattern;
        }
    }

    return bestScore > 0 ? bestMatch : undefined;
}

/** Get benchmark for an industry (fuzzy match) */
export function getIndustryBenchmark(industry: string): IndustryBenchmark | undefined {
    const lower = industry.toLowerCase();
    return INDUSTRY_BENCHMARKS.find((b) =>
        b.industry.toLowerCase().includes(lower) || lower.includes(b.industry.toLowerCase()),
    );
}

/** Get benchmark for an email type (fuzzy match) */
export function getEmailTypeBenchmark(type: string): EmailTypeBenchmark | undefined {
    const lower = type.toLowerCase().replace(/[_-]/g, ' ');
    return EMAIL_TYPE_BENCHMARKS.find((b) =>
        b.type.toLowerCase().includes(lower) || lower.includes(b.type.toLowerCase()),
    );
}
