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
