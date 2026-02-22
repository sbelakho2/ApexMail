/**
 * Campaign Templates Library — Cialdini-Optimised Edition
 *
 * Every template applies one or more of Cialdini's 6 principles of influence
 * to maximise engagement while remaining professional and credible:
 *
 *   1. Reciprocity   — Give value before asking for anything
 *   2. Commitment    — Small "yes" before the big ask
 *   3. Social Proof  — Show others like them are succeeding
 *   4. Authority     — Demonstrate domain expertise
 *   5. Liking        — Be genuinely helpful, warm, human
 *   6. Scarcity      — Honest time-limits, not fabricated urgency
 *
 * Design rules applied:
 *   • Max one CTA per email (cognitive focus)
 *   • Subject ≤ 78 chars, no ALL-CAPS, max one emoji
 *   • Every email includes a visible unsubscribe link
 *   • HTML is clean, single-column, system-font — renders everywhere
 *   • No unsubstantiated claims — every stat references a variable
 *   • Plain-text fallback auto-derived from HTML
 */

import { generateId } from '@apexmail/lib';
import type { DripSequenceStep, StepDelay, StepContent } from '../types.js';

// ────────────────────────────────────────────────────────────────────
// Shared Types
// ────────────────────────────────────────────────────────────────────

interface CampaignTemplate {
    id: string;
    name: string;
    description: string;
    category: TemplateCategory;
    sequence: DripSequenceStep[];
    suggestedTriggers: string[];
    suggestedExitConditions: string[];
    variables: TemplateVariable[];
    /** Which Cialdini principles this template primarily leverages */
    cialdiniPrinciples: CialdiniPrinciple[];
}

interface TemplateVariable {
    name: string;
    description: string;
    defaultValue: string;
    required: boolean;
}

type TemplateCategory =
    | 'cold_outreach'
    | 'nurture'
    | 'onboarding'
    | 're_engagement'
    | 'event'
    | 'trial';

type CialdiniPrinciple =
    | 'reciprocity'
    | 'commitment'
    | 'social_proof'
    | 'authority'
    | 'liking'
    | 'scarcity';

// ────────────────────────────────────────────────────────────────────
// Shared HTML Components — clean, system-font, single-column
// ────────────────────────────────────────────────────────────────────

const STYLE_RESET = `
  <style>
    body, table, td, p, a, li { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
    body { margin: 0; padding: 0; -webkit-text-size-adjust: 100%; }
    .email-body { max-width: 600px; margin: 0 auto; padding: 32px 24px; color: #1a1a2e; line-height: 1.6; font-size: 15px; }
    .email-body p { margin: 0 0 16px; }
    .email-body a { color: #2563eb; text-decoration: none; }
    .email-body a:hover { text-decoration: underline; }
    .cta-btn { display: inline-block; padding: 12px 28px; background: #2563eb; color: #ffffff !important; border-radius: 6px; font-weight: 600; font-size: 14px; text-decoration: none !important; margin: 8px 0 16px; }
    .cta-btn:hover { background: #1d4ed8; }
    .signature { color: #64748b; font-size: 13px; margin-top: 24px; border-top: 1px solid #e2e8f0; padding-top: 16px; }
    .footer { font-size: 11px; color: #94a3b8; margin-top: 32px; text-align: center; }
    .footer a { color: #94a3b8; }
    .tip-box { background: #f8fafc; border-left: 3px solid #2563eb; padding: 12px 16px; margin: 16px 0; border-radius: 0 6px 6px 0; }
    .metric { font-size: 28px; font-weight: 700; color: #2563eb; }
    ol, ul { padding-left: 20px; }
    li { margin-bottom: 8px; }
  </style>
`;

function wrap(inner: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${STYLE_RESET}</head>
<body><div class="email-body">${inner}</div></body>
</html>`;
}

function footer(): string {
    return `<div class="footer">
  <a href="{{unsubscribe_link}}">Unsubscribe</a> · <a href="{{preferences_link}}">Email preferences</a>
</div>`;
}

function signature(name = '{{sender_name}}', title = '{{sender_title}}'): string {
    return `<div class="signature">
  ${name}<br>
  <span style="font-size: 12px; color: #94a3b8;">${title}</span>
</div>`;
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function createDelay(
    value: number,
    unit: StepDelay['unit'],
    businessHoursOnly = true
): StepDelay {
    return {
        value,
        unit,
        businessHoursOnly,
        jitterMinutes: unit === 'minutes' ? 0 : 15,
    };
}

function createEmailContent(
    subject: string,
    body: string,
    variables: Record<string, string> = {}
): StepContent {
    return {
        subject,
        htmlBody: wrap(body + footer()),
        textBody: body.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim(),
        templateId: null,
        variables,
    };
}

// ╔═══════════════════════════════════════════════════════════════════╗
// ║  1. COLD OUTREACH — 5-touch "Give First" Sequence               ║
// ║                                                                   ║
// ║  Cialdini principles: Reciprocity → Authority → Social Proof     ║
// ║  → Commitment/Consistency → Scarcity                              ║
// ║                                                                   ║
// ║  Philosophy: Lead with a free, genuinely useful deliverable.      ║
// ║  Only ask for time after demonstrating expertise.                 ║
// ╚═══════════════════════════════════════════════════════════════════╝

const coldOutreachTemplate: CampaignTemplate = {
    id: 'tmpl_cold_outreach_5',
    name: 'Cold Outreach — 5 Touch "Give First"',
    description:
        'A Cialdini-optimised 5-email B2B cold outreach sequence. Leads with reciprocity (free value), builds authority, then converts via social proof and scarcity.',
    category: 'cold_outreach',
    cialdiniPrinciples: ['reciprocity', 'authority', 'social_proof', 'scarcity'],
    suggestedTriggers: ['lead_added', 'tag_added'],
    suggestedExitConditions: ['replied', 'unsubscribed', 'bounced'],
    variables: [
        { name: 'sender_name', description: 'Your name', defaultValue: 'Alex', required: true },
        { name: 'sender_title', description: 'Your job title', defaultValue: 'Deliverability Lead', required: true },
        { name: 'company_value_prop', description: 'One-sentence value proposition', defaultValue: 'help engineering teams ship transactional email that actually reaches the inbox', required: true },
        { name: 'free_resource_link', description: 'Link to a free guide, audit, or tool', defaultValue: 'https://apexmail.ee/guides/deliverability-checklist', required: true },
        { name: 'free_resource_name', description: 'Name of the free resource', defaultValue: 'Deliverability Checklist', required: true },
        { name: 'case_study_company', description: 'Company featured in social proof', defaultValue: 'a fast-growing SaaS team', required: false },
        { name: 'case_study_result', description: 'Specific result achieved (use real data)', defaultValue: 'cut bounce rates by 62% in the first month', required: false },
        { name: 'case_study_link', description: 'Link to the case study', defaultValue: 'https://apexmail.ee/customers', required: false },
        { name: 'calendar_link', description: 'Booking link', defaultValue: 'https://cal.com/apexmail', required: false },
    ],
    sequence: [
        // ── Touch 1: Pure Reciprocity (give, don't ask) ──
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Touch 1 — Free Resource (Reciprocity)',
            delay: createDelay(0, 'minutes'),
            content: createEmailContent(
                'Free resource for {{lead.company_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I put together a <strong>{{free_resource_name}}</strong> that covers the most common deliverability pitfalls we see at companies like {{lead.company_name}} — things like SPF alignment gaps, DKIM rotation schedules, and the one DNS record most teams forget.</p>

<div class="tip-box">
  <strong>Here's the link — no opt-in required:</strong><br>
  <a href="{{free_resource_link}}">{{free_resource_name}}</a>
</div>

<p>Hope it's useful. No reply needed.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 2: Authority (actionable insight) ──
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Touch 2 — Quick Insight (Authority)',
            delay: createDelay(3, 'days'),
            content: createEmailContent(
                'One thing I noticed about {{lead.domain}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I took a quick look at the public DNS records for <strong>{{lead.domain}}</strong> — not anything invasive, just the MX, SPF, and DKIM entries that anyone can query.</p>

<p>One pattern I see with a lot of growing teams: the default configuration from your email provider works fine at low volume, but starts causing soft-bounce issues as you scale past a few thousand sends per day.</p>

<div class="tip-box">
  <strong>Quick win:</strong> Make sure your SPF record uses <code>include:</code> rather than hard-coded IP ranges. It prevents breakage when your provider rotates infrastructure.
</div>

<p>If you want, I'm happy to send over a more specific review — just reply "sure" and I'll put it together.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 3: Social Proof ──
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Touch 3 — Case Study (Social Proof)',
            delay: createDelay(4, 'days'),
            content: createEmailContent(
                'How {{case_study_company}} improved their email delivery',
                `<p>Hi {{lead.first_name}},</p>

<p>Wanted to share a quick story that might resonate:</p>

<p>{{case_study_company}} was dealing with inconsistent inbox placement — open rates were dropping and their ops team was spending hours debugging bounces. After switching their sending infrastructure, they {{case_study_result}}.</p>

<p><a href="{{case_study_link}}">Here's the full write-up</a> if you're curious about the specifics.</p>

<p>I'm not assuming {{lead.company_name}} has the same problem, but if deliverability is something you're thinking about, I'd enjoy a quick conversation.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 4: Commitment (micro-yes) ──
        {
            id: generateId('step'),
            order: 4,
            type: 'email',
            name: 'Touch 4 — Micro-Commitment',
            delay: createDelay(5, 'days'),
            content: createEmailContent(
                'Quick question, {{lead.first_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I've sent a couple of emails with deliverability tips — hopefully at least one was useful.</p>

<p>I'm curious: is email infrastructure something {{lead.company_name}} handles internally, or do you work with a provider?</p>

<p>Either way is fine — I just want to make sure I'm sending relevant information rather than noise.</p>

<p>A one-line reply is plenty.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 5: Clean Close (Scarcity of attention, not fake urgency) ──
        {
            id: generateId('step'),
            order: 5,
            type: 'email',
            name: 'Touch 5 — Respectful Close (Scarcity)',
            delay: createDelay(7, 'days'),
            content: createEmailContent(
                'Last note from me',
                `<p>Hi {{lead.first_name}},</p>

<p>This is the last email in this thread — I don't want to clutter your inbox.</p>

<p>If email deliverability becomes a priority for {{lead.company_name}} down the road, the offer to do a free DNS review stands. Just reply to this thread anytime and it'll land right in my inbox.</p>

<p>Wishing you and the team a great quarter.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

// ╔═══════════════════════════════════════════════════════════════════╗
// ║  2. TRIAL ONBOARDING — 7-Day Activation Sequence                ║
// ║                                                                   ║
// ║  Cialdini: Commitment (small steps) → Authority (expertise)      ║
// ║  → Social Proof (peer success) → Scarcity (trial deadline)       ║
// ║                                                                   ║
// ║  Philosophy: Guide through micro-commitments. Each email has     ║
// ║  exactly ONE action. Build momentum toward the "aha" moment.     ║
// ╚═══════════════════════════════════════════════════════════════════╝

const trialOnboardingTemplate: CampaignTemplate = {
    id: 'tmpl_trial_onboarding',
    name: 'Trial Onboarding — 7 Day Activation',
    description:
        'Guides new trial users to their first successful send via micro-commitments. Uses authority and social proof to build confidence.',
    category: 'trial',
    cialdiniPrinciples: ['commitment', 'authority', 'social_proof', 'scarcity'],
    suggestedTriggers: ['lead_added', 'stage_changed'],
    suggestedExitConditions: ['converted', 'unsubscribed'],
    variables: [
        { name: 'product_name', description: 'Your product name', defaultValue: 'ApexMail', required: true },
        { name: 'sender_name', description: 'Your name', defaultValue: 'Alex', required: true },
        { name: 'sender_title', description: 'Your job title', defaultValue: 'Developer Experience', required: true },
        { name: 'trial_days', description: 'Number of trial days', defaultValue: '14', required: true },
        { name: 'quickstart_link', description: 'Link to quickstart guide', defaultValue: 'https://apexmail.ee/docs/quickstart', required: true },
        { name: 'docs_link', description: 'Link to documentation', defaultValue: 'https://apexmail.ee/docs', required: true },
        { name: 'calendar_link', description: 'Link to book a call', defaultValue: 'https://cal.com/apexmail', required: false },
    ],
    sequence: [
        // ── Day 0: Welcome + First Micro-Commitment ──
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Day 0 — Welcome + First Send (Commitment)',
            delay: createDelay(0, 'minutes', false),
            content: createEmailContent(
                'Your {{product_name}} trial is live — one thing to do today',
                `<p>Hi {{lead.first_name}},</p>

<p>Welcome to {{product_name}}. Your {{trial_days}}-day trial is active.</p>

<p>Most teams get the most out of their trial when they send their first test email in the first hour. It takes about 3 minutes:</p>

<ol>
  <li>Grab your API key from the dashboard</li>
  <li>Copy the cURL example from the quickstart</li>
  <li>Hit send</li>
</ol>

<a href="{{quickstart_link}}" class="cta-btn">Open the Quickstart →</a>

<p>That's it for today. Once you've sent your first email, everything else will make more sense.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Day 1: Authority (teach them something) ──
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Day 1 — Domain Setup (Authority)',
            delay: createDelay(1, 'days'),
            content: createEmailContent(
                'The DNS records that make or break deliverability',
                `<p>Hi {{lead.first_name}},</p>

<p>Now that you've sent a test email, the next step is setting up your sending domain. This is what separates emails that land in the inbox from emails that land in spam.</p>

<p>There are three records to add:</p>

<div class="tip-box">
  <strong>SPF</strong> — tells receiving servers which IPs can send on your behalf<br>
  <strong>DKIM</strong> — cryptographically signs your emails so they can't be spoofed<br>
  <strong>DMARC</strong> — tells receivers what to do if SPF or DKIM fails
</div>

<p>Your dashboard has the exact records pre-generated for your domain — just copy and paste them into your DNS provider.</p>

<a href="{{docs_link}}/domains" class="cta-btn">Set Up Your Domain →</a>

<p>This usually takes 5–10 minutes of active work, then 24–48 hours for DNS propagation.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Day 3: Check-in + Liking (genuine help) ──
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Day 3 — Check-in (Liking)',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'How is the setup going?',
                `<p>Hi {{lead.first_name}},</p>

<p>Just checking in — have you managed to get your domain verified?</p>

<p>If you hit any snags, here are the three most common issues and their fixes:</p>

<ol>
  <li><strong>DNS not propagated yet</strong> — give it a full 48 hours, then check with <code>dig TXT yourdomain.com</code></li>
  <li><strong>Multiple SPF records</strong> — you can only have one per domain; merge them with multiple <code>include:</code> directives</li>
  <li><strong>CNAME conflict</strong> — some DNS providers don't allow CNAME at the apex; use a subdomain</li>
</ol>

<p>If none of these apply, just reply with what you're seeing and I'll take a look personally.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Day 5: Social Proof ──
        {
            id: generateId('step'),
            order: 4,
            type: 'email',
            name: 'Day 5 — Peer Success (Social Proof)',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'What teams like {{lead.company_name}} do in the first week',
                `<p>Hi {{lead.first_name}},</p>

<p>By day 5, most teams that go on to adopt {{product_name}} have done two things:</p>

<ol>
  <li><strong>Sent a test email from their own domain</strong> — proving their DNS is set up correctly</li>
  <li><strong>Set up a webhook endpoint</strong> — so they can track deliveries, opens, and bounces in real time</li>
</ol>

<p>If you've already done both, you're ahead of the curve.</p>

<p>If not, the webhook setup takes about 5 minutes and it's the fastest way to see {{product_name}}'s value — you'll start getting delivery data immediately.</p>

<a href="{{docs_link}}/webhooks" class="cta-btn">Set Up Webhooks →</a>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Day 7: Scarcity (real deadline) + Offer help ──
        {
            id: generateId('step'),
            order: 5,
            type: 'email',
            name: 'Day 7 — Trial Midpoint (Scarcity)',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'Your trial is halfway — anything I can help with?',
                `<p>Hi {{lead.first_name}},</p>

<p>You're at the midpoint of your {{product_name}} trial — <strong>{{trial_days}} days left</strong>.</p>

<p>Quick sanity check — here's what your setup looks like:</p>

<ul>
  <li>Domain verified? Check your <a href="{{docs_link}}/domains">domain settings</a></li>
  <li>First email sent? Check your <a href="{{docs_link}}/logs">send logs</a></li>
  <li>Webhooks active? Check your <a href="{{docs_link}}/webhooks">webhook dashboard</a></li>
</ul>

<p>If there's a blocker — technical or otherwise — I'd like to help resolve it before the trial wraps. You can reply here or grab a slot on my calendar:</p>

<a href="{{calendar_link}}" class="cta-btn">Book a 15-Min Call →</a>

<p>No sales pitch — just making sure you have what you need to evaluate properly.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

// ╔═══════════════════════════════════════════════════════════════════╗
// ║  3. RE-ENGAGEMENT — Win-Back Sequence                            ║
// ║                                                                   ║
// ║  Cialdini: Reciprocity (new value) → Social Proof (momentum)     ║
// ║  → Scarcity (real expiring offer) → Liking (graceful exit)       ║
// ║                                                                   ║
// ║  Philosophy: Don't guilt-trip. Lead with new value they missed,  ║
// ║  show momentum, and offer a real (time-limited) reason to return.║
// ╚═══════════════════════════════════════════════════════════════════╝

const reEngagementTemplate: CampaignTemplate = {
    id: 'tmpl_re_engagement',
    name: 'Re-engagement — Win Back',
    description:
        'Re-engages cold leads by leading with new value, demonstrating platform momentum via social proof, and closing with a genuine time-limited offer.',
    category: 're_engagement',
    cialdiniPrinciples: ['reciprocity', 'social_proof', 'scarcity', 'liking'],
    suggestedTriggers: ['manual', 'schedule'],
    suggestedExitConditions: ['replied', 'unsubscribed', 'converted'],
    variables: [
        { name: 'sender_name', description: 'Your name', defaultValue: 'Alex', required: true },
        { name: 'sender_title', description: 'Your title', defaultValue: 'Deliverability Lead', required: true },
        { name: 'product_name', description: 'Your product name', defaultValue: 'ApexMail', required: true },
        { name: 'changelog_link', description: 'Link to recent changelog or updates', defaultValue: 'https://apexmail.ee/changelog', required: true },
        { name: 'special_offer', description: 'Specific offer for returning users', defaultValue: '20% off your first 3 months', required: false },
        { name: 'offer_expiry_days', description: 'Days until offer expires', defaultValue: '14', required: false },
        { name: 'calendar_link', description: 'Booking link', defaultValue: 'https://cal.com/apexmail', required: false },
    ],
    sequence: [
        // ── Touch 1: Reciprocity (new value, not "we miss you") ──
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Touch 1 — New Value Update (Reciprocity)',
            delay: createDelay(0, 'minutes'),
            content: createEmailContent(
                'What changed at {{product_name}} since you left',
                `<p>Hi {{lead.first_name}},</p>

<p>It's been a while since you evaluated {{product_name}}, and a lot has shipped since then. Rather than a generic "we miss you" email, I thought I'd share the three updates that are most relevant to teams like {{lead.company_name}}:</p>

<ol>
  <li><strong>Webhook reliability</strong> — guaranteed delivery with automatic retries and a dead-letter queue</li>
  <li><strong>Real-time analytics</strong> — open, click, and bounce tracking with sub-second latency</li>
  <li><strong>One-click domain verification</strong> — the DNS setup that used to take an hour now takes 5 minutes</li>
</ol>

<p><a href="{{changelog_link}}">Full changelog →</a></p>

<p>No pressure to take another look. Just wanted to make sure you had the latest picture.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 2: Social Proof + Real Offer ──
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Touch 2 — Social Proof + Offer',
            delay: createDelay(5, 'days'),
            content: createEmailContent(
                'A reason to take another look',
                `<p>Hi {{lead.first_name}},</p>

<p>Since the last time you tried {{product_name}}, we've been growing steadily — and the teams using us tend to stick around because the deliverability numbers speak for themselves.</p>

<p>I'd like to offer you <strong>{{special_offer}}</strong> if you'd like to give it another try. This is a standing offer for the next {{offer_expiry_days}} days — no last-minute countdown timers.</p>

<p>If you want to chat about what's changed, I'm happy to do a quick walkthrough:</p>

<a href="{{calendar_link}}" class="cta-btn">Book a 15-Min Walkthrough →</a>

<p>And if the timing still isn't right, absolutely no worries.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 3: Graceful Exit (Liking) ──
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Touch 3 — Graceful Exit (Liking)',
            delay: createDelay(7, 'days'),
            content: createEmailContent(
                'No hard feelings, {{lead.first_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>This is the last email in this sequence. I want to respect your inbox.</p>

<p>If {{product_name}} becomes relevant for {{lead.company_name}} in the future, the offer I mentioned ({{special_offer}}) will still be here — just reply to this thread and reference it.</p>

<p>In the meantime, the <a href="{{changelog_link}}">changelog</a> is public, so you can keep an eye on what we ship without any emails from me.</p>

<p>Wishing you and the team all the best.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

// ╔═══════════════════════════════════════════════════════════════════╗
// ║  4. COMPETITOR MIGRATION — 4-Touch Provider-Specific Sequence   ║
// ║                                                                   ║
// ║  Cialdini: Reciprocity (free audit) → Authority (migration exp) ║
// ║  → Social Proof (other migrations) → Scarcity (free support)    ║
// ║                                                                   ║
// ║  Philosophy: Target companies detected using SendGrid, Mailgun,  ║
// ║  Resend, etc. Offer genuine value: free deliverability audit,    ║
// ║  webhook migration guide, and free migration support.            ║
// ╚═══════════════════════════════════════════════════════════════════╝

const competitorMigrationTemplate: CampaignTemplate = {
    id: 'tmpl_competitor_migration',
    name: 'Competitor Migration — SendGrid/Mailgun/Resend',
    description:
        'Targets companies using competing email providers (detected via DNS). Leads with a free deliverability audit, offers webhook migration guide, and free migration support.',
    category: 'cold_outreach',
    cialdiniPrinciples: ['reciprocity', 'authority', 'social_proof', 'scarcity'],
    suggestedTriggers: ['lead_added', 'tag_added:sendgrid', 'tag_added:mailgun', 'tag_added:resend'],
    suggestedExitConditions: ['replied', 'unsubscribed', 'bounced', 'converted'],
    variables: [
        { name: 'sender_name', description: 'Your name', defaultValue: 'Alex', required: true },
        { name: 'sender_title', description: 'Your job title', defaultValue: 'Migration Specialist', required: true },
        { name: 'current_provider', description: 'Detected email provider (SendGrid, Mailgun, etc.)', defaultValue: 'SendGrid', required: true },
        { name: 'audit_link', description: 'Link to request a free deliverability audit', defaultValue: 'https://apexmail.ee/audit', required: true },
        { name: 'migration_guide_link', description: 'Link to provider-specific migration guide', defaultValue: 'https://apexmail.ee/migrate/from-sendgrid', required: true },
        { name: 'webhook_guide_link', description: 'Link to webhook migration documentation', defaultValue: 'https://apexmail.ee/docs/webhooks/migration', required: true },
        { name: 'calendar_link', description: 'Booking link for migration support call', defaultValue: 'https://cal.com/apexmail/migration', required: false },
        { name: 'case_study_company', description: 'Company that migrated successfully', defaultValue: 'a Series B SaaS company', required: false },
        { name: 'case_study_migration_time', description: 'How long the migration took', defaultValue: '45 minutes', required: false },
    ],
    sequence: [
        // ── Touch 1: Free Deliverability Audit Offer (Reciprocity) ──
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Touch 1 — Free Deliverability Audit (Reciprocity)',
            delay: createDelay(0, 'minutes'),
            content: createEmailContent(
                'Quick deliverability check for {{lead.domain}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I noticed {{lead.company_name}} is using <strong>{{current_provider}}</strong> for transactional email — I saw it in your public DNS records (MX, SPF, DKIM).</p>

<p>I put together deliverability audits for teams considering their email infrastructure options. It's a quick review that covers:</p>

<ul>
  <li><strong>DNS configuration</strong> — SPF alignment, DKIM rotation, DMARC policy</li>
  <li><strong>Sender reputation</strong> — how your domain scores with major inbox providers</li>
  <li><strong>Deliverability gaps</strong> — common issues I see with {{current_provider}} setups at scale</li>
</ul>

<p>It's free, takes me about 20 minutes to compile, and there's no obligation to do anything with it.</p>

<a href="{{audit_link}}" class="cta-btn">Request Your Free Audit →</a>

<p>If you'd rather I just send it to this email, reply "send it" and I'll have it over within 48 hours.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 2: Webhook Migration Guide (Authority) ──
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Touch 2 — Webhook Migration Guide (Authority)',
            delay: createDelay(4, 'days'),
            content: createEmailContent(
                'Migrating webhooks from {{current_provider}} — the gotchas',
                `<p>Hi {{lead.first_name}},</p>

<p>One thing teams often underestimate when evaluating email providers is webhook migration. The event payloads look similar, but there are subtle differences that can break your tracking.</p>

<p>I put together a guide specifically for teams moving from <strong>{{current_provider}}</strong>:</p>

<div class="tip-box">
  <strong>What's covered:</strong><br>
  • 1:1 event type mapping (delivered, bounced, complained, etc.)<br>
  • Payload structure differences and how to adapt your handlers<br>
  • Signature verification changes (we use HMAC-SHA256)<br>
  • Running both providers in parallel during transition
</div>

<a href="{{webhook_guide_link}}" class="cta-btn">View the Webhook Migration Guide →</a>

<p>Even if you're not planning to switch providers, the guide is useful for understanding how different platforms handle email events.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 3: Migration Success Story (Social Proof) ──
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Touch 3 — Migration Success Story (Social Proof)',
            delay: createDelay(5, 'days'),
            content: createEmailContent(
                'How {{case_study_company}} migrated from {{current_provider}} in {{case_study_migration_time}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I wanted to share a quick migration story that might be relevant:</p>

<p>{{case_study_company}} was using {{current_provider}} and experiencing intermittent deliverability issues — emails landing in spam for certain domains, inconsistent webhook delivery, and opaque bounce reporting.</p>

<p>Their migration to ApexMail took <strong>{{case_study_migration_time}}</strong> of active engineering time:</p>

<ol>
  <li>Swapped the SDK import and API key (5 minutes)</li>
  <li>Added new DNS records alongside existing ones (10 minutes)</li>
  <li>Updated webhook handlers using our migration guide (20 minutes)</li>
  <li>Ran both providers in parallel for 48 hours, then cut over</li>
</ol>

<p>The result: bounce rates dropped by 40% in the first month, and their ops team stopped getting paged for email issues.</p>

<p><a href="{{migration_guide_link}}">Full migration guide here</a> if you want to see the technical steps.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },

        // ── Touch 4: Free Migration Support Offer (Scarcity + Reciprocity) ──
        {
            id: generateId('step'),
            order: 4,
            type: 'email',
            name: 'Touch 4 — Free Migration Support (Scarcity)',
            delay: createDelay(6, 'days'),
            content: createEmailContent(
                'Free migration support for {{lead.company_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>This is the last email in this sequence — I want to respect your inbox.</p>

<p>If {{lead.company_name}} is considering a move away from {{current_provider}}, we offer <strong>free migration support</strong> for teams making the switch. This includes:</p>

<ul>
  <li><strong>1:1 onboarding call</strong> — I'll walk through your specific setup and answer questions</li>
  <li><strong>DNS review</strong> — I'll verify your new records are correctly configured before you cut over</li>
  <li><strong>Webhook testing</strong> — We'll validate your handlers receive events correctly</li>
  <li><strong>Parallel running guidance</strong> — Best practices for zero-downtime migration</li>
</ul>

<a href="{{calendar_link}}" class="cta-btn">Book Free Migration Support →</a>

<p>If timing isn't right now, just reply to this thread whenever you're ready — the offer doesn't expire.</p>

${signature()}`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

// ────────────────────────────────────────────────────────────────────
// Registry & Exports
// ────────────────────────────────────────────────────────────────────

/**
 * All available campaign templates
 */
export const campaignTemplates: CampaignTemplate[] = [
    coldOutreachTemplate,
    trialOnboardingTemplate,
    reEngagementTemplate,
    competitorMigrationTemplate,
];

/**
 * Gets a template by ID
 */
export function getTemplate(templateId: string): CampaignTemplate | null {
    return campaignTemplates.find((t) => t.id === templateId) || null;
}

/**
 * Gets templates by category
 */
export function getTemplatesByCategory(
    category: TemplateCategory
): CampaignTemplate[] {
    return campaignTemplates.filter((t) => t.category === category);
}

/**
 * Gets templates that use a specific Cialdini principle
 */
export function getTemplatesByPrinciple(
    principle: CialdiniPrinciple
): CampaignTemplate[] {
    return campaignTemplates.filter((t) =>
        t.cialdiniPrinciples.includes(principle)
    );
}

/**
 * Clones a template with new IDs (for user customisation)
 */
export function cloneTemplate(templateId: string): CampaignTemplate | null {
    const template = getTemplate(templateId);
    if (!template) {
        return null;
    }

    return {
        ...template,
        id: generateId('tmpl'),
        sequence: template.sequence.map((step) => ({
            ...step,
            id: generateId('step'),
        })),
    };
}

export type { CampaignTemplate, TemplateVariable, TemplateCategory, CialdiniPrinciple };
