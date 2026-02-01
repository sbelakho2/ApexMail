/**
 * Campaign Templates Library
 * Pre-built drip campaign templates for common use cases
 */

import { generateId } from '@apexmail/lib';
import type { DripSequenceStep, StepDelay, StepContent } from '../types.js';

interface CampaignTemplate {
    id: string;
    name: string;
    description: string;
    category: TemplateCategory;
    sequence: DripSequenceStep[];
    suggestedTriggers: string[];
    suggestedExitConditions: string[];
    variables: TemplateVariable[];
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

function createDelay(
    value: number,
    unit: StepDelay['unit'],
    businessHoursOnly = true
): StepDelay {
    return {
        value,
        unit,
        businessHoursOnly,
        jitterMinutes: 5,
    };
}

function createEmailContent(
    subject: string,
    body: string,
    variables: Record<string, string> = {}
): StepContent {
    return {
        subject,
        htmlBody: body,
        textBody: body.replace(/<[^>]*>/g, ''),
        templateId: null,
        variables,
    };
}

/**
 * Cold Outreach Template - 5-touch sequence
 */
const coldOutreachTemplate: CampaignTemplate = {
    id: 'tmpl_cold_outreach_5',
    name: 'Cold Outreach - 5 Touch',
    description: 'A proven 5-email cold outreach sequence for B2B sales',
    category: 'cold_outreach',
    suggestedTriggers: ['lead_added', 'tag_added'],
    suggestedExitConditions: ['replied', 'unsubscribed', 'bounced'],
    variables: [
        {
            name: 'sender_name',
            description: 'Your name',
            defaultValue: 'John',
            required: true,
        },
        {
            name: 'company_value_prop',
            description: 'Your company value proposition',
            defaultValue: 'help companies increase email deliverability',
            required: true,
        },
        {
            name: 'case_study_link',
            description: 'Link to a case study',
            defaultValue: 'https://example.com/case-study',
            required: false,
        },
    ],
    sequence: [
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Initial Outreach',
            delay: createDelay(0, 'minutes'),
            content: createEmailContent(
                'Quick question about {{lead.company_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I noticed {{lead.company_name}} is growing quickly. Congrats on the momentum!</p>

<p>I'm reaching out because we {{company_value_prop}}. Given your growth, I thought this might be relevant.</p>

<p>Would you be open to a quick 15-minute chat to see if there's a fit?</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Value Add Follow-up',
            delay: createDelay(3, 'days'),
            content: createEmailContent(
                'Thought you might find this useful',
                `<p>Hi {{lead.first_name}},</p>

<p>Following up on my previous email. I wanted to share a quick tip that might help {{lead.company_name}}:</p>

<p>[Insert relevant industry tip or insight]</p>

<p>Let me know if you'd like to discuss how this applies to your situation.</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Social Proof',
            delay: createDelay(4, 'days'),
            content: createEmailContent(
                'How [Similar Company] achieved [Result]',
                `<p>Hi {{lead.first_name}},</p>

<p>I wanted to share a quick success story that might resonate with {{lead.company_name}}.</p>

<p>[Similar company in their industry] was facing [common challenge]. After working with us, they achieved [specific result].</p>

<p>Here's the full case study if you're interested: {{case_study_link}}</p>

<p>Would love to explore if we can help you achieve similar results.</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 4,
            type: 'email',
            name: 'Breakup Warning',
            delay: createDelay(5, 'days'),
            content: createEmailContent(
                'Should I close your file?',
                `<p>Hi {{lead.first_name}},</p>

<p>I've reached out a few times and haven't heard back. I completely understand if the timing isn't right or this isn't a priority.</p>

<p>If you're not interested, just let me know and I'll close out your file. No hard feelings!</p>

<p>But if you're just busy and this is still on your radar, I'd love to find a time that works better.</p>

<p>Either way, wishing you and {{lead.company_name}} continued success!</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 5,
            type: 'email',
            name: 'Final Breakup',
            delay: createDelay(7, 'days'),
            content: createEmailContent(
                'Closing the loop',
                `<p>Hi {{lead.first_name}},</p>

<p>This will be my last email. I don't want to be a pest!</p>

<p>If anything changes in the future, feel free to reach out. I'm always happy to help.</p>

<p>Best of luck with everything at {{lead.company_name}}!</p>

<p>Cheers,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

/**
 * Trial Onboarding Template
 */
const trialOnboardingTemplate: CampaignTemplate = {
    id: 'tmpl_trial_onboarding',
    name: 'Trial Onboarding - 7 Day',
    description: 'Welcome and guide new trial users through your product',
    category: 'trial',
    suggestedTriggers: ['lead_added', 'stage_changed'],
    suggestedExitConditions: ['converted', 'unsubscribed'],
    variables: [
        {
            name: 'product_name',
            description: 'Your product name',
            defaultValue: 'ApexMail',
            required: true,
        },
        {
            name: 'trial_days',
            description: 'Number of trial days',
            defaultValue: '14',
            required: true,
        },
        {
            name: 'getting_started_link',
            description: 'Link to getting started guide',
            defaultValue: 'https://example.com/getting-started',
            required: true,
        },
    ],
    sequence: [
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'Welcome Email',
            delay: createDelay(0, 'minutes', false),
            content: createEmailContent(
                'Welcome to {{product_name}}! 🎉',
                `<p>Hi {{lead.first_name}},</p>

<p>Welcome to {{product_name}}! We're thrilled to have you.</p>

<p>Your {{trial_days}}-day free trial starts now. Here's what you can do to get the most out of it:</p>

<ol>
  <li><strong>Set up your first project</strong> - Takes about 5 minutes</li>
  <li><strong>Invite your team</strong> - Collaborate from day one</li>
  <li><strong>Explore our templates</strong> - Get started faster</li>
</ol>

<p>👉 <a href="{{getting_started_link}}">Get Started Guide</a></p>

<p>Need help? Just reply to this email - I'm here to assist!</p>

<p>Best,<br>{{sender_name}}</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Day 1 - Feature Highlight',
            delay: createDelay(1, 'days'),
            content: createEmailContent(
                'Did you know {{product_name}} can do this?',
                `<p>Hi {{lead.first_name}},</p>

<p>One feature our users love most is [Key Feature].</p>

<p>Here's how it works:</p>

<p>[Brief explanation with screenshot or gif]</p>

<p>Try it out and let me know what you think!</p>

<p>Best,<br>{{sender_name}}</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Day 3 - Check-in',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'How\'s it going with {{product_name}}?',
                `<p>Hi {{lead.first_name}},</p>

<p>You've been using {{product_name}} for a few days now. How's everything going?</p>

<p>I'd love to hear:</p>
<ul>
  <li>What's working well for you?</li>
  <li>Any challenges or questions?</li>
  <li>Features you wish we had?</li>
</ul>

<p>Just hit reply - I read every response personally.</p>

<p>Best,<br>{{sender_name}}</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 4,
            type: 'email',
            name: 'Day 5 - Success Story',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'How [Customer] saves 10 hours/week with {{product_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I wanted to share how one of our customers is using {{product_name}}:</p>

<p>[Customer story with specific results]</p>

<p>Want to achieve similar results? Let's hop on a quick call to optimize your setup.</p>

<p>📅 <a href="[calendar_link]">Book a 15-min call</a></p>

<p>Best,<br>{{sender_name}}</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 5,
            type: 'email',
            name: 'Day 7 - Trial Reminder',
            delay: createDelay(2, 'days'),
            content: createEmailContent(
                'Your {{product_name}} trial: 7 days left',
                `<p>Hi {{lead.first_name}},</p>

<p>Quick heads up - you have 7 days left in your {{product_name}} trial.</p>

<p>Before it ends, I want to make sure you've:</p>
<ul>
  <li>✅ Set up your workspace</li>
  <li>✅ Tried our core features</li>
  <li>✅ Invited team members</li>
</ul>

<p>Questions about upgrading? I'm happy to help you find the right plan for {{lead.company_name}}.</p>

<p>Best,<br>{{sender_name}}</p>`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

/**
 * Re-engagement Template
 */
const reEngagementTemplate: CampaignTemplate = {
    id: 'tmpl_re_engagement',
    name: 'Re-engagement - Win Back',
    description: 'Re-engage leads who have gone cold',
    category: 're_engagement',
    suggestedTriggers: ['manual', 'schedule'],
    suggestedExitConditions: ['replied', 'unsubscribed', 'converted'],
    variables: [
        {
            name: 'special_offer',
            description: 'Special offer for returning leads',
            defaultValue: '20% off your first month',
            required: false,
        },
    ],
    sequence: [
        {
            id: generateId('step'),
            order: 1,
            type: 'email',
            name: 'We Miss You',
            delay: createDelay(0, 'minutes'),
            content: createEmailContent(
                'It\'s been a while, {{lead.first_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>It's been a while since we last connected, and I wanted to check in.</p>

<p>A lot has changed at {{product_name}} since then:</p>
<ul>
  <li>[New Feature 1]</li>
  <li>[New Feature 2]</li>
  <li>[Improvement]</li>
</ul>

<p>Would you be interested in taking another look?</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 2,
            type: 'email',
            name: 'Special Offer',
            delay: createDelay(5, 'days'),
            content: createEmailContent(
                'A special offer for {{lead.company_name}}',
                `<p>Hi {{lead.first_name}},</p>

<p>I wanted to offer you something special: {{special_offer}}</p>

<p>This is exclusively for past contacts like yourself who we'd love to welcome back.</p>

<p>Interested? Just reply and I'll set it up for you.</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
        {
            id: generateId('step'),
            order: 3,
            type: 'email',
            name: 'Final Touch',
            delay: createDelay(7, 'days'),
            content: createEmailContent(
                'Last chance: {{special_offer}}',
                `<p>Hi {{lead.first_name}},</p>

<p>This is a quick reminder that our special offer ({{special_offer}}) expires soon.</p>

<p>If the timing still isn't right, no worries at all. I'll keep you on our list for future updates unless you'd prefer otherwise.</p>

<p>Wishing you all the best!</p>

<p>Best,<br>{{sender_name}}</p>

<p style="font-size: 11px; color: #666;">
<a href="{{unsubscribe_link}}">Unsubscribe</a>
</p>`
            ),
            conditions: [],
            abTest: null,
        },
    ],
};

/**
 * All available templates
 */
export const campaignTemplates: CampaignTemplate[] = [
    coldOutreachTemplate,
    trialOnboardingTemplate,
    reEngagementTemplate,
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
 * Clones a template with new IDs
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
