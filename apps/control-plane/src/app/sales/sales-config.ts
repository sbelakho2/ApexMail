// ─── Improvement #1: Rich type system with contact info, deal values, engagement tracking ───

export interface DiscoverySource {
    id: 'product_hunt' | 'g2' | 'capterra' | 'crunchbase' | 'linkedin' | 'builtwith' | 'apollo' | 'clearbit';
    name: string;
    icon: string;
    enabled: boolean;
    description: string;
    tier: 'free' | 'premium';
    avgLeadsPerRun: number;
}

// ─── Improvement #2: Leads now have contact info, deal values, engagement history ───

export interface DiscoveredLead {
    id: string;
    companyName: string;
    domain: string;
    source: string;
    category: string;
    description: string;
    foundAt: string;
    emailProvider: string | null;
    mxRecords: string[];
    score: number;
    status: LeadStatus;
    tags: string[];
    contactEmail: string | null;
    contactName: string | null;
    contactTitle: string | null;
    companySize: CompanySize | null;
    estimatedDealValue: number | null;
    lastContactedAt: string | null;
    nextFollowUpAt: string | null;
    engagementHistory: EngagementEvent[];
    notes: string;
    assignedTo: string | null;
    icpFit: ICPFitScore;
    linkedinUrl: string | null;
    websiteTraffic: 'low' | 'medium' | 'high' | null;
}

// ─── Improvement #3: Granular lead statuses with full lifecycle ───

export type LeadStatus =
    | 'new'
    | 'enriching'
    | 'contacted'
    | 'opened'
    | 'replied'
    | 'qualified'
    | 'demo_scheduled'
    | 'proposal_sent'
    | 'negotiation'
    | 'nurturing'
    | 'closed_won'
    | 'closed_lost'
    | 'unsubscribed'
    | 'do_not_contact';

export const LEAD_STATUS_CONFIG: Record<LeadStatus, { label: string; color: string; icon: string; order: number }> = {
    new: { label: 'New', color: 'text-blue-600 bg-blue-500/10 border-blue-500/20', icon: '⬤', order: 0 },
    enriching: { label: 'Enriching', color: 'text-purple-600 bg-purple-500/10 border-purple-500/20', icon: '🔄', order: 1 },
    contacted: { label: 'Contacted', color: 'text-amber-600 bg-amber-500/10 border-amber-500/20', icon: '📤', order: 2 },
    opened: { label: 'Opened', color: 'text-orange-600 bg-orange-500/10 border-orange-500/20', icon: '👁', order: 3 },
    replied: { label: 'Replied', color: 'text-teal-600 bg-teal-500/10 border-teal-500/20', icon: '💬', order: 4 },
    qualified: { label: 'Qualified', color: 'text-emerald-600 bg-emerald-500/10 border-emerald-500/20', icon: '✓', order: 5 },
    demo_scheduled: { label: 'Demo Scheduled', color: 'text-indigo-600 bg-indigo-500/10 border-indigo-500/20', icon: '📅', order: 6 },
    proposal_sent: { label: 'Proposal Sent', color: 'text-sky-600 bg-sky-500/10 border-sky-500/20', icon: '📋', order: 7 },
    negotiation: { label: 'Negotiation', color: 'text-yellow-600 bg-yellow-500/10 border-yellow-500/20', icon: '🤝', order: 8 },
    nurturing: { label: 'Nurturing', color: 'text-violet-600 bg-violet-500/10 border-violet-500/20', icon: '🌱', order: 9 },
    closed_won: { label: 'Closed Won', color: 'text-green-700 bg-green-500/10 border-green-500/20', icon: '🏆', order: 10 },
    closed_lost: { label: 'Closed Lost', color: 'text-red-600 bg-red-500/10 border-red-500/20', icon: '✗', order: 11 },
    unsubscribed: { label: 'Unsubscribed', color: 'text-gray-500 bg-gray-500/10 border-gray-500/20', icon: '🚫', order: 12 },
    do_not_contact: { label: 'Do Not Contact', color: 'text-red-800 bg-red-700/10 border-red-700/20', icon: '⛔', order: 13 },
};

// ─── Improvement #4: Engagement event tracking ───

export interface EngagementEvent {
    type: 'email_sent' | 'email_opened' | 'email_clicked' | 'email_replied' | 'call' | 'meeting' | 'note' | 'status_change';
    timestamp: string;
    detail: string;
    actor: string;
}

// ─── Improvement #5: ICP fit scoring ───

export type ICPFitScore = 'excellent' | 'good' | 'moderate' | 'poor' | 'unscored';

export const ICP_FIT_CONFIG: Record<ICPFitScore, { label: string; color: string; minScore: number }> = {
    excellent: { label: 'Excellent Fit', color: 'text-green-700 bg-green-100 border-green-200', minScore: 85 },
    good: { label: 'Good Fit', color: 'text-emerald-600 bg-emerald-50 border-emerald-200', minScore: 70 },
    moderate: { label: 'Moderate Fit', color: 'text-amber-600 bg-amber-50 border-amber-200', minScore: 50 },
    poor: { label: 'Poor Fit', color: 'text-red-600 bg-red-50 border-red-200', minScore: 0 },
    unscored: { label: 'Unscored', color: 'text-gray-500 bg-gray-50 border-gray-200', minScore: -1 },
};

// ─── Improvement #6: Company size enum ───

export type CompanySize = '1-10' | '11-50' | '51-200' | '201-500' | '501-1000' | '1000+';

export const COMPANY_SIZE_OPTIONS: { value: CompanySize; label: string; dealMultiplier: number }[] = [
    { value: '1-10', label: '1-10 employees', dealMultiplier: 0.5 },
    { value: '11-50', label: '11-50 employees', dealMultiplier: 1 },
    { value: '51-200', label: '51-200 employees', dealMultiplier: 2.5 },
    { value: '201-500', label: '201-500 employees', dealMultiplier: 5 },
    { value: '501-1000', label: '501-1,000 employees', dealMultiplier: 10 },
    { value: '1000+', label: '1,000+ employees', dealMultiplier: 20 },
];

// ─── Improvement #7: Outreach offers with distinct templates & sequences ───

export interface OutreachOffer {
    id: string;
    name: string;
    description: string;
    icon: string;
    templateId: string;
    sequenceLength: number;
    expectedConversionRate: number;
    bestFor: string[];
}

export interface DiscoveryStats {
    totalScraped: number;
    totalWithMx: number;
    byProvider: Record<string, number>;
    bySource: Record<string, number>;
    avgScore: number;
    topCategories: Array<{ name: string; count: number }>;
    discoveryDuration: number;
    lastRunAt: string | null;
}

// ─── Improvement #8: 8 discovery sources (doubled from 4) ───

export const DISCOVERY_SOURCES: DiscoverySource[] = [
    { id: 'product_hunt', name: 'Product Hunt', icon: '🚀', enabled: true, description: 'New SaaS launches and trending products', tier: 'free', avgLeadsPerRun: 25 },
    { id: 'g2', name: 'G2 Crowd', icon: '⭐', enabled: true, description: 'Enterprise software reviews and comparisons', tier: 'free', avgLeadsPerRun: 40 },
    { id: 'capterra', name: 'Capterra', icon: '📊', enabled: true, description: 'Business software directory and reviews', tier: 'free', avgLeadsPerRun: 35 },
    { id: 'crunchbase', name: 'Crunchbase', icon: '💼', enabled: true, description: 'Startup and company funding data', tier: 'free', avgLeadsPerRun: 30 },
    { id: 'linkedin', name: 'LinkedIn Sales Nav', icon: '👔', enabled: false, description: 'Professional network company search', tier: 'premium', avgLeadsPerRun: 50 },
    { id: 'builtwith', name: 'BuiltWith', icon: '🔧', enabled: false, description: 'Technology usage tracking across websites', tier: 'premium', avgLeadsPerRun: 60 },
    { id: 'apollo', name: 'Apollo.io', icon: '🎯', enabled: false, description: 'Contact & company enrichment platform', tier: 'premium', avgLeadsPerRun: 45 },
    { id: 'clearbit', name: 'Clearbit', icon: '🔮', enabled: false, description: 'Business intelligence and enrichment API', tier: 'premium', avgLeadsPerRun: 55 },
];

// ─── Improvement #9: Expanded target categories ───

export const TARGET_CATEGORIES = [
    'Email Marketing',
    'Marketing Automation',
    'CRM Software',
    'Sales Enablement',
    'Customer Success',
    'Newsletter Platforms',
    'Transactional Email',
    'E-commerce',
    'SaaS',
    'Developer Tools',
    'FinTech',
    'HealthTech',
    'EdTech',
    'B2B Marketplaces',
    'Logistics & Supply Chain',
];

// ─── Improvement #10: Expanded competitor list with migration details ───

export const COMPETITOR_PROVIDERS = [
    'SendGrid',
    'Mailgun',
    'Resend',
    'Postmark',
    'Mailchimp/Mandrill',
    'SparkPost',
    'Amazon SES',
    'Brevo (Sendinblue)',
    'Customer.io',
    'Mailjet',
];

export const COMPETITOR_DETAILS: Record<string, {
    weaknesses: string[];
    migrationComplexity: 'easy' | 'medium' | 'hard';
    avgMigrationDays: number;
}> = {
    'SendGrid': { weaknesses: ['Deliverability degraded in shared pools', 'Limited analytics', 'Slow support'], migrationComplexity: 'easy', avgMigrationDays: 3 },
    'Mailgun': { weaknesses: ['Pricing spikes at scale', 'Limited template system', 'EU compliance gaps'], migrationComplexity: 'easy', avgMigrationDays: 2 },
    'Resend': { weaknesses: ['Early-stage feature gaps', 'No native SMTP relay', 'Limited integrations'], migrationComplexity: 'easy', avgMigrationDays: 1 },
    'Postmark': { weaknesses: ['Marketing email restrictions', 'Higher per-message cost', 'Limited automation'], migrationComplexity: 'medium', avgMigrationDays: 3 },
    'Mailchimp/Mandrill': { weaknesses: ['Separate transactional service', 'Complex pricing', 'API limitations'], migrationComplexity: 'medium', avgMigrationDays: 5 },
    'SparkPost': { weaknesses: ['Complex setup', 'Limited free tier', 'Enterprise-focused pricing'], migrationComplexity: 'medium', avgMigrationDays: 4 },
    'Amazon SES': { weaknesses: ['No UI/dashboard', 'Requires DevOps knowledge', 'Bare-bones analytics'], migrationComplexity: 'hard', avgMigrationDays: 7 },
    'Brevo (Sendinblue)': { weaknesses: ['Daily sending limits', 'Template quality', 'Deliverability variance'], migrationComplexity: 'easy', avgMigrationDays: 2 },
    'Customer.io': { weaknesses: ['Expensive at scale', 'Complex workflows', 'Limited transactional support'], migrationComplexity: 'medium', avgMigrationDays: 4 },
    'Mailjet': { weaknesses: ['Basic analytics', 'Template editor limitations', 'Slower support tiers'], migrationComplexity: 'easy', avgMigrationDays: 2 },
};

// ─── Improvement #11: 6 distinct outreach offers with unique templates ───

export const OUTREACH_OFFERS: OutreachOffer[] = [
    {
        id: 'deliverability_audit',
        name: 'Free Deliverability Audit',
        description: 'Comprehensive DNS, SPF, DKIM, DMARC, and inbox placement analysis with actionable report',
        icon: '🔍',
        templateId: 'tmpl_deliverability_audit',
        sequenceLength: 3,
        expectedConversionRate: 0.12,
        bestFor: ['Companies with deliverability issues', 'SendGrid users', 'High-volume senders'],
    },
    {
        id: 'webhook_migration',
        name: 'Webhook Migration Guide',
        description: 'Provider-specific webhook mapping with code examples and test suite',
        icon: '🔗',
        templateId: 'tmpl_webhook_migration',
        sequenceLength: 2,
        expectedConversionRate: 0.08,
        bestFor: ['Developer-focused companies', 'Teams with webhook integrations'],
    },
    {
        id: 'free_migration_support',
        name: 'White Glove Migration',
        description: '1:1 onboarding with dedicated engineer — DNS review, webhook testing, rollover plan',
        icon: '🤝',
        templateId: 'tmpl_white_glove_migration',
        sequenceLength: 4,
        expectedConversionRate: 0.18,
        bestFor: ['Enterprise leads', 'Complex setups', 'High deal-value prospects'],
    },
    {
        id: 'cost_comparison',
        name: 'Cost Savings Calculator',
        description: 'Personalized pricing comparison showing projected savings vs current provider',
        icon: '💰',
        templateId: 'tmpl_cost_comparison',
        sequenceLength: 3,
        expectedConversionRate: 0.15,
        bestFor: ['Price-sensitive leads', 'Companies scaling email volume'],
    },
    {
        id: 'security_compliance',
        name: 'Security & Compliance Brief',
        description: 'SOC 2, GDPR, HIPAA compliance comparison with audit-ready documentation',
        icon: '🛡️',
        templateId: 'tmpl_security_compliance',
        sequenceLength: 2,
        expectedConversionRate: 0.10,
        bestFor: ['FinTech', 'HealthTech', 'Regulated industries'],
    },
    {
        id: 'developer_experience',
        name: 'Developer Experience Demo',
        description: 'Interactive sandbox environment showcasing API ergonomics, SDKs, and real-time webhooks',
        icon: '🧑‍💻',
        templateId: 'tmpl_dev_experience',
        sequenceLength: 2,
        expectedConversionRate: 0.14,
        bestFor: ['Developer tools companies', 'API-first businesses', 'Technical founders'],
    },
];

// ─── Improvement #12: Expanded tabs with pipeline, campaigns, and settings ───

export const SALES_TABS = ['discovery', 'leads', 'outreach', 'campaigns', 'pipeline', 'analytics', 'settings'] as const;
export type TabKey = (typeof SALES_TABS)[number];

// ─── Improvement #44: Campaign type definition ───

export interface Campaign {
    id: string;
    name: string;
    offerId: string;
    templateId: string;
    status: 'draft' | 'active' | 'paused' | 'completed' | 'cancelled' | 'archived';
    leads: number;
    metrics: {
        sent: number;
        opened: number;
        clicked: number;
        replied: number;
        bounced: number;
    };
    createdAt: string;
    startedAt: string | null;
    completedAt: string | null;
}

export const CAMPAIGN_STATUS_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
    draft: { label: 'Draft', color: 'text-gray-600 bg-gray-100 border-gray-200', icon: '📝' },
    active: { label: 'Active', color: 'text-green-700 bg-green-100 border-green-200', icon: '▶️' },
    paused: { label: 'Paused', color: 'text-amber-600 bg-amber-100 border-amber-200', icon: '⏸️' },
    completed: { label: 'Completed', color: 'text-blue-600 bg-blue-100 border-blue-200', icon: '✅' },
    cancelled: { label: 'Cancelled', color: 'text-red-600 bg-red-100 border-red-200', icon: '⛔' },
    archived: { label: 'Archived', color: 'text-gray-500 bg-gray-50 border-gray-200', icon: '📦' },
};

// ─── Improvement #13: Sort options for leads ───

export type LeadSortField = 'score' | 'companyName' | 'foundAt' | 'status' | 'estimatedDealValue' | 'lastContactedAt';
export type SortDirection = 'asc' | 'desc';

export interface LeadSortConfig {
    field: LeadSortField;
    direction: SortDirection;
    label: string;
}

export const LEAD_SORT_OPTIONS: LeadSortConfig[] = [
    { field: 'score', direction: 'desc', label: 'Score (High → Low)' },
    { field: 'score', direction: 'asc', label: 'Score (Low → High)' },
    { field: 'foundAt', direction: 'desc', label: 'Newest First' },
    { field: 'foundAt', direction: 'asc', label: 'Oldest First' },
    { field: 'companyName', direction: 'asc', label: 'Company A → Z' },
    { field: 'companyName', direction: 'desc', label: 'Company Z → A' },
    { field: 'estimatedDealValue', direction: 'desc', label: 'Deal Value (High → Low)' },
    { field: 'lastContactedAt', direction: 'desc', label: 'Recently Contacted' },
    { field: 'status', direction: 'asc', label: 'Status (Pipeline Order)' },
];

// ─── Improvement #14: Discovery schedule presets ───

export interface DiscoverySchedule {
    id: string;
    label: string;
    cronExpression: string;
    description: string;
}

export const DISCOVERY_SCHEDULES: DiscoverySchedule[] = [
    { id: 'manual', label: 'Manual Only', cronExpression: '', description: 'Run discovery jobs manually' },
    { id: 'daily', label: 'Daily', cronExpression: '0 9 * * *', description: 'Every day at 9:00 AM' },
    { id: 'weekdays', label: 'Weekdays', cronExpression: '0 9 * * 1-5', description: 'Monday–Friday at 9:00 AM' },
    { id: 'weekly', label: 'Weekly', cronExpression: '0 9 * * 1', description: 'Every Monday at 9:00 AM' },
    { id: 'biweekly', label: 'Bi-weekly', cronExpression: '0 9 1,15 * *', description: '1st and 15th of each month' },
];

// ─── Improvement #15: Lead scoring weights (configurable) ───

export interface ScoringWeights {
    competitorUsage: number;
    companySize: number;
    categoryFit: number;
    websiteTraffic: number;
    recentFunding: number;
    contactAvailability: number;
}

export const DEFAULT_SCORING_WEIGHTS: ScoringWeights = {
    competitorUsage: 30,
    companySize: 20,
    categoryFit: 20,
    websiteTraffic: 10,
    recentFunding: 10,
    contactAvailability: 10,
};

// ─── Improvement #16: Notification types for sales events ───

export type SalesNotificationType = 'lead_discovered' | 'outreach_sent' | 'email_opened' | 'email_replied' | 'demo_booked' | 'deal_won' | 'deal_lost' | 'discovery_complete' | 'error';

export interface SalesNotification {
    id: string;
    type: SalesNotificationType;
    title: string;
    message: string;
    timestamp: string;
    read: boolean;
    leadId?: string;
}

// ─── Enhanced filter function with search, status, ICP filters ───

export function getFilteredLeads(
    leads: DiscoveredLead[],
    providerFilter: string | null,
    searchQuery?: string,
    statusFilter?: LeadStatus | null,
    icpFilter?: ICPFitScore | null,
): DiscoveredLead[] {
    let filtered = leads;

    if (providerFilter) {
        filtered = filtered.filter((lead) => lead.emailProvider === providerFilter);
    }

    if (searchQuery && searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        filtered = filtered.filter((lead) =>
            lead.companyName.toLowerCase().includes(q) ||
            lead.domain.toLowerCase().includes(q) ||
            (lead.contactEmail && lead.contactEmail.toLowerCase().includes(q)) ||
            (lead.contactName && lead.contactName.toLowerCase().includes(q)) ||
            lead.tags.some(t => t.toLowerCase().includes(q))
        );
    }

    if (statusFilter) {
        filtered = filtered.filter((lead) => lead.status === statusFilter);
    }

    if (icpFilter) {
        filtered = filtered.filter((lead) => lead.icpFit === icpFilter);
    }

    return filtered;
}

// ─── Improvement #17: Sort function ───

export function sortLeads(leads: DiscoveredLead[], sortConfig: LeadSortConfig): DiscoveredLead[] {
    const sorted = [...leads].sort((a, b) => {
        let cmp = 0;
        switch (sortConfig.field) {
            case 'score':
                cmp = a.score - b.score;
                break;
            case 'companyName':
                cmp = a.companyName.localeCompare(b.companyName);
                break;
            case 'foundAt':
                cmp = new Date(a.foundAt).getTime() - new Date(b.foundAt).getTime();
                break;
            case 'status':
                cmp = (LEAD_STATUS_CONFIG[a.status]?.order ?? 99) - (LEAD_STATUS_CONFIG[b.status]?.order ?? 99);
                break;
            case 'estimatedDealValue':
                cmp = (a.estimatedDealValue ?? 0) - (b.estimatedDealValue ?? 0);
                break;
            case 'lastContactedAt': {
                const aDate = a.lastContactedAt ? new Date(a.lastContactedAt).getTime() : 0;
                const bDate = b.lastContactedAt ? new Date(b.lastContactedAt).getTime() : 0;
                cmp = aDate - bDate;
                break;
            }
        }
        return sortConfig.direction === 'desc' ? -cmp : cmp;
    });
    return sorted;
}

export function getProviderCounts(leads: DiscoveredLead[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const lead of leads) {
        if (lead.emailProvider) {
            counts[lead.emailProvider] = (counts[lead.emailProvider] || 0) + 1;
        }
    }
    return counts;
}

export function getScoreColor(score: number): string {
    if (score >= 80) return 'text-success bg-success/10 border border-success/20';
    if (score >= 60) return 'text-warning bg-warning/10 border border-warning/20';
    if (score >= 40) return 'text-amber-600 bg-amber-500/10 border border-amber-500/20';
    return 'text-muted-foreground bg-muted border border-border';
}

// ─── Improvement #18: Revenue forecasting helper ───

export function forecastPipelineRevenue(leads: DiscoveredLead[]): {
    totalPipelineValue: number;
    weightedForecast: number;
    byStage: Record<string, { count: number; value: number; probability: number }>;
} {
    const stageProbability: Partial<Record<LeadStatus, number>> = {
        new: 0.05,
        contacted: 0.10,
        opened: 0.12,
        replied: 0.20,
        qualified: 0.35,
        demo_scheduled: 0.50,
        proposal_sent: 0.65,
        negotiation: 0.80,
        closed_won: 1.0,
        closed_lost: 0,
    };

    const byStage: Record<string, { count: number; value: number; probability: number }> = {};
    let totalPipelineValue = 0;
    let weightedForecast = 0;

    for (const lead of leads) {
        const value = lead.estimatedDealValue ?? 0;
        const prob = stageProbability[lead.status] ?? 0;

        if (!byStage[lead.status]) {
            byStage[lead.status] = { count: 0, value: 0, probability: prob };
        }
        byStage[lead.status].count++;
        byStage[lead.status].value += value;
        totalPipelineValue += value;
        weightedForecast += value * prob;
    }

    return { totalPipelineValue, weightedForecast, byStage };
}

// ─── Improvement #19: Export leads to CSV ───

export function exportLeadsToCSV(leads: DiscoveredLead[]): string {
    const headers = [
        'Company Name', 'Domain', 'Contact Name', 'Contact Email', 'Contact Title',
        'Score', 'ICP Fit', 'Status', 'Email Provider', 'Company Size',
        'Estimated Deal Value', 'Source', 'Category', 'Tags', 'Found At',
        'Last Contacted', 'Next Follow-up', 'Notes',
    ];

    const rows = leads.map(l => [
        l.companyName,
        l.domain,
        l.contactName ?? '',
        l.contactEmail ?? '',
        l.contactTitle ?? '',
        l.score.toString(),
        l.icpFit,
        l.status,
        l.emailProvider ?? '',
        l.companySize ?? '',
        l.estimatedDealValue?.toString() ?? '',
        l.source,
        l.category,
        l.tags.join('; '),
        l.foundAt,
        l.lastContactedAt ?? '',
        l.nextFollowUpAt ?? '',
        l.notes,
    ]);

    const escape = (val: string) => `"${val.replace(/"/g, '""')}"`;
    return [headers.map(escape).join(','), ...rows.map(r => r.map(escape).join(','))].join('\n');
}

// ─── Improvement #20: Lead enrichment status tracking ───

export interface EnrichmentStatus {
    mxResolved: boolean;
    contactFound: boolean;
    companySizeResolved: boolean;
    trafficEstimated: boolean;
    linkedinFound: boolean;
    completeness: number;
}

export function getEnrichmentStatus(lead: DiscoveredLead): EnrichmentStatus {
    const checks = [
        lead.mxRecords.length > 0,
        !!lead.contactEmail,
        !!lead.companySize,
        !!lead.websiteTraffic,
        !!lead.linkedinUrl,
    ];
    const completed = checks.filter(Boolean).length;
    return {
        mxResolved: checks[0],
        contactFound: checks[1],
        companySizeResolved: checks[2],
        trafficEstimated: checks[3],
        linkedinFound: checks[4],
        completeness: Math.round((completed / checks.length) * 100),
    };
}