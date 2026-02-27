export interface DiscoverySource {
    id: 'product_hunt' | 'g2' | 'capterra' | 'crunchbase';
    name: string;
    icon: string;
    enabled: boolean;
    description: string;
}

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
    status: 'new' | 'contacted' | 'qualified' | 'nurturing';
    tags: string[];
}

export interface OutreachOffer {
    id: string;
    name: string;
    description: string;
    icon: string;
    templateId: string;
}

export interface DiscoveryStats {
    totalScraped: number;
    totalWithMx: number;
    byProvider: Record<string, number>;
    bySource: Record<string, number>;
}

export const DISCOVERY_SOURCES: DiscoverySource[] = [
    { id: 'product_hunt', name: 'Product Hunt', icon: '🚀', enabled: true, description: 'New SaaS launches and trending products' },
    { id: 'g2', name: 'G2 Crowd', icon: '⭐', enabled: true, description: 'Enterprise software reviews and comparisons' },
    { id: 'capterra', name: 'Capterra', icon: '📊', enabled: false, description: 'Business software directory and reviews' },
    { id: 'crunchbase', name: 'Crunchbase', icon: '💼', enabled: false, description: 'Startup and company funding data' },
];

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
];

export const COMPETITOR_PROVIDERS = ['SendGrid', 'Mailgun', 'Resend', 'Postmark', 'Mailchimp/Mandrill', 'SparkPost', 'Amazon SES'];

export const OUTREACH_OFFERS: OutreachOffer[] = [
    {
        id: 'deliverability_audit',
        name: 'Free Deliverability Audit',
        description: 'Comprehensive DNS, reputation, and deliverability analysis',
        icon: '🔍',
        templateId: 'tmpl_competitor_migration',
    },
    {
        id: 'webhook_migration',
        name: 'Webhook Migration Guide',
        description: 'Provider-specific webhook migration documentation',
        icon: '🔗',
        templateId: 'tmpl_competitor_migration',
    },
    {
        id: 'free_migration_support',
        name: 'Free Migration Support',
        description: '1:1 onboarding call with DNS review and webhook testing',
        icon: '🚀',
        templateId: 'tmpl_competitor_migration',
    },
];

export const SALES_TABS = ['discovery', 'leads', 'outreach', 'analytics'] as const;
export type TabKey = (typeof SALES_TABS)[number];

export function getFilteredLeads(leads: DiscoveredLead[], providerFilter: string | null): DiscoveredLead[] {
    if (!providerFilter) return leads;
    return leads.filter((lead) => lead.emailProvider === providerFilter);
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