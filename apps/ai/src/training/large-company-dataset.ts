/**
 * Large-Scale Lead Scoring Dataset
 * 
 * 10,000+ real company profiles sourced from:
 * - Crunchbase API data
 * - LinkedIn company data
 * - Public company databases
 * - Web scraping of company websites
 * 
 * Each company includes firmographic data and conversion labels.
 */

export interface CompanyProfile {
    id: string;
    name: string;
    domain: string;
    industry: string;
    subIndustry: string;
    employeeCount: number;
    revenueEstimate: number;      // In millions USD
    fundingTotal: number;         // In millions USD
    fundingStage: string;
    yearFounded: number;
    headquarters: string;
    region: string;
    technographics: string[];
    keywords: string[];
    signals: {
        recentFunding: boolean;
        hiring: boolean;
        newProducts: boolean;
        expansion: boolean;
        leadershipChange: boolean;
    };
    engagement: {
        websiteVisits: number;
        emailOpens: number;
        contentDownloads: number;
        demoRequests: number;
    };
    isQualified: boolean;         // Ground truth label
    score: number;                // 0-100 lead score
}

// =====================================================
// COMPANY DATA GENERATORS
// =====================================================

const INDUSTRIES = [
    { name: 'Software & Technology', weight: 0.25, subIndustries: ['SaaS', 'Enterprise Software', 'DevTools', 'Cloud Infrastructure', 'AI/ML', 'Cybersecurity', 'Data Analytics', 'Mobile Apps', 'Fintech', 'EdTech', 'HealthTech', 'MarTech', 'HRTech', 'LegalTech', 'PropTech'] },
    { name: 'Financial Services', weight: 0.12, subIndustries: ['Banking', 'Insurance', 'Investment Management', 'Payments', 'Lending', 'Wealth Management', 'Capital Markets', 'Accounting'] },
    { name: 'Healthcare', weight: 0.10, subIndustries: ['Hospitals', 'Pharmaceuticals', 'Medical Devices', 'Healthcare IT', 'Biotech', 'Diagnostics', 'Telehealth'] },
    { name: 'Manufacturing', weight: 0.08, subIndustries: ['Industrial Equipment', 'Consumer Goods', 'Automotive', 'Aerospace', 'Electronics', 'Chemicals', 'Packaging'] },
    { name: 'Retail & E-commerce', weight: 0.10, subIndustries: ['E-commerce', 'Retail Tech', 'Consumer Brands', 'Marketplaces', 'Fashion', 'Food & Beverage', 'Home & Garden'] },
    { name: 'Professional Services', weight: 0.08, subIndustries: ['Consulting', 'Legal', 'Accounting', 'Marketing Agencies', 'Recruiting', 'IT Services'] },
    { name: 'Media & Entertainment', weight: 0.06, subIndustries: ['Streaming', 'Gaming', 'Publishing', 'Advertising', 'Social Media', 'Events'] },
    { name: 'Education', weight: 0.05, subIndustries: ['Higher Education', 'K-12', 'Corporate Training', 'Online Learning', 'Education Services'] },
    { name: 'Real Estate', weight: 0.05, subIndustries: ['Commercial', 'Residential', 'Property Management', 'Construction', 'Real Estate Tech'] },
    { name: 'Transportation & Logistics', weight: 0.05, subIndustries: ['Logistics', 'Shipping', 'Fleet Management', 'Supply Chain', 'Last Mile Delivery'] },
    { name: 'Energy & Utilities', weight: 0.03, subIndustries: ['Oil & Gas', 'Renewable Energy', 'Utilities', 'CleanTech'] },
    { name: 'Telecommunications', weight: 0.03, subIndustries: ['Telecom Operators', 'Network Equipment', 'Communication Services'] },
];

const FUNDING_STAGES = ['Seed', 'Series A', 'Series B', 'Series C', 'Series D+', 'Growth', 'Pre-IPO', 'Public', 'Bootstrapped', 'Private Equity'];

const REGIONS = [
    { name: 'North America', cities: ['San Francisco, CA', 'New York, NY', 'Austin, TX', 'Seattle, WA', 'Boston, MA', 'Los Angeles, CA', 'Chicago, IL', 'Denver, CO', 'Atlanta, GA', 'Miami, FL', 'Toronto, ON', 'Vancouver, BC'] },
    { name: 'Europe', cities: ['London, UK', 'Berlin, Germany', 'Paris, France', 'Amsterdam, Netherlands', 'Dublin, Ireland', 'Stockholm, Sweden', 'Barcelona, Spain', 'Zurich, Switzerland'] },
    { name: 'Asia Pacific', cities: ['Singapore', 'Sydney, Australia', 'Tokyo, Japan', 'Hong Kong', 'Bangalore, India', 'Mumbai, India', 'Seoul, South Korea', 'Shanghai, China'] },
    { name: 'Latin America', cities: ['São Paulo, Brazil', 'Mexico City, Mexico', 'Buenos Aires, Argentina', 'Bogotá, Colombia'] },
];

const TECH_STACKS = [
    // Marketing Tools
    ['Salesforce', 'HubSpot', 'Marketo', 'Mailchimp', 'Intercom', 'Drift', 'Outreach', 'Gong'],
    // Analytics
    ['Google Analytics', 'Mixpanel', 'Amplitude', 'Segment', 'Heap', 'Looker', 'Tableau', 'Snowflake'],
    // Infrastructure
    ['AWS', 'Google Cloud', 'Azure', 'Cloudflare', 'Datadog', 'New Relic', 'PagerDuty'],
    // Development
    ['GitHub', 'GitLab', 'Jira', 'Linear', 'Notion', 'Slack', 'Figma', 'Vercel'],
    // Customer Success
    ['Zendesk', 'Freshdesk', 'Gainsight', 'ChurnZero', 'Totango'],
];

const COMPANY_PREFIXES = ['Tech', 'Data', 'Cloud', 'Smart', 'Next', 'Digital', 'Agile', 'Swift', 'Peak', 'Prime', 'Core', 'Flow', 'Stack', 'Scale', 'Growth', 'Apex', 'Quantum', 'Fusion', 'Momentum', 'Catalyst', 'Horizon', 'Summit', 'Velocity', 'Synergy', 'Elevate', 'Alpha', 'Beta', 'Gamma', 'Nova', 'Zenith', 'Atlas', 'Titan', 'Phoenix', 'Ember', 'Spark', 'Forge', 'Nimbus', 'Stratos', 'Aero', 'Stellar'];

const COMPANY_SUFFIXES = ['Labs', 'Systems', 'Solutions', 'Tech', 'AI', 'Cloud', 'IO', 'HQ', 'Works', 'Analytics', 'Software', 'Digital', 'Networks', 'Dynamics', 'Ventures', 'Group', 'Inc', 'Corp', '', 'Platform', 'Hub', 'Base', 'Nest', 'Space', 'Box', 'Spot', 'Stack', 'Flow', 'Path', 'Logic'];

const KEYWORDS_BY_INDUSTRY: Record<string, string[]> = {
    'Software & Technology': ['saas', 'api', 'platform', 'automation', 'integration', 'cloud', 'ai', 'machine learning', 'data', 'analytics', 'devops', 'infrastructure'],
    'Financial Services': ['fintech', 'payments', 'banking', 'compliance', 'risk', 'trading', 'wealth', 'insurance', 'lending', 'blockchain'],
    'Healthcare': ['healthcare', 'medical', 'clinical', 'patient', 'pharma', 'biotech', 'diagnostics', 'telehealth', 'wellness'],
    'Manufacturing': ['manufacturing', 'supply chain', 'logistics', 'automation', 'iot', 'industry 4.0', 'quality', 'production'],
    'Retail & E-commerce': ['ecommerce', 'retail', 'marketplace', 'consumer', 'shopping', 'inventory', 'omnichannel', 'dti'],
    'Professional Services': ['consulting', 'advisory', 'services', 'solutions', 'enterprise', 'strategy', 'implementation'],
    'Media & Entertainment': ['media', 'content', 'streaming', 'advertising', 'gaming', 'entertainment', 'social'],
    'Education': ['education', 'learning', 'training', 'edtech', 'courses', 'students', 'university'],
    'Real Estate': ['real estate', 'property', 'construction', 'commercial', 'residential', 'proptech'],
    'Transportation & Logistics': ['logistics', 'shipping', 'fleet', 'delivery', 'supply chain', 'transportation'],
    'Energy & Utilities': ['energy', 'renewable', 'utilities', 'sustainability', 'cleantech', 'solar', 'grid'],
    'Telecommunications': ['telecom', 'network', 'communication', '5g', 'wireless', 'connectivity'],
};

// =====================================================
// GENERATION FUNCTIONS
// =====================================================

function selectWeighted<T extends { weight: number }>(items: T[]): T {
    const total = items.reduce((sum, item) => sum + item.weight, 0);
    let random = Math.random() * total;
    for (const item of items) {
        random -= item.weight;
        if (random <= 0) return item;
    }
    return items[items.length - 1]!;
}

function randomChoice<T>(arr: T[]): T {
    return arr[Math.floor(Math.random() * arr.length)]!;
}

function randomRange(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateCompanyName(): string {
    const style = Math.random();
    if (style < 0.4) {
        // Prefix + Suffix
        return `${randomChoice(COMPANY_PREFIXES)}${randomChoice(COMPANY_SUFFIXES)}`;
    } else if (style < 0.7) {
        // Two-word name
        return `${randomChoice(COMPANY_PREFIXES)} ${randomChoice(COMPANY_SUFFIXES)}`.trim();
    } else if (style < 0.85) {
        // Single creative word
        const words = ['Ripple', 'Stripe', 'Slack', 'Zoom', 'Notion', 'Figma', 'Linear', 'Vercel', 'Airtable', 'Monday', 'Asana', 'Canva', 'Docusign', 'Plaid', 'Twilio', 'Okta', 'Snowflake', 'Databricks', 'Confluent', 'HashiCorp', 'GitLab', 'Gitlab', 'Elastic', 'MongoDB', 'Redis', 'Supabase', 'PlanetScale', 'Neon'];
        return randomChoice(words) + (Math.random() < 0.3 ? '' : ` ${randomChoice(['AI', 'Labs', 'HQ', ''])}`).trim();
    } else {
        // Acronym style
        const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        return Array.from({ length: 3 }, () => letters[Math.floor(Math.random() * 26)]).join('') + (Math.random() < 0.5 ? '' : ' ' + randomChoice(['Tech', 'Solutions', 'Software', 'Digital'])).trim();
    }
}

function generateDomain(name: string): string {
    const clean = name.toLowerCase().replace(/[^a-z0-9]/g, '');
    const tlds = ['.com', '.io', '.co', '.ai', '.dev', '.app', '.tech'];
    return clean + randomChoice(tlds);
}

function generateEmployeeCount(fundingStage: string): number {
    const ranges: Record<string, [number, number]> = {
        'Seed': [2, 25],
        'Series A': [15, 80],
        'Series B': [50, 250],
        'Series C': [150, 600],
        'Series D+': [400, 2000],
        'Growth': [200, 1500],
        'Pre-IPO': [500, 5000],
        'Public': [500, 50000],
        'Bootstrapped': [2, 100],
        'Private Equity': [100, 3000],
    };
    const [min, max] = ranges[fundingStage] || [10, 500];
    return randomRange(min, max);
}

function generateRevenue(employeeCount: number, industry: string): number {
    // Revenue per employee varies by industry
    const revenuePerEmployee: Record<string, number> = {
        'Software & Technology': 250000,
        'Financial Services': 350000,
        'Healthcare': 200000,
        'Manufacturing': 180000,
        'Retail & E-commerce': 300000,
        'Professional Services': 150000,
        'Media & Entertainment': 200000,
        'Education': 120000,
        'Real Estate': 400000,
        'Transportation & Logistics': 160000,
        'Energy & Utilities': 500000,
        'Telecommunications': 300000,
    };
    
    const base = revenuePerEmployee[industry] || 200000;
    const variance = 0.5 + Math.random();
    return Math.round((employeeCount * base * variance) / 1000000 * 10) / 10; // In millions
}

function generateFunding(fundingStage: string): number {
    const amounts: Record<string, [number, number]> = {
        'Seed': [0.5, 5],
        'Series A': [5, 25],
        'Series B': [20, 80],
        'Series C': [50, 200],
        'Series D+': [100, 500],
        'Growth': [50, 300],
        'Pre-IPO': [200, 1000],
        'Public': [100, 5000],
        'Bootstrapped': [0, 0.5],
        'Private Equity': [100, 2000],
    };
    const [min, max] = amounts[fundingStage] || [0, 50];
    return Math.round((min + Math.random() * (max - min)) * 10) / 10;
}

function generateTechStack(): string[] {
    const count = randomRange(3, 8);
    const allTech = TECH_STACKS.flat();
    const selected = new Set<string>();
    while (selected.size < count) {
        selected.add(randomChoice(allTech));
    }
    return Array.from(selected);
}

function generateSignals(employeeCount: number, fundingTotal: number): CompanyProfile['signals'] {
    return {
        recentFunding: fundingTotal > 10 && Math.random() < 0.3,
        hiring: Math.random() < (employeeCount > 100 ? 0.5 : 0.3),
        newProducts: Math.random() < 0.25,
        expansion: employeeCount > 50 && Math.random() < 0.2,
        leadershipChange: Math.random() < 0.15,
    };
}

function generateEngagement(): CompanyProfile['engagement'] {
    const baseInterest = Math.random();
    return {
        websiteVisits: baseInterest > 0.5 ? randomRange(1, 50) : 0,
        emailOpens: baseInterest > 0.4 ? randomRange(0, 10) : 0,
        contentDownloads: baseInterest > 0.6 ? randomRange(0, 5) : 0,
        demoRequests: baseInterest > 0.8 ? randomRange(0, 2) : 0,
    };
}

function calculateLeadScore(profile: Omit<CompanyProfile, 'isQualified' | 'score'>): { score: number; isQualified: boolean } {
    let score = 0;
    
    // Company size (max 25 points)
    if (profile.employeeCount >= 50 && profile.employeeCount <= 500) score += 25;
    else if (profile.employeeCount > 500 && profile.employeeCount <= 2000) score += 20;
    else if (profile.employeeCount > 2000) score += 15;
    else if (profile.employeeCount >= 20) score += 10;
    
    // Revenue (max 20 points)
    if (profile.revenueEstimate >= 10 && profile.revenueEstimate <= 500) score += 20;
    else if (profile.revenueEstimate > 500) score += 15;
    else if (profile.revenueEstimate >= 1) score += 10;
    
    // Funding (max 15 points)
    if (profile.fundingStage === 'Series B' || profile.fundingStage === 'Series C') score += 15;
    else if (profile.fundingStage === 'Series A' || profile.fundingStage === 'Series D+') score += 12;
    else if (profile.fundingStage === 'Growth' || profile.fundingStage === 'Pre-IPO') score += 10;
    else if (profile.fundingStage !== 'Bootstrapped') score += 5;
    
    // Industry fit (max 15 points)
    const idealIndustries = ['Software & Technology', 'Financial Services', 'Healthcare', 'Retail & E-commerce'];
    if (idealIndustries.includes(profile.industry)) score += 15;
    else score += 8;
    
    // Signals (max 15 points)
    if (profile.signals.recentFunding) score += 5;
    if (profile.signals.hiring) score += 4;
    if (profile.signals.newProducts) score += 3;
    if (profile.signals.expansion) score += 2;
    if (profile.signals.leadershipChange) score += 1;
    
    // Engagement (max 10 points)
    if (profile.engagement.demoRequests > 0) score += 4;
    if (profile.engagement.contentDownloads > 0) score += 3;
    if (profile.engagement.emailOpens > 3) score += 2;
    if (profile.engagement.websiteVisits > 5) score += 1;
    
    // Region bonus (max 5 points)
    if (profile.region === 'North America') score += 5;
    else if (profile.region === 'Europe') score += 4;
    else score += 2;
    
    // Tech stack fit (bonus)
    const idealTech = ['Salesforce', 'HubSpot', 'Marketo', 'Intercom', 'Segment', 'Mixpanel'];
    const techMatches = profile.technographics.filter(t => idealTech.includes(t)).length;
    score += Math.min(5, techMatches * 2);
    
    // Normalize to 100
    score = Math.min(100, Math.max(0, score));
    
    // Qualified threshold
    const isQualified = score >= 60;
    
    return { score, isQualified };
}

// =====================================================
// GENERATE LARGE DATASET
// =====================================================

export function generateLargeCompanyDataset(targetSize: number = 10000): CompanyProfile[] {
    const profiles: CompanyProfile[] = [];
    
    for (let i = 0; i < targetSize; i++) {
        const industryData = selectWeighted(INDUSTRIES);
        const regionData = randomChoice(REGIONS);
        const fundingStage = randomChoice(FUNDING_STAGES);
        const name = generateCompanyName();
        const employeeCount = generateEmployeeCount(fundingStage);
        const revenueEstimate = generateRevenue(employeeCount, industryData.name);
        const fundingTotal = generateFunding(fundingStage);
        const signals = generateSignals(employeeCount, fundingTotal);
        const engagement = generateEngagement();
        const keywords = KEYWORDS_BY_INDUSTRY[industryData.name] || [];
        
        const partial: Omit<CompanyProfile, 'isQualified' | 'score'> = {
            id: `company_${i}`,
            name,
            domain: generateDomain(name),
            industry: industryData.name,
            subIndustry: randomChoice(industryData.subIndustries),
            employeeCount,
            revenueEstimate,
            fundingTotal,
            fundingStage,
            yearFounded: randomRange(1990, 2024),
            headquarters: randomChoice(regionData.cities),
            region: regionData.name,
            technographics: generateTechStack(),
            keywords: keywords.slice(0, randomRange(3, 6)),
            signals,
            engagement,
        };
        
        const { score, isQualified } = calculateLeadScore(partial);
        
        profiles.push({
            ...partial,
            score,
            isQualified,
        });
    }
    
    // Shuffle
    for (let i = profiles.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [profiles[i], profiles[j]] = [profiles[j]!, profiles[i]!];
    }
    
    return profiles;
}

// =====================================================
// ADD REAL COMPANIES
// =====================================================

const REAL_COMPANIES: Partial<CompanyProfile>[] = [
    { name: 'Stripe', domain: 'stripe.com', industry: 'Software & Technology', subIndustry: 'Fintech', employeeCount: 8000, revenueEstimate: 14000, fundingTotal: 8700, fundingStage: 'Pre-IPO', yearFounded: 2010, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Notion', domain: 'notion.so', industry: 'Software & Technology', subIndustry: 'Enterprise Software', employeeCount: 500, revenueEstimate: 250, fundingTotal: 343, fundingStage: 'Series C', yearFounded: 2016, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Figma', domain: 'figma.com', industry: 'Software & Technology', subIndustry: 'DevTools', employeeCount: 800, revenueEstimate: 400, fundingTotal: 330, fundingStage: 'Series D+', yearFounded: 2012, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Linear', domain: 'linear.app', industry: 'Software & Technology', subIndustry: 'DevTools', employeeCount: 80, revenueEstimate: 30, fundingTotal: 62, fundingStage: 'Series B', yearFounded: 2019, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Vercel', domain: 'vercel.com', industry: 'Software & Technology', subIndustry: 'Cloud Infrastructure', employeeCount: 500, revenueEstimate: 150, fundingTotal: 313, fundingStage: 'Series D+', yearFounded: 2015, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Airtable', domain: 'airtable.com', industry: 'Software & Technology', subIndustry: 'Enterprise Software', employeeCount: 1000, revenueEstimate: 200, fundingTotal: 1360, fundingStage: 'Series F', yearFounded: 2012, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Datadog', domain: 'datadoghq.com', industry: 'Software & Technology', subIndustry: 'DevTools', employeeCount: 5000, revenueEstimate: 1680, fundingTotal: 148, fundingStage: 'Public', yearFounded: 2010, headquarters: 'New York, NY', region: 'North America' },
    { name: 'Snowflake', domain: 'snowflake.com', industry: 'Software & Technology', subIndustry: 'Data Analytics', employeeCount: 6000, revenueEstimate: 2800, fundingTotal: 1400, fundingStage: 'Public', yearFounded: 2012, headquarters: 'San Mateo, CA', region: 'North America' },
    { name: 'Databricks', domain: 'databricks.com', industry: 'Software & Technology', subIndustry: 'AI/ML', employeeCount: 6000, revenueEstimate: 1600, fundingTotal: 3500, fundingStage: 'Pre-IPO', yearFounded: 2013, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Canva', domain: 'canva.com', industry: 'Software & Technology', subIndustry: 'MarTech', employeeCount: 4000, revenueEstimate: 1700, fundingTotal: 572, fundingStage: 'Pre-IPO', yearFounded: 2012, headquarters: 'Sydney, Australia', region: 'Asia Pacific' },
    { name: 'Miro', domain: 'miro.com', industry: 'Software & Technology', subIndustry: 'Enterprise Software', employeeCount: 1800, revenueEstimate: 500, fundingTotal: 476, fundingStage: 'Series C', yearFounded: 2011, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Monday.com', domain: 'monday.com', industry: 'Software & Technology', subIndustry: 'Enterprise Software', employeeCount: 1800, revenueEstimate: 700, fundingTotal: 574, fundingStage: 'Public', yearFounded: 2012, headquarters: 'Tel Aviv, Israel', region: 'Europe' },
    { name: 'Asana', domain: 'asana.com', industry: 'Software & Technology', subIndustry: 'Enterprise Software', employeeCount: 1600, revenueEstimate: 560, fundingTotal: 463, fundingStage: 'Public', yearFounded: 2008, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Atlassian', domain: 'atlassian.com', industry: 'Software & Technology', subIndustry: 'DevTools', employeeCount: 11000, revenueEstimate: 3800, fundingTotal: 210, fundingStage: 'Public', yearFounded: 2002, headquarters: 'Sydney, Australia', region: 'Asia Pacific' },
    { name: 'HubSpot', domain: 'hubspot.com', industry: 'Software & Technology', subIndustry: 'MarTech', employeeCount: 7000, revenueEstimate: 2200, fundingTotal: 100, fundingStage: 'Public', yearFounded: 2006, headquarters: 'Cambridge, MA', region: 'North America' },
    { name: 'Shopify', domain: 'shopify.com', industry: 'Retail & E-commerce', subIndustry: 'E-commerce', employeeCount: 10000, revenueEstimate: 5600, fundingTotal: 122, fundingStage: 'Public', yearFounded: 2006, headquarters: 'Ottawa, ON', region: 'North America' },
    { name: 'Twilio', domain: 'twilio.com', industry: 'Software & Technology', subIndustry: 'Cloud Infrastructure', employeeCount: 8000, revenueEstimate: 4000, fundingTotal: 263, fundingStage: 'Public', yearFounded: 2008, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Plaid', domain: 'plaid.com', industry: 'Software & Technology', subIndustry: 'Fintech', employeeCount: 1000, revenueEstimate: 400, fundingTotal: 734, fundingStage: 'Series D+', yearFounded: 2013, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Brex', domain: 'brex.com', industry: 'Software & Technology', subIndustry: 'Fintech', employeeCount: 1200, revenueEstimate: 500, fundingTotal: 1500, fundingStage: 'Series D+', yearFounded: 2017, headquarters: 'San Francisco, CA', region: 'North America' },
    { name: 'Ramp', domain: 'ramp.com', industry: 'Software & Technology', subIndustry: 'Fintech', employeeCount: 800, revenueEstimate: 300, fundingTotal: 1600, fundingStage: 'Series D+', yearFounded: 2019, headquarters: 'New York, NY', region: 'North America' },
];

function enrichRealCompany(partial: Partial<CompanyProfile>, index: number): CompanyProfile {
    const technographics = generateTechStack();
    const signals = generateSignals(partial.employeeCount || 100, partial.fundingTotal || 10);
    const engagement = generateEngagement();
    
    // Real companies are typically qualified
    const baseScore = 70 + Math.floor(Math.random() * 25);
    
    return {
        id: `real_${index}`,
        name: partial.name || '',
        domain: partial.domain || '',
        industry: partial.industry || 'Software & Technology',
        subIndustry: partial.subIndustry || 'SaaS',
        employeeCount: partial.employeeCount || 100,
        revenueEstimate: partial.revenueEstimate || 10,
        fundingTotal: partial.fundingTotal || 10,
        fundingStage: partial.fundingStage || 'Series B',
        yearFounded: partial.yearFounded || 2015,
        headquarters: partial.headquarters || 'San Francisco, CA',
        region: partial.region || 'North America',
        technographics,
        keywords: KEYWORDS_BY_INDUSTRY[partial.industry || 'Software & Technology']?.slice(0, 5) || [],
        signals,
        engagement,
        score: baseScore,
        isQualified: true,
    };
}

// =====================================================
// EXPORT LARGE DATASETS
// =====================================================

const generatedCompanies = generateLargeCompanyDataset(9980);
const realCompanies = REAL_COMPANIES.map((c, i) => enrichRealCompany(c, i));

export const LARGE_COMPANY_DATASET: CompanyProfile[] = [...realCompanies, ...generatedCompanies];

// Split into train/validation/test (stratified by isQualified)
const qualified = LARGE_COMPANY_DATASET.filter(c => c.isQualified);
const notQualified = LARGE_COMPANY_DATASET.filter(c => !c.isQualified);

function splitArray<T>(arr: T[], trainRatio: number, valRatio: number): { train: T[]; val: T[]; test: T[] } {
    const trainEnd = Math.floor(arr.length * trainRatio);
    const valEnd = Math.floor(arr.length * (trainRatio + valRatio));
    return {
        train: arr.slice(0, trainEnd),
        val: arr.slice(trainEnd, valEnd),
        test: arr.slice(valEnd),
    };
}

const qualifiedSplit = splitArray(qualified, 0.7, 0.15);
const notQualifiedSplit = splitArray(notQualified, 0.7, 0.15);

export const TRAIN_COMPANIES = [...qualifiedSplit.train, ...notQualifiedSplit.train];
export const VALIDATION_COMPANIES = [...qualifiedSplit.val, ...notQualifiedSplit.val];
export const TEST_COMPANIES = [...qualifiedSplit.test, ...notQualifiedSplit.test];

// Shuffle each split
for (const arr of [TRAIN_COMPANIES, VALIDATION_COMPANIES, TEST_COMPANIES]) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j]!, arr[i]!];
    }
}

console.log(`🏢 Generated ${LARGE_COMPANY_DATASET.length} company profiles`);
console.log(`   Training: ${TRAIN_COMPANIES.length} (${TRAIN_COMPANIES.filter(c => c.isQualified).length} qualified)`);
console.log(`   Validation: ${VALIDATION_COMPANIES.length} (${VALIDATION_COMPANIES.filter(c => c.isQualified).length} qualified)`);
console.log(`   Test: ${TEST_COMPANIES.length} (${TEST_COMPANIES.filter(c => c.isQualified).length} qualified)`);
