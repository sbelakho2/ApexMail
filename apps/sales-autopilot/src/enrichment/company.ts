/**
 * Company Enrichment Service
 * Enriches lead data with publicly available company information
 */

import * as cheerio from 'cheerio';
import { createLogger } from '@apexmail/lib';
import { config } from '../config.js';
import { isUrlAllowed } from '../scrapers/robots-service.js';
import { waitForRateLimit } from '../scrapers/rate-limiter.js';
import type {
    EnrichmentResult,
    TechnologyStack,
    SocialProfile,
    EmployeeRange,
} from '../types.js';

const logger = createLogger({ name: 'company-enrichment', level: 'info' });

/**
 * Fetches a page with proper headers
 */
async function fetchPage(url: string): Promise<string | null> {
    const allowed = await isUrlAllowed(url);
    if (!allowed) {
        return null;
    }

    const urlObj = new URL(url);
    await waitForRateLimit(urlObj.hostname);

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.scraper.timeoutMs);

        const response = await fetch(url, {
            headers: {
                'User-Agent': config.scraper.userAgent,
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            return null;
        }

        return await response.text();
    } catch {
        return null;
    }
}

/**
 * Extracts company info from the company's own website
 */
async function enrichFromWebsite(domain: string): Promise<Partial<EnrichmentResult>> {
    const url = `https://${domain}`;
    const html = await fetchPage(url);

    if (!html) {
        return {};
    }

    const $ = cheerio.load(html);
    const result: Partial<EnrichmentResult> = {
        sources: [{ name: 'website', url, scrapedAt: new Date() }],
    };

    // Extract meta tags
    result.description = $('meta[name="description"]').attr('content') ||
        $('meta[property="og:description"]').attr('content') ||
        null;

    // Extract social profiles from links
    const socialProfiles: SocialProfile[] = [];
    const socialPatterns = [
        { platform: 'linkedin', pattern: /linkedin\.com\/(company|in)\/([^/?]+)/i },
        { platform: 'twitter', pattern: /twitter\.com\/([^/?]+)/i },
        { platform: 'facebook', pattern: /facebook\.com\/([^/?]+)/i },
        { platform: 'github', pattern: /github\.com\/([^/?]+)/i },
    ] as const;

    $('a[href*="linkedin"], a[href*="twitter"], a[href*="facebook"], a[href*="github"]').each(
        (_, el) => {
            const href = $(el).attr('href');
            if (!href) return;

            for (const { platform, pattern } of socialPatterns) {
                const match = href.match(pattern);
                if (match) {
                    if (!socialProfiles.find((p) => p.platform === platform)) {
                        socialProfiles.push({
                            platform,
                            url: href,
                            handle: match[platform === 'linkedin' ? 2 : 1] || null,
                        });
                    }
                    break;
                }
            }
        }
    );

    result.socialProfiles = socialProfiles;

    // Extract keywords from meta tags
    const keywordsMeta = $('meta[name="keywords"]').attr('content');
    if (keywordsMeta) {
        result.keywords = keywordsMeta.split(',').map((k) => k.trim()).filter(Boolean);
    }

    // Try to detect technologies from HTML
    result.technologies = detectTechnologies(html);

    return result;
}

/**
 * Detects technologies from HTML content
 */
function detectTechnologies(html: string): TechnologyStack[] {
    const technologies: TechnologyStack[] = [];

    const patterns = [
        // Frontend frameworks
        { name: 'React', category: 'Frontend', pattern: /react|__NEXT_DATA__|_next/i },
        { name: 'Vue.js', category: 'Frontend', pattern: /__vue__|vue\.js|nuxt/i },
        { name: 'Angular', category: 'Frontend', pattern: /ng-app|angular\.js|@angular/i },
        { name: 'Svelte', category: 'Frontend', pattern: /svelte/i },

        // CMS
        { name: 'WordPress', category: 'CMS', pattern: /wp-content|wp-includes|wordpress/i },
        { name: 'Drupal', category: 'CMS', pattern: /drupal/i },
        { name: 'Shopify', category: 'E-commerce', pattern: /shopify|cdn\.shopify/i },
        { name: 'Webflow', category: 'CMS', pattern: /webflow/i },
        { name: 'Squarespace', category: 'CMS', pattern: /squarespace/i },
        { name: 'Wix', category: 'CMS', pattern: /wix\.com|wixsite/i },

        // Analytics
        { name: 'Google Analytics', category: 'Analytics', pattern: /google-analytics|gtag|UA-\d+/i },
        { name: 'Mixpanel', category: 'Analytics', pattern: /mixpanel/i },
        { name: 'Segment', category: 'Analytics', pattern: /segment\.com|analytics\.js/i },
        { name: 'Heap', category: 'Analytics', pattern: /heap\.io|heapanalytics/i },
        { name: 'Hotjar', category: 'Analytics', pattern: /hotjar/i },
        { name: 'FullStory', category: 'Analytics', pattern: /fullstory/i },

        // Marketing
        { name: 'HubSpot', category: 'Marketing', pattern: /hubspot/i },
        { name: 'Intercom', category: 'Marketing', pattern: /intercom/i },
        { name: 'Drift', category: 'Marketing', pattern: /drift\.com/i },
        { name: 'Mailchimp', category: 'Marketing', pattern: /mailchimp/i },
        { name: 'Zendesk', category: 'Support', pattern: /zendesk/i },

        // Infrastructure
        { name: 'Cloudflare', category: 'CDN', pattern: /cloudflare/i },
        { name: 'AWS', category: 'Cloud', pattern: /amazonaws\.com/i },
        { name: 'Google Cloud', category: 'Cloud', pattern: /googleapis\.com/i },

        // Payments
        { name: 'Stripe', category: 'Payments', pattern: /stripe\.com|js\.stripe/i },
        { name: 'PayPal', category: 'Payments', pattern: /paypal/i },
    ];

    for (const { name, category, pattern } of patterns) {
        if (pattern.test(html)) {
            technologies.push({
                name,
                category,
                confidence: 0.8,
            });
        }
    }

    return technologies;
}

/**
 * Parses employee count ranges
 */
function parseEmployeeRange(text: string): EmployeeRange | null {
    const patterns = [
        { pattern: /1-10|1 to 10/i, min: 1, max: 10, label: '1-10' },
        { pattern: /11-50|11 to 50/i, min: 11, max: 50, label: '11-50' },
        { pattern: /51-200|51 to 200/i, min: 51, max: 200, label: '51-200' },
        { pattern: /201-500|201 to 500/i, min: 201, max: 500, label: '201-500' },
        { pattern: /501-1000|501 to 1000/i, min: 501, max: 1000, label: '501-1000' },
        { pattern: /1001-5000|1001 to 5000/i, min: 1001, max: 5000, label: '1001-5000' },
        { pattern: /5001-10000|5001 to 10000/i, min: 5001, max: 10000, label: '5001-10000' },
        { pattern: /10000\+|10001\+|10,000\+/i, min: 10001, max: 100000, label: '10000+' },
    ];

    for (const { pattern, min, max, label } of patterns) {
        if (pattern.test(text)) {
            return { min, max, label };
        }
    }

    return null;
}

/**
 * Enriches from LinkedIn company page (public data only)
 */
async function enrichFromLinkedIn(companyName: string): Promise<Partial<EnrichmentResult>> {
    // LinkedIn blocks most scraping, so we use minimal public data
    // In production, you'd use LinkedIn's official API
    const searchUrl = `https://www.linkedin.com/company/${companyName
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-]/g, '')}`;

    const html = await fetchPage(searchUrl);
    if (!html) {
        return {};
    }

    const $ = cheerio.load(html);
    const result: Partial<EnrichmentResult> = {
        sources: [{ name: 'linkedin', url: searchUrl, scrapedAt: new Date() }],
    };

    // Extract public profile info
    const description = $('meta[property="og:description"]').attr('content');
    if (description) {
        result.description = description;

        // Try to extract employee count from description
        const empMatch = description.match(/(\d[\d,]+)\s*employees?/i);
        if (empMatch && empMatch[1]) {
            const empCount = parseInt(empMatch[1].replace(/,/g, ''), 10);
            if (empCount <= 10) {
                result.employeeRange = { min: 1, max: 10, label: '1-10' };
            } else if (empCount <= 50) {
                result.employeeRange = { min: 11, max: 50, label: '11-50' };
            } else if (empCount <= 200) {
                result.employeeRange = { min: 51, max: 200, label: '51-200' };
            } else if (empCount <= 500) {
                result.employeeRange = { min: 201, max: 500, label: '201-500' };
            } else if (empCount <= 1000) {
                result.employeeRange = { min: 501, max: 1000, label: '501-1000' };
            } else if (empCount <= 5000) {
                result.employeeRange = { min: 1001, max: 5000, label: '1001-5000' };
            } else {
                result.employeeRange = { min: 5001, max: 10000, label: '5001-10000' };
            }
        }

        // Try to extract industry
        const industryMatch = description.match(/industry:\s*([^|•\n]+)/i);
        if (industryMatch && industryMatch[1]) {
            result.industry = industryMatch[1].trim();
        }
    }

    return result;
}

/**
 * Enriches from Clearbit (if API key provided)
 */
async function enrichFromClearbit(
    domain: string,
    apiKey?: string
): Promise<Partial<EnrichmentResult>> {
    if (!apiKey) {
        return {};
    }

    try {
        const response = await fetch(
            `https://company.clearbit.com/v2/companies/find?domain=${domain}`,
            {
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                },
            }
        );

        if (!response.ok) {
            return {};
        }

        const data = await response.json() as Record<string, unknown>;

        const result: Partial<EnrichmentResult> = {
            companyName: data['name'] as string || undefined,
            description: data['description'] as string || undefined,
            industry: data['industry'] as string || undefined,
            sources: [{ name: 'clearbit', url: `https://clearbit.com/company/${domain}`, scrapedAt: new Date() }],
        };

        // Parse metrics
        const metrics = data['metrics'] as Record<string, unknown> | undefined;
        if (metrics) {
            const employees = metrics['employees'] as number | undefined;
            if (employees !== undefined) {
                result.employeeRange = parseEmployeeRange(`${employees} employees`);
            }
        }

        // Parse location
        const geo = data['geo'] as Record<string, unknown> | undefined;
        if (geo) {
            result.location = {
                city: (geo['city'] as string) || null,
                state: (geo['state'] as string) || null,
                country: (geo['country'] as string) || '',
                countryCode: (geo['countryCode'] as string) || '',
                postalCode: (geo['postalCode'] as string) || null,
                timezone: null,
            };
        }

        // Parse tech stack
        const tech = data['tech'] as string[] | undefined;
        if (tech && Array.isArray(tech)) {
            result.technologies = tech.map((t: string) => ({
                name: t,
                category: 'Unknown',
                confidence: 0.9,
            }));
        }

        return result;
    } catch {
        return {};
    }
}

/**
 * Merges multiple enrichment results
 */
function mergeEnrichmentResults(
    results: Partial<EnrichmentResult>[]
): EnrichmentResult {
    const merged: EnrichmentResult = {
        companyName: '',
        domain: '',
        description: null,
        foundedYear: null,
        employeeRange: null,
        revenueRange: null,
        industry: null,
        subIndustry: null,
        technologies: [],
        socialProfiles: [],
        location: null,
        funding: null,
        contacts: [],
        keywords: [],
        confidence: 0,
        sources: [],
        enrichedAt: new Date(),
    };

    for (const result of results) {
        if (result.companyName) merged.companyName = result.companyName;
        if (result.domain) merged.domain = result.domain;
        if (result.description) merged.description = result.description;
        if (result.foundedYear) merged.foundedYear = result.foundedYear;
        if (result.employeeRange) merged.employeeRange = result.employeeRange;
        if (result.revenueRange) merged.revenueRange = result.revenueRange;
        if (result.industry) merged.industry = result.industry;
        if (result.subIndustry) merged.subIndustry = result.subIndustry;
        if (result.location) merged.location = result.location;
        if (result.funding) merged.funding = result.funding;

        if (result.technologies) {
            for (const tech of result.technologies) {
                if (!merged.technologies.find((t) => t.name === tech.name)) {
                    merged.technologies.push(tech);
                }
            }
        }

        if (result.socialProfiles) {
            for (const profile of result.socialProfiles) {
                if (!merged.socialProfiles.find((p) => p.platform === profile.platform)) {
                    merged.socialProfiles.push(profile);
                }
            }
        }

        if (result.contacts) {
            merged.contacts.push(...result.contacts);
        }

        if (result.keywords) {
            for (const keyword of result.keywords) {
                if (!merged.keywords.includes(keyword)) {
                    merged.keywords.push(keyword);
                }
            }
        }

        if (result.sources) {
            merged.sources.push(...result.sources);
        }
    }

    // Calculate confidence based on sources
    merged.confidence = Math.min(1, merged.sources.length * 0.25);

    return merged;
}

/**
 * Main enrichment function
 */
export async function enrichCompany(
    domain: string,
    companyName: string,
    options?: {
        clearbitApiKey?: string;
        skipLinkedIn?: boolean;
    }
): Promise<EnrichmentResult> {
    logger.info('Enriching company', { domain, companyName });

    const results: Partial<EnrichmentResult>[] = [];

    // Fetch from multiple sources in parallel
    const [websiteResult, linkedInResult, clearbitResult] = await Promise.all([
        enrichFromWebsite(domain),
        options?.skipLinkedIn ? {} : enrichFromLinkedIn(companyName),
        enrichFromClearbit(domain, options?.clearbitApiKey),
    ]);

    results.push(websiteResult, linkedInResult, clearbitResult);

    const merged = mergeEnrichmentResults(results);
    merged.domain = domain;
    merged.companyName = companyName || merged.companyName;

    logger.info('Enrichment complete', {
        domain,
        sources: merged.sources.length,
        confidence: merged.confidence,
    });

    return merged;
}

/**
 * Batch enrich multiple companies
 */
export async function batchEnrichCompanies(
    companies: Array<{ domain: string; name: string }>,
    options?: {
        clearbitApiKey?: string;
        skipLinkedIn?: boolean;
        maxConcurrent?: number;
    }
): Promise<Map<string, EnrichmentResult>> {
    const results = new Map<string, EnrichmentResult>();
    const maxConcurrent = options?.maxConcurrent || 3;

    // Process in batches to avoid overwhelming rate limits
    for (let i = 0; i < companies.length; i += maxConcurrent) {
        const batch = companies.slice(i, i + maxConcurrent);

        const batchResults = await Promise.allSettled(
            batch.map((company) =>
                enrichCompany(company.domain, company.name, {
                    clearbitApiKey: options?.clearbitApiKey,
                    skipLinkedIn: options?.skipLinkedIn,
                })
            )
        );

        for (let j = 0; j < batchResults.length; j++) {
            const result = batchResults[j];
            const company = batch[j];

            if (!result || !company) continue;

            if (result.status === 'fulfilled') {
                results.set(company.domain, result.value);
            } else if (result.status === 'rejected') {
                logger.warn('Failed to enrich company', {
                    domain: company.domain,
                    error: result.reason,
                });
            }
        }

        // Delay between batches
        if (i + maxConcurrent < companies.length) {
            await new Promise((resolve) => setTimeout(resolve, 2000));
        }
    }

    return results;
}
