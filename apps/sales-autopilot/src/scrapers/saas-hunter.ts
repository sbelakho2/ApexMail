/**
 * SaaS Hunter - Lead Discovery Scraper
 * Scrapes SaaS directories to find potential leads
 * Fully robots.txt compliant and ethically rate-limited
 */

import * as cheerio from 'cheerio';
import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import { isUrlAllowed } from './robots-service.js';
import { waitForRateLimit } from './rate-limiter.js';
import {
    resolveMxRecords,
    identifyEmailProvider,
} from './dns-resolver.js';
import { LeadScoringModel, extractFeatures } from './hunter-training.js';
import type { Lead, LeadSource, MxRecord, EnrichmentResult } from '../types.js';

const hunterLogger = createLogger({ name: 'saas-hunter', level: 'info' });

interface ScrapedCompany {
    name: string;
    domain: string;
    website: string;
    description: string | null;
    category: string | null;
    tags: string[];
    sourceUrl: string;
    source: LeadSource;
}

interface ScrapeResult {
    companies: ScrapedCompany[];
    nextPageUrl: string | null;
    totalFound: number;
    errors: string[];
}

// Global trained model instance (lazy initialized)
let trainedModel: LeadScoringModel | null = null;
let modelLoadAttempted = false;

/**
 * Initializes or retrieves the trained lead scoring model
 */
export function getLeadScoringModel(): LeadScoringModel {
    if (trainedModel) {
        return trainedModel;
    }

    if (!modelLoadAttempted) {
        modelLoadAttempted = true;

        // Try to load from stored model
        try {
            // In production, this would load from file/database
            // For now, create a default model
            trainedModel = new LeadScoringModel({
                learningRate: 0.1,
                numTrees: 100,
                maxDepth: 4,
            });

            hunterLogger.info('Lead scoring model initialized');
        } catch (error) {
            hunterLogger.warn('Failed to load trained model, using defaults', { error });
            trainedModel = new LeadScoringModel();
        }
    }

    return trainedModel || new LeadScoringModel();
}

/**
 * Sets a pre-trained model instance
 */
export function setLeadScoringModel(model: LeadScoringModel): void {
    trainedModel = model;
    hunterLogger.info('Lead scoring model updated');
}

/**
 * Calculates lead score using the ML model
 */
export function calculateLeadScore(
    company: ScrapedCompany,
    enrichment?: EnrichmentResult | null
): number {
    // Create a partial lead for feature extraction
    const partialLead: Lead = {
        id: 'temp',
        tenantId: 'temp',
        companyName: company.name,
        domain: company.domain,
        website: company.website,
        email: null,
        emailVerified: false,
        phone: null,
        industry: company.category,
        employeeCount: null,
        revenue: null,
        technologies: [],
        socialProfiles: [],
        location: null,
        source: company.source,
        sourceUrl: company.sourceUrl,
        score: 0,
        status: 'new',
        stage: 'prospect',
        assignedTo: null,
        tags: company.tags,
        customFields: company.description ? { description: company.description } : {},
        mxRecords: [],
        emailProvider: null,
        lastContactedAt: null,
        nextFollowUpAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const features = extractFeatures(partialLead, enrichment ?? null);
    const model = getLeadScoringModel();

    // Calculate raw ML score (0-1)
    const rawScore = model.predict(features);

    // Convert to 0-100 scale
    return Math.round(rawScore * 100);
}

// FIX-500-319: Duplicate ScrapeResult interface removed (was declared at line 28 and here)

/**
 * Fetches a page with proper rate limiting and headers
 */
async function fetchPage(url: string): Promise<string | null> {
    // Check robots.txt
    const allowed = await isUrlAllowed(url);
    if (!allowed) {
        hunterLogger.info('URL blocked by robots.txt', { url });
        return null;
    }

    // Wait for rate limit
    const urlObj = new URL(url);
    await waitForRateLimit(urlObj.hostname);

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(
            () => controller.abort(),
            config.scraper.timeoutMs
        );

        const response = await fetch(url, {
            headers: {
                'User-Agent': config.scraper.userAgent,
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                Connection: 'keep-alive',
            },
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            hunterLogger.warn('Failed to fetch page', { url, status: response.status });
            return null;
        }

        return await response.text();
    } catch (error) {
        hunterLogger.error('Error fetching page', { url, error });
        return null;
    }
}

/**
 * Extracts domain from a URL
 */
function extractDomain(url: string): string | null {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace(/^www\./, '');
    } catch {
        return null;
    }
}

/**
 * Scrapes Product Hunt for launched products
 */
export async function scrapeProductHunt(
    category?: string,
    maxPages: number = 5
): Promise<ScrapeResult> {
    const companies: ScrapedCompany[] = [];
    const errors: string[] = [];
    let nextPageUrl: string | null = null;

    const baseUrl = category
        ? `https://www.producthunt.com/topics/${category}`
        : 'https://www.producthunt.com/all';

    for (let page = 1; page <= maxPages; page++) {
        const url = page === 1 ? baseUrl : `${baseUrl}?page=${page}`;
        const html = await fetchPage(url);

        if (!html) {
            errors.push(`Failed to fetch ${url}`);
            continue;
        }

        const $ = cheerio.load(html);

        // Product Hunt uses data attributes for product cards
        $('[data-test="post-item"]').each((_, element) => {
            const $el = $(element);
            const name = $el.find('[data-test="post-name"]').text().trim();
            const tagline = $el.find('[data-test="post-tagline"]').text().trim();
            const link = $el.find('a[href^="/posts/"]').attr('href');

            if (name && link) {
                // Extract website from product page (would need additional fetch)
                const productUrl = `https://www.producthunt.com${link}`;

                companies.push({
                    name,
                    domain: '', // Will be enriched later
                    website: productUrl,
                    description: tagline || null,
                    category: category || null,
                    tags: [],
                    sourceUrl: url,
                    source: 'product_hunt',
                });
            }
        });

        // Check for next page
        const hasNextPage = $('a[rel="next"]').length > 0;
        if (hasNextPage && page < maxPages) {
            nextPageUrl = `${baseUrl}?page=${page + 1}`;
        }

        hunterLogger.info('Scraped Product Hunt page', { page, found: companies.length });
    }

    return {
        companies,
        nextPageUrl,
        totalFound: companies.length,
        errors,
    };
}

/**
 * Scrapes G2 for software products
 */
export async function scrapeG2(
    category: string,
    maxPages: number = 5
): Promise<ScrapeResult> {
    const companies: ScrapedCompany[] = [];
    const errors: string[] = [];
    let nextPageUrl: string | null = null;

    for (let page = 1; page <= maxPages; page++) {
        const url = `https://www.g2.com/categories/${category}?page=${page}`;
        const html = await fetchPage(url);

        if (!html) {
            errors.push(`Failed to fetch ${url}`);
            continue;
        }

        const $ = cheerio.load(html);

        // G2 product cards
        $('.product-listing').each((_, element) => {
            const $el = $(element);
            const name = $el.find('.product-listing__product-name').text().trim();
            const description = $el.find('.product-listing__paragraph').text().trim();
            const websiteLink = $el.find('a[data-track-name="Visit Website"]').attr('href');

            if (name) {
                const domain = websiteLink ? extractDomain(websiteLink) : null;

                companies.push({
                    name,
                    domain: domain || '',
                    website: websiteLink || '',
                    description: description || null,
                    category,
                    tags: [],
                    sourceUrl: url,
                    source: 'saas_directory',
                });
            }
        });

        // Check for next page
        const hasNextPage = $('a[rel="next"]').length > 0;
        if (hasNextPage && page < maxPages) {
            nextPageUrl = `https://www.g2.com/categories/${category}?page=${page + 1}`;
        }

        hunterLogger.info('Scraped G2 page', { page, category, found: companies.length });
    }

    return {
        companies,
        nextPageUrl,
        totalFound: companies.length,
        errors,
    };
}

/**
 * Scrapes Capterra for software products
 */
export async function scrapeCapterra(
    category: string,
    maxPages: number = 5
): Promise<ScrapeResult> {
    const companies: ScrapedCompany[] = [];
    const errors: string[] = [];
    let nextPageUrl: string | null = null;

    for (let page = 1; page <= maxPages; page++) {
        const url = `https://www.capterra.com/categories/${category}/?page=${page}`;
        const html = await fetchPage(url);

        if (!html) {
            errors.push(`Failed to fetch ${url}`);
            continue;
        }

        const $ = cheerio.load(html);

        // Capterra product listings
        $('[data-testid="product-card"]').each((_, element) => {
            const $el = $(element);
            const name = $el.find('[data-testid="product-name"]').text().trim();
            const description = $el.find('[data-testid="product-description"]').text().trim();

            if (name) {
                companies.push({
                    name,
                    domain: '',
                    website: '',
                    description: description || null,
                    category,
                    tags: [],
                    sourceUrl: url,
                    source: 'saas_directory',
                });
            }
        });

        const hasNextPage = $('a[aria-label="Next page"]').length > 0;
        if (hasNextPage && page < maxPages) {
            nextPageUrl = `https://www.capterra.com/categories/${category}/?page=${page + 1}`;
        }

        hunterLogger.info('Scraped Capterra page', { page, category, found: companies.length });
    }

    return {
        companies,
        nextPageUrl,
        totalFound: companies.length,
        errors,
    };
}

/**
 * Scrapes Crunchbase for startups (public data only)
 */
export async function scrapeCrunchbase(
    query: string,
    _maxPages: number = 3
): Promise<ScrapeResult> {
    const companies: ScrapedCompany[] = [];
    const errors: string[] = [];

    // Crunchbase requires authentication for most data
    // We'll scrape their public company pages
    const searchUrl = `https://www.crunchbase.com/discover/organizations/featured`;
    const html = await fetchPage(searchUrl);

    if (!html) {
        errors.push('Failed to fetch Crunchbase');
        return { companies, nextPageUrl: null, totalFound: 0, errors };
    }

    const $ = cheerio.load(html);

    // Parse public company cards
    $('[data-type="company"]').each((_, element) => {
        const $el = $(element);
        const name = $el.find('.identifier-label').text().trim();
        const description = $el.find('.description').text().trim();
        const link = $el.find('a.identifier-link').attr('href');

        if (name) {
            companies.push({
                name,
                domain: '',
                website: link ? `https://www.crunchbase.com${link}` : '',
                description: description || null,
                category: null,
                tags: [],
                sourceUrl: searchUrl,
                source: 'crunchbase',
            });
        }
    });

    hunterLogger.info('Scraped Crunchbase', { query, found: companies.length });

    return {
        companies,
        nextPageUrl: null,
        totalFound: companies.length,
        errors,
    };
}

/**
 * Enriches scraped companies with MX record information
 */
export async function enrichWithMxRecords(
    companies: ScrapedCompany[]
): Promise<Array<ScrapedCompany & { mxRecords: MxRecord[]; emailProvider: string | null }>> {
    const enriched: Array<ScrapedCompany & { mxRecords: MxRecord[]; emailProvider: string | null }> =
        [];

    for (const company of companies) {
        if (!company.domain) {
            enriched.push({
                ...company,
                mxRecords: [],
                emailProvider: null,
            });
            continue;
        }

        try {
            const mxRecords = await resolveMxRecords(company.domain);
            const emailProvider = identifyEmailProvider(mxRecords);

            enriched.push({
                ...company,
                mxRecords,
                emailProvider,
            });

            hunterLogger.debug('Enriched company with MX records', {
                domain: company.domain,
                provider: emailProvider,
            });
        } catch (error) {
            hunterLogger.warn('Failed to enrich MX records', { domain: company.domain, error });
            enriched.push({
                ...company,
                mxRecords: [],
                emailProvider: null,
            });
        }

        // Small delay between DNS lookups
        await new Promise((resolve) => setTimeout(resolve, 50));
    }

    return enriched;
}

/**
 * Converts scraped companies to lead format with ML-based scoring
 * FIX-500-325: Returns Lead[] instead of Partial<Lead>[]. All required fields
 * are populated by this function, so there's no reason to use Partial — that
 * forced unsafe casts in the caller.
 */
export function scrapedToLeads(
    scrapedCompanies: Array<
        ScrapedCompany & { mxRecords: MxRecord[]; emailProvider: string | null }
    >,
    tenantId: string,
    enrichmentData?: Map<string, EnrichmentResult>
): Lead[] {
    return scrapedCompanies.map((company) => {
        // Get enrichment data for this company if available
        const enrichment = enrichmentData?.get(company.domain) || null;

        // Calculate ML-based lead score
        const score = calculateLeadScore(company, enrichment);

        const now = new Date();
        return {
            id: generateId('lead'),
            tenantId,
            companyName: company.name,
            domain: company.domain,
            website: company.website || null,
            email: null,
            emailVerified: false,
            phone: null,
            industry: company.category,
            employeeCount: null,
            revenue: null,
            technologies: [] as string[],
            socialProfiles: [] as Lead['socialProfiles'],
            location: null,
            source: company.source,
            sourceUrl: company.sourceUrl,
            score, // ML-based score (0-100)
            status: 'new' as const,
            stage: 'prospect' as const,
            assignedTo: null,
            tags: company.tags,
            customFields: {
                description: company.description,
            } as Record<string, unknown>,
            mxRecords: company.mxRecords,
            emailProvider: company.emailProvider,
            lastContactedAt: null,
            nextFollowUpAt: null,
            createdAt: now,
            updatedAt: now,
        };
    });
}

/**
 * Runs a full discovery job
 */
export async function runDiscoveryJob(options: {
    tenantId: string;
    sources: Array<'product_hunt' | 'g2' | 'capterra' | 'crunchbase'>;
    categories: string[];
    maxPagesPerSource: number;
}): Promise<{
    leads: Lead[];
    stats: {
        totalScraped: number;
        totalWithMx: number;
        byProvider: Record<string, number>;
        bySource: Record<string, number>;
        errors: string[];
    };
}> {
    const allCompanies: Array<
        ScrapedCompany & { mxRecords: MxRecord[]; emailProvider: string | null }
    > = [];
    const errors: string[] = [];
    const bySource: Record<string, number> = {};

    for (const source of options.sources) {
        for (const category of options.categories) {
            let result: ScrapeResult;

            switch (source) {
                case 'product_hunt':
                    result = await scrapeProductHunt(category, options.maxPagesPerSource);
                    break;
                case 'g2':
                    result = await scrapeG2(category, options.maxPagesPerSource);
                    break;
                case 'capterra':
                    result = await scrapeCapterra(category, options.maxPagesPerSource);
                    break;
                case 'crunchbase':
                    result = await scrapeCrunchbase(category, options.maxPagesPerSource);
                    break;
            }

            errors.push(...result.errors);
            bySource[source] = (bySource[source] || 0) + result.companies.length;

            // Enrich with MX records
            const enriched = await enrichWithMxRecords(result.companies);
            allCompanies.push(...enriched);
        }
    }

    // Deduplicate by domain
    const seenDomains = new Set<string>();
    const uniqueCompanies = allCompanies.filter((c) => {
        if (!c.domain || seenDomains.has(c.domain)) {
            return false;
        }
        seenDomains.add(c.domain);
        return true;
    });

    // Calculate stats
    const totalWithMx = uniqueCompanies.filter((c) => c.mxRecords.length > 0).length;
    const byProvider: Record<string, number> = {};

    for (const company of uniqueCompanies) {
        if (company.emailProvider) {
            byProvider[company.emailProvider] = (byProvider[company.emailProvider] || 0) + 1;
        }
    }

    // Convert to leads
    const leads = scrapedToLeads(uniqueCompanies, options.tenantId);

    return {
        leads,
        stats: {
            totalScraped: allCompanies.length,
            totalWithMx,
            byProvider,
            bySource,
            errors,
        },
    };
}

/**
 * Exports leads to CSV format
 */
export function exportLeadsToCsv(
    leads: Lead[]
): string {
    const headers = [
        'Company Name',
        'Domain',
        'Website',
        'Email',
        'Email Provider',
        'Industry',
        'Source',
        'MX Records',
        'Score',
        'Status',
        'Stage',
    ];

    const rows = leads.map((lead) => [
        lead.companyName || '',
        lead.domain || '',
        lead.website || '',
        lead.email || '',
        lead.emailProvider || '',
        lead.industry || '',
        lead.source || '',
        (lead.mxRecords || []).map((mx) => mx.exchange).join('; '),
        String(lead.score || 0),
        lead.status || '',
        lead.stage || '',
    ]);

    const csvContent = [
        headers.join(','),
        ...rows.map((row) =>
            row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ),
    ].join('\n');

    return csvContent;
}
