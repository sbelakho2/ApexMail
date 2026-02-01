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
    getEmailInfrastructure,
} from './dns-resolver.js';
import type { Lead, LeadSource, MxRecord } from '../types.js';

const logger = createLogger('saas-hunter');

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

/**
 * Fetches a page with proper rate limiting and headers
 */
async function fetchPage(url: string): Promise<string | null> {
    // Check robots.txt
    const allowed = await isUrlAllowed(url);
    if (!allowed) {
        logger.info('URL blocked by robots.txt', { url });
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
            logger.warn('Failed to fetch page', { url, status: response.status });
            return null;
        }

        return await response.text();
    } catch (error) {
        logger.error('Error fetching page', { url, error });
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

        logger.info('Scraped Product Hunt page', { page, found: companies.length });
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

        logger.info('Scraped G2 page', { page, category, found: companies.length });
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

        logger.info('Scraped Capterra page', { page, category, found: companies.length });
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
    maxPages: number = 3
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

    logger.info('Scraped Crunchbase', { query, found: companies.length });

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

            logger.debug('Enriched company with MX records', {
                domain: company.domain,
                provider: emailProvider,
            });
        } catch (error) {
            logger.warn('Failed to enrich MX records', { domain: company.domain, error });
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
 * Converts scraped companies to lead format
 */
export function scrapedToLeads(
    scrapedCompanies: Array<
        ScrapedCompany & { mxRecords: MxRecord[]; emailProvider: string | null }
    >,
    tenantId: string
): Partial<Lead>[] {
    return scrapedCompanies.map((company) => ({
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
        customFields: {
            description: company.description,
        },
        mxRecords: company.mxRecords,
        emailProvider: company.emailProvider,
        lastContactedAt: null,
        nextFollowUpAt: null,
    }));
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
    leads: Partial<Lead>[];
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
    leads: Partial<Lead>[]
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
