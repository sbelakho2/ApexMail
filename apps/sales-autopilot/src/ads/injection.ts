/**
 * Promotional Content Injection
 * Handles dynamic ad slots and affiliate link wrapping
 */

import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import type {
    PromoConfig,
    PromoType,
    PromoPlacement,
    Lead,
    PipelineStage,
} from '../types.js';

const logger = createLogger('promo-injection');

// In-memory storage
const promoConfigs = new Map<string, PromoConfig>();
const promoStats = new Map<string, { impressions: number; clicks: number; conversions: number }>();

/**
 * Creates a new promo configuration
 */
export function createPromoConfig(
    tenantId: string,
    params: {
        name: string;
        type: PromoType;
        placement: PromoPlacement;
        text: string;
        link: string;
        html?: string;
        imageUrl?: string;
        ctaText?: string;
        targeting?: {
            industries?: string[];
            companySizes?: string[];
            locations?: string[];
            leadStages?: PipelineStage[];
            excludeTags?: string[];
        };
        schedule?: {
            startDate?: Date;
            endDate?: Date;
            daysOfWeek?: number[];
        };
    }
): PromoConfig {
    const promo: PromoConfig = {
        id: generateId('promo'),
        tenantId,
        name: params.name,
        type: params.type,
        placement: params.placement,
        content: {
            text: params.text,
            html: params.html || null,
            link: params.link,
            imageUrl: params.imageUrl || null,
            ctaText: params.ctaText || null,
        },
        targeting: {
            industries: params.targeting?.industries || [],
            companySizes: params.targeting?.companySizes || [],
            locations: params.targeting?.locations || [],
            leadStages: params.targeting?.leadStages || [],
            excludeTags: params.targeting?.excludeTags || [],
        },
        schedule: {
            startDate: params.schedule?.startDate || null,
            endDate: params.schedule?.endDate || null,
            daysOfWeek: params.schedule?.daysOfWeek || [0, 1, 2, 3, 4, 5, 6],
        },
        stats: {
            impressions: 0,
            clicks: 0,
            conversions: 0,
        },
        active: true,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    promoConfigs.set(promo.id, promo);
    promoStats.set(promo.id, { impressions: 0, clicks: 0, conversions: 0 });

    logger.info('Created promo config', { promoId: promo.id, name: params.name });

    return promo;
}

/**
 * Updates promo config
 */
export function updatePromoConfig(
    promoId: string,
    updates: Partial<Omit<PromoConfig, 'id' | 'tenantId' | 'createdAt'>>
): PromoConfig | null {
    const promo = promoConfigs.get(promoId);
    if (!promo) return null;

    Object.assign(promo, updates, { updatedAt: new Date() });
    return promo;
}

/**
 * Deletes a promo config
 */
export function deletePromoConfig(promoId: string): boolean {
    return promoConfigs.delete(promoId);
}

/**
 * Gets active promos for a tenant
 */
export function getActivePromos(tenantId: string): PromoConfig[] {
    const now = new Date();
    const dayOfWeek = now.getDay();

    return Array.from(promoConfigs.values()).filter((promo) => {
        if (promo.tenantId !== tenantId) return false;
        if (!promo.active) return false;

        // Check schedule
        if (promo.schedule.startDate && now < promo.schedule.startDate) return false;
        if (promo.schedule.endDate && now > promo.schedule.endDate) return false;
        if (!promo.schedule.daysOfWeek.includes(dayOfWeek)) return false;

        return true;
    });
}

/**
 * Checks if a lead matches promo targeting
 */
function matchesTargeting(lead: Lead, targeting: PromoConfig['targeting']): boolean {
    // Check industry
    if (
        targeting.industries.length > 0 &&
        lead.industry &&
        !targeting.industries.some((i) =>
            lead.industry!.toLowerCase().includes(i.toLowerCase())
        )
    ) {
        return false;
    }

    // Check company size
    if (
        targeting.companySizes.length > 0 &&
        lead.employeeCount &&
        !targeting.companySizes.includes(lead.employeeCount)
    ) {
        return false;
    }

    // Check location
    if (
        targeting.locations.length > 0 &&
        lead.location?.countryCode &&
        !targeting.locations.includes(lead.location.countryCode)
    ) {
        return false;
    }

    // Check pipeline stage
    if (
        targeting.leadStages.length > 0 &&
        !targeting.leadStages.includes(lead.stage)
    ) {
        return false;
    }

    // Check excluded tags
    if (
        targeting.excludeTags.length > 0 &&
        targeting.excludeTags.some((tag) => lead.tags.includes(tag))
    ) {
        return false;
    }

    return true;
}

/**
 * Selects the best promo for a lead
 */
export function selectPromoForLead(
    tenantId: string,
    lead: Lead,
    placement?: PromoPlacement
): PromoConfig | null {
    const activePromos = getActivePromos(tenantId);

    // Filter by placement if specified
    const candidates = placement
        ? activePromos.filter((p) => p.placement === placement)
        : activePromos;

    // Filter by targeting
    const matchingPromos = candidates.filter((p) =>
        matchesTargeting(lead, p.targeting)
    );

    if (matchingPromos.length === 0) {
        return null;
    }

    // Select promo with best performance (highest CTR)
    // or rotate for even distribution
    return matchingPromos.reduce((best, current) => {
        const bestCtr = best.stats.impressions > 0
            ? best.stats.clicks / best.stats.impressions
            : 0;
        const currentCtr = current.stats.impressions > 0
            ? current.stats.clicks / current.stats.impressions
            : 0;

        // Favor promos with fewer impressions (for A/B testing)
        if (current.stats.impressions < best.stats.impressions * 0.5) {
            return current;
        }

        return currentCtr > bestCtr ? current : best;
    });
}

/**
 * Generates promo HTML for injection
 */
export function generatePromoHtml(
    promo: PromoConfig,
    trackingParams?: { leadId?: string; campaignId?: string }
): string {
    const trackingUrl = buildTrackingUrl(promo, trackingParams);

    switch (promo.type) {
        case 'banner':
            return `
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
    ${promo.content.imageUrl ? `<img src="${promo.content.imageUrl}" alt="${promo.name}" style="max-width: 100%; height: auto; margin-bottom: 10px;">` : ''}
    <p style="color: white; font-size: 16px; margin: 0 0 15px 0;">${promo.content.text}</p>
    <a href="${trackingUrl}" style="display: inline-block; background: white; color: #667eea; padding: 10px 25px; border-radius: 5px; text-decoration: none; font-weight: bold;">
        ${promo.content.ctaText || 'Learn More'}
    </a>
</div>`;

        case 'text_link':
            return `<p style="margin: 15px 0; padding: 10px; background: #f7f7f7; border-radius: 4px;">
    ${promo.content.text} <a href="${trackingUrl}" style="color: #667eea; text-decoration: underline;">${promo.content.ctaText || 'Click here'}</a>
</p>`;

        case 'cta_button':
            return `
<div style="text-align: center; margin: 20px 0;">
    <a href="${trackingUrl}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; border-radius: 5px; text-decoration: none; font-weight: bold;">
        ${promo.content.ctaText || promo.content.text}
    </a>
</div>`;

        case 'signature':
            return `
<p style="margin-top: 20px; font-size: 12px; color: #666;">
    ${promo.content.text} <a href="${trackingUrl}" style="color: #667eea;">${promo.content.ctaText || 'Learn more'}</a>
</p>`;

        case 'ps_line':
            return `
<p style="margin-top: 20px; font-size: 14px; font-style: italic;">
    P.S. ${promo.content.text} <a href="${trackingUrl}" style="color: #667eea;">${promo.content.ctaText || 'Check it out'}</a>
</p>`;

        default:
            return '';
    }
}

/**
 * Builds tracking URL for promo
 */
function buildTrackingUrl(
    promo: PromoConfig,
    params?: { leadId?: string; campaignId?: string }
): string {
    const baseUrl = promo.content.link;
    const url = new URL(baseUrl.startsWith('http') ? baseUrl : `https://${baseUrl}`);

    // Add tracking parameters
    url.searchParams.set('utm_source', 'apexmail');
    url.searchParams.set('utm_medium', 'email');
    url.searchParams.set('utm_campaign', promo.id);

    if (params?.leadId) {
        url.searchParams.set('lead_id', params.leadId);
    }

    if (params?.campaignId) {
        url.searchParams.set('drip_campaign', params.campaignId);
    }

    // Check for affiliate link
    const affiliateLink = config.promo.affiliateLinks[promo.content.link];
    if (affiliateLink) {
        return affiliateLink + (affiliateLink.includes('?') ? '&' : '?') + url.searchParams.toString();
    }

    return url.toString();
}

/**
 * Injects promo into email content
 */
export function injectPromoIntoEmail(
    htmlContent: string,
    promo: PromoConfig,
    trackingParams?: { leadId?: string; campaignId?: string }
): string {
    const promoHtml = generatePromoHtml(promo, trackingParams);

    switch (promo.placement) {
        case 'header':
            // Insert after opening body or at the start
            if (htmlContent.includes('<body')) {
                return htmlContent.replace(
                    /(<body[^>]*>)/i,
                    `$1${promoHtml}`
                );
            }
            return promoHtml + htmlContent;

        case 'footer':
            // Insert before closing body or at the end
            if (htmlContent.includes('</body>')) {
                return htmlContent.replace('</body>', `${promoHtml}</body>`);
            }
            return htmlContent + promoHtml;

        case 'inline':
            // Insert after first paragraph
            const firstParagraphEnd = htmlContent.indexOf('</p>');
            if (firstParagraphEnd > -1) {
                return (
                    htmlContent.slice(0, firstParagraphEnd + 4) +
                    promoHtml +
                    htmlContent.slice(firstParagraphEnd + 4)
                );
            }
            return htmlContent + promoHtml;

        default:
            return htmlContent + promoHtml;
    }
}

/**
 * Records promo impression
 */
export function recordImpression(promoId: string): void {
    const promo = promoConfigs.get(promoId);
    if (promo) {
        promo.stats.impressions++;
    }

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.impressions++;
    }
}

/**
 * Records promo click
 */
export function recordClick(promoId: string): void {
    const promo = promoConfigs.get(promoId);
    if (promo) {
        promo.stats.clicks++;
    }

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.clicks++;
    }

    logger.debug('Recorded promo click', { promoId });
}

/**
 * Records promo conversion
 */
export function recordConversion(promoId: string): void {
    const promo = promoConfigs.get(promoId);
    if (promo) {
        promo.stats.conversions++;
    }

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.conversions++;
    }

    logger.info('Recorded promo conversion', { promoId });
}

/**
 * Gets promo analytics
 */
export function getPromoAnalytics(
    tenantId: string,
    options?: {
        startDate?: Date;
        endDate?: Date;
    }
): {
    promos: Array<{
        id: string;
        name: string;
        impressions: number;
        clicks: number;
        conversions: number;
        ctr: number;
        conversionRate: number;
    }>;
    totals: {
        impressions: number;
        clicks: number;
        conversions: number;
        averageCtr: number;
    };
} {
    const tenantPromos = Array.from(promoConfigs.values()).filter(
        (p) => p.tenantId === tenantId
    );

    const promoAnalytics = tenantPromos.map((promo) => ({
        id: promo.id,
        name: promo.name,
        impressions: promo.stats.impressions,
        clicks: promo.stats.clicks,
        conversions: promo.stats.conversions,
        ctr: promo.stats.impressions > 0
            ? promo.stats.clicks / promo.stats.impressions
            : 0,
        conversionRate: promo.stats.clicks > 0
            ? promo.stats.conversions / promo.stats.clicks
            : 0,
    }));

    const totals = promoAnalytics.reduce(
        (acc, p) => ({
            impressions: acc.impressions + p.impressions,
            clicks: acc.clicks + p.clicks,
            conversions: acc.conversions + p.conversions,
            averageCtr: 0,
        }),
        { impressions: 0, clicks: 0, conversions: 0, averageCtr: 0 }
    );

    totals.averageCtr = totals.impressions > 0
        ? totals.clicks / totals.impressions
        : 0;

    return { promos: promoAnalytics, totals };
}

/**
 * Wraps links with affiliate tracking
 */
export function wrapAffiliateLinks(
    htmlContent: string,
    affiliateMap: Record<string, string>
): string {
    let result = htmlContent;

    for (const [originalUrl, affiliateUrl] of Object.entries(affiliateMap)) {
        // Escape special regex characters in URL
        const escapedUrl = originalUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`href=["']${escapedUrl}["']`, 'gi');
        result = result.replace(regex, `href="${affiliateUrl}"`);
    }

    return result;
}
