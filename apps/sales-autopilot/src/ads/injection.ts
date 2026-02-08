/**
 * Promotional Content Injection
 * Handles dynamic ad slots and affiliate link wrapping
 */

import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import { getDbPool } from '../db.js';
import type {
    PromoConfig,
    PromoType,
    PromoPlacement,
    Lead,
    PipelineStage,
} from '../types.js';

const logger = createLogger({ name: 'promo-injection', level: 'info' });

/**
 * FIX-500-151: L1 in-memory cache backed by Postgres.
 * All mutations write-through to DB; reads fall back to DB when cache misses.
 */
const promoConfigs = new Map<string, PromoConfig>();
const promoStats = new Map<string, { impressions: number; clicks: number; conversions: number }>();
/**
 * FIX-500-100: Secondary index tenantId -> Set of promoIds for O(k)
 * lookup instead of O(n) full scan.
 */
const promosByTenant = new Map<string, Set<string>>();
let cacheLoaded = false;

/**
 * FIX-500-151: Load all promo configs and stats from DB into cache.
 */
async function ensureCacheLoaded(): Promise<void> {
    if (cacheLoaded) return;
    try {
        const pool = getDbPool();
        const { rows } = await pool.query(
            `SELECT c.*, s.impressions, s.clicks, s.conversions
             FROM promo_configs c
             LEFT JOIN promo_stats s ON s.promo_id = c.id`
        );
        for (const row of rows) {
            const promo: PromoConfig = {
                id: row.id,
                tenantId: row.tenant_id,
                name: row.name,
                type: row.type as PromoType,
                placement: row.placement as PromoPlacement,
                content: row.content as PromoConfig['content'],
                targeting: row.targeting as PromoConfig['targeting'],
                schedule: {
                    ...(row.schedule as PromoConfig['schedule']),
                    startDate: (row.schedule as Record<string, unknown>).startDate ? new Date((row.schedule as Record<string, unknown>).startDate as string) : null,
                    endDate: (row.schedule as Record<string, unknown>).endDate ? new Date((row.schedule as Record<string, unknown>).endDate as string) : null,
                },
                stats: {
                    impressions: Number(row.impressions ?? 0),
                    clicks: Number(row.clicks ?? 0),
                    conversions: Number(row.conversions ?? 0),
                },
                active: row.active,
                createdAt: new Date(row.created_at),
                updatedAt: new Date(row.updated_at),
            };
            promoConfigs.set(promo.id, promo);
            promoStats.set(promo.id, { impressions: promo.stats.impressions, clicks: promo.stats.clicks, conversions: promo.stats.conversions });
            let tenantSet = promosByTenant.get(promo.tenantId);
            if (!tenantSet) { tenantSet = new Set(); promosByTenant.set(promo.tenantId, tenantSet); }
            tenantSet.add(promo.id);
        }
        cacheLoaded = true;
        logger.info('Loaded promo configs from DB', { count: rows.length });
    } catch (err) {
        logger.warn('Failed to load promo configs from DB — starting with empty cache', { error: err instanceof Error ? err.message : String(err) });
        cacheLoaded = true; // Don't retry forever
    }
}

/**
 * Creates a new promo configuration
 * FIX-500-151: Persists to DB with write-through cache.
 */
export async function createPromoConfig(
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
): Promise<PromoConfig> {
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
    // FIX-500-100: Maintain tenant secondary index
    let tenantSet = promosByTenant.get(tenantId);
    if (!tenantSet) { tenantSet = new Set(); promosByTenant.set(tenantId, tenantSet); }
    tenantSet.add(promo.id);

    // FIX-500-151: Persist to DB
    try {
        const pool = getDbPool();
        await pool.query(
            `INSERT INTO promo_configs (id, tenant_id, name, type, placement, content, targeting, schedule, active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [promo.id, tenantId, params.name, params.type, params.placement,
             JSON.stringify(promo.content), JSON.stringify(promo.targeting), JSON.stringify(promo.schedule),
             true, promo.createdAt, promo.updatedAt]
        );
        await pool.query(
            `INSERT INTO promo_stats (promo_id, impressions, clicks, conversions) VALUES ($1, 0, 0, 0)`,
            [promo.id]
        );
    } catch (err) {
        logger.error('Failed to persist promo config to DB', { promoId: promo.id, error: err instanceof Error ? err.message : String(err) });
    }

    logger.info('Created promo config', { promoId: promo.id, name: params.name });

    return promo;
}

/**
 * Updates promo config
 * FIX-500-151: Write-through to DB.
 */
export async function updatePromoConfig(
    promoId: string,
    updates: Partial<Omit<PromoConfig, 'id' | 'tenantId' | 'createdAt'>>
): Promise<PromoConfig | null> {
    await ensureCacheLoaded();
    const promo = promoConfigs.get(promoId);
    if (!promo) return null;

    // FIX-500-320: Deep merge nested objects instead of Object.assign which
    // shallow-overwrites, losing sibling keys of nested objects like content,
    // targeting, schedule.
    if (updates.content) {
        promo.content = { ...promo.content, ...updates.content };
    }
    if (updates.targeting) {
        promo.targeting = { ...promo.targeting, ...updates.targeting };
    }
    if (updates.schedule) {
        promo.schedule = { ...promo.schedule, ...updates.schedule };
    }
    if (updates.stats) {
        promo.stats = { ...promo.stats, ...updates.stats };
    }
    // Apply remaining scalar fields
    if (updates.name !== undefined) promo.name = updates.name;
    if (updates.type !== undefined) promo.type = updates.type;
    if (updates.placement !== undefined) promo.placement = updates.placement;
    if (updates.active !== undefined) promo.active = updates.active;
    promo.updatedAt = new Date();

    // FIX-500-151: Persist updates to DB
    try {
        const pool = getDbPool();
        await pool.query(
            `UPDATE promo_configs SET name = $1, type = $2, placement = $3, content = $4,
             targeting = $5, schedule = $6, active = $7, updated_at = $8 WHERE id = $9`,
            [promo.name, promo.type, promo.placement,
             JSON.stringify(promo.content), JSON.stringify(promo.targeting), JSON.stringify(promo.schedule),
             promo.active, promo.updatedAt, promoId]
        );
    } catch (err) {
        logger.error('Failed to update promo in DB', { promoId, error: err instanceof Error ? err.message : String(err) });
    }

    return promo;
}

/**
 * Deletes a promo config
 * FIX-500-151: Also deletes from DB (cascades to promo_stats).
 */
export async function deletePromoConfig(promoId: string): Promise<boolean> {
    // FIX-500-100: Remove from tenant secondary index
    const promo = promoConfigs.get(promoId);
    if (promo) {
        const tenantSet = promosByTenant.get(promo.tenantId);
        if (tenantSet) tenantSet.delete(promoId);
    }
    const deleted = promoConfigs.delete(promoId);

    // FIX-500-151: Delete from DB
    if (deleted) {
        try {
            const pool = getDbPool();
            await pool.query('DELETE FROM promo_configs WHERE id = $1', [promoId]);
        } catch (err) {
            logger.error('Failed to delete promo from DB', { promoId, error: err instanceof Error ? err.message : String(err) });
        }
    }

    return deleted;
}

/**
 * Gets active promos for a tenant
 * FIX-500-100: Uses secondary index promosByTenant for O(k) lookup
 * instead of O(n) full scan.
 * FIX-500-151: Ensures cache is hydrated from DB before reading.
 * FIX-500-448: Verified — tenant-indexed lookup is in place; no further changes needed.
 */
export async function getActivePromos(tenantId: string): Promise<PromoConfig[]> {
    await ensureCacheLoaded();
    const now = new Date();
    const dayOfWeek = now.getDay();

    const ids = promosByTenant.get(tenantId);
    if (!ids || ids.size === 0) return [];

    const results: PromoConfig[] = [];
    for (const id of ids) {
        const promo = promoConfigs.get(id);
        if (!promo) continue;
        if (!promo.active) continue;

        // Check schedule
        if (promo.schedule.startDate && now < promo.schedule.startDate) continue;
        if (promo.schedule.endDate && now > promo.schedule.endDate) continue;
        if (!promo.schedule.daysOfWeek.includes(dayOfWeek)) continue;

        results.push(promo);
    }

    return results;
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
 * FIX-500-151: Ensures cache is hydrated from DB.
 */
export async function selectPromoForLead(
    tenantId: string,
    lead: Lead,
    placement?: PromoPlacement
): Promise<PromoConfig | null> {
    const activePromos = await getActivePromos(tenantId);

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
 * FIX-500-037: HTML-escape user-provided content to prevent XSS in emails.
 */
function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/**
 * Sanitize URLs — only allow http(s) schemes to prevent javascript: injection.
 */
function sanitizeUrl(url: string): string {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return '#';
        }
        return url;
    } catch {
        return '#';
    }
}

/**
 * Generates promo HTML for injection
 */
export function generatePromoHtml(
    promo: PromoConfig,
    trackingParams?: { leadId?: string; campaignId?: string }
): string {
    const trackingUrl = buildTrackingUrl(promo, trackingParams);
    // FIX-500-037: Escape all user-provided content before HTML interpolation
    const safeText = escapeHtml(promo.content.text);
    const safeName = escapeHtml(promo.name);
    const safeCta = promo.content.ctaText ? escapeHtml(promo.content.ctaText) : null;
    const safeImageUrl = promo.content.imageUrl ? sanitizeUrl(promo.content.imageUrl) : null;

    switch (promo.type) {
        case 'banner':
            return `
<div style="background-color: #2563EB; padding: 24px; border-radius: 18px; margin: 24px 0; text-align: center; border: 1px solid #1D4ED8;">
    ${safeImageUrl ? `<img src="${safeImageUrl}" alt="${safeName}" style="max-width: 100%; height: auto; margin-bottom: 12px; border-radius: 12px;">` : ''}
    <p style="color: white; font-size: 17px; margin: 0 0 18px 0; font-family: 'Inter', sans-serif; font-weight: 700; line-height: 1.4; letter-spacing: -0.01em;">${safeText}</p>
    <a href="${trackingUrl}" style="display: inline-block; background: white; color: #2563EB; padding: 12px 28px; border-radius: 12px; text-decoration: none; font-weight: 700; font-family: 'Inter', sans-serif; text-transform: uppercase; font-size: 13px; letter-spacing: 0.05em; transition: all 0.2s;">
        ${safeCta || 'Learn More'}
    </a>
</div>`;

        case 'text_link':
            return `<p style="margin: 18px 0; padding: 12px; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; font-family: 'Inter', sans-serif; font-size: 15px; color: #475569;">
    ${safeText} <a href="${trackingUrl}" style="color: #2563EB; text-decoration: underline; font-weight: 700;">${safeCta || 'Click here'}</a>
</p>`;

        case 'cta_button':
            return `
<div style="text-align: center; margin: 24px 0;">
    <a href="${trackingUrl}" style="display: inline-block; background: #2563EB; color: white; padding: 14px 32px; border-radius: 12px; text-decoration: none; font-weight: 700; font-family: 'Inter', sans-serif; text-transform: uppercase; font-size: 13px; letter-spacing: 0.05em;">
        ${safeCta || safeText}
    </a>
</div>`;

        case 'signature':
            return `
<div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #E2E8F0; font-family: 'Inter', sans-serif; font-size: 13px; color: #64748B;">
    ${safeText} <a href="${trackingUrl}" style="color: #2563EB; font-weight: 700;">${safeCta || 'Learn more'}</a>
</div>`;

        case 'ps_line':
            return `
<p style="margin-top: 24px; font-family: 'Inter', sans-serif; font-size: 15px; font-style: italic; color: #475569; border-left: 3px solid #2563EB; padding-left: 12px;">
    P.S. ${safeText} <a href="${trackingUrl}" style="color: #2563EB; font-weight: 700; font-style: normal;">${safeCta || 'Check it out'}</a>
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

        case 'inline': {
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
        }

        default:
            return htmlContent + promoHtml;
    }
}

/**
 * Records promo impression
 * FIX-500-151: Atomically increments in DB.
 */
export async function recordImpression(promoId: string): Promise<void> {
    const promo = promoConfigs.get(promoId);
    if (promo) {
        promo.stats.impressions++;
    }

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.impressions++;
    }

    try {
        const pool = getDbPool();
        await pool.query(
            'UPDATE promo_stats SET impressions = impressions + 1, updated_at = NOW() WHERE promo_id = $1',
            [promoId]
        );
    } catch (err) {
        logger.error('Failed to record impression in DB', { promoId, error: err instanceof Error ? err.message : String(err) });
    }
}

/**
 * Records promo click
 * FIX-500-151: Atomically increments in DB.
 * FIX-500-311: Returns false if the promo doesn't exist.
 */
export async function recordClick(promoId: string): Promise<boolean> {
    await ensureCacheLoaded();
    const promo = promoConfigs.get(promoId);
    if (!promo) return false;

    promo.stats.clicks++;

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.clicks++;
    }

    try {
        const pool = getDbPool();
        await pool.query(
            'UPDATE promo_stats SET clicks = clicks + 1, updated_at = NOW() WHERE promo_id = $1',
            [promoId]
        );
    } catch (err) {
        logger.error('Failed to record click in DB', { promoId, error: err instanceof Error ? err.message : String(err) });
    }

    logger.debug('Recorded promo click', { promoId });
    return true;
}

/**
 * Records promo conversion
 * FIX-500-151: Atomically increments in DB.
 * FIX-500-311: Returns false if the promo doesn't exist.
 */
export async function recordConversion(promoId: string): Promise<boolean> {
    await ensureCacheLoaded();
    const promo = promoConfigs.get(promoId);
    if (!promo) return false;

    promo.stats.conversions++;

    const stats = promoStats.get(promoId);
    if (stats) {
        stats.conversions++;
    }

    try {
        const pool = getDbPool();
        await pool.query(
            'UPDATE promo_stats SET conversions = conversions + 1, updated_at = NOW() WHERE promo_id = $1',
            [promoId]
        );
    } catch (err) {
        logger.error('Failed to record conversion in DB', { promoId, error: err instanceof Error ? err.message : String(err) });
    }

    logger.info('Recorded promo conversion', { promoId });
    return true;
}

/**
 * Gets promo analytics
 * FIX-500-151: Ensures cache is hydrated from DB.
 */
export async function getPromoAnalytics(
    tenantId: string,
    _options?: {
        startDate?: Date;
        endDate?: Date;
    }
): Promise<{
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
}> {
    await ensureCacheLoaded();
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
