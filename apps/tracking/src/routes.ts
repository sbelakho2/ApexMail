/**
 * Tracking Routes - Open pixel, click tracking, unsubscribe handling
 * 
 * SECURITY: IP address extraction validates proxy headers against trusted proxy list
 */

import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { TrackingCodec } from './codec.js';
import { EventProcessor } from './processor.js';
import { config } from './config.js';

interface TrackingContext {
  db: Pool;
  redis: Redis;
  logger: Logger;
  codec: TrackingCodec;
  processor: EventProcessor;
}

// 1x1 transparent GIF
const TRANSPARENT_GIF = Buffer.from(config.tracking.pixel.gifBase64, 'base64');

// FIX-062: Pre-compute pixel response headers once at module init instead of
// rebuilding the same object on every request.
const PIXEL_HEADERS: Record<string, string> = {
  'Content-Type': 'image/gif',
  'Content-Length': TRANSPARENT_GIF.length.toString(),
  'Cache-Control': config.tracking.pixel.cacheControl,
  'Pragma': 'no-cache',
  'Expires': '0',
  'Vary': '*',
  'X-Content-Type-Options': 'nosniff',
  // FIX-500-454: Prevent search engines from indexing tracking pixel URLs
  'X-Robots-Tag': 'noindex, nofollow',
};

/**
 * E-190: Bot detection for tracking pixels.
 * Email security scanners (Barracuda, Mimecast, etc.) and email client
 * proxies pre-fetch tracking pixels, inflating open metrics.
 * This function checks the User-Agent against known bot patterns.
 *
 * Returns true if the UA matches a known bot/scanner/proxy pattern.
 */
// FIX-063: Single combined regex instead of 18 separate patterns tested via .some().
// The regex engine can optimize a single alternation internally, and we avoid
// 18 separate RegExp.test() calls per request.
const BOT_UA_PATTERN = /GoogleImageProxy|YahooMailProxy|Barracuda|Mimecast|FireEye|ProofPoint|Symantec|MessageLabs|Trend\s?Micro|Sophos|\bbot\b|\bcrawler\b|\bscanner\b|\bspider\b|\bprefetch\b|link\s?preview|Microsoft\s?Office|ms-office/i;

function isBot(userAgent: string | undefined): boolean {
  if (!userAgent) return false;
  return BOT_UA_PATTERN.test(userAgent);
}

/**
 * SECURITY: Verify that a redirect domain is allowed for a tenant
 * This prevents open redirect attacks where attackers craft links to arbitrary domains
 * through our trusted tracking URLs.
 * 
 * Allowed domains include:
 * - Domains owned by the tenant (from domains table)
 * - Domains in the tenant's allowed redirect domains list (from tenant_settings)
 * - The configured fallback URL's domain
 */
// FIX-500-356: In-memory domain verification cache to avoid Redis round-trips on hot paths
const domainCache = new Map<string, { result: boolean; expiry: number }>();
const DOMAIN_CACHE_TTL_MS = 60_000; // 1 minute in-memory, Redis has 5 min
const DOMAIN_CACHE_MAX_ENTRIES = 10_000;

async function verifyRedirectDomain(
  db: Pool,
  tenantId: string,
  domain: string,
  redis: Redis
): Promise<boolean> {
  // FIX-500-356: Check in-memory cache first
  const memKey = `${tenantId}:${domain}`;
  const memCached = domainCache.get(memKey);
  if (memCached && memCached.expiry > Date.now()) {
    return memCached.result;
  }

  // Check Redis cache (5 minute TTL)
  const cacheKey = `redirect_domain:${tenantId}:${domain}`;
  const cached = await redis.get(cacheKey);
  if (cached !== null) {
    return cached === '1';
  }

  // FIX-500-356: Helper to populate both Redis and in-memory cache for positive results
  const cachePositive = async () => {
    await redis.setex(cacheKey, 300, '1');
    if (domainCache.size >= DOMAIN_CACHE_MAX_ENTRIES) {
      const oldest = domainCache.keys().next().value;
      if (oldest !== undefined) domainCache.delete(oldest);
    }
    domainCache.set(memKey, { result: true, expiry: Date.now() + DOMAIN_CACHE_TTL_MS });
  };

  // Allow the fallback domain
  try {
    const fallbackDomain = new URL(config.tracking.click.fallbackUrl).hostname;
    if (domain === fallbackDomain) {
      await cachePositive();
      return true;
    }
  } catch {
    // Ignore fallback URL parse errors
  }

  // Check tenant's owned domains
  const domainResult = await db.query<{ id: string }>(
    `SELECT id FROM domains WHERE tenant_id = $1 AND domain = $2 LIMIT 1`,
    [tenantId, domain]
  );

  if (domainResult.rows.length > 0) {
    await cachePositive();
    return true;
  }

  // Check if domain matches tenant's allowed redirect patterns
  // Patterns can include wildcards like *.example.com
  const settingsResult = await db.query<{ allowed_redirect_domains: string[] }>(
    `SELECT allowed_redirect_domains FROM tenant_settings WHERE tenant_id = $1`,
    [tenantId]
  );

  const allowedDomains = settingsResult.rows[0]?.allowed_redirect_domains ?? [];
  
  for (const pattern of allowedDomains) {
    if (matchDomainPattern(domain, pattern)) {
      await cachePositive();
      return true;
    }
  }

  // Domain not allowed
  await redis.setex(cacheKey, 300, '0');
  // FIX-500-356: Populate in-memory cache
  if (domainCache.size >= DOMAIN_CACHE_MAX_ENTRIES) {
    const oldest = domainCache.keys().next().value;
    if (oldest !== undefined) domainCache.delete(oldest);
  }
  domainCache.set(memKey, { result: false, expiry: Date.now() + DOMAIN_CACHE_TTL_MS });
  return false;
}

/**
 * Match a domain against a pattern (supports wildcard prefix)
 * Examples:
 * - "example.com" matches "example.com"
 * - "*.example.com" matches "sub.example.com", "a.b.example.com"
 */
function matchDomainPattern(domain: string, pattern: string): boolean {
  // F-212: Case-insensitive domain matching per RFC 4343
  const d = domain.toLowerCase();
  const p = pattern.toLowerCase();
  if (p === d) {
    return true;
  }
  
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // Remove the '*', keep the '.'
    return d.endsWith(suffix) && d.length > suffix.length;
  }
  
  return false;
}

/**
 * SECURITY FIX: Safely extract client IP address with proxy validation
 * Only trusts X-Forwarded-For/X-Real-IP if request comes from a trusted proxy
 * 
 * @param c - Hono context
 * @param connectingIP - Direct socket IP (from c.env.incoming.socket.remoteAddress or similar)
 * @returns The actual client IP address
 */
function getClientIP(c: any): string {
  // Get the direct connecting IP (the IP of the immediate client or proxy)
  // This is the socket-level IP and cannot be spoofed
  const connectingIP = (c.req.raw as any)?.socket?.remoteAddress || 'unknown';
  
  // SECURITY: Get trusted proxy IP ranges from config
  // Configure via TRUSTED_PROXIES env var (comma-separated CIDR ranges)
  // Only trust X-Forwarded-For headers from these IPs
  const trustedProxies = config.tracking.trustedProxies;
  
  // Check if connecting IP is a trusted proxy
  if (!isIPInRanges(connectingIP, trustedProxies)) {
    // Not from a trusted proxy - use the direct IP, ignore headers
    return connectingIP;
  }
  
  // From a trusted proxy - we can trust the forwarded headers
  // X-Forwarded-For format: client, proxy1, proxy2, ...
  const xForwardedFor = c.req.header('x-forwarded-for');
  if (xForwardedFor) {
    // Get the leftmost IP that isn't a trusted proxy
    const ips = xForwardedFor.split(',').map((ip: string) => ip.trim());
    for (const ip of ips) {
      if (!isIPInRanges(ip, trustedProxies)) {
        return ip;
      }
    }
  }
  
  // Check X-Real-IP (typically set by nginx)
  const xRealIP = c.req.header('x-real-ip');
  if (xRealIP) {
    return xRealIP.trim();
  }
  
  // Fallback to connecting IP
  return connectingIP;
}

/**
 * Check if an IP address falls within any of the given CIDR ranges
 */
function isIPInRanges(ip: string, ranges: string[]): boolean {
  // Handle IPv4-mapped IPv6 addresses
  const normalizedIP = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  
  for (const range of ranges) {
    if (ipInCIDR(normalizedIP, range)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if an IP is within a CIDR range
 * F-176: Fix signed overflow — use unsigned right shift (>>>) throughout
 */
function ipInCIDR(ip: string, cidr: string): boolean {
  const [rangeIP, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr || '32', 10);
  
  if (!rangeIP || prefix < 0 || prefix > 32) {
    return false;
  }
  
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(rangeIP);
  
  if (ipNum === null || rangeNum === null) {
    return false;
  }
  
  if (prefix === 0) return true;
  // Use unsigned shift to prevent signed overflow
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Convert IPv4 address to 32-bit number
 */
function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return null;
  }
  
  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) {
      return null;
    }
    num = (num << 8) | octet;
  }
  return num >>> 0; // Convert to unsigned
}

export function createRoutes(ctx: TrackingContext): Hono {
  const { db, redis, logger, codec, processor } = ctx;
  const app = new Hono();

  /**
   * E-182: Structured request logging middleware.
   * Logs every tracking request with the four fields needed for
   * abuse detection and bot filtering:
   *   1. IP address  — for abuse detection and rate limit correlation
   *   2. User-Agent  — for bot detection (prefetch bots, scanners)
   *   3. Token/ID    — tracking token from path or query parameter
   *   4. Response status — to correlate with error rates
   */
  app.use('*', async (c, next) => {
    // FIX-500-446: Use performance.now() for timing instead of Date.now().
    // performance.now() uses a monotonic clock immune to NTP adjustments,
    // providing sub-millisecond accuracy for duration measurement.
    const startTime = performance.now();
    await next();

    // FIX-500-353: Skip logging for health check endpoints
    const path = c.req.path;
    if (path === '/health' || path === '/ready') return;

    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    const status = c.res.status;
    const ip = getClientIP(c);
    const userAgent = c.req.header('user-agent') ?? 'unknown';
    // Extract tracking token from path param or query param
    const pathParts = path.split('/');
    const trackingToken = pathParts[pathParts.length - 1]?.substring(0, 20) ?? '';
    const method = c.req.method;

    logger.info('tracking.request', {
      method,
      path,
      status,
      durationMs,
      ip,
      userAgent,
      trackingToken: trackingToken ? trackingToken + '...' : 'none',
    });
  });

  // FIX-040: Rate limiting middleware using Redis sliding window
  if (config.rateLimit.enabled) {
    app.use('*', async (c, next) => {
      const ip = getClientIP(c);
      // FIX-500-348: Removed redundant 'tracking:' — Redis keyPrefix already adds it
      const key = `rl:${ip}`;
      const now = Math.floor(Date.now() / 60000); // Current minute
      const windowKey = `${key}:${now}`;
      
      // A-022: Pipeline INCR + EXPIRE for atomicity — avoids a key leaking
      // without a TTL if the process crashes between the two commands.
      const pipeline = redis.pipeline();
      pipeline.incr(windowKey);
      // FIX-500-350: Only set EXPIRE when key is first created (TTL not yet set)
      pipeline.pttl(windowKey);
      const results = await pipeline.exec();
      const count = (results?.[0]?.[1] as number) ?? 0;
      const ttl = (results?.[1]?.[1] as number) ?? -1;
      // Set TTL only when key is new (ttl == -1 means no expiry set)
      if (ttl < 0) {
        await redis.expire(windowKey, 120);
      }
      
      if (count > config.rateLimit.maxRequestsPerMinute) {
        logger.warn('Rate limit exceeded', { ip, count });
        // FIX-500-352: Add Retry-After header per RFC 6585
        c.header('Retry-After', '60');
        // FIX-500-351: Return transparent GIF for pixel/image paths instead of JSON
        const path = c.req.path;
        if (path.includes('/o/') || path.includes('/o.gif') || path.endsWith('.gif')) {
          // FIX-500-444: Reuse the pre-computed module-level TRANSPARENT_GIF
          // instead of re-allocating a Buffer on every rate-limited request.
          return c.body(TRANSPARENT_GIF, 429, {
            'Content-Type': 'image/gif',
            'Content-Length': TRANSPARENT_GIF.length.toString(),
            'Retry-After': '60',
          });
        }
        return c.json({ error: 'Rate limit exceeded' }, 429);
      }
      
      return next();
    });
  }

  /**
   * E-187: Body size limit for POST endpoints (unsubscribe / preferences).
   * Form submissions should be tiny; 10KB is generous. This prevents
   * attackers from sending oversized payloads to tracking endpoints.
   */
  app.use(`${config.tracking.unsubscribe.path}/*`, bodyLimit({
    maxSize: 10 * 1024, // 10 KB
    onError: (c) => c.json({ error: 'Request body too large' }, 413),
  }));
  app.use(`${config.tracking.preferences.path}/*`, bodyLimit({
    maxSize: 10 * 1024, // 10 KB
    onError: (c) => c.json({ error: 'Request body too large' }, 413),
  }));

  // FIX-067: CORS middleware removed from pixel path. Tracking pixels are loaded
  // via <img> tags which are "simple requests" — browsers never send CORS preflight
  // for <img>. The middleware was adding unnecessary headers on every pixel request.

  // =============================================================================
  // OPEN TRACKING PIXEL
  // =============================================================================

  /**
   * FIX-500-445: Shared helper for pixel endpoints — eliminates duplicated
   * validation / bot-detection / open-recording logic between the main pixel
   * route and the /o.gif alternative.
   */
  function handlePixelRequest(trackingId: string | undefined, c: { req: { header: (name: string) => string | undefined } }): void {
    if (!trackingId || trackingId.length < 10 || trackingId.length > 4096) return;

    const userAgent = c.req.header('user-agent');
    const ipAddress = getClientIP(c as Parameters<typeof getClientIP>[0]);

    const botDetected = isBot(userAgent);
    if (botDetected) {
      logger.debug('E-190: Bot detected on open pixel', {
        trackingId: trackingId.substring(0, 20) + '...',
        userAgent,
      });
    }

    logger.debug('Open pixel request', { trackingId: trackingId.substring(0, 20) + '...', botDetected });

    const data = codec.decode(trackingId);

    if (data) {
      if (botDetected) {
        logger.info('E-190: Skipping open recording for bot', {
          messageId: data.messageId,
          userAgent,
        });
      } else {
        processor.recordOpen({
          tenantId: data.tenantId,
          messageId: data.messageId,
          recipient: data.recipient,
          userAgent,
          ipAddress,
        }).catch(err => {
          logger.error('Failed to record open', { error: err instanceof Error ? err.message : 'Unknown' });
        });
      }
    } else {
      logger.warn('Invalid tracking ID', { trackingId: trackingId.substring(0, 20) + '...' });
    }
  }

  app.get(`${config.tracking.pixel.path}/:trackingId`, async (c) => {
    const trackingId = c.req.param('trackingId');
    handlePixelRequest(trackingId, c);

    // F-209: Cache-busting query params (e.g. ?cb=<random>) are accepted and
    // ignored — they make each pixel URL unique so email clients that strip
    // Cache-Control headers still re-fetch the image on every open.
    // No explicit handling needed: Hono ignores unknown query params.

    // Always return the pixel (even for invalid tracking IDs)
    // FIX-062: Use pre-computed PIXEL_HEADERS
    return c.body(TRANSPARENT_GIF, 200, PIXEL_HEADERS);
  });

  // Alternative pixel endpoint without path (just base64 encoded data)
  app.get('/o.gif', async (c) => {
    const trackingId = c.req.query('t');
    handlePixelRequest(trackingId, c);

    // FIX-062: Use pre-computed PIXEL_HEADERS
    return c.body(TRANSPARENT_GIF, 200, PIXEL_HEADERS);
  });

  // =============================================================================
  // CLICK TRACKING
  // =============================================================================
  
  app.get(`${config.tracking.click.path}/:trackingId`, async (c) => {
    const trackingId = c.req.param('trackingId');

    // E-148: Validate trackingId parameter before processing
    if (!trackingId || trackingId.length < 10 || trackingId.length > 4096) {
      logger.warn('Click tracking: invalid trackingId length', {
        length: trackingId?.length ?? 0,
      });
      c.header('Content-Security-Policy', "frame-ancestors 'none'");
      return c.redirect(config.tracking.click.fallbackUrl, config.tracking.click.redirectStatus as 301 | 302 | 303 | 307 | 308);
    }

    const originalUrl = c.req.query('r');
    const userAgent = c.req.header('user-agent');
    // SECURITY FIX: Use validated IP extraction
    const ipAddress = getClientIP(c);

    logger.debug('Click tracking request', { 
      trackingId: trackingId.substring(0, 20) + '...',
      hasOriginalUrl: !!originalUrl,
    });

    // Decode tracking data
    const data = codec.decode(trackingId);
    
    // SECURITY FIX (FIX-041): Prefer the URL from inside the encrypted token
    // over the query parameter, since the query param can be tampered with.
    // The encrypted token's originalUrl is authoritative.
    let redirectUrl: string;
    if (data?.originalUrl) {
      redirectUrl = data.originalUrl;
    } else if (originalUrl) {
      // F-211: decodeURIComponent can throw URIError on malformed percent-encoding
      try {
        redirectUrl = decodeURIComponent(originalUrl);
      } catch {
        redirectUrl = config.tracking.click.fallbackUrl;
      }
    } else {
      redirectUrl = config.tracking.click.fallbackUrl;
    }

    // SECURITY: Validate URL to prevent open redirect vulnerability
    // Without proper validation, attackers could use: /click/xxx?r=https://evil.com
    // to redirect users through our trusted domain to a phishing site
    try {
      const parsed = new URL(redirectUrl);
      // Only allow http/https
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        logger.warn('Click tracking: blocked non-http redirect', { 
          protocol: parsed.protocol,
          trackingId: trackingId.substring(0, 20) + '...',
        });
        redirectUrl = config.tracking.click.fallbackUrl;
      } else if (data) {
        // For valid tracking data, verify the domain is allowed for this tenant
        // This prevents attackers from crafting links to arbitrary domains
        const domainAllowed = await verifyRedirectDomain(db, data.tenantId, parsed.hostname, redis);
        if (!domainAllowed) {
          logger.warn('Click tracking: blocked unauthorized redirect domain', {
            domain: parsed.hostname,
            tenantId: data.tenantId,
            trackingId: trackingId.substring(0, 20) + '...',
          });
          redirectUrl = config.tracking.click.fallbackUrl;
        }
      }
    } catch {
      redirectUrl = config.tracking.click.fallbackUrl;
    }

    if (data) {
      // Record click event asynchronously
      processor.recordClick({
        tenantId: data.tenantId,
        messageId: data.messageId,
        recipient: data.recipient,
        linkId: data.linkId ?? 'unknown',
        linkUrl: redirectUrl,
        userAgent,
        ipAddress,
      }).catch(err => {
        logger.error('Failed to record click', { error: err instanceof Error ? err.message : 'Unknown' });
      });

      // Also store the link URL for analytics
      if (data.linkId) {
        // F-213: Pipeline hset + expire to add 90-day TTL (prevents unbounded Redis memory growth)
        // F-214: Log errors instead of silently swallowing
        const linkKey = `links:${data.tenantId}:${data.messageId}`;
        const pipe = redis.pipeline();
        pipe.hset(linkKey, data.linkId, redirectUrl);
        pipe.expire(linkKey, 86400 * 90);
        pipe.exec().catch((err) => {
          logger.error('Failed to store link URL', { error: err instanceof Error ? err.message : 'Unknown' });
        });
      }
    } else {
      logger.warn('Invalid click tracking ID', { trackingId: trackingId.substring(0, 20) + '...' });
    }

    // FIX-500-455: Prevent click redirect page from being framed (clickjacking protection)
    c.header('Content-Security-Policy', "frame-ancestors 'none'");
    // Redirect to original URL
    return c.redirect(redirectUrl, config.tracking.click.redirectStatus as 301 | 302 | 303 | 307 | 308);
  });

  // =============================================================================
  // ONE-CLICK UNSUBSCRIBE (RFC 8058)
  // =============================================================================
  
  // POST endpoint for List-Unsubscribe-Post header
  app.post(`${config.tracking.unsubscribe.path}/:token`, async (c) => {
    const token = c.req.param('token');

    // E-148: Validate token parameter before processing
    if (!token || token.length < 10 || token.length > 4096) {
      logger.warn('Unsubscribe: invalid token length', { length: token?.length ?? 0 });
      return c.json({ error: 'Invalid token' }, 400);
    }

    const body = (await c.req.text()).trim();
    const userAgent = c.req.header('user-agent');
    // SECURITY FIX: Use validated IP extraction
    const ipAddress = getClientIP(c);

    logger.info('One-click unsubscribe request', { 
      token: token.substring(0, 20) + '...',
      body,
    });

    // Verify the body contains the expected value
    // F-210: Body is trimmed above to handle trailing CRLF/whitespace from email clients
    if (body !== 'List-Unsubscribe=One-Click') {
      logger.warn('Invalid unsubscribe body', { body });
      return c.json({ error: 'Invalid request body' }, 400);
    }

    // Decode token
    const data = codec.verifyUnsubscribeToken(token);
    
    if (!data) {
      logger.warn('Invalid unsubscribe token');
      return c.json({ error: 'Invalid or expired token' }, 400);
    }

    // Find the message to get additional context
    const messageResult = await db.query<{ id: string; tenant_id: string }>(`
      SELECT id, tenant_id FROM messages
      WHERE tenant_id = $1 AND to_address = $2
      ORDER BY created_at DESC LIMIT 1
    `, [data.tenantId, data.recipient]);

    const messageId = messageResult.rows[0]?.id ?? generateId('msg');

    // Record unsubscribe
    await processor.recordUnsubscribe({
      tenantId: data.tenantId,
      messageId,
      recipient: data.recipient,
      reason: 'one-click',
      userAgent,
      ipAddress,
    });

    // Queue webhook notification
    // F-215: Fire-and-forget — don't block HTTP response for webhook queuing
    queueUnsubscribeWebhook(db, data.tenantId, {
      recipient: data.recipient,
      method: 'one-click',
      timestamp: new Date().toISOString(),
    }).catch((err) => {
      logger.error('Failed to queue unsubscribe webhook', { error: err instanceof Error ? err.message : 'Unknown' });
    });

    // Return success (RFC 8058 expects 200)
    return c.json({ success: true });
  });

  // GET endpoint for manual unsubscribe (shows confirmation page)
  app.get(`${config.tracking.unsubscribe.path}/:token`, async (c) => {
    const token = c.req.param('token');

    // E-148: Validate token parameter before processing
    if (!token || token.length < 10 || token.length > 4096) {
      return c.html(renderErrorPage('Invalid or expired unsubscribe link'));
    }

    const confirm = c.req.query('confirm');

    // Decode token
    const data = codec.verifyUnsubscribeToken(token);
    
    if (!data) {
      return c.html(renderErrorPage('Invalid or expired unsubscribe link'));
    }

    // If confirm=1, process the unsubscribe
    if (confirm === '1') {
      const userAgent = c.req.header('user-agent');
      // SECURITY FIX: Use validated IP extraction
      const ipAddress = getClientIP(c);

      const messageResult = await db.query<{ id: string }>(`
        SELECT id FROM messages
        WHERE tenant_id = $1 AND to_address = $2
        ORDER BY created_at DESC LIMIT 1
      `, [data.tenantId, data.recipient]);

      const messageId = messageResult.rows[0]?.id ?? generateId('msg');

      await processor.recordUnsubscribe({
        tenantId: data.tenantId,
        messageId,
        recipient: data.recipient,
        reason: 'link-click',
        userAgent,
        ipAddress,
      });

      // F-215: Fire-and-forget webhook queuing
      queueUnsubscribeWebhook(db, data.tenantId, {
        recipient: data.recipient,
        method: 'link-click',
        timestamp: new Date().toISOString(),
      }).catch((err) => {
        logger.error('Failed to queue unsubscribe webhook', { error: err instanceof Error ? err.message : 'Unknown' });
      });

      return c.html(renderSuccessPage(data.recipient));
    }

    // Show confirmation page
    return c.html(renderConfirmationPage(token, data.recipient));
  });

  // =============================================================================
  // PREFERENCES CENTER
  // =============================================================================
  
  app.get(`${config.tracking.preferences.path}/:token`, async (c) => {
    const token = c.req.param('token');

    // E-148: Validate token parameter before processing
    if (!token || token.length < 10 || token.length > 4096) {
      return c.html(renderErrorPage('Invalid or expired preferences link'));
    }

    // Decode token
    const data = codec.verifyPreferencesToken(token);
    
    if (!data) {
      return c.html(renderErrorPage('Invalid or expired preferences link'));
    }

    // FIX-077: Parallel DB queries — preferences, categories, and suppression check
    // are independent and can be fetched concurrently.
    const normalizedEmail = data.recipient.toLowerCase();
    const [prefsResult, categoriesResult, suppressionResult] = await Promise.all([
      db.query<{ category: string; subscribed: boolean }>(`
        SELECT category, subscribed FROM subscription_preferences
        WHERE tenant_id = $1 AND email = $2
      `, [data.tenantId, normalizedEmail]),
      db.query<{ name: string; description: string }>(`
        SELECT name, description FROM email_categories
        WHERE tenant_id = $1 AND active = true
        ORDER BY display_order
      `, [data.tenantId]),
      db.query(`
        SELECT 1 FROM suppressions
        WHERE tenant_id = $1 AND email = $2
      `, [data.tenantId, normalizedEmail]),
    ]);

    const preferences = new Map(prefsResult.rows.map((r: { category: string; subscribed: boolean }) => [r.category, r.subscribed]));

    // Categories already fetched in parallel above
    const categories = categoriesResult.rows.map((cat: { name: string; description: string }) => ({
      name: cat.name,
      description: cat.description,
      subscribed: preferences.get(cat.name) ?? true, // Default to subscribed
    }));

    // Suppression already fetched in parallel above
    const globallyUnsubscribed = suppressionResult.rows.length > 0;

    return c.html(renderPreferencesPage(token, data.recipient, categories, globallyUnsubscribed));
  });

  app.post(`${config.tracking.preferences.path}/:token`, async (c) => {
    const token = c.req.param('token');

    // E-148: Validate token parameter before processing
    if (!token || token.length < 10 || token.length > 4096) {
      return c.json({ error: 'Invalid token' }, 400);
    }

    const body = await c.req.parseBody();

    // Decode token
    const data = codec.verifyPreferencesToken(token);
    
    if (!data) {
      return c.json({ error: 'Invalid or expired token' }, 400);
    }

    const email = data.recipient.toLowerCase();

    // Handle global unsubscribe
    if (body.unsubscribe_all === 'true') {
      const suppressionId = generateId('sup');
      await db.query(`
        INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at)
        VALUES ($1, $2, $3, 'unsubscribe', 'preferences', NOW())
        ON CONFLICT (tenant_id, email) DO UPDATE SET
          reason = 'unsubscribe',
          subtype = 'preferences',
          updated_at = NOW()
      `, [suppressionId, data.tenantId, email]);

      // F-215: Fire-and-forget webhook queuing
      queueUnsubscribeWebhook(db, data.tenantId, {
        recipient: email,
        method: 'preferences-center',
        timestamp: new Date().toISOString(),
      }).catch((err) => {
        logger.error('Failed to queue unsubscribe webhook', { error: err instanceof Error ? err.message : 'Unknown' });
      });

      return c.redirect(`${config.tracking.preferences.path}/${token}?saved=1`);
    }

    // Handle resubscribe
    if (body.resubscribe_all === 'true') {
      await db.query(`
        DELETE FROM suppressions
        WHERE tenant_id = $1 AND email = $2 AND reason = 'unsubscribe'
      `, [data.tenantId, email]);

      return c.redirect(`${config.tracking.preferences.path}/${token}?saved=1`);
    }

    // Update category preferences
    // B-033: Wrap all category preference updates in a single transaction
    // Previously each category was a separate INSERT/UPDATE; a crash mid-loop
    // would leave preferences in a partial state.
    const categories = Object.keys(body).filter(k => k.startsWith('category_'));
    
    // FIX-500-357: Single multi-row INSERT instead of per-category loop
    if (categories.length > 0) {
      const values: unknown[] = [];
      const placeholders: string[] = [];
      let paramIdx = 1;
      for (const key of categories) {
        const category = key.replace('category_', '');
        const subscribed = body[key] === 'true';
        const prefId = generateId('prf');
        placeholders.push(`($${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, NOW())`);
        values.push(prefId, data.tenantId, email, category, subscribed);
      }
      try {
        await db.query(`
          INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at)
          VALUES ${placeholders.join(', ')}
          ON CONFLICT (tenant_id, email, category) DO UPDATE SET
            subscribed = EXCLUDED.subscribed,
            updated_at = NOW()
        `, values);
      } catch (err) {
        logger.error('Failed to update subscription preferences', { error: err });
      }
    }

    return c.redirect(`${config.tracking.preferences.path}/${token}?saved=1`);
  });

  // =============================================================================
  // HEALTH CHECK
  // =============================================================================
  
  // FIX-500-354: Basic liveness check instead of always returning 200
  let shuttingDown = false;
  process.once('SIGTERM', () => { shuttingDown = true; });
  process.once('SIGINT', () => { shuttingDown = true; });

  app.get('/health', (c) => {
    if (shuttingDown) {
      return c.json({ status: 'shutting_down', service: 'tracking' }, 503);
    }
    return c.json({ status: 'healthy', service: 'tracking' });
  });

  app.get('/ready', async (c) => {
    try {
      // FIX-078: Parallel health checks — DB and Redis are independent
      await Promise.all([db.query('SELECT 1'), redis.ping()]);
      return c.json({ status: 'ready' });
    } catch (error) {
      // E-161: Don't leak internal details (connection strings, stack traces)
      // in the readiness probe response. Log the full error server-side only.
      logger.error('Readiness check failed', { error: error instanceof Error ? error.message : 'Unknown' });
      return c.json({ status: 'not ready' }, 503);
    }
  });

  return app;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// FIX-500-358: Cache webhook IDs per tenant to avoid DB query on every unsubscribe
const webhookCache = new Map<string, { ids: string[]; expiry: number }>();
const WEBHOOK_CACHE_TTL_MS = 60_000; // 1 minute
const WEBHOOK_CACHE_MAX_ENTRIES = 5_000;

async function queueUnsubscribeWebhook(
  db: Pool,
  tenantId: string,
  data: Record<string, unknown>
): Promise<void> {
  // Check cache first
  let webhookIds: string[];
  const cached = webhookCache.get(tenantId);
  if (cached && cached.expiry > Date.now()) {
    webhookIds = cached.ids;
  } else {
    const result = await db.query<{ id: string }>(`
      SELECT id FROM webhooks
      WHERE tenant_id = $1 AND enabled = true
        AND (events @> '"recipient.unsubscribed"'::jsonb OR events @> '"*"'::jsonb)
    `, [tenantId]);
    webhookIds = result.rows.map(r => r.id);
    // Populate cache
    if (webhookCache.size >= WEBHOOK_CACHE_MAX_ENTRIES) {
      const oldest = webhookCache.keys().next().value;
      if (oldest !== undefined) webhookCache.delete(oldest);
    }
    webhookCache.set(tenantId, { ids: webhookIds, expiry: Date.now() + WEBHOOK_CACHE_TTL_MS });
  }

  // F-216: Batch all webhook queue inserts into a single multi-row INSERT
  if (webhookIds.length > 0) {
    const values: unknown[] = [];
    const placeholders: string[] = [];
    let paramIdx = 1;
    for (const webhookId of webhookIds) {
      placeholders.push(`($${paramIdx++}, $${paramIdx++}, $${paramIdx++}, 'recipient.unsubscribed', $${paramIdx++}, 'pending', 1, NOW())`);
      values.push(
        generateId('whj'),
        webhookId,
        tenantId,
        JSON.stringify({
          id: generateId('evt'),
          type: 'recipient.unsubscribed',
          tenantId,
          timestamp: new Date().toISOString(),
          data,
        }),
      );
    }
    await db.query(`
      INSERT INTO webhook_queue (
        id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
      ) VALUES ${placeholders.join(', ')}
    `, values);
  }
}

// =============================================================================
// HTML TEMPLATES
// =============================================================================

function renderErrorPage(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error - ApexMail</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #F8FAFC;
      color: #0F172A;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: #FFFFFF;
      border: 1px solid #E2E8F0;
      border-radius: 18px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
    }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }
    p { color: #475569; line-height: 1.6; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Something went wrong</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

function renderSuccessPage(email: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Unsubscribed - ApexMail</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #F8FAFC;
      color: #0F172A;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: #FFFFFF;
      border: 1px solid #E2E8F0;
      border-radius: 18px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
    }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }
    p { color: #475569; line-height: 1.6; font-weight: 500; }
    .email { color: #0F172A; font-weight: 700; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>You've been unsubscribed</h1>
    <p><span class="email">${escapeHtml(email)}</span> has been removed from our mailing list.</p>
  </div>
</body>
</html>`;
}

function renderConfirmationPage(token: string, email: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Confirm Unsubscribe - ApexMail</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #F8FAFC;
      color: #0F172A;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: #FFFFFF;
      border: 1px solid #E2E8F0;
      border-radius: 18px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
    }
    h1 { font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }
    p { color: #475569; line-height: 1.6; margin-bottom: 24px; font-weight: 500; }
    .email { color: #0F172A; font-weight: 700; display: block; margin-top: 8px; }
    .btn {
      display: inline-block;
      background: #2563EB;
      color: #fff;
      padding: 12px 24px;
      border-radius: 12px;
      text-decoration: none;
      font-weight: 700;
      transition: all 0.2s;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-size: 14px;
    }
    .btn:hover { background: #1742B4; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Confirm Unsubscribe</h1>
    <p>
      Are you sure you want to unsubscribe?
      <span class="email">${escapeHtml(email)}</span>
    </p>
    <a href="${config.tracking.unsubscribe.path}/${token}?confirm=1" class="btn">
      Yes, Unsubscribe Me
    </a>
  </div>
</body>
</html>`;
}

function renderPreferencesPage(
  token: string,
  email: string,
  categories: Array<{ name: string; description: string; subscribed: boolean }>,
  globallyUnsubscribed: boolean
): string {
  const categoryHtml = categories.map(cat => `
    <label class="pref-item">
      <input type="hidden" name="category_${escapeHtml(cat.name)}" value="false">
      <input type="checkbox" name="category_${escapeHtml(cat.name)}" value="true" 
             ${cat.subscribed ? 'checked' : ''} ${globallyUnsubscribed ? 'disabled' : ''}>
      <div class="pref-info">
        <span class="pref-name">${escapeHtml(cat.name)}</span>
        <span class="pref-desc">${escapeHtml(cat.description)}</span>
      </div>
    </label>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Preferences - ApexMail</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #F8FAFC;
      color: #0F172A;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: #FFFFFF;
      border: 1px solid #E2E8F0;
      border-radius: 18px;
      padding: 40px;
      max-width: 500px;
      width: 100%;
      color: #0F172A;
    }
    h1 { font-size: 24px; margin-bottom: 8px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }
    .subtitle { color: #475569; margin-bottom: 24px; font-weight: 500; }
    .email { color: #0F172A; font-weight: 700; }
    .section { margin-bottom: 24px; }
    .section-title { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #64748B; margin-bottom: 12px; }
    .pref-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px;
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 10px;
      margin-bottom: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .pref-item:hover { background: #F1F5F9; border-color: #CBD5E1; }
    .pref-item input[type="checkbox"] {
      margin-top: 4px;
      accent-color: #2563EB;
    }
    .pref-info { flex: 1; }
    .pref-name { display: block; font-weight: 700; margin-bottom: 2px; color: #0F172A; }
    .pref-desc { display: block; font-size: 14px; color: #64748B; font-weight: 500; }
    .btn {
      display: inline-block;
      padding: 12px 24px;
      border-radius: 12px;
      font-weight: 700;
      text-decoration: none;
      border: none;
      cursor: pointer;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      transition: all 0.2s;
    }
    .btn-primary { background: #2563EB; color: #fff; }
    .btn-primary:hover { background: #1742B4; }
    .btn-danger { background: #FFFFFF; color: #EF4444; border: 1px solid #FECACA; }
    .btn-danger:hover { background: #FEF2F2; border-color: #EF4444; }
    .btn-success { background: #16A34A; color: #fff; }
    .btn-success:hover { background: #15803D; }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; }
    .divider { border-top: 1px solid #E2E8F0; margin: 24px 0; }
    .alert {
      padding: 12px 16px;
      border-radius: 10px;
      margin-bottom: 16px;
      font-size: 14px;
      font-weight: 500;
    }
    .alert-warning { background: #FFFBEB; border: 1px solid #FEF3C7; color: #92400E; }
    .alert-success { background: #F0FDF4; border: 1px solid #DCFCE7; color: #166534; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Email Preferences</h1>
    <p class="subtitle">Manage your subscriptions for <span class="email">${escapeHtml(email)}</span></p>
    
    ${globallyUnsubscribed ? `
      <div class="alert alert-warning">
        You are currently unsubscribed from all emails. Click "Resubscribe" to start receiving emails again.
      </div>
      <form method="POST" action="${config.tracking.preferences.path}/${token}">
        <input type="hidden" name="resubscribe_all" value="true">
        <button type="submit" class="btn btn-success">Resubscribe to All</button>
      </form>
    ` : `
      <form method="POST" action="${config.tracking.preferences.path}/${token}">
        ${categories.length > 0 ? `
          <div class="section">
            <div class="section-title">Email Categories</div>
            ${categoryHtml}
          </div>
          <div class="actions">
            <button type="submit" class="btn btn-primary">Save Preferences</button>
          </div>
        ` : ''}
        
        <div class="divider"></div>
        
        <div class="section">
          <div class="section-title">Unsubscribe</div>
          <p style="color: #64748B; font-size: 14px; margin-bottom: 12px;">
            Stop receiving all emails from this sender.
          </p>
        </div>
      </form>
      <form method="POST" action="${config.tracking.preferences.path}/${token}">
        <input type="hidden" name="unsubscribe_all" value="true">
        <button type="submit" class="btn btn-danger">Unsubscribe from All</button>
      </form>
    `}
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
