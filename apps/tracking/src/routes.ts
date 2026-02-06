/**
 * Tracking Routes - Open pixel, click tracking, unsubscribe handling
 * 
 * SECURITY: IP address extraction validates proxy headers against trusted proxy list
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
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
async function verifyRedirectDomain(
  db: Pool,
  tenantId: string,
  domain: string,
  redis: Redis
): Promise<boolean> {
  // Check cache first (5 minute TTL)
  const cacheKey = `redirect_domain:${tenantId}:${domain}`;
  const cached = await redis.get(cacheKey);
  if (cached !== null) {
    return cached === '1';
  }

  // Allow the fallback domain
  try {
    const fallbackDomain = new URL(config.tracking.click.fallbackUrl).hostname;
    if (domain === fallbackDomain) {
      await redis.setex(cacheKey, 300, '1');
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
    await redis.setex(cacheKey, 300, '1');
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
      await redis.setex(cacheKey, 300, '1');
      return true;
    }
  }

  // Domain not allowed
  await redis.setex(cacheKey, 300, '0');
  return false;
}

/**
 * Match a domain against a pattern (supports wildcard prefix)
 * Examples:
 * - "example.com" matches "example.com"
 * - "*.example.com" matches "sub.example.com", "a.b.example.com"
 */
function matchDomainPattern(domain: string, pattern: string): boolean {
  if (pattern === domain) {
    return true;
  }
  
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // Remove the '*', keep the '.'
    return domain.endsWith(suffix) && domain.length > suffix.length;
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
 */
function ipInCIDR(ip: string, cidr: string): boolean {
  const [rangeIP, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr || '32', 10);
  
  if (!rangeIP) {
    return false;
  }
  
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(rangeIP);
  
  if (ipNum === null || rangeNum === null) {
    return false;
  }
  
  const mask = ~(0xFFFFFFFF >>> prefix);
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

  // FIX-040: Rate limiting middleware using Redis sliding window
  if (config.rateLimit.enabled) {
    app.use('*', async (c, next) => {
      const ip = getClientIP(c);
      const key = `rl:tracking:${ip}`;
      const now = Math.floor(Date.now() / 60000); // Current minute
      const windowKey = `${key}:${now}`;
      
      const count = await redis.incr(windowKey);
      if (count === 1) {
        await redis.expire(windowKey, 120); // 2 min TTL (covers current + next window)
      }
      
      if (count > config.rateLimit.maxRequestsPerMinute) {
        logger.warn('Rate limit exceeded', { ip, count });
        return c.json({ error: 'Rate limit exceeded' }, 429);
      }
      
      return next();
    });
  }

  // CORS for pixel (needed for cross-origin image loading)
  app.use(`${config.tracking.pixel.path}/*`, cors({
    origin: '*',
    allowMethods: ['GET'],
    maxAge: 0,
  }));

  // =============================================================================
  // OPEN TRACKING PIXEL
  // =============================================================================
  
  app.get(`${config.tracking.pixel.path}/:trackingId`, async (c) => {
    const trackingId = c.req.param('trackingId');
    const userAgent = c.req.header('user-agent');
    // SECURITY FIX: Use validated IP extraction instead of blindly trusting headers
    const ipAddress = getClientIP(c);

    logger.debug('Open pixel request', { trackingId: trackingId.substring(0, 20) + '...' });

    // Decode tracking data
    const data = codec.decode(trackingId);
    
    if (data) {
      // Record open event asynchronously (don't block response)
      processor.recordOpen({
        tenantId: data.tenantId,
        messageId: data.messageId,
        recipient: data.recipient,
        userAgent,
        ipAddress,
      }).catch(err => {
        logger.error('Failed to record open', { error: err instanceof Error ? err.message : 'Unknown' });
      });
    } else {
      logger.warn('Invalid tracking ID', { trackingId: trackingId.substring(0, 20) + '...' });
    }

    // Always return the pixel (even for invalid tracking IDs)
    return c.body(TRANSPARENT_GIF, 200, {
      'Content-Type': 'image/gif',
      'Content-Length': TRANSPARENT_GIF.length.toString(),
      'Cache-Control': config.tracking.pixel.cacheControl,
      'Pragma': 'no-cache',
      'Expires': '0',
      // Prevent caching in proxies
      'X-Content-Type-Options': 'nosniff',
    });
  });

  // Alternative pixel endpoint without path (just base64 encoded data)
  app.get('/o.gif', async (c) => {
    const trackingId = c.req.query('t');
    
    if (trackingId) {
      const userAgent = c.req.header('user-agent');
      // SECURITY FIX: Use validated IP extraction
      const ipAddress = getClientIP(c);
      
      const data = codec.decode(trackingId);
      
      if (data) {
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
    }

    return c.body(TRANSPARENT_GIF, 200, {
      'Content-Type': 'image/gif',
      'Content-Length': TRANSPARENT_GIF.length.toString(),
      'Cache-Control': config.tracking.pixel.cacheControl,
    });
  });

  // =============================================================================
  // CLICK TRACKING
  // =============================================================================
  
  app.get(`${config.tracking.click.path}/:trackingId`, async (c) => {
    const trackingId = c.req.param('trackingId');
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
    let redirectUrl = (data?.originalUrl)
      ? data.originalUrl
      : (originalUrl ? decodeURIComponent(originalUrl) : config.tracking.click.fallbackUrl);

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
        redis.hset(`links:${data.tenantId}:${data.messageId}`, data.linkId, redirectUrl).catch(() => {});
      }
    } else {
      logger.warn('Invalid click tracking ID', { trackingId: trackingId.substring(0, 20) + '...' });
    }

    // Redirect to original URL
    return c.redirect(redirectUrl, config.tracking.click.redirectStatus as 301 | 302 | 303 | 307 | 308);
  });

  // =============================================================================
  // ONE-CLICK UNSUBSCRIBE (RFC 8058)
  // =============================================================================
  
  // POST endpoint for List-Unsubscribe-Post header
  app.post(`${config.tracking.unsubscribe.path}/:token`, async (c) => {
    const token = c.req.param('token');
    const body = await c.req.text();
    const userAgent = c.req.header('user-agent');
    // SECURITY FIX: Use validated IP extraction
    const ipAddress = getClientIP(c);

    logger.info('One-click unsubscribe request', { 
      token: token.substring(0, 20) + '...',
      body,
    });

    // Verify the body contains the expected value
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
    await queueUnsubscribeWebhook(db, data.tenantId, {
      recipient: data.recipient,
      method: 'one-click',
      timestamp: new Date().toISOString(),
    });

    // Return success (RFC 8058 expects 200)
    return c.json({ success: true });
  });

  // GET endpoint for manual unsubscribe (shows confirmation page)
  app.get(`${config.tracking.unsubscribe.path}/:token`, async (c) => {
    const token = c.req.param('token');
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

      await queueUnsubscribeWebhook(db, data.tenantId, {
        recipient: data.recipient,
        method: 'link-click',
        timestamp: new Date().toISOString(),
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

    // Decode token
    const data = codec.verifyPreferencesToken(token);
    
    if (!data) {
      return c.html(renderErrorPage('Invalid or expired preferences link'));
    }

    // Get current preferences
    const prefsResult = await db.query<{ category: string; subscribed: boolean }>(`
      SELECT category, subscribed FROM subscription_preferences
      WHERE tenant_id = $1 AND email = $2
    `, [data.tenantId, data.recipient.toLowerCase()]);

    const preferences = new Map(prefsResult.rows.map((r: { category: string; subscribed: boolean }) => [r.category, r.subscribed]));

    // Get available categories for this tenant
    const categoriesResult = await db.query<{ name: string; description: string }>(`
      SELECT name, description FROM email_categories
      WHERE tenant_id = $1 AND active = true
      ORDER BY display_order
    `, [data.tenantId]);

    const categories = categoriesResult.rows.map((cat: { name: string; description: string }) => ({
      name: cat.name,
      description: cat.description,
      subscribed: preferences.get(cat.name) ?? true, // Default to subscribed
    }));

    // Check if globally unsubscribed
    const suppressionResult = await db.query(`
      SELECT 1 FROM suppressions
      WHERE tenant_id = $1 AND email = $2
    `, [data.tenantId, data.recipient.toLowerCase()]);

    const globallyUnsubscribed = suppressionResult.rows.length > 0;

    return c.html(renderPreferencesPage(token, data.recipient, categories, globallyUnsubscribed));
  });

  app.post(`${config.tracking.preferences.path}/:token`, async (c) => {
    const token = c.req.param('token');
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

      await queueUnsubscribeWebhook(db, data.tenantId, {
        recipient: email,
        method: 'preferences-center',
        timestamp: new Date().toISOString(),
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
    const categories = Object.keys(body).filter(k => k.startsWith('category_'));
    
    for (const key of categories) {
      const category = key.replace('category_', '');
      const subscribed = body[key] === 'true';
      
      const prefId = generateId('prf');
      await db.query(`
        INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (tenant_id, email, category) DO UPDATE SET
          subscribed = $5,
          updated_at = NOW()
      `, [prefId, data.tenantId, email, category, subscribed]);
    }

    return c.redirect(`${config.tracking.preferences.path}/${token}?saved=1`);
  });

  // =============================================================================
  // HEALTH CHECK
  // =============================================================================
  
  app.get('/health', (c) => {
    return c.json({ status: 'healthy', service: 'tracking' });
  });

  app.get('/ready', async (c) => {
    try {
      await db.query('SELECT 1');
      await redis.ping();
      return c.json({ status: 'ready' });
    } catch (error) {
      return c.json({ status: 'not ready', error: String(error) }, 503);
    }
  });

  return app;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

async function queueUnsubscribeWebhook(
  db: Pool,
  tenantId: string,
  data: Record<string, unknown>
): Promise<void> {
  const result = await db.query<{ id: string }>(`
    SELECT id FROM webhooks
    WHERE tenant_id = $1 AND enabled = true
      AND (events @> '"recipient.unsubscribed"'::jsonb OR events @> '"*"'::jsonb)
  `, [tenantId]);

  for (const webhook of result.rows) {
    await db.query(`
      INSERT INTO webhook_queue (
        id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
      ) VALUES ($1, $2, $3, 'recipient.unsubscribed', $4, 'pending', 1, NOW())
    `, [
      generateId('whj'),
      webhook.id,
      tenantId,
      JSON.stringify({
        id: generateId('evt'),
        type: 'recipient.unsubscribed',
        tenantId,
        timestamp: new Date().toISOString(),
        data,
      }),
    ]);
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
