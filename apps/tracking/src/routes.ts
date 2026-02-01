/**
 * Tracking Routes - Open pixel, click tracking, unsubscribe handling
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

export function createRoutes(ctx: TrackingContext): Hono {
  const { db, redis, logger, codec, processor } = ctx;
  const app = new Hono();

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
    const ipAddress = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() 
                   || c.req.header('x-real-ip')
                   || 'unknown';

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
      const ipAddress = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() 
                     || c.req.header('x-real-ip')
                     || 'unknown';
      
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
    const ipAddress = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() 
                   || c.req.header('x-real-ip')
                   || 'unknown';

    logger.debug('Click tracking request', { 
      trackingId: trackingId.substring(0, 20) + '...',
      hasOriginalUrl: !!originalUrl,
    });

    // Decode tracking data
    const data = codec.decode(trackingId);
    
    // Determine redirect URL
    let redirectUrl = originalUrl 
      ? decodeURIComponent(originalUrl) 
      : config.tracking.click.fallbackUrl;

    // Validate URL
    try {
      const parsed = new URL(redirectUrl);
      // Only allow http/https
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        redirectUrl = config.tracking.click.fallbackUrl;
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
    const ipAddress = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() 
                   || c.req.header('x-real-ip')
                   || 'unknown';

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
      const ipAddress = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() 
                     || c.req.header('x-real-ip')
                     || 'unknown';

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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
      color: #fff;
    }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; }
    p { color: rgba(255,255,255,0.7); line-height: 1.6; }
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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
      color: #fff;
    }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; }
    p { color: rgba(255,255,255,0.7); line-height: 1.6; }
    .email { color: #fff; font-weight: 500; }
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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
      color: #fff;
    }
    h1 { font-size: 24px; margin-bottom: 16px; }
    p { color: rgba(255,255,255,0.7); line-height: 1.6; margin-bottom: 24px; }
    .email { color: #fff; font-weight: 500; display: block; margin-top: 8px; }
    .btn {
      display: inline-block;
      background: #ef4444;
      color: #fff;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 500;
      transition: background 0.2s;
    }
    .btn:hover { background: #dc2626; }
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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 40px;
      max-width: 500px;
      width: 100%;
      color: #fff;
    }
    h1 { font-size: 24px; margin-bottom: 8px; }
    .subtitle { color: rgba(255,255,255,0.7); margin-bottom: 24px; }
    .email { color: #fff; font-weight: 500; }
    .section { margin-bottom: 24px; }
    .section-title { font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; color: rgba(255,255,255,0.5); margin-bottom: 12px; }
    .pref-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px;
      background: rgba(255,255,255,0.03);
      border-radius: 8px;
      margin-bottom: 8px;
      cursor: pointer;
    }
    .pref-item:hover { background: rgba(255,255,255,0.06); }
    .pref-item input[type="checkbox"] {
      margin-top: 4px;
      accent-color: #3b82f6;
    }
    .pref-info { flex: 1; }
    .pref-name { display: block; font-weight: 500; margin-bottom: 4px; }
    .pref-desc { display: block; font-size: 14px; color: rgba(255,255,255,0.6); }
    .btn {
      display: inline-block;
      padding: 12px 24px;
      border-radius: 8px;
      font-weight: 500;
      text-decoration: none;
      border: none;
      cursor: pointer;
      font-size: 14px;
    }
    .btn-primary { background: #3b82f6; color: #fff; }
    .btn-primary:hover { background: #2563eb; }
    .btn-danger { background: #ef4444; color: #fff; }
    .btn-danger:hover { background: #dc2626; }
    .btn-success { background: #22c55e; color: #fff; }
    .btn-success:hover { background: #16a34a; }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; }
    .divider { border-top: 1px solid rgba(255,255,255,0.1); margin: 24px 0; }
    .alert {
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 16px;
      font-size: 14px;
    }
    .alert-warning { background: rgba(234,179,8,0.2); border: 1px solid rgba(234,179,8,0.3); }
    .alert-success { background: rgba(34,197,94,0.2); border: 1px solid rgba(34,197,94,0.3); }
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
          <p style="color: rgba(255,255,255,0.6); font-size: 14px; margin-bottom: 12px;">
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
