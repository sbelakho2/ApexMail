/**
 * Edge Cases Routes
 * 
 * HTTP endpoints for email edge case handling
 */

import { Hono } from 'hono';
import { EAIService } from '../services/eai.js';
import { AttachmentService, Attachment } from '../services/attachment.js';
import { CalendarService, CalendarMethod, CalendarStatus, AttendeeRole, AttendeePartStat } from '../services/calendar.js';
import { DeliveryService } from '../services/delivery.js';

export function createEdgeCaseRoutes(
  eai: EAIService,
  attachments: AttachmentService,
  calendar: CalendarService,
  delivery: DeliveryService
): Hono {
  const app = new Hono();

  // ==================== EAI (Internationalized Email) Routes ====================

  /**
   * Validate email address with EAI support
   */
  app.post('/eai/validate', async (c) => {
    const body = await c.req.json();
    const { email, emails } = body;

    if (emails && Array.isArray(emails)) {
      const result = await eai.validateEmailAddresses(emails);
      if (!result.ok) {
        return c.json({ error: result.error.message }, 500);
      }
      return c.json({ results: result.value });
    }

    if (email) {
      const result = await eai.validateEmail(email);
      if (!result.ok) {
        return c.json({ error: result.error.message }, 500);
      }
      return c.json(result.value);
    }

    return c.json({ error: 'Email or emails array required' }, 400);
  });

  /**
   * Parse email address
   */
  app.post('/eai/parse', async (c) => {
    const body = await c.req.json();
    const { email, displayName } = body;

    if (!email) {
      return c.json({ error: 'Email required' }, 400);
    }

    const result = await eai.parseEmailAddress(email, displayName);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value);
  });

  /**
   * Normalize Unicode content
   */
  app.post('/eai/normalize', async (c) => {
    const body = await c.req.json();
    const { content, charset } = body;

    if (!content) {
      return c.json({ error: 'Content required' }, 400);
    }

    const normalized = eai.normalizeContent(content, charset);
    return c.json(normalized);
  });

  // ==================== Attachment Routes ====================

  /**
   * Validate attachments
   */
  app.post('/attachments/validate', async (c) => {
    const body = await c.req.json();
    const { attachments: attachmentList } = body;

    if (!attachmentList || !Array.isArray(attachmentList)) {
      return c.json({ error: 'Attachments array required' }, 400);
    }

    // Convert base64 content to buffers
    const processedAttachments: Attachment[] = attachmentList.map((att: any) => ({
      filename: att.filename,
      contentType: att.contentType || 'application/octet-stream',
      content: Buffer.from(att.content, 'base64'),
      size: att.size || Buffer.from(att.content, 'base64').length,
      disposition: att.disposition || 'attachment',
      contentId: att.contentId,
    }));

    const result = await attachments.validateAttachments(processedAttachments);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Pre-check message size
   */
  app.post('/attachments/size-check', async (c) => {
    const body = await c.req.json();
    const { bodySize, htmlSize, attachments: attachmentSizes } = body;

    if (typeof bodySize !== 'number') {
      return c.json({ error: 'bodySize (number) required' }, 400);
    }

    const sizes = (attachmentSizes || []).map((a: any) => ({
      size: typeof a === 'number' ? a : a.size,
    }));

    const result = attachments.validateMessageSize(bodySize, sizes, htmlSize);
    
    if (!result.isValid) {
      return c.json({
        error: result.error,
        estimatedSize: result.estimatedSize,
        maxSize: result.maxSize,
      }, 413);
    }

    return c.json({
      valid: true,
      estimatedSize: result.estimatedSize,
      maxSize: result.maxSize,
    });
  });

  /**
   * Get attachment stats
   */
  app.post('/attachments/stats', async (c) => {
    const body = await c.req.json();
    const { attachments: attachmentList } = body;

    if (!attachmentList || !Array.isArray(attachmentList)) {
      return c.json({ error: 'Attachments array required' }, 400);
    }

    const processedAttachments: Attachment[] = attachmentList.map((att: any) => ({
      filename: att.filename,
      contentType: att.contentType || 'application/octet-stream',
      content: Buffer.alloc(0),
      size: att.size || 0,
      disposition: att.disposition || 'attachment',
    }));

    const stats = attachments.getAttachmentStats(processedAttachments);
    return c.json(stats);
  });

  // ==================== Calendar Routes ====================

  /**
   * Create calendar invite
   */
  app.post('/calendar/invite', async (c) => {
    const body = await c.req.json();

    const result = await calendar.createInvite({
      summary: body.summary,
      description: body.description,
      location: body.location,
      start: new Date(body.start),
      end: new Date(body.end),
      allDay: body.allDay || false,
      timezone: body.timezone,
      organizer: body.organizer,
      attendees: (body.attendees || []).map((a: any) => ({
        email: a.email,
        name: a.name,
        role: a.role || AttendeeRole.REQ_PARTICIPANT,
        partStat: a.partStat || AttendeePartStat.NEEDS_ACTION,
        rsvp: a.rsvp !== false,
      })),
      method: body.method || CalendarMethod.REQUEST,
      status: body.status || CalendarStatus.CONFIRMED,
      url: body.url,
      categories: body.categories,
      recurrence: body.recurrence,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({
      uid: result.value.event.uid,
      icsContent: result.value.icsContent,
      htmlPreview: result.value.htmlPreview,
    });
  });

  /**
   * Parse ICS content
   */
  app.post('/calendar/parse', async (c) => {
    const body = await c.req.json();
    const { icsContent } = body;

    if (!icsContent) {
      return c.json({ error: 'ICS content required' }, 400);
    }

    const result = calendar.parseICS(icsContent);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value);
  });

  /**
   * Generate ICS from event
   */
  app.post('/calendar/generate-ics', async (c) => {
    const body = await c.req.json();

    const result = await calendar.createInvite(body);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    c.header('Content-Type', 'text/calendar');
    c.header('Content-Disposition', `attachment; filename="invite.ics"`);
    return c.text(result.value.icsContent);
  });

  // ==================== Delivery Routes ====================

  /**
   * Parse SMTP response
   */
  app.post('/delivery/parse-response', async (c) => {
    const body = await c.req.json();
    const { code, message } = body;

    if (typeof code !== 'number' || typeof message !== 'string') {
      return c.json({ error: 'Code (number) and message (string) required' }, 400);
    }

    const response = delivery.parseSMTPResponse(code, message);
    return c.json(response);
  });

  /**
   * Calculate retry schedule
   */
  app.post('/delivery/retry-schedule', async (c) => {
    const body = await c.req.json();
    const { code, message, currentAttempt } = body;

    if (typeof code !== 'number' || typeof message !== 'string') {
      return c.json({ error: 'Code and message required' }, 400);
    }

    const response = delivery.parseSMTPResponse(code, message);
    const schedule = delivery.calculateRetrySchedule(response, currentAttempt || 0);

    if (!schedule) {
      return c.json({ shouldRetry: false });
    }

    return c.json({
      shouldRetry: true,
      ...schedule,
    });
  });

  /**
   * Detect email loop
   */
  app.post('/delivery/detect-loop', async (c) => {
    const body = await c.req.json();
    const { receivedHeaders } = body;

    if (!receivedHeaders || !Array.isArray(receivedHeaders)) {
      return c.json({ error: 'Received headers array required' }, 400);
    }

    const result = delivery.detectLoop(receivedHeaders);
    return c.json(result);
  });

  /**
   * Detect auto-responder
   */
  app.post('/delivery/detect-autoresponder', async (c) => {
    const body = await c.req.json();
    const { headers, subject, body: messageBody } = body;

    if (!headers || typeof subject !== 'string') {
      return c.json({ error: 'Headers object and subject required' }, 400);
    }

    const headersMap = new Map(Object.entries(headers));
    const result = delivery.detectAutoResponder(headersMap, subject, messageBody);

    return c.json(result);
  });

  /**
   * Resolve MX records
   */
  app.get('/delivery/mx/:domain', async (c) => {
    const domain = c.req.param('domain');

    const result = await delivery.resolveMX(domain);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 404);
    }

    return c.json({ mxRecords: result.value });
  });

  /**
   * Get delivery history
   */
  app.get('/delivery/history/:messageId', async (c) => {
    const messageId = c.req.param('messageId');

    const result = await delivery.getDeliveryHistory(messageId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ attempts: result.value });
  });

  /**
   * Schedule greylist retry
   */
  app.post('/delivery/greylist-retry', async (c) => {
    const body = await c.req.json();
    const { messageId, delay } = body;

    if (!messageId) {
      return c.json({ error: 'Message ID required' }, 400);
    }

    const result = await delivery.scheduleGreylistRetry(messageId, delay || 300000);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ retryAt: result.value });
  });

  /**
   * Check if domain is known for greylisting
   */
  app.get('/delivery/greylist-check/:domain', async (c) => {
    const domain = c.req.param('domain');

    const isGreylister = await delivery.isKnownGreylister(domain);
    return c.json({ domain, isKnownGreylister: isGreylister });
  });

  return app;
}
