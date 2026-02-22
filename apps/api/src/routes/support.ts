/**
 * Support Tickets Routes - Customer-facing ticket system
 *
 * Endpoints:
 *   GET    /support/tickets          - List caller's tickets
 *   GET    /support/tickets/:id      - Get single ticket with messages
 *   POST   /support/tickets          - Create ticket (enforces subject + category)
 *   POST   /support/tickets/:id/messages - Add message to ticket
 *   POST   /support/tickets/:id/chatbot  - AI chatbot auto-reply
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { SupportTicketsRepository, type TicketCategory, type TicketPriority } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';

/* ------------------------------------------------------------------ */
/*  Validation schemas                                                 */
/* ------------------------------------------------------------------ */

const VALID_CATEGORIES: TicketCategory[] = ['billing', 'technical', 'feature_request', 'bug', 'general'];
const VALID_PRIORITIES: TicketPriority[] = ['low', 'medium', 'high', 'urgent'];

const createTicketSchema = z.object({
  subject: z.string()
    .min(5, 'Subject must be at least 5 characters')
    .max(200, 'Subject must be at most 200 characters')
    .trim(),
  description: z.string()
    .min(10, 'Description must be at least 10 characters')
    .max(5000, 'Description must be at most 5000 characters')
    .trim(),
  category: z.enum(VALID_CATEGORIES as [string, ...string[]], {
    required_error: 'Category is required',
    invalid_type_error: `Category must be one of: ${VALID_CATEGORIES.join(', ')}`,
  }),
  priority: z.enum(VALID_PRIORITIES as [string, ...string[]]).optional().default('medium'),
});

const addMessageSchema = z.object({
  content: z.string()
    .min(1, 'Message cannot be empty')
    .max(5000, 'Message must be at most 5000 characters')
    .trim(),
  attachments: z.array(z.string().url()).max(5).optional(),
});

/* ------------------------------------------------------------------ */
/*  Chatbot knowledge base                                             */
/* ------------------------------------------------------------------ */

interface KBEntry {
  keywords: string[];
  answer: string;
}

const KNOWLEDGE_BASE: KBEntry[] = [
  {
    keywords: ['domain', 'verify', 'dns', 'spf', 'dkim', 'dmarc'],
    answer: 'To verify your sending domain, go to Settings → Domains, add your domain, and configure the DNS records shown (SPF, DKIM, DMARC). Verification typically takes a few minutes. If you need help with specific DNS records, please provide your domain name and we can guide you through the setup.',
  },
  {
    keywords: ['rate limit', 'sending limit', 'throttl', 'too many'],
    answer: 'Email sending limits are monthly by plan: Free 3,000/mo, Starter 50,000/mo, Pro 150,000/mo, Growth 500,000/mo, Scale 2,000,000/mo, Enterprise 5,000,000/mo. API rate limits are 1,000 requests/min for all plans. You can check your current usage in the Dashboard, and upgrade in Billing if you need higher limits.',
  },
  {
    keywords: ['bounce', 'bounced', 'hard bounce', 'soft bounce'],
    answer: 'ApexMail automatically processes bounces and adds hard-bounced addresses to your suppression list. Soft bounces are retried up to 3 times. You can view bounce details in Reports → Bounces and manage your suppression list in Compliance → Suppressions.',
  },
  {
    keywords: ['webhook', 'webhooks', 'event', 'callback'],
    answer: 'To set up webhooks, go to Settings → API & Webhooks. Add your endpoint URL and select the events you want to receive (delivered, opened, clicked, bounced, complained, unsubscribed). We recommend verifying webhook signatures for security.',
  },
  {
    keywords: ['api key', 'api token', 'authentication', 'auth'],
    answer: 'You can manage API keys in Settings → API & Webhooks. Create a new key, set its scopes (send, read, admin), and copy it immediately — it cannot be shown again. Use the key in the `X-API-Key` header: `X-API-Key: YOUR_API_KEY`.',
  },
  {
    keywords: ['billing', 'invoice', 'payment', 'charge', 'subscription', 'plan', 'upgrade', 'downgrade'],
    answer: 'You can manage your billing and subscription in the Billing page. View invoices, update your payment method, and change your plan. If you have a billing dispute or need a refund, please describe the issue and our billing team will review it within 24 hours.',
  },
  {
    keywords: ['template', 'email template', 'html', 'design'],
    answer: 'ApexMail supports HTML, MJML, and plain text templates. Go to Templates to create or edit templates. You can use variables like {{firstName}} for personalization. Our template editor includes preview and test-send features.',
  },
  {
    keywords: ['unsubscribe', 'opt-out', 'list-unsubscribe'],
    answer: 'ApexMail automatically adds List-Unsubscribe headers to all marketing emails for compliance. Unsubscribed contacts are moved to the "unsubscribed" status and won\'t receive further emails. You can manage unsubscribe preferences in Compliance.',
  },
  {
    keywords: ['campaign', 'send campaign', 'bulk', 'mass email'],
    answer: 'To send a campaign: 1) Create or select a template, 2) Go to Campaigns → Create Campaign, 3) Select your recipient list, 4) Configure subject and sender, 5) Schedule or send immediately. You can track performance in Reports.',
  },
  {
    keywords: ['deliverability', 'spam', 'inbox', 'reputation'],
    answer: 'To improve deliverability: 1) Verify your domain with SPF, DKIM, and DMARC, 2) Warm up new IPs gradually, 3) Maintain clean lists by removing bounces, 4) Keep complaint rates below 0.1%, 5) Use engaging content to improve open rates.',
  },
];

function findBotAnswer(text: string): string | null {
  const lower = text.toLowerCase();
  let bestMatch: KBEntry | null = null;
  let bestScore = 0;

  for (const entry of KNOWLEDGE_BASE) {
    const score = entry.keywords.filter(kw => lower.includes(kw)).length;
    if (score > bestScore) {
      bestScore = score;
      bestMatch = entry;
    }
  }

  return bestScore >= 1 ? bestMatch!.answer : null;
}

/* ------------------------------------------------------------------ */
/*  Routes                                                             */
/* ------------------------------------------------------------------ */

export function supportRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const repo = new SupportTicketsRepository(ctx.db);

  /* --- GET /support/tickets -------------------------------------- */
  router.get('/tickets', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 100);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const [tickets, total] = await Promise.all([
      repo.findByTenantId(tenantId, limit, offset),
      repo.countByTenantId(tenantId),
    ]);

    return c.json({
      tickets,
      pagination: { total, limit, offset, hasMore: offset + limit < total },
    });
  });

  /* --- GET /support/tickets/:id ---------------------------------- */
  router.get('/tickets/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const ticketId = c.req.param('id');

    const ticket = await repo.findById(ticketId);
    if (!ticket || ticket.tenantId !== tenantId) {
      throw ApiError.notFound('Ticket');
    }

    const messages = await repo.getMessages(ticketId);

    return c.json({ ticket: { ...ticket, messages } });
  });

  /* --- POST /support/tickets ------------------------------------- */
  router.post('/tickets', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const parsed = createTicketSchema.parse(body);

    // Resolve tenant info from context or DB
    let tenantName = 'Unknown';
    let tenantEmail = 'unknown@example.com';

    try {
      const { TenantsRepository } = await import('@apexmail/db');
      const tenantsRepo = new TenantsRepository(ctx.db);
      const tenant = await tenantsRepo.findById(tenantId);
      if (tenant.ok && tenant.value) {
        tenantName = tenant.value.name;
        tenantEmail = (tenant.value.metadata?.contactEmail as string) ?? `${tenant.value.slug}@apexmail.io`;
      }
    } catch {
      ctx.logger.warn('Could not resolve tenant info for ticket', { tenantId });
    }

    const ticket = await repo.create({
      tenantId,
      tenantName,
      tenantEmail,
      subject: parsed.subject,
      description: parsed.description,
      category: parsed.category as TicketCategory,
      priority: parsed.priority as TicketPriority,
    });

    // Add initial description as first message
    await repo.addMessage({
      ticketId: ticket.id,
      content: parsed.description,
      author: tenantName,
      authorType: 'customer',
    });

    // Try auto-reply from chatbot
    const botAnswer = findBotAnswer(`${parsed.subject} ${parsed.description}`);
    if (botAnswer) {
      await repo.addMessage({
        ticketId: ticket.id,
        content: `🤖 **Automated Response**\n\n${botAnswer}\n\n---\n*This is an automated response from our support bot. A human agent will follow up if needed.*`,
        author: 'ApexMail Bot',
        authorType: 'bot',
      });
    }

    const messages = await repo.getMessages(ticket.id);

    return c.json({ ticket: { ...ticket, messages } }, 201);
  });

  /* --- POST /support/tickets/:id/messages ------------------------ */
  router.post('/tickets/:id/messages', async (c) => {
    const tenantId = c.get('tenantId');
    const ticketId = c.req.param('id');
    const body = await c.req.json();
    const parsed = addMessageSchema.parse(body);

    const ticket = await repo.findById(ticketId);
    if (!ticket || ticket.tenantId !== tenantId) {
      throw ApiError.notFound('Ticket');
    }

    if (ticket.status === 'closed') {
      throw ApiError.badRequest('Cannot add messages to a closed ticket', 'TICKET_CLOSED');
    }

    // Resolve author name
    let authorName = 'Customer';
    try {
      const { UsersRepository } = await import('@apexmail/db');
      const usersRepo = new UsersRepository(ctx.db);
      const userId = c.get('userId');
      if (userId) {
        const user = await usersRepo.findById(userId);
        if (user.ok && user.value) authorName = user.value.name;
      }
    } catch {
      // fallback to 'Customer'
    }

    const message = await repo.addMessage({
      ticketId,
      content: parsed.content,
      author: authorName,
      authorType: 'customer',
      attachments: parsed.attachments,
    });

    // Reopen ticket if it was waiting/resolved
    if (ticket.status === 'waiting_on_customer' || ticket.status === 'resolved') {
      await repo.update(ticketId, { status: 'open' });
    }

    // Auto-reply from chatbot
    const botAnswer = findBotAnswer(parsed.content);
    let botMessage = null;
    if (botAnswer) {
      botMessage = await repo.addMessage({
        ticketId,
        content: `🤖 **Automated Response**\n\n${botAnswer}\n\n---\n*This is an automated response. A human agent will follow up if needed.*`,
        author: 'ApexMail Bot',
        authorType: 'bot',
      });
    }

    return c.json({
      message,
      ...(botMessage ? { botReply: botMessage } : {}),
    }, 201);
  });

  /* --- POST /support/tickets/:id/close --------------------------- */
  router.post('/tickets/:id/close', async (c) => {
    const tenantId = c.get('tenantId');
    const ticketId = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const reason = z.string().max(500).optional().parse(body.reason);

    const ticket = await repo.findById(ticketId);
    if (!ticket || ticket.tenantId !== tenantId) {
      throw ApiError.notFound('Ticket');
    }

    if (ticket.status === 'closed') {
      return c.json({ ticket }, 200);
    }

    const closeMessage = reason?.trim()
      ? `Customer closed the ticket. Reason: ${reason.trim()}`
      : 'Customer closed the ticket.';

    await repo.addMessage({
      ticketId,
      content: closeMessage,
      author: 'Customer',
      authorType: 'customer',
    });

    const updated = await repo.update(ticketId, { status: 'closed' });
    const messages = await repo.getMessages(ticketId);

    return c.json({ ticket: { ...updated, messages } }, 200);
  });

  /* --- POST /support/tickets/:id/reopen -------------------------- */
  router.post('/tickets/:id/reopen', async (c) => {
    const tenantId = c.get('tenantId');
    const ticketId = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const reason = z.string().max(500).optional().parse(body.reason);

    const ticket = await repo.findById(ticketId);
    if (!ticket || ticket.tenantId !== tenantId) {
      throw ApiError.notFound('Ticket');
    }

    if (ticket.status !== 'closed') {
      const messages = await repo.getMessages(ticketId);
      return c.json({ ticket: { ...ticket, messages } }, 200);
    }

    const reopenMessage = reason?.trim()
      ? `Customer reopened the ticket. Reason: ${reason.trim()}`
      : 'Customer reopened the ticket.';

    await repo.addMessage({
      ticketId,
      content: reopenMessage,
      author: 'Customer',
      authorType: 'customer',
    });

    const updated = await repo.update(ticketId, { status: 'open' });
    const messages = await repo.getMessages(ticketId);

    return c.json({ ticket: { ...updated, messages } }, 200);
  });

  /* --- POST /support/tickets/:id/chatbot ------------------------- */
  router.post('/tickets/:id/chatbot', async (c) => {
    const tenantId = c.get('tenantId');
    const ticketId = c.req.param('id');
    const body = await c.req.json();
    const question = z.string().min(1).max(2000).parse(body.question);

    const ticket = await repo.findById(ticketId);
    if (!ticket || ticket.tenantId !== tenantId) {
      throw ApiError.notFound('Ticket');
    }

    const botAnswer = findBotAnswer(question);
    if (!botAnswer) {
      return c.json({
        reply: "I'm not sure how to help with that. Let me escalate this to a human agent who can assist you better.",
        escalated: true,
      });
    }

    return c.json({
      reply: botAnswer,
      escalated: false,
    });
  });

  /* --- POST /support/tickets/chatbot-general --------------------- */
  /* General chatbot endpoint - no ticket context required */
  router.post('/tickets/chatbot-general', async (c) => {
    const body = await c.req.json();
    const question = z.string().min(1).max(2000).parse(body.question);

    const botAnswer = findBotAnswer(question);
    if (!botAnswer) {
      return c.json({
        reply: "I'm not sure how to help with that. Would you like to create a support ticket so our team can assist you?",
        escalated: true,
      });
    }

    return c.json({
      reply: botAnswer,
      escalated: false,
    });
  });

  return router;
}
