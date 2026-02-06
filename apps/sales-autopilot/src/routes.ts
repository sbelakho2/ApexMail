/**
 * Sales Autopilot API Routes
 * 
 * SECURITY: This API is part of the Control Plane and is protected by:
 * 1. Control Plane API key authentication
 * 2. IP whitelisting in production
 * 3. Explicit blocking of customer API keys
 * 
 * Customers CANNOT access these endpoints even with direct links.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger as honoLogger } from 'hono/logger';
import { createLogger } from '@apexmail/lib';

// Security middleware
import { controlPlaneAuth, blockCustomerAuth } from './middleware/auth.js';

// Import modules
import * as scrapers from './scrapers/index.js';
import * as enrichment from './enrichment/index.js';
import * as campaigns from './campaigns/index.js';
import * as inbox from './inbox/index.js';
import * as crm from './crm/index.js';
import * as calendar from './calendar/index.js';
import * as ads from './ads/index.js';
import type { Lead, LeadFilters, LeadStatus, PipelineStage, MeetingType, PromoType, PromoPlacement, TaskType, TaskPriority } from './types.js';

// Type validation helpers
const LEAD_STATUSES: readonly LeadStatus[] = [
    'new', 'contacted', 'qualified', 'unqualified', 'nurturing', 'converted', 'lost'
] as const;

const PIPELINE_STAGES: readonly PipelineStage[] = [
    'prospect', 'outreach', 'engaged', 'demo_scheduled', 'proposal', 'negotiation', 'closed_won', 'closed_lost'
] as const;

const MEETING_TYPES: readonly MeetingType[] = [
    'demo', 'discovery', 'follow_up', 'onboarding', 'support'
] as const;

const PROMO_TYPES: readonly PromoType[] = [
    'banner', 'text_link', 'cta_button', 'signature', 'ps_line'
] as const;

const PROMO_PLACEMENTS: readonly PromoPlacement[] = [
    'header', 'footer', 'inline', 'sidebar'
] as const;

const TASK_TYPES: readonly TaskType[] = [
    'call', 'email', 'meeting', 'follow_up', 'research', 'other'
] as const;

const TASK_PRIORITIES: readonly TaskPriority[] = [
    'low', 'medium', 'high', 'urgent'
] as const;

function isLeadStatus(value: string | undefined): value is LeadStatus {
    return value !== undefined && LEAD_STATUSES.includes(value as LeadStatus);
}

function isLeadStatusArray(values: string[] | undefined): values is LeadStatus[] {
    return values !== undefined && values.every(v => isLeadStatus(v));
}

function isPipelineStage(value: string | undefined): value is PipelineStage {
    return value !== undefined && PIPELINE_STAGES.includes(value as PipelineStage);
}

function isPipelineStageArray(values: string[] | undefined): values is PipelineStage[] {
    return values !== undefined && values.every(v => isPipelineStage(v));
}

function isMeetingType(value: string | undefined): value is MeetingType {
    return value !== undefined && MEETING_TYPES.includes(value as MeetingType);
}

function isPromoType(value: string | undefined): value is PromoType {
    return value !== undefined && PROMO_TYPES.includes(value as PromoType);
}

function isPromoPlacement(value: string | undefined): value is PromoPlacement {
    return value !== undefined && PROMO_PLACEMENTS.includes(value as PromoPlacement);
}

function isTaskType(value: string | undefined): value is TaskType {
    return value !== undefined && TASK_TYPES.includes(value as TaskType);
}

function isTaskPriority(value: string | undefined): value is TaskPriority {
    return value !== undefined && TASK_PRIORITIES.includes(value as TaskPriority);
}

const logger = createLogger({ name: 'autopilot-api', level: 'info' });

const app = new Hono();

// ==== GLOBAL MIDDLEWARE ====
app.use('*', cors({
    // Only allow Control Plane UI origin in production
    origin: process.env.NODE_ENV === 'production' 
        ? (process.env.CONTROL_PLANE_ORIGIN || 'http://localhost:3020')
        : '*',
    credentials: true,
}));
app.use('*', honoLogger());

// ==== SECURITY: Block customer auth on all routes ====
app.use('*', blockCustomerAuth());

// Health check (public, for orchestration)
app.get('/health', (c) => {
    return c.json({ status: 'healthy', service: 'sales-autopilot' });
});

// ==== PROTECTED ROUTES: Require Control Plane authentication ====
app.use('/api/v1/*', controlPlaneAuth());

// ============================================
// Lead Discovery Routes
// ============================================

app.post('/api/v1/discovery/run', async (c) => {
    const body = await c.req.json<{
        tenantId: string;
        sources: Array<'product_hunt' | 'g2' | 'capterra' | 'crunchbase'>;
        categories: string[];
        maxPagesPerSource?: number;
    }>();

    const result = await scrapers.runDiscoveryJob({
        tenantId: body.tenantId,
        sources: body.sources,
        categories: body.categories,
        maxPagesPerSource: body.maxPagesPerSource || 3,
    });

    // Store leads in CRM
    for (const lead of result.leads) {
        if (lead.id && lead.tenantId && lead.companyName && lead.domain) {
            await crm.storeLead(lead as Lead);
        }
    }

    logger.info('Discovery job completed', { stats: result.stats });

    return c.json({ success: true, data: result });
});

app.get('/api/v1/discovery/mx/:domain', async (c) => {
    const domain = c.req.param('domain');

    const infrastructure = await scrapers.getEmailInfrastructure(domain);

    return c.json({ success: true, data: infrastructure });
});

app.post('/api/v1/discovery/export', async (c) => {
    const body = await c.req.json<{
        tenantId: string;
        filters?: {
            status?: string[];
            stage?: string[];
        };
    }>();

    const leads = await crm.filterLeads(body.tenantId, (body.filters || {}) as LeadFilters);
    const csv = scrapers.exportLeadsToCsv(leads);

    return new Response(csv, {
        headers: {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="leads.csv"',
        },
    });
});

// ============================================
// Enrichment Routes
// ============================================

app.post('/api/v1/enrichment/company', async (c) => {
    const body = await c.req.json<{
        domain: string;
        companyName: string;
        clearbitApiKey?: string;
    }>();

    const result = await enrichment.enrichCompany(
        body.domain,
        body.companyName,
        { clearbitApiKey: body.clearbitApiKey }
    );

    return c.json({ success: true, data: result });
});

app.post('/api/v1/enrichment/batch', async (c) => {
    const body = await c.req.json<{
        companies: Array<{ domain: string; name: string }>;
        clearbitApiKey?: string;
    }>();

    const results = await enrichment.batchEnrichCompanies(body.companies, {
        clearbitApiKey: body.clearbitApiKey,
    });

    return c.json({
        success: true,
        data: Object.fromEntries(results),
    });
});

// ============================================
// Lead Scoring Routes
// ============================================

app.post('/api/v1/scoring/calculate', async (c) => {
    const body = await c.req.json<{
        leadId: string;
    }>();

    const lead = await crm.getLead(body.leadId);
    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    const activities = await crm.getLeadActivities(body.leadId);

    // IMP-010: Include firmographic data when scoring individual leads.
    // Previously passed `null`, ignoring technology stack, employee count,
    // and industry data that can contribute 20-60 points to the score.
    let enrichmentData = null;
    if (lead.domain) {
        try {
            enrichmentData = await enrichment.enrichCompany(lead.domain, lead.companyName || '');
        } catch {
            // Enrichment failure is non-fatal — score without it
        }
    }

    const score = enrichment.calculateLeadScore(lead, enrichmentData, activities);

    // Update lead score
    await crm.updateLead(body.leadId, { score: score.totalScore });

    return c.json({ success: true, data: score });
});

/**
 * IMP-010: Batch lead scoring with bulk activity fetching.
 *
 * Previous implementation:
 *   for (const lead of leads) {
 *       const activities = await crm.getLeadActivities(lead.id);  // N queries
 *       const score = enrichment.calculateLeadScore(lead, null, activities);  // null enrichment
 *   }
 *
 * For 200 leads this was 200 sequential DB queries + 200 ignored enrichment lookups.
 * Now we batch-fetch all activities in one call and enrich all unique domains
 * in parallel, reducing round-trips from ~400 to ~3.
 */
app.get('/api/v1/scoring/top/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const limit = parseInt(c.req.query('limit') || '10', 10);

    const leads = await crm.filterLeads(tenantId, {});

    // Batch fetch activities for all leads at once
    const activitiesMap = new Map<string, Awaited<ReturnType<typeof crm.getLeadActivities>>>();
    await Promise.all(
        leads.map(async (lead) => {
            const activities = await crm.getLeadActivities(lead.id);
            activitiesMap.set(lead.id, activities);
        })
    );

    // Batch enrich unique domains
    const domainLeadMap = new Map<string, string>();
    for (const lead of leads) {
        if (lead.domain && !domainLeadMap.has(lead.domain)) {
            domainLeadMap.set(lead.domain, lead.companyName || '');
        }
    }
    const enrichmentMap = new Map<string, Awaited<ReturnType<typeof enrichment.enrichCompany>>>();
    if (domainLeadMap.size > 0) {
        try {
            const companies = Array.from(domainLeadMap.entries()).map(([domain, name]) => ({ domain, name }));
            const enrichResults = await enrichment.batchEnrichCompanies(companies);
            for (const [domain, result] of enrichResults) {
                enrichmentMap.set(domain, result);
            }
        } catch {
            // Enrichment failure is non-fatal — score without it
        }
    }

    // Use bulk scoring with enrichment data
    const scoredLeads = enrichment.bulkScoreLeads(leads, enrichmentMap, activitiesMap);

    const topLeads = enrichment.getTopLeads(scoredLeads, limit);

    const topLeadDetails = await Promise.all(
        topLeads.map(async (item) => ({
            lead: await crm.getLead(item.leadId),
            score: item.score,
        }))
    );

    return c.json({
        success: true,
        data: topLeadDetails,
    });
});

// ============================================
// Campaign Routes
// ============================================

app.post('/api/v1/campaigns', async (c) => {
    const body = await c.req.json<{
        tenantId: string;
        name: string;
        description?: string;
        fromEmail: string;
        fromName: string;
        replyTo?: string;
        templateId?: string;
    }>();

    // If using a template, clone it
    let sequence: typeof campaigns.campaignTemplates[0]['sequence'] = [];
    if (body.templateId) {
        const template = campaigns.cloneTemplate(body.templateId);
        if (template) {
            sequence = template.sequence;
        }
    }

    const campaign = await campaigns.createCampaign(body.tenantId, {
        name: body.name,
        description: body.description || null,
        fromEmail: body.fromEmail,
        fromName: body.fromName,
        replyTo: body.replyTo || null,
        sequence,
        triggers: [],
        exitConditions: [{ type: 'replied', config: {} }],
        settings: {
            sendWindow: {
                enabled: true,
                timezone: 'Europe/Tallinn',
                days: [1, 2, 3, 4, 5],
                startHour: 9,
                endHour: 17,
            },
            trackOpens: true,
            trackClicks: true,
            throttling: {
                maxPerHour: 50,
                maxPerDay: 200,
                rampUp: true,
                rampUpDays: 7,
            },
            unsubscribeLink: true,
        },
        createdBy: 'api',
    });

    return c.json({ success: true, data: campaign }, 201);
});

app.get('/api/v1/campaigns/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const campaignList = campaigns.getTenantCampaigns(tenantId);

    return c.json({ success: true, data: campaignList });
});

app.get('/api/v1/campaigns/detail/:campaignId', async (c) => {
    const campaignId = c.req.param('campaignId');
    const campaign = campaigns.getCampaign(campaignId);

    if (!campaign) {
        return c.json({ success: false, error: 'Campaign not found' }, 404);
    }

    return c.json({ success: true, data: campaign });
});

app.patch('/api/v1/campaigns/:campaignId/status', async (c) => {
    const campaignId = c.req.param('campaignId');
    const body = await c.req.json<{ status: 'active' | 'paused' }>();

    const campaign = await campaigns.updateCampaignStatus(campaignId, body.status);

    if (!campaign) {
        return c.json({ success: false, error: 'Campaign not found' }, 404);
    }

    return c.json({ success: true, data: campaign });
});

app.post('/api/v1/campaigns/:campaignId/enroll', async (c) => {
    const campaignId = c.req.param('campaignId');
    const body = await c.req.json<{ leadId: string }>();

    const lead = await crm.getLead(body.leadId);
    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    const enrollment = await campaigns.enrollLead(campaignId, lead);

    if (!enrollment) {
        return c.json({ success: false, error: 'Failed to enroll lead' }, 400);
    }

    await crm.recordActivity(body.leadId, {
        type: 'campaign_enrolled',
        description: `Enrolled in campaign`,
        data: { campaignId, enrollmentId: enrollment.id },
        userId: null,
    });

    return c.json({ success: true, data: enrollment }, 201);
});

app.get('/api/v1/campaigns/templates', async (c) => {
    return c.json({ success: true, data: campaigns.campaignTemplates });
});

// ============================================
// Inbox Routes
// ============================================

app.post('/api/v1/inbox/process', async (c) => {
    const body = await c.req.json<{
        tenantId: string;
        leadId?: string;
        campaignId?: string;
        messageId: string;
        inReplyTo?: string;
        from: string;
        to: string[];
        cc?: string[];
        subject: string;
        textBody?: string;
        htmlBody?: string;
        receivedAt: string;
    }>();

    const message = inbox.processIncomingMessage({
        tenantId: body.tenantId,
        leadId: body.leadId || null,
        campaignId: body.campaignId || null,
        messageId: body.messageId,
        inReplyTo: body.inReplyTo || null,
        from: body.from,
        to: body.to,
        cc: body.cc,
        subject: body.subject,
        textBody: body.textBody || null,
        htmlBody: body.htmlBody || null,
        receivedAt: new Date(body.receivedAt),
    });

    // If we identified the lead, update their record
    if (message.leadId) {
            await crm.recordActivity(message.leadId, {
            type: 'email_replied',
            description: `Reply received: ${message.classification}`,
            data: {
                classification: message.classification,
                sentiment: message.sentiment,
                suggestedAction: message.suggestedAction,
            },
            userId: null,
        });

        // Record engagement in campaign if applicable
        if (message.campaignId) {
            const enrollmentsForLead = campaigns.getLeadEnrollments(message.leadId);
            const relevantEnrollment = enrollmentsForLead.find(
                (e) => e.campaignId === message.campaignId
            );
            if (relevantEnrollment) {
                campaigns.recordEngagement(relevantEnrollment.id, 'replied');
            }
        }
    }

    return c.json({ success: true, data: message });
});

app.post('/api/v1/inbox/classify', async (c) => {
    const body = await c.req.json<{
        subject: string;
        body: string;
    }>();

    const classification = inbox.classifyMessage(body.subject, body.body);
    const sentiment = inbox.analyzeSentiment(body.body);
    const intent = inbox.analyzeIntent(classification, body.body);
    const suggestedAction = inbox.suggestAction(classification, sentiment, intent);

    return c.json({
        success: true,
        data: {
            classification,
            sentiment,
            intent,
            suggestedAction,
        },
    });
});

// ============================================
// CRM Routes
// ============================================

app.get('/api/v1/leads/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const statusParam = c.req.query('status')?.split(',');
    const stageParam = c.req.query('stage')?.split(',');
    const filters = {
        status: isLeadStatusArray(statusParam) ? statusParam : undefined,
        stage: isPipelineStageArray(stageParam) ? stageParam : undefined,
        search: c.req.query('search'),
    };

    const leads = await crm.filterLeads(tenantId, filters);

    return c.json({ success: true, data: leads });
});

app.get('/api/v1/leads/detail/:leadId', async (c) => {
    const leadId = c.req.param('leadId');
    const lead = await crm.getLead(leadId);

    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    const activities = await crm.getLeadActivities(leadId, { limit: 20 });
    const tasks = await crm.getLeadTasks(leadId);
    const enrollments = campaigns.getLeadEnrollments(leadId);

    return c.json({
        success: true,
        data: {
            lead,
            activities,
            tasks,
            enrollments,
        },
    });
});

app.patch('/api/v1/leads/:leadId', async (c) => {
    const leadId = c.req.param('leadId');
    const updates = await c.req.json();

    const lead = await crm.updateLead(leadId, updates);

    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    return c.json({ success: true, data: lead });
});

app.post('/api/v1/leads/:leadId/stage', async (c) => {
    const leadId = c.req.param('leadId');
    const body = await c.req.json<{ stage: string; userId?: string }>();

    if (!isPipelineStage(body.stage)) {
        return c.json({ success: false, error: 'Invalid pipeline stage' }, 400);
    }

    const lead = await crm.moveLeadToStage(leadId, body.stage, body.userId);

    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    return c.json({ success: true, data: lead });
});

app.post('/api/v1/leads/:leadId/tasks', async (c) => {
    const leadId = c.req.param('leadId');
    const body = await c.req.json<{
        title: string;
        description?: string;
        type: string;
        priority: string;
        dueAt?: string;
        assignedTo?: string;
    }>();

    if (!isTaskType(body.type)) {
        return c.json({ success: false, error: 'Invalid task type' }, 400);
    }
    if (!isTaskPriority(body.priority)) {
        return c.json({ success: false, error: 'Invalid task priority' }, 400);
    }

    const lead = await crm.getLead(leadId);
    if (!lead) {
        return c.json({ success: false, error: 'Lead not found' }, 404);
    }

    const task = await crm.createTask(leadId, lead.tenantId, {
        title: body.title,
        description: body.description,
        type: body.type,
        priority: body.priority,
        dueAt: body.dueAt ? new Date(body.dueAt) : null,
        assignedTo: body.assignedTo || null,
    });

    return c.json({ success: true, data: task }, 201);
});

app.patch('/api/v1/tasks/:taskId/complete', async (c) => {
    const taskId = c.req.param('taskId');
    const body = await c.req.json<{ completedBy: string }>();

    const task = await crm.completeTask(taskId, body.completedBy);

    if (!task) {
        return c.json({ success: false, error: 'Task not found' }, 404);
    }

    return c.json({ success: true, data: task });
});

app.get('/api/v1/pipeline/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');

    let pipeline = await crm.getPipeline(tenantId);
    if (!pipeline) {
        pipeline = await crm.createDefaultPipeline(tenantId);
    }

    const stats = await crm.getPipelineStats(tenantId);

    return c.json({ success: true, data: { pipeline, stats } });
});

// ============================================
// Calendar Routes
// ============================================

app.get('/api/v1/calendar/slots/:userId', async (c) => {
    const userId = c.req.param('userId');
    const tenantId = c.req.query('tenantId') || 'default';
    const startDate = new Date(c.req.query('startDate') || Date.now());
    const endDate = new Date(
        c.req.query('endDate') || Date.now() + 7 * 24 * 60 * 60 * 1000
    );
    const duration = parseInt(c.req.query('duration') || '30', 10);

    const slots = calendar.getAvailableSlots(
        userId,
        tenantId,
        startDate,
        endDate,
        duration
    );

    return c.json({ success: true, data: slots });
});

app.post('/api/v1/calendar/book', async (c) => {
    const body = await c.req.json<{
        slotId: string;
        leadId: string;
        bookedBy: string;
        meetingType?: string;
        notes?: string;
    }>();

    const meetingType: MeetingType = isMeetingType(body.meetingType) ? body.meetingType : 'demo';

    const slot = calendar.bookSlot(
        body.slotId,
        body.leadId,
        body.bookedBy,
        meetingType,
        body.notes
    );

    if (!slot) {
        return c.json({ success: false, error: 'Slot not available' }, 400);
    }

    // Record activity
    await crm.recordActivity(body.leadId, {
        type: 'meeting_scheduled',
        description: `Meeting scheduled for ${slot.startTime.toISOString()}`,
        data: { slotId: slot.id, meetingType: slot.meetingType },
        userId: body.bookedBy,
    });

    // Move lead to demo scheduled stage
    await crm.moveLeadToStage(body.leadId, 'demo_scheduled');

    return c.json({ success: true, data: slot });
});

app.post('/api/v1/calendar/cancel/:slotId', async (c) => {
    const slotId = c.req.param('slotId');
    const body = await c.req.json<{ reason?: string }>();

    const slot = calendar.cancelBooking(slotId, body.reason);

    if (!slot) {
        return c.json({ success: false, error: 'Slot not found' }, 404);
    }

    return c.json({ success: true, data: slot });
});

app.get('/api/v1/calendar/ics/:slotId', async (c) => {
    const slotId = c.req.param('slotId');
    const organizerEmail = c.req.query('email') || 'noreply@apexmail.ee';

    // This would need the actual slot data
    // For now, create a mock slot with proper typing
    const mockSlot: {
        id: string;
        startTime: Date;
        endTime: Date;
        meetingType: MeetingType;
        meetingLink: string;
    } = {
        id: slotId,
        startTime: new Date(Date.now() + 24 * 60 * 60 * 1000),
        endTime: new Date(Date.now() + 24 * 60 * 60 * 1000 + 30 * 60 * 1000),
        meetingType: 'demo',
        meetingLink: `https://meet.apexmail.ee/${slotId}`,
    };

    const ics = calendar.generateIcsFile(mockSlot, organizerEmail);

    return new Response(ics, {
        headers: {
            'Content-Type': 'text/calendar',
            'Content-Disposition': `attachment; filename="meeting-${slotId}.ics"`,
        },
    });
});

// ============================================
// Promo Routes
// ============================================

app.post('/api/v1/promos', async (c) => {
    const body = await c.req.json<{
        tenantId: string;
        name: string;
        type: string;
        placement: string;
        text: string;
        link: string;
        html?: string;
        ctaText?: string;
        targeting?: Record<string, unknown>;
    }>();

    if (!isPromoType(body.type)) {
        return c.json({ success: false, error: 'Invalid promo type' }, 400);
    }
    if (!isPromoPlacement(body.placement)) {
        return c.json({ success: false, error: 'Invalid promo placement' }, 400);
    }

    const promo = ads.createPromoConfig(body.tenantId, {
        name: body.name,
        type: body.type,
        placement: body.placement,
        text: body.text,
        link: body.link,
        html: body.html,
        ctaText: body.ctaText,
        targeting: body.targeting,
    });

    return c.json({ success: true, data: promo }, 201);
});

app.get('/api/v1/promos/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const promos = ads.getActivePromos(tenantId);

    return c.json({ success: true, data: promos });
});

app.get('/api/v1/promos/analytics/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const analytics = ads.getPromoAnalytics(tenantId);

    return c.json({ success: true, data: analytics });
});

app.post('/api/v1/promos/track/click/:promoId', async (c) => {
    const promoId = c.req.param('promoId');
    ads.recordClick(promoId);

    return c.json({ success: true });
});

app.post('/api/v1/promos/track/conversion/:promoId', async (c) => {
    const promoId = c.req.param('promoId');
    ads.recordConversion(promoId);

    return c.json({ success: true });
});

// Error handler
app.onError((err, c) => {
    logger.error('API error', { error: err.message, stack: err.stack });
    return c.json(
        { success: false, error: 'Internal server error' },
        500
    );
});

export default app;
