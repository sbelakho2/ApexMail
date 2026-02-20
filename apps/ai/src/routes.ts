/**
 * @apexmail/ai - Hono API Routes
 * 
 * HTTP API for the AI Intelligence Suite.
 * Provides endpoints for inference, chatbot, mailbot, STO, and content generation.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { secureHeaders } from 'hono/secure-headers';
import { bodyLimit } from 'hono/body-limit'; // FIX-500-394
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';

// G-199: Structured logger for AI service (local — no @apexmail/lib dependency)
const aiLogger = {
    error(msg: string, meta?: Record<string, unknown>) {
        console.error(JSON.stringify({ level: 'error', service: 'ai-routes', msg, ...meta, ts: new Date().toISOString() }));
    },
    warn(msg: string, meta?: Record<string, unknown>) {
        console.warn(JSON.stringify({ level: 'warn', service: 'ai-routes', msg, ...meta, ts: new Date().toISOString() }));
    },
    info(msg: string, meta?: Record<string, unknown>) {
        console.log(JSON.stringify({ level: 'info', service: 'ai-routes', msg, ...meta, ts: new Date().toISOString() }));
    },
};

import { InferenceEngine, EmbeddingsService, getSharedEngine } from './inference/index.js';
import { UnifiedAssistant, ActionRouter } from './assistant/index.js';
import { STOOptimizer } from './sto/index.js';
import { ContentGenerator } from './content/index.js';
import { PredictiveAnalytics } from './analytics/index.js';

// FIX-500-099: Use shared engine instead of creating a new instance
const inference = getSharedEngine();
const embeddings = new EmbeddingsService();
const assistant = new UnifiedAssistant();
const actionRouter = new ActionRouter();
const sto = new STOOptimizer();
const content = new ContentGenerator();
const analytics = new PredictiveAnalytics();

const STO_SNAPSHOT_PATH = process.env.STO_SNAPSHOT_PATH || path.resolve(process.cwd(), 'data/sto-engagement.ndjson');
const STO_SNAPSHOT_INTERVAL_MS = 60_000;

async function restoreStoSnapshot(): Promise<void> {
    try {
        const snapshot = await fs.readFile(STO_SNAPSHOT_PATH, 'utf8');
        const result = sto.importNdjson(snapshot);
        aiLogger.info('STO snapshot restored', { imported: result.imported, errors: result.errors });
    } catch {
        // No snapshot yet — first boot or no persisted data
    }
}

async function persistStoSnapshot(): Promise<void> {
    try {
        await fs.mkdir(path.dirname(STO_SNAPSHOT_PATH), { recursive: true });
        const payload = sto.exportNdjson();
        await fs.writeFile(STO_SNAPSHOT_PATH, payload, 'utf8');
    } catch (error) {
        aiLogger.warn('Failed to persist STO snapshot', { error: error instanceof Error ? error.message : String(error) });
    }
}

void restoreStoSnapshot();
const stoSnapshotTimer = setInterval(() => {
    void persistStoSnapshot();
}, STO_SNAPSHOT_INTERVAL_MS);
stoSnapshotTimer.unref();

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.once(signal, () => {
        void persistStoSnapshot();
    });
}

// Create Hono app
const app = new Hono();

// ========================================
// RATE LIMITING (AI-007: Per-tenant rate limiting)
// ========================================

const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute window
const RATE_LIMIT_MAX_REQUESTS = 60; // 60 requests per minute per tenant

let redisClient: Redis | null = null;

function getRedisClient(): Redis {
    if (!redisClient) {
        const redisUrl = process.env.REDIS_URL;
        if (redisUrl) {
            redisClient = new Redis(redisUrl, {
                maxRetriesPerRequest: 2,
                enableReadyCheck: true,
            });
        } else {
            redisClient = new Redis({
                host: process.env.REDIS_HOST ?? '127.0.0.1',
                port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
                password: process.env.REDIS_PASSWORD,
                db: parseInt(process.env.REDIS_DB ?? '0', 10),
                maxRetriesPerRequest: 2,
                enableReadyCheck: true,
            });
        }
    }
    return redisClient;
}

// ========================================
// MIDDLEWARE
// ========================================

app.use('*', logger());
// FIX-500-394: Reject oversized request bodies (1 MB default)
app.use('*', bodyLimit({ maxSize: 1024 * 1024 }));
app.use('*', cors({
    origin: ['http://localhost:3000', 'https://apexmail.app'],
    credentials: true,
}));
app.use('*', secureHeaders());
app.use('*', prettyJSON());

// AI-008/009: Request ID propagation middleware
// Generates or propagates request IDs for distributed tracing
app.use('*', async (c, next) => {
    // Get existing request ID from header or generate a new one
    const incomingRequestId = c.req.header('X-Request-ID');
    const requestId = incomingRequestId ?? `ai-${randomUUID()}`;
    
    // Store in header for downstream use (Hono's preferred pattern)
    c.req.raw.headers.set('X-Request-ID', requestId);
    
    // Always set the response header for tracing
    c.header('X-Request-ID', requestId);
    
    return next();
});

// AI-007: Rate limiting middleware for AI endpoints
app.use('/api/*', async (c, next) => {
    // Extract tenant ID from header or request body
    const tenantId = c.req.header('X-Tenant-ID') ?? 'default';
    const now = Date.now();
    const windowStart = Math.floor(now / RATE_LIMIT_WINDOW_MS) * RATE_LIMIT_WINDOW_MS;
    const windowEnd = windowStart + RATE_LIMIT_WINDOW_MS;
    const key = `ai:ratelimit:${tenantId}:${windowStart}`;

    try {
        const redis = getRedisClient();
        const count = await redis.incr(key);
        if (count === 1) {
            await redis.expire(key, Math.ceil(RATE_LIMIT_WINDOW_MS / 1000) + 1);
        }

        const remaining = Math.max(0, RATE_LIMIT_MAX_REQUESTS - count);
        c.header('X-RateLimit-Limit', String(RATE_LIMIT_MAX_REQUESTS));
        c.header('X-RateLimit-Remaining', String(remaining));
        c.header('X-RateLimit-Reset', String(Math.floor(windowEnd / 1000)));

        if (count > RATE_LIMIT_MAX_REQUESTS) {
            const retryAfter = Math.ceil((windowEnd - now) / 1000);
            c.header('Retry-After', String(retryAfter));
            return c.json({
                success: false,
                error: `Rate limit exceeded. Retry after ${retryAfter} seconds.`,
                code: 'RATE_LIMIT_EXCEEDED',
            }, 429);
        }

        return next();
    } catch (error) {
        aiLogger.error('Rate limiter unavailable', { error: error instanceof Error ? error.message : String(error) });
        if (process.env.NODE_ENV === 'production') {
            return c.json({
                success: false,
                error: 'Service temporarily unavailable.',
                code: 'RATE_LIMITER_UNAVAILABLE',
            }, 503);
        }
        return next();
    }
});

// Error handling
// AI-009: Include request ID in error responses for tracing
app.onError((err, c) => {
    const requestId = c.req.header('X-Request-ID') ?? 'unknown';
    // G-199: Use structured logger instead of console.error
    aiLogger.error('API Error', { requestId, error: err.message, stack: err.stack });
    
    // Return appropriate error code based on error type
    const status = err.message.includes('not found') ? 404 
        : err.message.includes('validation') ? 400
        : err.message.includes('unauthorized') ? 401
        : 500;
    
    return c.json({
        success: false,
        error: err.message || 'Internal server error',
        code: status === 400 ? 'VALIDATION_ERROR' 
            : status === 401 ? 'UNAUTHORIZED'
            : status === 404 ? 'NOT_FOUND'
            : 'INTERNAL_ERROR',
        requestId, // AI-009: Include request ID for debugging
    }, status);
});

// ========================================
// HEALTH CHECK
// ========================================

app.get('/', (c) => {
    return c.json({
        service: '@apexmail/ai',
        version: '1.0.0',
        status: 'healthy',
        timestamp: new Date().toISOString(),
    });
});

app.get('/health', async (c) => {
    // FIX-500-017: Report actual service readiness instead of hardcoded values.
    // Lazy-import to avoid circular dependency with index.ts.
    try {
        const { getBootstrap, isInitFailed } = await import('./index.js');

        // FIX-500-392: If initialization failed, report unhealthy immediately
        if (isInitFailed()) {
            return c.json({
                status: 'unhealthy',
                ready: false,
                reason: 'Service initialization failed',
                uptime: process.uptime(),
            }, 503);
        }

        const bootstrap = getBootstrap();
        if (bootstrap) {
            const readiness = bootstrap.getReadiness();
            const status = readiness.ready && readiness.healthCheckPassing ? 'healthy' : 'degraded';
            return c.json({
                status,
                ready: readiness.ready,
                modelsLoaded: readiness.modelsLoaded,
                cacheConnected: readiness.cacheConnected,
                healthCheckPassing: readiness.healthCheckPassing,
                startupTime: readiness.startupTime,
                uptime: readiness.uptime,
            }, status === 'healthy' ? 200 : 503);
        }
    } catch {
        // Bootstrap not available yet — report startup state
    }
    return c.json({
        status: 'starting',
        ready: false,
        uptime: process.uptime(),
    }, 503);
});

// ========================================
// INFERENCE ROUTES
// ========================================

const inferenceRoutes = new Hono();

// Generate completion
inferenceRoutes.post(
    '/generate',
    zValidator('json', z.object({
        prompt: z.string().min(1).max(10000),
        maxTokens: z.number().optional().default(1024),
        temperature: z.number().min(0).max(2).optional().default(0.7),
        topP: z.number().min(0).max(1).optional().default(0.95),
        stopSequences: z.array(z.string()).optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        
        const result = await inference.generate(body.prompt, {
            maxTokens: body.maxTokens,
            temperature: body.temperature,
            topP: body.topP,
            stopSequences: body.stopSequences,
        });

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Chat completion
inferenceRoutes.post(
    '/chat',
    zValidator('json', z.object({
        messages: z.array(z.object({
            role: z.enum(['system', 'user', 'assistant']),
            content: z.string(),
        })),
        maxTokens: z.number().optional().default(1024),
        temperature: z.number().min(0).max(2).optional().default(0.7),
    })),
    async (c) => {
        const body = c.req.valid('json');
        
        const result = await inference.chat(body.messages, {
            maxTokens: body.maxTokens,
            temperature: body.temperature,
        });

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Generate embedding
inferenceRoutes.post(
    '/embed',
    zValidator('json', z.object({
        text: z.string().min(1).max(10000),
    })),
    async (c) => {
        const { text } = c.req.valid('json');
        const result = await embeddings.embed(text);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Batch embeddings
inferenceRoutes.post(
    '/embed/batch',
    zValidator('json', z.object({
        texts: z.array(z.string().min(1).max(10000)).max(100),
    })),
    async (c) => {
        const { texts } = c.req.valid('json');
        const results = await embeddings.embedBatch(texts);

        return c.json({
            success: true,
            data: results,
        });
    }
);

// Token count
inferenceRoutes.post(
    '/tokenize',
    zValidator('json', z.object({
        text: z.string().min(1).max(100000),
    })),
    async (c) => {
        const { text } = c.req.valid('json');
        const result = inference.tokenize(text);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Model info
inferenceRoutes.get('/model', (c) => {
    return c.json({
        success: true,
        data: inference.getModelInfo(),
    });
});

app.route('/api/inference', inferenceRoutes);

// ========================================
// UNIFIED ASSISTANT ROUTES
// (replaces chatbot + mailbot with a single AI assistant)
// ========================================

const assistantRoutes = new Hono();

// Start session
assistantRoutes.post(
    '/session',
    zValidator('json', z.object({
        userId: z.string().min(1),
        context: z.object({
            campaigns: z.array(z.object({
                id: z.string(),
                name: z.string(),
            })).optional(),
            contacts: z.number().optional(),
            recentActivity: z.array(z.string()).optional(),
        }).optional(),
    })),
    async (c) => {
        const { userId, context } = c.req.valid('json');
        const session = assistant.startSession(userId, context);

        return c.json({
            success: true,
            data: {
                sessionId: session.id,
                createdAt: session.createdAt,
            },
        });
    }
);

// Send message (handles chat, commands, and backend actions in one endpoint)
assistantRoutes.post(
    '/message',
    zValidator('json', z.object({
        sessionId: z.string().min(1),
        message: z.string().min(1).max(5000),
        context: z.record(z.unknown()).optional(),
    })),
    async (c) => {
        const { sessionId, message, context } = c.req.valid('json');
        const response = await assistant.chat(sessionId, message, context as Record<string, unknown> | undefined);

        // Auto-execute non-confirmation actions through the action router
        const executedResults = [];
        for (const action of response.actions) {
            if (!action.confirm && actionRouter.has(action.action)) {
                const result = await actionRouter.execute(action);
                executedResults.push({ action: action.action, result });
            }
        }

        return c.json({
            success: true,
            data: {
                message: response.message,
                actions: response.actions,
                executedResults,
                suggestedActions: response.suggestedActions,
                requiresConfirmation: response.requiresConfirmation,
                confirmationId: response.confirmationId,
                tokens: response.tokens,
                latencyMs: response.latencyMs,
            },
        });
    }
);

// Get session
assistantRoutes.get('/session/:sessionId', (c) => {
    const sessionId = c.req.param('sessionId');
    const session = assistant.getSession(sessionId);

    if (!session) {
        return c.json({ success: false, error: 'Session not found' }, 404);
    }

    return c.json({
        success: true,
        data: session,
    });
});

// End session
assistantRoutes.delete('/session/:sessionId', (c) => {
    const sessionId = c.req.param('sessionId');
    const deleted = assistant.endSession(sessionId);

    return c.json({
        success: true,
        data: { deleted },
    });
});

// Confirm pending action
assistantRoutes.post(
    '/confirm/:confirmationId',
    async (c) => {
        const confirmationId = c.req.param('confirmationId');
        const result = assistant.confirmAction(confirmationId);

        // Execute the confirmed action
        if (result.success && result.action && actionRouter.has(result.action.action)) {
            const execResult = await actionRouter.execute(result.action);
            return c.json({
                success: true,
                data: { ...result, executionResult: execResult },
            });
        }

        return c.json({
            success: result.success,
            data: result,
        }, result.success ? 200 : 404);
    }
);

// Cancel pending action
assistantRoutes.delete(
    '/confirm/:confirmationId',
    (c) => {
        const confirmationId = c.req.param('confirmationId');
        const result = assistant.cancelAction(confirmationId);

        return c.json({
            success: result.success,
            data: result,
        }, result.success ? 200 : 404);
    }
);

// Detect intent (quick classification without full chat)
assistantRoutes.post(
    '/intent',
    zValidator('json', z.object({
        text: z.string().min(1).max(1000),
    })),
    async (c) => {
        const { text } = c.req.valid('json');
        const intent = await assistant.detectIntent(text);

        return c.json({
            success: true,
            data: intent,
        });
    }
);

// Get available actions
assistantRoutes.get('/actions', (c) => {
    const actions = assistant.getAvailableActions();

    return c.json({
        success: true,
        data: actions,
    });
});

app.route('/api/assistant', assistantRoutes);

// ========================================
// STO ROUTES
// ========================================

const stoRoutes = new Hono();

// Get optimized send time
stoRoutes.post(
    '/optimize',
    zValidator('json', z.object({
        tenantId: z.string().optional(),
        campaignId: z.string().optional(),
        subscriberIds: z.array(z.string()).optional(),
        listId: z.string().optional(),
        timezone: z.string().optional().default('America/New_York'),
        constraints: z.object({
            excludeWeekends: z.boolean().optional(),
            businessHoursOnly: z.boolean().optional(),
            excludeHours: z.array(z.number()).optional(),
        }).optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await sto.optimize({
            tenantId: body.tenantId ?? 'default',
            campaignId: body.campaignId ?? 'unknown',
            ...body,
        });

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Predict engagement for specific time
stoRoutes.post(
    '/predict',
    zValidator('json', z.object({
        subscriberIds: z.array(z.string()),
        sendTime: z.string().datetime(),
    })),
    async (c) => {
        const { subscriberIds, sendTime } = c.req.valid('json');
        const result = sto.predictEngagement(subscriberIds, new Date(sendTime));

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Get list pattern
stoRoutes.get('/pattern/:listId', (c) => {
    const listId = c.req.param('listId');
    const pattern = sto.getListPattern(listId);

    return c.json({
        success: true,
        data: pattern,
    });
});

// Add engagement data
stoRoutes.post(
    '/engagement',
    zValidator('json', z.object({
        subscriberId: z.string(),
        pattern: z.object({
            timestamp: z.string().datetime(),
            sentAt: z.string().datetime().optional(),
            openedAt: z.string().datetime().optional(),
            clickedAt: z.string().datetime().optional(),
            opened: z.boolean(),
            clicked: z.boolean(),
        }),
    })),
    async (c) => {
        const { subscriberId, pattern } = c.req.valid('json');
        
        sto.addEngagementData(subscriberId, {
            contactId: subscriberId,
            hourlyDistribution: [],
            dayOfWeekDistribution: [],
            timezone: 'UTC',
            preferredDevices: [],
            timestamp: new Date(pattern.timestamp),
            sentAt: pattern.sentAt ? new Date(pattern.sentAt) : undefined,
            openedAt: pattern.openedAt ? new Date(pattern.openedAt) : undefined,
            clickedAt: pattern.clickedAt ? new Date(pattern.clickedAt) : undefined,
            opened: pattern.opened,
            clicked: pattern.clicked,
        });

        return c.json({
            success: true,
            data: { added: true },
        });
    }
);

// Get stats
stoRoutes.get('/stats', (c) => {
    return c.json({
        success: true,
        data: sto.getStats(),
    });
});

app.route('/api/sto', stoRoutes);

// ========================================
// CONTENT ROUTES
// ========================================

const contentRoutes = new Hono();

// Generate content
contentRoutes.post(
    '/generate',
    zValidator('json', z.object({
        type: z.enum(['subject_line', 'preheader', 'email_body', 'cta', 'product_description', 'social_proof', 'ps_line']),
        topic: z.string().min(1).max(500),
        style: z.enum(['professional', 'casual', 'urgent', 'playful', 'formal']).optional(),
        industry: z.string().optional(),
        keywords: z.array(z.string()).optional(),
        variants: z.number().min(1).max(10).optional(),
        subjectLine: z.string().optional(),
        goal: z.string().optional(),
        keyPoints: z.array(z.string()).optional(),
        features: z.array(z.string()).optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await content.generate(body);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Generate subject lines
contentRoutes.post(
    '/subject-lines',
    zValidator('json', z.object({
        topic: z.string().min(1).max(500),
        tone: z.string().optional().default('professional'),
        industry: z.string().optional().default('general'),
        keywords: z.array(z.string()).optional(),
        count: z.number().min(1).max(20).optional().default(5),
        product: z.string().optional(),
        benefit: z.string().optional(),
        offer: z.string().optional(),
        audience: z.string().optional(),
        timeframe: z.string().optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await content.generateSubjectLines(body);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Analyze sentiment
contentRoutes.post(
    '/sentiment',
    zValidator('json', z.object({
        text: z.string().min(1).max(10000),
    })),
    async (c) => {
        const { text } = c.req.valid('json');
        const result = await content.analyzeSentiment({ text });

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Analyze content
contentRoutes.post(
    '/analyze',
    zValidator('json', z.object({
        content: z.string().min(1).max(50000),
    })),
    async (c) => {
        const { content: text } = c.req.valid('json');
        const analysis = content.analyzeContent(text);

        return c.json({
            success: true,
            data: analysis,
        });
    }
);

// Get suggestions
contentRoutes.post(
    '/suggestions',
    zValidator('json', z.object({
        content: z.string().min(1).max(50000),
        type: z.enum(['subject_line', 'preheader', 'email_body', 'cta', 'product_description', 'social_proof', 'ps_line']),
    })),
    async (c) => {
        const { content: text, type } = c.req.valid('json');
        const suggestions = content.getSuggestions(text, type);

        return c.json({
            success: true,
            data: suggestions,
        });
    }
);

app.route('/api/content', contentRoutes);

// ========================================
// ANALYTICS ROUTES
// ========================================

const analyticsRoutes = new Hono();

// Make prediction
analyticsRoutes.post(
    '/predict',
    zValidator('json', z.object({
        type: z.enum(['open_rate', 'click_rate', 'conversion_rate', 'unsubscribe_rate', 'churn_risk', 'revenue', 'best_time']),
        sendHour: z.number().min(0).max(23).optional(),
        sendDay: z.number().min(0).max(6).optional(),
        subjectLength: z.number().optional(),
        listSize: z.number().optional(),
        expectedOpenRate: z.number().optional(),
        expectedClickRate: z.number().optional(),
        hasPersonalization: z.boolean().optional(),
        emailFrequency: z.number().optional(),
        subscriberId: z.string().optional(),
        avgOrderValue: z.number().optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await analytics.predict(body);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Segment audience
analyticsRoutes.post(
    '/segment',
    zValidator('json', z.object({
        type: z.enum(['engagement', 'recency', 'frequency', 'rfm', 'lifecycle', 'behavioral']),
        criteria: z.record(z.unknown()).optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await analytics.segmentAudience(body);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Analyze A/B test
analyticsRoutes.post(
    '/ab-test',
    zValidator('json', z.object({
        variantA: z.object({
            sent: z.number(),
            opens: z.number(),
            clicks: z.number(),
            conversions: z.number().optional(),
        }),
        variantB: z.object({
            sent: z.number(),
            opens: z.number(),
            clicks: z.number(),
            conversions: z.number().optional(),
        }),
        metric: z.enum(['open_rate', 'click_rate', 'conversion_rate']),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const result = await analytics.analyzeABTest(body);

        return c.json({
            success: true,
            data: result,
        });
    }
);

// Add historical data
analyticsRoutes.post(
    '/data/historical',
    zValidator('json', z.object({
        campaignId: z.string(),
        sentAt: z.string().datetime(),
        listSize: z.number(),
        openRate: z.number(),
        clickRate: z.number(),
        unsubscribeRate: z.number(),
        bounceRate: z.number(),
        conversionRate: z.number().optional(),
        revenue: z.number().optional(),
        subject: z.string(),
        industry: z.string().optional(),
        dayOfWeek: z.number(),
        hourOfDay: z.number(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        
        analytics.addHistoricalData({
            ...body,
            sentAt: new Date(body.sentAt),
        });

        return c.json({
            success: true,
            data: { added: true },
        });
    }
);

// Add subscriber data
analyticsRoutes.post(
    '/data/subscriber',
    zValidator('json', z.object({
        subscriberId: z.string(),
        totalEmails: z.number(),
        opens: z.number(),
        clicks: z.number(),
        lastOpenedAt: z.string().datetime().optional(),
        lastClickedAt: z.string().datetime().optional(),
        daysInactive: z.number(),
        engagementScore: z.number(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        
        analytics.addSubscriberData({
            ...body,
            lastOpenedAt: body.lastOpenedAt ? new Date(body.lastOpenedAt) : undefined,
            lastClickedAt: body.lastClickedAt ? new Date(body.lastClickedAt) : undefined,
        });

        return c.json({
            success: true,
            data: { added: true },
        });
    }
);

// Get stats
analyticsRoutes.get('/stats', (c) => {
    return c.json({
        success: true,
        data: analytics.getStats(),
    });
});

app.route('/api/analytics', analyticsRoutes);

// ========================================
// VECTOR SEARCH ROUTES
// ========================================

const vectorRoutes = new Hono();

// Add vector
vectorRoutes.post(
    '/add',
    zValidator('json', z.object({
        id: z.string().min(1),
        text: z.string().min(1).max(10000),
        metadata: z.record(z.unknown()).optional(),
    })),
    async (c) => {
        const { id, text, metadata } = c.req.valid('json');
        await embeddings.addVector(id, text, metadata || {});

        return c.json({
            success: true,
            data: { id, added: true },
        });
    }
);

// Batch add vectors
vectorRoutes.post(
    '/add/batch',
    zValidator('json', z.object({
        entries: z.array(z.object({
            id: z.string().min(1),
            text: z.string().min(1).max(10000),
            metadata: z.record(z.unknown()).optional(),
        })).max(100),
    })),
    async (c) => {
        const { entries } = c.req.valid('json');
        await embeddings.addVectors(entries);

        return c.json({
            success: true,
            data: { count: entries.length, added: true },
        });
    }
);

// Search vectors
vectorRoutes.post(
    '/search',
    zValidator('json', z.object({
        query: z.string().min(1).max(5000),
        topK: z.number().min(1).max(100).optional().default(10),
        threshold: z.number().min(0).max(1).optional().default(0),
    })),
    async (c) => {
        const { query, topK, threshold } = c.req.valid('json');
        const results = await embeddings.search(query, topK, threshold);

        return c.json({
            success: true,
            data: results,
        });
    }
);

// Get vector
vectorRoutes.get('/:id', (c) => {
    const id = c.req.param('id');
    const vector = embeddings.getVector(id);

    if (!vector) {
        return c.json({ success: false, error: 'Vector not found' }, 404);
    }

    return c.json({
        success: true,
        data: vector,
    });
});

// Delete vector
vectorRoutes.delete('/:id', (c) => {
    const id = c.req.param('id');
    const deleted = embeddings.removeVector(id);

    return c.json({
        success: true,
        data: { deleted },
    });
});

// Get stats
vectorRoutes.get('/stats', (c) => {
    return c.json({
        success: true,
        data: embeddings.getStats(),
    });
});

app.route('/api/vectors', vectorRoutes);

export { app };
export default app;
