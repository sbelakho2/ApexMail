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
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';

import { InferenceEngine, EmbeddingsService } from './inference/index.js';
import { ChatbotAssistant, IntentDetector } from './chatbot/index.js';
import { MailbotExecutor } from './mailbot/index.js';
import { STOOptimizer } from './sto/index.js';
import { ContentGenerator } from './content/index.js';
import { PredictiveAnalytics } from './analytics/index.js';

// Initialize services
const inference = new InferenceEngine();
const embeddings = new EmbeddingsService();
const chatbot = new ChatbotAssistant();
const intentDetector = new IntentDetector();
const mailbot = new MailbotExecutor();
const sto = new STOOptimizer();
const content = new ContentGenerator();
const analytics = new PredictiveAnalytics();

// Create Hono app
const app = new Hono();

// ========================================
// MIDDLEWARE
// ========================================

app.use('*', logger());
app.use('*', cors({
    origin: ['http://localhost:3000', 'https://apexmail.app'],
    credentials: true,
}));
app.use('*', secureHeaders());
app.use('*', prettyJSON());

// Error handling
app.onError((err, c) => {
    console.error('API Error:', err);
    return c.json({
        success: false,
        error: err.message || 'Internal server error',
    }, 500);
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

app.get('/health', (c) => {
    return c.json({
        status: 'healthy',
        services: {
            inference: 'ready',
            chatbot: 'ready',
            mailbot: 'ready',
            sto: 'ready',
            content: 'ready',
            analytics: 'ready',
        },
        uptime: process.uptime(),
    });
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
// CHATBOT ROUTES
// ========================================

const chatbotRoutes = new Hono();

// Start session
chatbotRoutes.post(
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
        const session = chatbot.startSession(userId, context);

        return c.json({
            success: true,
            data: {
                sessionId: session.id,
                createdAt: session.createdAt,
            },
        });
    }
);

// Send message
chatbotRoutes.post(
    '/message',
    zValidator('json', z.object({
        sessionId: z.string().min(1),
        message: z.string().min(1).max(5000),
        context: z.record(z.unknown()).optional(),
    })),
    async (c) => {
        const { sessionId, message, context } = c.req.valid('json');
        const response = await chatbot.chat(sessionId, message, context);

        return c.json({
            success: true,
            data: response,
        });
    }
);

// Get session
chatbotRoutes.get('/session/:sessionId', (c) => {
    const sessionId = c.req.param('sessionId');
    const session = chatbot.getSession(sessionId);

    if (!session) {
        return c.json({ success: false, error: 'Session not found' }, 404);
    }

    return c.json({
        success: true,
        data: session,
    });
});

// Get suggestions
chatbotRoutes.get('/session/:sessionId/suggestions', async (c) => {
    const sessionId = c.req.param('sessionId');
    const suggestions = await chatbot.generateSuggestions(sessionId);

    return c.json({
        success: true,
        data: suggestions,
    });
});

// End session
chatbotRoutes.delete('/session/:sessionId', (c) => {
    const sessionId = c.req.param('sessionId');
    const deleted = chatbot.endSession(sessionId);

    return c.json({
        success: true,
        data: { deleted },
    });
});

// Detect intent
chatbotRoutes.post(
    '/intent',
    zValidator('json', z.object({
        text: z.string().min(1).max(1000),
    })),
    async (c) => {
        const { text } = c.req.valid('json');
        const intent = intentDetector.detect(text);

        return c.json({
            success: true,
            data: intent,
        });
    }
);

app.route('/api/chatbot', chatbotRoutes);

// ========================================
// MAILBOT ROUTES
// ========================================

const mailbotRoutes = new Hono();

// Process command
mailbotRoutes.post(
    '/command',
    zValidator('json', z.object({
        command: z.string().min(1).max(1000),
        userId: z.string().min(1),
        context: z.object({
            activeCampaign: z.string().optional(),
            activeList: z.string().optional(),
        }).optional(),
    })),
    async (c) => {
        const body = c.req.valid('json');
        const response = await mailbot.process(body);

        return c.json({
            success: true,
            data: response,
        });
    }
);

// Confirm action
mailbotRoutes.post(
    '/confirm/:confirmationId',
    async (c) => {
        const confirmationId = c.req.param('confirmationId');
        const response = mailbot.confirmAction(confirmationId);

        return c.json({
            success: true,
            data: response,
        });
    }
);

// Cancel action
mailbotRoutes.delete(
    '/confirm/:confirmationId',
    async (c) => {
        const confirmationId = c.req.param('confirmationId');
        const response = mailbot.cancelAction(confirmationId);

        return c.json({
            success: true,
            data: response,
        });
    }
);

// Get suggestions
mailbotRoutes.get('/suggestions', (c) => {
    const query = c.req.query('q') || '';
    const suggestions = mailbot.getSuggestions(query);

    return c.json({
        success: true,
        data: suggestions,
    });
});

// Get available commands
mailbotRoutes.get('/commands', (c) => {
    const commands = mailbot.getAvailableCommands();

    return c.json({
        success: true,
        data: commands,
    });
});

app.route('/api/mailbot', mailbotRoutes);

// ========================================
// STO ROUTES
// ========================================

const stoRoutes = new Hono();

// Get optimized send time
stoRoutes.post(
    '/optimize',
    zValidator('json', z.object({
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
        const result = await sto.optimize(body);

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
            ...pattern,
            timestamp: new Date(pattern.timestamp),
            sentAt: pattern.sentAt ? new Date(pattern.sentAt) : undefined,
            openedAt: pattern.openedAt ? new Date(pattern.openedAt) : undefined,
            clickedAt: pattern.clickedAt ? new Date(pattern.clickedAt) : undefined,
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
