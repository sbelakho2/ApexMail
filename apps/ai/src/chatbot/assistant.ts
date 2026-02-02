/**
 * @apexmail/ai - Conversational Chatbot Assistant
 * 
 * Multi-turn conversational AI assistant for email marketing tasks.
 * Supports context-aware conversations with memory and suggested actions.
 */

import { InferenceEngine } from '../inference/engine.js';
import type {
    ChatMessage,
    ChatSession,
    ChatContext,
    ChatResponse,
    SuggestedAction,
} from '../types.js';

/**
 * Chatbot configuration
 */
export interface ChatbotConfig {
    systemPrompt: string;
    maxHistoryLength: number;
    maxContextTokens: number;
    temperature: number;
    suggestActions: boolean;
    streamResponses: boolean;
}

/**
 * Default system prompt for email marketing assistant
 */
const DEFAULT_SYSTEM_PROMPT = `You are ApexMail AI, an expert email marketing assistant. You help users with:

1. **Campaign Strategy**: Creating effective email campaigns, A/B testing strategies, and audience targeting
2. **Content Writing**: Composing compelling subject lines, email bodies, and CTAs
3. **List Management**: Segmentation strategies, list hygiene, and subscriber management
4. **Analytics Insights**: Interpreting metrics, identifying trends, and optimization recommendations
5. **Deliverability**: Best practices for inbox placement and sender reputation
6. **Automation**: Setting up drip campaigns, triggers, and workflows

Guidelines:
- Be concise and actionable
- Provide specific examples when helpful
- Suggest A/B tests for optimization
- Consider industry best practices
- Respect user privacy and compliance (GDPR, CAN-SPAM)
- When unsure, ask clarifying questions

Current Context:
{{context}}`;

/**
 * Default chatbot configuration
 */
const DEFAULT_CHATBOT_CONFIG: ChatbotConfig = {
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    maxHistoryLength: 20,
    maxContextTokens: 4096,
    temperature: 0.7,
    suggestActions: true,
    streamResponses: false,
};

/**
 * Chatbot Session Manager
 */
export class SessionManager {
    private sessions: Map<string, ChatSession> = new Map();
    private maxSessions: number = 1000;

    /**
     * Create a new session
     */
    createSession(userId: string, metadata?: Record<string, unknown>): ChatSession {
        const sessionId = this.generateSessionId();
        const now = new Date();

        const session: ChatSession = {
            id: sessionId,
            tenantId: 'default',
            userId,
            messages: [],
            context: {
                campaigns: [],
                contacts: 0,
                recentActivity: [],
            },
            createdAt: now,
            updatedAt: now,
            metadata,
        };

        this.sessions.set(sessionId, session);
        this.pruneOldSessions();

        return session;
    }

    /**
     * Get session by ID
     */
    getSession(sessionId: string): ChatSession | undefined {
        return this.sessions.get(sessionId);
    }

    /**
     * Get sessions for a user
     */
    getUserSessions(userId: string): ChatSession[] {
        return Array.from(this.sessions.values()).filter(
            (s) => s.userId === userId
        );
    }

    /**
     * Update session
     */
    updateSession(sessionId: string, updates: Partial<ChatSession>): ChatSession | undefined {
        const session = this.sessions.get(sessionId);
        if (!session) return undefined;

        const updated = {
            ...session,
            ...updates,
            updatedAt: new Date(),
        };

        this.sessions.set(sessionId, updated);
        return updated;
    }

    /**
     * Add message to session
     */
    addMessage(sessionId: string, message: ChatMessage): ChatSession | undefined {
        const session = this.sessions.get(sessionId);
        if (!session) return undefined;

        session.messages.push(message);
        session.updatedAt = new Date();

        return session;
    }

    /**
     * Delete session
     */
    deleteSession(sessionId: string): boolean {
        return this.sessions.delete(sessionId);
    }

    /**
     * Delete all sessions for a user
     */
    deleteUserSessions(userId: string): number {
        let count = 0;
        for (const [sessionId, session] of this.sessions) {
            if (session.userId === userId) {
                this.sessions.delete(sessionId);
                count++;
            }
        }
        return count;
    }

    private generateSessionId(): string {
        return `chat_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    }

    private pruneOldSessions(): void {
        if (this.sessions.size <= this.maxSessions) return;

        // Sort by updatedAt and remove oldest
        const sorted = Array.from(this.sessions.entries()).sort(
            ([, a], [, b]) => a.updatedAt.getTime() - b.updatedAt.getTime()
        );

        const toRemove = sorted.slice(0, this.sessions.size - this.maxSessions);
        for (const [sessionId] of toRemove) {
            this.sessions.delete(sessionId);
        }
    }
}

/**
 * AI Chatbot Assistant
 * 
 * Provides conversational AI capabilities for email marketing tasks.
 */
export class ChatbotAssistant {
    private engine: InferenceEngine;
    private sessionManager: SessionManager;
    private config: ChatbotConfig;

    constructor(config?: Partial<ChatbotConfig>) {
        this.config = { ...DEFAULT_CHATBOT_CONFIG, ...config };
        this.engine = new InferenceEngine({
            temperature: this.config.temperature,
        });
        this.sessionManager = new SessionManager();
    }

    /**
     * Start a new chat session
     */
    startSession(userId: string, context?: ChatContext): ChatSession {
        const session = this.sessionManager.createSession(userId);

        if (context) {
            this.sessionManager.updateSession(session.id, { context });
        }

        return session;
    }

    /**
     * Send a message and get a response
     */
    async chat(
        sessionId: string,
        userMessage: string,
        context?: Partial<ChatContext>
    ): Promise<ChatResponse> {
        const session = this.sessionManager.getSession(sessionId);
        if (!session) {
            throw new Error(`Session not found: ${sessionId}`);
        }

        // Update context if provided
        if (context) {
            this.sessionManager.updateSession(sessionId, {
                context: { ...session.context, ...context },
            });
        }

        // Add user message to history
        const userMsg: ChatMessage = {
            role: 'user',
            content: userMessage,
            timestamp: new Date(),
        };
        this.sessionManager.addMessage(sessionId, userMsg);

        // Build prompt with context
        const prompt = this.buildPrompt(session, userMessage);

        // Generate response
        const result = await this.engine.chat(
            prompt.messages,
            { temperature: this.config.temperature }
        );

        // Parse response and extract suggestions
        const { text, suggestions } = this.parseResponse(result.text);

        // Add assistant message to history
        const assistantMsg: ChatMessage = {
            role: 'assistant',
            content: text,
            timestamp: new Date(),
        };
        this.sessionManager.addMessage(sessionId, assistantMsg);

        // Prune history if too long
        this.pruneHistory(sessionId);

        return {
            message: { role: 'assistant' as const, content: text },
            suggestions: this.config.suggestActions ? suggestions : undefined,
            tokens: result.tokens,
            latencyMs: result.latencyMs,
        };
    }

    /**
     * Get session
     */
    getSession(sessionId: string): ChatSession | undefined {
        return this.sessionManager.getSession(sessionId);
    }

    /**
     * Update session context
     */
    updateContext(sessionId: string, context: Partial<ChatContext>): void {
        const session = this.sessionManager.getSession(sessionId);
        if (session) {
            this.sessionManager.updateSession(sessionId, {
                context: { ...session.context, ...context },
            });
        }
    }

    /**
     * End a session
     */
    endSession(sessionId: string): boolean {
        return this.sessionManager.deleteSession(sessionId);
    }

    /**
     * Get conversation history
     */
    getHistory(sessionId: string): ChatMessage[] {
        const session = this.sessionManager.getSession(sessionId);
        return session?.messages || [];
    }

    /**
     * Clear conversation history
     */
    clearHistory(sessionId: string): void {
        const session = this.sessionManager.getSession(sessionId);
        if (session) {
            this.sessionManager.updateSession(sessionId, { messages: [] });
        }
    }

    /**
     * Generate quick suggestions based on context
     */
    async generateSuggestions(sessionId: string): Promise<SuggestedAction[]> {
        const session = this.sessionManager.getSession(sessionId);
        if (!session) return [];

        const suggestions: SuggestedAction[] = [];
        const context = session.context;

        // Analyze context and generate relevant suggestions
        if (context.campaigns && context.campaigns.length > 0) {
            const recentCampaign = context.campaigns[0];
            suggestions.push({
                type: 'view',
                label: `View ${recentCampaign.name} performance`,
                action: 'view_campaign',
                params: { campaignId: recentCampaign.id },
            });
        }

        if (context.contacts && context.contacts > 0) {
            suggestions.push({
                type: 'action',
                label: 'Segment your audience',
                action: 'create_segment',
            });
        }

        // Generic suggestions
        suggestions.push(
            {
                type: 'action',
                label: 'Create new campaign',
                action: 'create_campaign',
            },
            {
                type: 'query',
                label: 'Analyze my metrics',
                action: 'analyze_metrics',
            },
            {
                type: 'query',
                label: 'Suggest subject lines',
                action: 'suggest_subjects',
            }
        );

        return suggestions.slice(0, 5);
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private buildPrompt(
        session: ChatSession,
        currentMessage: string
    ): { messages: Array<{ role: string; content: string }> } {
        const messages: Array<{ role: string; content: string }> = [];

        // Build context string
        const contextStr = this.buildContextString(session.context);

        // Add system message with context
        const systemPrompt = this.config.systemPrompt.replace(
            '{{context}}',
            contextStr
        );
        messages.push({ role: 'system', content: systemPrompt });

        // Add conversation history (limited)
        const historyLimit = Math.min(
            session.messages.length,
            this.config.maxHistoryLength
        );
        const historyStart = session.messages.length - historyLimit;

        for (let i = historyStart; i < session.messages.length; i++) {
            const msg = session.messages[i];
            messages.push({ role: msg.role, content: msg.content });
        }

        // Add current message
        messages.push({ role: 'user', content: currentMessage });

        return { messages };
    }

    private buildContextString(context: ChatContext): string {
        const parts: string[] = [];

        if (context.campaigns && context.campaigns.length > 0) {
            parts.push(
                `Active campaigns: ${context.campaigns
                    .map((c) => c.name)
                    .join(', ')}`
            );
        }

        if (context.contacts) {
            parts.push(`Total contacts: ${context.contacts.toLocaleString()}`);
        }

        if (context.recentActivity && context.recentActivity.length > 0) {
            parts.push(
                `Recent activity: ${context.recentActivity.slice(0, 3).join(', ')}`
            );
        }

        if (context.currentCampaign) {
            parts.push(`Currently editing: ${context.currentCampaign}`);
        }

        if (context.selectedSegment) {
            parts.push(`Selected segment: ${context.selectedSegment}`);
        }

        return parts.length > 0 ? parts.join('\n') : 'No specific context available.';
    }

    private parseResponse(text: string): {
        text: string;
        suggestions: SuggestedAction[];
    } {
        const suggestions: SuggestedAction[] = [];

        // Extract action suggestions from response
        // Look for patterns like [ACTION: type label]
        const actionPattern = /\[ACTION:\s*(\w+)\s+(.+?)\]/g;
        let match;

        while ((match = actionPattern.exec(text)) !== null) {
            suggestions.push({
                type: 'action' as const,
                label: match[2].trim(),
                action: match[1].toLowerCase(),
            });
        }

        // Remove action tags from text
        const cleanText = text.replace(actionPattern, '').trim();

        // Extract suggested queries
        // Look for bullet points starting with "•" or "-" that suggest actions
        const lines = cleanText.split('\n');
        for (const line of lines) {
            if (line.match(/^[•-]\s*(?:Try|Consider|You could|Suggestion:)/i)) {
                const label = line.replace(/^[•-]\s*/, '').trim();
                if (label.length < 100) {
                    suggestions.push({
                        type: 'query' as const,
                        label,
                        action: 'query',
                    });
                }
            }
        }

        return { text: cleanText, suggestions: suggestions.slice(0, 5) };
    }

    private pruneHistory(sessionId: string): void {
        const session = this.sessionManager.getSession(sessionId);
        if (!session || session.messages.length <= this.config.maxHistoryLength) {
            return;
        }

        const prunedMessages = session.messages.slice(-this.config.maxHistoryLength);
        this.sessionManager.updateSession(sessionId, { messages: prunedMessages });
    }
}

/**
 * Intent detection for routing queries
 */
export class IntentDetector {
    private patterns: Map<string, RegExp[]> = new Map();

    constructor() {
        this.initializePatterns();
    }

    private initializePatterns(): void {
        this.patterns.set('create_campaign', [
            /create\s+(?:a\s+)?(?:new\s+)?campaign/i,
            /start\s+(?:a\s+)?campaign/i,
            /new\s+email\s+campaign/i,
            /set\s+up\s+(?:a\s+)?campaign/i,
        ]);

        this.patterns.set('write_subject', [
            /write\s+(?:a\s+)?subject\s+line/i,
            /suggest\s+subject\s+lines?/i,
            /subject\s+line\s+ideas?/i,
            /help\s+(?:me\s+)?with\s+subject/i,
        ]);

        this.patterns.set('analyze_metrics', [
            /analyz[es]\s+(?:my\s+)?metrics/i,
            /show\s+(?:me\s+)?(?:my\s+)?analytics/i,
            /how\s+(?:is|are)\s+(?:my\s+)?campaigns?\s+(?:doing|performing)/i,
            /campaign\s+performance/i,
        ]);

        this.patterns.set('segment_audience', [
            /segment\s+(?:my\s+)?audience/i,
            /create\s+(?:a\s+)?segment/i,
            /target\s+(?:specific\s+)?audience/i,
            /divide\s+(?:my\s+)?(?:list|contacts)/i,
        ]);

        this.patterns.set('improve_deliverability', [
            /improve\s+deliverability/i,
            /inbox\s+placement/i,
            /avoid\s+spam/i,
            /sender\s+reputation/i,
        ]);

        this.patterns.set('write_email', [
            /write\s+(?:an?\s+)?email/i,
            /compose\s+(?:an?\s+)?email/i,
            /draft\s+(?:an?\s+)?email/i,
            /help\s+(?:me\s+)?write/i,
        ]);

        this.patterns.set('ab_test', [
            /a\/b\s+test/i,
            /split\s+test/i,
            /test\s+(?:different\s+)?versions?/i,
        ]);

        this.patterns.set('list_management', [
            /clean\s+(?:my\s+)?list/i,
            /list\s+hygiene/i,
            /remove\s+(?:inactive|bounced)/i,
            /manage\s+subscribers/i,
        ]);
    }

    /**
     * Detect intent from text
     */
    detect(text: string): { intent: string; confidence: number } | null {
        for (const [intent, patterns] of this.patterns) {
            for (const pattern of patterns) {
                if (pattern.test(text)) {
                    // Calculate confidence based on match quality
                    const match = text.match(pattern);
                    const matchLength = match?.[0]?.length || 0;
                    const confidence = Math.min(0.9, 0.5 + (matchLength / text.length) * 0.4);

                    return { intent, confidence };
                }
            }
        }

        return null;
    }

    /**
     * Get all possible intents
     */
    getIntents(): string[] {
        return Array.from(this.patterns.keys());
    }
}

export { DEFAULT_CHATBOT_CONFIG, DEFAULT_SYSTEM_PROMPT };
