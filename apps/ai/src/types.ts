/**
 * @apexmail/ai - AI Intelligence Suite Types
 * 
 * Type definitions for AI services including:
 * - Local LLM inference with ONNX Runtime
 * - Chatbot and Mailbot assistants
 * - Send Time Optimization (STO)
 * - Content generation and analysis
 */

// ========================================
// INFERENCE ENGINE TYPES
// ========================================

export interface InferenceConfig {
    modelPath: string;
    modelName: string;
    maxTokens: number;
    temperature: number;
    topP: number;
    topK: number;
    repetitionPenalty: number;
    stopSequences: string[];
    useGPU: boolean;
    numThreads: number;
    contextLength: number;
}

export interface InferenceResult {
    text: string;
    tokens: number;
    promptTokens: number;
    completionTokens: number;
    latencyMs: number;
    model: string;
    finishReason: 'stop' | 'length' | 'error';
}

export interface EmbeddingResult {
    embedding: number[];
    dimensions: number;
    model: string;
    latencyMs: number;
}

export interface TokenizeResult {
    tokens: number[];
    tokenCount: number;
}

// ========================================
// CHATBOT TYPES
// ========================================

export type ChatRole = 'system' | 'user' | 'assistant';

export interface ChatMessage {
    role: ChatRole;
    content: string;
    timestamp?: Date;
    metadata?: Record<string, unknown>;
}

export interface ChatSession {
    id: string;
    tenantId: string;
    userId?: string;
    messages: ChatMessage[];
    context: ChatContext;
    createdAt: Date;
    updatedAt: Date;
    expiresAt?: Date;
    metadata?: Record<string, unknown>;
}

export interface CustomerProfile {
    /** Customer display name */
    name?: string;
    /** Customer email address */
    email?: string;
    /** Current subscription plan */
    plan?: 'free' | 'starter' | 'professional' | 'enterprise';
    /** Account status */
    accountStatus?: 'active' | 'suspended' | 'past_due' | 'trial' | 'cancelled';
    /** Monthly send quota */
    sendQuota?: number;
    /** Sends used this billing period */
    sendsUsed?: number;
    /** Account creation date */
    memberSince?: Date;
    /** Verified email domains */
    verifiedDomains?: string[];
    /** Whether the user has completed onboarding */
    onboarded?: boolean;
    /** User role in the organization */
    role?: 'owner' | 'admin' | 'editor' | 'viewer';
    /** Organization/company name */
    organization?: string;
    /** Two-factor authentication enabled */
    twoFactorEnabled?: boolean;
    /** Session authentication level */
    authLevel?: 'basic' | 'verified' | 'elevated';
}

export interface ChatContext {
    campaignId?: string;
    contactId?: string;
    pageContext?: string;
    userIntent?: string;
    entities?: ExtractedEntity[];
    sentiment?: SentimentResult;
    campaigns?: Array<{ id: string; name: string }>;
    contacts?: number;
    recentActivity?: string[];
    currentCampaign?: string;
    selectedSegment?: string;
    /** Customer profile for personalized, context-aware support */
    customer?: CustomerProfile;
    /** Whether the current session has been identity-verified */
    authenticated?: boolean;
    /** Tenant ID for multi-tenant isolation */
    tenantId?: string;
}

export interface ExtractedEntity {
    type: 'campaign' | 'list' | 'contact' | 'date' | 'metric' | 'action';
    value: string;
    confidence: number;
    span: { start: number; end: number };
}

export interface ChatResponse {
    message: ChatMessage;
    suggestedActions?: SuggestedAction[];
    suggestions?: SuggestedAction[];
    relatedResources?: RelatedResource[];
    sessionId?: string;
    tokens?: number;
    latencyMs?: number;
}

export interface SuggestedAction {
    id?: string;
    label: string;
    action: string;
    type?: string;
    params?: Record<string, unknown>;
    icon?: string;
}

export interface RelatedResource {
    type: 'campaign' | 'list' | 'contact' | 'template' | 'report';
    id: string;
    title: string;
    url: string;
    relevanceScore: number;
}

// ========================================
// MAILBOT TYPES
// ========================================

export interface MailbotRequest {
    tenantId?: string;
    userId: string;
    instruction?: string;
    command?: string;
    context?: MailbotContext;
    dryRun?: boolean;
}

export interface MailbotContext {
    currentCampaignId?: string;
    selectedContactIds?: string[];
    selectedListIds?: string[];
    recentActions?: RecentAction[];
    activeList?: string;
    activeCampaign?: string;
}

export interface RecentAction {
    action: string;
    targetType: string;
    targetId: string;
    timestamp: Date;
}

export interface MailbotResponse {
    success: boolean;
    message: string;
    actions?: MailbotAction[];
    action?: MailbotAction;
    warnings?: string[];
    requiresConfirmation?: boolean;
    confirmationId?: string;
    latencyMs?: number;
}

export interface MailbotAction {
    type: MailbotActionType;
    description: string;
    params: Record<string, unknown>;
    estimatedImpact?: string;
    executed?: boolean;
    result?: unknown;
}

export type MailbotActionType =
    | 'create_campaign'
    | 'send_campaign'
    | 'schedule_campaign'
    | 'pause_campaign'
    | 'resume_campaign'
    | 'stop_campaign'
    | 'delete_campaign'
    | 'create_list'
    | 'delete_list'
    | 'add_contacts'
    | 'add_contact'
    | 'remove_contacts'
    | 'remove_contact'
    | 'import_contacts'
    | 'tag_contacts'
    | 'tag_contact'
    | 'create_segment'
    | 'generate_content'
    | 'analyze_performance'
    | 'get_stats'
    | 'export_data'
    | 'export_report'
    | 'set_automation';

// ========================================
// SEND TIME OPTIMIZATION (STO) TYPES
// ========================================

export interface STORequest {
    tenantId: string;
    campaignId: string;
    listId?: string;
    subscriberIds?: string[];
    timezone?: string;
    constraints?: STOConstraints;
}

export interface STOConstraints {
    minSendTime?: Date;
    maxSendTime?: Date;
    excludedHours?: number[];
    excludeHours?: number[];
    excludedDays?: number[];
    timezone?: string;
    maxBatchSize?: number;
    deliveryWindow?: number; // hours
    excludeWeekends?: boolean;
    businessHoursOnly?: boolean;
}

export interface STOResult {
    campaignId?: string;
    recommendations: STORecommendation[];
    confidence: number;
    methodology?: string;
    dataPoints: number;
    factors?: STOFactor[];
    latencyMs?: number;
}

export interface STORecommendation {
    contactId?: string;
    optimalSendTime?: Date;
    sendTime: Date;
    confidence: number;
    factors?: STOFactor[];
    alternativeTimes?: Date[];
    timezone?: string;
    expectedOpenRate?: number;
    expectedClickRate?: number;
    reason?: string;
}

export interface STOFactor {
    name: string;
    weight?: number;
    value?: number;
    description: string;
    impact: number;
    direction?: 'positive' | 'negative' | 'neutral';
}

export interface EngagementPattern {
    contactId: string;
    hourlyDistribution: number[];
    dayOfWeekDistribution: number[];
    timezone: string;
    lastEngagement?: Date;
    avgResponseTime?: number;
    preferredDevices: string[];
    timestamp: Date;
    sentAt?: Date;
    openedAt?: Date;
    clickedAt?: Date;
    opened: boolean;
    clicked: boolean;
}

// ========================================
// CONTENT GENERATION TYPES
// ========================================

export interface ContentGenerationRequest {
    tenantId?: string;
    type: ContentType;
    prompt?: string;
    context?: ContentContext;
    style?: ContentStyle | string;
    constraints?: ContentConstraints;
    features?: string[];
    topic?: string;
    industry?: string;
    keywords?: string[];
    variants?: number;
    subjectLine?: string;
    goal?: string;
    keyPoints?: string[];
}

export type ContentType = 
    | 'subject_line'
    | 'preview_text'
    | 'preheader'
    | 'email_body'
    | 'cta_button'
    | 'cta'
    | 'headline'
    | 'product_description'
    | 'social_proof'
    | 'ps_line';

export interface ContentContext {
    brandVoice?: string;
    targetAudience?: string;
    campaignGoal?: string;
    productInfo?: string;
    previousContent?: string[];
    competitorExamples?: string[];
}

export interface ContentStyle {
    tone: 'professional' | 'casual' | 'friendly' | 'urgent' | 'humorous';
    formality: 'formal' | 'neutral' | 'informal';
    length: 'short' | 'medium' | 'long';
    emotionalAppeal?: string;
}

export interface ContentConstraints {
    maxLength?: number;
    minLength?: number;
    requiredKeywords?: string[];
    excludedWords?: string[];
    includeEmoji?: boolean;
    includePersonalization?: boolean;
}

export interface ContentGenerationResult {
    variants?: GeneratedContent[] | string[];
    metadata?: ContentMetadata;
    content?: string;
    type?: ContentType;
    style?: ContentStyle | string;
    analysis?: ContentAnalysis;
    latencyMs?: number;
}

export interface GeneratedContent {
    id: string;
    content: string;
    score: number;
    analysis: ContentAnalysis;
}

export interface ContentAnalysis {
    readabilityScore: number;
    sentimentScore?: number;
    spamScore: number;
    emotionalTone?: string;
    keyThemes?: string[];
    predictedEngagement?: number;
    wordCount: number;
    sentenceCount?: number;
    engagementScore?: number;
    suggestions?: string[];
}

export interface ContentMetadata {
    generationTime: number;
    model: string;
    promptTokens: number;
    completionTokens: number;
}

// ========================================
// SENTIMENT ANALYSIS TYPES
// ========================================

export interface SentimentRequest {
    text: string;
    language?: string;
    granularity?: 'document' | 'sentence' | 'aspect';
    aspects?: string[]; // For aspect-based sentiment analysis
}

export interface SentimentResult {
    overall?: SentimentScore;
    sentences?: SentenceSentiment[];
    aspects?: AspectSentiment[];
    emotions?: EmotionScores;
    sentiment?: 'positive' | 'negative' | 'neutral';
    score?: number;
    confidence?: number;
    keywords?: string[];
    latencyMs?: number;
}

export interface SentimentScore {
    label: 'positive' | 'negative' | 'neutral' | 'mixed';
    score: number;
    confidence: number;
}

export interface SentenceSentiment {
    text: string;
    sentiment: SentimentScore;
    span: { start: number; end: number };
}

export interface AspectSentiment {
    aspect: string;
    sentiment: SentimentScore;
    mentions: string[];
}

export interface EmotionScores {
    joy: number;
    sadness: number;
    anger: number;
    fear: number;
    surprise: number;
    trust: number;
    anticipation: number;
    disgust: number;
}

// ========================================
// SUBJECT LINE OPTIMIZATION TYPES
// ========================================

export interface SubjectLineRequest {
    tenantId?: string;
    baseSubject?: string;
    campaignGoal?: string;
    targetAudience?: string;
    variants?: number;
    topic: string;
    tone?: string;
    industry?: string;
    keywords?: string[];
    count?: number;
    product?: string;
    benefit?: string;
    offer?: string;
    audience?: string;
    timeframe?: string;
    number?: number;
    action?: string;
}

export interface SubjectLineResult {
    original?: SubjectLineAnalysis;
    optimized?: SubjectLineVariant[];
    recommendations?: SubjectLineRecommendation[];
    variants: SubjectLineVariant[];
    bestVariant?: SubjectLineVariant;
    latencyMs?: number;
}

export interface SubjectLineAnalysis {
    subject?: string;
    length?: number;
    wordCount?: number;
    hasPersonalization?: boolean;
    hasEmoji?: boolean;
    hasNumber?: boolean;
    hasQuestion?: boolean;
    hasUrgency?: boolean;
    readingLevel?: number;
    predictedOpenRate?: number;
    spamScore?: number;
    issues?: SubjectLineIssue[];
    score?: number;
    predictions?: {
        openRate: number;
        spamProbability: number;
    };
}

export interface SubjectLineVariant {
    subject?: string;
    text?: string;
    score: number;
    predictedOpenRate?: number;
    improvements?: string[];
    analysis?: SubjectLineAnalysis;
}

export interface SubjectLineRecommendation {
    type: 'length' | 'personalization' | 'emoji' | 'urgency' | 'clarity' | 'spam';
    message: string;
    priority: 'high' | 'medium' | 'low';
}

export interface SubjectLineIssue {
    type: string;
    message: string;
    severity: 'error' | 'warning' | 'info';
    span?: { start: number; end: number };
}

// ========================================
// PREDICTIVE ANALYTICS TYPES
// ========================================

export interface PredictionRequest {
    tenantId?: string;
    type: PredictionType;
    campaignId?: string;
    listId?: string;
    timeHorizon?: number;
    sendHour?: number;
    sendDay?: number;
    subjectLength?: number;
    listSize?: number;
    expectedOpenRate?: number;
    expectedClickRate?: number;
    hasPersonalization?: boolean;
    emailFrequency?: number;
    subscriberId?: string;
    avgOrderValue?: number;
}

export type PredictionType =
    | 'open_rate'
    | 'click_rate'
    | 'conversion_rate'
    | 'unsubscribe_rate'
    | 'churn_risk'
    | 'engagement_score'
    | 'revenue_impact'
    | 'revenue'
    | 'best_time';

export interface PredictionResult {
    type?: PredictionType;
    prediction: number;
    confidence: number;
    range: { low?: number; high?: number; min?: number; max?: number };
    factors: PredictionFactor[];
    historicalComparison?: HistoricalComparison;
    dataPoints?: number;
    latencyMs?: number;
}

export interface PredictionFactor {
    name: string;
    impact: number;
    direction?: 'positive' | 'negative' | 'neutral';
    description: string;
}

export interface HistoricalComparison {
    average: number;
    percentile: number;
    trend: 'improving' | 'declining' | 'stable';
    trendMagnitude: number;
}

// ========================================
// AUDIENCE INTELLIGENCE TYPES
// ========================================

export interface AudienceSegmentRequest {
    tenantId?: string;
    listId?: string;
    segmentationType?: SegmentationType;
    type?: SegmentationType;
    numSegments?: number;
    criteria?: Record<string, unknown>;
}

export type SegmentationType =
    | 'behavioral'
    | 'demographic'
    | 'engagement'
    | 'rfm'
    | 'lifecycle'
    | 'custom'
    | 'recency'
    | 'frequency';

export interface AudienceSegmentResult {
    segments: AudienceSegment[];
    segmentationQuality?: number;
    methodology?: string;
    recommendations?: SegmentRecommendation[];
    totalSubscribers?: number;
    segmentationType?: SegmentationType;
    latencyMs?: number;
}

export interface AudienceSegment {
    id: string;
    name: string;
    description?: string;
    size: number;
    percentage: number;
    characteristics: SegmentCharacteristic[] | Record<string, unknown>;
    avgEngagementScore?: number;
    suggestedStrategy?: string;
    recommendedAction?: string;
}

export interface SegmentCharacteristic {
    attribute: string;
    value: string | number;
    importance: number;
}

export interface SegmentRecommendation {
    segmentId: string;
    type: 'content' | 'timing' | 'frequency' | 'channel';
    recommendation: string;
    expectedImpact: string;
}

// ========================================
// A/B TEST INTELLIGENCE TYPES
// ========================================

export interface ABTestAnalysisRequest {
    tenantId?: string;
    testId?: string;
    variants?: ABTestVariant[];
    metric?: string;
    confidenceLevel?: number;
    variantA?: {
        sent: number;
        opens: number;
        clicks: number;
        conversions?: number;
    };
    variantB?: {
        sent: number;
        opens: number;
        clicks: number;
        conversions?: number;
    };
}

export interface ABTestVariant {
    id: string;
    name: string;
    sampleSize: number;
    conversions: number;
    revenue?: number;
}

export interface VariantMetrics {
    rate: number;
    samples: number;
    conversions: number;
}

export interface ABTestAnalysisResult {
    winner: string | null;
    confidence: number;
    isStatisticallySignificant?: boolean;
    significant?: boolean;
    variants?: ABTestVariantResult[];
    recommendation: string;
    sampleSizeRecommendation?: number;
    estimatedTimeToSignificance?: number;
    lift?: number;
    pValue?: number;
    latencyMs?: number;
    variantAMetrics?: VariantMetrics;
    variantBMetrics?: VariantMetrics;
    sampleSize?: {
        current: number;
        required: number;
        sufficient: boolean;
    };
}

export interface ABTestVariantResult {
    id: string;
    conversionRate: number;
    confidence: number;
    probabilityToBeatBaseline: number;
    uplift?: number;
    revenuePerVisitor?: number;
}

// ========================================
// MODEL MANAGEMENT TYPES
// ========================================

export interface ModelInfo {
    name: string;
    version: string;
    type: 'llm' | 'embedding' | 'classifier' | 'regressor';
    size: number;
    loadedAt?: Date;
    status: ModelStatus;
    metrics?: ModelMetrics;
}

export type ModelStatus = 'loading' | 'ready' | 'error' | 'unloaded';

export interface ModelMetrics {
    requestCount: number;
    avgLatencyMs: number;
    errorRate: number;
    tokensProcessed: number;
    lastUsed?: Date;
}

export interface ModelLoadRequest {
    modelName: string;
    modelPath?: string;
    config?: Partial<InferenceConfig>;
}

// ========================================
// API REQUEST/RESPONSE TYPES
// ========================================

export interface AIServiceRequest {
    tenantId: string;
    userId?: string;
    requestId: string;
    timestamp: Date;
}

export interface AIServiceResponse<T> {
    success: boolean;
    data?: T;
    error?: AIServiceError;
    requestId: string;
    latencyMs: number;
}

export interface AIServiceError {
    code: string;
    message: string;
    details?: Record<string, unknown>;
}

// ========================================
// AUTONOMOUS ASSISTANT TYPES
// ========================================

/** Risk level for autonomous actions */
export type AutonomousRiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

/** Escalation reason codes */
export type EscalationReason =
    | 'high_risk_action'        // Action is too risky for autonomous execution
    | 'billing_change'          // Financial impact requires human approval
    | 'account_deletion'        // Destructive account-level action
    | 'data_export'             // Bulk data leaving the platform
    | 'compliance_concern'      // Potential regulatory issue
    | 'angry_customer'          // Sentiment detection → human needed
    | 'repeated_failure'        // Bot failed multiple times → needs human
    | 'ambiguous_intent'        // Can't confidently determine what user wants
    | 'security_incident'       // Suspicious activity detected
    | 'quota_override'          // User requesting quota exception
    | 'custom_request'          // Request outside bot capabilities
    | 'confidence_too_low'      // Intent confidence below threshold
    | 'multi_step_risky'        // Multi-step workflow with cumulative risk
    | 'pii_detected'            // PII in request needs human handling
    | 'legal_request';          // Legal/subpoena/compliance request

/** Escalation ticket created when bot can't handle autonomously */
export interface EscalationTicket {
    id: string;
    sessionId: string;
    tenantId: string;
    userId: string;
    reason: EscalationReason;
    severity: 'low' | 'medium' | 'high' | 'urgent';
    summary: string;
    conversationHistory: Array<{ role: string; content: string }>;
    suggestedAction?: string;
    customerProfile?: CustomerProfile;
    createdAt: Date;
    status: 'open' | 'assigned' | 'resolved' | 'dismissed';
    assignedTo?: string;
    resolvedAt?: Date;
    resolution?: string;
}

/** Configuration for autonomous mode — set by control-plane owner */
export interface AutonomousConfig {
    /** Master toggle — enables/disables autonomous mode */
    enabled: boolean;
    /** Actions the bot may execute without user confirmation */
    autoApproveActions: string[];
    /** Actions that ALWAYS require human escalation */
    alwaysEscalateActions: string[];
    /** Confidence threshold — below this, escalate to human */
    confidenceThreshold: number;
    /** Maximum autonomous actions per session before forcing escalation */
    maxAutoActionsPerSession: number;
    /** Maximum monetary value ($) of autonomous billing actions */
    maxAutonomousBillingAmount: number;
    /** Enable proactive outreach (bot initiates conversations) */
    proactiveOutreach: boolean;
    /** Proactive triggers */
    proactiveTriggers: ProactiveTrigger[];
    /** Sentiment threshold — below this negative score, escalate */
    sentimentEscalationThreshold: number;
    /** Rate limit for autonomous actions per hour per tenant */
    autonomousActionsPerHour: number;
    /** Allowed hours for autonomous actions (UTC) */
    allowedHoursUtc: { start: number; end: number };
    /** Audit log every autonomous action */
    auditAllActions: boolean;
    /** Dry-run mode — log actions but don't execute */
    dryRun: boolean;
}

/** Proactive trigger — bot reaches out based on events */
export interface ProactiveTrigger {
    id: string;
    event: ProactiveTriggerEvent;
    enabled: boolean;
    action: string;
    messageTemplate: string;
    cooldownMinutes: number;
}

export type ProactiveTriggerEvent =
    | 'deliverability_drop'      // Deliverability score drops below threshold
    | 'bounce_rate_spike'        // Bounce rate exceeds threshold
    | 'quota_approaching'        // >80% of send quota used
    | 'domain_expiring'          // Domain cert/DNS about to expire
    | 'campaign_stalled'         // Campaign hasn't been sent in N days
    | 'billing_past_due'         // Payment failed/past due
    | 'new_user_onboarding'      // New user hasn't completed setup
    | 'engagement_drop'          // Open/click rates dropping
    | 'compliance_deadline'      // GDPR/CAN-SPAM deadline approaching
    | 'api_errors_spike';        // API error rate exceeding threshold

/** Autonomous action audit log entry */
export interface AutonomousAuditEntry {
    id: string;
    tenantId: string;
    sessionId: string;
    userId: string;
    action: string;
    params: Record<string, unknown>;
    riskLevel: AutonomousRiskLevel;
    autoApproved: boolean;
    escalated: boolean;
    escalationReason?: EscalationReason;
    result?: 'success' | 'failure' | 'pending';
    timestamp: Date;
    durationMs: number;
}
