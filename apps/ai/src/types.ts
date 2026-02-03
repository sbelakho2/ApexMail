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
    | 'delete_campaign'
    | 'create_list'
    | 'delete_list'
    | 'add_contacts'
    | 'add_contact'
    | 'remove_contacts'
    | 'remove_contact'
    | 'import_contacts'
    | 'tag_contacts'
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
