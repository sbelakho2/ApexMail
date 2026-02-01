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
    expiresAt: Date;
}

export interface ChatContext {
    campaignId?: string;
    contactId?: string;
    pageContext?: string;
    userIntent?: string;
    entities: ExtractedEntity[];
    sentiment?: SentimentResult;
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
    relatedResources?: RelatedResource[];
    sessionId: string;
}

export interface SuggestedAction {
    id: string;
    label: string;
    action: string;
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
    tenantId: string;
    userId: string;
    instruction: string;
    context?: MailbotContext;
    dryRun?: boolean;
}

export interface MailbotContext {
    currentCampaignId?: string;
    selectedContactIds?: string[];
    selectedListIds?: string[];
    recentActions?: RecentAction[];
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
    actions: MailbotAction[];
    warnings?: string[];
    requiresConfirmation?: boolean;
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
    | 'create_list'
    | 'add_contacts'
    | 'remove_contacts'
    | 'tag_contacts'
    | 'create_segment'
    | 'generate_content'
    | 'analyze_performance'
    | 'export_data'
    | 'set_automation';

// ========================================
// SEND TIME OPTIMIZATION (STO) TYPES
// ========================================

export interface STORequest {
    tenantId: string;
    campaignId: string;
    listId: string;
    constraints?: STOConstraints;
}

export interface STOConstraints {
    minSendTime?: Date;
    maxSendTime?: Date;
    excludedHours?: number[];
    excludedDays?: number[];
    timezone?: string;
    maxBatchSize?: number;
    deliveryWindow?: number; // hours
}

export interface STOResult {
    campaignId: string;
    recommendations: STORecommendation[];
    confidence: number;
    methodology: string;
    dataPoints: number;
}

export interface STORecommendation {
    contactId: string;
    optimalSendTime: Date;
    confidence: number;
    factors: STOFactor[];
    alternativeTimes?: Date[];
}

export interface STOFactor {
    name: string;
    weight: number;
    value: number;
    description: string;
}

export interface EngagementPattern {
    contactId: string;
    hourlyDistribution: number[];
    dayOfWeekDistribution: number[];
    timezone: string;
    lastEngagement?: Date;
    avgResponseTime?: number;
    preferredDevices: string[];
}

// ========================================
// CONTENT GENERATION TYPES
// ========================================

export interface ContentGenerationRequest {
    tenantId: string;
    type: ContentType;
    prompt: string;
    context?: ContentContext;
    style?: ContentStyle;
    constraints?: ContentConstraints;
}

export type ContentType = 
    | 'subject_line'
    | 'preview_text'
    | 'email_body'
    | 'cta_button'
    | 'headline'
    | 'product_description'
    | 'social_proof';

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
    variants: GeneratedContent[];
    metadata: ContentMetadata;
}

export interface GeneratedContent {
    id: string;
    content: string;
    score: number;
    analysis: ContentAnalysis;
}

export interface ContentAnalysis {
    readabilityScore: number;
    sentimentScore: number;
    spamScore: number;
    emotionalTone: string;
    keyThemes: string[];
    predictedEngagement?: number;
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
}

export interface SentimentResult {
    overall: SentimentScore;
    sentences?: SentenceSentiment[];
    aspects?: AspectSentiment[];
    emotions?: EmotionScores;
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
    tenantId: string;
    baseSubject: string;
    campaignGoal?: string;
    targetAudience?: string;
    variants?: number;
}

export interface SubjectLineResult {
    original: SubjectLineAnalysis;
    optimized: SubjectLineVariant[];
    recommendations: SubjectLineRecommendation[];
}

export interface SubjectLineAnalysis {
    subject: string;
    length: number;
    wordCount: number;
    hasPersonalization: boolean;
    hasEmoji: boolean;
    hasNumber: boolean;
    hasQuestion: boolean;
    hasUrgency: boolean;
    readingLevel: number;
    predictedOpenRate: number;
    spamScore: number;
    issues: SubjectLineIssue[];
}

export interface SubjectLineVariant {
    subject: string;
    score: number;
    predictedOpenRate: number;
    improvements: string[];
    analysis: SubjectLineAnalysis;
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
    tenantId: string;
    type: PredictionType;
    campaignId?: string;
    listId?: string;
    timeHorizon?: number;
}

export type PredictionType =
    | 'open_rate'
    | 'click_rate'
    | 'conversion_rate'
    | 'unsubscribe_rate'
    | 'churn_risk'
    | 'engagement_score'
    | 'revenue_impact';

export interface PredictionResult {
    type: PredictionType;
    prediction: number;
    confidence: number;
    range: { low: number; high: number };
    factors: PredictionFactor[];
    historicalComparison?: HistoricalComparison;
}

export interface PredictionFactor {
    name: string;
    impact: number;
    direction: 'positive' | 'negative' | 'neutral';
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
    tenantId: string;
    listId: string;
    segmentationType: SegmentationType;
    numSegments?: number;
}

export type SegmentationType =
    | 'behavioral'
    | 'demographic'
    | 'engagement'
    | 'rfm'
    | 'lifecycle'
    | 'custom';

export interface AudienceSegmentResult {
    segments: AudienceSegment[];
    segmentationQuality: number;
    methodology: string;
    recommendations: SegmentRecommendation[];
}

export interface AudienceSegment {
    id: string;
    name: string;
    description: string;
    size: number;
    percentage: number;
    characteristics: SegmentCharacteristic[];
    avgEngagementScore: number;
    suggestedStrategy: string;
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
    tenantId: string;
    testId: string;
    variants: ABTestVariant[];
    metric: string;
    confidenceLevel?: number;
}

export interface ABTestVariant {
    id: string;
    name: string;
    sampleSize: number;
    conversions: number;
    revenue?: number;
}

export interface ABTestAnalysisResult {
    winner: string | null;
    confidence: number;
    isStatisticallySignificant: boolean;
    variants: ABTestVariantResult[];
    recommendation: string;
    sampleSizeRecommendation?: number;
    estimatedTimeToSignificance?: number;
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
