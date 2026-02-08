/**
 * @apexmail/ai - Predictive Analytics Engine
 * 
 * ML-powered predictions for campaign performance, churn risk,
 * and subscriber behavior using statistical modeling.
 */

import type {
    PredictionRequest,
    PredictionResult,
    PredictionType,
    AudienceSegmentRequest,
    AudienceSegmentResult,
    ABTestAnalysisRequest,
    ABTestAnalysisResult,
} from '../types.js';

/**
 * Prediction model configuration
 */
export interface PredictorConfig {
    minDataPoints: number;
    confidenceThreshold: number;
    modelUpdateInterval: number;
}

/**
 * Historical data point for training
 */
interface HistoricalData {
    campaignId: string;
    sentAt: Date;
    listSize: number;
    openRate: number;
    clickRate: number;
    unsubscribeRate: number;
    bounceRate: number;
    conversionRate?: number;
    revenue?: number;
    subject: string;
    industry?: string;
    dayOfWeek: number;
    hourOfDay: number;
}

/**
 * Subscriber behavior data
 */
interface SubscriberBehavior {
    subscriberId: string;
    totalEmails: number;
    opens: number;
    clicks: number;
    lastOpenedAt?: Date;
    lastClickedAt?: Date;
    daysInactive: number;
    engagementScore: number;
}

/**
 * Default configuration
 */
const DEFAULT_PREDICTOR_CONFIG: PredictorConfig = {
    minDataPoints: 50,
    confidenceThreshold: 0.6,
    modelUpdateInterval: 86400000, // 24 hours
};

// FIX-500-398: Prevent unbounded growth of in-memory data
const MAX_HISTORICAL_DATA = 100_000;
const MAX_SUBSCRIBERS = 50_000;

/**
 * Predictive Analytics Engine
 * 
 * Provides ML-based predictions for email marketing metrics
 * and subscriber behavior analysis.
 */
export class PredictiveAnalytics {
    private config: PredictorConfig;
    private historicalData: HistoricalData[] = [];
    private subscriberData: Map<string, SubscriberBehavior> = new Map();
    private modelCoefficients: Map<PredictionType, number[]> = new Map();
    private lastModelUpdate: Date | null = null;

    constructor(config?: Partial<PredictorConfig>) {
        this.config = { ...DEFAULT_PREDICTOR_CONFIG, ...config };
        this.initializeDefaultCoefficients();
    }

    /**
     * Make a prediction based on request
     */
    async predict(request: PredictionRequest): Promise<PredictionResult> {
        const startTime = Date.now();

        // Update model if needed
        if (this.shouldUpdateModel()) {
            this.updateModels();
        }

        try {
            let prediction: number;
            let confidence: number;
            let factors: Array<{ name: string; impact: number; description: string }>;

            switch (request.type) {
                case 'open_rate':
                    ({ prediction, confidence, factors } = this.predictOpenRate(request));
                    break;
                case 'click_rate':
                    ({ prediction, confidence, factors } = this.predictClickRate(request));
                    break;
                case 'conversion_rate':
                    ({ prediction, confidence, factors } = this.predictConversionRate(request));
                    break;
                case 'unsubscribe_rate':
                    ({ prediction, confidence, factors } = this.predictUnsubscribeRate(request));
                    break;
                case 'churn_risk':
                    ({ prediction, confidence, factors } = this.predictChurnRisk(request));
                    break;
                case 'revenue':
                    ({ prediction, confidence, factors } = this.predictRevenue(request));
                    break;
                case 'best_time': {
                    const bestTime = this.predictBestTime(request);
                    return {
                        prediction: bestTime.hour,
                        confidence: bestTime.confidence,
                        factors: bestTime.factors,
                        range: { min: bestTime.hour - 1, max: bestTime.hour + 1 },
                        dataPoints: this.historicalData.length,
                        latencyMs: Date.now() - startTime,
                    };
                }
                default:
                    throw new Error(`Unknown prediction type: ${request.type}`);
            }

            // Calculate prediction range
            const range = this.calculateRange(prediction, confidence);

            return {
                prediction,
                confidence,
                factors,
                range,
                dataPoints: this.historicalData.length,
                latencyMs: Date.now() - startTime,
            };
        } catch (error) {
            throw new Error(`Prediction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Segment audience based on criteria
     */
    async segmentAudience(request: AudienceSegmentRequest): Promise<AudienceSegmentResult> {
        const startTime = Date.now();
        const subscribers = Array.from(this.subscriberData.values());

        if (subscribers.length === 0) {
            return {
                segments: [],
                totalSubscribers: 0,
                segmentationType: request.type,
                latencyMs: Date.now() - startTime,
            };
        }

        let segments: Array<{
            id: string;
            name: string;
            size: number;
            percentage: number;
            characteristics: Record<string, unknown>;
            recommendedAction: string;
        }>;

        switch (request.type) {
            case 'engagement':
                segments = this.segmentByEngagement(subscribers);
                break;
            case 'recency':
                segments = this.segmentByRecency(subscribers);
                break;
            case 'frequency':
                segments = this.segmentByFrequency(subscribers);
                break;
            case 'rfm':
                segments = this.segmentByRFM(subscribers);
                break;
            case 'lifecycle':
                segments = this.segmentByLifecycle(subscribers);
                break;
            case 'behavioral':
                segments = this.segmentByBehavior(subscribers);
                break;
            default:
                segments = this.segmentByEngagement(subscribers);
        }

        return {
            segments,
            totalSubscribers: subscribers.length,
            segmentationType: request.type,
            latencyMs: Date.now() - startTime,
        };
    }

    /**
     * Analyze A/B test results
     */
    async analyzeABTest(request: ABTestAnalysisRequest): Promise<ABTestAnalysisResult> {
        const startTime = Date.now();
        const { variantA, variantB, metric } = request;
        const metricStr = metric ?? 'open_rate';

        if (!variantA || !variantB) {
            throw new Error('Both variantA and variantB are required');
        }

        // Calculate key metrics
        const rateA = this.calculateRate(variantA, metricStr);
        const rateB = this.calculateRate(variantB, metricStr);

        // Statistical significance using z-test
        const { significant, pValue, confidence } = this.calculateSignificance(
            variantA,
            variantB,
            metricStr
        );

        // Determine winner
        const lift = rateA > 0 ? ((rateB - rateA) / rateA) * 100 : 0;
        const winner = !significant ? 'none' :
            rateB > rateA ? 'B' : rateA > rateB ? 'A' : 'none';

        // Sample size recommendations
        const { required, current, needsMore } = this.calculateSampleSize(
            variantA,
            variantB,
            metricStr
        );

        return {
            winner,
            lift,
            confidence,
            pValue,
            significant,
            variantAMetrics: {
                rate: rateA,
                samples: variantA.sent,
                conversions: this.getMetricValue(variantA, metricStr),
            },
            variantBMetrics: {
                rate: rateB,
                samples: variantB.sent,
                conversions: this.getMetricValue(variantB, metricStr),
            },
            sampleSize: {
                current,
                required,
                sufficient: !needsMore,
            },
            recommendation: this.buildABRecommendation(winner, lift, significant, needsMore),
            latencyMs: Date.now() - startTime,
        };
    }

    /**
     * Add historical campaign data
     */
    addHistoricalData(data: HistoricalData): void {
        this.historicalData.push(data);
        
        // Keep only recent data (last year)
        const cutoff = new Date();
        cutoff.setFullYear(cutoff.getFullYear() - 1);
        this.historicalData = this.historicalData.filter(
            (d) => d.sentAt >= cutoff
        );

        // FIX-500-398: Hard cap on array size to prevent unbounded growth
        if (this.historicalData.length > MAX_HISTORICAL_DATA) {
            this.historicalData = this.historicalData.slice(-MAX_HISTORICAL_DATA);
        }
    }

    /**
     * Add subscriber behavior data
     */
    addSubscriberData(data: SubscriberBehavior): void {
        this.subscriberData.set(data.subscriberId, data);

        // FIX-500-398: Evict oldest entry if cap exceeded
        if (this.subscriberData.size > MAX_SUBSCRIBERS) {
            const firstKey = this.subscriberData.keys().next().value;
            if (firstKey !== undefined) {
                this.subscriberData.delete(firstKey);
            }
        }
    }

    /**
     * Get model statistics
     */
    getStats(): {
        historicalDataPoints: number;
        subscriberCount: number;
        lastModelUpdate: Date | null;
        modelTypes: PredictionType[];
    } {
        return {
            historicalDataPoints: this.historicalData.length,
            subscriberCount: this.subscriberData.size,
            lastModelUpdate: this.lastModelUpdate,
            modelTypes: Array.from(this.modelCoefficients.keys()),
        };
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private initializeDefaultCoefficients(): void {
        // Initialize with industry-average baseline coefficients
        // These would be refined through actual ML training in production

        this.modelCoefficients.set('open_rate', [
            0.22,  // Base rate
            0.05,  // Time of day factor
            0.03,  // Day of week factor
            0.02,  // Subject line length factor
            -0.01, // List size factor (larger lists = slightly lower rates)
        ]);

        this.modelCoefficients.set('click_rate', [
            0.03,  // Base rate
            0.02,  // Open rate correlation
            0.01,  // CTA factor
            0.005, // Personalization factor
        ]);

        this.modelCoefficients.set('conversion_rate', [
            0.02,  // Base rate
            0.015, // Click rate correlation
            0.01,  // Offer strength factor
        ]);

        this.modelCoefficients.set('unsubscribe_rate', [
            0.002, // Base rate
            0.001, // Frequency factor
            -0.0005, // Engagement correlation (higher engagement = lower unsub)
        ]);

        this.modelCoefficients.set('churn_risk', [
            0.1,   // Base risk
            0.05,  // Inactivity factor
            0.03,  // Declining engagement factor
        ]);
    }

    private shouldUpdateModel(): boolean {
        if (!this.lastModelUpdate) return true;
        const elapsed = Date.now() - this.lastModelUpdate.getTime();
        return elapsed >= this.config.modelUpdateInterval;
    }

    private updateModels(): void {
        // In production, this would run actual ML training
        // For now, adjust coefficients based on historical data

        if (this.historicalData.length < this.config.minDataPoints) {
            // FIX-500-397: Don't set lastModelUpdate when skipping due to
            // insufficient data — otherwise the model won't retry for another
            // full modelUpdateInterval even though no training was done.
            return;
        }

        // Calculate average rates from historical data
        const avgOpenRate = this.average(this.historicalData.map((d) => d.openRate));
        const avgClickRate = this.average(this.historicalData.map((d) => d.clickRate));
        const avgUnsubRate = this.average(this.historicalData.map((d) => d.unsubscribeRate));

        // AI-003 FIX: Clone coefficients before mutation to ensure immutability
        // This prevents unintended side effects from shared references
        const openCoeffs = [...(this.modelCoefficients.get('open_rate') ?? [])];
        openCoeffs[0] = avgOpenRate;
        this.modelCoefficients.set('open_rate', openCoeffs);

        const clickCoeffs = [...(this.modelCoefficients.get('click_rate') ?? [])];
        clickCoeffs[0] = avgClickRate;
        this.modelCoefficients.set('click_rate', clickCoeffs);

        const unsubCoeffs = [...(this.modelCoefficients.get('unsubscribe_rate') ?? [])];
        unsubCoeffs[0] = avgUnsubRate;
        this.modelCoefficients.set('unsubscribe_rate', unsubCoeffs);

        this.lastModelUpdate = new Date();
    }

    private predictOpenRate(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const coeffs = this.modelCoefficients.get('open_rate')!;
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        let prediction = coeffs[0]; // Base rate

        // Time of day adjustment
        const hourFactor = this.getTimeFactor(request.sendHour || 10);
        prediction += coeffs[1] * hourFactor;
        factors.push({
            name: 'Send Time',
            impact: coeffs[1] * hourFactor,
            description: this.describeTimeFactor(request.sendHour || 10),
        });

        // Day of week adjustment
        const dayFactor = this.getDayFactor(request.sendDay || 2);
        prediction += coeffs[2] * dayFactor;
        factors.push({
            name: 'Day of Week',
            impact: coeffs[2] * dayFactor,
            description: this.describeDayFactor(request.sendDay || 2),
        });

        // Subject line factor
        if (request.subjectLength) {
            const subjectFactor = request.subjectLength < 50 ? 0.5 : request.subjectLength < 70 ? 0 : -0.5;
            prediction += coeffs[3] * subjectFactor;
            factors.push({
                name: 'Subject Length',
                impact: coeffs[3] * subjectFactor,
                description: `Subject line is ${request.subjectLength} characters`,
            });
        }

        // List size factor
        if (request.listSize) {
            const sizeFactor = Math.log10(request.listSize) / 6;
            prediction += coeffs[4] * sizeFactor;
            factors.push({
                name: 'List Size',
                impact: coeffs[4] * sizeFactor,
                description: `Sending to ${request.listSize.toLocaleString()} subscribers`,
            });
        }

        // Calculate confidence based on data availability
        const confidence = Math.min(
            this.historicalData.length / (this.config.minDataPoints * 2),
            0.95
        );

        return {
            prediction: Math.max(0, Math.min(1, prediction)),
            confidence,
            factors,
        };
    }

    private predictClickRate(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const coeffs = this.modelCoefficients.get('click_rate')!;
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        let prediction = coeffs[0];

        // Open rate correlation
        if (request.expectedOpenRate) {
            const openCorrelation = request.expectedOpenRate / 0.22;
            prediction *= openCorrelation;
            factors.push({
                name: 'Expected Opens',
                impact: coeffs[1] * openCorrelation,
                description: `Based on ${(request.expectedOpenRate * 100).toFixed(1)}% expected open rate`,
            });
        }

        // Personalization factor
        if (request.hasPersonalization) {
            prediction += coeffs[3];
            factors.push({
                name: 'Personalization',
                impact: coeffs[3],
                description: 'Email contains personalized content',
            });
        }

        const confidence = Math.min(
            this.historicalData.length / (this.config.minDataPoints * 2),
            0.9
        );

        return {
            prediction: Math.max(0, Math.min(1, prediction)),
            confidence,
            factors,
        };
    }

    private predictConversionRate(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const coeffs = this.modelCoefficients.get('conversion_rate')!;
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        let prediction = coeffs[0];

        // Click rate correlation
        if (request.expectedClickRate) {
            const clickCorrelation = request.expectedClickRate / 0.03;
            prediction *= clickCorrelation;
            factors.push({
                name: 'Click Rate',
                impact: coeffs[1] * clickCorrelation,
                description: 'Conversion correlated with click-through',
            });
        }

        factors.push({
            name: 'Industry Average',
            impact: coeffs[0],
            description: 'Based on email marketing industry benchmarks',
        });

        const confidence = Math.min(
            this.historicalData.length / (this.config.minDataPoints * 3),
            0.8
        );

        return {
            prediction: Math.max(0, Math.min(1, prediction)),
            confidence,
            factors,
        };
    }

    private predictUnsubscribeRate(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const coeffs = this.modelCoefficients.get('unsubscribe_rate')!;
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        let prediction = coeffs[0];

        // Email frequency factor
        if (request.emailFrequency) {
            const frequencyFactor = request.emailFrequency > 4 ? 1 : request.emailFrequency > 2 ? 0.5 : 0;
            prediction += coeffs[1] * frequencyFactor;
            factors.push({
                name: 'Send Frequency',
                impact: coeffs[1] * frequencyFactor,
                description: `${request.emailFrequency} emails per week`,
            });
        }

        factors.push({
            name: 'Baseline Rate',
            impact: coeffs[0],
            description: 'Average unsubscribe rate for email campaigns',
        });

        const confidence = Math.min(
            this.historicalData.length / (this.config.minDataPoints * 2),
            0.85
        );

        return {
            prediction: Math.max(0, Math.min(0.1, prediction)), // Cap at 10%
            confidence,
            factors,
        };
    }

    private predictChurnRisk(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        // Get subscriber-level data if available
        const subscriber = request.subscriberId
            ? this.subscriberData.get(request.subscriberId)
            : null;

        let risk = 0.1; // Base risk

        if (subscriber) {
            // Inactivity factor
            const inactivityFactor = Math.min(subscriber.daysInactive / 90, 1);
            risk += 0.4 * inactivityFactor;
            factors.push({
                name: 'Inactivity',
                impact: 0.4 * inactivityFactor,
                description: `${subscriber.daysInactive} days since last engagement`,
            });

            // Engagement decline factor
            const engagementDecline = 1 - subscriber.engagementScore;
            risk += 0.3 * engagementDecline;
            factors.push({
                name: 'Engagement Level',
                impact: 0.3 * engagementDecline,
                description: `Engagement score: ${(subscriber.engagementScore * 100).toFixed(0)}%`,
            });
        } else {
            factors.push({
                name: 'Baseline Risk',
                impact: 0.1,
                description: 'Average churn risk for subscribers',
            });
        }

        const confidence = subscriber ? 0.8 : 0.4;

        return {
            prediction: Math.max(0, Math.min(1, risk)),
            confidence,
            factors,
        };
    }

    private predictRevenue(request: PredictionRequest): {
        prediction: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        const factors: Array<{ name: string; impact: number; description: string }> = [];

        // Calculate based on expected conversions and average order value
        const listSize = request.listSize || 10000;
        const expectedOpenRate = request.expectedOpenRate || 0.22;
        const expectedClickRate = request.expectedClickRate || 0.03;
        const conversionRate = 0.02;
        const avgOrderValue = request.avgOrderValue || 50;

        const expectedConversions = listSize * expectedOpenRate * expectedClickRate * conversionRate;
        const prediction = expectedConversions * avgOrderValue;

        factors.push(
            {
                name: 'List Size',
                impact: listSize / 10000,
                description: `${listSize.toLocaleString()} subscribers`,
            },
            {
                name: 'Conversion Funnel',
                impact: expectedOpenRate * expectedClickRate * conversionRate,
                description: 'Open → Click → Convert flow',
            },
            {
                name: 'Average Order Value',
                impact: avgOrderValue / 100,
                description: `$${avgOrderValue.toFixed(2)} per conversion`,
            }
        );

        const confidence = this.historicalData.some((d) => d.revenue)
            ? 0.7
            : 0.4;

        return {
            prediction,
            confidence,
            factors,
        };
    }

    private predictBestTime(_request: PredictionRequest): {
        hour: number;
        confidence: number;
        factors: Array<{ name: string; impact: number; description: string }>;
    } {
        // Analyze historical data to find best performing hours
        const hourPerformance = new Map<number, { opens: number; sent: number }>();

        for (const data of this.historicalData) {
            const hour = data.hourOfDay;
            const existing = hourPerformance.get(hour) || { opens: 0, sent: 0 };
            existing.opens += data.openRate * data.listSize;
            existing.sent += data.listSize;
            hourPerformance.set(hour, existing);
        }

        // Find best hour
        let bestHour = 10; // Default
        let bestRate = 0;

        for (const [hour, data] of hourPerformance) {
            const rate = data.sent > 0 ? data.opens / data.sent : 0;
            if (rate > bestRate) {
                bestRate = rate;
                bestHour = hour;
            }
        }

        const factors = [
            {
                name: 'Historical Performance',
                impact: bestRate,
                description: `Hour ${bestHour} has shown ${(bestRate * 100).toFixed(1)}% open rate`,
            },
        ];

        const confidence = this.historicalData.length >= this.config.minDataPoints
            ? 0.75
            : 0.4;

        return { hour: bestHour, confidence, factors };
    }

    private segmentByEngagement(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        const segments = [
            { id: 'highly_engaged', name: 'Highly Engaged', threshold: 0.7, subscribers: [] as SubscriberBehavior[] },
            { id: 'moderately_engaged', name: 'Moderately Engaged', threshold: 0.4, subscribers: [] as SubscriberBehavior[] },
            { id: 'low_engagement', name: 'Low Engagement', threshold: 0.1, subscribers: [] as SubscriberBehavior[] },
            { id: 'inactive', name: 'Inactive', threshold: 0, subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            for (const segment of segments) {
                if (sub.engagementScore >= segment.threshold) {
                    segment.subscribers.push(sub);
                    break;
                }
            }
        }

        const recommendations: Record<string, string> = {
            highly_engaged: 'Send exclusive offers and early access',
            moderately_engaged: 'Increase engagement with targeted content',
            low_engagement: 'Re-engagement campaign with incentives',
            inactive: 'Win-back campaign or consider list cleaning',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgEngagementScore: this.average(s.subscribers.map((sub) => sub.engagementScore)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private segmentByRecency(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        const segments = [
            { id: 'active', name: 'Active (7 days)', maxDays: 7, subscribers: [] as SubscriberBehavior[] },
            { id: 'recent', name: 'Recent (30 days)', maxDays: 30, subscribers: [] as SubscriberBehavior[] },
            { id: 'lapsed', name: 'Lapsed (90 days)', maxDays: 90, subscribers: [] as SubscriberBehavior[] },
            { id: 'dormant', name: 'Dormant (90+ days)', maxDays: Infinity, subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            for (const segment of segments) {
                if (sub.daysInactive <= segment.maxDays) {
                    segment.subscribers.push(sub);
                    break;
                }
            }
        }

        const recommendations: Record<string, string> = {
            active: 'Continue regular communication',
            recent: 'Maintain engagement momentum',
            lapsed: 'Send re-engagement campaign',
            dormant: 'Win-back campaign or sunset',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgDaysInactive: this.average(s.subscribers.map((sub) => sub.daysInactive)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private segmentByFrequency(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        const segments = [
            { id: 'power_users', name: 'Power Users', minOpens: 10, subscribers: [] as SubscriberBehavior[] },
            { id: 'regular', name: 'Regular Readers', minOpens: 5, subscribers: [] as SubscriberBehavior[] },
            { id: 'occasional', name: 'Occasional Readers', minOpens: 2, subscribers: [] as SubscriberBehavior[] },
            { id: 'rare', name: 'Rare Readers', minOpens: 0, subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            for (const segment of segments) {
                if (sub.opens >= segment.minOpens) {
                    segment.subscribers.push(sub);
                    break;
                }
            }
        }

        const recommendations: Record<string, string> = {
            power_users: 'VIP treatment with exclusive content',
            regular: 'Optimize send frequency',
            occasional: 'Test different content types',
            rare: 'Reduce frequency, focus on quality',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgOpens: this.average(s.subscribers.map((sub) => sub.opens)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private segmentByRFM(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        // RFM: Recency, Frequency, Monetary (using engagement as proxy for monetary)
        const segments = [
            { id: 'champions', name: 'Champions', subscribers: [] as SubscriberBehavior[] },
            { id: 'loyal', name: 'Loyal Customers', subscribers: [] as SubscriberBehavior[] },
            { id: 'potential', name: 'Potential Loyalists', subscribers: [] as SubscriberBehavior[] },
            { id: 'at_risk', name: 'At Risk', subscribers: [] as SubscriberBehavior[] },
            { id: 'hibernating', name: 'Hibernating', subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            const recencyScore = sub.daysInactive < 7 ? 5 : sub.daysInactive < 30 ? 4 : sub.daysInactive < 90 ? 3 : sub.daysInactive < 180 ? 2 : 1;
            const frequencyScore = sub.opens > 10 ? 5 : sub.opens > 5 ? 4 : sub.opens > 2 ? 3 : sub.opens > 0 ? 2 : 1;
            const engagementScore = sub.engagementScore > 0.8 ? 5 : sub.engagementScore > 0.6 ? 4 : sub.engagementScore > 0.4 ? 3 : sub.engagementScore > 0.2 ? 2 : 1;

            const totalScore = recencyScore + frequencyScore + engagementScore;

            if (totalScore >= 13) segments[0].subscribers.push(sub);
            else if (totalScore >= 10) segments[1].subscribers.push(sub);
            else if (totalScore >= 7) segments[2].subscribers.push(sub);
            else if (totalScore >= 4) segments[3].subscribers.push(sub);
            else segments[4].subscribers.push(sub);
        }

        const recommendations: Record<string, string> = {
            champions: 'Reward with exclusivity and early access',
            loyal: 'Upsell and cross-sell opportunities',
            potential: 'Nurture with personalized content',
            at_risk: 'Win-back with special offers',
            hibernating: 'Re-engagement or sunset campaign',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgEngagementScore: this.average(s.subscribers.map((sub) => sub.engagementScore)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private segmentByLifecycle(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        // Simplified lifecycle based on total emails received and engagement
        const segments = [
            { id: 'new', name: 'New Subscribers', subscribers: [] as SubscriberBehavior[] },
            { id: 'onboarding', name: 'Onboarding', subscribers: [] as SubscriberBehavior[] },
            { id: 'active', name: 'Active', subscribers: [] as SubscriberBehavior[] },
            { id: 'mature', name: 'Mature', subscribers: [] as SubscriberBehavior[] },
            { id: 'churning', name: 'Churning', subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            if (sub.totalEmails < 3) segments[0].subscribers.push(sub);
            else if (sub.totalEmails < 10) segments[1].subscribers.push(sub);
            else if (sub.engagementScore > 0.5) segments[2].subscribers.push(sub);
            else if (sub.engagementScore > 0.2) segments[3].subscribers.push(sub);
            else segments[4].subscribers.push(sub);
        }

        const recommendations: Record<string, string> = {
            new: 'Welcome series and first-time offers',
            onboarding: 'Educational content and engagement',
            active: 'Regular newsletters and promotions',
            mature: 'Loyalty rewards and exclusive content',
            churning: 'Win-back campaign with incentives',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgTotalEmails: this.average(s.subscribers.map((sub) => sub.totalEmails)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private segmentByBehavior(subscribers: SubscriberBehavior[]): Array<{
        id: string;
        name: string;
        size: number;
        percentage: number;
        characteristics: Record<string, unknown>;
        recommendedAction: string;
    }> {
        // Behavior-based: openers, clickers, passive
        const segments = [
            { id: 'clickers', name: 'Clickers', subscribers: [] as SubscriberBehavior[] },
            { id: 'openers', name: 'Openers Only', subscribers: [] as SubscriberBehavior[] },
            { id: 'passive', name: 'Passive', subscribers: [] as SubscriberBehavior[] },
        ];

        for (const sub of subscribers) {
            const clickRate = sub.opens > 0 ? sub.clicks / sub.opens : 0;
            const openRate = sub.totalEmails > 0 ? sub.opens / sub.totalEmails : 0;

            if (clickRate > 0.2) segments[0].subscribers.push(sub);
            else if (openRate > 0.3) segments[1].subscribers.push(sub);
            else segments[2].subscribers.push(sub);
        }

        const recommendations: Record<string, string> = {
            clickers: 'Action-oriented content with clear CTAs',
            openers: 'Improve CTA placement and value proposition',
            passive: 'Re-engagement with new content formats',
        };

        return segments.map((s) => ({
            id: s.id,
            name: s.name,
            size: s.subscribers.length,
            percentage: (s.subscribers.length / subscribers.length) * 100,
            characteristics: {
                avgClicks: this.average(s.subscribers.map((sub) => sub.clicks)),
            },
            recommendedAction: recommendations[s.id],
        }));
    }

    private calculateRate(
        variant: NonNullable<ABTestAnalysisRequest['variantA']>,
        metric: string
    ): number {
        switch (metric) {
            case 'open_rate':
                return variant.sent > 0 ? variant.opens / variant.sent : 0;
            case 'click_rate':
                return variant.sent > 0 ? variant.clicks / variant.sent : 0;
            case 'conversion_rate':
                return variant.sent > 0 ? (variant.conversions || 0) / variant.sent : 0;
            default:
                return 0;
        }
    }

    private getMetricValue(
        variant: NonNullable<ABTestAnalysisRequest['variantA']>,
        metric: string
    ): number {
        switch (metric) {
            case 'open_rate':
                return variant.opens;
            case 'click_rate':
                return variant.clicks;
            case 'conversion_rate':
                return variant.conversions || 0;
            default:
                return 0;
        }
    }

    private calculateSignificance(
        variantA: NonNullable<ABTestAnalysisRequest['variantA']>,
        variantB: NonNullable<ABTestAnalysisRequest['variantB']>,
        metric: string
    ): { significant: boolean; pValue: number; confidence: number } {
        const rateA = this.calculateRate(variantA, metric);
        const rateB = this.calculateRate(variantB, metric);
        const nA = variantA.sent;
        const nB = variantB.sent;

        if (nA === 0 || nB === 0) {
            return { significant: false, pValue: 1, confidence: 0 };
        }

        // Pooled proportion
        const pooledRate = (rateA * nA + rateB * nB) / (nA + nB);
        const pooledSE = Math.sqrt(pooledRate * (1 - pooledRate) * (1 / nA + 1 / nB));

        if (pooledSE === 0) {
            return { significant: false, pValue: 1, confidence: 0 };
        }

        // Z-score
        const z = Math.abs(rateB - rateA) / pooledSE;

        // P-value (two-tailed, using approximation)
        const pValue = 2 * (1 - this.normalCDF(z));

        // 95% confidence threshold
        const significant = pValue < 0.05;
        const confidence = 1 - pValue;

        return { significant, pValue, confidence };
    }

    private normalCDF(z: number): number {
        // Approximation of the standard normal CDF
        const a1 = 0.254829592;
        const a2 = -0.284496736;
        const a3 = 1.421413741;
        const a4 = -1.453152027;
        const a5 = 1.061405429;
        const p = 0.3275911;

        const sign = z < 0 ? -1 : 1;
        z = Math.abs(z) / Math.sqrt(2);

        const t = 1.0 / (1.0 + p * z);
        const y = 1.0 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-z * z);

        return 0.5 * (1.0 + sign * y);
    }

    private calculateSampleSize(
        variantA: NonNullable<ABTestAnalysisRequest['variantA']>,
        variantB: NonNullable<ABTestAnalysisRequest['variantB']>,
        _metric: string
    ): { required: number; current: number; needsMore: boolean } {
        // Minimum sample size for 95% confidence, 80% power
        // Using rule of thumb: n = 16 / (effect_size^2)
        const effectSize = 0.05; // 5% minimum detectable effect
        const required = Math.ceil(16 / (effectSize * effectSize));
        const current = variantA.sent + variantB.sent;
        const needsMore = current < required * 2;

        return { required: required * 2, current, needsMore };
    }

    private buildABRecommendation(
        winner: string,
        lift: number,
        significant: boolean,
        needsMore: boolean
    ): string {
        if (needsMore) {
            return 'Continue test - need more data for statistical significance';
        }

        if (!significant) {
            return 'No statistically significant difference detected. Consider testing larger variations.';
        }

        if (winner === 'none') {
            return 'Results are too close to call. Consider other factors or continue testing.';
        }

        return `Variant ${winner} is the winner with ${lift.toFixed(1)}% lift. Consider deploying to full audience.`;
    }

    private calculateRange(
        prediction: number,
        confidence: number
    ): { min: number; max: number } {
        const margin = prediction * (1 - confidence) * 0.5;
        return {
            min: Math.max(0, prediction - margin),
            max: Math.min(1, prediction + margin),
        };
    }

    private getTimeFactor(hour: number): number {
        // Peak hours: 9-11 AM, 1-3 PM
        if ((hour >= 9 && hour <= 11) || (hour >= 13 && hour <= 15)) {
            return 1;
        }
        if (hour >= 7 && hour <= 17) {
            return 0.5;
        }
        return -0.5;
    }

    private getDayFactor(day: number): number {
        // Best days: Tuesday (2), Wednesday (3), Thursday (4)
        if (day >= 2 && day <= 4) return 1;
        if (day === 1 || day === 5) return 0.5;
        return -0.5; // Weekend
    }

    private describeTimeFactor(hour: number): string {
        if ((hour >= 9 && hour <= 11) || (hour >= 13 && hour <= 15)) {
            return 'Optimal send time for engagement';
        }
        if (hour >= 7 && hour <= 17) {
            return 'Good business hours';
        }
        return 'Off-peak hours may reduce engagement';
    }

    private describeDayFactor(day: number): string {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        if (day >= 2 && day <= 4) {
            return `${days[day]} is a top-performing day`;
        }
        return `${days[day]} may have lower engagement`;
    }

    private average(values: number[]): number {
        if (values.length === 0) return 0;
        return values.reduce((a, b) => a + b, 0) / values.length;
    }
}

export { DEFAULT_PREDICTOR_CONFIG };
