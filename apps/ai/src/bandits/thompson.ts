/**
 * @apexmail/ai - Thompson Sampling Multi-Armed Bandit
 * 
 * Implementation of Thompson Sampling for Bayesian exploration-exploitation
 * in email marketing optimization (subject lines, send times, content variants).
 * 
 * Uses Beta distribution for binary outcomes (open/no-open, click/no-click).
 */

/**
 * Beta distribution sampler using the Gamma distribution method
 * More numerically stable than inverse CDF method
 * 
 * SECURITY FIX: Handles edge cases to prevent division by zero
 */
function sampleBeta(alpha: number, beta: number): number {
    // SECURITY FIX: Validate inputs to prevent numerical issues
    // Alpha and beta must be positive
    if (alpha <= 0 || beta <= 0) {
        // Default to 0.5 (equivalent to uniform prior with no data)
        return 0.5;
    }
    
    // Handle very small values that could cause numerical instability
    const minParam = 1e-10;
    const safeAlpha = Math.max(alpha, minParam);
    const safeBeta = Math.max(beta, minParam);
    
    // Use Gamma sampling: Beta(a,b) = Gamma(a,1) / (Gamma(a,1) + Gamma(b,1))
    const gammaA = sampleGamma(safeAlpha);
    const gammaB = sampleGamma(safeBeta);
    
    // SECURITY FIX: Prevent division by zero
    const sum = gammaA + gammaB;
    if (sum === 0 || !Number.isFinite(sum)) {
        return 0.5;
    }
    
    const result = gammaA / sum;
    
    // Ensure result is in valid range [0, 1]
    if (!Number.isFinite(result)) {
        return 0.5;
    }
    return Math.max(0, Math.min(1, result));
}

/**
 * Gamma distribution sampler using Marsaglia and Tsang's method
 * Works for alpha >= 1, uses transformation for alpha < 1
 */
function sampleGamma(alpha: number): number {
    if (alpha < 1) {
        // For alpha < 1, use: Gamma(alpha) = Gamma(alpha + 1) * U^(1/alpha)
        return sampleGamma(alpha + 1) * Math.pow(Math.random(), 1 / alpha);
    }
    
    // Marsaglia and Tsang's method for alpha >= 1
    const d = alpha - 1 / 3;
    const c = 1 / Math.sqrt(9 * d);
    
    // FIX-500-386: Cap iterations to prevent infinite loop on pathological RNG sequences
    const MAX_ITERATIONS = 1000;
    for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
        let x: number;
        let v: number;
        
        do {
            x = sampleStandardNormal();
            v = 1 + c * x;
        } while (v <= 0);
        
        v = v * v * v;
        const u = Math.random();
        
        if (u < 1 - 0.0331 * x * x * x * x) {
            return d * v;
        }
        
        if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) {
            return d * v;
        }
    }

    // FIX-500-386: Fallback — return the mean of the Gamma distribution
    return alpha;
}

/**
 * Standard normal distribution sampler using Box-Muller transform
 */
function sampleStandardNormal(): number {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

/**
 * Arm in the multi-armed bandit
 */
export interface BanditArm<T = unknown> {
    id: string;
    data: T;
    alpha: number;  // Success count + 1 (prior)
    beta: number;   // Failure count + 1 (prior)
    pulls: number;  // Total number of times this arm was pulled
    successes: number;
    lastPulled?: Date;
    createdAt: Date;
}

/**
 * Configuration for Thompson Sampling
 */
export interface ThompsonConfig {
    /** Prior alpha (default 1 = uniform prior) */
    priorAlpha: number;
    /** Prior beta (default 1 = uniform prior) */
    priorBeta: number;
    /** Minimum pulls before arm can be pruned */
    minPullsForPruning: number;
    /** Maximum age in ms before arm expires */
    maxAgeMs: number;
    /** Decay factor for older observations (1 = no decay) */
    decayFactor: number;
    /** Decay window in milliseconds */
    decayWindowMs: number;
}

const DEFAULT_CONFIG: ThompsonConfig = {
    priorAlpha: 1,
    priorBeta: 1,
    minPullsForPruning: 100,
    maxAgeMs: 30 * 24 * 60 * 60 * 1000, // 30 days
    decayFactor: 0.95,
    decayWindowMs: 7 * 24 * 60 * 60 * 1000, // 7 days
};

/**
 * Thompson Sampling Multi-Armed Bandit
 * 
 * Optimal for binary outcome optimization:
 * - Subject line A/B testing
 * - Send time selection
 * - Content variant selection
 * - CTA optimization
 */
export class ThompsonSampler<T = unknown> {
    private arms: Map<string, BanditArm<T>> = new Map();
    private config: ThompsonConfig;
    private pullHistory: Array<{ armId: string; timestamp: Date; success: boolean }> = [];

    constructor(config?: Partial<ThompsonConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Add a new arm to the bandit
     */
    addArm(id: string, data: T): BanditArm<T> {
        const arm: BanditArm<T> = {
            id,
            data,
            alpha: this.config.priorAlpha,
            beta: this.config.priorBeta,
            pulls: 0,
            successes: 0,
            createdAt: new Date(),
        };
        this.arms.set(id, arm);
        return arm;
    }

    /**
     * Remove an arm from the bandit
     */
    removeArm(id: string): boolean {
        return this.arms.delete(id);
    }

    /**
     * Get an arm by ID
     */
    getArm(id: string): BanditArm<T> | undefined {
        return this.arms.get(id);
    }

    /**
     * Get all arms
     */
    getAllArms(): BanditArm<T>[] {
        return Array.from(this.arms.values());
    }

    /**
     * Select the best arm using Thompson Sampling
     * Returns the arm with the highest sampled value
     */
    selectArm(): BanditArm<T> | null {
        if (this.arms.size === 0) return null;

        let bestArm: BanditArm<T> | null = null;
        let bestSample = -Infinity;

        for (const arm of this.arms.values()) {
            // Apply time decay to alpha/beta if configured
            const { alpha, beta } = this.getDecayedParams(arm);
            
            // Sample from Beta distribution
            const sample = sampleBeta(alpha, beta);

            if (sample > bestSample) {
                bestSample = sample;
                bestArm = arm;
            }
        }

        return bestArm;
    }

    /**
     * Select top-k arms using Thompson Sampling
     * Useful for batch experiments
     */
    selectTopK(k: number): BanditArm<T>[] {
        if (this.arms.size === 0) return [];

        const samples: Array<{ arm: BanditArm<T>; sample: number }> = [];

        for (const arm of this.arms.values()) {
            const { alpha, beta } = this.getDecayedParams(arm);
            const sample = sampleBeta(alpha, beta);
            samples.push({ arm, sample });
        }

        // Sort by sample descending and take top k
        samples.sort((a, b) => b.sample - a.sample);
        return samples.slice(0, k).map(s => s.arm);
    }

    /**
     * Record the outcome of pulling an arm
     */
    recordOutcome(armId: string, success: boolean): void {
        const arm = this.arms.get(armId);
        if (!arm) {
            throw new Error(`Arm not found: ${armId}`);
        }

        arm.pulls++;
        if (success) {
            arm.alpha++;
            arm.successes++;
        } else {
            arm.beta++;
        }
        arm.lastPulled = new Date();

        // Record in history for decay calculations
        this.pullHistory.push({
            armId,
            timestamp: new Date(),
            success,
        });

        // Prune old history
        this.pruneHistory();
    }

    /**
     * Batch record outcomes
     */
    recordBatchOutcomes(outcomes: Array<{ armId: string; success: boolean }>): void {
        for (const { armId, success } of outcomes) {
            this.recordOutcome(armId, success);
        }
    }

    /**
     * Get the expected value (mean) for an arm
     */
    getExpectedValue(armId: string): number {
        const arm = this.arms.get(armId);
        if (!arm) return 0;

        const { alpha, beta } = this.getDecayedParams(arm);
        return alpha / (alpha + beta);
    }

    /**
     * Get the 95% credible interval for an arm
     */
    getCredibleInterval(armId: string): { lower: number; upper: number } {
        const arm = this.arms.get(armId);
        if (!arm) return { lower: 0, upper: 1 };

        const { alpha, beta } = this.getDecayedParams(arm);
        
        // Use Beta quantile approximation
        // For large alpha/beta, Beta approximates Normal
        const mean = alpha / (alpha + beta);
        const variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
        const std = Math.sqrt(variance);

        return {
            lower: Math.max(0, mean - 1.96 * std),
            upper: Math.min(1, mean + 1.96 * std),
        };
    }

    /**
     * Get statistics for all arms
     */
    getStatistics(): Array<{
        armId: string;
        data: T;
        pulls: number;
        successes: number;
        successRate: number;
        expectedValue: number;
        credibleInterval: { lower: number; upper: number };
    }> {
        return this.getAllArms().map(arm => ({
            armId: arm.id,
            data: arm.data,
            pulls: arm.pulls,
            successes: arm.successes,
            successRate: arm.pulls > 0 ? arm.successes / arm.pulls : 0,
            expectedValue: this.getExpectedValue(arm.id),
            credibleInterval: this.getCredibleInterval(arm.id),
        }));
    }

    /**
     * Get the probability that each arm is the best
     * FIX-500-089: Reduced default from 10K to 1K samples to avoid blocking
     * the event loop. Made async and yields every 500 iterations.
     */
    async getProbabilityBest(numSamples: number = 1000): Promise<Map<string, number>> {
        const counts = new Map<string, number>();
        for (const arm of this.arms.values()) {
            counts.set(arm.id, 0);
        }

        const YIELD_INTERVAL = 500;

        for (let i = 0; i < numSamples; i++) {
            // FIX-500-089: Yield to event loop periodically
            if (i > 0 && i % YIELD_INTERVAL === 0) {
                await new Promise<void>(resolve => setImmediate(resolve));
            }

            let bestId: string | null = null;
            let bestSample = -Infinity;

            for (const arm of this.arms.values()) {
                const { alpha, beta } = this.getDecayedParams(arm);
                const sample = sampleBeta(alpha, beta);

                if (sample > bestSample) {
                    bestSample = sample;
                    bestId = arm.id;
                }
            }

            if (bestId) {
                counts.set(bestId, (counts.get(bestId) || 0) + 1);
            }
        }

        // Convert counts to probabilities
        const probabilities = new Map<string, number>();
        for (const [id, count] of counts) {
            probabilities.set(id, count / numSamples);
        }

        return probabilities;
    }

    /**
     * Check if we have enough evidence to declare a winner
     * FIX-500-089: Now async, reduced from 10K to 1K samples
     */
    async hasSignificantWinner(threshold: number = 0.95): Promise<{
        hasWinner: boolean;
        winnerId: string | null;
        probability: number;
    }> {
        const probs = await this.getProbabilityBest(1000);
        
        let bestId: string | null = null;
        let bestProb = 0;

        for (const [id, prob] of probs) {
            if (prob > bestProb) {
                bestProb = prob;
                bestId = id;
            }
        }

        return {
            hasWinner: bestProb >= threshold,
            winnerId: bestId,
            probability: bestProb,
        };
    }

    /**
     * Prune underperforming arms that have sufficient data
     */
    pruneUnderperformers(keepTopN: number = 3): string[] {
        const stats = this.getStatistics()
            .filter(s => s.pulls >= this.config.minPullsForPruning)
            .sort((a, b) => b.expectedValue - a.expectedValue);

        const pruned: string[] = [];
        const toKeep = new Set(stats.slice(0, keepTopN).map(s => s.armId));

        for (const stat of stats.slice(keepTopN)) {
            if (!toKeep.has(stat.armId)) {
                this.removeArm(stat.armId);
                pruned.push(stat.armId);
            }
        }

        return pruned;
    }

    /**
     * Reset all arms to prior
     */
    reset(): void {
        for (const arm of this.arms.values()) {
            arm.alpha = this.config.priorAlpha;
            arm.beta = this.config.priorBeta;
            arm.pulls = 0;
            arm.successes = 0;
            arm.lastPulled = undefined;
        }
        this.pullHistory = [];
    }

    /**
     * Serialize the bandit state
     */
    serialize(): string {
        return JSON.stringify({
            config: this.config,
            arms: Array.from(this.arms.entries()),
            pullHistory: this.pullHistory.slice(-1000), // Keep last 1000
        });
    }

    /**
     * Deserialize bandit state
     * FIX-500-189: Wrap JSON.parse in try/catch with meaningful error.
     */
    static deserialize<T>(json: string): ThompsonSampler<T> {
        let data: any;
        try {
            data = JSON.parse(json);
        } catch (err) {
            throw new Error(`ThompsonSampler.deserialize: invalid JSON — ${err instanceof Error ? err.message : String(err)}`);
        }
        const sampler = new ThompsonSampler<T>(data.config);
        
        for (const [id, arm] of data.arms) {
            sampler.arms.set(id, {
                ...arm,
                createdAt: new Date(arm.createdAt),
                lastPulled: arm.lastPulled ? new Date(arm.lastPulled) : undefined,
            });
        }

        sampler.pullHistory = data.pullHistory.map((h: { armId: string; timestamp: string; success: boolean }) => ({
            ...h,
            timestamp: new Date(h.timestamp),
        }));

        return sampler;
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private getDecayedParams(arm: BanditArm<T>): { alpha: number; beta: number } {
        if (this.config.decayFactor >= 1) {
            return { alpha: arm.alpha, beta: arm.beta };
        }

        // Apply time-based decay to observations
        const now = Date.now();
        let alpha = this.config.priorAlpha;
        let beta = this.config.priorBeta;

        const armHistory = this.pullHistory.filter(h => h.armId === arm.id);

        for (const record of armHistory) {
            const age = now - record.timestamp.getTime();
            const decayPeriods = Math.floor(age / this.config.decayWindowMs);
            const weight = Math.pow(this.config.decayFactor, decayPeriods);

            if (record.success) {
                alpha += weight;
            } else {
                beta += weight;
            }
        }

        return { alpha, beta };
    }

    private pruneHistory(): void {
        const cutoff = Date.now() - this.config.maxAgeMs;
        this.pullHistory = this.pullHistory.filter(
            h => h.timestamp.getTime() > cutoff
        );
        // FIX-500-250: Hard cap to prevent unbounded growth if maxAgeMs is very large
        if (this.pullHistory.length > 10000) {
            this.pullHistory = this.pullHistory.slice(-10000);
        }
    }
}

/**
 * Create a subject line optimizer using Thompson Sampling
 */
export function createSubjectLineOptimizer(): ThompsonSampler<{ subject: string; metadata?: Record<string, unknown> }> {
    return new ThompsonSampler<{ subject: string; metadata?: Record<string, unknown> }>({
        priorAlpha: 1,
        priorBeta: 1,
        minPullsForPruning: 50,
        maxAgeMs: 14 * 24 * 60 * 60 * 1000, // 14 days for subject lines
    });
}

/**
 * Create a send time optimizer using Thompson Sampling
 */
export function createSendTimeOptimizer(): ThompsonSampler<{ hour: number; dayOfWeek: number }> {
    return new ThompsonSampler<{ hour: number; dayOfWeek: number }>({
        priorAlpha: 1,
        priorBeta: 1,
        minPullsForPruning: 100,
        maxAgeMs: 30 * 24 * 60 * 60 * 1000, // 30 days for send times
        decayFactor: 0.9, // Recent data more important
        decayWindowMs: 7 * 24 * 60 * 60 * 1000,
    });
}

/**
 * Create a content variant optimizer using Thompson Sampling
 */
export function createContentOptimizer(): ThompsonSampler<{ variantId: string; content: string }> {
    return new ThompsonSampler<{ variantId: string; content: string }>({
        priorAlpha: 1,
        priorBeta: 1,
        minPullsForPruning: 30,
        maxAgeMs: 7 * 24 * 60 * 60 * 1000, // 7 days for content variants
    });
}
