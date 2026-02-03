/**
 * @apexmail/ai - Upper Confidence Bound (UCB) Multi-Armed Bandit
 * 
 * Implementation of UCB1 algorithm for deterministic exploration-exploitation
 * trade-off. UCB is preferred when you need reproducible results and
 * theoretical guarantees on regret bounds.
 * 
 * UCB1 uses: mean + sqrt(2 * ln(total_pulls) / arm_pulls)
 */

/**
 * UCB Arm representation
 */
export interface UCBArm<T = unknown> {
    id: string;
    data: T;
    pulls: number;
    totalReward: number;
    successes: number;
    lastPulled?: Date;
    createdAt: Date;
}

/**
 * UCB Configuration
 */
export interface UCBConfig {
    /** Exploration parameter (default 2 for UCB1) */
    explorationParam: number;
    /** Minimum pulls before UCB score is calculated */
    minInitialPulls: number;
    /** Maximum age before arm expires */
    maxAgeMs: number;
    /** Time decay factor (1 = no decay) */
    timeDecay: number;
}

const DEFAULT_UCB_CONFIG: UCBConfig = {
    explorationParam: 2,
    minInitialPulls: 1,
    maxAgeMs: 30 * 24 * 60 * 60 * 1000, // 30 days
    timeDecay: 1,
};

/**
 * UCB1 Multi-Armed Bandit
 * 
 * Deterministic arm selection based on upper confidence bounds.
 * Good for:
 * - A/B testing where reproducibility matters
 * - When you need theoretical regret guarantees
 * - Systems that can't handle randomness
 */
export class UCBBandit<T = unknown> {
    private arms: Map<string, UCBArm<T>> = new Map();
    private config: UCBConfig;
    private totalPulls: number = 0;

    constructor(config?: Partial<UCBConfig>) {
        this.config = { ...DEFAULT_UCB_CONFIG, ...config };
    }

    /**
     * Add a new arm
     */
    addArm(id: string, data: T): UCBArm<T> {
        const arm: UCBArm<T> = {
            id,
            data,
            pulls: 0,
            totalReward: 0,
            successes: 0,
            createdAt: new Date(),
        };
        this.arms.set(id, arm);
        return arm;
    }

    /**
     * Remove an arm
     */
    removeArm(id: string): boolean {
        const arm = this.arms.get(id);
        if (arm) {
            this.totalPulls -= arm.pulls;
        }
        return this.arms.delete(id);
    }

    /**
     * Get an arm by ID
     */
    getArm(id: string): UCBArm<T> | undefined {
        return this.arms.get(id);
    }

    /**
     * Get all arms
     */
    getAllArms(): UCBArm<T>[] {
        return Array.from(this.arms.values());
    }

    /**
     * Select the best arm using UCB1 algorithm
     */
    selectArm(): UCBArm<T> | null {
        if (this.arms.size === 0) return null;

        // First, try arms that haven't been pulled enough
        for (const arm of this.arms.values()) {
            if (arm.pulls < this.config.minInitialPulls) {
                return arm;
            }
        }

        // All arms have been pulled, use UCB1 formula
        let bestArm: UCBArm<T> | null = null;
        let bestUCB = -Infinity;

        for (const arm of this.arms.values()) {
            const ucbScore = this.calculateUCB(arm);
            if (ucbScore > bestUCB) {
                bestUCB = ucbScore;
                bestArm = arm;
            }
        }

        return bestArm;
    }

    /**
     * Select top-k arms by UCB score
     */
    selectTopK(k: number): UCBArm<T>[] {
        const scores: Array<{ arm: UCBArm<T>; ucb: number }> = [];

        for (const arm of this.arms.values()) {
            scores.push({
                arm,
                ucb: arm.pulls < this.config.minInitialPulls ? Infinity : this.calculateUCB(arm),
            });
        }

        scores.sort((a, b) => b.ucb - a.ucb);
        return scores.slice(0, k).map(s => s.arm);
    }

    /**
     * Record outcome of pulling an arm
     */
    recordOutcome(armId: string, reward: number): void {
        const arm = this.arms.get(armId);
        if (!arm) {
            throw new Error(`Arm not found: ${armId}`);
        }

        arm.pulls++;
        arm.totalReward += reward;
        if (reward > 0) {
            arm.successes++;
        }
        arm.lastPulled = new Date();
        this.totalPulls++;
    }

    /**
     * Record binary outcome (success/failure)
     */
    recordBinaryOutcome(armId: string, success: boolean): void {
        this.recordOutcome(armId, success ? 1 : 0);
    }

    /**
     * Get the mean reward for an arm
     */
    getMeanReward(armId: string): number {
        const arm = this.arms.get(armId);
        if (!arm || arm.pulls === 0) return 0;
        return arm.totalReward / arm.pulls;
    }

    /**
     * Get UCB score for an arm
     */
    getUCBScore(armId: string): number {
        const arm = this.arms.get(armId);
        if (!arm) return 0;
        return this.calculateUCB(arm);
    }

    /**
     * Get statistics for all arms
     */
    getStatistics(): Array<{
        armId: string;
        data: T;
        pulls: number;
        meanReward: number;
        ucbScore: number;
        explorationBonus: number;
    }> {
        return this.getAllArms().map(arm => {
            const meanReward = arm.pulls > 0 ? arm.totalReward / arm.pulls : 0;
            const explorationBonus = arm.pulls > 0
                ? Math.sqrt((this.config.explorationParam * Math.log(this.totalPulls)) / arm.pulls)
                : Infinity;
            
            return {
                armId: arm.id,
                data: arm.data,
                pulls: arm.pulls,
                meanReward,
                ucbScore: this.calculateUCB(arm),
                explorationBonus,
            };
        });
    }

    /**
     * Get the estimated best arm based on mean reward
     */
    getBestArm(): UCBArm<T> | null {
        let best: UCBArm<T> | null = null;
        let bestMean = -Infinity;

        for (const arm of this.arms.values()) {
            if (arm.pulls > 0) {
                const mean = arm.totalReward / arm.pulls;
                if (mean > bestMean) {
                    bestMean = mean;
                    best = arm;
                }
            }
        }

        return best;
    }

    /**
     * Calculate regret (difference between optimal and actual performance)
     */
    calculateRegret(): number {
        const best = this.getBestArm();
        if (!best || best.pulls === 0) return 0;

        const optimalMean = best.totalReward / best.pulls;
        let actualReward = 0;

        for (const arm of this.arms.values()) {
            actualReward += arm.totalReward;
        }

        return optimalMean * this.totalPulls - actualReward;
    }

    /**
     * Get confidence interval for an arm using Hoeffding's inequality
     */
    getConfidenceInterval(armId: string, confidence: number = 0.95): { lower: number; upper: number } {
        const arm = this.arms.get(armId);
        if (!arm || arm.pulls === 0) return { lower: 0, upper: 1 };

        const mean = arm.totalReward / arm.pulls;
        // Hoeffding bound: P(|mean - true_mean| > epsilon) <= 2*exp(-2*n*epsilon^2)
        // For confidence c: epsilon = sqrt(ln(2/(1-c)) / (2*n))
        const epsilon = Math.sqrt(Math.log(2 / (1 - confidence)) / (2 * arm.pulls));

        return {
            lower: Math.max(0, mean - epsilon),
            upper: Math.min(1, mean + epsilon),
        };
    }

    /**
     * Check if we have statistical significance between arms
     */
    hasSignificantDifference(armId1: string, armId2: string, confidence: number = 0.95): boolean {
        const ci1 = this.getConfidenceInterval(armId1, confidence);
        const ci2 = this.getConfidenceInterval(armId2, confidence);

        // Intervals don't overlap = significant difference
        return ci1.upper < ci2.lower || ci2.upper < ci1.lower;
    }

    /**
     * Reset all arms
     */
    reset(): void {
        for (const arm of this.arms.values()) {
            arm.pulls = 0;
            arm.totalReward = 0;
            arm.successes = 0;
            arm.lastPulled = undefined;
        }
        this.totalPulls = 0;
    }

    /**
     * Serialize bandit state
     */
    serialize(): string {
        return JSON.stringify({
            config: this.config,
            arms: Array.from(this.arms.entries()),
            totalPulls: this.totalPulls,
        });
    }

    /**
     * Deserialize bandit state
     */
    static deserialize<T>(json: string): UCBBandit<T> {
        const data = JSON.parse(json);
        const bandit = new UCBBandit<T>(data.config);
        bandit.totalPulls = data.totalPulls;

        for (const [id, arm] of data.arms) {
            bandit.arms.set(id, {
                ...arm,
                createdAt: new Date(arm.createdAt),
                lastPulled: arm.lastPulled ? new Date(arm.lastPulled) : undefined,
            });
        }

        return bandit;
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private calculateUCB(arm: UCBArm<T>): number {
        if (arm.pulls === 0) return Infinity;

        const mean = arm.totalReward / arm.pulls;
        const explorationBonus = Math.sqrt(
            (this.config.explorationParam * Math.log(this.totalPulls)) / arm.pulls
        );

        // Apply time decay if configured
        let timeWeight = 1;
        if (this.config.timeDecay < 1 && arm.lastPulled) {
            const age = Date.now() - arm.lastPulled.getTime();
            const days = age / (24 * 60 * 60 * 1000);
            timeWeight = Math.pow(this.config.timeDecay, days);
        }

        return (mean * timeWeight) + explorationBonus;
    }
}

/**
 * UCB-Tuned: A variant of UCB that uses variance estimates
 * Often performs better than UCB1 in practice
 */
export class UCBTunedBandit<T = unknown> extends UCBBandit<T> {
    private rewardSquares: Map<string, number> = new Map();

    addArm(id: string, data: T): UCBArm<T> {
        const arm = super.addArm(id, data);
        this.rewardSquares.set(id, 0);
        return arm;
    }

    recordOutcome(armId: string, reward: number): void {
        super.recordOutcome(armId, reward);
        const current = this.rewardSquares.get(armId) || 0;
        this.rewardSquares.set(armId, current + reward * reward);
    }

    /**
     * Get variance estimate for an arm
     */
    getVariance(armId: string): number {
        const arm = this.getArm(armId);
        if (!arm || arm.pulls < 2) return 0.25; // Default variance for binary

        const mean = arm.totalReward / arm.pulls;
        const meanSquare = (this.rewardSquares.get(armId) || 0) / arm.pulls;
        return Math.max(0, meanSquare - mean * mean);
    }
}

/**
 * Epsilon-Greedy: Simple baseline algorithm
 * With probability epsilon, explore randomly; otherwise exploit best
 */
export class EpsilonGreedy<T = unknown> {
    private arms: Map<string, UCBArm<T>> = new Map();
    private epsilon: number;
    private decayRate: number;
    private minEpsilon: number;
    private totalPulls: number = 0;

    constructor(epsilon: number = 0.1, decayRate: number = 0.999, minEpsilon: number = 0.01) {
        this.epsilon = epsilon;
        this.decayRate = decayRate;
        this.minEpsilon = minEpsilon;
    }

    addArm(id: string, data: T): UCBArm<T> {
        const arm: UCBArm<T> = {
            id,
            data,
            pulls: 0,
            totalReward: 0,
            successes: 0,
            createdAt: new Date(),
        };
        this.arms.set(id, arm);
        return arm;
    }

    selectArm(): UCBArm<T> | null {
        if (this.arms.size === 0) return null;

        const currentEpsilon = Math.max(
            this.minEpsilon,
            this.epsilon * Math.pow(this.decayRate, this.totalPulls)
        );

        // Explore
        if (Math.random() < currentEpsilon) {
            const armArray = Array.from(this.arms.values());
            return armArray[Math.floor(Math.random() * armArray.length)];
        }

        // Exploit
        let best: UCBArm<T> | null = null;
        let bestMean = -Infinity;

        for (const arm of this.arms.values()) {
            const mean = arm.pulls > 0 ? arm.totalReward / arm.pulls : 0;
            if (mean > bestMean || (mean === bestMean && arm.pulls < (best?.pulls || Infinity))) {
                bestMean = mean;
                best = arm;
            }
        }

        return best;
    }

    recordOutcome(armId: string, reward: number): void {
        const arm = this.arms.get(armId);
        if (!arm) throw new Error(`Arm not found: ${armId}`);

        arm.pulls++;
        arm.totalReward += reward;
        if (reward > 0) arm.successes++;
        arm.lastPulled = new Date();
        this.totalPulls++;
    }

    getCurrentEpsilon(): number {
        return Math.max(
            this.minEpsilon,
            this.epsilon * Math.pow(this.decayRate, this.totalPulls)
        );
    }
}
