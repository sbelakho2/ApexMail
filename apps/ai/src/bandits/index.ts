/**
 * @apexmail/ai - Multi-Armed Bandit Algorithms
 * 
 * Reinforcement learning algorithms for optimization:
 * - Thompson Sampling (Bayesian, probabilistic)
 * - UCB1 (Deterministic, theoretical guarantees)
 * - UCB-Tuned (Variance-aware UCB)
 * - Epsilon-Greedy (Simple baseline)
 */

export {
    ThompsonSampler,
    createSubjectLineOptimizer,
    createSendTimeOptimizer,
    createContentOptimizer,
    type BanditArm,
    type ThompsonConfig,
} from './thompson.js';

export {
    UCBBandit,
    UCBTunedBandit,
    EpsilonGreedy,
    type UCBArm,
    type UCBConfig,
} from './ucb.js';
