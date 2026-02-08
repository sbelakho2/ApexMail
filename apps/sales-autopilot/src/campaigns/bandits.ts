/**
 * Multi-Stage Thompson Sampling Bandits
 *
 * Split bandits by stage — each optimizes for a different feedback signal:
 *   • Subject bandit → optimizes open rate (fast feedback)
 *   • Value-prop bandit → optimizes reply/meeting (slow feedback)
 *   • CTA bandit → optimizes click/intent (optional, fast-medium feedback)
 *
 * Key features:
 *   • Weighted (soft) updates instead of naïve α+=1 / β+=1
 *   • Hierarchical priors: global → industry → arm (prevents cold-start garbage)
 *   • Per-ICP bandit pools (founders ≠ enterprise IT)
 *   • Catastrophic exploration cap
 *   • Decay toward prior (not toward 1)
 *   • Learning freeze toggle per tenant segment
 *   • Thompson sampling within under-tested arms (smart exploration)
 */

import { createLogger, generateId } from '@apexmail/lib';
import type { Pool } from 'pg';

const logger = createLogger({ name: 'bandits', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export type BanditStage = 'subject' | 'value_prop' | 'cta';

export type OutcomeType =
  | 'open'
  | 'click'
  | 'positive_reply'
  | 'neutral_reply'
  | 'negative_reply'
  | 'unsubscribe'
  | 'spam'
  | 'no_response';

export interface BanditArm {
  id: string;
  label: string;
  stage: BanditStage;
  icpCluster: string;
  alpha: number;
  beta: number;
  /** Initial prior α — used for decay-toward-prior */
  alpha0: number;
  /** Initial prior β — used for decay-toward-prior */
  beta0: number;
  totalTrials: number;
  recentNegativeRate: number;
  lastUpdatedAt: Date;
  frozen: boolean;
  metadata: Record<string, unknown>;
}

export interface HierarchicalPrior {
  globalAlpha: number;
  globalBeta: number;
  industryAlpha: Record<string, number>;
  industryBeta: Record<string, number>;
}

export interface BanditConfig {
  /** Max % of traffic an arm with high negative rate can receive */
  catastrophicCap: number;
  /** Threshold for "high negative rate" */
  negativeRateThreshold: number;
  /** Min trials before an arm is considered "tested" */
  minTrialsForTested: number;
  /** Fraction of parent stats a new arm inherits */
  priorInheritanceFraction: number;
  /** Decay divisor (d) for daily decay-toward-prior */
  decayDivisor: number;
}

// ────────────────────────────────────────────────────────────────────
// Outcome Weights — soft updates
// ────────────────────────────────────────────────────────────────────

export const OUTCOME_WEIGHTS: Record<OutcomeType, { alpha: number; beta: number }> = {
  open:            { alpha: 0.10,  beta: 0    },
  click:           { alpha: 0.35,  beta: 0    },
  positive_reply:  { alpha: 2.5,   beta: 0    },
  neutral_reply:   { alpha: 0.55,  beta: 0    },
  negative_reply:  { alpha: 0,     beta: 3.0  },
  unsubscribe:     { alpha: 0,     beta: 7.5  },
  spam:            { alpha: 0,     beta: 10.0 },
  no_response:     { alpha: 0,     beta: 0.45 },
};

const DEFAULT_CONFIG: BanditConfig = {
  catastrophicCap: 0.05,
  negativeRateThreshold: 0.15,
  minTrialsForTested: 20,
  priorInheritanceFraction: 0.25,
  decayDivisor: 2.0,
};

// ────────────────────────────────────────────────────────────────────
// Bandit Pool
// ────────────────────────────────────────────────────────────────────

export class BanditPool {
  private arms: Map<string, BanditArm> = new Map();
  private config: BanditConfig;
  private prior: HierarchicalPrior;
  readonly stage: BanditStage;
  readonly icpCluster: string;
  private _frozen = false;

  constructor(
    stage: BanditStage,
    icpCluster: string,
    config?: Partial<BanditConfig>,
    prior?: Partial<HierarchicalPrior>
  ) {
    this.stage = stage;
    this.icpCluster = icpCluster;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.prior = {
      globalAlpha: prior?.globalAlpha ?? 1.0,
      globalBeta: prior?.globalBeta ?? 1.0,
      industryAlpha: prior?.industryAlpha ?? {},
      industryBeta: prior?.industryBeta ?? {},
    };
  }

  // ─────── Arm Management ───────

  addArm(label: string, industry?: string, metadata?: Record<string, unknown>): BanditArm {
    const alpha0 = this.computeHierarchicalAlpha(industry);
    const beta0 = this.computeHierarchicalBeta(industry);

    const arm: BanditArm = {
      id: generateId('arm'),
      label,
      stage: this.stage,
      icpCluster: this.icpCluster,
      alpha: alpha0,
      beta: beta0,
      alpha0,
      beta0,
      totalTrials: 0,
      recentNegativeRate: 0,
      lastUpdatedAt: new Date(),
      frozen: false,
      metadata: metadata ?? {},
    };

    this.arms.set(arm.id, arm);
    logger.debug('Arm added', { armId: arm.id, label, stage: this.stage, icp: this.icpCluster });
    return arm;
  }

  getArm(armId: string): BanditArm | undefined {
    return this.arms.get(armId);
  }

  getAllArms(): BanditArm[] {
    return Array.from(this.arms.values());
  }

  /** Direct injection — used only by BanditManager.hydrateFromDb() */
  injectArm(arm: BanditArm): void {
    this.arms.set(arm.id, arm);
  }

  // ─────── Selection (Thompson Sampling) ───────

  /**
   * Smart exploration: under-tested arms use Thompson sampling within
   * the under-tested set (not uniform random). Tested arms are sampled
   * normally. Catastrophic cap enforced.
   */
  select(randomSeed?: number): BanditArm | null {
    const allArms = this.getAllArms();
    if (allArms.length === 0) return null;

    const underTested = allArms.filter(a => a.totalTrials < this.config.minTrialsForTested);
    const tested = allArms.filter(a => a.totalTrials >= this.config.minTrialsForTested);

    // If all arms are under-tested, sample Thompson within under-tested set
    const pool = underTested.length > 0 && tested.length === 0
      ? underTested
      : underTested.length > 0 && Math.random() < 0.3
        ? underTested  // 30% chance to explore under-tested
        : tested.length > 0 ? tested : allArms;

    let bestArm: BanditArm | null = null;
    let bestSample = -Infinity;

    for (const arm of pool) {
      // Catastrophic cap: skip arms with high negative rate
      if (
        arm.recentNegativeRate > this.config.negativeRateThreshold &&
        arm.totalTrials >= this.config.minTrialsForTested
      ) {
        // Only allow this arm to serve at most catastrophicCap fraction of the time
        if (Math.random() > this.config.catastrophicCap) {
          continue;
        }
      }

      const sample = this.thompsonSample(arm.alpha, arm.beta, randomSeed);
      if (sample > bestSample) {
        bestSample = sample;
        bestArm = arm;
      }
    }

    if (bestArm) {
      bestArm.totalTrials++;
      logger.debug('Arm selected', { armId: bestArm.id, label: bestArm.label, sample: bestSample });
    }

    return bestArm;
  }

  // ─────── Outcome Recording (Weighted Updates) ───────

  recordOutcome(armId: string, outcome: OutcomeType): void {
    if (this._frozen) {
      logger.info('Learning frozen — skipping update', { armId, outcome });
      return;
    }

    const arm = this.arms.get(armId);
    if (!arm) {
      logger.warn('Arm not found for update', { armId });
      return;
    }

    if (arm.frozen) {
      logger.debug('Arm frozen — skipping update', { armId, outcome });
      return;
    }

    const weight = OUTCOME_WEIGHTS[outcome];
    arm.alpha += weight.alpha;
    arm.beta += weight.beta;
    arm.lastUpdatedAt = new Date();

    // Update recent negative rate (exponential moving average)
    const isNegative = outcome === 'negative_reply' || outcome === 'unsubscribe' || outcome === 'spam';
    arm.recentNegativeRate = arm.recentNegativeRate * 0.95 + (isNegative ? 0.05 : 0);

    logger.debug('Outcome recorded', {
      armId,
      outcome,
      alphaΔ: weight.alpha,
      betaΔ: weight.beta,
      newAlpha: arm.alpha,
      newBeta: arm.beta,
    });
  }

  // ─────── Daily Decay (toward prior, not toward 1) ───────

  /**
   * Decay toward prior: α' = α0 + (α−α0)/d, β' = β0 + (β−β0)/d
   * Run on a daily cron job, NEVER inline during selection.
   */
  applyDecay(): void {
    if (this._frozen) {
      logger.info('Learning frozen — skipping decay', { stage: this.stage, icp: this.icpCluster });
      return;
    }

    const d = this.config.decayDivisor;

    for (const arm of this.arms.values()) {
      if (arm.frozen) continue;

      const prevAlpha = arm.alpha;
      const prevBeta = arm.beta;

      arm.alpha = arm.alpha0 + (arm.alpha - arm.alpha0) / d;
      arm.beta = arm.beta0 + (arm.beta - arm.beta0) / d;

      logger.debug('Decay applied', {
        armId: arm.id,
        prevAlpha,
        newAlpha: arm.alpha,
        prevBeta,
        newBeta: arm.beta,
      });
    }
  }

  // ─────── Learning Freeze ───────

  freeze(): void {
    this._frozen = true;
    logger.info('Pool frozen', { stage: this.stage, icp: this.icpCluster });
  }

  unfreeze(): void {
    this._frozen = false;
    logger.info('Pool unfrozen', { stage: this.stage, icp: this.icpCluster });
  }

  get isFrozen(): boolean {
    return this._frozen;
  }

  freezeArm(armId: string): void {
    const arm = this.arms.get(armId);
    if (arm) arm.frozen = true;
  }

  unfreezeArm(armId: string): void {
    const arm = this.arms.get(armId);
    if (arm) arm.frozen = false;
  }

  // ─────── Hierarchical Priors ───────

  private computeHierarchicalAlpha(industry?: string): number {
    const global = this.prior.globalAlpha;
    const ind = industry ? (this.prior.industryAlpha[industry] ?? global) : global;
    // Blend: 60% industry, 40% global (+ inheritance fraction of existing pool stats)
    let base = ind * 0.6 + global * 0.4;

    // Inherit from existing arms if any
    const existingArms = this.getAllArms();
    if (existingArms.length > 0) {
      const avgAlpha = existingArms.reduce((s, a) => s + a.alpha, 0) / existingArms.length;
      base += avgAlpha * this.config.priorInheritanceFraction;
    }

    return base;
  }

  private computeHierarchicalBeta(industry?: string): number {
    const global = this.prior.globalBeta;
    const ind = industry ? (this.prior.industryBeta[industry] ?? global) : global;
    let base = ind * 0.6 + global * 0.4;

    const existingArms = this.getAllArms();
    if (existingArms.length > 0) {
      const avgBeta = existingArms.reduce((s, a) => s + a.beta, 0) / existingArms.length;
      base += avgBeta * this.config.priorInheritanceFraction;
    }

    return base;
  }

  // ─────── Thompson Sample ───────

  private thompsonSample(alpha: number, beta: number, _seed?: number): number {
    // Beta distribution sampling via Jöhnk's algorithm
    return betaSample(Math.max(alpha, 0.01), Math.max(beta, 0.01));
  }

  // ─────── Serialization ───────

  serialize(): object {
    return {
      stage: this.stage,
      icpCluster: this.icpCluster,
      frozen: this._frozen,
      config: this.config,
      prior: this.prior,
      arms: Array.from(this.arms.values()),
    };
  }

  static deserialize(data: {
    stage: BanditStage;
    icpCluster: string;
    frozen: boolean;
    config: BanditConfig;
    prior: HierarchicalPrior;
    arms: BanditArm[];
  }): BanditPool {
    const pool = new BanditPool(data.stage, data.icpCluster, data.config, data.prior);
    pool._frozen = data.frozen;
    for (const arm of data.arms) {
      pool.arms.set(arm.id, { ...arm, lastUpdatedAt: new Date(arm.lastUpdatedAt) });
    }
    return pool;
  }
}

// ────────────────────────────────────────────────────────────────────
// Multi-Stage Bandit Manager
// ────────────────────────────────────────────────────────────────────

export class BanditManager {
  /** pools keyed by `${stage}:${icpCluster}` */
  private pools: Map<string, BanditPool> = new Map();
  private db: Pool | null = null;

  setDb(pool: Pool): void {
    this.db = pool;
    logger.info('BanditManager database wired');
  }

  /**
   * Hydrate pools and arms from the bandit_pools / bandit_arms tables.
   * Called once at startup after setDb().
   */
  async hydrateFromDb(): Promise<void> {
    if (!this.db) return;
    try {
      const poolRows = await this.db.query(
        `SELECT id, pool_key, stage, icp_segment, frozen, frozen_at FROM bandit_pools`
      );
      for (const row of poolRows.rows) {
        const key = row.pool_key as string;
        const stage = row.stage as BanditStage;
        const icp = row.icp_segment as string;
        const pool = new BanditPool(stage, icp);
        if (row.frozen) pool.freeze();

        // Load arms for this pool
        const armRows = await this.db.query(
          `SELECT id, arm_key, alpha, beta, trials, successes, failures, frozen, metadata
           FROM bandit_arms WHERE pool_id = $1`,
          [row.id]
        );
        for (const a of armRows.rows) {
          const meta = (a.metadata ?? {}) as Record<string, unknown>;
          const arm: BanditArm = {
            id: a.id as string,
            label: a.arm_key as string,
            stage,
            icpCluster: icp,
            alpha: a.alpha as number,
            beta: a.beta as number,
            alpha0: (meta.alpha0 as number) ?? 1.0,
            beta0: (meta.beta0 as number) ?? 1.0,
            totalTrials: a.trials as number,
            recentNegativeRate: (meta.recentNegativeRate as number) ?? 0,
            lastUpdatedAt: new Date(),
            frozen: a.frozen as boolean,
            metadata: meta,
          };
          pool.injectArm(arm);
        }

        this.pools.set(key, pool);
      }
      logger.info('BanditManager hydrated from DB', { poolCount: this.pools.size });
    } catch (err) {
      logger.error('Failed to hydrate bandits from DB', { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * Persist a pool + all its arms to Postgres.
   * Called after mutations (addArm, recordOutcome, decay, freeze).
   */
  async persistPool(pool: BanditPool): Promise<void> {
    if (!this.db) return;
    const key = `${pool.stage}:${pool.icpCluster}`;
    try {
      // Upsert pool row
      const res = await this.db.query(
        `INSERT INTO bandit_pools (id, pool_key, stage, icp_segment, frozen, frozen_at, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (pool_key) DO UPDATE SET frozen = $4, frozen_at = $5, updated_at = NOW()
         RETURNING id`,
        [key, pool.stage, pool.icpCluster, pool.isFrozen, pool.isFrozen ? new Date() : null]
      );
      const poolId = res.rows[0]?.id as string;
      if (!poolId) return;

      // Upsert each arm
      for (const arm of pool.getAllArms()) {
        await this.db.query(
          `INSERT INTO bandit_arms (id, pool_id, arm_key, alpha, beta, trials, successes, failures, frozen, frozen_at, metadata, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
           ON CONFLICT (pool_id, arm_key) DO UPDATE SET
             alpha = $4, beta = $5, trials = $6, successes = $7, failures = $8,
             frozen = $9, frozen_at = $10, metadata = $11, updated_at = NOW()`,
          [
            arm.id, poolId, arm.label, arm.alpha, arm.beta,
            arm.totalTrials,
            Math.round(arm.alpha - arm.alpha0),   // successes ≈ alpha growth
            Math.round(arm.beta - arm.beta0),     // failures ≈ beta growth
            arm.frozen, arm.frozen ? new Date() : null,
            JSON.stringify({ alpha0: arm.alpha0, beta0: arm.beta0, recentNegativeRate: arm.recentNegativeRate, ...arm.metadata }),
          ]
        );
      }
    } catch (err) {
      logger.error('Failed to persist bandit pool', { key, error: err instanceof Error ? err.message : String(err) });
    }
  }

  getOrCreatePool(
    stage: BanditStage,
    icpCluster: string,
    config?: Partial<BanditConfig>,
    prior?: Partial<HierarchicalPrior>
  ): BanditPool {
    const key = `${stage}:${icpCluster}`;
    let pool = this.pools.get(key);
    if (!pool) {
      pool = new BanditPool(stage, icpCluster, config, prior);
      this.pools.set(key, pool);
      logger.info('Created bandit pool', { stage, icpCluster });
      void this.persistPool(pool);
    }
    return pool;
  }

  getPool(stage: BanditStage, icpCluster: string): BanditPool | undefined {
    return this.pools.get(`${stage}:${icpCluster}`);
  }

  /** Persist a single pool after external mutations (e.g. recordOutcome, freezeArm). */
  persistPoolByKey(stage: BanditStage, icpCluster: string): void {
    const pool = this.pools.get(`${stage}:${icpCluster}`);
    if (pool) void this.persistPool(pool);
  }

  getAllPools(): BanditPool[] {
    return Array.from(this.pools.values());
  }

  /**
   * Run daily decay on all pools. This should be called by a cron job,
   * never inline during arm selection.
   */
  runDailyDecay(): void {
    logger.info('Running daily bandit decay', { poolCount: this.pools.size });
    for (const pool of this.pools.values()) {
      pool.applyDecay();
      void this.persistPool(pool);
    }
  }

  /**
   * Freeze all pools for a given ICP cluster (e.g., during incidents)
   */
  freezeCluster(icpCluster: string): void {
    for (const [key, pool] of this.pools) {
      if (key.endsWith(`:${icpCluster}`)) {
        pool.freeze();
        void this.persistPool(pool);
      }
    }
  }

  unfreezeCluster(icpCluster: string): void {
    for (const [key, pool] of this.pools) {
      if (key.endsWith(`:${icpCluster}`)) {
        pool.unfreeze();
        void this.persistPool(pool);
      }
    }
  }

  serialize(): object {
    const pools: Record<string, object> = {};
    for (const [key, pool] of this.pools) {
      pools[key] = pool.serialize();
    }
    return pools;
  }
}

// ────────────────────────────────────────────────────────────────────
// Beta Distribution Sampler
// ────────────────────────────────────────────────────────────────────

function gammaSample(shape: number): number {
  // Marsaglia and Tsang's method for shape >= 1
  if (shape < 1) {
    return gammaSample(shape + 1) * Math.pow(Math.random(), 1 / shape);
  }

  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);

  for (;;) {
    let x: number;
    let v: number;

    do {
      x = randn();
      v = 1 + c * x;
    } while (v <= 0);

    v = v * v * v;
    const u = Math.random();

    if (u < 1 - 0.0331 * (x * x) * (x * x)) return d * v;
    if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
}

function randn(): number {
  // Box-Muller transform
  const u = Math.random();
  const v = Math.random();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function betaSample(alpha: number, beta: number): number {
  const x = gammaSample(alpha);
  const y = gammaSample(beta);
  return x / (x + y);
}

// Export singleton manager
export const banditManager = new BanditManager();
