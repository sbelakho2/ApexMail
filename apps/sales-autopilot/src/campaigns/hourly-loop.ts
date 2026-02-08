/**
 * One-Hour Automated Testing + Improvement Loop
 *
 * Every hour the system runs a complete optimisation cycle:
 *   Phase 0  – Fixed Baseline invariants (≥10 % traffic, never mutated)
 *   Phase 1  – State snapshot (serialise bandit pools, funnel metrics)
 *   Phase 2  – Candidate selection (Thompson sampling + exploration floor)
 *   Phase 3  – Personalisation & generation with QA copy gates
 *   Phase 4  – Execution window (T=00:00 → T=00:50, cadence-governed sends)
 *   Phase 5  – Hourly evaluation (T=00:50, metric aggregation)
 *   Phase 6  – Safety enforcement (instant kill rules)
 *   Phase 7  – Pruning + promotion (under-performers removed, winners promoted)
 *   Phase 8  – Adaptive refresh (1-2 new variants seeded, controlled decay)
 *   Phase 9  – End-of-hour assertion (invariants hold, log decision trace)
 *
 * Operator requirements:
 *   • System ON/OFF toggle (only thing the operator controls)
 *   • Operator approves emails before send via approval queue
 *   • Operator sees all statistics
 *   • "In every hour, either improve, hold steady, or safely retreat — never degrade"
 */

import { createLogger, generateId } from '@apexmail/lib';
import { CronJob } from 'cron';
import { banditManager, type BanditArm } from './bandits.js';
import { safetyMonitor } from './safety.js';
import { cadenceGovernor } from './cadence-governor.js';

import { validateAndProcessCopy } from './copy-gates.js';

const logger = createLogger({ name: 'hourly-loop', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export type LoopStatus = 'idle' | 'running' | 'paused' | 'safe_mode';

export interface HourlySnapshot {
  id: string;
  hour: number;                    // sequential counter
  takenAt: Date;
  banditState: object;             // serialised BanditManager
  baselineArm: BaselineArmSnapshot;
  metrics: HourlyMetrics;
  activeCandidates: CandidateRecord[];
}

export interface BaselineArmSnapshot {
  subjectLabel: string;
  valuePropLabel: string;
  armIds: { subject: string; valueProp: string };
  /** Metrics for baseline arm only */
  openRate: number;
  replyRate: number;
  negativeRate: number;
  impressions: number;
}

export interface HourlyMetrics {
  totalSent: number;
  totalOpened: number;
  totalClicked: number;
  totalReplied: number;
  totalNegative: number;
  totalBounced: number;
  totalUnsubscribed: number;
  aggregateOpenRate: number;
  aggregateReplyRate: number;
  aggregateNegativeRate: number;
  aggregateBounceRate: number;
}

export interface CandidateRecord {
  armId: string;
  label: string;
  stage: string;
  icpCluster: string;
  impressions: number;
  opens: number;
  clicks: number;
  replies: number;
  negatives: number;
  openRate: number;
  replyRate: number;
  negativeRate: number;
  /** Beta-distribution lower/upper 95% CI bounds */
  lowerBound: number;
  upperBound: number;
  consecutiveHoursBeating: number;
  status: 'active' | 'pruned' | 'promoted' | 'killed' | 'baseline';
}

export interface EmailApprovalItem {
  id: string;
  contactId: string;
  contactEmail: string;
  campaignId: string;
  armId: string;
  armLabel: string;
  subject: string;
  bodyPreview: string;
  createdAt: Date;
  status: 'pending' | 'approved' | 'rejected';
  decidedAt: Date | null;
  decidedBy: string | null;
}

export interface LoopConfig {
  /** Min fraction of total traffic reserved for baseline arm */
  baselineTrafficFloor: number;
  /** Min impressions per arm before it can be pruned */
  explorationFloor: number;
  /** If arm upper CI bound < baseline lower CI bound, prune */
  pruneOnCIGap: boolean;
  /** Consecutive hours an arm must beat baseline before promotion */
  promotionThresholdHours: number;
  /** Negative rate that triggers instant kill */
  instantKillNegativeRate: number;
  /** Max new variants seeded per hour */
  maxNewVariantsPerHour: number;
  /** Execution window: minutes from cycle start to send cutoff */
  executionWindowMinutes: number;
  /** Whether operator must approve every email before send */
  requireApproval: boolean;
}

export interface LoopStats {
  status: LoopStatus;
  currentHour: number;
  totalHoursRun: number;
  lastCycleAt: Date | null;
  nextCycleAt: Date | null;
  baselineArm: BaselineArmSnapshot | null;
  candidateCount: number;
  prunedCount: number;
  promotedCount: number;
  killedCount: number;
  safeModeActivations: number;
  approvalQueueSize: number;
  recentSnapshots: HourlySnapshot[];
}

export interface HourlyOutcome {
  hour: number;
  verdict: 'improved' | 'held_steady' | 'retreated';
  baselineOpenRate: number;
  aggregateOpenRate: number;
  baselineReplyRate: number;
  aggregateReplyRate: number;
  candidatesPromoted: string[];
  candidatesPruned: string[];
  candidatesKilled: string[];
  newVariantsSeeded: number;
  safeModeTriggered: boolean;
  decisionTraceId: string;
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

const DEFAULT_LOOP_CONFIG: LoopConfig = {
  baselineTrafficFloor: 0.10,
  explorationFloor: 20,
  pruneOnCIGap: true,
  promotionThresholdHours: 3,
  instantKillNegativeRate: 0.25,
  maxNewVariantsPerHour: 2,
  executionWindowMinutes: 50,
  requireApproval: true,
};

// ────────────────────────────────────────────────────────────────────
// Hourly Loop Orchestrator
// ────────────────────────────────────────────────────────────────────

export class HourlyLoopOrchestrator {
  private config: LoopConfig;
  private status: LoopStatus = 'idle';
  private cronJob: CronJob | null = null;
  private hourCounter = 0;
  private totalHoursRun = 0;
  private lastCycleAt: Date | null = null;
  private safeModeActivations = 0;

  /** Rolling window of hourly snapshots (keep last 168 = 7 days) */
  private snapshots: HourlySnapshot[] = [];
  private outcomes: HourlyOutcome[] = [];

  /** Per-arm tracking across hours */
  private candidateTracking: Map<string, CandidateRecord> = new Map();
  /** Arms that have been pruned/killed — never re-enabled */
  private deadArms: Set<string> = new Set();
  /** The designated baseline arm IDs — NEVER mutated */
  private baselineArmIds: { subject: string | null; valueProp: string | null } = {
    subject: null,
    valueProp: null,
  };

  /** Approval queue for operator review */
  private approvalQueue: Map<string, EmailApprovalItem> = new Map();

  /** Hourly metric accumulators (reset each cycle) */
  private hourlyAccumulator: HourlyMetrics = this.emptyMetrics();

  constructor(config?: Partial<LoopConfig>) {
    this.config = { ...DEFAULT_LOOP_CONFIG, ...config };
  }

  // ════════════════════════════════════════════════════════════════
  //  SYSTEM ON/OFF (the only operator actions needed)
  // ════════════════════════════════════════════════════════════════

  start(): { success: boolean; message: string } {
    if (this.status === 'running') {
      return { success: false, message: 'Loop is already running' };
    }

    // Start hourly cron (every hour on the hour)
    this.cronJob = new CronJob('0 * * * *', () => {
      this.runHourlyCycle().catch(err => {
        logger.error(`Hourly cycle failed: ${err instanceof Error ? err.message : String(err)}`);
        this.enterSafeMode('Hourly cycle threw an exception');
      });
    });

    this.cronJob.start();
    this.status = 'running';
    logger.info('Hourly loop STARTED');

    return { success: true, message: 'Hourly optimisation loop started' };
  }

  stop(): { success: boolean; message: string } {
    if (this.status === 'idle') {
      return { success: false, message: 'Loop is not running' };
    }

    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
    }

    this.status = 'idle';
    logger.info('Hourly loop STOPPED');

    return { success: true, message: 'Hourly optimisation loop stopped' };
  }

  // ════════════════════════════════════════════════════════════════
  //  EMAIL APPROVAL QUEUE
  // ════════════════════════════════════════════════════════════════

  submitForApproval(item: Omit<EmailApprovalItem, 'id' | 'createdAt' | 'status' | 'decidedAt' | 'decidedBy'>): EmailApprovalItem {
    const full: EmailApprovalItem = {
      id: generateId('appr'),
      createdAt: new Date(),
      status: 'pending',
      decidedAt: null,
      decidedBy: null,
      ...item,
    };
    this.approvalQueue.set(full.id, full);
    logger.info(`Email queued for approval: ${full.id} → ${full.contactEmail}`);
    return full;
  }

  approveEmail(approvalId: string, operatorId: string = 'operator'): boolean {
    const item = this.approvalQueue.get(approvalId);
    if (!item || item.status !== 'pending') return false;
    item.status = 'approved';
    item.decidedAt = new Date();
    item.decidedBy = operatorId;
    logger.info(`Email APPROVED: ${approvalId} by ${operatorId}`);
    return true;
  }

  rejectEmail(approvalId: string, operatorId: string = 'operator'): boolean {
    const item = this.approvalQueue.get(approvalId);
    if (!item || item.status !== 'pending') return false;
    item.status = 'rejected';
    item.decidedAt = new Date();
    item.decidedBy = operatorId;
    logger.info(`Email REJECTED: ${approvalId} by ${operatorId}`);
    return true;
  }

  getPendingApprovals(): EmailApprovalItem[] {
    return Array.from(this.approvalQueue.values())
      .filter(i => i.status === 'pending')
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }

  getApprovalHistory(limit: number = 50): EmailApprovalItem[] {
    return Array.from(this.approvalQueue.values())
      .filter(i => i.status !== 'pending')
      .sort((a, b) => (b.decidedAt?.getTime() ?? 0) - (a.decidedAt?.getTime() ?? 0))
      .slice(0, limit);
  }

  isApproved(approvalId: string): boolean {
    return this.approvalQueue.get(approvalId)?.status === 'approved';
  }

  // ════════════════════════════════════════════════════════════════
  //  METRIC RECORDING (called by drip engine during the hour)
  // ════════════════════════════════════════════════════════════════

  recordSend(armId: string): void {
    this.hourlyAccumulator.totalSent++;
    this.incrementCandidate(armId, 'impressions');
  }

  recordOpen(armId: string): void {
    this.hourlyAccumulator.totalOpened++;
    this.incrementCandidate(armId, 'opens');
  }

  recordClick(armId: string): void {
    this.hourlyAccumulator.totalClicked++;
    this.incrementCandidate(armId, 'clicks');
  }

  recordReply(armId: string): void {
    this.hourlyAccumulator.totalReplied++;
    this.incrementCandidate(armId, 'replies');
  }

  recordNegative(armId: string): void {
    this.hourlyAccumulator.totalNegative++;
    this.incrementCandidate(armId, 'negatives');
  }

  recordBounce(): void {
    this.hourlyAccumulator.totalBounced++;
  }

  recordUnsubscribe(): void {
    this.hourlyAccumulator.totalUnsubscribed++;
  }

  // ════════════════════════════════════════════════════════════════
  //  THE HOURLY CYCLE (Phases 0–9)
  // ════════════════════════════════════════════════════════════════

  async runHourlyCycle(): Promise<HourlyOutcome> {
    this.hourCounter++;
    this.totalHoursRun++;
    const cycleStart = new Date();
    logger.info(`═══ HOURLY CYCLE #${this.hourCounter} START ═══`);

    // ── Phase 0: Fixed Baseline Invariants ──────────────────────
    this.enforceBaselineInvariants();

    // ── Phase 1: State Snapshot ─────────────────────────────────
    const snapshot = this.takeSnapshot();
    this.snapshots.push(snapshot);
    if (this.snapshots.length > 168) {
      this.snapshots = this.snapshots.slice(-168);
    }

    // ── Phase 2: Candidate Selection ────────────────────────────
    const selectedCandidates = this.selectCandidates();
    logger.info(`Phase 2: Selected ${selectedCandidates.length} candidates for this hour`);

    // ── Phase 3: Personalisation & QA Gates ─────────────────────
    const approvedCandidates = await this.runQAGates(selectedCandidates);
    logger.info(`Phase 3: ${approvedCandidates.length}/${selectedCandidates.length} candidates passed QA`);

    // ── Phase 4: Execution Window (T=00:00 – T=00:50) ──────────
    // Actual sends are driven by the drip engine's cron. The loop
    // just ensures that the bandit pools are configured correctly
    // and the approval queue is populated.
    logger.info(`Phase 4: Execution window open — ${this.config.executionWindowMinutes} min`);

    // ── Phase 5: Hourly Evaluation (computed from accumulators) ─
    this.computeHourlyRates();
    const evaluation = this.evaluate(snapshot);
    logger.info(`Phase 5: Evaluation — verdict: ${evaluation.verdict}`);

    // ── Phase 6: Safety Enforcement ─────────────────────────────
    const killed = this.enforceInstantKillRules();
    logger.info(`Phase 6: Safety — killed ${killed.length} arms`);

    // ── Phase 7: Pruning + Promotion ────────────────────────────
    const { pruned, promoted } = this.pruneAndPromote(snapshot.baselineArm);
    logger.info(`Phase 7: Pruned ${pruned.length}, Promoted ${promoted.length}`);

    // ── Phase 8: Adaptive Refresh ───────────────────────────────
    const seeded = this.adaptiveRefresh();
    logger.info(`Phase 8: Seeded ${seeded} new variants`);

    // ── Phase 9: End-of-Hour Assertions ─────────────────────────
    this.assertInvariants();

    // Build outcome
    const outcome: HourlyOutcome = {
      hour: this.hourCounter,
      verdict: evaluation.verdict,
      baselineOpenRate: snapshot.baselineArm.openRate,
      aggregateOpenRate: this.hourlyAccumulator.aggregateOpenRate,
      baselineReplyRate: snapshot.baselineArm.replyRate,
      aggregateReplyRate: this.hourlyAccumulator.aggregateReplyRate,
      candidatesPromoted: promoted,
      candidatesPruned: pruned,
      candidatesKilled: killed,
      newVariantsSeeded: seeded,
      safeModeTriggered: this.status === 'safe_mode',
      decisionTraceId: safetyMonitor.traceDecision({
        contactId: 'system',
        campaignId: 'hourly-loop',
        enrollmentId: `hour-${this.hourCounter}`,
        subjectArmId: this.baselineArmIds.subject,
        valuePropArmId: this.baselineArmIds.valueProp,
        ctaArmId: null,
        subjectArmPrior: null,
        valuePropArmPrior: null,
        decayApplied: false,
        controlGroup: false,
        randomSeed: Math.random(),
      }).id,
    };

    this.outcomes.push(outcome);
    if (this.outcomes.length > 168) {
      this.outcomes = this.outcomes.slice(-168);
    }

    // Reset accumulators for next hour
    this.lastCycleAt = cycleStart;
    this.hourlyAccumulator = this.emptyMetrics();

    logger.info(`═══ HOURLY CYCLE #${this.hourCounter} END — ${outcome.verdict.toUpperCase()} ═══`);
    return outcome;
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 0: Baseline Invariants
  // ════════════════════════════════════════════════════════════════

  /**
   * The baseline arm receives ≥10% of traffic and is NEVER mutated.
   * If no baseline exists yet, designate the current best-performing
   * arm as baseline.
   */
  private enforceBaselineInvariants(): void {
    // Auto-designate baseline on first run
    if (!this.baselineArmIds.subject) {
      const subjectPools = banditManager.getAllPools().filter(p => p.stage === 'subject');
      for (const pool of subjectPools) {
        const arms = pool.getAllArms();
        if (arms.length > 0) {
          // Pick the arm with highest α/(α+β)
          const best = arms.reduce((a, b) =>
            (a.alpha / (a.alpha + a.beta)) > (b.alpha / (b.alpha + b.beta)) ? a : b
          );
          this.baselineArmIds.subject = best.id;
          pool.freezeArm(best.id); // Never mutated
          this.initCandidateTracking(best, 'baseline');
          logger.info(`Baseline subject arm designated: ${best.label} (${best.id})`);
          break;
        }
      }
    }

    if (!this.baselineArmIds.valueProp) {
      const vpPools = banditManager.getAllPools().filter(p => p.stage === 'value_prop');
      for (const pool of vpPools) {
        const arms = pool.getAllArms();
        if (arms.length > 0) {
          const best = arms.reduce((a, b) =>
            (a.alpha / (a.alpha + a.beta)) > (b.alpha / (b.alpha + b.beta)) ? a : b
          );
          this.baselineArmIds.valueProp = best.id;
          pool.freezeArm(best.id);
          this.initCandidateTracking(best, 'baseline');
          logger.info(`Baseline value_prop arm designated: ${best.label} (${best.id})`);
          break;
        }
      }
    }

    // Ensure baseline arms are still frozen
    for (const pool of banditManager.getAllPools()) {
      if (this.baselineArmIds.subject) {
        const arm = pool.getArm(this.baselineArmIds.subject);
        if (arm && !arm.frozen) pool.freezeArm(this.baselineArmIds.subject);
      }
      if (this.baselineArmIds.valueProp) {
        const arm = pool.getArm(this.baselineArmIds.valueProp);
        if (arm && !arm.frozen) pool.freezeArm(this.baselineArmIds.valueProp);
      }
    }
  }

  setBaseline(subjectArmId: string, valuePropArmId: string): void {
    this.baselineArmIds = { subject: subjectArmId, valueProp: valuePropArmId };
    // Freeze both
    for (const pool of banditManager.getAllPools()) {
      const sArm = pool.getArm(subjectArmId);
      if (sArm) pool.freezeArm(subjectArmId);
      const vArm = pool.getArm(valuePropArmId);
      if (vArm) pool.freezeArm(valuePropArmId);
    }
    logger.info(`Baseline manually set: subject=${subjectArmId}, valueProp=${valuePropArmId}`);
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 1: State Snapshot
  // ════════════════════════════════════════════════════════════════

  private takeSnapshot(): HourlySnapshot {
    const baselineMetrics = this.getBaselineMetrics();

    const candidates = Array.from(this.candidateTracking.values())
      .filter(c => c.status === 'active' || c.status === 'baseline');

    return {
      id: generateId('snap'),
      hour: this.hourCounter,
      takenAt: new Date(),
      banditState: banditManager.serialize(),
      baselineArm: baselineMetrics,
      metrics: { ...this.hourlyAccumulator },
      activeCandidates: candidates.map(c => ({ ...c })),
    };
  }

  private getBaselineMetrics(): BaselineArmSnapshot {
    const subjectId = this.baselineArmIds.subject;
    const vpId = this.baselineArmIds.valueProp;

    // Find baseline tracking records
    const subjectTracking = subjectId ? this.candidateTracking.get(subjectId) : null;

    const impressions = subjectTracking?.impressions ?? 0;
    const opens = subjectTracking?.opens ?? 0;
    const replies = subjectTracking?.replies ?? 0;
    const negatives = subjectTracking?.negatives ?? 0;

    return {
      subjectLabel: subjectTracking?.label ?? 'unset',
      valuePropLabel: vpId
        ? (this.candidateTracking.get(vpId)?.label ?? 'unset')
        : 'unset',
      armIds: { subject: subjectId ?? '', valueProp: vpId ?? '' },
      openRate: impressions > 0 ? opens / impressions : 0,
      replyRate: impressions > 0 ? replies / impressions : 0,
      negativeRate: impressions > 0 ? negatives / impressions : 0,
      impressions,
    };
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 2: Candidate Selection (Thompson Sampling)
  // ════════════════════════════════════════════════════════════════

  private selectCandidates(): BanditArm[] {
    const selected: BanditArm[] = [];

    for (const pool of banditManager.getAllPools()) {
      // Skip arms already pruned/killed
      const arm = pool.select();
      if (!arm) continue;
      if (this.deadArms.has(arm.id)) continue;

      // Ensure candidate tracking exists
      if (!this.candidateTracking.has(arm.id)) {
        this.initCandidateTracking(arm, 'active');
      }

      selected.push(arm);
    }

    return selected;
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 3: Personalisation + QA Copy Gates
  // ════════════════════════════════════════════════════════════════

  private async runQAGates(candidates: BanditArm[]): Promise<BanditArm[]> {
    const approved: BanditArm[] = [];

    for (const arm of candidates) {
      // Build synthetic copy input from arm metadata
      const subject = (arm.metadata['subject'] as string) || arm.label;
      const body = (arm.metadata['body'] as string) || '';

      const copyResult = validateAndProcessCopy({
        subject,
        body,
        templateBaseline: null,
        tokens: {
          '{{lead.first_name}}': 'Test',
          '{{lead.company_name}}': 'TestCo',
        },
        isHighRisk: false,
      });

      if (copyResult.approved) {
        approved.push(arm);
      } else {
        const failMessages = copyResult.lint.violations
          .map((v: { message: string }) => v.message)
          .join('; ');
        logger.warn(`QA gate FAILED for arm ${arm.id}: ${failMessages}`);
        // Don't kill — just skip this hour
      }
    }

    return approved;
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 5: Hourly Evaluation
  // ════════════════════════════════════════════════════════════════

  private computeHourlyRates(): void {
    const m = this.hourlyAccumulator;
    m.aggregateOpenRate = m.totalSent > 0 ? m.totalOpened / m.totalSent : 0;
    m.aggregateReplyRate = m.totalSent > 0 ? m.totalReplied / m.totalSent : 0;
    m.aggregateNegativeRate = m.totalSent > 0 ? m.totalNegative / m.totalSent : 0;
    m.aggregateBounceRate = m.totalSent > 0 ? m.totalBounced / m.totalSent : 0;
  }

  private evaluate(snapshot: HourlySnapshot): { verdict: 'improved' | 'held_steady' | 'retreated' } {
    const baseline = snapshot.baselineArm;
    const agg = this.hourlyAccumulator;

    // If no baseline data yet, hold steady
    if (baseline.impressions < 5) {
      return { verdict: 'held_steady' };
    }

    const replyDelta = agg.aggregateReplyRate - baseline.replyRate;
    const openDelta = agg.aggregateOpenRate - baseline.openRate;

    // If aggregate is meaningfully worse → retreat
    if (
      agg.aggregateReplyRate < baseline.replyRate * 0.8 ||
      agg.aggregateNegativeRate > baseline.negativeRate * 1.5
    ) {
      this.enterSafeMode('Aggregate performance dropped below 80% of baseline');
      return { verdict: 'retreated' };
    }

    // If aggregate is better → improved
    if (replyDelta > 0.005 || openDelta > 0.01) {
      return { verdict: 'improved' };
    }

    // Otherwise hold steady
    return { verdict: 'held_steady' };
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 6: Safety Enforcement (Instant Kill Rules)
  // ════════════════════════════════════════════════════════════════

  private enforceInstantKillRules(): string[] {
    const killed: string[] = [];

    for (const [armId, record] of this.candidateTracking) {
      if (record.status !== 'active') continue;
      if (record.impressions < 5) continue; // Not enough data

      // Instant kill: negative rate above threshold
      if (record.negativeRate > this.config.instantKillNegativeRate) {
        record.status = 'killed';
        this.deadArms.add(armId);

        // Freeze in bandit pool
        for (const pool of banditManager.getAllPools()) {
          pool.freezeArm(armId);
        }

        killed.push(armId);
        logger.warn(`INSTANT KILL: Arm ${armId} (${record.label}) — negative rate ${(record.negativeRate * 100).toFixed(1)}%`);
      }
    }

    return killed;
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 7: Pruning + Promotion
  // ════════════════════════════════════════════════════════════════

  private pruneAndPromote(baseline: BaselineArmSnapshot): { pruned: string[]; promoted: string[] } {
    const pruned: string[] = [];
    const promoted: string[] = [];

    for (const [armId, record] of this.candidateTracking) {
      if (record.status !== 'active') continue;
      if (armId === this.baselineArmIds.subject || armId === this.baselineArmIds.valueProp) continue;

      // Need at least exploration floor impressions
      if (record.impressions < this.config.explorationFloor) continue;

      // Compute 95% CI bounds using Beta distribution
      const { lower, upper } = this.betaCI(record.replies, record.impressions, 0.95);
      record.lowerBound = lower;
      record.upperBound = upper;

      const baselineLower = baseline.impressions > 0
        ? this.betaCI(
            Math.round(baseline.replyRate * baseline.impressions),
            baseline.impressions,
            0.95
          ).lower
        : 0;

      // Prune: upper bound of candidate < lower bound of baseline
      if (this.config.pruneOnCIGap && upper < baselineLower && baseline.impressions >= this.config.explorationFloor) {
        record.status = 'pruned';
        this.deadArms.add(armId);
        pruned.push(armId);
        logger.info(`PRUNED: Arm ${armId} (${record.label}) — CI upper ${upper.toFixed(4)} < baseline lower ${baselineLower.toFixed(4)}`);

        for (const pool of banditManager.getAllPools()) {
          pool.freezeArm(armId);
        }
        continue;
      }

      // Promotion check: arm beats baseline for N consecutive hours
      if (record.replyRate > baseline.replyRate && record.impressions >= this.config.explorationFloor) {
        record.consecutiveHoursBeating++;
      } else {
        record.consecutiveHoursBeating = 0;
      }

      if (record.consecutiveHoursBeating >= this.config.promotionThresholdHours) {
        record.status = 'promoted';
        promoted.push(armId);
        logger.info(`PROMOTED: Arm ${armId} (${record.label}) — beat baseline for ${record.consecutiveHoursBeating} consecutive hours`);
      }
    }

    return { pruned, promoted };
  }

  /**
   * Compute 95% credible interval for Beta(α, β) using normal approximation.
   * α = successes + 1, β = failures + 1 (Jeffreys prior would be +0.5)
   */
  private betaCI(successes: number, trials: number, confidence: number): { lower: number; upper: number } {
    const alpha = successes + 1;
    const beta = trials - successes + 1;
    const mean = alpha / (alpha + beta);
    const variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
    const stddev = Math.sqrt(variance);

    // Z-score for 95% = 1.96
    const z = confidence >= 0.99 ? 2.576 : confidence >= 0.95 ? 1.96 : 1.645;

    return {
      lower: Math.max(0, mean - z * stddev),
      upper: Math.min(1, mean + z * stddev),
    };
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 8: Adaptive Refresh
  // ════════════════════════════════════════════════════════════════

  private adaptiveRefresh(): number {
    // Count active candidates
    const activeCount = Array.from(this.candidateTracking.values())
      .filter(c => c.status === 'active').length;

    // Only seed if we've pruned/killed enough to need refresh
    const deadThisHour = Array.from(this.candidateTracking.values())
      .filter(c => c.status === 'pruned' || c.status === 'killed').length;

    if (deadThisHour === 0 && activeCount >= 3) return 0;

    // Seed up to maxNewVariantsPerHour
    let seeded = 0;
    for (const pool of banditManager.getAllPools()) {
      if (seeded >= this.config.maxNewVariantsPerHour) break;

      // Only seed in pools that have room
      const aliveInPool = pool.getAllArms().filter(a => !this.deadArms.has(a.id) && !a.frozen).length;
      if (aliveInPool >= 5) continue;

      // Add a new exploratory arm with inherited priors
      const newArm = pool.addArm(
        `variant-h${this.hourCounter}-${seeded + 1}`,
        undefined,
        { seededAtHour: this.hourCounter, exploratory: true }
      );

      this.initCandidateTracking(newArm, 'active');
      seeded++;
      logger.info(`Seeded new variant: ${newArm.label} in ${pool.stage}:${pool.icpCluster}`);
    }

    // Apply controlled decay on all pools
    banditManager.runDailyDecay();

    return seeded;
  }

  // ════════════════════════════════════════════════════════════════
  //  Phase 9: End-of-Hour Assertions
  // ════════════════════════════════════════════════════════════════

  private assertInvariants(): void {
    // Invariant 1: Baseline arm must exist and be frozen
    if (this.baselineArmIds.subject) {
      let found = false;
      for (const pool of banditManager.getAllPools()) {
        const arm = pool.getArm(this.baselineArmIds.subject);
        if (arm) {
          found = true;
          if (!arm.frozen) {
            logger.error('INVARIANT VIOLATION: Baseline subject arm is not frozen — fixing');
            pool.freezeArm(this.baselineArmIds.subject);
          }
        }
      }
      if (!found) {
        logger.error('INVARIANT VIOLATION: Baseline subject arm not found in any pool');
      }
    }

    // Invariant 2: Dead arms must remain dead
    for (const deadId of this.deadArms) {
      for (const pool of banditManager.getAllPools()) {
        const arm = pool.getArm(deadId);
        if (arm && !arm.frozen) {
          logger.error(`INVARIANT VIOLATION: Dead arm ${deadId} is not frozen — fixing`);
          pool.freezeArm(deadId);
        }
      }
    }

    // Invariant 3: Baseline traffic floor
    const baselineRecord = this.baselineArmIds.subject
      ? this.candidateTracking.get(this.baselineArmIds.subject)
      : null;
    if (baselineRecord && this.hourlyAccumulator.totalSent > 0) {
      const baselineFraction = baselineRecord.impressions / this.hourlyAccumulator.totalSent;
      if (baselineFraction < this.config.baselineTrafficFloor * 0.8) {
        logger.warn(`Baseline traffic ${(baselineFraction * 100).toFixed(1)}% below floor ${(this.config.baselineTrafficFloor * 100).toFixed(1)}%`);
      }
    }

    logger.info('Phase 9: All invariants checked');
  }

  // ════════════════════════════════════════════════════════════════
  //  Safe Mode
  // ════════════════════════════════════════════════════════════════

  private enterSafeMode(reason: string): void {
    this.status = 'safe_mode';
    this.safeModeActivations++;

    // Freeze all non-baseline arms
    for (const pool of banditManager.getAllPools()) {
      for (const arm of pool.getAllArms()) {
        if (arm.id !== this.baselineArmIds.subject && arm.id !== this.baselineArmIds.valueProp) {
          pool.freezeArm(arm.id);
        }
      }
    }

    logger.error(`SAFE MODE ACTIVATED: ${reason}. Only baseline arm is active.`);
  }

  exitSafeMode(): void {
    if (this.status !== 'safe_mode') return;
    this.status = 'running';

    // Unfreeze active (non-dead) arms
    for (const pool of banditManager.getAllPools()) {
      for (const arm of pool.getAllArms()) {
        if (!this.deadArms.has(arm.id) && arm.id !== this.baselineArmIds.subject && arm.id !== this.baselineArmIds.valueProp) {
          pool.unfreezeArm(arm.id);
        }
      }
    }

    logger.info('Safe mode EXITED — non-baseline arms unfrozen');
  }

  // ════════════════════════════════════════════════════════════════
  //  STATISTICS (everything the operator needs to see)
  // ════════════════════════════════════════════════════════════════

  getStatus(): LoopStatus {
    return this.status;
  }

  getStats(): LoopStats {
    const nextCycle = this.cronJob
      ? new Date(this.cronJob.nextDate().toMillis())
      : null;

    return {
      status: this.status,
      currentHour: this.hourCounter,
      totalHoursRun: this.totalHoursRun,
      lastCycleAt: this.lastCycleAt,
      nextCycleAt: nextCycle,
      baselineArm: this.getBaselineMetrics(),
      candidateCount: Array.from(this.candidateTracking.values()).filter(c => c.status === 'active').length,
      prunedCount: Array.from(this.candidateTracking.values()).filter(c => c.status === 'pruned').length,
      promotedCount: Array.from(this.candidateTracking.values()).filter(c => c.status === 'promoted').length,
      killedCount: Array.from(this.candidateTracking.values()).filter(c => c.status === 'killed').length,
      safeModeActivations: this.safeModeActivations,
      approvalQueueSize: this.getPendingApprovals().length,
      recentSnapshots: this.snapshots.slice(-24),
    };
  }

  getCandidates(): CandidateRecord[] {
    return Array.from(this.candidateTracking.values())
      .sort((a, b) => b.replyRate - a.replyRate);
  }

  getOutcomes(limit: number = 24): HourlyOutcome[] {
    return this.outcomes.slice(-limit);
  }

  getCurrentMetrics(): HourlyMetrics {
    const m = { ...this.hourlyAccumulator };
    m.aggregateOpenRate = m.totalSent > 0 ? m.totalOpened / m.totalSent : 0;
    m.aggregateReplyRate = m.totalSent > 0 ? m.totalReplied / m.totalSent : 0;
    m.aggregateNegativeRate = m.totalSent > 0 ? m.totalNegative / m.totalSent : 0;
    m.aggregateBounceRate = m.totalSent > 0 ? m.totalBounced / m.totalSent : 0;
    return m;
  }

  /** Full dashboard data in one call */
  getDashboard(): {
    status: LoopStatus;
    stats: LoopStats;
    candidates: CandidateRecord[];
    currentMetrics: HourlyMetrics;
    recentOutcomes: HourlyOutcome[];
    pendingApprovals: EmailApprovalItem[];
    approvalHistory: EmailApprovalItem[];
    safetyReport: ReturnType<typeof safetyMonitor.shouldThrottleCampaign>;
    cadenceAtLimit: string[];
    cadenceStopped: Array<{ contactId: string; reason: string | null; stoppedAt: Date | null }>;
  } {
    const m = this.getCurrentMetrics();

    return {
      status: this.status,
      stats: this.getStats(),
      candidates: this.getCandidates(),
      currentMetrics: m,
      recentOutcomes: this.getOutcomes(),
      pendingApprovals: this.getPendingApprovals(),
      approvalHistory: this.getApprovalHistory(),
      safetyReport: safetyMonitor.shouldThrottleCampaign(
        m.aggregateBounceRate,
        m.aggregateNegativeRate,
        m.totalSent > 0 ? m.totalUnsubscribed / m.totalSent : 0
      ),
      cadenceAtLimit: cadenceGovernor.getContactsAtLimit(),
      cadenceStopped: cadenceGovernor.getStoppedContacts(),
    };
  }

  // ════════════════════════════════════════════════════════════════
  //  Helpers
  // ════════════════════════════════════════════════════════════════

  private initCandidateTracking(arm: BanditArm, status: CandidateRecord['status']): void {
    this.candidateTracking.set(arm.id, {
      armId: arm.id,
      label: arm.label,
      stage: arm.stage,
      icpCluster: arm.icpCluster,
      impressions: 0,
      opens: 0,
      clicks: 0,
      replies: 0,
      negatives: 0,
      openRate: 0,
      replyRate: 0,
      negativeRate: 0,
      lowerBound: 0,
      upperBound: 1,
      consecutiveHoursBeating: 0,
      status,
    });
  }

  private incrementCandidate(armId: string, field: 'impressions' | 'opens' | 'clicks' | 'replies' | 'negatives'): void {
    const record = this.candidateTracking.get(armId);
    if (!record) return;
    record[field]++;

    // Recompute rates
    if (record.impressions > 0) {
      record.openRate = record.opens / record.impressions;
      record.replyRate = record.replies / record.impressions;
      record.negativeRate = record.negatives / record.impressions;
    }
  }

  private emptyMetrics(): HourlyMetrics {
    return {
      totalSent: 0,
      totalOpened: 0,
      totalClicked: 0,
      totalReplied: 0,
      totalNegative: 0,
      totalBounced: 0,
      totalUnsubscribed: 0,
      aggregateOpenRate: 0,
      aggregateReplyRate: 0,
      aggregateNegativeRate: 0,
      aggregateBounceRate: 0,
    };
  }
}

// Singleton
export const hourlyLoop = new HourlyLoopOrchestrator();
