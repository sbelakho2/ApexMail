/**
 * Rollback Triggers + Poison Pill Detection
 *
 * Reliability features for "fire-and-forget" operations:
 *   • Daily autopilot health report
 *   • Automatic rollback when KPIs drop below control by X% for Y days
 *   • Poison pill detection: stop serving arms that spike negative replies
 *   • Reproducibility: log random seeds, selected samples, decision traces
 *   • Lead list quality gate (syntax, MX, role-address, free-mail)
 */

import { createLogger, generateId } from '@apexmail/lib';
import type { BanditPool } from './bandits.js';
import type { Pool } from 'pg';

const logger = createLogger({ name: 'safety', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface HealthReport {
  id: string;
  generatedAt: Date;
  activationRate: number;
  activationBaseline: number;
  replyRate: number;
  replyBaseline: number;
  negativeRate: number;
  armEntropy: number;
  alerts: HealthAlert[];
  rollbackTriggered: boolean;
  poisonPillsDetected: PoisonPill[];
}

export interface HealthAlert {
  type: 'activation_drop' | 'reply_drop' | 'negative_spike' | 'entropy_stuck' | 'bounce_spike';
  message: string;
  severity: 'warning' | 'critical';
  value: number;
  threshold: number;
}

export interface PoisonPill {
  armId: string;
  armLabel: string;
  stage: string;
  icpCluster: string;
  negativeRate: number;
  detectedAt: Date;
  action: 'frozen' | 'removed';
}

export interface DecisionTrace {
  id: string;
  contactId: string;
  campaignId: string;
  enrollmentId: string;
  subjectArmId: string | null;
  valuePropArmId: string | null;
  ctaArmId: string | null;
  subjectArmPrior: { alpha: number; beta: number } | null;
  valuePropArmPrior: { alpha: number; beta: number } | null;
  decayApplied: boolean;
  controlGroup: boolean;
  randomSeed: number;
  timestamp: Date;
}

export interface RollbackConfig {
  /** How many % below control before rollback triggers */
  dropThresholdPercent: number;
  /** How many consecutive days the drop must persist */
  consecutiveDaysRequired: number;
  /** Poison pill: negative rate threshold for immediate freeze */
  poisonNegativeRateThreshold: number;
  /** Bounce rate threshold for campaign halt */
  bounceRateThreshold: number;
  /** Unsubscribe rate threshold for throttling */
  unsubscribeRateThreshold: number;
}

export interface LeadQualityResult {
  valid: boolean;
  issues: LeadQualityIssue[];
}

export interface LeadQualityIssue {
  email: string;
  issue: 'invalid_syntax' | 'no_mx' | 'role_address' | 'free_mail' | 'disposable';
  message: string;
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

const DEFAULT_ROLLBACK_CONFIG: RollbackConfig = {
  dropThresholdPercent: 20,
  consecutiveDaysRequired: 3,
  poisonNegativeRateThreshold: 0.25,
  bounceRateThreshold: 0.05,
  unsubscribeRateThreshold: 0.02,
};

// ────────────────────────────────────────────────────────────────────
// Safety Monitor
// ────────────────────────────────────────────────────────────────────

export class SafetyMonitor {
  private config: RollbackConfig;
  private kpiHistory: Array<{ date: Date; activationRate: number; replyRate: number; negativeRate: number; bounceRate: number }> = [];
  private decisionTraces: DecisionTrace[] = [];
  private frozenArms: Set<string> = new Set();
  private safeArms: Map<string, { subject: string; valueProp: string }> = new Map();
  private db: Pool | null = null;

  constructor(config?: Partial<RollbackConfig>) {
    this.config = { ...DEFAULT_ROLLBACK_CONFIG, ...config };
  }

  setDb(pool: Pool): void {
    this.db = pool;
    logger.info('SafetyMonitor database wired');
  }

  /**
   * Hydrate frozen arms from the bandit_arms table and recent decision traces.
   * Called once at startup after setDb().
   */
  async hydrateFromDb(): Promise<void> {
    if (!this.db) return;
    try {
      // Load frozen arms from bandit_arms
      const frozenRows = await this.db.query(
        `SELECT id FROM bandit_arms WHERE frozen = true`
      );
      for (const row of frozenRows.rows) {
        this.frozenArms.add(row.id as string);
      }

      // Load recent KPI history from health_reports (last 30 days)
      const reportRows = await this.db.query(
        `SELECT report_date, activation_rate, reply_rate, negative_rate, bounce_rate
         FROM health_reports WHERE report_date > NOW() - INTERVAL '30 days'
         ORDER BY report_date`
      );
      for (const row of reportRows.rows) {
        this.kpiHistory.push({
          date: new Date(row.report_date as string),
          activationRate: (row.activation_rate as number) ?? 0,
          replyRate: (row.reply_rate as number) ?? 0,
          negativeRate: (row.negative_rate as number) ?? 0,
          bounceRate: (row.bounce_rate as number) ?? 0,
        });
      }

      logger.info('SafetyMonitor hydrated from DB', {
        frozenArms: this.frozenArms.size,
        kpiDays: this.kpiHistory.length,
      });
    } catch (err) {
      logger.error('Failed to hydrate safety monitor from DB', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ─────── Decision Tracing ───────

  traceDecision(trace: Omit<DecisionTrace, 'id' | 'timestamp'>): DecisionTrace {
    const full: DecisionTrace = {
      id: generateId('dt'),
      timestamp: new Date(),
      ...trace,
    };
    this.decisionTraces.push(full);

    // Cap trace buffer to prevent memory growth (keep last 10k)
    if (this.decisionTraces.length > 10_000) {
      this.decisionTraces = this.decisionTraces.slice(-5_000);
    }

    // Persist to DB
    if (this.db) {
      this.db.query(
        `INSERT INTO decision_traces (trace_type, campaign_id, contact_id, pool_id, arm_id, decision, reason, context, created_at)
         VALUES ('bandit_select', $1, $2, NULL, $3, 'select', $4, $5, $6)`,
        [
          full.campaignId,
          full.contactId,
          full.subjectArmId ?? full.valuePropArmId ?? full.ctaArmId,
          full.controlGroup ? 'control_group' : 'bandit_select',
          JSON.stringify({
            subjectArmPrior: full.subjectArmPrior,
            valuePropArmPrior: full.valuePropArmPrior,
            decayApplied: full.decayApplied,
            randomSeed: full.randomSeed,
          }),
          full.timestamp,
        ]
      ).catch(err => logger.warn('Failed to persist decision trace', { error: err instanceof Error ? err.message : String(err) }));
    }

    return full;
  }

  getRecentTraces(limit: number = 100): DecisionTrace[] {
    return this.decisionTraces.slice(-limit);
  }

  // ─────── Daily Health Report ───────

  generateHealthReport(
    currentMetrics: {
      activationRate: number;
      replyRate: number;
      negativeRate: number;
      bounceRate: number;
    },
    baselineMetrics: {
      activationRate: number;
      replyRate: number;
    },
    banditPools: BanditPool[]
  ): HealthReport {
    const alerts: HealthAlert[] = [];
    const poisonPills: PoisonPill[] = [];

    // Record KPIs
    this.kpiHistory.push({ date: new Date(), ...currentMetrics });

    // ── Activation Rate Check ──
    if (baselineMetrics.activationRate > 0) {
      const drop = (baselineMetrics.activationRate - currentMetrics.activationRate) / baselineMetrics.activationRate * 100;
      if (drop > this.config.dropThresholdPercent) {
        alerts.push({
          type: 'activation_drop',
          message: `Activation rate dropped ${drop.toFixed(1)}% below baseline`,
          severity: 'critical',
          value: currentMetrics.activationRate,
          threshold: baselineMetrics.activationRate * (1 - this.config.dropThresholdPercent / 100),
        });
      }
    }

    // ── Reply Rate Check ──
    if (baselineMetrics.replyRate > 0) {
      const drop = (baselineMetrics.replyRate - currentMetrics.replyRate) / baselineMetrics.replyRate * 100;
      if (drop > this.config.dropThresholdPercent) {
        alerts.push({
          type: 'reply_drop',
          message: `Reply rate dropped ${drop.toFixed(1)}% below baseline`,
          severity: 'critical',
          value: currentMetrics.replyRate,
          threshold: baselineMetrics.replyRate * (1 - this.config.dropThresholdPercent / 100),
        });
      }
    }

    // ── Negative Rate Check ──
    if (currentMetrics.negativeRate > this.config.poisonNegativeRateThreshold) {
      alerts.push({
        type: 'negative_spike',
        message: `Negative rate at ${(currentMetrics.negativeRate * 100).toFixed(1)}%`,
        severity: 'critical',
        value: currentMetrics.negativeRate,
        threshold: this.config.poisonNegativeRateThreshold,
      });
    }

    // ── Bounce Rate Check ──
    if (currentMetrics.bounceRate > this.config.bounceRateThreshold) {
      alerts.push({
        type: 'bounce_spike',
        message: `Bounce rate at ${(currentMetrics.bounceRate * 100).toFixed(1)}%`,
        severity: 'critical',
        value: currentMetrics.bounceRate,
        threshold: this.config.bounceRateThreshold,
      });
    }

    // ── Arm Entropy ──
    const entropy = this.calculateArmEntropy(banditPools);
    if (entropy < 0.3) {
      alerts.push({
        type: 'entropy_stuck',
        message: `Arm entropy is low (${entropy.toFixed(3)}). Bandits may be stuck.`,
        severity: 'warning',
        value: entropy,
        threshold: 0.3,
      });
    }

    // ── Poison Pill Detection ──
    for (const pool of banditPools) {
      for (const arm of pool.getAllArms()) {
        if (
          arm.recentNegativeRate > this.config.poisonNegativeRateThreshold &&
          arm.totalTrials >= 10 &&
          !this.frozenArms.has(arm.id)
        ) {
          const pill: PoisonPill = {
            armId: arm.id,
            armLabel: arm.label,
            stage: pool.stage,
            icpCluster: pool.icpCluster,
            negativeRate: arm.recentNegativeRate,
            detectedAt: new Date(),
            action: 'frozen',
          };
          poisonPills.push(pill);
          pool.freezeArm(arm.id);
          this.frozenArms.add(arm.id);

          logger.warn('POISON PILL: Arm frozen due to high negative rate', {
            armId: arm.id,
            label: arm.label,
            negativeRate: arm.recentNegativeRate,
          });
        }
      }
    }

    // ── Rollback Decision ──
    const rollbackTriggered = this.shouldRollback();

    if (rollbackTriggered) {
      logger.error('ROLLBACK TRIGGERED: Reverting to safe copy set', {
        consecutiveBadDays: this.countConsecutiveBadDays(),
      });
    }

    const report: HealthReport = {
      id: generateId('hr'),
      generatedAt: new Date(),
      activationRate: currentMetrics.activationRate,
      activationBaseline: baselineMetrics.activationRate,
      replyRate: currentMetrics.replyRate,
      replyBaseline: baselineMetrics.replyRate,
      negativeRate: currentMetrics.negativeRate,
      armEntropy: entropy,
      alerts,
      rollbackTriggered,
      poisonPillsDetected: poisonPills,
    };

    logger.info('Health report generated', {
      reportId: report.id,
      alertCount: alerts.length,
      poisonPillCount: poisonPills.length,
      rollback: rollbackTriggered,
    });

    // Persist health report to DB
    if (this.db) {
      this.db.query(
        `INSERT INTO health_reports (report_date, campaign_id, activation_rate, reply_rate, negative_rate, bounce_rate, unsub_rate, arm_entropy, kpi_flags, rollback_triggered)
         VALUES (CURRENT_DATE, NULL, $1, $2, $3, $4, NULL, $5, $6, $7)
         ON CONFLICT (report_date, campaign_id) DO UPDATE SET
           activation_rate = $1, reply_rate = $2, negative_rate = $3, bounce_rate = $4,
           arm_entropy = $5, kpi_flags = $6, rollback_triggered = $7`,
        [
          currentMetrics.activationRate,
          currentMetrics.replyRate,
          currentMetrics.negativeRate,
          currentMetrics.bounceRate,
          entropy,
          JSON.stringify({ alerts: alerts.map(a => a.type), poisonPills: poisonPills.map(p => p.armId) }),
          rollbackTriggered,
        ]
      ).catch(err => logger.warn('Failed to persist health report', { error: err instanceof Error ? err.message : String(err) }));
    }

    return report;
  }

  // ─────── Rollback Logic ───────

  private shouldRollback(): boolean {
    const badDays = this.countConsecutiveBadDays();
    return badDays >= this.config.consecutiveDaysRequired;
  }

  private countConsecutiveBadDays(): number {
    if (this.kpiHistory.length < 2) return 0;

    let consecutive = 0;
    // Walk backwards through history
    for (let i = this.kpiHistory.length - 1; i >= 1; i--) {
      const current = this.kpiHistory[i]!;
      const baseline = this.kpiHistory[0]!; // First entry is baseline

      const replyDrop = baseline.replyRate > 0
        ? (baseline.replyRate - current.replyRate) / baseline.replyRate * 100
        : 0;

      const activationDrop = baseline.activationRate > 0
        ? (baseline.activationRate - current.activationRate) / baseline.activationRate * 100
        : 0;

      if (replyDrop > this.config.dropThresholdPercent || activationDrop > this.config.dropThresholdPercent) {
        consecutive++;
      } else {
        break;
      }
    }

    return consecutive;
  }

  // ─────── Safe Arm Set ───────

  registerSafeArms(icpCluster: string, subject: string, valueProp: string): void {
    this.safeArms.set(icpCluster, { subject, valueProp });
  }

  getSafeArms(icpCluster: string): { subject: string; valueProp: string } | null {
    return this.safeArms.get(icpCluster) || null;
  }

  // ─────── Arm Entropy ───────

  private calculateArmEntropy(pools: BanditPool[]): number {
    let totalTrials = 0;
    const armTrials: number[] = [];

    for (const pool of pools) {
      for (const arm of pool.getAllArms()) {
        armTrials.push(arm.totalTrials);
        totalTrials += arm.totalTrials;
      }
    }

    if (totalTrials === 0 || armTrials.length <= 1) return 1;

    let entropy = 0;
    for (const trials of armTrials) {
      if (trials > 0) {
        const p = trials / totalTrials;
        entropy -= p * Math.log2(p);
      }
    }

    // Normalize to 0-1
    return entropy / Math.log2(armTrials.length);
  }

  // ─────── Auto-Throttle ───────

  shouldThrottleCampaign(
    bounceRate: number,
    negativeReplyRate: number,
    unsubscribeRate: number
  ): { throttle: boolean; halt: boolean; reason: string } {
    if (bounceRate > this.config.bounceRateThreshold) {
      return { throttle: false, halt: true, reason: `Bounce rate ${(bounceRate * 100).toFixed(1)}% exceeds threshold` };
    }

    if (unsubscribeRate > this.config.unsubscribeRateThreshold) {
      return { throttle: true, halt: false, reason: `Unsubscribe rate ${(unsubscribeRate * 100).toFixed(1)}% — throttling` };
    }

    if (negativeReplyRate > this.config.poisonNegativeRateThreshold) {
      return { throttle: true, halt: false, reason: `Negative reply rate ${(negativeReplyRate * 100).toFixed(1)}% — throttling` };
    }

    return { throttle: false, halt: false, reason: 'OK' };
  }
}

// ────────────────────────────────────────────────────────────────────
// Lead List Quality Gate
// ────────────────────────────────────────────────────────────────────

const ROLE_ADDRESSES = new Set([
  'abuse', 'admin', 'billing', 'compliance', 'devnull', 'dns',
  'ftp', 'hostmaster', 'info', 'inoc', 'ispfeedback', 'ispsupport',
  'list', 'list-request', 'maildaemon', 'mailerdaemon', 'marketing',
  'noc', 'no-reply', 'noreply', 'noc', 'phish', 'phishing',
  'postmaster', 'privacy', 'registrar', 'root', 'security',
  'spam', 'support', 'sysadmin', 'tech', 'undisclosed-recipients',
  'unsubscribe', 'usenet', 'uucp', 'webmaster', 'www',
  'sales', 'hello', 'contact', 'help', 'office', 'team',
]);

const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'gmx.net', 'live.com', 'msn.com', 'me.com',
  'fastmail.com', 'tutanota.com', 'mailinator.com', 'guerrillamail.com',
]);

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export function validateLeadList(
  emails: string[],
  options: { allowRoleAddresses?: boolean; allowFreeMail?: boolean } = {}
): LeadQualityResult {
  const issues: LeadQualityIssue[] = [];

  for (const email of emails) {
    // Syntax validation
    if (!EMAIL_REGEX.test(email)) {
      issues.push({ email, issue: 'invalid_syntax', message: `Invalid email syntax: ${email}` });
      continue;
    }

    const [local, domain] = email.toLowerCase().split('@');
    if (!local || !domain) {
      issues.push({ email, issue: 'invalid_syntax', message: `Missing local or domain part` });
      continue;
    }

    // Role address check
    if (!options.allowRoleAddresses && ROLE_ADDRESSES.has(local)) {
      issues.push({ email, issue: 'role_address', message: `Role-based address: ${local}@...` });
    }

    // Free mail check
    if (!options.allowFreeMail && FREE_MAIL_DOMAINS.has(domain)) {
      issues.push({ email, issue: 'free_mail', message: `Free mail domain: ${domain}` });
    }
  }

  return {
    valid: issues.filter(i => i.issue === 'invalid_syntax').length === 0,
    issues,
  };
}

// ────────────────────────────────────────────────────────────────────
// Token Divergence Helper
// ────────────────────────────────────────────────────────────────────

export function calculateTokenDivergence(
  baseline: string,
  generated: string
): number {
  const baseTokens = baseline.split(/\s+/);
  const genTokens = generated.split(/\s+/);

  if (baseTokens.length === 0) return 0;

  let changes = 0;
  const maxLen = Math.max(baseTokens.length, genTokens.length);

  for (let i = 0; i < maxLen; i++) {
    if (baseTokens[i] !== genTokens[i]) {
      changes++;
    }
  }

  return (changes / Math.max(baseTokens.length, 1)) * 100;
}

// Singleton
export const safetyMonitor = new SafetyMonitor();
