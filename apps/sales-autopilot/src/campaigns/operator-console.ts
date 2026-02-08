/**
 * Operator Console — Simple operator interface
 *
 * The operator only needs to:
 *   1. Turn the system ON / OFF
 *   2. Approve or reject emails before they send
 *   3. See all statistics & dashboards
 *
 * Nothing else needed. Every other action is automated.
 *
 * This module provides the API handlers that the routes.ts file will
 * mount. All state lives in the HourlyLoopOrchestrator singleton.
 */

import { createLogger } from '@apexmail/lib';
import type { Pool } from 'pg';
import { hourlyLoop } from './hourly-loop.js';
import { safetyMonitor } from './safety.js';
import { banditManager } from './bandits.js';

import { cadenceGovernor } from './cadence-governor.js';

const logger = createLogger({ name: 'operator-console', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface OperatorAction {
  action: string;
  performedAt: Date;
  operatorId: string;
  detail: string;
}

export interface SystemOverview {
  /** Current loop status: idle | running | paused | safe_mode */
  status: string;
  /** Whether the operator can start the loop */
  canStart: boolean;
  /** Whether the operator can stop the loop */
  canStop: boolean;
  /** Quick stats */
  hoursRun: number;
  currentHour: number;
  pendingApprovals: number;
  activeCandidates: number;
  safeModeCount: number;
  /** Safety status */
  safetyOk: boolean;
  safetyMessage: string;
}

export interface EmailReviewItem {
  id: string;
  contactEmail: string;
  subject: string;
  bodyPreview: string;
  armLabel: string;
  campaignId: string;
  createdAt: Date;
  status: 'pending' | 'approved' | 'rejected';
}

// ────────────────────────────────────────────────────────────────────
// Operator Console
// ────────────────────────────────────────────────────────────────────

export class OperatorConsole {
  private actionLog: OperatorAction[] = [];
  private maxLogSize = 1000;
  private db: Pool | null = null;

  setDb(pool: Pool): void {
    this.db = pool;
    logger.info('OperatorConsole database wired');
  }

  // ─────── 1. ON/OFF ───────

  turnOn(operatorId: string = 'operator'): { success: boolean; message: string } {
    const result = hourlyLoop.start();
    this.logAction(operatorId, 'SYSTEM_ON', result.message);
    return result;
  }

  turnOff(operatorId: string = 'operator'): { success: boolean; message: string } {
    const result = hourlyLoop.stop();
    this.logAction(operatorId, 'SYSTEM_OFF', result.message);
    return result;
  }

  // ─────── 2. Email Approval ───────

  getPendingEmails(): EmailReviewItem[] {
    return hourlyLoop.getPendingApprovals().map(item => ({
      id: item.id,
      contactEmail: item.contactEmail,
      subject: item.subject,
      bodyPreview: item.bodyPreview,
      armLabel: item.armLabel,
      campaignId: item.campaignId,
      createdAt: item.createdAt,
      status: item.status,
    }));
  }

  approveEmail(approvalId: string, operatorId: string = 'operator'): boolean {
    const ok = hourlyLoop.approveEmail(approvalId, operatorId);
    if (ok) this.logAction(operatorId, 'EMAIL_APPROVED', `Approved ${approvalId}`);
    return ok;
  }

  rejectEmail(approvalId: string, operatorId: string = 'operator'): boolean {
    const ok = hourlyLoop.rejectEmail(approvalId, operatorId);
    if (ok) this.logAction(operatorId, 'EMAIL_REJECTED', `Rejected ${approvalId}`);
    return ok;
  }

  approveAll(operatorId: string = 'operator'): number {
    const pending = hourlyLoop.getPendingApprovals();
    let approved = 0;
    for (const item of pending) {
      if (hourlyLoop.approveEmail(item.id, operatorId)) {
        approved++;
      }
    }
    if (approved > 0) {
      this.logAction(operatorId, 'EMAIL_BULK_APPROVED', `Approved ${approved} emails`);
    }
    return approved;
  }

  // ─────── 3. Statistics Dashboard ───────

  getOverview(): SystemOverview {
    const status = hourlyLoop.getStatus();
    const stats = hourlyLoop.getStats();
    const metrics = hourlyLoop.getCurrentMetrics();

    const safety = safetyMonitor.shouldThrottleCampaign(
      metrics.aggregateBounceRate,
      metrics.aggregateNegativeRate,
      metrics.totalSent > 0 ? metrics.totalUnsubscribed / metrics.totalSent : 0
    );

    return {
      status,
      canStart: status === 'idle' || status === 'safe_mode',
      canStop: status === 'running' || status === 'safe_mode',
      hoursRun: stats.totalHoursRun,
      currentHour: stats.currentHour,
      pendingApprovals: stats.approvalQueueSize,
      activeCandidates: stats.candidateCount,
      safeModeCount: stats.safeModeActivations,
      safetyOk: !safety.throttle && !safety.halt,
      safetyMessage: safety.reason,
    };
  }

  getFullDashboard() {
    return hourlyLoop.getDashboard();
  }

  getCandidatePerformance() {
    return hourlyLoop.getCandidates();
  }

  getHourlyOutcomes(limit: number = 24) {
    return hourlyLoop.getOutcomes(limit);
  }

  getCurrentMetrics() {
    return hourlyLoop.getCurrentMetrics();
  }

  getBaselineComparison() {
    const stats = hourlyLoop.getStats();
    const metrics = hourlyLoop.getCurrentMetrics();
    const baseline = stats.baselineArm;

    if (!baseline) {
      return { hasBaseline: false, comparison: null };
    }

    return {
      hasBaseline: true,
      comparison: {
        baseline: {
          subjectLabel: baseline.subjectLabel,
          valuePropLabel: baseline.valuePropLabel,
          openRate: baseline.openRate,
          replyRate: baseline.replyRate,
          negativeRate: baseline.negativeRate,
          impressions: baseline.impressions,
        },
        aggregate: {
          openRate: metrics.aggregateOpenRate,
          replyRate: metrics.aggregateReplyRate,
          negativeRate: metrics.aggregateNegativeRate,
          totalSent: metrics.totalSent,
        },
        deltas: {
          openRateDelta: metrics.aggregateOpenRate - baseline.openRate,
          replyRateDelta: metrics.aggregateReplyRate - baseline.replyRate,
          negativeRateDelta: metrics.aggregateNegativeRate - baseline.negativeRate,
        },
        verdict: metrics.aggregateReplyRate >= baseline.replyRate ? 'improving' : 'declining',
      },
    };
  }

  getSafetyReport() {
    const metrics = hourlyLoop.getCurrentMetrics();
    const pools = banditManager.getAllPools();

    return {
      throttleStatus: safetyMonitor.shouldThrottleCampaign(
        metrics.aggregateBounceRate,
        metrics.aggregateNegativeRate,
        metrics.totalSent > 0 ? metrics.totalUnsubscribed / metrics.totalSent : 0
      ),
      recentTraces: safetyMonitor.getRecentTraces(20),
      banditPoolCount: pools.length,
      totalArms: pools.reduce((sum, p) => sum + p.getAllArms().length, 0),
      frozenArms: pools.reduce((sum, p) => sum + p.getAllArms().filter(a => a.frozen).length, 0),
      cadenceAtLimit: cadenceGovernor.getContactsAtLimit().length,
      cadenceStopped: cadenceGovernor.getStoppedContacts().length,
    };
  }

  // ─────── Safe Mode Controls ───────

  exitSafeMode(operatorId: string = 'operator'): void {
    hourlyLoop.exitSafeMode();
    this.logAction(operatorId, 'SAFE_MODE_EXIT', 'Manually exited safe mode');
  }

  // ─────── Operator Action Log ───────

  getActionLog(limit: number = 50): OperatorAction[] {
    return this.actionLog.slice(-limit);
  }

  private logAction(operatorId: string, action: string, detail: string): void {
    this.actionLog.push({
      action,
      performedAt: new Date(),
      operatorId,
      detail,
    });
    if (this.actionLog.length > this.maxLogSize) {
      this.actionLog = this.actionLog.slice(-500);
    }

    // Persist to decision_traces for durable audit trail
    if (this.db) {
      this.db.query(
        `INSERT INTO decision_traces (trace_type, campaign_id, contact_id, decision, reason, context, created_at)
         VALUES ('operator_action', NULL, NULL, $1, $2, $3, NOW())`,
        [action, detail, JSON.stringify({ operatorId })]
      ).catch(err => logger.warn('Failed to persist operator action', { error: err instanceof Error ? err.message : String(err) }));
    }

    logger.info(`Operator action: ${action} — ${detail} (by ${operatorId})`);
  }
}

// Singleton
export const operatorConsole = new OperatorConsole();
