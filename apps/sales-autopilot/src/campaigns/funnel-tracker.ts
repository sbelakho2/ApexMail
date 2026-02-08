/**
 * Funnel Tracker — Full-funnel instrumentation per contact & account
 *
 * Tracks: delivered → opened → clicked → replied → booked → activated → retained (7d/30d)
 *
 * Key design decisions:
 *   • "Customer activation" = first_successful_send + first_event_received (not just signup)
 *   • "Non-reply" is a censored outcome — soft penalty only after the reply window expires
 *   • Per-channel attribution IDs are attached to every tracked event
 *   • Time windows: reply window (7–14d), activation window (24–72h after signup)
 */

import { createLogger, generateId } from '@apexmail/lib';
import type { Pool } from 'pg';

const logger = createLogger({ name: 'funnel-tracker', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export type FunnelStage =
  | 'delivered'
  | 'opened'
  | 'clicked'
  | 'replied'
  | 'booked'
  | 'activated'
  | 'retained_7d'
  | 'retained_30d';

export interface AttributionIds {
  subjectArmId: string | null;
  valuePropArmId: string | null;
  templateId: string | null;
  toneId: string | null;
  sendTimePolicyId: string | null;
  controlGroup: boolean;
}

export interface FunnelEvent {
  id: string;
  contactId: string;
  accountId: string;
  campaignId: string;
  enrollmentId: string;
  stage: FunnelStage;
  attribution: AttributionIds;
  occurredAt: Date;
  metadata: Record<string, unknown>;
}

export interface TimeWindows {
  /** How many days after send before a non-reply becomes a soft failure */
  replyWindowDays: number;
  /** Min hours after signup for activation to count */
  activationWindowMinHours: number;
  /** Max hours after signup for activation to count */
  activationWindowMaxHours: number;
}

export interface AccountActivation {
  accountId: string;
  firstSuccessfulSend: Date | null;
  firstEventReceived: Date | null;
  isActivated: boolean;
  activatedAt: Date | null;
}

// ────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────

const DEFAULT_TIME_WINDOWS: TimeWindows = {
  replyWindowDays: 10,           // 7–14 day range, we use 10 as default
  activationWindowMinHours: 24,
  activationWindowMaxHours: 72,
};

/** Permanent control group: 10% of outbound runs use baseline everything */
export const CONTROL_GROUP_RATIO = 0.10;

// ────────────────────────────────────────────────────────────────────
// Funnel Tracker
// ────────────────────────────────────────────────────────────────────

export class FunnelTracker {
  private db: Pool | null = null;
  private timeWindows: TimeWindows;

  constructor(timeWindows?: Partial<TimeWindows>) {
    this.timeWindows = { ...DEFAULT_TIME_WINDOWS, ...timeWindows };
  }

  setDb(pool: Pool): void {
    this.db = pool;
    logger.info('FunnelTracker database wired');
  }

  // ─────── Control Group ───────

  /**
   * Determines whether a given contact/run should be assigned to the
   * permanent control group. Uses a deterministic hash so the same
   * contact always gets the same assignment (stable assignment).
   */
  isControlGroup(contactId: string): boolean {
    let hash = 0;
    for (let i = 0; i < contactId.length; i++) {
      hash = ((hash << 5) - hash + contactId.charCodeAt(i)) | 0;
    }
    return (Math.abs(hash) % 100) < (CONTROL_GROUP_RATIO * 100);
  }

  // ─────── Event Recording ───────

  async recordEvent(event: Omit<FunnelEvent, 'id'>): Promise<FunnelEvent> {
    const fullEvent: FunnelEvent = {
      id: generateId('fe'),
      ...event,
    };

    if (this.db) {
      try {
        await this.db.query(
          `INSERT INTO funnel_events (
            id, contact_id, account_id, campaign_id, enrollment_id,
            stage, attribution, occurred_at, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          ON CONFLICT (contact_id, campaign_id, stage) DO NOTHING`,
          [
            fullEvent.id,
            fullEvent.contactId,
            fullEvent.accountId,
            fullEvent.campaignId,
            fullEvent.enrollmentId,
            fullEvent.stage,
            JSON.stringify(fullEvent.attribution),
            fullEvent.occurredAt,
            JSON.stringify(fullEvent.metadata),
          ]
        );
      } catch (err) {
        logger.error('Failed to persist funnel event', {
          eventId: fullEvent.id,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    logger.debug('Funnel event recorded', {
      stage: fullEvent.stage,
      contactId: fullEvent.contactId,
      campaignId: fullEvent.campaignId,
    });

    return fullEvent;
  }

  // ─────── Activation Check ───────

  /**
   * Customer activation = first_successful_send + first_event_received.
   * Both must occur within the activation window after signup.
   */
  async checkAccountActivation(
    accountId: string,
    signupDate: Date
  ): Promise<AccountActivation> {
    const activation: AccountActivation = {
      accountId,
      firstSuccessfulSend: null,
      firstEventReceived: null,
      isActivated: false,
      activatedAt: null,
    };

    if (!this.db) return activation;

    try {
      const result = await this.db.query(
        `SELECT
           MIN(CASE WHEN stage = 'delivered' THEN occurred_at END) AS first_send,
           MIN(CASE WHEN stage IN ('opened','clicked','replied') THEN occurred_at END) AS first_event
         FROM funnel_events
         WHERE account_id = $1`,
        [accountId]
      );

      const row = result.rows[0];
      if (row) {
        activation.firstSuccessfulSend = row.first_send || null;
        activation.firstEventReceived = row.first_event || null;

        if (activation.firstSuccessfulSend && activation.firstEventReceived) {
          // Check that both events fall within the activation window
          const windowStart = new Date(
            signupDate.getTime() + this.timeWindows.activationWindowMinHours * 3600_000
          );
          const windowEnd = new Date(
            signupDate.getTime() + this.timeWindows.activationWindowMaxHours * 3600_000
          );

          const latestEvent = new Date(
            Math.max(
              activation.firstSuccessfulSend.getTime(),
              activation.firstEventReceived.getTime()
            )
          );

          if (latestEvent >= windowStart && latestEvent <= windowEnd) {
            activation.isActivated = true;
            activation.activatedAt = latestEvent;
          } else if (latestEvent < windowStart) {
            // Activated even earlier — still counts
            activation.isActivated = true;
            activation.activatedAt = latestEvent;
          }
        }
      }
    } catch (err) {
      logger.error('Failed to check account activation', {
        accountId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return activation;
  }

  // ─────── Censored Outcomes ───────

  /**
   * Returns contacts whose reply window has expired without a reply.
   * These are "censored" outcomes — not immediate failures.
   * The bandit should apply a soft β penalty, not a hard failure.
   */
  async getCensoredNonReplies(campaignId: string): Promise<Array<{
    contactId: string;
    deliveredAt: Date;
    daysSinceDelivery: number;
  }>> {
    if (!this.db) return [];

    try {
      const result = await this.db.query(
        `SELECT fe.contact_id, fe.occurred_at AS delivered_at,
                EXTRACT(DAY FROM NOW() - fe.occurred_at) AS days_since
         FROM funnel_events fe
         WHERE fe.campaign_id = $1
           AND fe.stage = 'delivered'
           AND EXTRACT(DAY FROM NOW() - fe.occurred_at) >= $2
           AND NOT EXISTS (
             SELECT 1 FROM funnel_events re
             WHERE re.contact_id = fe.contact_id
               AND re.campaign_id = fe.campaign_id
               AND re.stage = 'replied'
           )`,
        [campaignId, this.timeWindows.replyWindowDays]
      );

      return result.rows.map((r: Record<string, unknown>) => ({
        contactId: r.contact_id as string,
        deliveredAt: r.delivered_at as Date,
        daysSinceDelivery: Number(r.days_since),
      }));
    } catch (err) {
      logger.error('Failed to get censored non-replies', {
        campaignId,
        error: err instanceof Error ? err.message : String(err),
      });
      return [];
    }
  }

  // ─────── Funnel Stats ───────

  async getFunnelStats(
    campaignId: string
  ): Promise<Record<FunnelStage, number>> {
    const stats: Record<FunnelStage, number> = {
      delivered: 0,
      opened: 0,
      clicked: 0,
      replied: 0,
      booked: 0,
      activated: 0,
      retained_7d: 0,
      retained_30d: 0,
    };

    if (!this.db) return stats;

    try {
      const result = await this.db.query(
        `SELECT stage, COUNT(DISTINCT contact_id) AS cnt
         FROM funnel_events
         WHERE campaign_id = $1
         GROUP BY stage`,
        [campaignId]
      );

      for (const row of result.rows) {
        const stage = row.stage as FunnelStage;
        if (stage in stats) {
          stats[stage] = Number(row.cnt);
        }
      }
    } catch (err) {
      logger.error('Failed to get funnel stats', {
        campaignId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return stats;
  }

  /**
   * Get per-account funnel for a list of accounts
   */
  async getAccountFunnels(
    accountIds: string[]
  ): Promise<Map<string, Record<FunnelStage, number>>> {
    const result = new Map<string, Record<FunnelStage, number>>();
    if (!this.db || accountIds.length === 0) return result;

    try {
      const rows = await this.db.query(
        `SELECT account_id, stage, COUNT(DISTINCT contact_id) AS cnt
         FROM funnel_events
         WHERE account_id = ANY($1)
         GROUP BY account_id, stage`,
        [accountIds]
      );

      for (const row of rows.rows) {
        const acctId = row.account_id as string;
        if (!result.has(acctId)) {
          result.set(acctId, {
            delivered: 0, opened: 0, clicked: 0, replied: 0,
            booked: 0, activated: 0, retained_7d: 0, retained_30d: 0,
          });
        }
        const stats = result.get(acctId)!;
        const stage = row.stage as FunnelStage;
        if (stage in stats) {
          stats[stage] = Number(row.cnt);
        }
      }
    } catch (err) {
      logger.error('Failed to get account funnels', {
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return result;
  }
}

// Singleton
export const funnelTracker = new FunnelTracker();
