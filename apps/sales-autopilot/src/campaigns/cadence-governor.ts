/**
 * Cadence Governor — Protect leads from over-contacting
 *
 * Rules:
 *   • Max touches per contact per 7/14 days (configurable)
 *   • Automatic stop on reply, bounce, complaint, unsubscribe
 *   • Send-time bounded to safe window (local 9am–4pm)
 *   • Time zone inference + fallback to UTC business hours
 *   • Send-time bandit updates only on reply/positive actions (not opens)
 */

import { createLogger } from '@apexmail/lib';
import type { Pool } from 'pg';

const logger = createLogger({ name: 'cadence-governor', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface CadenceConfig {
  maxTouchesPer7Days: number;
  maxTouchesPer14Days: number;
  sendWindowStart: number;  // local hour, e.g. 9
  sendWindowEnd: number;    // local hour, e.g. 16
  defaultTimezone: string;
  stopOnEvents: StopEvent[];
}

export type StopEvent = 'reply' | 'bounce' | 'complaint' | 'unsubscribe';

export interface ContactTouchHistory {
  contactId: string;
  touches: TouchRecord[];
  stopped: boolean;
  stopReason: StopEvent | null;
  stoppedAt: Date | null;
  timezone: string | null;
  inferredTimezone: string | null;
}

export interface TouchRecord {
  sentAt: Date;
  campaignId: string;
  enrollmentId: string;
  stepId: string;
}

export interface SendTimeDecision {
  allowed: boolean;
  reason: string;
  suggestedTime: Date | null;
  contactTimezone: string;
}

// ────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────

const DEFAULT_CADENCE_CONFIG: CadenceConfig = {
  maxTouchesPer7Days: 3,
  maxTouchesPer14Days: 5,
  sendWindowStart: 9,
  sendWindowEnd: 16,
  defaultTimezone: 'UTC',
  stopOnEvents: ['reply', 'bounce', 'complaint', 'unsubscribe'],
};

// ────────────────────────────────────────────────────────────────────
// Time Zone Data (common US/EU/APAC)
// ────────────────────────────────────────────────────────────────────

const COUNTRY_TIMEZONES: Record<string, string> = {
  US: 'America/New_York',
  CA: 'America/Toronto',
  GB: 'Europe/London',
  UK: 'Europe/London',
  DE: 'Europe/Berlin',
  FR: 'Europe/Paris',
  NL: 'Europe/Amsterdam',
  EE: 'Europe/Tallinn',
  AU: 'Australia/Sydney',
  JP: 'Asia/Tokyo',
  SG: 'Asia/Singapore',
  IN: 'Asia/Kolkata',
  IL: 'Asia/Jerusalem',
  BR: 'America/Sao_Paulo',
  MX: 'America/Mexico_City',
  SE: 'Europe/Stockholm',
  NO: 'Europe/Oslo',
  FI: 'Europe/Helsinki',
  DK: 'Europe/Copenhagen',
  IE: 'Europe/Dublin',
  NZ: 'Pacific/Auckland',
};

// ────────────────────────────────────────────────────────────────────
// Governor
// ────────────────────────────────────────────────────────────────────

export class CadenceGovernor {
  private config: CadenceConfig;
  private histories: Map<string, ContactTouchHistory> = new Map();
  private db: Pool | null = null;

  constructor(config?: Partial<CadenceConfig>) {
    this.config = { ...DEFAULT_CADENCE_CONFIG, ...config };
  }

  setDb(pool: Pool): void {
    this.db = pool;
    logger.info('CadenceGovernor database wired');
  }

  /**
   * Hydrate touch histories and stop signals from Postgres.
   * Called once at startup after setDb().
   */
  async hydrateFromDb(): Promise<void> {
    if (!this.db) return;
    try {
      // Load recent cadence touches (last 14 days is sufficient for governor checks)
      const touchRows = await this.db.query(
        `SELECT contact_id, campaign_id, step_id, sent_at, timezone
         FROM contact_cadence WHERE sent_at > NOW() - INTERVAL '14 days'
         ORDER BY sent_at`
      );
      for (const row of touchRows.rows) {
        const history = this.getOrCreateHistory(row.contact_id as string);
        history.touches.push({
          sentAt: new Date(row.sent_at as string),
          campaignId: row.campaign_id as string,
          enrollmentId: '',
          stepId: row.step_id as string,
        });
        if (row.timezone) history.inferredTimezone = row.timezone as string;
      }

      // Load stop signals
      const stopRows = await this.db.query(
        `SELECT contact_id, campaign_id, reason, stopped_at FROM contact_stop_signals`
      );
      for (const row of stopRows.rows) {
        const history = this.getOrCreateHistory(row.contact_id as string);
        history.stopped = true;
        history.stopReason = row.reason as StopEvent;
        history.stoppedAt = new Date(row.stopped_at as string);
      }

      logger.info('CadenceGovernor hydrated from DB', {
        contacts: this.histories.size,
        touches: touchRows.rows.length,
        stops: stopRows.rows.length,
      });
    } catch (err) {
      logger.error('Failed to hydrate cadence from DB', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ─────── Touch Recording ───────

  recordTouch(
    contactId: string,
    campaignId: string,
    enrollmentId: string,
    stepId: string
  ): void {
    const history = this.getOrCreateHistory(contactId);
    const now = new Date();
    history.touches.push({
      sentAt: now,
      campaignId,
      enrollmentId,
      stepId,
    });

    // Persist to DB
    if (this.db) {
      const tz = this.resolveTimezone(history);
      const localHour = this.getLocalHour(tz);
      this.db.query(
        `INSERT INTO contact_cadence (contact_id, campaign_id, step_id, channel, sent_at, local_hour, timezone)
         VALUES ($1, $2, $3, 'email', $4, $5, $6)`,
        [contactId, campaignId, stepId, now, localHour, tz]
      ).catch(err => logger.warn('Failed to persist cadence touch', { contactId, error: err instanceof Error ? err.message : String(err) }));
    }

    logger.debug('Touch recorded', {
      contactId,
      totalTouches: history.touches.length,
      last7d: this.countRecentTouches(history, 7),
    });
  }

  // ─────── Stop Events ───────

  recordStopEvent(contactId: string, event: StopEvent): void {
    if (!this.config.stopOnEvents.includes(event)) return;

    const history = this.getOrCreateHistory(contactId);
    history.stopped = true;
    history.stopReason = event;
    history.stoppedAt = new Date();

    // Persist to DB
    if (this.db) {
      this.db.query(
        `INSERT INTO contact_stop_signals (contact_id, campaign_id, reason, stopped_at)
         VALUES ($1, '', $2, $3)
         ON CONFLICT (contact_id, campaign_id, reason) DO NOTHING`,
        [contactId, event, history.stoppedAt]
      ).catch(err => logger.warn('Failed to persist stop signal', { contactId, error: err instanceof Error ? err.message : String(err) }));
    }

    logger.info('Contact stopped due to event', { contactId, event });
  }

  // ─────── Can Send Check ───────

  canSend(contactId: string): SendTimeDecision {
    const history = this.getOrCreateHistory(contactId);

    // Check stop conditions
    if (history.stopped) {
      return {
        allowed: false,
        reason: `Contact stopped: ${history.stopReason}`,
        suggestedTime: null,
        contactTimezone: this.resolveTimezone(history),
      };
    }

    // Check cadence limits
    const last7d = this.countRecentTouches(history, 7);
    if (last7d >= this.config.maxTouchesPer7Days) {
      return {
        allowed: false,
        reason: `Cadence limit: ${last7d}/${this.config.maxTouchesPer7Days} touches in last 7 days`,
        suggestedTime: this.nextAvailableSlot(history, 7),
        contactTimezone: this.resolveTimezone(history),
      };
    }

    const last14d = this.countRecentTouches(history, 14);
    if (last14d >= this.config.maxTouchesPer14Days) {
      return {
        allowed: false,
        reason: `Cadence limit: ${last14d}/${this.config.maxTouchesPer14Days} touches in last 14 days`,
        suggestedTime: this.nextAvailableSlot(history, 14),
        contactTimezone: this.resolveTimezone(history),
      };
    }

    // Check send window
    const tz = this.resolveTimezone(history);
    const localHour = this.getLocalHour(tz);

    if (localHour < this.config.sendWindowStart || localHour >= this.config.sendWindowEnd) {
      const nextWindowStart = this.nextSendWindowStart(tz);
      return {
        allowed: false,
        reason: `Outside send window: ${localHour}:00 local time (window: ${this.config.sendWindowStart}:00–${this.config.sendWindowEnd}:00)`,
        suggestedTime: nextWindowStart,
        contactTimezone: tz,
      };
    }

    return {
      allowed: true,
      reason: 'OK',
      suggestedTime: null,
      contactTimezone: tz,
    };
  }

  // ─────── Time Zone Inference ───────

  setContactTimezone(contactId: string, timezone: string): void {
    const history = this.getOrCreateHistory(contactId);
    history.timezone = timezone;
  }

  inferTimezone(contactId: string, countryCode: string | null, companyDomain?: string): void {
    const history = this.getOrCreateHistory(contactId);

    if (countryCode) {
      const tz = COUNTRY_TIMEZONES[countryCode.toUpperCase()];
      if (tz) {
        history.inferredTimezone = tz;
        logger.debug('Timezone inferred from country', { contactId, countryCode, timezone: tz });
        return;
      }
    }

    // TLD-based inference as fallback
    if (companyDomain) {
      const tld = companyDomain.split('.').pop()?.toUpperCase();
      if (tld) {
        const tz = COUNTRY_TIMEZONES[tld];
        if (tz) {
          history.inferredTimezone = tz;
          return;
        }
      }
    }

    // Default fallback
    history.inferredTimezone = this.config.defaultTimezone;
  }

  // ─────── Helpers ───────

  private getOrCreateHistory(contactId: string): ContactTouchHistory {
    let history = this.histories.get(contactId);
    if (!history) {
      history = {
        contactId,
        touches: [],
        stopped: false,
        stopReason: null,
        stoppedAt: null,
        timezone: null,
        inferredTimezone: null,
      };
      this.histories.set(contactId, history);
    }
    return history;
  }

  private countRecentTouches(history: ContactTouchHistory, days: number): number {
    const cutoff = new Date(Date.now() - days * 24 * 3600_000);
    return history.touches.filter(t => t.sentAt >= cutoff).length;
  }

  private resolveTimezone(history: ContactTouchHistory): string {
    return history.timezone || history.inferredTimezone || this.config.defaultTimezone;
  }

  private getLocalHour(timezone: string): number {
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        hour: 'numeric',
        hour12: false,
      });
      return parseInt(formatter.format(new Date()), 10);
    } catch {
      // Invalid timezone — fall back to UTC
      return new Date().getUTCHours();
    }
  }

  private nextSendWindowStart(timezone: string): Date {
    const now = new Date();
    const localHour = this.getLocalHour(timezone);

    // If we're past the send window today, next window is tomorrow
    const hoursUntilWindow = localHour >= this.config.sendWindowEnd
      ? (24 - localHour + this.config.sendWindowStart)
      : (this.config.sendWindowStart - localHour);

    return new Date(now.getTime() + hoursUntilWindow * 3600_000);
  }

  private nextAvailableSlot(history: ContactTouchHistory, windowDays: number): Date {
    // Find the oldest touch in the window and calculate when it'll expire
    const cutoff = new Date(Date.now() - windowDays * 24 * 3600_000);
    const touchesInWindow = history.touches
      .filter(t => t.sentAt >= cutoff)
      .sort((a, b) => a.sentAt.getTime() - b.sentAt.getTime());

    if (touchesInWindow.length > 0 && touchesInWindow[0]) {
      // When the oldest touch in the window expires
      return new Date(touchesInWindow[0].sentAt.getTime() + windowDays * 24 * 3600_000);
    }

    return new Date(Date.now() + 24 * 3600_000); // fallback: tomorrow
  }

  // ─────── Bulk Operations ───────

  getContactsAtLimit(): string[] {
    const result: string[] = [];
    for (const [id, history] of this.histories) {
      if (history.stopped) continue;
      const last7d = this.countRecentTouches(history, 7);
      if (last7d >= this.config.maxTouchesPer7Days) {
        result.push(id);
      }
    }
    return result;
  }

  getStoppedContacts(): Array<{ contactId: string; reason: StopEvent | null; stoppedAt: Date | null }> {
    const result: Array<{ contactId: string; reason: StopEvent | null; stoppedAt: Date | null }> = [];
    for (const history of this.histories.values()) {
      if (history.stopped) {
        result.push({
          contactId: history.contactId,
          reason: history.stopReason,
          stoppedAt: history.stoppedAt,
        });
      }
    }
    return result;
  }
}

// Singleton
export const cadenceGovernor = new CadenceGovernor();
