/**
 * Calendar Invite Support Service
 * 
 * Handles iCalendar (ICS) attachments and calendar invite generation
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { CALENDAR_CONTENT_TYPES } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum CalendarMethod {
  REQUEST = 'REQUEST',
  REPLY = 'REPLY',
  CANCEL = 'CANCEL',
  REFRESH = 'REFRESH',
  COUNTER = 'COUNTER',
  DECLINECOUNTER = 'DECLINECOUNTER',
  ADD = 'ADD',
  PUBLISH = 'PUBLISH',
}

export enum CalendarStatus {
  TENTATIVE = 'TENTATIVE',
  CONFIRMED = 'CONFIRMED',
  CANCELLED = 'CANCELLED',
}

export enum AttendeeRole {
  CHAIR = 'CHAIR',
  REQ_PARTICIPANT = 'REQ-PARTICIPANT',
  OPT_PARTICIPANT = 'OPT-PARTICIPANT',
  NON_PARTICIPANT = 'NON-PARTICIPANT',
}

export enum AttendeePartStat {
  NEEDS_ACTION = 'NEEDS-ACTION',
  ACCEPTED = 'ACCEPTED',
  DECLINED = 'DECLINED',
  TENTATIVE = 'TENTATIVE',
  DELEGATED = 'DELEGATED',
}

export interface Attendee {
  email: string;
  name?: string;
  role: AttendeeRole;
  partStat: AttendeePartStat;
  rsvp: boolean;
}

export interface Organizer {
  email: string;
  name?: string;
}

export interface CalendarEvent {
  uid: string;
  summary: string;
  description?: string;
  location?: string;
  start: Date;
  end: Date;
  allDay: boolean;
  timezone?: string;
  organizer: Organizer;
  attendees: Attendee[];
  method: CalendarMethod;
  status: CalendarStatus;
  sequence: number;
  created: Date;
  lastModified: Date;
  url?: string;
  categories?: string[];
  priority?: number;
  transp?: 'OPAQUE' | 'TRANSPARENT';
  recurrence?: RecurrenceRule;
}

export interface RecurrenceRule {
  freq: 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'YEARLY';
  interval?: number;
  count?: number;
  until?: Date;
  byDay?: string[];
  byMonth?: number[];
  byMonthDay?: number[];
}

export interface CalendarInvite {
  event: CalendarEvent;
  icsContent: string;
  htmlPreview: string;
}

export interface ParsedCalendar {
  events: CalendarEvent[];
  method: CalendarMethod;
  productId: string;
}

/**
 * Calendar Service for handling iCalendar invites
 */
export class CalendarService {
  private pool: Pool;

  constructor(pool: Pool, _redis: Redis) {
    this.pool = pool;
    void _redis; // Reserved for future caching
  }

  /**
   * Create a calendar invite
   */
  async createInvite(event: Omit<CalendarEvent, 'uid' | 'created' | 'lastModified' | 'sequence'>): Promise<Result<CalendarInvite>> {
    try {
      const fullEvent: CalendarEvent = {
        ...event,
        uid: `${uuidv4()}@apexmail.ee`,
        created: new Date(),
        lastModified: new Date(),
        sequence: 0,
      };

      const icsContent = this.generateICS(fullEvent);
      const htmlPreview = this.generateHTMLPreview(fullEvent);

      return {
        ok: true,
        value: {
          event: fullEvent,
          icsContent,
          htmlPreview,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Generate ICS content
   */
  generateICS(event: CalendarEvent): string {
    const lines: string[] = [];

    // Calendar header
    lines.push('BEGIN:VCALENDAR');
    lines.push('VERSION:2.0');
    lines.push('PRODID:-//ApexMail//Calendar//EN');
    lines.push('CALSCALE:GREGORIAN');
    lines.push(`METHOD:${event.method}`);

    // Timezone definition (if specified)
    if (event.timezone) {
      lines.push(...this.generateTimezoneComponent(event.timezone));
    }

    // Event
    lines.push('BEGIN:VEVENT');
    lines.push(`UID:${event.uid}`);
    lines.push(`DTSTAMP:${this.formatDate(new Date())}`);
    
    if (event.allDay) {
      lines.push(`DTSTART;VALUE=DATE:${this.formatDateOnly(event.start)}`);
      lines.push(`DTEND;VALUE=DATE:${this.formatDateOnly(event.end)}`);
    } else if (event.timezone) {
      lines.push(`DTSTART;TZID=${event.timezone}:${this.formatDateLocal(event.start)}`);
      lines.push(`DTEND;TZID=${event.timezone}:${this.formatDateLocal(event.end)}`);
    } else {
      lines.push(`DTSTART:${this.formatDate(event.start)}`);
      lines.push(`DTEND:${this.formatDate(event.end)}`);
    }

    lines.push(`SUMMARY:${this.escapeICS(event.summary)}`);
    
    if (event.description) {
      lines.push(`DESCRIPTION:${this.escapeICS(event.description)}`);
    }

    if (event.location) {
      lines.push(`LOCATION:${this.escapeICS(event.location)}`);
    }

    lines.push(`STATUS:${event.status}`);
    lines.push(`SEQUENCE:${event.sequence}`);
    lines.push(`CREATED:${this.formatDate(event.created)}`);
    lines.push(`LAST-MODIFIED:${this.formatDate(event.lastModified)}`);

    if (event.url) {
      // FIX-500-032: Validate URL scheme to prevent javascript: injection in ICS
      try {
        const parsed = new URL(event.url);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          lines.push(`URL:${event.url}`);
        }
      } catch {
        // Invalid URL — skip silently
      }
    }

    if (event.categories && event.categories.length > 0) {
      lines.push(`CATEGORIES:${event.categories.join(',')}`);
    }

    if (event.priority !== undefined) {
      lines.push(`PRIORITY:${event.priority}`);
    }

    if (event.transp) {
      lines.push(`TRANSP:${event.transp}`);
    }

    // Organizer
    const organizerParams = event.organizer.name 
      ? `;CN=${this.escapeICS(event.organizer.name)}` 
      : '';
    lines.push(`ORGANIZER${organizerParams}:mailto:${event.organizer.email}`);

    // Attendees
    for (const attendee of event.attendees) {
      const attendeeParams = [
        attendee.name ? `CN=${this.escapeICS(attendee.name)}` : null,
        `ROLE=${attendee.role}`,
        `PARTSTAT=${attendee.partStat}`,
        `RSVP=${attendee.rsvp ? 'TRUE' : 'FALSE'}`,
      ].filter(Boolean).join(';');
      
      lines.push(`ATTENDEE;${attendeeParams}:mailto:${attendee.email}`);
    }

    // Recurrence rule
    if (event.recurrence) {
      lines.push(this.generateRRule(event.recurrence));
    }

    lines.push('END:VEVENT');
    lines.push('END:VCALENDAR');

    // Fold lines at 75 characters
    return this.foldLines(lines.join('\r\n'));
  }

  /**
   * Generate HTML preview for calendar invite
   */
  generateHTMLPreview(event: CalendarEvent): string {
    const formatDateTime = (date: Date, allDay: boolean): string => {
      if (allDay) {
        return date.toLocaleDateString('en-US', { 
          weekday: 'long', 
          year: 'numeric', 
          month: 'long', 
          day: 'numeric' 
        });
      }
      return date.toLocaleString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZoneName: 'short',
      });
    };

    const attendeesList = event.attendees.map(a => {
      const status = {
        [AttendeePartStat.ACCEPTED]: '✓',
        [AttendeePartStat.DECLINED]: '✗',
        [AttendeePartStat.TENTATIVE]: '?',
        [AttendeePartStat.NEEDS_ACTION]: '○',
        [AttendeePartStat.DELEGATED]: '→',
      }[a.partStat];
      return `<li>${status} ${a.name || a.email} ${a.role === AttendeeRole.OPT_PARTICIPANT ? '(optional)' : ''}</li>`;
    }).join('');

    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    .calendar-invite {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 18px;
    }
    .calendar-header {
      background: #2563eb;
      color: white;
      padding: 15px;
      border-radius: 18px 18px 0 0;
      text-align: center;
    }
    .calendar-body {
      background: white;
      padding: 20px;
      border-radius: 0 0 18px 18px;
    }
    .calendar-title {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.01em;
    }
    .calendar-status {
      font-size: 12px;
      opacity: 0.9;
      margin-top: 5px;
      font-weight: 500;
    }
    .calendar-detail {
      margin: 15px 0;
      padding: 12px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
    }
    .calendar-detail-label {
      font-size: 10px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 700;
    }
    .calendar-detail-value {
      font-size: 14px;
      margin-top: 4px;
      color: #0f172a;
      font-weight: 500;
    }
    .calendar-attendees {
      margin: 15px 0;
    }
    .calendar-attendees ul {
      list-style: none;
      padding: 0;
      margin: 5px 0 0 0;
    }
    .calendar-attendees li {
      padding: 6px 0;
      font-size: 14px;
      color: #334155;
      border-bottom: 1px solid #f1f5f9;
    }
    .calendar-actions {
      display: flex;
      gap: 12px;
      margin-top: 24px;
    }
    .calendar-btn {
      flex: 1;
      padding: 12px;
      border: none;
      border-radius: 12px;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      text-align: center;
    }
    .calendar-btn-accept {
      background: #16a34a;
      color: white;
    }
    .calendar-btn-maybe {
      background: #f59e0b;
      color: white;
    }
    .calendar-btn-decline {
      background: #dc2626;
      color: white;
    }
  </style>
</head>
<body>
  <div class="calendar-invite">
    <div class="calendar-header">
      <h1 class="calendar-title">${this.escapeHTML(event.summary)}</h1>
      <div class="calendar-status">
        ${event.method === CalendarMethod.REQUEST ? 'Calendar Invitation' : 
          event.method === CalendarMethod.CANCEL ? 'Event Cancelled' : 
          'Calendar Update'}
      </div>
    </div>
    <div class="calendar-body">
      <div class="calendar-detail">
        <div class="calendar-detail-label">When</div>
        <div class="calendar-detail-value">
          ${formatDateTime(event.start, event.allDay)}
          ${!event.allDay ? ' – ' + formatDateTime(event.end, false) : ''}
        </div>
      </div>
      ${event.location ? `
      <div class="calendar-detail">
        <div class="calendar-detail-label">Where</div>
        <div class="calendar-detail-value">${this.escapeHTML(event.location)}</div>
      </div>
      ` : ''}
      ${event.description ? `
      <div class="calendar-detail">
        <div class="calendar-detail-label">Description</div>
        <div class="calendar-detail-value">${this.escapeHTML(event.description)}</div>
      </div>
      ` : ''}
      <div class="calendar-detail">
        <div class="calendar-detail-label">Organizer</div>
        <div class="calendar-detail-value">${event.organizer.name || event.organizer.email}</div>
      </div>
      ${event.attendees.length > 0 ? `
      <div class="calendar-attendees">
        <div class="calendar-detail-label">Attendees</div>
        <ul>${attendeesList}</ul>
      </div>
      ` : ''}
      ${event.method === CalendarMethod.REQUEST ? `
      <div class="calendar-actions">
        <a href="mailto:${event.organizer.email}?subject=Accepted: ${encodeURIComponent(event.summary)}" class="calendar-btn calendar-btn-accept">Accept</a>
        <a href="mailto:${event.organizer.email}?subject=Tentative: ${encodeURIComponent(event.summary)}" class="calendar-btn calendar-btn-maybe">Maybe</a>
        <a href="mailto:${event.organizer.email}?subject=Declined: ${encodeURIComponent(event.summary)}" class="calendar-btn calendar-btn-decline">Decline</a>
      </div>
      ` : ''}
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * Parse ICS content
   */
  parseICS(icsContent: string): Result<ParsedCalendar> {
    try {
      // Unfold lines
      const content = icsContent.replace(/\r\n[ \t]/g, '');
      const lines = content.split(/\r\n|\n|\r/);

      let method = CalendarMethod.PUBLISH;
      let productId = 'Unknown';
      const events: CalendarEvent[] = [];
      let currentEvent: Partial<CalendarEvent> | null = null;

      for (const line of lines) {
        const colonIndex = line.indexOf(':');
        if (colonIndex === -1) continue;

        const key = line.substring(0, colonIndex);
        const value = line.substring(colonIndex + 1);
        const [prop, ...params] = key.split(';');

        switch ((prop ?? '').toUpperCase()) {
          case 'METHOD':
            method = value as CalendarMethod;
            break;
          case 'PRODID':
            productId = value;
            break;
          case 'BEGIN':
            if (value === 'VEVENT') {
              currentEvent = {
                attendees: [],
                status: CalendarStatus.CONFIRMED,
                sequence: 0,
                method,
              };
            }
            break;
          case 'END':
            if (value === 'VEVENT' && currentEvent) {
              events.push(currentEvent as CalendarEvent);
              currentEvent = null;
            }
            break;
          case 'UID':
            if (currentEvent) currentEvent.uid = value;
            break;
          case 'SUMMARY':
            if (currentEvent) currentEvent.summary = this.unescapeICS(value);
            break;
          case 'DESCRIPTION':
            if (currentEvent) currentEvent.description = this.unescapeICS(value);
            break;
          case 'LOCATION':
            if (currentEvent) currentEvent.location = this.unescapeICS(value);
            break;
          case 'DTSTART':
            if (currentEvent) {
              currentEvent.start = this.parseICSDate(value, params);
              currentEvent.allDay = params.some(p => p.includes('DATE'));
            }
            break;
          case 'DTEND':
            if (currentEvent) currentEvent.end = this.parseICSDate(value, params);
            break;
          case 'STATUS':
            if (currentEvent) currentEvent.status = value as CalendarStatus;
            break;
          case 'SEQUENCE':
            if (currentEvent) currentEvent.sequence = parseInt(value, 10);
            break;
          case 'CREATED':
            if (currentEvent) currentEvent.created = this.parseICSDate(value, []);
            break;
          case 'LAST-MODIFIED':
            if (currentEvent) currentEvent.lastModified = this.parseICSDate(value, []);
            break;
          case 'ORGANIZER':
            if (currentEvent) {
              const orgEmail = value.replace('mailto:', '');
              const orgName = this.getParam(params, 'CN');
              currentEvent.organizer = { email: orgEmail, name: orgName };
            }
            break;
          case 'ATTENDEE':
            if (currentEvent) {
              const attEmail = value.replace('mailto:', '');
              const attName = this.getParam(params, 'CN');
              const role = this.getParam(params, 'ROLE') as AttendeeRole || AttendeeRole.REQ_PARTICIPANT;
              const partStat = this.getParam(params, 'PARTSTAT') as AttendeePartStat || AttendeePartStat.NEEDS_ACTION;
              const rsvp = this.getParam(params, 'RSVP') === 'TRUE';
              currentEvent.attendees!.push({ email: attEmail, name: attName, role, partStat, rsvp });
            }
            break;
          case 'URL':
            if (currentEvent) currentEvent.url = value;
            break;
          case 'CATEGORIES':
            if (currentEvent) currentEvent.categories = value.split(',');
            break;
        }
      }

      return {
        ok: true,
        value: {
          events,
          method,
          productId,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Check if content type is calendar
   */
  isCalendarContentType(contentType: string): boolean {
    return CALENDAR_CONTENT_TYPES.some(type => 
      contentType.toLowerCase().includes(type.toLowerCase())
    );
  }

  /**
   * Generate RRULE for recurrence
   */
  private generateRRule(rule: RecurrenceRule): string {
    const parts = [`FREQ=${rule.freq}`];

    if (rule.interval && rule.interval > 1) {
      parts.push(`INTERVAL=${rule.interval}`);
    }

    if (rule.count) {
      parts.push(`COUNT=${rule.count}`);
    }

    if (rule.until) {
      parts.push(`UNTIL=${this.formatDate(rule.until)}`);
    }

    if (rule.byDay && rule.byDay.length > 0) {
      parts.push(`BYDAY=${rule.byDay.join(',')}`);
    }

    if (rule.byMonth && rule.byMonth.length > 0) {
      parts.push(`BYMONTH=${rule.byMonth.join(',')}`);
    }

    if (rule.byMonthDay && rule.byMonthDay.length > 0) {
      parts.push(`BYMONTHDAY=${rule.byMonthDay.join(',')}`);
    }

    return `RRULE:${parts.join(';')}`;
  }

  /**
   * Generate timezone component
   */
  private generateTimezoneComponent(timezone: string): string[] {
    const tzid = this.resolveTimezone(timezone);
    const standardDate = new Date(Date.UTC(new Date().getUTCFullYear(), 0, 1, 12, 0, 0));
    const daylightDate = new Date(Date.UTC(new Date().getUTCFullYear(), 6, 1, 12, 0, 0));

    const standardOffset = this.getTimezoneOffsetString(standardDate, tzid);
    const daylightOffset = this.getTimezoneOffsetString(daylightDate, tzid);
    const hasDst = standardOffset !== daylightOffset;

    const [offsetFrom, offsetTo] = hasDst
      ? (Math.abs(parseInt(standardOffset, 10)) > Math.abs(parseInt(daylightOffset, 10))
          ? [daylightOffset, standardOffset]
          : [standardOffset, daylightOffset])
      : [standardOffset, standardOffset];

    return [
      'BEGIN:VTIMEZONE',
      `TZID:${tzid}`,
      'BEGIN:STANDARD',
      'DTSTART:19710101T030000',
      `TZOFFSETFROM:${offsetFrom}`,
      `TZOFFSETTO:${offsetTo}`,
      'END:STANDARD',
      ...(hasDst
        ? [
            'BEGIN:DAYLIGHT',
            'DTSTART:19710101T020000',
            `TZOFFSETFROM:${offsetTo}`,
            `TZOFFSETTO:${offsetFrom}`,
            'END:DAYLIGHT',
          ]
        : []),
      'END:VTIMEZONE',
    ];
  }

  private resolveTimezone(timezone: string): string {
    try {
      Intl.DateTimeFormat('en-US', { timeZone: timezone });
      return timezone;
    } catch {
      return 'UTC';
    }
  }

  private getTimezoneOffsetString(date: Date, timezone: string): string {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });

    const parts = formatter.formatToParts(date);
    const byType = new Map(parts.map((part) => [part.type, part.value]));

    const localYear = parseInt(byType.get('year') ?? '0', 10);
    const localMonth = parseInt(byType.get('month') ?? '1', 10);
    const localDay = parseInt(byType.get('day') ?? '1', 10);
    const localHour = parseInt(byType.get('hour') ?? '0', 10);
    const localMinute = parseInt(byType.get('minute') ?? '0', 10);
    const localSecond = parseInt(byType.get('second') ?? '0', 10);

    const utcMillis = Date.UTC(localYear, localMonth - 1, localDay, localHour, localMinute, localSecond);
    const offsetMinutes = Math.round((utcMillis - date.getTime()) / 60000);
    const sign = offsetMinutes >= 0 ? '+' : '-';
    const absolute = Math.abs(offsetMinutes);
    const hours = Math.floor(absolute / 60).toString().padStart(2, '0');
    const minutes = Math.floor(absolute % 60).toString().padStart(2, '0');

    return `${sign}${hours}${minutes}`;
  }

  /**
   * Format date to ICS format
   */
  private formatDate(date: Date): string {
    return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  }

  /**
   * Format date only (no time)
   */
  private formatDateOnly(date: Date): string {
    return date.toISOString().slice(0, 10).replace(/-/g, '');
  }

  /**
   * Format date for local time
   */
  private formatDateLocal(date: Date): string {
    return this.formatDate(date).replace('Z', '');
  }

  /**
   * Parse ICS date format
   */
  private parseICSDate(value: string, params: string[]): Date {
    // Handle date-only format (YYYYMMDD)
    if (params.some(p => p.includes('DATE')) || value.length === 8) {
      const year = parseInt(value.substring(0, 4), 10);
      const month = parseInt(value.substring(4, 6), 10) - 1;
      const day = parseInt(value.substring(6, 8), 10);
      return new Date(year, month, day);
    }

    // Handle datetime format (YYYYMMDDTHHMMSS or YYYYMMDDTHHMMSSZ)
    const year = parseInt(value.substring(0, 4), 10);
    const month = parseInt(value.substring(4, 6), 10) - 1;
    const day = parseInt(value.substring(6, 8), 10);
    const hour = parseInt(value.substring(9, 11), 10);
    const minute = parseInt(value.substring(11, 13), 10);
    const second = parseInt(value.substring(13, 15), 10);

    if (value.endsWith('Z')) {
      return new Date(Date.UTC(year, month, day, hour, minute, second));
    }

    return new Date(year, month, day, hour, minute, second);
  }

  /**
   * Escape ICS special characters
   */
  private escapeICS(text: string): string {
    return text
      .replace(/\\/g, '\\\\')
      .replace(/;/g, '\\;')
      .replace(/,/g, '\\,')
      .replace(/\n/g, '\\n');
  }

  /**
   * Unescape ICS special characters
   */
  private unescapeICS(text: string): string {
    return text
      .replace(/\\n/g, '\n')
      .replace(/\\,/g, ',')
      .replace(/\\;/g, ';')
      .replace(/\\\\/g, '\\');
  }

  /**
   * Escape HTML special characters
   */
  private escapeHTML(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get parameter value from ICS params
   */
  private getParam(params: string[], name: string): string | undefined {
    for (const param of params) {
      const [key, value] = param.split('=');
      if (key === name) {
        return value?.replace(/^"(.*)"$/, '$1');
      }
    }
    return undefined;
  }

  /**
   * Fold lines at 75 characters per RFC 5545
   */
  private foldLines(content: string): string {
    const lines = content.split('\r\n');
    const foldedLines: string[] = [];

    for (const line of lines) {
      if (line.length <= 75) {
        foldedLines.push(line);
      } else {
        let remaining = line;
        let first = true;
        while (remaining.length > 0) {
          const maxLen = first ? 75 : 74;
          const chunk = remaining.substring(0, maxLen);
          remaining = remaining.substring(maxLen);
          foldedLines.push(first ? chunk : ' ' + chunk);
          first = false;
        }
      }
    }

    return foldedLines.join('\r\n');
  }

  /**
   * Store calendar event for tracking
   */
  async storeEvent(messageId: string, event: CalendarEvent): Promise<Result<void>> {
    try {
      await this.pool.query(`
        INSERT INTO edge_calendar_events (
          message_id, uid, summary, organizer_email, start_time, end_time,
          location, method, status, attendee_count, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      `, [
        messageId,
        event.uid,
        event.summary,
        event.organizer.email,
        event.start,
        event.end,
        event.location,
        event.method,
        event.status,
        event.attendees.length,
      ]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }
}
