/**
 * Calendar Invite Support Service
 * 
 * Handles iCalendar (ICS) attachments and calendar invite generation
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
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
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
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
      lines.push(`URL:${event.url}`);
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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background: #f8f9fa;
      border-radius: 8px;
    }
    .calendar-header {
      background: #4285f4;
      color: white;
      padding: 15px;
      border-radius: 8px 8px 0 0;
      text-align: center;
    }
    .calendar-body {
      background: white;
      padding: 20px;
      border-radius: 0 0 8px 8px;
    }
    .calendar-title {
      font-size: 20px;
      font-weight: 600;
      margin: 0;
    }
    .calendar-status {
      font-size: 12px;
      opacity: 0.9;
      margin-top: 5px;
    }
    .calendar-detail {
      margin: 15px 0;
      padding: 10px;
      background: #f8f9fa;
      border-radius: 4px;
    }
    .calendar-detail-label {
      font-size: 12px;
      color: #666;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .calendar-detail-value {
      font-size: 14px;
      margin-top: 4px;
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
      padding: 5px 0;
      font-size: 14px;
    }
    .calendar-actions {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }
    .calendar-btn {
      flex: 1;
      padding: 12px;
      border: none;
      border-radius: 4px;
      font-size: 14px;
      cursor: pointer;
      text-decoration: none;
      text-align: center;
    }
    .calendar-btn-accept {
      background: #34a853;
      color: white;
    }
    .calendar-btn-maybe {
      background: #fbbc04;
      color: #333;
    }
    .calendar-btn-decline {
      background: #ea4335;
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

        switch (prop.toUpperCase()) {
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
    // Simplified timezone component - production would need full VTIMEZONE
    return [
      'BEGIN:VTIMEZONE',
      `TZID:${timezone}`,
      'BEGIN:STANDARD',
      'DTSTART:19710101T030000',
      'TZOFFSETFROM:+0200',
      'TZOFFSETTO:+0100',
      'END:STANDARD',
      'BEGIN:DAYLIGHT',
      'DTSTART:19710101T020000',
      'TZOFFSETFROM:+0100',
      'TZOFFSETTO:+0200',
      'END:DAYLIGHT',
      'END:VTIMEZONE',
    ];
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
    return date.toISOString().split('T')[0].replace(/-/g, '');
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
