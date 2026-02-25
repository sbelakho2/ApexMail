/**
 * Time Utilities - Deterministic time handling
 * 
 * Provides:
 * - Mockable time source for testing
 * - Date formatting
 * - Duration calculations
 * - Timezone handling
 */

export interface TimeProvider {
  now(): Date;
  nowMs(): number;
  nowIso(): string;
}

class SystemTimeProvider implements TimeProvider {
  now(): Date {
    return new Date();
  }

  nowMs(): number {
    return Date.now();
  }

  nowIso(): string {
    return new Date().toISOString();
  }
}

class MockTimeProvider implements TimeProvider {
  private currentTime: number;

  constructor(initialTime?: Date | number) {
    this.currentTime = initialTime instanceof Date 
      ? initialTime.getTime() 
      : initialTime ?? Date.now();
  }

  now(): Date {
    return new Date(this.currentTime);
  }

  nowMs(): number {
    return this.currentTime;
  }

  nowIso(): string {
    return new Date(this.currentTime).toISOString();
  }

  setTime(time: Date | number): void {
    this.currentTime = time instanceof Date ? time.getTime() : time;
  }

  advance(ms: number): void {
    this.currentTime += ms;
  }

  advanceSeconds(seconds: number): void {
    this.advance(seconds * 1000);
  }

  advanceMinutes(minutes: number): void {
    this.advance(minutes * 60 * 1000);
  }

  advanceHours(hours: number): void {
    this.advance(hours * 60 * 60 * 1000);
  }

  advanceDays(days: number): void {
    this.advance(days * 24 * 60 * 60 * 1000);
  }
}

// Global time provider (can be swapped for testing)
let timeProvider: TimeProvider = new SystemTimeProvider();

export function getTimeProvider(): TimeProvider {
  return timeProvider;
}

export function setTimeProvider(provider: TimeProvider): void {
  timeProvider = provider;
}

export function createMockTimeProvider(initialTime?: Date | number): MockTimeProvider {
  return new MockTimeProvider(initialTime);
}

export function resetTimeProvider(): void {
  timeProvider = new SystemTimeProvider();
}

// Convenience functions
export function now(): Date {
  return timeProvider.now();
}

export function nowMs(): number {
  return timeProvider.nowMs();
}

export function nowIso(): string {
  return timeProvider.nowIso();
}

// Duration helpers
export interface Duration {
  milliseconds: number;
  seconds: number;
  minutes: number;
  hours: number;
  days: number;
}

export function parseDuration(ms: number): Duration {
  return {
    milliseconds: ms % 1000,
    seconds: Math.floor(ms / 1000) % 60,
    minutes: Math.floor(ms / (1000 * 60)) % 60,
    hours: Math.floor(ms / (1000 * 60 * 60)) % 24,
    days: Math.floor(ms / (1000 * 60 * 60 * 24)),
  };
}

export function formatDuration(ms: number): string {
  const duration = parseDuration(ms);
  const parts: string[] = [];

  if (duration.days > 0) parts.push(`${duration.days}d`);
  if (duration.hours > 0) parts.push(`${duration.hours}h`);
  if (duration.minutes > 0) parts.push(`${duration.minutes}m`);
  if (duration.seconds > 0 || parts.length === 0) parts.push(`${duration.seconds}s`);

  return parts.join(' ');
}

export function durationMs(spec: Partial<Duration>): number {
  return (
    (spec.milliseconds ?? 0) +
    (spec.seconds ?? 0) * 1000 +
    (spec.minutes ?? 0) * 60 * 1000 +
    (spec.hours ?? 0) * 60 * 60 * 1000 +
    (spec.days ?? 0) * 24 * 60 * 60 * 1000
  );
}

// Date range helpers
export function startOfDay(date: Date): Date {
  const result = new Date(date);
  result.setHours(0, 0, 0, 0);
  return result;
}

export function endOfDay(date: Date): Date {
  const result = new Date(date);
  result.setHours(23, 59, 59, 999);
  return result;
}

export function startOfWeek(date: Date): Date {
  const result = new Date(date);
  const day = result.getDay();
  const diff = result.getDate() - day + (day === 0 ? -6 : 1); // Monday start
  result.setDate(diff);
  result.setHours(0, 0, 0, 0);
  return result;
}

export function startOfMonth(date: Date): Date {
  const result = new Date(date);
  result.setDate(1);
  result.setHours(0, 0, 0, 0);
  return result;
}

export function addDays(date: Date, days: number): Date {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

export function addMonths(date: Date, months: number): Date {
  const result = new Date(date);
  result.setMonth(result.getMonth() + months);
  return result;
}

export function differenceInDays(later: Date, earlier: Date): number {
  const diffMs = later.getTime() - earlier.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

export function differenceInHours(later: Date, earlier: Date): number {
  const diffMs = later.getTime() - earlier.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60));
}

export function differenceInMinutes(later: Date, earlier: Date): number {
  const diffMs = later.getTime() - earlier.getTime();
  return Math.floor(diffMs / (1000 * 60));
}

// Format helpers
export function formatIso(date: Date): string {
  return date.toISOString();
}

export function formatDate(date: Date, format: 'short' | 'long' | 'iso' = 'iso'): string {
  switch (format) {
    case 'short':
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    case 'long':
      return date.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });
    case 'iso':
    default:
      return date.toISOString().split('T')[0] ?? '';
  }
}

export function formatDateTime(date: Date): string {
  return date.toISOString().replace('T', ' ').slice(0, 19);
}

// Parse helpers
export function parseIso(isoString: string): Date | null {
  const date = new Date(isoString);
  return isNaN(date.getTime()) ? null : date;
}

// Timezone helpers
export function getUtcOffset(): number {
  return new Date().getTimezoneOffset();
}

export function toUtc(date: Date): Date {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60 * 1000);
}

export function fromUtc(date: Date): Date {
  return new Date(date.getTime() + date.getTimezoneOffset() * 60 * 1000);
}

// Week number (ISO 8601)
export function getWeekNumber(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
}

// DKIM selector format (YYYYWW)
export function getDkimSelector(date: Date = now()): string {
  const year = date.getFullYear();
  const week = getWeekNumber(date).toString().padStart(2, '0');
  return `apexmail${year}${week}`;
}
