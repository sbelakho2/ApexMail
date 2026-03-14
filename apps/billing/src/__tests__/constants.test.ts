import { describe, it, expect } from 'vitest';
import {
  MS_PER_SECOND,
  MS_PER_MINUTE,
  MS_PER_HOUR,
  MS_PER_DAY,
  SECONDS_PER_MINUTE,
  SECONDS_PER_HOUR,
  SECONDS_PER_DAY,
  TTL_ONE_HOUR,
  TTL_ONE_DAY,
  TTL_30_DAYS,
  TTL_35_DAYS,
} from '../lib/constants.js';

describe('Time constants', () => {
  describe('Milliseconds', () => {
    it('MS_PER_SECOND equals 1000', () => {
      expect(MS_PER_SECOND).toBe(1_000);
    });

    it('MS_PER_MINUTE equals 60000', () => {
      expect(MS_PER_MINUTE).toBe(60_000);
      expect(MS_PER_MINUTE).toBe(MS_PER_SECOND * 60);
    });

    it('MS_PER_HOUR equals 3600000', () => {
      expect(MS_PER_HOUR).toBe(3_600_000);
      expect(MS_PER_HOUR).toBe(MS_PER_MINUTE * 60);
    });

    it('MS_PER_DAY equals 86400000', () => {
      expect(MS_PER_DAY).toBe(86_400_000);
      expect(MS_PER_DAY).toBe(MS_PER_HOUR * 24);
    });
  });

  describe('Seconds', () => {
    it('SECONDS_PER_MINUTE equals 60', () => {
      expect(SECONDS_PER_MINUTE).toBe(60);
    });

    it('SECONDS_PER_HOUR equals 3600', () => {
      expect(SECONDS_PER_HOUR).toBe(3_600);
      expect(SECONDS_PER_HOUR).toBe(SECONDS_PER_MINUTE * 60);
    });

    it('SECONDS_PER_DAY equals 86400', () => {
      expect(SECONDS_PER_DAY).toBe(86_400);
      expect(SECONDS_PER_DAY).toBe(SECONDS_PER_HOUR * 24);
    });
  });

  describe('TTL values', () => {
    it('TTL_ONE_HOUR equals 3600 seconds', () => {
      expect(TTL_ONE_HOUR).toBe(3_600);
      expect(TTL_ONE_HOUR).toBe(SECONDS_PER_HOUR);
    });

    it('TTL_ONE_DAY equals 86400 seconds', () => {
      expect(TTL_ONE_DAY).toBe(86_400);
      expect(TTL_ONE_DAY).toBe(SECONDS_PER_DAY);
    });

    it('TTL_30_DAYS equals 30 days in seconds', () => {
      expect(TTL_30_DAYS).toBe(30 * SECONDS_PER_DAY);
      expect(TTL_30_DAYS).toBe(2_592_000);
    });

    it('TTL_35_DAYS equals 35 days in seconds', () => {
      expect(TTL_35_DAYS).toBe(35 * SECONDS_PER_DAY);
      expect(TTL_35_DAYS).toBe(3_024_000);
    });
  });
});

describe('Consistency checks', () => {
  it('millisecond and second constants are consistent', () => {
    expect(MS_PER_DAY).toBe(SECONDS_PER_DAY * MS_PER_SECOND);
    expect(MS_PER_HOUR).toBe(SECONDS_PER_HOUR * MS_PER_SECOND);
    expect(MS_PER_MINUTE).toBe(SECONDS_PER_MINUTE * MS_PER_SECOND);
  });
});
