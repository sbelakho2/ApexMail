/**
 * IP Warmup Management Service
 * 
 * Manages IP address warmup schedules, tracking, and daily advancement.
 * This service should be run on a daily cron job to advance warmup days.
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

// ISP warmup schedules - must match worker service
const DEFAULT_ISP_WARMUP_SCHEDULES: Record<string, number[]> = {
  gmail: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000, 30000],
  microsoft: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000],
  yahoo: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000],
  apple: [75, 150, 300, 600, 1200, 2400, 4000, 6000, 9000, 12000, 16000, 22000, 30000],
  default: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000, 75000, 100000],
};

const DEFAULT_INITIAL_LIMIT = 100;

export interface WarmupManagerConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
}

export interface IPWarmupInfo {
  id: string;
  ipAddress: string;
  poolId: string;
  warmupDay: number;
  dailyLimit: number;
  dailySent: number;
  warmupStartedAt: Date | null;
  status: string;
  isFullyWarmed: boolean;
  nextDayLimit: number | null;
  utilizationPercent: number;
}

export interface WarmupPoolInfo {
  id: string;
  name: string;
  tenantId: string;
  ipCount: number;
  activeIPs: number;
  totalDailyLimit: number;
  totalDailySent: number;
  utilizationPercent: number;
}

export class WarmupManager {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;

  constructor(config: WarmupManagerConfig) {
    this.db = config.db;
    this.redis = config.redis;
    this.logger = config.logger;
  }

  /**
   * Run daily warmup advancement for all IPs
   * This should be called by a cron job at midnight UTC
   */
  async runDailyAdvancement(): Promise<{ advanced: number; errors: number }> {
    this.logger.info('Starting daily warmup advancement');
    
    const client = await this.db.connect();
    let advanced = 0;
    let errors = 0;
    
    try {
      // Get all active IPs that have started warmup
      const result = await client.query<{
        id: string;
        ip_address: string;
        warmup_day: number;
        warmup_started_at: Date | null;
        daily_limit: number;
        daily_sent: number;
      }>(`
        SELECT id, ip_address, warmup_day, warmup_started_at, daily_limit, daily_sent
        FROM ip_pool_addresses
        WHERE status = 'active'
          AND warmup_enabled = true
          AND warmup_started_at IS NOT NULL
      `);

      const defaultSchedule = DEFAULT_ISP_WARMUP_SCHEDULES['default'] ?? [DEFAULT_INITIAL_LIMIT];
      
      for (const row of result.rows) {
        try {
          // Calculate days since warmup started
          const daysSinceStart = row.warmup_started_at 
            ? Math.floor((Date.now() - row.warmup_started_at.getTime()) / (1000 * 60 * 60 * 24))
            : row.warmup_day;
          
          // If IP sent at least 75% of daily limit, advance the warmup day
          const utilizationThreshold = 0.75;
          const utilization = row.daily_limit > 0 ? row.daily_sent / row.daily_limit : 0;
          
          let newDay = row.warmup_day;
          
          if (utilization >= utilizationThreshold && daysSinceStart > row.warmup_day) {
            // Good utilization, advance warmup
            newDay = Math.min(row.warmup_day + 1, defaultSchedule.length - 1);
            this.logger.info('IP warmup advanced (good utilization)', {
              ipAddress: row.ip_address,
              oldDay: row.warmup_day,
              newDay,
              utilization: (utilization * 100).toFixed(1) + '%',
            });
          } else if (daysSinceStart > row.warmup_day) {
            // Time-based advancement (slower if not sending much)
            newDay = row.warmup_day; // Stay at same day if not utilizing
            this.logger.debug('IP warmup unchanged (low utilization)', {
              ipAddress: row.ip_address,
              day: row.warmup_day,
              utilization: (utilization * 100).toFixed(1) + '%',
            });
          }

          // Calculate new limit
          const newLimit = defaultSchedule[newDay] ?? defaultSchedule[defaultSchedule.length - 1] ?? DEFAULT_INITIAL_LIMIT;

          // Update the IP
          await client.query(`
            UPDATE ip_pool_addresses
            SET warmup_day = $2,
                daily_limit = $3,
                daily_sent = 0,
                last_reset_at = CURRENT_DATE,
                updated_at = NOW()
            WHERE id = $1
          `, [row.id, newDay, newLimit]);

          // Clear Redis counters for this IP
          const today = new Date().toISOString().split('T')[0] ?? '';
          const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0] ?? '';
          
          await this.redis.del(`ip_rate:daily:${row.ip_address}:${yesterday}`);
          
          advanced++;
        } catch (ipError) {
          this.logger.error('Failed to advance warmup for IP', {
            ipAddress: row.ip_address,
            error: ipError,
          });
          errors++;
        }
      }

      this.logger.info('Daily warmup advancement complete', { advanced, errors, total: result.rows.length });
      return { advanced, errors };
    } finally {
      client.release();
    }
  }

  /**
   * Get warmup status for all IPs in a pool
   */
  async getPoolWarmupStatus(poolId: string): Promise<IPWarmupInfo[]> {
    const client = await this.db.connect();
    try {
      const result = await client.query<{
        id: string;
        ip_address: string;
        pool_id: string;
        warmup_day: number;
        daily_limit: number;
        daily_sent: number;
        warmup_started_at: Date | null;
        status: string;
      }>(`
        SELECT id, ip_address, pool_id, warmup_day, daily_limit, daily_sent, warmup_started_at, status
        FROM ip_pool_addresses
        WHERE pool_id = $1
        ORDER BY warmup_day DESC, ip_address ASC
      `, [poolId]);

      const defaultSchedule = DEFAULT_ISP_WARMUP_SCHEDULES['default'] ?? [DEFAULT_INITIAL_LIMIT];
      
      return result.rows.map(row => ({
        id: row.id,
        ipAddress: row.ip_address,
        poolId: row.pool_id,
        warmupDay: row.warmup_day,
        dailyLimit: row.daily_limit,
        dailySent: row.daily_sent,
        warmupStartedAt: row.warmup_started_at,
        status: row.status,
        isFullyWarmed: row.warmup_day >= defaultSchedule.length - 1,
        nextDayLimit: row.warmup_day < defaultSchedule.length - 1 
          ? defaultSchedule[row.warmup_day + 1] ?? null 
          : null,
        utilizationPercent: row.daily_limit > 0 
          ? Math.round((row.daily_sent / row.daily_limit) * 100) 
          : 0,
      }));
    } finally {
      client.release();
    }
  }

  /**
   * Get summary of all IP pools
   */
  async getAllPoolsStatus(): Promise<WarmupPoolInfo[]> {
    const client = await this.db.connect();
    try {
      const result = await client.query<{
        id: string;
        name: string;
        tenant_id: string;
        ip_count: string;
        active_ips: string;
        total_daily_limit: string;
        total_daily_sent: string;
      }>(`
        SELECT 
          p.id,
          p.name,
          p.tenant_id,
          COUNT(a.id) as ip_count,
          COUNT(a.id) FILTER (WHERE a.status = 'active') as active_ips,
          COALESCE(SUM(a.daily_limit), 0) as total_daily_limit,
          COALESCE(SUM(a.daily_sent), 0) as total_daily_sent
        FROM ip_pools p
        LEFT JOIN ip_pool_addresses a ON a.pool_id = p.id
        GROUP BY p.id, p.name, p.tenant_id
        ORDER BY p.name
      `);

      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        tenantId: row.tenant_id,
        ipCount: parseInt(row.ip_count, 10),
        activeIPs: parseInt(row.active_ips, 10),
        totalDailyLimit: parseInt(row.total_daily_limit, 10),
        totalDailySent: parseInt(row.total_daily_sent, 10),
        utilizationPercent: parseInt(row.total_daily_limit, 10) > 0
          ? Math.round((parseInt(row.total_daily_sent, 10) / parseInt(row.total_daily_limit, 10)) * 100)
          : 0,
      }));
    } finally {
      client.release();
    }
  }

  /**
   * Start warmup for a specific IP
   */
  async startIPWarmup(ipAddress: string): Promise<void> {
    const defaultSchedule = DEFAULT_ISP_WARMUP_SCHEDULES['default'] ?? [DEFAULT_INITIAL_LIMIT];
    const initialLimit = defaultSchedule[0] ?? DEFAULT_INITIAL_LIMIT;
    
    await this.db.query(`
      UPDATE ip_pool_addresses
      SET warmup_enabled = true,
          warmup_started_at = NOW(),
          warmup_day = 0,
          daily_limit = $2,
          daily_sent = 0,
          updated_at = NOW()
      WHERE ip_address = $1
    `, [ipAddress, initialLimit]);

    this.logger.info('IP warmup started', { ipAddress, initialLimit });
  }

  /**
   * Pause warmup for a specific IP
   */
  async pauseIPWarmup(ipAddress: string): Promise<void> {
    await this.db.query(`
      UPDATE ip_pool_addresses
      SET warmup_enabled = false,
          updated_at = NOW()
      WHERE ip_address = $1
    `, [ipAddress]);

    this.logger.info('IP warmup paused', { ipAddress });
  }

  /**
   * Reset warmup for a specific IP (start from day 0)
   */
  async resetIPWarmup(ipAddress: string): Promise<void> {
    const defaultSchedule = DEFAULT_ISP_WARMUP_SCHEDULES['default'] ?? [DEFAULT_INITIAL_LIMIT];
    const initialLimit = defaultSchedule[0] ?? DEFAULT_INITIAL_LIMIT;
    
    await this.db.query(`
      UPDATE ip_pool_addresses
      SET warmup_enabled = true,
          warmup_started_at = NOW(),
          warmup_day = 0,
          daily_limit = $2,
          daily_sent = 0,
          updated_at = NOW()
      WHERE ip_address = $1
    `, [ipAddress, initialLimit]);

    this.logger.info('IP warmup reset', { ipAddress, initialLimit });
  }

  /**
   * Manually set warmup day for an IP (for recovery scenarios)
   */
  async setWarmupDay(ipAddress: string, day: number): Promise<void> {
    const defaultSchedule = DEFAULT_ISP_WARMUP_SCHEDULES['default'] ?? [DEFAULT_INITIAL_LIMIT];
    const limit = defaultSchedule[Math.min(day, defaultSchedule.length - 1)] ?? DEFAULT_INITIAL_LIMIT;
    
    await this.db.query(`
      UPDATE ip_pool_addresses
      SET warmup_day = $2,
          daily_limit = $3,
          updated_at = NOW()
      WHERE ip_address = $1
    `, [ipAddress, day, limit]);

    this.logger.info('IP warmup day set manually', { ipAddress, day, limit });
  }

  /**
   * Get warmup schedule info (for API responses)
   */
  getWarmupScheduleInfo(): Record<string, { schedule: number[]; maxDay: number; maxLimit: number }> {
    const result: Record<string, { schedule: number[]; maxDay: number; maxLimit: number }> = {};
    
    for (const [isp, schedule] of Object.entries(DEFAULT_ISP_WARMUP_SCHEDULES)) {
      result[isp] = {
        schedule,
        maxDay: schedule.length - 1,
        maxLimit: schedule[schedule.length - 1] ?? 0,
      };
    }
    
    return result;
  }
}
