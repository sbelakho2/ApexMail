/**
 * Health Check Service
 * 
 * Comprehensive health monitoring for all services:
 * - Database health (primary, replica, standby)
 * - Redis health (primary, sentinel)
 * - Service health (API, MTA, Worker, etc.)
 * - External dependencies
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { Result, createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'ha-health-check' });

export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown',
}

export interface ComponentHealth {
  name: string;
  status: HealthStatus;
  latencyMs: number;
  message?: string;
  lastCheck: Date;
  metadata?: Record<string, unknown>;
}

export interface ClusterHealth {
  clusterId: string;
  nodeId: string;
  region: string;
  status: HealthStatus;
  components: ComponentHealth[];
  replicationLag?: number;
  lastUpdate: Date;
}

export interface ServiceEndpoint {
  name: string;
  url: string;
  healthPath: string;
  timeout: number;
  critical: boolean;
}

export class HealthCheckService {
  private primaryDb: Pool;
  private replicaDb: Pool | null;
  private standbyDb: Pool | null;
  private redis: Redis;
  private healthHistory: Map<string, ComponentHealth[]>;
  private listeners: Set<(health: ClusterHealth) => void>;
  private checkInterval: NodeJS.Timeout | null = null;
  private lastClusterHealth: ClusterHealth | null = null;

  private readonly serviceEndpoints: ServiceEndpoint[] = [
    { name: 'api', url: 'http://localhost:4000', healthPath: '/health', timeout: 3000, critical: true },
    { name: 'mta', url: 'http://localhost:4001', healthPath: '/health', timeout: 3000, critical: true },
    { name: 'worker', url: 'http://localhost:4002', healthPath: '/health', timeout: 3000, critical: true },
    { name: 'tracking', url: 'http://localhost:4003', healthPath: '/health', timeout: 3000, critical: false },
    { name: 'analytics', url: 'http://localhost:4004', healthPath: '/health', timeout: 3000, critical: false },
    { name: 'billing', url: 'http://localhost:4100', healthPath: '/health', timeout: 3000, critical: false },
    { name: 'devex', url: 'http://localhost:4200', healthPath: '/health', timeout: 3000, critical: false },
  ];

  constructor(primaryDb: Pool, redis: Redis, replicaDb?: Pool, standbyDb?: Pool) {
    this.primaryDb = primaryDb;
    this.replicaDb = replicaDb ?? null;
    this.standbyDb = standbyDb ?? null;
    this.redis = redis;
    this.healthHistory = new Map();
    this.listeners = new Set();
  }

  /**
   * Start periodic health checks
   */
  startPeriodicChecks(): void {
    if (this.checkInterval) return;

    this.checkInterval = setInterval(() => {
      this.getClusterHealth()
        .then(async (health) => {
          // Notify listeners
          for (const listener of this.listeners) {
            try {
              listener(health);
            } catch (error) {
              logger.error('[HealthCheck] Listener error:', { error: error instanceof Error ? error.message : String(error) });
            }
          }

          // Store in Redis for cluster-wide visibility
          await this.publishHealth(health);
        })
        .catch(err => {
          logger.error('[HealthCheck] Health check failed:', { error: err instanceof Error ? err.message : String(err) });
        });
    }, config.healthCheckInterval);

    // Run immediately
    this.getClusterHealth().then(health => {
      for (const listener of this.listeners) {
        try {
          listener(health);
        } catch (error) {
          logger.error('[HealthCheck] Listener error:', { error: error instanceof Error ? error.message : String(error) });
        }
      }
    });
  }

  /**
   * Stop periodic health checks
   */
  stopPeriodicChecks(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * Register health change listener
   */
  onHealthChange(listener: (health: ClusterHealth) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Get comprehensive cluster health
   */
  async getClusterHealth(): Promise<ClusterHealth> {
    const components: ComponentHealth[] = [];

    // Check database health
    const [primaryHealth, replicaHealth, standbyHealth] = await Promise.all([
      this.checkDatabaseHealth('primary', this.primaryDb),
      this.replicaDb ? this.checkDatabaseHealth('replica', this.replicaDb) : null,
      this.standbyDb ? this.checkDatabaseHealth('standby', this.standbyDb) : null,
    ]);

    components.push(primaryHealth);
    if (replicaHealth) components.push(replicaHealth);
    if (standbyHealth) components.push(standbyHealth);

    // Check Redis health
    const redisHealth = await this.checkRedisHealth();
    components.push(redisHealth);

    // Check system resources
    const [memoryHealth, diskHealth] = await Promise.all([
      this.checkMemoryHealth(),
      this.checkDiskHealth(),
    ]);
    components.push(memoryHealth);
    components.push(diskHealth);

    // Check service endpoints
    const serviceHealths = await Promise.all(
      this.serviceEndpoints.map(endpoint => this.checkServiceHealth(endpoint))
    );
    components.push(...serviceHealths);

    // Check replication lag
    const replicationLag = await this.getReplicationLag();

    // Calculate overall status
    const overallStatus = this.calculateOverallStatus(components);

    const clusterHealth: ClusterHealth = {
      clusterId: config.clusterId,
      nodeId: config.nodeId,
      region: config.region,
      status: overallStatus,
      components,
      replicationLag,
      lastUpdate: new Date(),
    };

    this.lastClusterHealth = clusterHealth;
    return clusterHealth;
  }

  /**
   * Check database health
   */
  private async checkDatabaseHealth(name: string, pool: Pool): Promise<ComponentHealth> {
    const startTime = Date.now();
    
    try {
      const client = await this.withTimeout(
        pool.connect(),
        config.healthCheckTimeout
      );

      try {
        // Check basic connectivity
        const result = await client.query('SELECT 1 as health, NOW() as server_time, pg_is_in_recovery() as is_replica');
        const row = result.rows[0];
        
        // Get additional metrics
        const statsResult = await client.query(`
          SELECT 
            numbackends as active_connections,
            xact_commit as transactions_committed,
            xact_rollback as transactions_rolled_back,
            blks_hit / NULLIF(blks_hit + blks_read, 0)::float as cache_hit_ratio
          FROM pg_stat_database 
          WHERE datname = current_database()
        `);
        
        const stats = statsResult.rows[0] || {};
        const latencyMs = Date.now() - startTime;

        return {
          name: `database_${name}`,
          status: HealthStatus.HEALTHY,
          latencyMs,
          lastCheck: new Date(),
          metadata: {
            isReplica: row.is_replica,
            serverTime: row.server_time,
            activeConnections: stats.active_connections,
            cacheHitRatio: stats.cache_hit_ratio ? parseFloat(stats.cache_hit_ratio.toFixed(4)) : null,
          },
        };
      } finally {
        client.release();
      }
    } catch (error) {
      return {
        name: `database_${name}`,
        status: HealthStatus.UNHEALTHY,
        latencyMs: Date.now() - startTime,
        message: (error as Error).message,
        lastCheck: new Date(),
      };
    }
  }

  /**
   * Check Redis health
   */
  private async checkRedisHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();
    
    try {
      const result = await this.withTimeout(
        this.redis.ping(),
        config.healthCheckTimeout
      );

      if (result !== 'PONG') {
        throw new Error('Unexpected PING response');
      }

      // Get Redis info
      const info = await this.redis.info('server');
      const memoryInfo = await this.redis.info('memory');
      
      const parseInfo = (infoStr: string): Record<string, string> => {
        const result: Record<string, string> = {};
        for (const line of infoStr.split('\n')) {
          const [key, value] = line.split(':');
          if (key && value) {
            result[key.trim()] = value.trim();
          }
        }
        return result;
      };

      const serverInfo = parseInfo(info);
      const memInfo = parseInfo(memoryInfo);

      const latencyMs = Date.now() - startTime;

      return {
        name: 'redis',
        status: HealthStatus.HEALTHY,
        latencyMs,
        lastCheck: new Date(),
        metadata: {
          version: serverInfo.redis_version,
          uptimeSeconds: parseInt(serverInfo.uptime_in_seconds ?? '0'),
          usedMemory: memInfo.used_memory_human,
          maxMemory: memInfo.maxmemory_human,
          connectedClients: serverInfo.connected_clients,
        },
      };
    } catch (error) {
      return {
        name: 'redis',
        status: HealthStatus.UNHEALTHY,
        latencyMs: Date.now() - startTime,
        message: (error as Error).message,
        lastCheck: new Date(),
      };
    }
  }

  /**
   * Check service health
   */
  private async checkServiceHealth(endpoint: ServiceEndpoint): Promise<ComponentHealth> {
    const startTime = Date.now();
    
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), endpoint.timeout);

      const response = await fetch(`${endpoint.url}${endpoint.healthPath}`, {
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        return {
          name: endpoint.name,
          status: endpoint.critical ? HealthStatus.UNHEALTHY : HealthStatus.DEGRADED,
          latencyMs,
          message: `HTTP ${response.status}`,
          lastCheck: new Date(),
        };
      }

      const data = await response.json().catch(() => ({})) as Record<string, unknown>;

      return {
        name: endpoint.name,
        status: HealthStatus.HEALTHY,
        latencyMs,
        lastCheck: new Date(),
        metadata: data,
      };
    } catch (error) {
      return {
        name: endpoint.name,
        status: endpoint.critical ? HealthStatus.UNHEALTHY : HealthStatus.DEGRADED,
        latencyMs: Date.now() - startTime,
        message: (error as Error).message,
        lastCheck: new Date(),
      };
    }
  }

  /**
   * G-206: Check memory usage health
   */
  private async checkMemoryHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const memUsage = process.memoryUsage();
      const totalMem = require('os').totalmem();
      const freeMem = require('os').freemem();
      const usedPercent = ((totalMem - freeMem) / totalMem) * 100;
      const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
      const latencyMs = Date.now() - startTime;

      let status = HealthStatus.HEALTHY;
      let message: string | undefined;

      if (usedPercent > 95 || heapUsedPercent > 95) {
        status = HealthStatus.UNHEALTHY;
        message = `Critical memory usage: system ${usedPercent.toFixed(1)}%, heap ${heapUsedPercent.toFixed(1)}%`;
      } else if (usedPercent > 85 || heapUsedPercent > 85) {
        status = HealthStatus.DEGRADED;
        message = `High memory usage: system ${usedPercent.toFixed(1)}%, heap ${heapUsedPercent.toFixed(1)}%`;
      }

      return {
        name: 'memory',
        status,
        latencyMs,
        message,
        lastCheck: new Date(),
        metadata: {
          systemTotalMb: Math.round(totalMem / 1024 / 1024),
          systemFreeMb: Math.round(freeMem / 1024 / 1024),
          systemUsedPercent: parseFloat(usedPercent.toFixed(1)),
          heapTotalMb: Math.round(memUsage.heapTotal / 1024 / 1024),
          heapUsedMb: Math.round(memUsage.heapUsed / 1024 / 1024),
          heapUsedPercent: parseFloat(heapUsedPercent.toFixed(1)),
          rssMb: Math.round(memUsage.rss / 1024 / 1024),
          externalMb: Math.round(memUsage.external / 1024 / 1024),
        },
      };
    } catch (error) {
      return {
        name: 'memory',
        status: HealthStatus.UNKNOWN,
        latencyMs: Date.now() - startTime,
        message: (error as Error).message,
        lastCheck: new Date(),
      };
    }
  }

  /**
   * G-206: Check disk space health
   */
  private async checkDiskHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const { execSync } = require('child_process');
      // Use df to check root partition usage
      const output = execSync("df -P / | tail -1", { encoding: 'utf-8', timeout: 5000 });
      const parts = output.trim().split(/\s+/);
      // df -P output: Filesystem 1024-blocks Used Available Capacity Mounted
      const totalKb = parseInt(parts[1] || '0', 10);
      const usedKb = parseInt(parts[2] || '0', 10);
      const availableKb = parseInt(parts[3] || '0', 10);
      const usedPercent = totalKb > 0 ? (usedKb / totalKb) * 100 : 0;
      const latencyMs = Date.now() - startTime;

      let status = HealthStatus.HEALTHY;
      let message: string | undefined;

      if (usedPercent > 95) {
        status = HealthStatus.UNHEALTHY;
        message = `Critical disk usage: ${usedPercent.toFixed(1)}% used`;
      } else if (usedPercent > 85) {
        status = HealthStatus.DEGRADED;
        message = `High disk usage: ${usedPercent.toFixed(1)}% used`;
      }

      return {
        name: 'disk',
        status,
        latencyMs,
        message,
        lastCheck: new Date(),
        metadata: {
          totalGb: parseFloat((totalKb / 1024 / 1024).toFixed(2)),
          usedGb: parseFloat((usedKb / 1024 / 1024).toFixed(2)),
          availableGb: parseFloat((availableKb / 1024 / 1024).toFixed(2)),
          usedPercent: parseFloat(usedPercent.toFixed(1)),
        },
      };
    } catch (error) {
      return {
        name: 'disk',
        status: HealthStatus.UNKNOWN,
        latencyMs: Date.now() - startTime,
        message: (error as Error).message,
        lastCheck: new Date(),
      };
    }
  }

  /**
   * Get replication lag in milliseconds
   */
  private async getReplicationLag(): Promise<number | undefined> {
    if (!this.replicaDb) return undefined;

    try {
      // Check lag on primary
      const primaryResult = await this.primaryDb.query(`
        SELECT 
          CASE 
            WHEN pg_is_in_recovery() THEN NULL
            ELSE pg_current_wal_lsn()
          END as current_lsn
      `);
      
      const primaryLsn = primaryResult.rows[0]?.current_lsn;
      if (!primaryLsn) return undefined;

      // Check replay position on replica
      const replicaResult = await this.replicaDb.query(`
        SELECT 
          pg_last_wal_receive_lsn() as receive_lsn,
          pg_last_wal_replay_lsn() as replay_lsn,
          EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())) * 1000 as lag_ms
      `);
      
      const lagMs = replicaResult.rows[0]?.lag_ms;
      return lagMs ? Math.round(lagMs) : 0;
    } catch (error) {
      logger.error('[HealthCheck] Failed to get replication lag:', { error: error instanceof Error ? error.message : String(error) });
      return undefined;
    }
  }

  /**
   * Calculate overall cluster status
   */
  private calculateOverallStatus(components: ComponentHealth[]): HealthStatus {
    const hasUnhealthy = components.some(c => c.status === HealthStatus.UNHEALTHY);
    const hasDegraded = components.some(c => c.status === HealthStatus.DEGRADED);
    const hasUnknown = components.some(c => c.status === HealthStatus.UNKNOWN);

    // Check critical services
    const criticalNames = new Set(
      this.serviceEndpoints.filter(e => e.critical).map(e => e.name)
    );
    criticalNames.add('database_primary');
    criticalNames.add('redis');

    const criticalUnhealthy = components.some(
      c => criticalNames.has(c.name) && c.status === HealthStatus.UNHEALTHY
    );

    if (criticalUnhealthy) return HealthStatus.UNHEALTHY;
    if (hasUnhealthy || hasDegraded) return HealthStatus.DEGRADED;
    if (hasUnknown) return HealthStatus.UNKNOWN;
    return HealthStatus.HEALTHY;
  }

  /**
   * Publish health to Redis for cluster visibility
   */
  private async publishHealth(health: ClusterHealth): Promise<void> {
    try {
      const key = `ha:health:${config.clusterId}:${config.nodeId}`;
      await this.redis.setex(key, 30, JSON.stringify(health));
      
      // Publish to health channel
      await this.redis.publish('ha:health', JSON.stringify({
        nodeId: config.nodeId,
        clusterId: config.clusterId,
        status: health.status,
        timestamp: health.lastUpdate.toISOString(),
      }));
    } catch (error) {
      logger.error('[HealthCheck] Failed to publish health:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  /**
   * Get health of all nodes in cluster
   */
  async getClusterNodesHealth(): Promise<Result<ClusterHealth[]>> {
    try {
      const pattern = `ha:health:${config.clusterId}:*`;
      // C-062: Use SCAN instead of KEYS to avoid blocking Redis
      const keys: string[] = [];
      let cursor = '0';
      do {
        const [nextCursor, batchKeys] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 200);
        cursor = nextCursor;
        keys.push(...batchKeys);
      } while (cursor !== '0');
      
      if (keys.length === 0) {
        return { ok: true, value: [] };
      }

      const healthData = await this.redis.mget(...keys);
      const nodes: ClusterHealth[] = [];

      for (const data of healthData) {
        if (data) {
          try {
            nodes.push(JSON.parse(data));
          } catch {
            // Skip invalid entries
          }
        }
      }

      return { ok: true, value: nodes };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get last health check result
   */
  getLastHealth(): ClusterHealth | null {
    return this.lastClusterHealth;
  }

  /**
   * Add custom health check
   */
  addCustomCheck(
    name: string,
    check: () => Promise<{ status: HealthStatus; message?: string; metadata?: Record<string, unknown> }>
  ): void {
    this.serviceEndpoints.push({
      name,
      url: '',
      healthPath: '',
      timeout: config.healthCheckTimeout,
      critical: false,
    });

    // Store custom check function (would need additional tracking)
    logger.info(`[HealthCheck] Added custom check: ${name}`);
  }

  /**
   * Helper: Execute with timeout
   */
  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error('Operation timed out')), timeoutMs)
      ),
    ]);
  }

  /**
   * Run liveness check (for Kubernetes)
   */
  async livenessCheck(): Promise<{ alive: boolean; message?: string }> {
    try {
      // Basic check - can we respond at all?
      return { alive: true };
    } catch (error) {
      return { alive: false, message: (error as Error).message };
    }
  }

  /**
   * Run readiness check (for Kubernetes)
   */
  async readinessCheck(): Promise<{ ready: boolean; message?: string }> {
    try {
      // Check critical components
      const dbHealth = await this.checkDatabaseHealth('primary', this.primaryDb);
      const redisHealth = await this.checkRedisHealth();

      const ready = dbHealth.status === HealthStatus.HEALTHY && 
                   redisHealth.status === HealthStatus.HEALTHY;

      return {
        ready,
        message: ready ? undefined : 'Critical components not healthy',
      };
    } catch (error) {
      return { ready: false, message: (error as Error).message };
    }
  }

  /**
   * Get health history for a component
   */
  getHealthHistory(componentName: string, limit: number = 100): ComponentHealth[] {
    const history = this.healthHistory.get(componentName) ?? [];
    return history.slice(-limit);
  }

  // Alias methods for app.ts compatibility
  startMonitoring(): void {
    this.startPeriodicChecks();
  }

  stopMonitoring(): void {
    this.stopPeriodicChecks();
  }

  async getSystemHealth(): Promise<ClusterHealth> {
    return this.getClusterHealth();
  }

  async checkDatabase(): Promise<ComponentHealth> {
    return this.checkDatabaseHealth('primary', this.primaryDb);
  }

  async checkRedis(): Promise<ComponentHealth> {
    return this.checkRedisHealth();
  }

  async checkReplicationLag(): Promise<number | null> {
    const result = await this.getReplicationLag();
    return result ?? null;
  }
}
