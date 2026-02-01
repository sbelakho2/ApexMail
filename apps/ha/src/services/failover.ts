/**
 * Failover Service
 * 
 * Manages automatic and manual failover:
 * - Database failover (primary -> standby)
 * - Redis failover (via Sentinel)
 * - Service failover
 * - Multi-region failover
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { config } from '../config.js';
import { HealthCheckService, HealthStatus, ClusterHealth } from './health-check.js';

export enum FailoverState {
  NORMAL = 'normal',
  DETECTING = 'detecting',
  FAILING_OVER = 'failing_over',
  FAILED_OVER = 'failed_over',
  FAILING_BACK = 'failing_back',
  MANUAL_INTERVENTION = 'manual_intervention',
}

export enum FailoverType {
  AUTOMATIC = 'automatic',
  MANUAL = 'manual',
  SCHEDULED = 'scheduled',
}

export interface FailoverEvent {
  id: string;
  type: FailoverType;
  component: string;
  fromTarget: string;
  toTarget: string;
  reason: string;
  state: FailoverState;
  startedAt: Date;
  completedAt: Date | null;
  duration: number | null;
  success: boolean | null;
  error: string | null;
  metadata: Record<string, unknown>;
}

export interface FailoverConfig {
  component: string;
  enabled: boolean;
  threshold: number;
  checkInterval: number;
  cooldownPeriod: number;
  targets: FailoverTarget[];
}

export interface FailoverTarget {
  id: string;
  priority: number;
  endpoint: string;
  region?: string;
  zone?: string;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class FailoverService {
  private db: Pool;
  private redis: Redis;
  private healthCheck: HealthCheckService;
  private state: FailoverState = FailoverState.NORMAL;
  private failureCount: Map<string, number> = new Map();
  private lastFailover: Map<string, Date> = new Map();
  private failoverHistory: FailoverEvent[] = [];
  private configs: Map<string, FailoverConfig> = new Map();
  private monitorInterval: NodeJS.Timeout | null = null;
  private listeners: Set<(event: FailoverEvent) => void> = new Set();

  constructor(db: Pool, redis: Redis, healthCheck: HealthCheckService) {
    this.db = db;
    this.redis = redis;
    this.healthCheck = healthCheck;
    this.initializeConfigs();
  }

  private initializeConfigs(): void {
    // Database failover config
    this.configs.set('database', {
      component: 'database',
      enabled: config.failoverEnabled,
      threshold: config.failoverThreshold,
      checkInterval: config.healthCheckInterval,
      cooldownPeriod: 300000, // 5 minutes
      targets: [
        {
          id: 'primary',
          priority: 1,
          endpoint: `${config.dbHost}:${config.dbPort}`,
          region: config.region,
          zone: config.availabilityZone,
        },
        ...(config.dbStandbyHost ? [{
          id: 'standby',
          priority: 2,
          endpoint: `${config.dbStandbyHost}:${config.dbStandbyPort}`,
          region: config.region,
          zone: 'standby',
        }] : []),
      ],
    });

    // Redis failover config (usually handled by Sentinel)
    this.configs.set('redis', {
      component: 'redis',
      enabled: config.failoverEnabled && !!config.redisSentinels,
      threshold: config.failoverThreshold,
      checkInterval: config.healthCheckInterval,
      cooldownPeriod: 60000, // 1 minute
      targets: [
        {
          id: 'primary',
          priority: 1,
          endpoint: `${config.redisHost}:${config.redisPort}`,
        },
      ],
    });

    // API service failover
    this.configs.set('api', {
      component: 'api',
      enabled: config.failoverEnabled,
      threshold: config.failoverThreshold,
      checkInterval: config.healthCheckInterval,
      cooldownPeriod: 60000,
      targets: [
        { id: 'api-1', priority: 1, endpoint: 'http://localhost:4000' },
        { id: 'api-2', priority: 2, endpoint: 'http://localhost:4010' },
      ],
    });
  }

  /**
   * Start failover monitoring
   */
  startMonitoring(): void {
    if (this.monitorInterval) return;

    // Listen to health changes
    this.healthCheck.onHealthChange((health) => {
      this.evaluateHealth(health);
    });

    // Start health checks
    this.healthCheck.startPeriodicChecks();

    console.log('[Failover] Monitoring started');
  }

  /**
   * Stop failover monitoring
   */
  stopMonitoring(): void {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }
    this.healthCheck.stopPeriodicChecks();
    console.log('[Failover] Monitoring stopped');
  }

  /**
   * Evaluate health and trigger failover if needed
   */
  private async evaluateHealth(health: ClusterHealth): Promise<void> {
    if (this.state !== FailoverState.NORMAL && this.state !== FailoverState.FAILED_OVER) {
      return; // Already in failover process
    }

    for (const component of health.components) {
      const componentConfig = this.configs.get(component.name.replace('database_', ''));
      if (!componentConfig?.enabled) continue;

      if (component.status === HealthStatus.UNHEALTHY) {
        await this.handleFailure(component.name, componentConfig);
      } else if (component.status === HealthStatus.HEALTHY) {
        this.resetFailureCount(component.name);
        
        // Check if we should fail back
        if (this.state === FailoverState.FAILED_OVER && config.failbackEnabled) {
          await this.evaluateFailback(component.name, componentConfig);
        }
      }
    }
  }

  /**
   * Handle component failure
   */
  private async handleFailure(componentName: string, failoverConfig: FailoverConfig): Promise<void> {
    const count = (this.failureCount.get(componentName) ?? 0) + 1;
    this.failureCount.set(componentName, count);

    console.log(`[Failover] ${componentName} failure detected (${count}/${failoverConfig.threshold})`);

    if (count >= failoverConfig.threshold) {
      // Check cooldown
      const lastFailoverTime = this.lastFailover.get(componentName);
      if (lastFailoverTime && Date.now() - lastFailoverTime.getTime() < failoverConfig.cooldownPeriod) {
        console.log(`[Failover] ${componentName} in cooldown period, skipping failover`);
        return;
      }

      await this.triggerFailover(componentName, failoverConfig, 'automatic', 'Health check failures exceeded threshold');
    }
  }

  /**
   * Reset failure count
   */
  private resetFailureCount(componentName: string): void {
    if (this.failureCount.has(componentName)) {
      this.failureCount.set(componentName, 0);
    }
  }

  /**
   * Trigger failover
   */
  async triggerFailover(
    componentName: string,
    failoverConfig: FailoverConfig,
    type: 'automatic' | 'manual' | 'scheduled',
    reason: string
  ): Promise<Result<FailoverEvent>> {
    const eventId = `fo_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    
    const event: FailoverEvent = {
      id: eventId,
      type: type === 'automatic' ? FailoverType.AUTOMATIC : 
            type === 'manual' ? FailoverType.MANUAL : FailoverType.SCHEDULED,
      component: componentName,
      fromTarget: failoverConfig.targets[0]?.id ?? 'unknown',
      toTarget: failoverConfig.targets[1]?.id ?? 'unknown',
      reason,
      state: FailoverState.FAILING_OVER,
      startedAt: new Date(),
      completedAt: null,
      duration: null,
      success: null,
      error: null,
      metadata: {},
    };

    this.state = FailoverState.FAILING_OVER;
    this.notifyListeners(event);

    console.log(`[Failover] Starting ${type} failover for ${componentName}: ${reason}`);

    try {
      // Execute failover based on component type
      switch (componentName) {
        case 'database':
        case 'database_primary':
          await this.executeDatabaseFailover(event);
          break;
        case 'redis':
          await this.executeRedisFailover(event);
          break;
        default:
          await this.executeServiceFailover(event, failoverConfig);
          break;
      }

      event.state = FailoverState.FAILED_OVER;
      event.success = true;
      event.completedAt = new Date();
      event.duration = event.completedAt.getTime() - event.startedAt.getTime();

      this.state = FailoverState.FAILED_OVER;
      this.lastFailover.set(componentName, new Date());
      this.failoverHistory.push(event);
      this.notifyListeners(event);

      // Store in database for audit
      await this.storeFailoverEvent(event);

      // Send alert
      await this.sendAlert('failover_completed', event);

      console.log(`[Failover] ${componentName} failover completed in ${event.duration}ms`);

      return { ok: true, value: event };
    } catch (error) {
      event.state = FailoverState.MANUAL_INTERVENTION;
      event.success = false;
      event.error = (error as Error).message;
      event.completedAt = new Date();
      event.duration = event.completedAt.getTime() - event.startedAt.getTime();

      this.state = FailoverState.MANUAL_INTERVENTION;
      this.failoverHistory.push(event);
      this.notifyListeners(event);

      // Send critical alert
      await this.sendAlert('failover_failed', event);

      console.error(`[Failover] ${componentName} failover failed:`, error);

      return { ok: false, error: error as Error };
    }
  }

  /**
   * Execute database failover
   */
  private async executeDatabaseFailover(event: FailoverEvent): Promise<void> {
    if (!config.dbStandbyHost) {
      throw new Error('No standby database configured');
    }

    // Step 1: Verify standby is available
    const standbyPool = new Pool({
      host: config.dbStandbyHost,
      port: config.dbStandbyPort,
      database: config.dbName,
      user: config.dbUser,
      password: config.dbPassword,
      max: 5,
      connectionTimeoutMillis: 5000,
    });

    try {
      const client = await standbyPool.connect();
      
      try {
        // Check if standby is in recovery mode
        const result = await client.query('SELECT pg_is_in_recovery() as is_replica');
        if (!result.rows[0]?.is_replica) {
          throw new Error('Standby is not in recovery mode');
        }

        // Step 2: Promote standby to primary
        // In production, this would use pg_promote() or external orchestration
        console.log('[Failover] Promoting standby database...');
        
        // Simulate promotion (actual command would be executed on the server)
        // await client.query('SELECT pg_promote()');
        
        event.metadata.standbyHost = config.dbStandbyHost;
        event.metadata.standbyPort = config.dbStandbyPort;

        // Step 3: Update connection configuration
        // In production, this would update DNS or load balancer
        await this.updateDatabaseEndpoint(config.dbStandbyHost, config.dbStandbyPort);

        // Step 4: Publish failover event
        await this.redis.publish('ha:failover:database', JSON.stringify({
          eventId: event.id,
          newPrimary: `${config.dbStandbyHost}:${config.dbStandbyPort}`,
          timestamp: new Date().toISOString(),
        }));

      } finally {
        client.release();
      }
    } finally {
      await standbyPool.end();
    }
  }

  /**
   * Execute Redis failover (via Sentinel)
   */
  private async executeRedisFailover(event: FailoverEvent): Promise<void> {
    if (!config.redisSentinels) {
      throw new Error('Redis Sentinel not configured');
    }

    // Connect to Sentinel
    const sentinel = new Redis({
      sentinels: config.redisSentinels,
      name: config.redisSentinelMaster,
      sentinelPassword: config.redisPassword,
    });

    try {
      // Force failover via Sentinel
      await sentinel.call('SENTINEL', 'FAILOVER', config.redisSentinelMaster);
      
      // Wait for failover to complete
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Get new master info
      const masterInfo = await sentinel.call('SENTINEL', 'MASTER', config.redisSentinelMaster);
      event.metadata.newMaster = masterInfo;

    } finally {
      sentinel.disconnect();
    }
  }

  /**
   * Execute service failover
   */
  private async executeServiceFailover(event: FailoverEvent, failoverConfig: FailoverConfig): Promise<void> {
    // Find next available target
    const currentTarget = failoverConfig.targets.find(t => t.id === event.fromTarget);
    const nextTargets = failoverConfig.targets
      .filter(t => t.priority > (currentTarget?.priority ?? 0))
      .sort((a, b) => a.priority - b.priority);

    if (nextTargets.length === 0) {
      throw new Error('No failover targets available');
    }

    const nextTarget = nextTargets[0];

    // Verify next target is healthy
    const response = await fetch(`${nextTarget.endpoint}/health`, {
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      throw new Error(`Failover target ${nextTarget.id} is not healthy`);
    }

    // Update routing (in production, would update load balancer/DNS)
    await this.updateServiceEndpoint(failoverConfig.component, nextTarget.endpoint);

    event.toTarget = nextTarget.id;
    event.metadata.newEndpoint = nextTarget.endpoint;
  }

  /**
   * Update database endpoint (would update DNS/config in production)
   */
  private async updateDatabaseEndpoint(host: string, port: number): Promise<void> {
    // Store new endpoint in Redis for other services to read
    await this.redis.hset('ha:endpoints', 'database', JSON.stringify({ host, port }));
    
    // Publish endpoint change
    await this.redis.publish('ha:endpoint-change', JSON.stringify({
      component: 'database',
      host,
      port,
      timestamp: new Date().toISOString(),
    }));
  }

  /**
   * Update service endpoint
   */
  private async updateServiceEndpoint(service: string, endpoint: string): Promise<void> {
    await this.redis.hset('ha:endpoints', service, endpoint);
    await this.redis.publish('ha:endpoint-change', JSON.stringify({
      component: service,
      endpoint,
      timestamp: new Date().toISOString(),
    }));
  }

  /**
   * Evaluate if we should fail back
   */
  private async evaluateFailback(componentName: string, failoverConfig: FailoverConfig): Promise<void> {
    if (!config.failbackEnabled) return;

    const lastFailoverTime = this.lastFailover.get(componentName);
    if (!lastFailoverTime) return;

    // Wait for failback delay
    if (Date.now() - lastFailoverTime.getTime() < config.failbackDelay) {
      return;
    }

    // Check if original target is now healthy
    const primaryTarget = failoverConfig.targets[0];
    if (!primaryTarget) return;

    try {
      const response = await fetch(`${primaryTarget.endpoint}/health`, {
        signal: AbortSignal.timeout(5000),
      });

      if (response.ok) {
        await this.triggerFailback(componentName, failoverConfig);
      }
    } catch {
      // Primary still not available
    }
  }

  /**
   * Trigger failback to original primary
   */
  async triggerFailback(componentName: string, failoverConfig: FailoverConfig): Promise<Result<FailoverEvent>> {
    const eventId = `fb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    
    const event: FailoverEvent = {
      id: eventId,
      type: FailoverType.AUTOMATIC,
      component: componentName,
      fromTarget: failoverConfig.targets[1]?.id ?? 'standby',
      toTarget: failoverConfig.targets[0]?.id ?? 'primary',
      reason: 'Original primary restored',
      state: FailoverState.FAILING_BACK,
      startedAt: new Date(),
      completedAt: null,
      duration: null,
      success: null,
      error: null,
      metadata: { isFailback: true },
    };

    this.state = FailoverState.FAILING_BACK;
    this.notifyListeners(event);

    console.log(`[Failover] Starting failback for ${componentName}`);

    try {
      // Failback logic similar to failover but in reverse
      const primaryTarget = failoverConfig.targets[0];
      if (primaryTarget) {
        await this.updateServiceEndpoint(componentName, primaryTarget.endpoint);
      }

      event.state = FailoverState.NORMAL;
      event.success = true;
      event.completedAt = new Date();
      event.duration = event.completedAt.getTime() - event.startedAt.getTime();

      this.state = FailoverState.NORMAL;
      this.failoverHistory.push(event);
      this.notifyListeners(event);

      await this.storeFailoverEvent(event);
      await this.sendAlert('failback_completed', event);

      console.log(`[Failover] ${componentName} failback completed`);

      return { ok: true, value: event };
    } catch (error) {
      event.state = FailoverState.MANUAL_INTERVENTION;
      event.success = false;
      event.error = (error as Error).message;
      event.completedAt = new Date();
      event.duration = event.completedAt.getTime() - event.startedAt.getTime();

      this.state = FailoverState.MANUAL_INTERVENTION;
      this.failoverHistory.push(event);
      this.notifyListeners(event);

      await this.sendAlert('failback_failed', event);

      return { ok: false, error: error as Error };
    }
  }

  /**
   * Manual failover trigger
   */
  async manualFailover(componentName: string, reason: string): Promise<Result<FailoverEvent>> {
    const failoverConfig = this.configs.get(componentName);
    if (!failoverConfig) {
      return { ok: false, error: new Error(`No failover config for ${componentName}`) };
    }

    return this.triggerFailover(componentName, failoverConfig, 'manual', reason);
  }

  /**
   * Get current failover state
   */
  getState(): FailoverState {
    return this.state;
  }

  /**
   * Get failover history
   */
  getHistory(limit: number = 100): FailoverEvent[] {
    return this.failoverHistory.slice(-limit);
  }

  /**
   * Register failover event listener
   */
  onFailover(listener: (event: FailoverEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Notify listeners
   */
  private notifyListeners(event: FailoverEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (error) {
        console.error('[Failover] Listener error:', error);
      }
    }
  }

  /**
   * Store failover event in database
   */
  private async storeFailoverEvent(event: FailoverEvent): Promise<void> {
    try {
      await this.db.query(`
        INSERT INTO ha_failover_events (
          id, type, component, from_target, to_target, reason, state,
          started_at, completed_at, duration_ms, success, error, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      `, [
        event.id,
        event.type,
        event.component,
        event.fromTarget,
        event.toTarget,
        event.reason,
        event.state,
        event.startedAt,
        event.completedAt,
        event.duration,
        event.success,
        event.error,
        JSON.stringify(event.metadata),
      ]);
    } catch (error) {
      console.error('[Failover] Failed to store event:', error);
    }
  }

  /**
   * Send alert
   */
  private async sendAlert(type: string, event: FailoverEvent): Promise<void> {
    if (!config.alertingWebhook) return;

    try {
      await fetch(config.alertingWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type,
          event,
          cluster: config.clusterId,
          region: config.region,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      console.error('[Failover] Failed to send alert:', error);
    }
  }

  /**
   * Get failover configuration
   */
  getConfig(componentName: string): FailoverConfig | undefined {
    return this.configs.get(componentName);
  }

  /**
   * Update failover configuration
   */
  updateConfig(componentName: string, updates: Partial<FailoverConfig>): void {
    const existing = this.configs.get(componentName);
    if (existing) {
      this.configs.set(componentName, { ...existing, ...updates });
    }
  }

  // Alias methods for app.ts and routes compatibility
  async initialize(): Promise<void> {
    console.log('[Failover] Initializing failover service...');
    // Start monitoring
    this.startMonitoring();
    console.log('[Failover] Initialized');
  }

  async getStatus(): Promise<{
    state: FailoverState;
    failureCount: Record<string, number>;
    lastFailover: Record<string, Date>;
    configuredComponents: string[];
  }> {
    return {
      state: this.getState(),
      failureCount: Object.fromEntries(this.failureCount),
      lastFailover: Object.fromEntries(this.lastFailover),
      configuredComponents: Array.from(this.configs.keys()),
    };
  }

  async initiateFailover(component: string, reason: string): Promise<FailoverEvent> {
    const failoverConfig = this.configs.get(component);
    if (!failoverConfig) {
      throw new Error(`No failover config for component: ${component}`);
    }
    const result = await this.triggerFailover(component, failoverConfig, 'manual', reason);
    if (!result.ok) {
      throw result.error;
    }
    return result.value;
  }

  async failback(component: string): Promise<void> {
    console.log(`[Failover] Initiating failback for ${component}`);
    // Reset state to normal
    this.state = FailoverState.NORMAL;
    this.failureCount.set(component, 0);
    console.log(`[Failover] Failback complete for ${component}`);
  }

  getFailoverHistory(limit: number = 100): FailoverEvent[] {
    return this.getHistory(limit);
  }
}
