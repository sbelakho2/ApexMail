/**
 * Chaos Engineering Service
 * 
 * Controlled fault injection for resilience testing:
 * - Network latency injection
 * - Service failure simulation
 * - Resource exhaustion
 * - Scheduled experiments
 * - Experiment analysis
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { Result, createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'ha-chaos' });

export enum ExperimentType {
  LATENCY = 'latency',
  FAILURE = 'failure',
  RESOURCE_EXHAUSTION = 'resource_exhaustion',
  NETWORK_PARTITION = 'network_partition',
  DNS_FAILURE = 'dns_failure',
  DISK_FULL = 'disk_full',
  MEMORY_PRESSURE = 'memory_pressure',
  CPU_STRESS = 'cpu_stress',
}

export enum ExperimentStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  ABORTED = 'aborted',
  FAILED = 'failed',
}

export interface ExperimentConfig {
  id: string;
  name: string;
  type: ExperimentType;
  target: ExperimentTarget;
  parameters: ExperimentParameters;
  duration: number;
  scheduledAt?: Date;
  safetyChecks: SafetyCheck[];
  rollbackEnabled: boolean;
  notifyChannels: string[];
}

export interface ExperimentTarget {
  service?: string;
  endpoint?: string;
  percentage?: number;
  userIds?: string[];
  regions?: string[];
}

export interface ExperimentParameters {
  latencyMs?: number;
  latencyJitter?: number;
  failureRate?: number;
  errorCode?: number;
  memoryMb?: number;
  cpuPercent?: number;
  diskPercent?: number;
  partitionedServices?: string[];
}

export interface SafetyCheck {
  type: 'error_rate' | 'latency' | 'availability' | 'custom';
  threshold: number;
  action: 'abort' | 'alert' | 'continue';
}

export interface Experiment {
  id: string;
  config: ExperimentConfig;
  status: ExperimentStatus;
  startedAt: Date | null;
  endedAt: Date | null;
  startedBy: string;
  results: ExperimentResults;
  abortReason?: string;
}

export interface ExperimentResults {
  affectedRequests: number;
  impactedServices: string[];
  safetyCheckTriggered: boolean;
  metrics: {
    beforeExperiment: MetricSnapshot;
    duringExperiment: MetricSnapshot;
    afterExperiment: MetricSnapshot;
  };
  findings: string[];
}

export interface MetricSnapshot {
  timestamp: Date;
  errorRate: number;
  latencyP50: number;
  latencyP99: number;
  availability: number;
  requestsPerSecond: number;
}

export class ChaosEngineeringService {
  private db: Pool;
  private redis: Redis;
  private activeExperiments: Map<string, Experiment> = new Map();
  private scheduledExperiments: Map<string, NodeJS.Timeout> = new Map();
  private injectedFaults: Map<string, () => void> = new Map();
  private enabled: boolean = false;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;

    // SAFETY: Never allow chaos in production unless explicitly overridden
    if (process.env.NODE_ENV === 'production' && !process.env.CHAOS_FORCE_ENABLE) {
      this.enabled = false;
      logger.warn('[Chaos] DISABLED in production. Set CHAOS_FORCE_ENABLE=true to override (dangerous).');
    } else {
      this.enabled = config.chaosEnabled ?? false;
    }
  }

  /**
   * Initialize chaos engineering service
   */
  async initialize(): Promise<void> {
    if (!this.enabled) {
      logger.info('[Chaos] Service disabled - set CHAOS_ENABLED=true to enable');
      return;
    }

    // Load scheduled experiments
    await this.loadScheduledExperiments();

    logger.info('[Chaos] Service initialized');
  }

  /**
   * Enable chaos engineering
   */
  enable(): void {
    this.enabled = true;
    logger.info('[Chaos] Service enabled');
  }

  /**
   * Disable chaos engineering
   */
  disable(): void {
    this.enabled = false;
    // Abort all active experiments
    for (const experiment of this.activeExperiments.values()) {
      this.abortExperiment(experiment.id, 'Service disabled');
    }
    logger.info('[Chaos] Service disabled');
  }

  /**
   * Create a new chaos experiment
   */
  async createExperiment(config: Omit<ExperimentConfig, 'id'>): Promise<Result<Experiment>> {
    if (!this.enabled) {
      return { ok: false, error: new Error('Chaos engineering is disabled') };
    }

    const id = `chaos_${Date.now()}`;
    const experimentConfig: ExperimentConfig = { ...config, id };

    const experiment: Experiment = {
      id,
      config: experimentConfig,
      status: ExperimentStatus.PENDING,
      startedAt: null,
      endedAt: null,
      startedBy: 'system',
      results: {
        affectedRequests: 0,
        impactedServices: [],
        safetyCheckTriggered: false,
        metrics: {
          beforeExperiment: this.createEmptySnapshot(),
          duringExperiment: this.createEmptySnapshot(),
          afterExperiment: this.createEmptySnapshot(),
        },
        findings: [],
      },
    };

    // Store in database
    await this.db.query(`
      INSERT INTO ha_chaos_experiments (
        id, name, type, config, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())
    `, [id, config.name, config.type, JSON.stringify(experimentConfig), experiment.status]);

    this.activeExperiments.set(id, experiment);

    logger.info(`[Chaos] Created experiment: ${config.name} (${id})`);

    return { ok: true, value: experiment };
  }

  /**
   * Start an experiment
   */
  async startExperiment(experimentId: string, userId: string = 'system'): Promise<Result<void>> {
    if (!this.enabled) {
      return { ok: false, error: new Error('Chaos engineering is disabled') };
    }

    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment) {
      return { ok: false, error: new Error(`Experiment not found: ${experimentId}`) };
    }

    if (experiment.status !== ExperimentStatus.PENDING) {
      return { ok: false, error: new Error(`Experiment not in pending state: ${experiment.status}`) };
    }

    logger.info(`[Chaos] Starting experiment: ${experiment.config.name}`);

    try {
      // Capture pre-experiment metrics
      experiment.results.metrics.beforeExperiment = await this.captureMetrics();

      // Start the experiment
      experiment.status = ExperimentStatus.RUNNING;
      experiment.startedAt = new Date();
      experiment.startedBy = userId;

      await this.updateExperimentStatus(experiment);

      // Inject faults based on experiment type
      await this.injectFaults(experiment);

      // Schedule automatic end
      setTimeout(async () => {
        if (experiment.status === ExperimentStatus.RUNNING) {
          await this.endExperiment(experimentId);
        }
      }, experiment.config.duration);

      // Start safety monitoring
      this.startSafetyMonitoring(experiment);

      // Publish event
      await this.redis.publish('chaos:started', JSON.stringify({
        experimentId,
        name: experiment.config.name,
        type: experiment.config.type,
        startedBy: userId,
        timestamp: new Date().toISOString(),
      }));

      return { ok: true, value: undefined };
    } catch (error) {
      experiment.status = ExperimentStatus.FAILED;
      experiment.endedAt = new Date();
      await this.updateExperimentStatus(experiment);
      return { ok: false, error: error as Error };
    }
  }

  /**
   * End an experiment
   */
  async endExperiment(experimentId: string): Promise<Result<ExperimentResults>> {
    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment) {
      return { ok: false, error: new Error(`Experiment not found: ${experimentId}`) };
    }

    logger.info(`[Chaos] Ending experiment: ${experiment.config.name}`);

    try {
      // Remove injected faults
      await this.removeFaults(experiment);

      // Capture during-experiment metrics
      experiment.results.metrics.duringExperiment = await this.captureMetrics();

      // Wait a bit for system to stabilize
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Capture post-experiment metrics
      experiment.results.metrics.afterExperiment = await this.captureMetrics();

      // Analyze results
      experiment.results.findings = this.analyzeResults(experiment.results.metrics);

      experiment.status = ExperimentStatus.COMPLETED;
      experiment.endedAt = new Date();

      await this.updateExperimentStatus(experiment);

      // Publish event
      await this.redis.publish('chaos:ended', JSON.stringify({
        experimentId,
        name: experiment.config.name,
        status: experiment.status,
        findings: experiment.results.findings,
        timestamp: new Date().toISOString(),
      }));

      return { ok: true, value: experiment.results };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Abort an experiment
   */
  async abortExperiment(experimentId: string, reason: string = 'Manual abort'): Promise<Result<void>> {
    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment) {
      return { ok: false, error: new Error(`Experiment not found: ${experimentId}`) };
    }

    logger.info(`[Chaos] Aborting experiment: ${experiment.config.name} - ${reason}`);

    try {
      // Remove injected faults immediately
      await this.removeFaults(experiment);

      experiment.status = ExperimentStatus.ABORTED;
      experiment.endedAt = new Date();
      experiment.abortReason = reason;

      // Capture metrics at abort
      experiment.results.metrics.duringExperiment = await this.captureMetrics();

      await this.updateExperimentStatus(experiment);

      // Publish event
      await this.redis.publish('chaos:aborted', JSON.stringify({
        experimentId,
        name: experiment.config.name,
        reason,
        timestamp: new Date().toISOString(),
      }));

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Schedule an experiment
   */
  async scheduleExperiment(experimentId: string, scheduledAt: Date): Promise<Result<void>> {
    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment) {
      return { ok: false, error: new Error(`Experiment not found: ${experimentId}`) };
    }

    const delay = scheduledAt.getTime() - Date.now();
    if (delay <= 0) {
      return { ok: false, error: new Error('Scheduled time must be in the future') };
    }

    experiment.config.scheduledAt = scheduledAt;

    const timeout = setTimeout(async () => {
      await this.startExperiment(experimentId);
    }, delay);

    this.scheduledExperiments.set(experimentId, timeout);

    logger.info(`[Chaos] Scheduled experiment: ${experiment.config.name} for ${scheduledAt.toISOString()}`);

    return { ok: true, value: undefined };
  }

  /**
   * Get experiment status
   */
  getExperiment(experimentId: string): Experiment | undefined {
    return this.activeExperiments.get(experimentId);
  }

  /**
   * List all experiments
   */
  async listExperiments(options?: {
    status?: ExperimentStatus;
    limit?: number;
    offset?: number;
  }): Promise<Result<{ experiments: Experiment[]; total: number }>> {
    try {
      let query = 'SELECT * FROM ha_chaos_experiments WHERE 1=1';
      const params: unknown[] = [];
      let paramIndex = 1;

      if (options?.status) {
        query += ` AND status = $${paramIndex}`;
        params.push(options.status);
        paramIndex++;
      }

      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM (${query}) subq`,
        params
      );

      query += ' ORDER BY created_at DESC';

      if (options?.limit) {
        query += ` LIMIT $${paramIndex}`;
        params.push(options.limit);
        paramIndex++;
      }

      if (options?.offset) {
        query += ` OFFSET $${paramIndex}`;
        params.push(options.offset);
      }

      const result = await this.db.query(query, params);

      const experiments: Experiment[] = result.rows.map(row => ({
        id: row.id,
        config: JSON.parse(row.config),
        status: row.status,
        startedAt: row.started_at ? new Date(row.started_at) : null,
        endedAt: row.ended_at ? new Date(row.ended_at) : null,
        startedBy: row.started_by || 'system',
        results: row.results ? JSON.parse(row.results) : this.createEmptyResults(),
        abortReason: row.abort_reason,
      }));

      return {
        ok: true,
        value: {
          experiments,
          total: parseInt(countResult.rows[0]?.total ?? '0', 10),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Check if a request should be affected by chaos
   */
  shouldAffectRequest(options: {
    service?: string;
    endpoint?: string;
    userId?: string;
    region?: string;
  }): { affected: boolean; experiment?: Experiment; faultType?: ExperimentType } {
    if (!this.enabled) {
      return { affected: false };
    }

    for (const experiment of this.activeExperiments.values()) {
      if (experiment.status !== ExperimentStatus.RUNNING) {
        continue;
      }

      const target = experiment.config.target;

      // Check service match
      if (target.service && target.service !== options.service) {
        continue;
      }

      // Check endpoint match
      if (target.endpoint && !options.endpoint?.includes(target.endpoint)) {
        continue;
      }

      // Check user match
      if (target.userIds && options.userId && !target.userIds.includes(options.userId)) {
        continue;
      }

      // Check region match
      if (target.regions && options.region && !target.regions.includes(options.region)) {
        continue;
      }

      // Check percentage
      if (target.percentage && Math.random() * 100 > target.percentage) {
        continue;
      }

      // This request should be affected
      experiment.results.affectedRequests++;
      if (options.service && !experiment.results.impactedServices.includes(options.service)) {
        experiment.results.impactedServices.push(options.service);
      }

      return {
        affected: true,
        experiment,
        faultType: experiment.config.type,
      };
    }

    return { affected: false };
  }

  /**
   * Apply chaos fault to a request
   */
  async applyFault(faultType: ExperimentType, parameters: ExperimentParameters): Promise<void> {
    switch (faultType) {
      case ExperimentType.LATENCY: {
        const latency = parameters.latencyMs ?? 1000;
        const jitter = parameters.latencyJitter ?? 0;
        const actualLatency = latency + (Math.random() * jitter * 2 - jitter);
        await new Promise(resolve => setTimeout(resolve, actualLatency));
        break;
      }

      case ExperimentType.FAILURE: {
        const failureRate = parameters.failureRate ?? 1.0;
        if (Math.random() < failureRate) {
          const errorCode = parameters.errorCode ?? 500;
          throw new ChaosError(`Chaos-induced failure`, errorCode);
        }
        break;
      }

      case ExperimentType.NETWORK_PARTITION:
        throw new ChaosError('Network partition simulated', 503);

      case ExperimentType.DNS_FAILURE:
        throw new ChaosError('DNS resolution failed', 502);

      default:
        // Other fault types are handled differently
        break;
    }
  }

  // Private methods

  private async injectFaults(experiment: Experiment): Promise<void> {
    const config = experiment.config;
    const faultId = `fault_${experiment.id}`;

    switch (config.type) {
      case ExperimentType.CPU_STRESS:
        this.injectCpuStress(faultId, config.parameters.cpuPercent ?? 80);
        break;

      case ExperimentType.MEMORY_PRESSURE:
        this.injectMemoryPressure(faultId, config.parameters.memoryMb ?? 500);
        break;

      default:
        // Request-level faults are applied via shouldAffectRequest
        break;
    }
  }

  private async removeFaults(experiment: Experiment): Promise<void> {
    const faultId = `fault_${experiment.id}`;
    const cleanup = this.injectedFaults.get(faultId);
    if (cleanup) {
      cleanup();
      this.injectedFaults.delete(faultId);
    }
  }

  private injectCpuStress(faultId: string, _targetPercent: number): void {
    let running = true;
    const workers: NodeJS.Timeout[] = [];

    // Create CPU stress workers
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const workerCount = Math.ceil(require('os').cpus().length * (_targetPercent / 100));
    for (let i = 0; i < workerCount; i++) {
      const worker = setInterval(() => {
        if (running) {
          // Busy loop to consume CPU
          const end = Date.now() + 100;
          while (Date.now() < end) {
            Math.random() * Math.random();
          }
        }
      }, 100);
      workers.push(worker);
    }

    this.injectedFaults.set(faultId, () => {
      running = false;
      workers.forEach(w => clearInterval(w));
    });

    logger.info(`[Chaos] Injected CPU stress: ${_targetPercent}%`);
  }

  private injectMemoryPressure(faultId: string, targetMb: number): void {
    const buffers: Buffer[] = [];
    const chunkSize = 10 * 1024 * 1024; // 10MB chunks
    const chunks = Math.ceil(targetMb / 10);

    for (let i = 0; i < chunks; i++) {
      buffers.push(Buffer.alloc(chunkSize));
    }

    this.injectedFaults.set(faultId, () => {
      buffers.length = 0;
      global.gc?.();
    });

    logger.info(`[Chaos] Injected memory pressure: ${targetMb}MB`);
  }

  private startSafetyMonitoring(experiment: Experiment): void {
    const interval = setInterval(async () => {
      if (experiment.status !== ExperimentStatus.RUNNING) {
        clearInterval(interval);
        return;
      }

      const currentMetrics = await this.captureMetrics();

      for (const check of experiment.config.safetyChecks) {
        let triggered = false;

        switch (check.type) {
          case 'error_rate':
            triggered = currentMetrics.errorRate > check.threshold;
            break;
          case 'latency':
            triggered = currentMetrics.latencyP99 > check.threshold;
            break;
          case 'availability':
            triggered = currentMetrics.availability < check.threshold;
            break;
        }

        if (triggered) {
          logger.info(`[Chaos] Safety check triggered: ${check.type}`);
          experiment.results.safetyCheckTriggered = true;

          switch (check.action) {
            case 'abort': {
              await this.abortExperiment(experiment.id, `Safety check: ${check.type}`);
              clearInterval(interval);
              return;
            }
            case 'alert': {
              await this.sendAlert(experiment, check);
              break;
            }
          }
        }
      }
    }, 5000);
  }

  private async captureMetrics(): Promise<MetricSnapshot> {
    try {
      const result = await this.db.query(`
        SELECT 
          COALESCE(AVG(error_rate), 0) as error_rate,
          COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latency_ms), 0) as p50,
          COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms), 0) as p99,
          COALESCE(AVG(availability), 100) as availability,
          COALESCE(SUM(request_count) / 60.0, 0) as rps
        FROM ha_service_metrics
        WHERE recorded_at > NOW() - INTERVAL '1 minute'
      `);

      const row = result.rows[0] || {};

      return {
        timestamp: new Date(),
        errorRate: parseFloat(row.error_rate) || 0,
        latencyP50: parseFloat(row.p50) || 0,
        latencyP99: parseFloat(row.p99) || 0,
        availability: parseFloat(row.availability) || 100,
        requestsPerSecond: parseFloat(row.rps) || 0,
      };
    } catch {
      return this.createEmptySnapshot();
    }
  }

  private analyzeResults(metrics: {
    beforeExperiment: MetricSnapshot;
    duringExperiment: MetricSnapshot;
    afterExperiment: MetricSnapshot;
  }): string[] {
    const findings: string[] = [];

    // Compare error rates
    const errorIncrease = metrics.duringExperiment.errorRate - metrics.beforeExperiment.errorRate;
    if (errorIncrease > 0.1) {
      findings.push(`Error rate increased by ${(errorIncrease * 100).toFixed(1)}% during experiment`);
    }

    // Compare latency
    const latencyIncrease = metrics.duringExperiment.latencyP99 - metrics.beforeExperiment.latencyP99;
    if (latencyIncrease > 100) {
      findings.push(`P99 latency increased by ${latencyIncrease.toFixed(0)}ms during experiment`);
    }

    // Check recovery
    const recoveryTime = metrics.afterExperiment.timestamp.getTime() - metrics.duringExperiment.timestamp.getTime();
    const errorRecovery = metrics.afterExperiment.errorRate - metrics.beforeExperiment.errorRate;
    if (Math.abs(errorRecovery) < 0.01) {
      findings.push(`System recovered to normal error rate in approximately ${(recoveryTime / 1000).toFixed(0)}s`);
    } else {
      findings.push(`System did not fully recover - error rate still elevated by ${(errorRecovery * 100).toFixed(1)}%`);
    }

    // Availability impact
    if (metrics.duringExperiment.availability < 99.9) {
      findings.push(`Availability dropped to ${metrics.duringExperiment.availability.toFixed(2)}% during experiment`);
    }

    return findings;
  }

  private async sendAlert(experiment: Experiment, check: SafetyCheck): Promise<void> {
    await this.redis.publish('chaos:alert', JSON.stringify({
      experimentId: experiment.id,
      name: experiment.config.name,
      safetyCheck: check.type,
      threshold: check.threshold,
      timestamp: new Date().toISOString(),
    }));
  }

  private async loadScheduledExperiments(): Promise<void> {
    try {
      const result = await this.db.query(`
        SELECT * FROM ha_chaos_experiments 
        WHERE status = 'pending' 
        AND config->>'scheduledAt' IS NOT NULL
      `);

      for (const row of result.rows) {
        const config = JSON.parse(row.config);
        const scheduledAt = new Date(config.scheduledAt);
        if (scheduledAt > new Date()) {
          await this.scheduleExperiment(row.id, scheduledAt);
        }
      }
    } catch (error) {
      logger.warn('[Chaos] Could not load scheduled experiments', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async updateExperimentStatus(experiment: Experiment): Promise<void> {
    await this.db.query(`
      UPDATE ha_chaos_experiments SET
        status = $2,
        started_at = $3,
        ended_at = $4,
        started_by = $5,
        results = $6,
        abort_reason = $7
      WHERE id = $1
    `, [
      experiment.id,
      experiment.status,
      experiment.startedAt,
      experiment.endedAt,
      experiment.startedBy,
      JSON.stringify(experiment.results),
      experiment.abortReason,
    ]);
  }

  private createEmptySnapshot(): MetricSnapshot {
    return {
      timestamp: new Date(),
      errorRate: 0,
      latencyP50: 0,
      latencyP99: 0,
      availability: 100,
      requestsPerSecond: 0,
    };
  }

  private createEmptyResults(): ExperimentResults {
    return {
      affectedRequests: 0,
      impactedServices: [],
      safetyCheckTriggered: false,
      metrics: {
        beforeExperiment: this.createEmptySnapshot(),
        duringExperiment: this.createEmptySnapshot(),
        afterExperiment: this.createEmptySnapshot(),
      },
      findings: [],
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    // Cancel all scheduled experiments
    for (const timeout of this.scheduledExperiments.values()) {
      clearTimeout(timeout);
    }
    this.scheduledExperiments.clear();

    // Remove all injected faults
    for (const cleanup of this.injectedFaults.values()) {
      cleanup();
    }
    this.injectedFaults.clear();

    logger.info('[Chaos] Service shut down');
  }
}

/**
 * Custom error class for chaos-induced failures
 */
export class ChaosError extends Error {
  public statusCode: number;

  constructor(message: string, statusCode: number = 500) {
    super(message);
    this.name = 'ChaosError';
    this.statusCode = statusCode;
  }
}
