/**
 * HA Routes
 * 
 * HTTP endpoints for High Availability service
 */

import { Hono } from 'hono';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { HealthCheckService } from '../services/health-check.js';
import { FailoverService, FailoverType } from '../services/failover.js';
import { BackupService, BackupType } from '../services/backup.js';
import { ReplicationService } from '../services/replication.js';
import { MultiRegionService, RegionStatus, RegionRole, RoutingMode } from '../services/multi-region.js';
import { CircuitBreakerService } from '../services/circuit-breaker.js';
import { ChaosEngineeringService, ExperimentType, ExperimentStatus } from '../services/chaos.js';

type Variables = {
  db: Pool;
  redis: Redis;
  healthCheck: HealthCheckService;
  failover: FailoverService;
  backup: BackupService;
  replication: ReplicationService;
  multiRegion: MultiRegionService;
  circuitBreaker: CircuitBreakerService;
  chaos: ChaosEngineeringService;
};

export const haRoutes = new Hono<{ Variables: Variables }>();

// ===== Health Check Routes =====

haRoutes.get('/health', async (c) => {
  const healthCheck = c.get('healthCheck');
  const health = await healthCheck.getSystemHealth();
  
  const status = health.status === 'healthy' ? 200 : health.status === 'degraded' ? 200 : 503;
  
  return c.json({
    status: health.status,
    components: health.components,
    timestamp: new Date().toISOString(),
  }, status);
});

haRoutes.get('/health/liveness', async (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

haRoutes.get('/health/readiness', async (c) => {
  const healthCheck = c.get('healthCheck');
  const result = await healthCheck.checkDatabase();
  
  if (!result.healthy) {
    return c.json({ status: 'not ready', reason: result.error }, 503);
  }
  
  return c.json({ status: 'ready', timestamp: new Date().toISOString() });
});

haRoutes.get('/health/detailed', async (c) => {
  const healthCheck = c.get('healthCheck');
  
  const [database, redis, replication] = await Promise.all([
    healthCheck.checkDatabase(),
    healthCheck.checkRedis(),
    healthCheck.checkReplicationLag(),
  ]);
  
  return c.json({
    database,
    redis,
    replication,
    timestamp: new Date().toISOString(),
  });
});

// ===== Failover Routes =====

haRoutes.get('/failover/status', async (c) => {
  const failover = c.get('failover');
  const status = failover.getStatus();
  
  return c.json(status);
});

haRoutes.post('/failover/initiate', async (c) => {
  const failover = c.get('failover');
  const body = await c.req.json<{ targetHost?: string; reason?: string }>();
  
  const result = await failover.initiateFailover(
    FailoverType.MANUAL,
    body.targetHost,
    body.reason
  );
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Failover initiated', event: result.value });
});

haRoutes.post('/failover/failback', async (c) => {
  const failover = c.get('failover');
  
  const result = await failover.failback();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Failback completed', event: result.value });
});

haRoutes.get('/failover/history', async (c) => {
  const failover = c.get('failover');
  const limit = parseInt(c.req.query('limit') || '100');
  
  const result = await failover.getFailoverHistory(limit);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json({ events: result.value });
});

// ===== Backup Routes =====

haRoutes.get('/backups', async (c) => {
  const backup = c.get('backup');
  const type = c.req.query('type') as BackupType | undefined;
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');
  
  const result = await backup.listBackups({ type, limit, offset });
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

haRoutes.post('/backups/full', async (c) => {
  const backup = c.get('backup');
  
  const result = await backup.createFullBackup();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Full backup created', backup: result.value });
});

haRoutes.post('/backups/incremental', async (c) => {
  const backup = c.get('backup');
  const body = await c.req.json<{ baseBackupId?: string }>().catch(() => ({}));
  
  const result = await backup.createIncrementalBackup(body.baseBackupId);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Incremental backup created', backup: result.value });
});

haRoutes.post('/backups/:id/verify', async (c) => {
  const backup = c.get('backup');
  const backupId = c.req.param('id');
  
  const result = await backup.verifyBackup(backupId);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

haRoutes.post('/restore', async (c) => {
  const backup = c.get('backup');
  const body = await c.req.json<{
    backupId?: string;
    pointInTime?: string;
    verifyOnly?: boolean;
  }>();
  
  const result = await backup.restore({
    backupId: body.backupId,
    pointInTime: body.pointInTime ? new Date(body.pointInTime) : undefined,
    verifyOnly: body.verifyOnly,
  });
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

haRoutes.post('/backups/retention', async (c) => {
  const backup = c.get('backup');
  
  const result = await backup.enforceRetention();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json({ message: 'Retention enforced', ...result.value });
});

// ===== Replication Routes =====

haRoutes.get('/replication/status', async (c) => {
  const replication = c.get('replication');
  
  const result = await replication.getReplicationStatus();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

haRoutes.get('/replication/slots', async (c) => {
  const replication = c.get('replication');
  
  const result = await replication.getReplicationStatus();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json({ slots: result.value.slots });
});

haRoutes.post('/replication/slots/physical', async (c) => {
  const replication = c.get('replication');
  const body = await c.req.json<{ name: string }>();
  
  const result = await replication.createPhysicalSlot(body.name);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Physical slot created', slot: result.value });
});

haRoutes.post('/replication/slots/logical', async (c) => {
  const replication = c.get('replication');
  const body = await c.req.json<{ name: string; plugin?: string }>();
  
  const result = await replication.createLogicalSlot(body.name, body.plugin);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Logical slot created', slot: result.value });
});

haRoutes.delete('/replication/slots/:name', async (c) => {
  const replication = c.get('replication');
  const name = c.req.param('name');
  
  const result = await replication.dropSlot(name);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Slot dropped' });
});

haRoutes.post('/replication/promote/:host', async (c) => {
  const replication = c.get('replication');
  const host = c.req.param('host');
  
  const result = await replication.promoteReplica(host);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Replica promoted', host });
});

haRoutes.post('/replication/sync-mode', async (c) => {
  const replication = c.get('replication');
  const body = await c.req.json<{ replicas: string[]; mode: 'on' | 'off' }>();
  
  const result = await replication.setSynchronousMode(body.replicas, body.mode);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: `Synchronous mode ${body.mode}` });
});

haRoutes.get('/replication/conflicts', async (c) => {
  const replication = c.get('replication');
  
  const result = await replication.getConflictStats();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

// ===== Multi-Region Routes =====

haRoutes.get('/regions', async (c) => {
  const multiRegion = c.get('multiRegion');
  
  const regions = multiRegion.getRegions();
  const summary = multiRegion.getHealthSummary();
  
  return c.json({ regions, summary });
});

haRoutes.get('/regions/:id', async (c) => {
  const multiRegion = c.get('multiRegion');
  const regionId = c.req.param('id');
  
  const region = multiRegion.getRegion(regionId);
  
  if (!region) {
    return c.json({ error: 'Region not found' }, 404);
  }
  
  return c.json(region);
});

haRoutes.put('/regions/:id/status', async (c) => {
  const multiRegion = c.get('multiRegion');
  const regionId = c.req.param('id');
  const body = await c.req.json<{ status: RegionStatus }>();
  
  const result = await multiRegion.setRegionStatus(regionId, body.status);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Region status updated' });
});

haRoutes.put('/regions/:id/role', async (c) => {
  const multiRegion = c.get('multiRegion');
  const regionId = c.req.param('id');
  const body = await c.req.json<{ role: RegionRole }>();
  
  const result = await multiRegion.setRegionRole(regionId, body.role);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Region role updated' });
});

haRoutes.post('/regions/failover', async (c) => {
  const multiRegion = c.get('multiRegion');
  const body = await c.req.json<{ targetRegionId: string }>();
  
  const result = await multiRegion.failoverToRegion(body.targetRegionId);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Regional failover completed' });
});

haRoutes.post('/regions/route', async (c) => {
  const multiRegion = c.get('multiRegion');
  const body = await c.req.json<{
    clientIp?: string;
    country?: string;
    continent?: string;
    preferredRegion?: string;
  }>();
  
  const result = await multiRegion.routeRequest(body);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ region: result.value });
});

haRoutes.get('/regions/traffic', async (c) => {
  const multiRegion = c.get('multiRegion');
  
  const result = await multiRegion.getTrafficDistribution();
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json({ distribution: result.value });
});

haRoutes.put('/regions/routing-mode', async (c) => {
  const multiRegion = c.get('multiRegion');
  const body = await c.req.json<{ mode: RoutingMode }>();
  
  multiRegion.setRoutingMode(body.mode);
  
  return c.json({ message: `Routing mode set to ${body.mode}` });
});

haRoutes.put('/regions/weights', async (c) => {
  const multiRegion = c.get('multiRegion');
  const body = await c.req.json<{ weights: Record<string, number> }>();
  
  const result = await multiRegion.updateRegionWeights(body.weights);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Region weights updated' });
});

// ===== Circuit Breaker Routes =====

haRoutes.get('/circuits', async (c) => {
  const circuitBreaker = c.get('circuitBreaker');
  
  const stats = circuitBreaker.getAllStats();
  const health = circuitBreaker.getHealthStatus();
  
  return c.json({ circuits: stats, health });
});

haRoutes.get('/circuits/:name', async (c) => {
  const circuitBreaker = c.get('circuitBreaker');
  const name = c.req.param('name');
  
  const stats = circuitBreaker.getStats(name);
  
  if (!stats) {
    return c.json({ error: 'Circuit not found' }, 404);
  }
  
  return c.json(stats);
});

haRoutes.post('/circuits/:name/open', async (c) => {
  const circuitBreaker = c.get('circuitBreaker');
  const name = c.req.param('name');
  
  const result = circuitBreaker.forceOpen(name);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Circuit opened' });
});

haRoutes.post('/circuits/:name/close', async (c) => {
  const circuitBreaker = c.get('circuitBreaker');
  const name = c.req.param('name');
  
  const result = circuitBreaker.forceClose(name);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Circuit closed' });
});

haRoutes.post('/circuits/:name/reset', async (c) => {
  const circuitBreaker = c.get('circuitBreaker');
  const name = c.req.param('name');
  
  const result = circuitBreaker.reset(name);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Circuit reset' });
});

// ===== Chaos Engineering Routes =====

haRoutes.get('/chaos/status', async (c) => {
  const chaos = c.get('chaos');
  
  const result = await chaos.listExperiments({ status: ExperimentStatus.RUNNING });
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json({
    activeExperiments: result.value.experiments.length,
    experiments: result.value.experiments,
  });
});

haRoutes.get('/chaos/experiments', async (c) => {
  const chaos = c.get('chaos');
  const status = c.req.query('status') as ExperimentStatus | undefined;
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');
  
  const result = await chaos.listExperiments({ status, limit, offset });
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 500);
  }
  
  return c.json(result.value);
});

haRoutes.get('/chaos/experiments/:id', async (c) => {
  const chaos = c.get('chaos');
  const id = c.req.param('id');
  
  const experiment = chaos.getExperiment(id);
  
  if (!experiment) {
    return c.json({ error: 'Experiment not found' }, 404);
  }
  
  return c.json(experiment);
});

haRoutes.post('/chaos/experiments', async (c) => {
  const chaos = c.get('chaos');
  const body = await c.req.json<{
    name: string;
    type: ExperimentType;
    target: {
      service?: string;
      endpoint?: string;
      percentage?: number;
      userIds?: string[];
      regions?: string[];
    };
    parameters: {
      latencyMs?: number;
      latencyJitter?: number;
      failureRate?: number;
      errorCode?: number;
    };
    duration: number;
    safetyChecks?: Array<{
      type: 'error_rate' | 'latency' | 'availability';
      threshold: number;
      action: 'abort' | 'alert' | 'continue';
    }>;
    rollbackEnabled?: boolean;
    notifyChannels?: string[];
  }>();
  
  const result = await chaos.createExperiment({
    name: body.name,
    type: body.type,
    target: body.target,
    parameters: body.parameters,
    duration: body.duration,
    safetyChecks: body.safetyChecks || [],
    rollbackEnabled: body.rollbackEnabled ?? true,
    notifyChannels: body.notifyChannels || [],
  });
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Experiment created', experiment: result.value }, 201);
});

haRoutes.post('/chaos/experiments/:id/start', async (c) => {
  const chaos = c.get('chaos');
  const id = c.req.param('id');
  
  const result = await chaos.startExperiment(id);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Experiment started' });
});

haRoutes.post('/chaos/experiments/:id/end', async (c) => {
  const chaos = c.get('chaos');
  const id = c.req.param('id');
  
  const result = await chaos.endExperiment(id);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Experiment ended', results: result.value });
});

haRoutes.post('/chaos/experiments/:id/abort', async (c) => {
  const chaos = c.get('chaos');
  const id = c.req.param('id');
  const body = await c.req.json<{ reason?: string }>().catch(() => ({}));
  
  const result = await chaos.abortExperiment(id, body.reason);
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Experiment aborted' });
});

haRoutes.post('/chaos/experiments/:id/schedule', async (c) => {
  const chaos = c.get('chaos');
  const id = c.req.param('id');
  const body = await c.req.json<{ scheduledAt: string }>();
  
  const result = await chaos.scheduleExperiment(id, new Date(body.scheduledAt));
  
  if (!result.ok) {
    return c.json({ error: result.error.message }, 400);
  }
  
  return c.json({ message: 'Experiment scheduled' });
});

haRoutes.post('/chaos/enable', async (c) => {
  const chaos = c.get('chaos');
  chaos.enable();
  return c.json({ message: 'Chaos engineering enabled' });
});

haRoutes.post('/chaos/disable', async (c) => {
  const chaos = c.get('chaos');
  chaos.disable();
  return c.json({ message: 'Chaos engineering disabled' });
});
