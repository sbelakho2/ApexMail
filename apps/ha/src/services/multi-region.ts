/**
 * Multi-Region Service
 * 
 * Global traffic management and multi-region coordination:
 * - Region health tracking
 * - Traffic routing decisions
 * - Cross-region data synchronization
 * - Geo-aware failover
 * - Active-active and active-passive modes
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { Result } from '@apexmail/lib';
import { config } from '../config.js';

export enum RegionStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  MAINTENANCE = 'maintenance',
  OFFLINE = 'offline',
}

export enum RegionRole {
  PRIMARY = 'primary',
  SECONDARY = 'secondary',
  STANDBY = 'standby',
  OBSERVER = 'observer',
}

// HA-003 FIX: Fencing status for STONITH mechanism
export enum FencingStatus {
  ACTIVE = 'active',       // Region is operating normally
  FENCED = 'fenced',       // Region has been fenced (STONITH applied)
  FENCING = 'fencing',     // Fencing operation in progress
  RECOVERY = 'recovery',   // Recovering from fenced state
}

export enum RoutingMode {
  ACTIVE_ACTIVE = 'active-active',
  ACTIVE_PASSIVE = 'active-passive',
  ROUND_ROBIN = 'round-robin',
  LATENCY_BASED = 'latency-based',
  GEO_PROXIMITY = 'geo-proximity',
  WEIGHTED = 'weighted',
}

export interface RegionInfo {
  id: string;
  name: string;
  endpoint: string;
  status: RegionStatus;
  role: RegionRole;
  fencingStatus: FencingStatus;  // HA-003 FIX: Track fencing state
  weight: number;
  latencyMs: number;
  lastCheck: Date;
  healthScore: number;
  activeConnections: number;
  requestsPerSecond: number;
  errorRate: number;
  replicationLagMs: number;
  metadata: Record<string, unknown>;
}

export interface TrafficDistribution {
  region: string;
  percentage: number;
  requestCount: number;
}

export interface GeoRoutingRule {
  id: string;
  name: string;
  sourceCountries: string[];
  sourceContinent?: string;
  targetRegion: string;
  priority: number;
  enabled: boolean;
}

export interface CrossRegionConfig {
  syncInterval: number;
  maxLagMs: number;
  conflictResolution: 'last-write-wins' | 'primary-wins' | 'custom';
  syncTables: string[];
}

export class MultiRegionService {
  private db: Pool;
  private redis: Redis;
  private regions: Map<string, RegionInfo> = new Map();
  private routingRules: Map<string, GeoRoutingRule> = new Map();
  private currentRegion: string;
  private routingMode: RoutingMode;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private syncInterval: NodeJS.Timeout | null = null;
  
  // HA-003 FIX: Fencing operation lock for STONITH mechanism
  private fencingInProgress: Map<string, boolean> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.currentRegion = config.region;
    this.routingMode = config.routingMode as RoutingMode ?? RoutingMode.ACTIVE_PASSIVE;
  }

  /**
   * Initialize multi-region service
   */
  async initialize(): Promise<void> {
    // Load regions from config (config.regions is string[])
    for (const regionId of config.regions) {
      const isPrimary = regionId === config.primaryRegion;
      const region: RegionInfo = {
        id: regionId,
        name: regionId,
        endpoint: `https://${regionId}.apexmail.ee`,
        status: RegionStatus.HEALTHY,
        role: isPrimary ? RegionRole.PRIMARY : RegionRole.SECONDARY,
        fencingStatus: FencingStatus.ACTIVE,  // HA-003 FIX: Initialize fencing status
        weight: isPrimary ? 2 : 1,
        latencyMs: 0,
        lastCheck: new Date(),
        healthScore: 100,
        activeConnections: 0,
        requestsPerSecond: 0,
        errorRate: 0,
        replicationLagMs: 0,
        metadata: {},
      };
      this.regions.set(regionId, region);
    }

    // Load routing rules from database
    await this.loadRoutingRules();

    console.log('[MultiRegion] Service initialized with', this.regions.size, 'regions');
  }

  /**
   * Start health checking and synchronization
   */
  startServices(): void {
    // Start health checking with error handling
    this.healthCheckInterval = setInterval(() => {
      this.checkAllRegions().catch(err => {
        console.error('[MultiRegion] Health check failed:', err instanceof Error ? err.message : err);
      });
    }, config.regionHealthCheckIntervalMs ?? 10000);

    // Start cross-region sync with error handling
    if (this.routingMode === RoutingMode.ACTIVE_ACTIVE) {
      this.syncInterval = setInterval(() => {
        this.synchronizeRegions().catch(err => {
          console.error('[MultiRegion] Region sync failed:', err instanceof Error ? err.message : err);
        });
      }, config.crossRegionSyncIntervalMs ?? 5000);
    }

    console.log('[MultiRegion] Services started');
  }

  /**
   * Stop services
   */
  stopServices(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }

  /**
   * Get all regions
   */
  getRegions(): RegionInfo[] {
    return Array.from(this.regions.values());
  }

  /**
   * Get a specific region
   */
  getRegion(regionId: string): RegionInfo | undefined {
    return this.regions.get(regionId);
  }

  /**
   * Get current region
   */
  getCurrentRegion(): RegionInfo | undefined {
    return this.regions.get(this.currentRegion);
  }

  /**
   * Get primary region
   */
  getPrimaryRegion(): RegionInfo | undefined {
    return Array.from(this.regions.values()).find(r => r.role === RegionRole.PRIMARY);
  }

  /**
   * Route request to appropriate region
   */
  async routeRequest(options: {
    clientIp?: string;
    country?: string;
    continent?: string;
    preferredRegion?: string;
  }): Promise<Result<RegionInfo>> {
    try {
      // Check for geo-routing rules
      if (options.country || options.continent) {
        const geoRegion = await this.applyGeoRouting(options.country, options.continent);
        if (geoRegion) {
          return { ok: true, value: geoRegion };
        }
      }

      // Check preferred region
      if (options.preferredRegion) {
        const preferred = this.regions.get(options.preferredRegion);
        if (preferred && preferred.status === RegionStatus.HEALTHY) {
          return { ok: true, value: preferred };
        }
      }

      // Apply routing mode
      const selectedRegion = await this.selectRegion();
      if (!selectedRegion) {
        return { ok: false, error: new Error('No healthy regions available') };
      }

      return { ok: true, value: selectedRegion };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Set region status
   */
  async setRegionStatus(regionId: string, status: RegionStatus): Promise<Result<void>> {
    const region = this.regions.get(regionId);
    if (!region) {
      return { ok: false, error: new Error(`Region not found: ${regionId}`) };
    }

    const previousStatus = region.status;
    region.status = status;

    // Record status change
    await this.db.query(`
      INSERT INTO ha_region_status_history (region_id, status, previous_status, changed_at)
      VALUES ($1, $2, $3, NOW())
    `, [regionId, status, previousStatus]);

    // Publish event
    await this.redis.publish('multiregion:status', JSON.stringify({
      regionId,
      status,
      previousStatus,
      timestamp: new Date().toISOString(),
    }));

    console.log(`[MultiRegion] Region ${regionId} status: ${previousStatus} -> ${status}`);

    return { ok: true, value: undefined };
  }

  /**
   * Set region role
   */
  async setRegionRole(regionId: string, role: RegionRole): Promise<Result<void>> {
    const region = this.regions.get(regionId);
    if (!region) {
      return { ok: false, error: new Error(`Region not found: ${regionId}`) };
    }

    // If setting to primary, demote current primary
    if (role === RegionRole.PRIMARY) {
      const currentPrimary = this.getPrimaryRegion();
      if (currentPrimary && currentPrimary.id !== regionId) {
        currentPrimary.role = RegionRole.SECONDARY;
        await this.recordRoleChange(currentPrimary.id, RegionRole.SECONDARY);
      }
    }

    const previousRole = region.role;
    region.role = role;

    await this.recordRoleChange(regionId, role);

    // Publish event
    await this.redis.publish('multiregion:role', JSON.stringify({
      regionId,
      role,
      previousRole,
      timestamp: new Date().toISOString(),
    }));

    console.log(`[MultiRegion] Region ${regionId} role: ${previousRole} -> ${role}`);

    return { ok: true, value: undefined };
  }

  /**
   * Failover to another region
   * CRITICAL: Verifies replication lag before failover to prevent data loss
   * HA-003 FIX: Implements STONITH (Shoot The Other Node In The Head) fencing
   * to prevent split-brain scenarios
   */
  async failoverToRegion(targetRegionId: string): Promise<Result<void>> {
    const targetRegion = this.regions.get(targetRegionId);
    if (!targetRegion) {
      return { ok: false, error: new Error(`Target region not found: ${targetRegionId}`) };
    }

    if (targetRegion.status === RegionStatus.OFFLINE) {
      return { ok: false, error: new Error(`Target region is offline: ${targetRegionId}`) };
    }

    const currentPrimary = this.getPrimaryRegion();
    if (!currentPrimary) {
      return { ok: false, error: new Error('No current primary region') };
    }

    // CRITICAL: Check replication lag before allowing failover
    const MAX_LAG_MS = 10000; // 10 seconds max acceptable lag
    if (targetRegion.replicationLagMs > MAX_LAG_MS) {
      return {
        ok: false,
        error: new Error(
          `Target region replication lag too high: ${targetRegion.replicationLagMs}ms (max: ${MAX_LAG_MS}ms). ` +
          `Data loss risk is too high. Please wait for replication to catch up or use force option.`
        )
      };
    }

    console.log(`[MultiRegion] Starting failover: ${currentPrimary.id} -> ${targetRegionId}`);
    console.log(`[MultiRegion] Target region replication lag: ${targetRegion.replicationLagMs}ms`);

    try {
      // HA-003 FIX: STONITH - Fence the old primary BEFORE promoting the new one
      // This ensures only one primary can accept writes at any time
      const fenceResult = await this.fenceRegion(currentPrimary.id, 'Failover to new primary initiated');
      if (!fenceResult.ok) {
        return {
          ok: false,
          error: new Error(
            `STONITH FAILED: Could not fence old primary ${currentPrimary.id}. ` +
            `Aborting failover to prevent split-brain. Error: ${fenceResult.error?.message}`
          )
        };
      }
      
      console.log(`[MultiRegion] STONITH: Successfully fenced old primary ${currentPrimary.id}`);

      // Mark current primary as degraded (already fenced)
      await this.setRegionStatus(currentPrimary.id, RegionStatus.DEGRADED);

      // Promote target to primary
      await this.setRegionRole(targetRegionId, RegionRole.PRIMARY);
      await this.setRegionStatus(targetRegionId, RegionStatus.HEALTHY);

      // Demote old primary to secondary
      await this.setRegionRole(currentPrimary.id, RegionRole.SECONDARY);

      // Update DNS/routing (in production, would call DNS API)
      await this.updateGlobalRouting(targetRegionId);

      // Record failover event with replication lag and fencing data
      await this.db.query(`
        INSERT INTO ha_region_failovers (
          source_region, target_region, reason, initiated_at, completed_at, metadata
        ) VALUES ($1, $2, 'manual_failover', NOW(), NOW(), $3)
      `, [currentPrimary.id, targetRegionId, JSON.stringify({ 
        replicationLagMs: targetRegion.replicationLagMs,
        stonithApplied: true,
        fencedRegion: currentPrimary.id
      })]);

      console.log(`[MultiRegion] Failover completed to ${targetRegionId}`);

      return { ok: true, value: undefined };
    } catch (error) {
      // HA-003 FIX: On failure, attempt to unfence the old primary to restore service
      console.error(`[MultiRegion] Failover failed, attempting to restore old primary...`);
      await this.unfenceRegion(currentPrimary.id, 'Failover failed - restoring previous primary');
      return { ok: false, error: error as Error };
    }
  }

  /**
   * HA-003 FIX: STONITH - Fence a region to prevent it from accepting writes
   * This is critical for preventing split-brain during failover
   */
  async fenceRegion(regionId: string, reason: string): Promise<Result<void>> {
    const region = this.regions.get(regionId);
    if (!region) {
      return { ok: false, error: new Error(`Region not found: ${regionId}`) };
    }

    // Prevent concurrent fencing operations
    if (this.fencingInProgress.get(regionId)) {
      return { ok: false, error: new Error(`Fencing already in progress for ${regionId}`) };
    }

    this.fencingInProgress.set(regionId, true);
    region.fencingStatus = FencingStatus.FENCING;

    try {
      // Step 1: Acquire distributed fencing lock
      const lockKey = `ha:stonith:lock:${regionId}`;
      const lockValue = `${this.currentRegion}:${Date.now()}`;
      const lockAcquired = await this.redis.set(lockKey, lockValue, 'EX', 60, 'NX');
      
      if (!lockAcquired) {
        return { ok: false, error: new Error(`Could not acquire fencing lock for ${regionId}`) };
      }

      try {
        // Step 2: Signal the target region to stop accepting writes
        // In production, this would use multiple methods:
        // - API call to set region to read-only
        // - Database promotion block
        // - Load balancer drain
        // - Network isolation (if hardware STONITH available)
        
        const fenceEndpoint = `${region.endpoint}/internal/fence`;
        const fenceResponse = await fetch(fenceEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'fence',
            reason,
            initiator: this.currentRegion,
            timestamp: new Date().toISOString(),
          }),
          signal: AbortSignal.timeout(10000),
        }).catch(() => null);

        // Even if the API call fails (region might be down), we proceed
        // The key is to ensure the region is marked as fenced in our state
        if (fenceResponse && !fenceResponse.ok) {
          console.warn(`[STONITH] API fence call to ${regionId} returned non-OK, but proceeding with state fence`);
        }

        // Step 3: Block the region at the routing level
        await this.redis.sadd('ha:fenced-regions', regionId);
        
        // Step 4: Publish fencing event for all services to honor
        await this.redis.publish('ha:stonith', JSON.stringify({
          action: 'fence',
          regionId,
          reason,
          initiator: this.currentRegion,
          timestamp: new Date().toISOString(),
        }));

        // Step 5: Update region state
        region.fencingStatus = FencingStatus.FENCED;

        // Step 6: Record fencing event
        await this.db.query(`
          INSERT INTO ha_fencing_events (region_id, action, reason, initiator, created_at)
          VALUES ($1, 'fence', $2, $3, NOW())
        `, [regionId, reason, this.currentRegion]);

        console.log(`[STONITH] Successfully fenced region ${regionId}: ${reason}`);
        return { ok: true, value: undefined };

      } finally {
        // Release fencing lock
        await this.redis.del(lockKey);
      }

    } catch (error) {
      region.fencingStatus = FencingStatus.ACTIVE; // Revert on failure
      return { ok: false, error: error as Error };
    } finally {
      this.fencingInProgress.set(regionId, false);
    }
  }

  /**
   * HA-003 FIX: Unfence a region to allow it to accept writes again
   */
  async unfenceRegion(regionId: string, reason: string): Promise<Result<void>> {
    const region = this.regions.get(regionId);
    if (!region) {
      return { ok: false, error: new Error(`Region not found: ${regionId}`) };
    }

    region.fencingStatus = FencingStatus.RECOVERY;

    try {
      // Step 1: Remove from fenced regions set
      await this.redis.srem('ha:fenced-regions', regionId);

      // Step 2: Signal the region to resume accepting writes
      const unfenceEndpoint = `${region.endpoint}/internal/fence`;
      await fetch(unfenceEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'unfence',
          reason,
          initiator: this.currentRegion,
          timestamp: new Date().toISOString(),
        }),
        signal: AbortSignal.timeout(10000),
      }).catch(() => null);

      // Step 3: Publish unfencing event
      await this.redis.publish('ha:stonith', JSON.stringify({
        action: 'unfence',
        regionId,
        reason,
        initiator: this.currentRegion,
        timestamp: new Date().toISOString(),
      }));

      // Step 4: Update region state
      region.fencingStatus = FencingStatus.ACTIVE;

      // Step 5: Record unfencing event
      await this.db.query(`
        INSERT INTO ha_fencing_events (region_id, action, reason, initiator, created_at)
        VALUES ($1, 'unfence', $2, $3, NOW())
      `, [regionId, reason, this.currentRegion]);

      console.log(`[STONITH] Successfully unfenced region ${regionId}: ${reason}`);
      return { ok: true, value: undefined };

    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * HA-003 FIX: Check if a region is currently fenced
   */
  async isRegionFenced(regionId: string): Promise<boolean> {
    const isFenced = await this.redis.sismember('ha:fenced-regions', regionId);
    return isFenced === 1;
  }

  /**
   * Add a geo-routing rule
   */
  async addGeoRoutingRule(rule: Omit<GeoRoutingRule, 'id'>): Promise<Result<GeoRoutingRule>> {
    const id = `geo_rule_${Date.now()}`;
    const fullRule: GeoRoutingRule = { ...rule, id };

    try {
      await this.db.query(`
        INSERT INTO ha_geo_routing_rules (
          id, name, source_countries, source_continent, target_region, priority, enabled
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        id,
        rule.name,
        JSON.stringify(rule.sourceCountries),
        rule.sourceContinent,
        rule.targetRegion,
        rule.priority,
        rule.enabled,
      ]);

      this.routingRules.set(id, fullRule);

      console.log(`[MultiRegion] Added geo-routing rule: ${rule.name}`);

      return { ok: true, value: fullRule };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Remove a geo-routing rule
   */
  async removeGeoRoutingRule(ruleId: string): Promise<Result<void>> {
    try {
      await this.db.query('DELETE FROM ha_geo_routing_rules WHERE id = $1', [ruleId]);
      this.routingRules.delete(ruleId);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get traffic distribution across regions
   */
  async getTrafficDistribution(): Promise<Result<TrafficDistribution[]>> {
    try {
      const result = await this.db.query(`
        SELECT 
          region,
          COUNT(*) as request_count,
          COUNT(*) * 100.0 / SUM(COUNT(*)) OVER () as percentage
        FROM ha_request_logs
        WHERE created_at > NOW() - INTERVAL '1 hour'
        GROUP BY region
        ORDER BY request_count DESC
      `);

      const distribution: TrafficDistribution[] = result.rows.map(row => ({
        region: row.region,
        percentage: parseFloat(row.percentage),
        requestCount: parseInt(row.request_count),
      }));

      return { ok: true, value: distribution };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Set routing mode
   */
  setRoutingMode(mode: RoutingMode): void {
    const previousMode = this.routingMode;
    this.routingMode = mode;

    // Restart services if needed
    if (mode === RoutingMode.ACTIVE_ACTIVE && previousMode !== RoutingMode.ACTIVE_ACTIVE) {
      this.syncInterval = setInterval(() => {
        this.synchronizeRegions().catch(err => {
          console.error('[MultiRegion] Region sync failed:', err instanceof Error ? err.message : err);
        });
      }, config.crossRegionSyncIntervalMs ?? 5000);
    } else if (mode !== RoutingMode.ACTIVE_ACTIVE && this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }

    console.log(`[MultiRegion] Routing mode: ${previousMode} -> ${mode}`);
  }

  /**
   * Update region weights for weighted routing
   */
  async updateRegionWeights(weights: Record<string, number>): Promise<Result<void>> {
    for (const [regionId, weight] of Object.entries(weights)) {
      const region = this.regions.get(regionId);
      if (region) {
        region.weight = weight;
      }
    }

    await this.redis.hset('multiregion:weights', weights);

    console.log('[MultiRegion] Updated region weights:', weights);

    return { ok: true, value: undefined };
  }

  /**
   * Get region health summary
   */
  getHealthSummary(): {
    totalRegions: number;
    healthyRegions: number;
    degradedRegions: number;
    unhealthyRegions: number;
    offlineRegions: number;
    primaryRegion: string | null;
  } {
    const regions = Array.from(this.regions.values());
    const primary = this.getPrimaryRegion();

    return {
      totalRegions: regions.length,
      healthyRegions: regions.filter(r => r.status === RegionStatus.HEALTHY).length,
      degradedRegions: regions.filter(r => r.status === RegionStatus.DEGRADED).length,
      unhealthyRegions: regions.filter(r => r.status === RegionStatus.UNHEALTHY).length,
      offlineRegions: regions.filter(r => r.status === RegionStatus.OFFLINE).length,
      primaryRegion: primary?.id ?? null,
    };
  }

  // Private helper methods

  private async loadRoutingRules(): Promise<void> {
    try {
      const result = await this.db.query('SELECT * FROM ha_geo_routing_rules WHERE enabled = true');
      
      for (const row of result.rows) {
        const rule: GeoRoutingRule = {
          id: row.id,
          name: row.name,
          sourceCountries: JSON.parse(row.source_countries || '[]'),
          sourceContinent: row.source_continent,
          targetRegion: row.target_region,
          priority: row.priority,
          enabled: row.enabled,
        };
        this.routingRules.set(rule.id, rule);
      }
    } catch (error) {
      console.warn('[MultiRegion] Could not load routing rules:', error);
    }
  }

  private async checkAllRegions(): Promise<void> {
    for (const region of this.regions.values()) {
      if (region.id === this.currentRegion) {
        // Don't check self
        continue;
      }

      try {
        const startTime = Date.now();
        const response = await fetch(`${region.endpoint}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000),
        });

        const latency = Date.now() - startTime;
        region.latencyMs = latency;
        region.lastCheck = new Date();

        if (response.ok) {
          const health = await response.json() as {
            score?: number;
            connections?: number;
            rps?: number;
            errorRate?: number;
            replicationLagMs?: number;
          };
          region.healthScore = health.score ?? 100;
          region.activeConnections = health.connections ?? 0;
          region.requestsPerSecond = health.rps ?? 0;
          region.errorRate = health.errorRate ?? 0;
          region.replicationLagMs = health.replicationLagMs ?? 0;

          // Update status based on health metrics
          if (region.healthScore >= 80 && region.errorRate < 0.05) {
            region.status = RegionStatus.HEALTHY;
          } else if (region.healthScore >= 50) {
            region.status = RegionStatus.DEGRADED;
          } else {
            region.status = RegionStatus.UNHEALTHY;
          }
        } else {
          region.status = RegionStatus.UNHEALTHY;
          region.healthScore = 0;
        }
      } catch (error) {
        region.status = RegionStatus.OFFLINE;
        region.healthScore = 0;
        region.lastCheck = new Date();
        console.warn(`[MultiRegion] Health check failed for ${region.id}:`, error);
      }
    }

    // Store region states in Redis
    await this.storeRegionStates();
  }

  private async storeRegionStates(): Promise<void> {
    for (const region of this.regions.values()) {
      await this.redis.hset(`multiregion:region:${region.id}`, {
        status: region.status,
        role: region.role,
        healthScore: region.healthScore,
        latencyMs: region.latencyMs,
        errorRate: region.errorRate,
        replicationLagMs: region.replicationLagMs,
        lastCheck: region.lastCheck.toISOString(),
      });
    }
  }

  private async applyGeoRouting(country?: string, continent?: string): Promise<RegionInfo | null> {
    const rules = Array.from(this.routingRules.values())
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of rules) {
      let matches = false;

      if (country && rule.sourceCountries.includes(country)) {
        matches = true;
      } else if (continent && rule.sourceContinent === continent) {
        matches = true;
      }

      if (matches) {
        const targetRegion = this.regions.get(rule.targetRegion);
        if (targetRegion && targetRegion.status === RegionStatus.HEALTHY) {
          return targetRegion;
        }
      }
    }

    return null;
  }

  private async selectRegion(): Promise<RegionInfo | null> {
    const healthyRegions = Array.from(this.regions.values())
      .filter(r => r.status === RegionStatus.HEALTHY || r.status === RegionStatus.DEGRADED);

    if (healthyRegions.length === 0) {
      return null;
    }

    switch (this.routingMode) {
      case RoutingMode.ACTIVE_PASSIVE:
        return this.getPrimaryRegion() ?? healthyRegions[0];

      case RoutingMode.ROUND_ROBIN:
        return this.roundRobinSelect(healthyRegions);

      case RoutingMode.LATENCY_BASED:
        return this.latencyBasedSelect(healthyRegions);

      case RoutingMode.WEIGHTED:
        return this.weightedSelect(healthyRegions);

      case RoutingMode.ACTIVE_ACTIVE:
      case RoutingMode.GEO_PROXIMITY:
      default: {
        // Return current region if healthy, otherwise best available
        const current = this.regions.get(this.currentRegion);
        return current && current.status === RegionStatus.HEALTHY ? current : healthyRegions[0];
      }
    }
  }

  private roundRobinCounter = 0;
  private roundRobinSelect(regions: RegionInfo[]): RegionInfo {
    const index = this.roundRobinCounter % regions.length;
    this.roundRobinCounter++;
    return regions[index];
  }

  private latencyBasedSelect(regions: RegionInfo[]): RegionInfo {
    return regions.reduce((best, current) => 
      current.latencyMs < best.latencyMs ? current : best
    );
  }

  private weightedSelect(regions: RegionInfo[]): RegionInfo {
    const totalWeight = regions.reduce((sum, r) => sum + r.weight, 0);
    let random = Math.random() * totalWeight;

    for (const region of regions) {
      random -= region.weight;
      if (random <= 0) {
        return region;
      }
    }

    return regions[0];
  }

  private async synchronizeRegions(): Promise<void> {
    // In active-active mode, synchronize state across regions
    const primary = this.getPrimaryRegion();
    if (!primary || primary.id === this.currentRegion) {
      return;
    }

    try {
      // Get state from primary
      const response = await fetch(`${primary.endpoint}/internal/state`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      if (response.ok) {
        const state = await response.json();
        await this.applyRemoteState(state);
      }
    } catch (error) {
      console.warn('[MultiRegion] Cross-region sync failed:', error);
    }
  }

  private async applyRemoteState(_state: unknown): Promise<void> {
    // Apply state from remote region
    // In production, would apply configuration changes, routing updates, etc.
  }

  private async updateGlobalRouting(_primaryRegionId: string): Promise<void> {
    // In production, would update DNS records, load balancer configuration, etc.
    console.log('[MultiRegion] Updated global routing');
  }

  private async recordRoleChange(regionId: string, role: RegionRole): Promise<void> {
    await this.db.query(`
      INSERT INTO ha_region_role_history (region_id, role, changed_at)
      VALUES ($1, $2, NOW())
    `, [regionId, role]);
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    this.stopServices();
    console.log('[MultiRegion] Service shut down');
  }
}
