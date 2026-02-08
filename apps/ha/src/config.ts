/**
 * HA Service Configuration
 */

export interface RegionConfig {
  id: string;
  name: string;
  endpoint: string;
  role: 'primary' | 'secondary' | 'standby';
  weight: number;
}

export const config = {
  // Server
  port: parseInt(process.env.HA_PORT ?? '4300', 10),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  serviceName: 'apexmail-ha',
  version: process.env.VERSION ?? '1.0.0',
  environment: process.env.NODE_ENV ?? 'development',

  // Database (Primary)
  dbHost: process.env.DB_HOST ?? 'localhost',
  dbPort: parseInt(process.env.DB_PORT ?? '5432', 10),
  dbName: process.env.DB_NAME ?? 'apexmail',
  database: process.env.DB_NAME ?? 'apexmail',
  dbUser: process.env.DB_USER ?? 'apexmail',
  dbPassword: process.env.DB_PASSWORD ?? 'apexmail',
  dbPoolMax: parseInt(process.env.DB_POOL_MAX ?? '20', 10),
  dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT ?? '30000', 10),
  dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT ?? '3000', 10),

  // Database (Replica - Read)
  dbReplicaHost: process.env.DB_REPLICA_HOST,
  dbReplicaPort: parseInt(process.env.DB_REPLICA_PORT ?? '5432', 10),
  replicaHosts: (process.env.DB_REPLICA_HOSTS ?? '').split(',').filter(h => h),

  // Database (Standby - Failover)
  dbStandbyHost: process.env.DB_STANDBY_HOST,
  dbStandbyPort: parseInt(process.env.DB_STANDBY_PORT ?? '5432', 10),

  // Redis (Primary)
  redisHost: process.env.REDIS_HOST ?? 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  redisPassword: process.env.REDIS_PASSWORD,
  redisDb: parseInt(process.env.REDIS_DB ?? '0', 10),

  // Redis (Sentinel for HA)
  redisSentinels: process.env.REDIS_SENTINELS?.split(',').filter(s => s.includes(':')).map(s => {
    const [host, port] = s.split(':');
    return { host: host || 'localhost', port: parseInt(port ?? '26379', 10) || 26379 };
  }),
  redisSentinelMaster: process.env.REDIS_SENTINEL_MASTER ?? 'mymaster',

  // API Keys
  // FIX-500-028: Reject hardcoded default keys in production
  internalApiKey: (() => {
    const key = process.env.INTERNAL_API_KEY ?? 'internal-key';
    if (key === 'internal-key' && (process.env.NODE_ENV === 'production')) {
      throw new Error('INTERNAL_API_KEY must be set in production — default key is insecure');
    }
    return key;
  })(),
  adminApiKey: (() => {
    const key = process.env.ADMIN_API_KEY ?? 'admin-key';
    if (key === 'admin-key' && (process.env.NODE_ENV === 'production')) {
      throw new Error('ADMIN_API_KEY must be set in production — default key is insecure');
    }
    return key;
  })(),
  
  // CORS
  corsOrigins: (process.env.CORS_ORIGINS ?? '*').split(','),

  // Cluster Configuration
  clusterId: process.env.CLUSTER_ID ?? 'apexmail-cluster-1',
  nodeId: process.env.NODE_ID ?? `node-${process.pid}`,
  region: process.env.AWS_REGION ?? process.env.REGION ?? 'us-east-1',
  availabilityZone: process.env.AVAILABILITY_ZONE ?? 'us-east-1a',

  // Multi-Region
  regions: (process.env.REGIONS ?? 'us-east-1,us-west-2,eu-west-1').split(','),
  primaryRegion: process.env.PRIMARY_REGION ?? 'us-east-1',
  routingMode: (process.env.ROUTING_MODE ?? 'latency') as 'latency' | 'geolocation' | 'failover' | 'weighted',
  regionHealthCheckIntervalMs: parseInt(process.env.REGION_HEALTH_CHECK_INTERVAL ?? '10000', 10),
  crossRegionSyncIntervalMs: parseInt(process.env.CROSS_REGION_SYNC_INTERVAL ?? '30000', 10),

  // Backup Configuration
  backupEnabled: process.env.BACKUP_ENABLED !== 'false',
  backupBucket: process.env.BACKUP_BUCKET ?? 'apexmail-backups',
  backupRegion: process.env.BACKUP_REGION ?? 'us-east-1',
  backupRetentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS ?? '90', 10),
  backupEncryptionKey: (() => {
    const key = process.env.BACKUP_ENCRYPTION_KEY;
    if (!key && process.env.NODE_ENV === 'production' && process.env.BACKUP_ENABLED !== 'false') {
      throw new Error('BACKUP_ENCRYPTION_KEY must be set in production when backups are enabled');
    }
    return key;
  })(),

  // Backup Schedules
  fullBackupSchedule: process.env.FULL_BACKUP_SCHEDULE ?? '0 2 * * 0', // Weekly Sunday 2 AM
  incrementalBackupSchedule: process.env.INCREMENTAL_BACKUP_SCHEDULE ?? '0 2 * * *', // Daily 2 AM
  walArchiveInterval: parseInt(process.env.WAL_ARCHIVE_INTERVAL ?? '300', 10), // 5 minutes

  // Failover Configuration
  failoverEnabled: process.env.FAILOVER_ENABLED !== 'false',
  failoverThreshold: parseInt(process.env.FAILOVER_THRESHOLD ?? '3', 10),
  healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL ?? '5000', 10),
  healthCheckTimeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT ?? '3000', 10),
  failbackEnabled: process.env.FAILBACK_ENABLED !== 'false',
  failbackDelay: parseInt(process.env.FAILBACK_DELAY ?? '300000', 10), // 5 minutes

  // Replication Configuration
  replicationEnabled: process.env.REPLICATION_ENABLED !== 'false',
  replicationLagThreshold: parseInt(process.env.REPLICATION_LAG_THRESHOLD ?? '30000', 10), // 30 seconds
  syncReplication: process.env.SYNC_REPLICATION === 'true',
  maxReplicationLagMs: parseInt(process.env.MAX_REPLICATION_LAG_MS ?? '30000', 10),
  criticalLagThresholdMs: parseInt(process.env.CRITICAL_LAG_THRESHOLD_MS ?? '60000', 10),
  warningLagThresholdMs: parseInt(process.env.WARNING_LAG_THRESHOLD_MS ?? '10000', 10),

  // Circuit Breaker
  circuitBreakerEnabled: process.env.CIRCUIT_BREAKER_ENABLED !== 'false',
  circuitBreakerThreshold: parseInt(process.env.CIRCUIT_BREAKER_THRESHOLD ?? '5', 10),
  circuitBreakerTimeout: parseInt(process.env.CIRCUIT_BREAKER_TIMEOUT ?? '30000', 10),
  circuitBreakerResetTimeout: parseInt(process.env.CIRCUIT_BREAKER_RESET_TIMEOUT ?? '60000', 10),

  // Chaos Engineering
  chaosEnabled: process.env.CHAOS_ENABLED === 'true',
  chaosFailureRate: parseFloat(process.env.CHAOS_FAILURE_RATE ?? '0.01'),

  // Monitoring
  metricsEnabled: process.env.METRICS_ENABLED !== 'false',
  tracingEnabled: process.env.TRACING_ENABLED !== 'false',
  alertingWebhook: process.env.ALERTING_WEBHOOK,

  // Recovery Point Objective (RPO) and Recovery Time Objective (RTO)
  rpoTarget: parseInt(process.env.RPO_TARGET ?? '60', 10), // 60 seconds
  rtoTarget: parseInt(process.env.RTO_TARGET ?? '300', 10), // 5 minutes
};

export type Config = typeof config;
