/**
 * Analytics Service Configuration
 */

import { z } from 'zod';

const configSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  
  database: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().default(5432),
    database: z.string().default('apexmail'),
    user: z.string().default('apexmail'),
    password: z.string().default(''),
    // 50 connections for 1000 tenants — Postgres can handle ~200 with proper pooling
    maxConnections: z.coerce.number().default(50),
  }),
  
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().default(6379),
    password: z.string().optional(),
    db: z.coerce.number().default(0),
  }),
  
  storage: z.object({
    // Base path for parquet files
    basePath: z.string().default('/var/lib/apexmail/analytics'),
    // S3-compatible endpoint (MinIO) for offsite storage
    s3Endpoint: z.string().optional(),
    s3Bucket: z.string().default('apexmail-analytics'),
    s3AccessKey: z.string().optional(),
    s3SecretKey: z.string().optional(),
    s3Region: z.string().default('us-east-1'),
  }),
  
  duckdb: z.object({
    // Path to DuckDB database file
    dbPath: z.string().default('/var/lib/apexmail/analytics/analytics.duckdb'),
    // Memory limit for DuckDB — default 32GB for EX44 (160GB RAM) with ~1000 tenants
    // DuckDB uses memory-mapped I/O, so allocating 20% of RAM is safe.
    memoryLimit: z.string().default('32GB'),
    // Number of threads — EX44 has AMD Ryzen 9 7950X (16c/32t); leave 8 threads for Postgres/Redis/Node
    threads: z.coerce.number().default(24),
  }),
  
  compaction: z.object({
    // Enable automatic compaction
    enabled: z.boolean().default(true),
    // Schedule (cron expression)
    schedule: z.string().default('0 2 * * *'), // 2 AM daily
    // Retention period in days for hot data
    hotRetentionDays: z.coerce.number().default(90),
    // Retention period in days for cold data
    coldRetentionDays: z.coerce.number().default(365 * 2), // 2 years
    // Batch size for compaction — larger batches for EX44 with ample RAM
    batchSize: z.coerce.number().default(100000),
  }),
  
  reconciliation: z.object({
    // Enable nightly reconciliation
    enabled: z.boolean().default(true),
    // Schedule (cron expression)
    schedule: z.string().default('0 3 * * *'), // 3 AM daily
  }),
  
  logging: z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    format: z.enum(['json', 'pretty']).default('json'),
  }),
});

function loadConfig() {
  const raw = {
    env: process.env.NODE_ENV,
    
    database: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      maxConnections: process.env.DB_MAX_CONNECTIONS,
    },
    
    redis: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD,
      db: process.env.REDIS_DB,
    },
    
    storage: {
      basePath: process.env.ANALYTICS_STORAGE_PATH,
      s3Endpoint: process.env.ANALYTICS_S3_ENDPOINT,
      s3Bucket: process.env.ANALYTICS_S3_BUCKET,
      s3AccessKey: process.env.ANALYTICS_S3_ACCESS_KEY,
      s3SecretKey: process.env.ANALYTICS_S3_SECRET_KEY,
      s3Region: process.env.ANALYTICS_S3_REGION,
    },
    
    duckdb: {
      dbPath: process.env.DUCKDB_PATH,
      memoryLimit: process.env.DUCKDB_MEMORY_LIMIT,
      threads: process.env.DUCKDB_THREADS,
    },
    
    compaction: {
      enabled: process.env.ANALYTICS_COMPACTION_ENABLED !== 'false',
      schedule: process.env.ANALYTICS_COMPACTION_SCHEDULE,
      hotRetentionDays: process.env.ANALYTICS_HOT_RETENTION_DAYS,
      coldRetentionDays: process.env.ANALYTICS_COLD_RETENTION_DAYS,
      batchSize: process.env.ANALYTICS_COMPACTION_BATCH_SIZE,
    },
    
    reconciliation: {
      enabled: process.env.ANALYTICS_RECONCILIATION_ENABLED !== 'false',
      schedule: process.env.ANALYTICS_RECONCILIATION_SCHEDULE,
    },
    
    logging: {
      level: process.env.LOG_LEVEL,
      format: process.env.LOG_FORMAT,
    },
  };
  
  const result = configSchema.safeParse(raw);
  
  if (!result.success) {
    console.error('Configuration validation failed:');
    for (const error of result.error.errors) {
      console.error(`  ${error.path.join('.')}: ${error.message}`);
    }
    process.exit(1);
  }
  
  return result.data;
}

export const config = loadConfig();
export type Config = z.infer<typeof configSchema>;
