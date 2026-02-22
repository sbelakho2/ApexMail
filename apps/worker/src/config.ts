/**
 * Worker Configuration
 * 
 * Uses Zod for schema validation to catch configuration errors at startup.
 */

import { z } from 'zod';

// Helper for number parsing from env strings
const envNumber = (defaultValue: number) => 
  z.string().transform(Number).pipe(z.number()).default(String(defaultValue));

const envBoolean = (defaultValue: boolean) =>
  z.enum(['true', 'false', '1', '0']).transform((v: string) => v === 'true' || v === '1').default(defaultValue ? 'true' : 'false');

// Zod schema for environment validation
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'staging', 'production']).default('development'),
  WORKER_ID: z.string().optional(),
  
  // Database
  DATABASE_URL: z.string().url(),
  DATABASE_MAX_CONNECTIONS: envNumber(10),
  
  // Redis
  REDIS_URL: z.string().url().default('redis://localhost:6379'),
  REDIS_KEY_PREFIX: z.string().default('apexmail:'),
  
  // Email Queue
  EMAIL_QUEUE_NAME: z.string().default('email:send'),
  EMAIL_QUEUE_CONCURRENCY: envNumber(10),
  EMAIL_QUEUE_POLL_INTERVAL: envNumber(1000),
  EMAIL_QUEUE_VISIBILITY_TIMEOUT: envNumber(300000),
  EMAIL_QUEUE_MAX_RETRIES: envNumber(3),
  EMAIL_QUEUE_RETRY_DELAY: envNumber(60000),
  
  // Webhook Queue
  WEBHOOK_QUEUE_NAME: z.string().default('webhook:deliver'),
  WEBHOOK_QUEUE_CONCURRENCY: envNumber(5),
  WEBHOOK_QUEUE_POLL_INTERVAL: envNumber(1000),
  WEBHOOK_QUEUE_MAX_RETRIES: envNumber(5),
  WEBHOOK_QUEUE_RETRY_DELAY: envNumber(30000),
  
  // Analytics Queue
  ANALYTICS_QUEUE_NAME: z.string().default('analytics:events'),
  ANALYTICS_QUEUE_CONCURRENCY: envNumber(2),
  ANALYTICS_QUEUE_POLL_INTERVAL: envNumber(5000),
  ANALYTICS_BATCH_SIZE: envNumber(100),
  ANALYTICS_FLUSH_INTERVAL: envNumber(10000),
  
  // SMTP
  SMTP_HOST: z.string().default('localhost'),
  SMTP_PORT: envNumber(25),
  SMTP_SECURE: envBoolean(false),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_POOL: envBoolean(true),
  SMTP_MAX_CONNECTIONS: envNumber(5),
  SMTP_MAX_MESSAGES: envNumber(100),
  SMTP_RATE_LIMIT: envNumber(10),
  
  // Email Transport (smtp | ses)
  EMAIL_TRANSPORT: z.enum(['smtp', 'ses']).default('smtp'),
  
  // AWS SES (only used when EMAIL_TRANSPORT=ses)
  AWS_REGION: z.string().default('us-east-1'),
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  SES_CONFIGURATION_SET: z.string().optional(),
  
  // DKIM
  DKIM_ENABLED: envBoolean(true),
  DKIM_SELECTOR: z.string().default('apexmail'),
  DKIM_KEY_PATH: z.string().optional(),
  
  // Tracking
  TRACKING_ENABLED: envBoolean(true),
  TRACKING_BASE_URL: z.string().url().default('https://track.example.com'),
  TRACKING_OPEN_PATH: z.string().default('/o'),
  TRACKING_CLICK_PATH: z.string().default('/c'),
  
  // Warmup
  WARMUP_ENABLED: envBoolean(false),
  WARMUP_SCHEDULE: z.string().optional(),
  
  // IP Rate Limiting
  IP_RATE_LIMITING_ENABLED: envBoolean(true),
  SENDING_IP_ADDRESS: z.string().optional(), // The IP address this worker sends from
  IP_HOURLY_LIMIT: envNumber(2500), // Default: 2500/hour per IP (60K/day max)
  IP_BURST_LIMIT: envNumber(50), // Allow bursts of 50 concurrent
  
  // Metrics
  METRICS_ENABLED: envBoolean(true),
  METRICS_PORT: envNumber(9090),
  
  // Shutdown
  GRACEFUL_SHUTDOWN_TIMEOUT: envNumber(30000),
});

export type ValidatedEnv = z.infer<typeof envSchema>;

export interface WorkerConfig {
  nodeEnv: string;
  workerId: string;
  
  database: {
    connectionString: string;
    maxConnections: number;
  };
  
  redis: {
    url: string;
    keyPrefix: string;
  };
  
  queues: {
    email: {
      name: string;
      concurrency: number;
      pollInterval: number;
      visibilityTimeout: number;
      maxRetries: number;
      retryDelay: number;
    };
    webhook: {
      name: string;
      concurrency: number;
      pollInterval: number;
      maxRetries: number;
      retryDelay: number;
    };
    analytics: {
      name: string;
      concurrency: number;
      pollInterval: number;
      batchSize: number;
      flushInterval: number;
    };
  };
  
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    auth?: {
      user: string;
      pass: string;
    };
    pool: boolean;
    maxConnections: number;
    maxMessages: number;
    rateLimitPerSecond: number;
  };
  
  emailTransport: 'smtp' | 'ses';
  
  ses: {
    region: string;
    accessKeyId?: string;
    secretAccessKey?: string;
    configurationSetName?: string;
  };
  
  dkim: {
    enabled: boolean;
    selector: string;
    keyPath?: string;
  };
  
  tracking: {
    enabled: boolean;
    baseUrl: string;
    openPixelPath: string;
    clickRedirectPath: string;
  };
  
  warmup: {
    enabled: boolean;
    schedule: Record<string, number[]>; // domain -> daily limits
  };
  
  ipRateLimiting: {
    enabled: boolean;
    ipAddress?: string;      // The IP this worker sends from
    hourlyLimit: number;     // Emails per hour per IP
    burstLimit: number;      // Max concurrent burst
  };
  
  metrics: {
    enabled: boolean;
    port: number;
  };
  
  gracefulShutdownTimeout: number;
}

// parseJSON is used for WARMUP_SCHEDULE parsing
function parseJSON<T>(value: string | undefined, defaultValue: T): T {
  if (!value) return defaultValue;
  try {
    return JSON.parse(value) as T;
  } catch {
    console.warn(`Invalid JSON in config: ${value.substring(0, 50)}...`);
    return defaultValue;
  }
}

export function loadConfig(): WorkerConfig {
  // Validate all environment variables with Zod
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const errors = result.error.issues
      .map(issue => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Worker configuration validation failed:\n${errors}`);
  }
  
  const env = result.data;
  
  return {
    nodeEnv: env.NODE_ENV,
    workerId: env.WORKER_ID ?? `worker-${process.pid}`,
    
    database: {
      connectionString: env.DATABASE_URL,
      maxConnections: env.DATABASE_MAX_CONNECTIONS,
    },
    
    redis: {
      url: env.REDIS_URL,
      keyPrefix: env.REDIS_KEY_PREFIX,
    },
    
    queues: {
      email: {
        name: env.EMAIL_QUEUE_NAME,
        concurrency: env.EMAIL_QUEUE_CONCURRENCY,
        pollInterval: env.EMAIL_QUEUE_POLL_INTERVAL,
        visibilityTimeout: env.EMAIL_QUEUE_VISIBILITY_TIMEOUT,
        maxRetries: env.EMAIL_QUEUE_MAX_RETRIES,
        retryDelay: env.EMAIL_QUEUE_RETRY_DELAY,
      },
      webhook: {
        name: env.WEBHOOK_QUEUE_NAME,
        concurrency: env.WEBHOOK_QUEUE_CONCURRENCY,
        pollInterval: env.WEBHOOK_QUEUE_POLL_INTERVAL,
        maxRetries: env.WEBHOOK_QUEUE_MAX_RETRIES,
        retryDelay: env.WEBHOOK_QUEUE_RETRY_DELAY,
      },
      analytics: {
        name: env.ANALYTICS_QUEUE_NAME,
        concurrency: env.ANALYTICS_QUEUE_CONCURRENCY,
        pollInterval: env.ANALYTICS_QUEUE_POLL_INTERVAL,
        batchSize: env.ANALYTICS_BATCH_SIZE,
        flushInterval: env.ANALYTICS_FLUSH_INTERVAL,
      },
    },
    
    smtp: {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      auth: env.SMTP_USER ? {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS ?? '',
      } : undefined,
      pool: env.SMTP_POOL,
      maxConnections: env.SMTP_MAX_CONNECTIONS,
      maxMessages: env.SMTP_MAX_MESSAGES,
      rateLimitPerSecond: env.SMTP_RATE_LIMIT,
    },
    
    emailTransport: env.EMAIL_TRANSPORT,
    
    ses: {
      region: env.AWS_REGION,
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      configurationSetName: env.SES_CONFIGURATION_SET,
    },
    
    dkim: {
      enabled: env.DKIM_ENABLED,
      selector: env.DKIM_SELECTOR,
      keyPath: env.DKIM_KEY_PATH,
    },
    
    tracking: {
      enabled: env.TRACKING_ENABLED,
      baseUrl: env.TRACKING_BASE_URL,
      openPixelPath: env.TRACKING_OPEN_PATH,
      clickRedirectPath: env.TRACKING_CLICK_PATH,
    },
    
    warmup: {
      enabled: env.WARMUP_ENABLED,
      schedule: parseJSON(env.WARMUP_SCHEDULE, {}),
    },
    
    ipRateLimiting: {
      enabled: env.IP_RATE_LIMITING_ENABLED,
      ipAddress: env.SENDING_IP_ADDRESS,
      hourlyLimit: env.IP_HOURLY_LIMIT,
      burstLimit: env.IP_BURST_LIMIT,
    },
    
    metrics: {
      enabled: env.METRICS_ENABLED,
      port: env.METRICS_PORT,
    },
    
    gracefulShutdownTimeout: env.GRACEFUL_SHUTDOWN_TIMEOUT,
  };
}
