/**
 * Worker Configuration
 */

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
  
  metrics: {
    enabled: boolean;
    port: number;
  };
  
  gracefulShutdownTimeout: number;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parseNumber(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

export function loadConfig(): WorkerConfig {
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  
  return {
    nodeEnv,
    workerId: process.env.WORKER_ID ?? `worker-${process.pid}`,
    
    database: {
      connectionString: requireEnv('DATABASE_URL'),
      maxConnections: parseNumber(process.env.DATABASE_MAX_CONNECTIONS, 10),
    },
    
    redis: {
      url: process.env.REDIS_URL ?? 'redis://localhost:6379',
      keyPrefix: process.env.REDIS_KEY_PREFIX ?? 'apexmail:',
    },
    
    queues: {
      email: {
        name: process.env.EMAIL_QUEUE_NAME ?? 'email:send',
        concurrency: parseNumber(process.env.EMAIL_QUEUE_CONCURRENCY, 10),
        pollInterval: parseNumber(process.env.EMAIL_QUEUE_POLL_INTERVAL, 1000),
        visibilityTimeout: parseNumber(process.env.EMAIL_QUEUE_VISIBILITY_TIMEOUT, 300000), // 5 min
        maxRetries: parseNumber(process.env.EMAIL_QUEUE_MAX_RETRIES, 3),
        retryDelay: parseNumber(process.env.EMAIL_QUEUE_RETRY_DELAY, 60000), // 1 min
      },
      webhook: {
        name: process.env.WEBHOOK_QUEUE_NAME ?? 'webhook:deliver',
        concurrency: parseNumber(process.env.WEBHOOK_QUEUE_CONCURRENCY, 5),
        pollInterval: parseNumber(process.env.WEBHOOK_QUEUE_POLL_INTERVAL, 1000),
        maxRetries: parseNumber(process.env.WEBHOOK_QUEUE_MAX_RETRIES, 5),
        retryDelay: parseNumber(process.env.WEBHOOK_QUEUE_RETRY_DELAY, 30000),
      },
      analytics: {
        name: process.env.ANALYTICS_QUEUE_NAME ?? 'analytics:events',
        concurrency: parseNumber(process.env.ANALYTICS_QUEUE_CONCURRENCY, 2),
        pollInterval: parseNumber(process.env.ANALYTICS_QUEUE_POLL_INTERVAL, 5000),
        batchSize: parseNumber(process.env.ANALYTICS_BATCH_SIZE, 100),
        flushInterval: parseNumber(process.env.ANALYTICS_FLUSH_INTERVAL, 10000),
      },
    },
    
    smtp: {
      host: process.env.SMTP_HOST ?? 'localhost',
      port: parseNumber(process.env.SMTP_PORT, 25),
      secure: parseBoolean(process.env.SMTP_SECURE, false),
      auth: process.env.SMTP_USER ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS ?? '',
      } : undefined,
      pool: parseBoolean(process.env.SMTP_POOL, true),
      maxConnections: parseNumber(process.env.SMTP_MAX_CONNECTIONS, 5),
      maxMessages: parseNumber(process.env.SMTP_MAX_MESSAGES, 100),
      rateLimitPerSecond: parseNumber(process.env.SMTP_RATE_LIMIT, 10),
    },
    
    dkim: {
      enabled: parseBoolean(process.env.DKIM_ENABLED, true),
      selector: process.env.DKIM_SELECTOR ?? 'apexmail',
      keyPath: process.env.DKIM_KEY_PATH,
    },
    
    tracking: {
      enabled: parseBoolean(process.env.TRACKING_ENABLED, true),
      baseUrl: process.env.TRACKING_BASE_URL ?? 'https://track.example.com',
      openPixelPath: process.env.TRACKING_OPEN_PATH ?? '/o',
      clickRedirectPath: process.env.TRACKING_CLICK_PATH ?? '/c',
    },
    
    warmup: {
      enabled: parseBoolean(process.env.WARMUP_ENABLED, false),
      schedule: process.env.WARMUP_SCHEDULE 
        ? JSON.parse(process.env.WARMUP_SCHEDULE)
        : {},
    },
    
    metrics: {
      enabled: parseBoolean(process.env.METRICS_ENABLED, true),
      port: parseNumber(process.env.METRICS_PORT, 9090),
    },
    
    gracefulShutdownTimeout: parseNumber(process.env.GRACEFUL_SHUTDOWN_TIMEOUT, 30000),
  };
}
