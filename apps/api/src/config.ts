/**
 * API Configuration
 */

export interface Config {
  env: 'development' | 'staging' | 'production';
  port: number;
  host: string;
  baseUrl: string;
  
  database: {
    host: string;
    port: number;
    name: string;
    user: string;
    password: string;
  };
  
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
  };
  
  auth: {
    jwtSecret: string;
    jwtExpiry: string;
    apiKeyHashSecret: string;
  };
  
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
  
  cors: {
    origins: string[];
    credentials: boolean;
  };
  
  idempotency: {
    ttlSeconds: number;
  };

  webhooks: {
    signingSecret: string;
    timeoutMs: number;
    maxRetries: number;
  };
}

function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key] ?? defaultValue;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function getEnvInt(key: string, defaultValue?: number): number {
  const value = process.env[key];
  if (value === undefined) {
    if (defaultValue === undefined) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
    return defaultValue;
  }
  const parsed = parseInt(value, 10);
  if (isNaN(parsed)) {
    throw new Error(`Invalid integer value for ${key}: ${value}`);
  }
  return parsed;
}

function getEnvBool(key: string, defaultValue: boolean): boolean {
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

export function loadConfig(): Config {
  const env = getEnv('NODE_ENV', 'development') as Config['env'];
  
  return {
    env,
    port: getEnvInt('PORT', 3000),
    host: getEnv('HOST', '0.0.0.0'),
    baseUrl: getEnv('BASE_URL', 'http://localhost:3000'),
    
    database: {
      host: getEnv('DB_HOST', 'localhost'),
      port: getEnvInt('DB_PORT', 5432),
      name: getEnv('DB_NAME', 'apexmail'),
      user: getEnv('DB_USER', 'apexmail'),
      password: getEnv('DB_PASSWORD', 'apexmail'),
    },
    
    redis: {
      host: getEnv('REDIS_HOST', 'localhost'),
      port: getEnvInt('REDIS_PORT', 6379),
      password: process.env.REDIS_PASSWORD,
      db: getEnvInt('REDIS_DB', 0),
    },
    
    auth: {
      jwtSecret: getEnv('JWT_SECRET', env === 'development' ? 'dev-secret-change-in-production' : undefined),
      jwtExpiry: getEnv('JWT_EXPIRY', '24h'),
      apiKeyHashSecret: getEnv('API_KEY_HASH_SECRET', env === 'development' ? 'dev-api-secret' : undefined),
    },
    
    rateLimit: {
      windowMs: getEnvInt('RATE_LIMIT_WINDOW_MS', 60000),
      maxRequests: getEnvInt('RATE_LIMIT_MAX_REQUESTS', 1000),
    },
    
    cors: {
      origins: getEnv('CORS_ORIGINS', '*').split(',').map(s => s.trim()),
      credentials: getEnvBool('CORS_CREDENTIALS', true),
    },
    
    idempotency: {
      ttlSeconds: getEnvInt('IDEMPOTENCY_TTL_SECONDS', 86400), // 24 hours
    },

    webhooks: {
      signingSecret: getEnv('WEBHOOK_SIGNING_SECRET', env === 'development' ? 'dev-webhook-secret' : undefined),
      timeoutMs: getEnvInt('WEBHOOK_TIMEOUT_MS', 30000),
      maxRetries: getEnvInt('WEBHOOK_MAX_RETRIES', 5),
    },
  };
}
