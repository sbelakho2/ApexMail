/**
 * API Configuration
 * 
 * Uses Zod for schema validation to catch configuration errors at startup.
 */

import { z } from 'zod';

// Zod schema for environment validation
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'staging', 'production']).default('development'),
  PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default('3000'),
  HOST: z.string().default('0.0.0.0'),
  BASE_URL: z.string().url().default('http://localhost:3000'),
  
  // Database
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default('5432'),
  DB_NAME: z.string().default('apexmail'),
  DB_USER: z.string().default('apexmail'),
  DB_PASSWORD: z.string().default('apexmail'),
  
  // Redis
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default('6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).pipe(z.number().min(0)).default('0'),
  
  // Auth - conditional validation based on NODE_ENV
  JWT_SECRET: z.string().min(1),
  JWT_EXPIRY: z.string().default('24h'),
  API_KEY_HASH_SECRET: z.string().min(1),
  
  // Rate limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).pipe(z.number().min(1)).default('60000'),
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).pipe(z.number().min(1)).default('1000'),
  
  // CORS
  CORS_ORIGINS: z.string().default('*'),
  CORS_CREDENTIALS: z.enum(['true', 'false', '1', '0']).default('true'),
  
  // Trusted proxies (comma-separated IPs/CIDRs that are allowed to set X-Forwarded-For)
  TRUSTED_PROXIES: z.string().default('127.0.0.1,::1'),
  
  // Idempotency
  IDEMPOTENCY_TTL_SECONDS: z.string().transform(Number).pipe(z.number().min(1)).default('86400'),
  
  // Webhooks
  WEBHOOK_SIGNING_SECRET: z.string().min(1),
  WEBHOOK_TIMEOUT_MS: z.string().transform(Number).pipe(z.number().min(1000)).default('30000'),
  WEBHOOK_MAX_RETRIES: z.string().transform(Number).pipe(z.number().min(0).max(10)).default('5'),
});

export type ValidatedEnv = z.infer<typeof envSchema>;

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
  
  trustedProxies: string[];
  
  idempotency: {
    ttlSeconds: number;
  };

  webhooks: {
    signingSecret: string;
    timeoutMs: number;
    maxRetries: number;
  };
}

export function loadConfig(): Config {
  // First, validate environment with Zod schema
  const devDefaults: Record<string, string> = {
    JWT_SECRET: 'dev-secret-change-in-production',
    API_KEY_HASH_SECRET: 'dev-api-secret',
    WEBHOOK_SIGNING_SECRET: 'dev-webhook-secret',
  };
  
  const isDev = (process.env.NODE_ENV ?? 'development') === 'development';
  
  // Apply dev defaults only in development mode
  const envToValidate = { ...process.env };
  if (isDev) {
    for (const [key, value] of Object.entries(devDefaults)) {
      if (!envToValidate[key]) {
        envToValidate[key] = value;
      }
    }
  }
  
  // Validate with Zod - this will throw with detailed errors on invalid config
  const result = envSchema.safeParse(envToValidate);
  if (!result.success) {
    const errors = result.error.issues
      .map(issue => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Configuration validation failed:\n${errors}`);
  }
  
  const validated = result.data;
  const env = validated.NODE_ENV;
  
  // SECURITY: Additional validation for production secrets
  if (!isDev) {
    // SECURITY FIX: Reject wildcard CORS origin in production
    if (validated.CORS_ORIGINS === '*') {
      throw new Error(
        'SECURITY: CORS_ORIGINS cannot be "*" in production. ' +
        'Set CORS_ORIGINS to a comma-separated list of allowed origins (e.g., "https://app.apexmail.com,https://admin.apexmail.com").'
      );
    }

    const devDefaultValues = Object.values(devDefaults);
    
    if (devDefaultValues.includes(validated.JWT_SECRET)) {
      throw new Error('SECURITY: JWT_SECRET is using a development default value in production!');
    }
    if (devDefaultValues.includes(validated.API_KEY_HASH_SECRET)) {
      throw new Error('SECURITY: API_KEY_HASH_SECRET is using a development default value in production!');
    }
    if (devDefaultValues.includes(validated.WEBHOOK_SIGNING_SECRET)) {
      throw new Error('SECURITY: WEBHOOK_SIGNING_SECRET is using a development default value in production!');
    }
    
    // Ensure secrets meet minimum length requirements
    if (validated.JWT_SECRET.length < 32) {
      throw new Error('SECURITY: JWT_SECRET must be at least 32 characters in production');
    }
    if (validated.API_KEY_HASH_SECRET.length < 32) {
      throw new Error('SECURITY: API_KEY_HASH_SECRET must be at least 32 characters in production');
    }
    if (validated.WEBHOOK_SIGNING_SECRET.length < 32) {
      throw new Error('SECURITY: WEBHOOK_SIGNING_SECRET must be at least 32 characters in production');
    }
  }
  
  return {
    env,
    port: validated.PORT,
    host: validated.HOST,
    baseUrl: validated.BASE_URL,
    
    database: {
      host: validated.DB_HOST,
      port: validated.DB_PORT,
      name: validated.DB_NAME,
      user: validated.DB_USER,
      password: validated.DB_PASSWORD,
    },
    
    redis: {
      host: validated.REDIS_HOST,
      port: validated.REDIS_PORT,
      password: validated.REDIS_PASSWORD,
      db: validated.REDIS_DB,
    },
    
    auth: {
      jwtSecret: validated.JWT_SECRET,
      jwtExpiry: validated.JWT_EXPIRY,
      apiKeyHashSecret: validated.API_KEY_HASH_SECRET,
    },
    
    rateLimit: {
      windowMs: validated.RATE_LIMIT_WINDOW_MS,
      maxRequests: validated.RATE_LIMIT_MAX_REQUESTS,
    },
    
    cors: {
      origins: validated.CORS_ORIGINS.split(',').map(s => s.trim()),
      credentials: validated.CORS_CREDENTIALS === 'true' || validated.CORS_CREDENTIALS === '1',
    },
    
    trustedProxies: validated.TRUSTED_PROXIES.split(',').map(s => s.trim()).filter(Boolean),
    
    idempotency: {
      ttlSeconds: validated.IDEMPOTENCY_TTL_SECONDS,
    },

    webhooks: {
      signingSecret: validated.WEBHOOK_SIGNING_SECRET,
      timeoutMs: validated.WEBHOOK_TIMEOUT_MS,
      maxRetries: validated.WEBHOOK_MAX_RETRIES,
    },
  };
}
