/**
 * Tracking Service Configuration
 */

import { z } from 'zod';

const configSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  
  server: z.object({
    host: z.string().default('0.0.0.0'),
    port: z.coerce.number().default(3002),
  }),
  
  database: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().default(5432),
    database: z.string().default('apexmail'),
    user: z.string().default('apexmail'),
    password: z.string().default(''),
    maxConnections: z.coerce.number().default(25),
    idleTimeout: z.coerce.number().default(10000),
    connectionTimeout: z.coerce.number().default(5000),
  }),
  
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().default(6379),
    password: z.string().optional(),
    db: z.coerce.number().default(0),
  }),
  
  tracking: z.object({
    // Base URL for tracking redirects
    baseUrl: z.string().default('https://t.apexmail.ee'),
    
    // SECURITY: Trusted proxy IP ranges (CIDR notation)
    // Configure these based on your infrastructure (load balancers, CDN, etc.)
    // Only trust X-Forwarded-For headers from these IPs
    trustedProxies: z.array(z.string()).default([
      '127.0.0.0/8',      // Localhost
      '10.0.0.0/8',       // Private network (internal load balancers)
      '172.16.0.0/12',    // Private network
      '192.168.0.0/16',   // Private network
    ]),
    
    // Pixel configuration
    pixel: z.object({
      // Path prefix for open tracking
      path: z.string().default('/o'),
      // Cache-control headers
      cacheControl: z.string().default('no-store, no-cache, must-revalidate, proxy-revalidate'),
      // Transparent 1x1 GIF
      gifBase64: z.string().default('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'),
    }),
    
    // Click tracking configuration
    click: z.object({
      // Path prefix for click tracking
      path: z.string().default('/c'),
      // Redirect status code
      redirectStatus: z.coerce.number().default(302),
      // Fallback URL if original is invalid
      fallbackUrl: z.string().default('https://apexmail.ee'),
    }),
    
    // Unsubscribe configuration
    unsubscribe: z.object({
      // Path prefix for unsubscribe
      path: z.string().default('/u'),
      // Confirmation page URL
      confirmationUrl: z.string().default('https://apexmail.ee/unsubscribed'),
    }),
    
    // Preferences center configuration
    preferences: z.object({
      // Path prefix for preferences
      path: z.string().default('/p'),
    }),
  }),
  
  customDomains: z.object({
    // Whether to support custom tracking domains
    enabled: z.boolean().default(true),
    // TLS certificate directory
    certDir: z.string().default('/etc/apexmail/certs'),
  }),
  
  rateLimit: z.object({
    enabled: z.boolean().default(true),
    // Max requests per IP per minute
    maxRequestsPerMinute: z.coerce.number().default(1000),
  }),
  
  logging: z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    format: z.enum(['json', 'pretty']).default('json'),
  }),
  
  metrics: z.object({
    enabled: z.boolean().default(true),
    port: z.coerce.number().default(9092),
  }),
});

function loadConfig() {
  const raw = {
    env: process.env.NODE_ENV,
    
    server: {
      host: process.env.TRACKING_HOST,
      port: process.env.TRACKING_PORT,
    },
    
    database: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      maxConnections: process.env.DB_MAX_CONNECTIONS,
      idleTimeout: process.env.DB_IDLE_TIMEOUT,
      connectionTimeout: process.env.DB_CONNECTION_TIMEOUT,
    },
    
    redis: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD,
      db: process.env.REDIS_DB,
    },
    
    tracking: {
      baseUrl: process.env.TRACKING_BASE_URL,
      trustedProxies: process.env.TRUSTED_PROXIES ? process.env.TRUSTED_PROXIES.split(',').map(s => s.trim()) : undefined,
      pixel: {
        path: process.env.TRACKING_PIXEL_PATH,
        cacheControl: process.env.TRACKING_PIXEL_CACHE_CONTROL,
      },
      click: {
        path: process.env.TRACKING_CLICK_PATH,
        redirectStatus: process.env.TRACKING_REDIRECT_STATUS,
        fallbackUrl: process.env.TRACKING_FALLBACK_URL,
      },
      unsubscribe: {
        path: process.env.TRACKING_UNSUBSCRIBE_PATH,
        confirmationUrl: process.env.TRACKING_UNSUBSCRIBE_CONFIRMATION_URL,
      },
      preferences: {
        path: process.env.TRACKING_PREFERENCES_PATH,
      },
    },
    
    customDomains: {
      enabled: process.env.TRACKING_CUSTOM_DOMAINS_ENABLED === 'true',
      certDir: process.env.TRACKING_CERT_DIR,
    },
    
    rateLimit: {
      enabled: process.env.TRACKING_RATE_LIMIT_ENABLED !== 'false',
      maxRequestsPerMinute: process.env.TRACKING_RATE_LIMIT_MAX,
    },
    
    logging: {
      level: process.env.LOG_LEVEL,
      format: process.env.LOG_FORMAT,
    },
    
    metrics: {
      enabled: process.env.METRICS_ENABLED !== 'false',
      port: process.env.TRACKING_METRICS_PORT,
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
