/**
 * Billing App Configuration
 * Environment-based settings with validation
 */

import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.string().default('4100'),
  HOST: z.string().default('0.0.0.0'),
  
  // Database
  DATABASE_URL: z.string().url(),
  
  // Redis
  REDIS_URL: z.string().url(),
  
  // Stripe
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),
  STRIPE_WEBHOOK_SECRET: z.string().startsWith('whsec_'),
  STRIPE_PUBLISHABLE_KEY: z.string().startsWith('pk_').optional(),
  
  // Internal service auth
  SERVICE_AUTH_TOKEN: z.string().min(32),
  
  // Metering
  METERING_BATCH_SIZE: z.string().default('100'),
  METERING_FLUSH_INTERVAL_MS: z.string().default('10000'),
});

export type Config = z.infer<typeof envSchema>;

let config: Config | null = null;

export function loadConfig(): Config {
  if (config) return config;
  
  const result = envSchema.safeParse(process.env);
  
  if (!result.success) {
    const missing = result.error.issues
      .filter(i => i.code === 'invalid_type' && i.received === 'undefined')
      .map(i => i.path.join('.'));
    
    throw new Error(
      `Missing or invalid environment variables:\n${missing.join('\n')}\n\n` +
      `Validation errors:\n${JSON.stringify(result.error.format(), null, 2)}`
    );
  }
  
  config = result.data;
  return config;
}

export function getConfig(): Config {
  if (!config) {
    throw new Error('Config not loaded. Call loadConfig() first.');
  }
  return config;
}
