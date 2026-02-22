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
  STRIPE_DEDICATED_IP_PRICE_ID: z.string().startsWith('price_').optional(),
  
  // Internal service auth
  SERVICE_AUTH_TOKEN: z.string().min(32),
  
  // Metering
  METERING_BATCH_SIZE: z.string().default('100'),
  METERING_FLUSH_INTERVAL_MS: z.string().default('10000'),
});

export type Config = z.infer<typeof envSchema>;

let loadedConfig: Config | null = null;

export function loadConfig(): Config {
  if (loadedConfig) return loadedConfig;
  
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
  
  loadedConfig = result.data;
  return loadedConfig;
}

export function getConfig(): Config {
  if (!loadedConfig) {
    throw new Error('Config not loaded. Call loadConfig() first.');
  }
  return loadedConfig;
}

// Export a config object with getter properties for convenience
export const config = {
  get databaseUrl(): string {
    return getConfig().DATABASE_URL;
  },
  get redisUrl(): string {
    return getConfig().REDIS_URL;
  },
  get stripeSecretKey(): string {
    return getConfig().STRIPE_SECRET_KEY;
  },
  get stripeWebhookSecret(): string {
    return getConfig().STRIPE_WEBHOOK_SECRET;
  },
  get serviceAuthToken(): string {
    return getConfig().SERVICE_AUTH_TOKEN;
  },
  get port(): number {
    return parseInt(getConfig().PORT, 10) || 3000;
  },
  get host(): string {
    return getConfig().HOST;
  },
  get corsOrigins(): string[] {
    return ['http://localhost:3000', 'https://apexmail.ee'];
  },
  get meteringBatchSize(): number {
    return parseInt(getConfig().METERING_BATCH_SIZE, 10) || 100;
  },
  get meteringFlushIntervalMs(): number {
    return parseInt(getConfig().METERING_FLUSH_INTERVAL_MS, 10) || 10000;
  },
  get stripeDedicatedIpPriceId(): string | undefined {
    return getConfig().STRIPE_DEDICATED_IP_PRICE_ID;
  },
};

/**
 * Company Information
 * Bel Consulting OÜ - ApexMail brand owner
 * Used for invoices, contracts, and legal documents
 */
export const COMPANY_INFO = {
  name: 'Bel Consulting OÜ',
  tradingAs: 'ApexMail',
  address: {
    street: 'Sakala 7-2',
    city: 'Tallinn',
    postalCode: '10141',
    country: 'Estonia',
    countryCode: 'EE',
  },
  registryCode: '16192499',
  vatNumber: 'EE102951727',
  email: {
    billing: 'billing@apexmail.ee',
    info: 'info@apexmail.ee',
    support: 'support@apexmail.ee',
  },
  bank: {
    name: 'Swedbank AS',
    iban: 'EE382200221012345678',
    bic: 'HABAEE2X',
  },
} as const;
