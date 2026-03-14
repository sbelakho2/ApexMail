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

  // Company banking details
  BILLING_COMPANY_IBAN: z.string().min(15).optional(),
  BILLING_COMPANY_PHONE: z.string().min(7).optional(),

  // Internal URLs and salts
  API_BASE_URL: z.string().url().optional(),
  PDF_RENDERER_URL: z.string().url().optional(),
  VIRAL_TELEMETRY_HASH_SALT: z.string().min(16).optional(),

  // Billing safeguards
  MAX_PRORATION_CHARGE_CENTS: z.string().regex(/^\d+$/).optional(),
  MAX_PRORATION_CREDIT_CENTS: z.string().regex(/^\d+$/).optional(),
  WARN_PRORATION_CHARGE_CENTS: z.string().regex(/^\d+$/).optional(),
  
  // Internal service auth
  SERVICE_AUTH_TOKEN: z.string().min(32),

  // Auth
  JWT_SECRET: z.string().min(32),

  // CORS
  CORS_ORIGINS: z.string().optional(),
  
  // Metering
  METERING_BATCH_SIZE: z.string().default('100'),
  METERING_FLUSH_INTERVAL_MS: z.string().default('10000'),

  // Runtime controls
  RATE_LIMIT_WINDOW_SECONDS: z.string().default('60'),
  RATE_LIMIT_MAX_REQUESTS: z.string().default('300'),
  SAGA_TIMEOUT_MINUTES: z.string().default('60'),
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
  
  // Validate IBAN is configured in production to prevent unprofessional invoices
  if (result.data.NODE_ENV === 'production' && !result.data.BILLING_COMPANY_IBAN) {
    throw new Error(
      'BILLING_COMPANY_IBAN must be configured in production environment. ' +
      'This IBAN appears on customer invoices.'
    );
  }

  if (result.data.NODE_ENV === 'production' && !result.data.API_BASE_URL) {
    throw new Error(
      'API_BASE_URL must be configured in production environment. ' +
      'Dedicated IP provisioning depends on a valid internal API base URL.'
    );
  }

  if (result.data.NODE_ENV === 'production' && !result.data.PDF_RENDERER_URL) {
    throw new Error(
      'PDF_RENDERER_URL must be configured in production environment. ' +
      'Invoice PDF generation depends on a valid internal PDF renderer URL.'
    );
  }

  if (result.data.NODE_ENV === 'production' && !result.data.VIRAL_TELEMETRY_HASH_SALT) {
    throw new Error(
      'VIRAL_TELEMETRY_HASH_SALT must be configured in production environment. ' +
      'Telemetry pseudonymization must not rely on a shared default salt.'
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
  get jwtSecret(): string {
    return getConfig().JWT_SECRET;
  },
  get port(): number {
    const parsed = parseInt(getConfig().PORT, 10);
    return Number.isNaN(parsed) ? 3000 : parsed;
  },
  get host(): string {
    return getConfig().HOST;
  },
  get corsOrigins(): string[] {
    const raw = getConfig().CORS_ORIGINS;
    if (raw) {
      return raw.split(',').map((v) => v.trim()).filter(Boolean);
    }
    return getConfig().NODE_ENV === 'development'
      ? ['http://localhost:3000']
      : ['https://apexmail.ee'];
  },
  get meteringBatchSize(): number {
    return parseInt(getConfig().METERING_BATCH_SIZE, 10) || 100;
  },
  get meteringFlushIntervalMs(): number {
    return parseInt(getConfig().METERING_FLUSH_INTERVAL_MS, 10) || 10000;
  },
  get rateLimitWindowSeconds(): number {
    return parseInt(getConfig().RATE_LIMIT_WINDOW_SECONDS, 10) || 60;
  },
  get rateLimitMaxRequests(): number {
    return parseInt(getConfig().RATE_LIMIT_MAX_REQUESTS, 10) || 300;
  },
  get sagaTimeoutMinutes(): number {
    return parseInt(getConfig().SAGA_TIMEOUT_MINUTES, 10) || 60;
  },
  get apiBaseUrl(): string {
    return getConfig().API_BASE_URL ?? 'http://localhost:3001';
  },
  get pdfRendererUrl(): string {
    return getConfig().PDF_RENDERER_URL ?? 'http://pdf-renderer:3004';
  },
  get viralTelemetryHashSalt(): string {
    return getConfig().VIRAL_TELEMETRY_HASH_SALT ?? 'apexmail-telemetry';
  },
  get billingCompanyPhone(): string {
    return getConfig().BILLING_COMPANY_PHONE ?? '+37200000000';
  },
  get maxProrationChargeCents(): number {
    return parseInt(getConfig().MAX_PRORATION_CHARGE_CENTS ?? '100000', 10);
  },
  get maxProrationCreditCents(): number {
    return parseInt(getConfig().MAX_PRORATION_CREDIT_CENTS ?? '50000', 10);
  },
  get warnProrationChargeCents(): number {
    return parseInt(getConfig().WARN_PRORATION_CHARGE_CENTS ?? '25000', 10);
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
    iban: getConfig().BILLING_COMPANY_IBAN ?? 'UNCONFIGURED',
    bic: 'HABAEE2X',
  },
} as const;
