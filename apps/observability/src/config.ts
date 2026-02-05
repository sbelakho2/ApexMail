/**
 * Observability Service Configuration
 */

export interface TracingConfig {
  enabled: boolean;
  serviceName: string;
  serviceVersion: string;
  environment: string;
  sampleRate: number;
  jaegerEndpoint: string;
  zipkinEndpoint: string;
  otlpEndpoint: string;
}

export interface MetricsConfig {
  enabled: boolean;
  prometheusPort: number;
  defaultLabels: Record<string, string>;
  histogramBuckets: number[];
  aggregationInterval: number;
}

export interface LoggingConfig {
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  format: 'json' | 'pretty';
  includeTimestamp: boolean;
  includeTraceId: boolean;
  sensitiveFields: string[];
  maxMessageLength: number;
}

export interface AlertConfig {
  enabled: boolean;
  webhookUrls: string[];
  slackWebhook: string;
  pagerdutyKey: string;
  opsgenieKey: string;
  emailRecipients: string[];
  cooldownMinutes: number;
}

// Validate required environment variables in production
function getRequiredEnv(name: string, defaultValue?: string): string {
  const value = process.env[name] || defaultValue;
  if (!value && process.env.NODE_ENV === 'production') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value || '';
}

// Check for insecure default credentials in production
function validateProductionSecurity(): void {
  if (process.env.NODE_ENV === 'production') {
    const dbPassword = process.env.DB_PASSWORD;
    if (!dbPassword) {
      throw new Error('DB_PASSWORD must be set in production');
    }
    if (dbPassword === 'apexmail' || dbPassword === 'password' || dbPassword.length < 8) {
      throw new Error('DB_PASSWORD appears to be a weak/default password. Use a strong password in production.');
    }
  }
}

// Run security validation on module load
validateProductionSecurity();

export const config = {
  // Server config
  port: parseInt(process.env.OBSERVABILITY_PORT || '4400'),
  environment: process.env.NODE_ENV || 'development',
  version: process.env.APP_VERSION || '1.0.0',
  
  // Database - require password in production, allow defaults only in dev
  dbHost: process.env.DB_HOST || 'localhost',
  dbPort: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'apexmail',
  dbUser: process.env.DB_USER || 'apexmail',
  dbPassword: getRequiredEnv('DB_PASSWORD', process.env.NODE_ENV === 'production' ? undefined : 'apexmail'),
  dbPoolMax: parseInt(process.env.DB_POOL_MAX || '20'),
  
  // Redis
  redisHost: process.env.REDIS_HOST || 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT || '6379'),
  redisPassword: process.env.REDIS_PASSWORD || undefined,
  
  // Tracing
  tracing: {
    enabled: process.env.TRACING_ENABLED !== 'false',
    serviceName: process.env.SERVICE_NAME || 'apexmail',
    serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    sampleRate: parseFloat(process.env.TRACE_SAMPLE_RATE || '1.0'),
    jaegerEndpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces',
    zipkinEndpoint: process.env.ZIPKIN_ENDPOINT || 'http://localhost:9411/api/v2/spans',
    otlpEndpoint: process.env.OTLP_ENDPOINT || 'http://localhost:4318',
  } as TracingConfig,
  
  // Metrics
  metrics: {
    enabled: process.env.METRICS_ENABLED !== 'false',
    prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9090'),
    defaultLabels: {
      service: process.env.SERVICE_NAME || 'apexmail',
      environment: process.env.NODE_ENV || 'development',
    },
    histogramBuckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    aggregationInterval: parseInt(process.env.METRICS_INTERVAL || '15000'),
  } as MetricsConfig,
  
  // Logging
  logging: {
    level: (process.env.LOG_LEVEL || 'info') as LoggingConfig['level'],
    format: (process.env.LOG_FORMAT || 'json') as LoggingConfig['format'],
    includeTimestamp: true,
    includeTraceId: true,
    // AUDIT-002 FIX: Comprehensive list of sensitive fields to mask
    sensitiveFields: [
      'password', 'passwd', 'pass', 'pwd',
      'token', 'accessToken', 'refreshToken', 'bearerToken', 'authToken',
      'apiKey', 'api_key', 'apikey',
      'secret', 'secretKey', 'clientSecret',
      'authorization', 'auth',
      'credential', 'credentials',
      'privateKey', 'private_key',
      'ssn', 'socialSecurity',
      'creditCard', 'credit_card', 'cardNumber', 'card_number', 'cvv', 'cvc',
      'bankAccount', 'bank_account', 'accountNumber', 'account_number', 'routingNumber',
      'dob', 'dateOfBirth', 'date_of_birth', 'birthdate',
      'sessionId', 'session_id', 'sid',
      'cookie', 'cookies',
      'otp', 'pin', 'mfa', 'totp',
      'encryptionKey', 'encryption_key', 'decryptionKey',
      'signingKey', 'signing_key',
      'accessKey', 'access_key',
      'webhook_secret', 'webhookSecret',
    ],
    maxMessageLength: parseInt(process.env.LOG_MAX_LENGTH || '10000'),
  } as LoggingConfig,
  
  // Alerting
  alerting: {
    enabled: process.env.ALERTING_ENABLED === 'true',
    webhookUrls: (process.env.ALERT_WEBHOOKS || '').split(',').filter(Boolean),
    slackWebhook: process.env.SLACK_WEBHOOK || '',
    pagerdutyKey: process.env.PAGERDUTY_KEY || '',
    opsgenieKey: process.env.OPSGENIE_KEY || '',
    emailRecipients: (process.env.ALERT_EMAILS || '').split(',').filter(Boolean),
    cooldownMinutes: parseInt(process.env.ALERT_COOLDOWN || '15'),
  } as AlertConfig,
  
  // Retention
  traceRetentionDays: parseInt(process.env.TRACE_RETENTION_DAYS || '7'),
  metricsRetentionDays: parseInt(process.env.METRICS_RETENTION_DAYS || '30'),
  logRetentionDays: parseInt(process.env.LOG_RETENTION_DAYS || '14'),
  
  // API keys
  internalApiKey: process.env.INTERNAL_API_KEY || 'internal-key',
  
  // CORS
  corsOrigins: (process.env.CORS_ORIGINS || '*').split(','),
};
