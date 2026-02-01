/**
 * DevEx Configuration
 */

import { z } from 'zod';

const configSchema = z.object({
  port: z.number().default(4200),
  host: z.string().default('0.0.0.0'),
  databaseUrl: z.string(),
  redisUrl: z.string(),
  webhookSigningSecret: z.string(),
  corsOrigins: z.array(z.string()).default(['*']),
  apiBaseUrl: z.string().default('https://api.apexmail.io'),
  docsBaseUrl: z.string().default('https://docs.apexmail.io'),
  currentApiVersion: z.string().default('2024-01'),
  supportedApiVersions: z.array(z.string()).default(['2024-01', '2023-10', '2023-06']),
  deprecatedApiVersions: z.array(z.string()).default(['2023-01', '2022-10']),
  sandboxEnabled: z.boolean().default(true),
});

export type Config = z.infer<typeof configSchema>;

function loadConfig(): Config {
  return configSchema.parse({
    port: parseInt(process.env.PORT ?? '4200', 10),
    host: process.env.HOST ?? '0.0.0.0',
    databaseUrl: process.env.DATABASE_URL,
    redisUrl: process.env.REDIS_URL,
    webhookSigningSecret: process.env.WEBHOOK_SIGNING_SECRET,
    corsOrigins: process.env.CORS_ORIGINS?.split(',') ?? ['*'],
    apiBaseUrl: process.env.API_BASE_URL ?? 'https://api.apexmail.io',
    docsBaseUrl: process.env.DOCS_BASE_URL ?? 'https://docs.apexmail.io',
    currentApiVersion: process.env.CURRENT_API_VERSION ?? '2024-01',
    supportedApiVersions: process.env.SUPPORTED_API_VERSIONS?.split(',') ?? ['2024-01', '2023-10', '2023-06'],
    deprecatedApiVersions: process.env.DEPRECATED_API_VERSIONS?.split(',') ?? ['2023-01', '2022-10'],
    sandboxEnabled: process.env.SANDBOX_ENABLED !== 'false',
  });
}

export const config = loadConfig();
