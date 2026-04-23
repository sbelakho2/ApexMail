import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export const repoRoot = path.resolve(here, '../../..');

const baseUrlDefaults: Record<string, string> = {
  'api-server': process.env.E2E_API_BASE_URL ?? 'http://127.0.0.1:3000',
  billing: process.env.E2E_BILLING_BASE_URL ?? 'http://127.0.0.1:4100',
  'rust-devex-service': process.env.E2E_DEVEX_BASE_URL ?? 'http://127.0.0.1:3031',
  'rust-observability-service': process.env.E2E_OBSERVABILITY_BASE_URL ?? 'http://127.0.0.1:3032',
  'rust-enterprise': process.env.E2E_ENTERPRISE_BASE_URL ?? 'http://127.0.0.1:3033',
};

export function serviceBaseUrl(service: string): string | undefined {
  if (baseUrlDefaults[service]) {
    return baseUrlDefaults[service];
  }

  const envKey = `E2E_${service.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_BASE_URL`;
  const value = process.env[envKey];
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

export async function assertServiceReachable(service: string, baseUrl: string): Promise<void> {
  const probes = ['/health', '/health/live', '/ready', '/readiness', '/'];
  const errors: string[] = [];

  for (const probe of probes) {
    const probeUrl = new URL(probe, baseUrl).toString();

    try {
      const head = await fetch(probeUrl, { method: 'HEAD' });
      if (head.status < 500) {
        return;
      }
      errors.push(`HEAD ${probe} => ${head.status}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`HEAD ${probe} => ${message}`);
    }

    try {
      const get = await fetch(probeUrl, { method: 'GET' });
      if (get.status < 500) {
        return;
      }
      errors.push(`GET ${probe} => ${get.status}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`GET ${probe} => ${message}`);
    }
  }

  throw new Error(
    `Service ${service} at ${baseUrl} is unreachable or returning 5xx on all probes. Details: ${errors.join(' | ')}`,
  );
}
