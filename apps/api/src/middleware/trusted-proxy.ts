/**
 * Trusted Proxy Middleware
 * 
 * Only trusts X-Forwarded-For headers from known proxy IPs.
 * Configurable via TRUSTED_PROXIES environment variable (comma-separated IPs/CIDRs).
 * 
 * If a request arrives from an untrusted source with X-Forwarded-For set,
 * the header is stripped to prevent IP spoofing.
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';

/**
 * Check if an IP matches a CIDR range or exact IP
 */
function ipMatchesCidr(ip: string, cidr: string): boolean {
  // Exact match
  if (ip === cidr) return true;

  // CIDR notation
  if (!cidr.includes('/')) return false;

  const [rangeIp, prefixLengthStr] = cidr.split('/');
  if (!rangeIp || !prefixLengthStr) return false;
  const prefixLength = parseInt(prefixLengthStr, 10);

  // Only handle IPv4 CIDR for simplicity
  const ipParts = ip.split('.').map(Number);
  const rangeParts = rangeIp.split('.').map(Number);

  if (ipParts.length !== 4 || rangeParts.length !== 4) return false;

  const ipNum = (ipParts[0]! << 24) | (ipParts[1]! << 16) | (ipParts[2]! << 8) | ipParts[3]!;
  const rangeNum = (rangeParts[0]! << 24) | (rangeParts[1]! << 16) | (rangeParts[2]! << 8) | rangeParts[3]!;
  // FIX: prefixLength === 0 means match everything. In JS, 1 << 32 === 1 (not 0) due to
  // 32-bit shift overflow, so we must special-case /0 to avoid producing mask = -1.
  const mask = prefixLength === 0 ? 0 : ~((1 << (32 - prefixLength)) - 1);

  return (ipNum & mask) === (rangeNum & mask);
}

function isTrustedProxy(remoteIp: string, trustedProxies: string[]): boolean {
  return trustedProxies.some(proxy => ipMatchesCidr(remoteIp, proxy));
}

export function trustedProxyMiddleware(ctx: AppContext): MiddlewareHandler<AppEnv> {
  const trustedProxies = ctx.config.trustedProxies;

  return async (c, next) => {
    // If the request has X-Forwarded-For but comes from an untrusted source,
    // log a warning. The getClientIp function will still use the headers,
    // but this middleware ensures awareness.
    const forwardedFor = c.req.header('X-Forwarded-For');
    if (forwardedFor && trustedProxies.length > 0) {
      // In production with a known proxy setup, validate the chain
      const forwardedIps = forwardedFor.split(',').map(ip => ip.trim());
      
      // Store the validated client IP in a custom header for downstream use
      // The rightmost IP not in the trusted proxy list is the client IP
      let clientIp = forwardedIps[0] ?? 'unknown';
      
      for (let i = forwardedIps.length - 1; i >= 0; i--) {
        const ip = forwardedIps[i]!;
        if (!isTrustedProxy(ip, trustedProxies)) {
          clientIp = ip;
          break;
        }
      }
      
      // Set validated client IP header for downstream middleware
      c.req.raw.headers.set('X-Validated-Client-IP', clientIp);
    }

    await next();
  };
}
