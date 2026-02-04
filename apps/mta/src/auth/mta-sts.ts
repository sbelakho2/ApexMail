/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) - RFC 8461
 * 
 * MTA-STS enables mail domain owners to opt into strict transport security mode.
 * This ensures TLS encryption is REQUIRED (not opportunistic) for email delivery.
 * 
 * How it works:
 * 1. Domain publishes a DNS TXT record: _mta-sts.domain.com
 * 2. Domain hosts a policy file at: https://mta-sts.domain.com/.well-known/mta-sts.txt
 * 3. Sending MTAs cache and enforce the policy
 * 
 * Benefits:
 * - Prevents man-in-the-middle attacks on email
 * - Prevents STARTTLS stripping attacks
 * - Validates MX server certificates
 * 
 * @see https://tools.ietf.org/html/rfc8461
 * @see https://security.googleblog.com/2019/04/gmail-making-email-more-secure-with-mta.html
 */

import * as dns from 'dns';
import * as https from 'https';
import { URL } from 'url';

export type MTASTSMode = 'enforce' | 'testing' | 'none';

export interface MTASTSPolicy {
  version: 'STSv1';
  mode: MTASTSMode;
  mx: string[];  // Allowed MX hosts (can use wildcards like *.google.com)
  maxAge: number; // Policy max-age in seconds (recommended: weeks)
}

export interface MTASTSRecord {
  version: 'STSv1';
  id: string;  // Policy identifier (changes when policy updates)
}

export interface MTASTSVerificationResult {
  supported: boolean;
  mode: MTASTSMode | null;
  policy: MTASTSPolicy | null;
  dnsRecord: MTASTSRecord | null;
  errors: string[];
  warnings: string[];
  recommendations: string[];
}

/**
 * Verify MTA-STS configuration for a domain
 */
export async function verifyMTASTS(domain: string): Promise<MTASTSVerificationResult> {
  const result: MTASTSVerificationResult = {
    supported: false,
    mode: null,
    policy: null,
    dnsRecord: null,
    errors: [],
    warnings: [],
    recommendations: [],
  };

  // Step 1: Check for _mta-sts DNS TXT record
  const dnsRecord = await checkMTASTSDNSRecord(domain);
  if (!dnsRecord.found) {
    result.errors.push('No _mta-sts TXT record found');
    result.recommendations.push(
      `Add TXT record: _mta-sts.${domain} with value "v=STSv1; id=<unique-id>"`
    );
    return result;
  }
  result.dnsRecord = dnsRecord.record!;

  // Step 2: Fetch the policy file
  const policyResult = await fetchMTASTSPolicy(domain);
  if (!policyResult.success) {
    result.errors.push(policyResult.error!);
    result.recommendations.push(
      `Host MTA-STS policy at https://mta-sts.${domain}/.well-known/mta-sts.txt`
    );
    return result;
  }
  result.policy = policyResult.policy!;
  result.mode = result.policy.mode;
  result.supported = true;

  // Step 3: Validate policy
  const validationErrors = validateMTASTSPolicy(result.policy, domain);
  result.errors.push(...validationErrors.errors);
  result.warnings.push(...validationErrors.warnings);

  // Step 4: Generate recommendations
  if (result.mode === 'testing') {
    result.recommendations.push(
      'MTA-STS is in testing mode. Once verified working, change to "enforce" mode for full protection.'
    );
  }
  
  if (result.policy.maxAge < 604800) { // Less than 1 week
    result.warnings.push('max_age is less than 1 week. Consider increasing for better protection.');
  }

  return result;
}

/**
 * Generate MTA-STS DNS record value
 */
export function generateMTASTSDNSRecord(policyId?: string): string {
  const id = policyId || generatePolicyId();
  return `v=STSv1; id=${id}`;
}

/**
 * Generate MTA-STS policy file content
 */
export function generateMTASTSPolicy(
  mxHosts: string[],
  mode: MTASTSMode = 'testing',
  maxAge: number = 604800 // 1 week default
): string {
  const lines = [
    'version: STSv1',
    `mode: ${mode}`,
    ...mxHosts.map(mx => `mx: ${mx}`),
    `max_age: ${maxAge}`,
  ];
  return lines.join('\n');
}

// Helper functions

async function checkMTASTSDNSRecord(
  domain: string
): Promise<{ found: boolean; record?: MTASTSRecord }> {
  return new Promise((resolve) => {
    dns.resolveTxt(`_mta-sts.${domain}`, (err, records) => {
      if (err || !records?.length) {
        resolve({ found: false });
        return;
      }

      // TXT records are returned as arrays of strings
      const txtValue = records.flat().join('');
      
      // Parse: v=STSv1; id=<id>
      const versionMatch = txtValue.match(/v=STSv1/i);
      const idMatch = txtValue.match(/id=([a-zA-Z0-9_-]+)/i);

      if (versionMatch && idMatch) {
        resolve({
          found: true,
          record: {
            version: 'STSv1',
            id: idMatch[1]!,
          },
        });
      } else {
        resolve({ found: false });
      }
    });
  });
}

async function fetchMTASTSPolicy(
  domain: string
): Promise<{ success: boolean; policy?: MTASTSPolicy; error?: string }> {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  
  return new Promise((resolve) => {
    const url = new URL(policyUrl);
    
    const req = https.get(
      {
        hostname: url.hostname,
        path: url.pathname,
        timeout: 10000,
        headers: {
          'User-Agent': 'ApexMail-MTA-STS-Checker/1.0',
        },
      },
      (res) => {
        if (res.statusCode !== 200) {
          resolve({
            success: false,
            error: `Policy file returned HTTP ${res.statusCode}`,
          });
          return;
        }

        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          const policy = parseMTASTSPolicy(data);
          if (policy) {
            resolve({ success: true, policy });
          } else {
            resolve({ success: false, error: 'Invalid policy file format' });
          }
        });
      }
    );

    req.on('error', (error) => {
      resolve({ success: false, error: `Failed to fetch policy: ${error.message}` });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'Policy fetch timed out' });
    });
  });
}

function parseMTASTSPolicy(content: string): MTASTSPolicy | null {
  const lines = content.split('\n').filter((l) => l.trim());
  const policy: Partial<MTASTSPolicy> = {
    mx: [],
  };

  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;

    const key = line.slice(0, colonIndex).trim().toLowerCase();
    const value = line.slice(colonIndex + 1).trim();

    switch (key) {
      case 'version':
        if (value.toLowerCase() !== 'stsv1') return null;
        policy.version = 'STSv1';
        break;
      case 'mode':
        if (!['enforce', 'testing', 'none'].includes(value.toLowerCase())) return null;
        policy.mode = value.toLowerCase() as MTASTSMode;
        break;
      case 'mx':
        policy.mx!.push(value);
        break;
      case 'max_age':
        const age = parseInt(value, 10);
        if (isNaN(age) || age < 0) return null;
        policy.maxAge = age;
        break;
    }
  }

  // Validate required fields
  if (!policy.version || !policy.mode || !policy.mx?.length || !policy.maxAge) {
    return null;
  }

  return policy as MTASTSPolicy;
}

function validateMTASTSPolicy(
  policy: MTASTSPolicy,
  _domain: string
): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check MX hosts
  if (policy.mx.length === 0) {
    errors.push('Policy must specify at least one MX host');
  }

  // Check max_age
  if (policy.maxAge > 31557600) { // More than 1 year
    warnings.push('max_age exceeds 1 year. This may cause issues if you need to change the policy.');
  }

  // Check for wildcard usage
  const hasWildcard = policy.mx.some((mx) => mx.startsWith('*.'));
  if (hasWildcard) {
    warnings.push('Wildcard MX patterns should be used carefully.');
  }

  return { errors, warnings };
}

function generatePolicyId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 8);
  return `${timestamp}${random}`;
}

/**
 * SMTP TLS Reporting (TLSRPT) - RFC 8460
 * Companion standard to MTA-STS for receiving TLS connection reports
 */
export interface TLSRPTRecord {
  version: 'TLSRPTv1';
  rua: string[];  // Reporting URIs (mailto: or https:)
}

/**
 * Generate TLSRPT DNS record value
 */
export function generateTLSRPTRecord(reportingEmails: string[]): string {
  const rua = reportingEmails.map(email => `mailto:${email}`).join(',');
  return `v=TLSRPTv1; rua=${rua}`;
}

/**
 * Verify TLSRPT configuration for a domain
 */
export async function verifyTLSRPT(
  domain: string
): Promise<{ supported: boolean; record: TLSRPTRecord | null; error?: string }> {
  return new Promise((resolve) => {
    dns.resolveTxt(`_smtp._tls.${domain}`, (err, records) => {
      if (err || !records?.length) {
        resolve({ supported: false, record: null, error: 'No _smtp._tls TXT record found' });
        return;
      }

      const txtValue = records.flat().join('');
      const versionMatch = txtValue.match(/v=TLSRPTv1/i);
      const ruaMatch = txtValue.match(/rua=([^;]+)/i);

      if (versionMatch && ruaMatch) {
        const rua = ruaMatch[1]!.split(',').map((r) => r.trim());
        resolve({
          supported: true,
          record: { version: 'TLSRPTv1', rua },
        });
      } else {
        resolve({ supported: false, record: null, error: 'Invalid TLSRPT record format' });
      }
    });
  });
}
