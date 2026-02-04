/**
 * Domains Routes - Domain management and verification
 * 
 * Includes advanced authentication verification:
 * - SPF, DKIM, DMARC (basic)
 * - MTA-STS (RFC 8461) - Strict TLS enforcement
 * - BIMI (Brand Indicators) - Logo in inbox
 * - TLSRPT - TLS reporting
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { DomainsRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { generateDKIMKeyPair } from '@apexmail/lib/crypto';
import { verifyMTASTS, generateMTASTSPolicy, generateMTASTSDNSRecord, verifyTLSRPT, generateTLSRPTRecord } from '../../mta/src/auth/mta-sts.js';
import { verifyBIMI, getBIMISetupInstructions, validateBIMILogo } from '../../mta/src/auth/bimi.js';

const addDomainSchema = z.object({
  domain: z.string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/, 'Invalid domain format'),
  verificationMethod: z.enum(['dns_txt', 'dns_cname', 'meta_tag']).default('dns_txt'),
});

export function domainsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const domainsRepo = new DomainsRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Add a new domain
  router.post('/', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { domain, verificationMethod } = addDomainSchema.parse(body);

    // Check if domain already exists for this tenant
    const existing = await domainsRepo.findByDomain(domain, tenantId);
    if (existing.ok && existing.value) {
      throw ApiError.conflict(`Domain ${domain} already exists`, 'DOMAIN_EXISTS');
    }

    // Create the domain
    const result = await domainsRepo.create({
      tenantId,
      domain,
      verificationMethod,
    });

    if (!result.ok) {
      logger.error('Failed to create domain', { error: result.error });
      throw ApiError.internal('Failed to add domain');
    }

    const domainRecord = result.value;

    // Generate DKIM keys for the domain
    const selector = `apexmail${new Date().getFullYear()}`;
    const dkimKeyPair = generateDKIMKeyPair(selector, domain);
    
    // Update domain with DNS records
    await domainsRepo.update(domainRecord.id, {
      dnsRecords: {
        spf: {
          value: `v=spf1 include:_spf.apexmail.ee ~all`,
          verified: false,
        },
        dkim: {
          selector,
          value: dkimKeyPair.publicKey,
          verified: false,
        },
        dmarc: {
          value: `v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee`,
          verified: false,
        },
        returnPath: {
          value: `bounce.${domain}`,
          verified: false,
        },
      },
    });

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'domain.created',
      resourceType: 'domain',
      resourceId: domainRecord.id,
      metadata: { domain, verificationMethod },
    });

    logger.info('Domain added', { domainId: domainRecord.id, domain });

    // Get the updated domain with DNS records
    const updated = await domainsRepo.findById(domainRecord.id);
    const finalDomain = updated.ok && updated.value ? updated.value : domainRecord;

    return c.json({
      domain: {
        id: finalDomain.id,
        domain: finalDomain.domain,
        status: finalDomain.status,
        verificationMethod: finalDomain.verificationMethod,
        verificationToken: finalDomain.verificationToken,
        dnsRecords: finalDomain.dnsRecords,
        expiresAt: finalDomain.expiresAt,
        createdAt: finalDomain.createdAt,
      },
      instructions: getVerificationInstructions(finalDomain),
    }, 201);
  });

  // Get domain by ID
  router.get('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    // Use tenant-scoped query for database-level isolation
    const result = await domainsRepo.findById(domainId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain');
    }

    if (!result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;

    return c.json({
      domain: {
        id: domain.id,
        domain: domain.domain,
        status: domain.status,
        verificationMethod: domain.verificationMethod,
        verificationToken: domain.verificationToken,
        verifiedAt: domain.verifiedAt,
        dnsRecords: domain.dnsRecords,
        healthStatus: domain.healthStatus,
        expiresAt: domain.expiresAt,
        createdAt: domain.createdAt,
        updatedAt: domain.updatedAt,
      },
      instructions: domain.status === 'pending' ? getVerificationInstructions(domain) : undefined,
    });
  });

  // List domains
  router.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const status = c.req.query('status') as 'pending' | 'verified' | 'failed' | 'expired' | undefined;
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await domainsRepo.listByTenant(tenantId, {
      status,
      limit: Math.min(limit, 100),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domains');
    }

    return c.json({
      domains: result.value.domains.map((d) => ({
        id: d.id,
        domain: d.domain,
        status: d.status,
        verifiedAt: d.verifiedAt,
        healthStatus: d.healthStatus.overall,
        createdAt: d.createdAt,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + result.value.domains.length < result.value.total,
      },
    });
  });

  // Verify domain
  router.post('/:id/verify', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const domainId = c.req.param('id');
    const logger = c.get('logger');

    // Use tenant-scoped query for database-level isolation
    const result = await domainsRepo.findById(domainId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain');
    }

    if (!result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;

    if (domain.status === 'verified') {
      return c.json({
        verified: true,
        message: 'Domain is already verified',
      });
    }

    if (domain.status === 'expired') {
      throw ApiError.badRequest('Domain verification has expired. Please delete and re-add the domain.', 'VERIFICATION_EXPIRED');
    }

    // Perform DNS verification
    const verificationResult = await verifyDomain(domain);

    if (verificationResult.verified) {
      // Mark as verified
      await domainsRepo.verify(domainId);

      // Audit log
      await auditRepo.create({
        tenantId,
        userId: userId ?? undefined,
        action: 'domain.verified',
        resourceType: 'domain',
        resourceId: domainId,
        metadata: { domain: domain.domain },
      });

      logger.info('Domain verified', { domainId, domain: domain.domain });

      return c.json({
        verified: true,
        message: 'Domain verified successfully',
      });
    }

    return c.json({
      verified: false,
      message: 'Verification failed',
      details: verificationResult.details,
    });
  });

  // Check DNS health
  router.get('/:id/health', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    // Use tenant-scoped query for database-level isolation
    const result = await domainsRepo.findById(domainId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain');
    }

    if (!result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;

    // Perform health check
    const healthCheck = await checkDnsHealth(domain);

    // Update health status in database (with tenant scope)
    await domainsRepo.update(domainId, {
      healthStatus: healthCheck,
    }, tenantId);

    return c.json({
      domain: domain.domain,
      healthStatus: healthCheck,
      dnsRecords: domain.dnsRecords,
    });
  });

  // Delete domain
  router.delete('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const domainId = c.req.param('id');
    const logger = c.get('logger');

    // Use tenant-scoped query for database-level isolation
    const result = await domainsRepo.findById(domainId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain');
    }

    if (!result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;

    // Delete the domain
    const deleteResult = await domainsRepo.delete(domainId);
    
    if (!deleteResult.ok) {
      throw ApiError.internal('Failed to delete domain');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'domain.deleted',
      resourceType: 'domain',
      resourceId: domainId,
      metadata: { domain: domain.domain },
    });

    logger.info('Domain deleted', { domainId, domain: domain.domain });

    return c.json({ success: true });
  });

  // Get DNS records for domain
  router.get('/:id/dns-records', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    // Use tenant-scoped query for database-level isolation
    const result = await domainsRepo.findById(domainId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain');
    }

    if (!result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;
    const records = generateDnsRecordInstructions(domain);

    return c.json({
      domain: domain.domain,
      records,
    });
  });

  // ============================================================================
  // ADVANCED AUTHENTICATION ENDPOINTS
  // ============================================================================

  /**
   * Check MTA-STS configuration for a domain
   * MTA-STS ensures TLS is enforced (not opportunistic) for email delivery
   * @see RFC 8461
   */
  router.get('/:id/mta-sts', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    const result = await domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;
    const mtaStsResult = await verifyMTASTS(domain.domain);

    return c.json({
      domain: domain.domain,
      mtaSts: {
        supported: mtaStsResult.supported,
        mode: mtaStsResult.mode,
        policy: mtaStsResult.policy,
        dnsRecord: mtaStsResult.dnsRecord,
        errors: mtaStsResult.errors,
        warnings: mtaStsResult.warnings,
        recommendations: mtaStsResult.recommendations,
      },
      setupInstructions: !mtaStsResult.supported ? {
        dnsRecord: {
          type: 'TXT',
          name: `_mta-sts.${domain.domain}`,
          value: generateMTASTSDNSRecord(),
        },
        policyFile: {
          url: `https://mta-sts.${domain.domain}/.well-known/mta-sts.txt`,
          content: generateMTASTSPolicy(['*.apexmail.ee'], 'testing', 604800),
        },
        tlsrptRecord: {
          type: 'TXT',
          name: `_smtp._tls.${domain.domain}`,
          value: generateTLSRPTRecord([`tlsrpt@${domain.domain}`]),
        },
      } : undefined,
    });
  });

  /**
   * Check BIMI configuration for a domain
   * BIMI displays sender brand logo in supporting email clients
   * @see https://bimigroup.org
   */
  router.get('/:id/bimi', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    const result = await domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;
    const bimiResult = await verifyBIMI(domain.domain);

    return c.json({
      domain: domain.domain,
      bimi: {
        supported: bimiResult.supported,
        record: bimiResult.record,
        logoValid: bimiResult.logoValid,
        dmarcValid: bimiResult.dmarcValid,
        certificateValid: bimiResult.certificateValid,
        errors: bimiResult.errors,
        warnings: bimiResult.warnings,
        recommendations: bimiResult.recommendations,
      },
      setupInstructions: getBIMISetupInstructions(
        domain.domain,
        `https://assets.${domain.domain}/logo.svg`
      ),
    });
  });

  /**
   * Validate a BIMI logo SVG file
   * Checks compliance with SVG Tiny PS requirements
   */
  router.post('/:id/bimi/validate-logo', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    const result = await domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      throw ApiError.notFound('Domain');
    }

    const body = await c.req.json();
    const logoUrl = z.string().url().parse(body.logoUrl);

    const validation = await validateBIMILogo(logoUrl);

    return c.json({
      valid: validation.valid,
      errors: validation.errors,
      warnings: validation.warnings,
      requirements: [
        'Format: SVG Tiny Portable/Secure (baseProfile="tiny-ps")',
        'Size: Maximum 32KB',
        'Aspect ratio: Must be square (1:1)',
        'No scripts, animations, or external references',
        'Must include <title> element for accessibility',
      ],
    });
  });

  /**
   * Check TLS reporting (TLSRPT) configuration
   * Companion to MTA-STS for receiving TLS connection reports
   * @see RFC 8460
   */
  router.get('/:id/tlsrpt', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    const result = await domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;
    const tlsrptResult = await verifyTLSRPT(domain.domain);

    return c.json({
      domain: domain.domain,
      tlsrpt: {
        supported: tlsrptResult.supported,
        record: tlsrptResult.record,
        error: tlsrptResult.error,
      },
      setupInstructions: !tlsrptResult.supported ? {
        dnsRecord: {
          type: 'TXT',
          name: `_smtp._tls.${domain.domain}`,
          value: generateTLSRPTRecord([`tlsrpt@${domain.domain}`]),
        },
        description: 'TLSRPT enables receiving reports about TLS connection issues from sending servers.',
      } : undefined,
    });
  });

  /**
   * Get comprehensive authentication status for a domain
   * Checks SPF, DKIM, DMARC, MTA-STS, BIMI, and TLSRPT
   */
  router.get('/:id/auth-status', async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.param('id');

    const result = await domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      throw ApiError.notFound('Domain');
    }

    const domain = result.value;
    
    // Run all checks in parallel
    const [healthResult, mtaStsResult, bimiResult, tlsrptResult] = await Promise.all([
      checkDnsHealth(domain),
      verifyMTASTS(domain.domain),
      verifyBIMI(domain.domain),
      verifyTLSRPT(domain.domain),
    ]);

    // Calculate overall score (0-100)
    let score = 0;
    const breakdown: Record<string, { status: 'pass' | 'fail' | 'warning'; points: number; maxPoints: number }> = {};

    // Basic auth (SPF, DKIM, DMARC) - 60 points
    const basicIssues = healthResult.issues.length;
    const basicPoints = Math.max(0, 60 - (basicIssues * 15));
    breakdown['basic'] = { 
      status: basicIssues === 0 ? 'pass' : basicIssues <= 2 ? 'warning' : 'fail',
      points: basicPoints,
      maxPoints: 60,
    };
    score += basicPoints;

    // MTA-STS - 20 points
    const mtaStsPoints = mtaStsResult.supported 
      ? (mtaStsResult.mode === 'enforce' ? 20 : 15)
      : 0;
    breakdown['mtaSts'] = {
      status: mtaStsResult.supported ? (mtaStsResult.mode === 'enforce' ? 'pass' : 'warning') : 'fail',
      points: mtaStsPoints,
      maxPoints: 20,
    };
    score += mtaStsPoints;

    // BIMI - 15 points
    const bimiPoints = bimiResult.supported
      ? (bimiResult.certificateValid ? 15 : 10)
      : 0;
    breakdown['bimi'] = {
      status: bimiResult.supported ? (bimiResult.certificateValid ? 'pass' : 'warning') : 'fail',
      points: bimiPoints,
      maxPoints: 15,
    };
    score += bimiPoints;

    // TLSRPT - 5 points
    const tlsrptPoints = tlsrptResult.supported ? 5 : 0;
    breakdown['tlsrpt'] = {
      status: tlsrptResult.supported ? 'pass' : 'fail',
      points: tlsrptPoints,
      maxPoints: 5,
    };
    score += tlsrptPoints;

    // Generate grade
    let grade: string;
    if (score >= 95) grade = 'A+';
    else if (score >= 90) grade = 'A';
    else if (score >= 85) grade = 'A-';
    else if (score >= 80) grade = 'B+';
    else if (score >= 75) grade = 'B';
    else if (score >= 70) grade = 'B-';
    else if (score >= 65) grade = 'C+';
    else if (score >= 60) grade = 'C';
    else if (score >= 50) grade = 'D';
    else grade = 'F';

    return c.json({
      domain: domain.domain,
      score,
      grade,
      breakdown,
      checks: {
        spfDkimDmarc: {
          status: healthResult.overall,
          issues: healthResult.issues,
        },
        mtaSts: {
          supported: mtaStsResult.supported,
          mode: mtaStsResult.mode,
          errors: mtaStsResult.errors,
        },
        bimi: {
          supported: bimiResult.supported,
          logoValid: bimiResult.logoValid,
          certificateValid: bimiResult.certificateValid,
        },
        tlsrpt: {
          supported: tlsrptResult.supported,
        },
      },
      recommendations: [
        ...mtaStsResult.recommendations,
        ...bimiResult.recommendations,
        ...(healthResult.issues.length > 0 ? ['Fix basic authentication issues first'] : []),
      ],
    });
  });

  return router;
}

interface DomainData {
  domain: string;
  verificationMethod: 'dns_txt' | 'dns_cname' | 'meta_tag';
  verificationToken: string;
  dnsRecords: {
    spf?: { value: string };
    dkim?: { selector: string; value: string };
    dmarc?: { value: string };
    returnPath?: { value: string };
  };
}

function getVerificationInstructions(domain: DomainData): Record<string, unknown> {
  switch (domain.verificationMethod) {
    case 'dns_txt':
      return {
        type: 'DNS TXT Record',
        name: `_apexmail.${domain.domain}`,
        value: domain.verificationToken,
        instructions: [
          `Add a TXT record to your DNS`,
          `Name/Host: _apexmail`,
          `Value: ${domain.verificationToken}`,
          `TTL: 3600 (or your provider's default)`,
        ],
      };
    case 'dns_cname':
      return {
        type: 'DNS CNAME Record',
        name: `_apexmail.${domain.domain}`,
        value: `verify.apexmail.ee`,
        instructions: [
          `Add a CNAME record to your DNS`,
          `Name/Host: _apexmail`,
          `Target: verify.apexmail.ee`,
        ],
      };
    case 'meta_tag':
      return {
        type: 'HTML Meta Tag',
        tag: `<meta name="apexmail-verification" content="${domain.verificationToken}" />`,
        instructions: [
          `Add the meta tag to your website's homepage`,
          `Place it in the <head> section`,
        ],
      };
  }
}

function generateDnsRecordInstructions(domain: DomainData): Array<{
  type: string;
  name: string;
  value: string;
  purpose: string;
  verified?: boolean;
}> {
  const records = [];

  // SPF
  if (domain.dnsRecords.spf) {
    records.push({
      type: 'TXT',
      name: domain.domain,
      value: domain.dnsRecords.spf.value,
      purpose: 'SPF - Authorizes ApexMail to send on your behalf',
    });
  }

  // DKIM
  if (domain.dnsRecords.dkim) {
    records.push({
      type: 'TXT',
      name: `${domain.dnsRecords.dkim.selector}._domainkey.${domain.domain}`,
      value: `v=DKIM1; k=rsa; p=${domain.dnsRecords.dkim.value}`,
      purpose: 'DKIM - Signs outgoing emails for authentication',
    });
  }

  // DMARC
  if (domain.dnsRecords.dmarc) {
    records.push({
      type: 'TXT',
      name: `_dmarc.${domain.domain}`,
      value: domain.dnsRecords.dmarc.value,
      purpose: 'DMARC - Defines handling policy for failed authentication',
    });
  }

  // Return Path (CNAME for bounce handling)
  if (domain.dnsRecords.returnPath) {
    records.push({
      type: 'CNAME',
      name: `bounce.${domain.domain}`,
      value: 'bounce.apexmail.ee',
      purpose: 'Return Path - Routes bounces to ApexMail for processing',
    });
  }

  return records;
}

async function verifyDomain(domain: DomainData): Promise<{ verified: boolean; details?: string }> {
  // In production, this would perform actual DNS lookups
  // For now, we'll simulate the verification process
  
  try {
    const dns = await import('dns').then(m => m.promises);
    
    switch (domain.verificationMethod) {
      case 'dns_txt': {
        const txtRecords = await dns.resolveTxt(`_apexmail.${domain.domain}`).catch(() => []);
        const flatRecords = txtRecords.flat();
        const found = flatRecords.some(record => record.includes(domain.verificationToken));
        return {
          verified: found,
          details: found ? undefined : 'TXT record not found or does not match verification token',
        };
      }
      
      case 'dns_cname': {
        const cnameRecords = await dns.resolveCname(`_apexmail.${domain.domain}`).catch(() => []);
        const found = cnameRecords.some(record => record === 'verify.apexmail.ee');
        return {
          verified: found,
          details: found ? undefined : 'CNAME record not found or incorrect',
        };
      }
      
      case 'meta_tag': {
        // Meta tag verification would require HTTP request to the domain
        // This is a placeholder
        return {
          verified: false,
          details: 'Meta tag verification not yet implemented',
        };
      }
    }
  } catch (error) {
    return {
      verified: false,
      details: error instanceof Error ? error.message : 'DNS lookup failed',
    };
  }
}

async function checkDnsHealth(domain: DomainData): Promise<{
  overall: 'healthy' | 'warning' | 'critical' | 'unknown';
  issues: string[];
  lastChecked: Date;
}> {
  const issues: string[] = [];

  try {
    const dns = await import('dns').then(m => m.promises);

    // Check SPF
    if (domain.dnsRecords.spf) {
      try {
        const txtRecords = await dns.resolveTxt(domain.domain);
        const spfRecords = txtRecords.flat().filter(r => r.startsWith('v=spf1'));
        if (spfRecords.length === 0) {
          issues.push('SPF record not found');
        } else if (spfRecords.length > 1) {
          issues.push('Multiple SPF records found (should have exactly one)');
        } else if (spfRecords[0] && !spfRecords[0].includes('apexmail')) {
          issues.push('SPF record does not include ApexMail');
        }
      } catch {
        issues.push('Could not verify SPF record');
      }
    }

    // Check DKIM
    if (domain.dnsRecords.dkim) {
      try {
        const dkimHost = `${domain.dnsRecords.dkim.selector}._domainkey.${domain.domain}`;
        await dns.resolveTxt(dkimHost);
      } catch {
        issues.push('DKIM record not found');
      }
    }

    // Check DMARC
    if (domain.dnsRecords.dmarc) {
      try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain.domain}`);
        const dmarc = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
        if (!dmarc) {
          issues.push('DMARC record not found');
        }
      } catch {
        issues.push('Could not verify DMARC record');
      }
    }
  } catch {
    return {
      overall: 'unknown',
      issues: ['DNS lookup failed'],
      lastChecked: new Date(),
    };
  }

  let overall: 'healthy' | 'warning' | 'critical';
  if (issues.length === 0) {
    overall = 'healthy';
  } else if (issues.some(i => i.includes('not found'))) {
    overall = 'critical';
  } else {
    overall = 'warning';
  }

  return {
    overall,
    issues,
    lastChecked: new Date(),
  };
}
