/**
 * BIMI (Brand Indicators for Message Identification)
 * 
 * BIMI allows senders to display their brand logo next to authenticated emails
 * in supporting email clients (Gmail, Yahoo, Apple Mail, etc.).
 * 
 * Requirements:
 * 1. DMARC policy must be at enforcement (p=quarantine or p=reject)
 * 2. Logo must be in SVG Tiny Portable/Secure format
 * 3. Optional but recommended: VMC (Verified Mark Certificate) for trademarked logos
 * 
 * How it works:
 * 1. Sender publishes BIMI DNS record: default._bimi.domain.com
 * 2. Record points to SVG logo URL and optional VMC certificate URL
 * 3. Receiving mail client displays logo if DMARC passes
 * 
 * Benefits:
 * - Visual brand recognition in inbox
 * - Increased trust and open rates
 * - Brand protection (with VMC)
 * 
 * @see https://bimigroup.org/implementation-guide/
 * @see https://tools.ietf.org/id/draft-svg-tiny-ps-abrotman-00.txt
 */

import * as dns from 'dns';
import * as https from 'https';
import { URL } from 'url';

export interface BIMIRecord {
  version: 'BIMI1';
  logoUrl: string;        // l= tag (required) - URL to SVG logo
  certificateUrl?: string; // a= tag (optional) - URL to VMC certificate
  selector: string;       // Usually "default"
}

export interface BIMIVerificationResult {
  supported: boolean;
  record: BIMIRecord | null;
  logoValid: boolean;
  dmarcValid: boolean;
  certificateValid: boolean;
  errors: string[];
  warnings: string[];
  recommendations: string[];
}

export interface BIMILogoRequirements {
  format: 'SVG Tiny PS';
  maxSize: number;      // 32KB recommended
  squareAspect: boolean;
  noAnimation: boolean;
  noExternalRefs: boolean;
  noScripts: boolean;
}

const BIMI_LOGO_REQUIREMENTS: BIMILogoRequirements = {
  format: 'SVG Tiny PS',
  maxSize: 32768,       // 32KB
  squareAspect: true,
  noAnimation: true,
  noExternalRefs: true,
  noScripts: true,
};

/**
 * Verify BIMI configuration for a domain
 */
export async function verifyBIMI(
  domain: string,
  selector: string = 'default'
): Promise<BIMIVerificationResult> {
  const result: BIMIVerificationResult = {
    supported: false,
    record: null,
    logoValid: false,
    dmarcValid: false,
    certificateValid: false,
    errors: [],
    warnings: [],
    recommendations: [],
  };

  // Step 1: Check DMARC policy (must be at enforcement)
  const dmarcResult = await checkDMARCForBIMI(domain);
  result.dmarcValid = dmarcResult.valid;
  if (!dmarcResult.valid) {
    result.errors.push(dmarcResult.error!);
    result.recommendations.push(
      'BIMI requires DMARC at enforcement: p=quarantine or p=reject'
    );
  }

  // Step 2: Check BIMI DNS record
  const bimiRecord = await checkBIMIDNSRecord(domain, selector);
  if (!bimiRecord.found) {
    result.errors.push('No BIMI record found');
    result.recommendations.push(
      `Add TXT record: ${selector}._bimi.${domain} with value "v=BIMI1; l=<logo-url>"`
    );
    return result;
  }
  result.record = bimiRecord.record!;
  result.supported = true;

  // Step 3: Validate logo
  const logoValidation = await validateBIMILogo(result.record.logoUrl);
  result.logoValid = logoValidation.valid;
  result.errors.push(...logoValidation.errors);
  result.warnings.push(...logoValidation.warnings);

  // Step 4: Validate certificate (if present)
  if (result.record.certificateUrl) {
    const certValidation = await validateVMC(result.record.certificateUrl);
    result.certificateValid = certValidation.valid;
    if (!certValidation.valid) {
      result.warnings.push(`VMC certificate issue: ${certValidation.error}`);
    }
  } else {
    result.warnings.push(
      'No VMC certificate specified. Some mailbox providers may not display your logo.'
    );
    result.recommendations.push(
      'Consider obtaining a Verified Mark Certificate (VMC) for broader support'
    );
  }

  // Step 5: Generate recommendations
  if (!result.logoValid) {
    result.recommendations.push(
      'Convert your logo to SVG Tiny PS format using BIMI-approved tools'
    );
  }

  return result;
}

/**
 * Generate BIMI DNS record value
 */
export function generateBIMIRecord(
  logoUrl: string,
  certificateUrl?: string
): string {
  let record = `v=BIMI1; l=${logoUrl}`;
  if (certificateUrl) {
    record += `; a=${certificateUrl}`;
  }
  return record;
}

/**
 * Validate an SVG logo against BIMI requirements
 */
export async function validateBIMILogo(
  logoUrl: string
): Promise<{ valid: boolean; errors: string[]; warnings: string[] }> {
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    // Fetch logo content
    const logoContent = await fetchContent(logoUrl, BIMI_LOGO_REQUIREMENTS.maxSize);
    
    if (!logoContent.success) {
      errors.push(logoContent.error!);
      return { valid: false, errors, warnings };
    }

    const svg = logoContent.content!;

    // Validate SVG structure
    if (!svg.includes('<svg') || !svg.includes('</svg>')) {
      errors.push('Invalid SVG structure');
      return { valid: false, errors, warnings };
    }

    // Check for SVG Tiny PS profile
    if (!svg.includes('baseProfile="tiny-ps"') && !svg.includes('baseProfile="tiny"')) {
      warnings.push('SVG should specify baseProfile="tiny-ps" for BIMI compliance');
    }

    // Check for scripts (not allowed)
    if (svg.includes('<script') || svg.includes('javascript:')) {
      errors.push('SVG must not contain scripts');
    }

    // Check for external references (not allowed)
    if (svg.includes('xlink:href="http') || svg.includes('href="http')) {
      const externalRefs = svg.match(/(?:xlink:)?href="(https?:[^"]+)"/g);
      if (externalRefs?.length) {
        errors.push('SVG must not contain external references');
      }
    }

    // Check for animation (not allowed)
    if (
      svg.includes('<animate') ||
      svg.includes('<animateTransform') ||
      svg.includes('<animateMotion')
    ) {
      errors.push('SVG must not contain animations');
    }

    // Check for foreign content (not allowed in Tiny PS)
    if (svg.includes('<foreignObject')) {
      errors.push('SVG must not contain foreignObject elements');
    }

    // Check viewBox for square aspect ratio
    const viewBoxMatch = svg.match(/viewBox=["']([^"']+)["']/);
    if (viewBoxMatch) {
      const parts = viewBoxMatch[1]!.split(/\s+/).map(Number);
      if (parts.length === 4) {
        const width = parts[2]!;
        const height = parts[3]!;
        if (Math.abs(width - height) > 0.01) {
          warnings.push('Logo should have a square aspect ratio (1:1)');
        }
      }
    }

    // Check file size
    if (svg.length > BIMI_LOGO_REQUIREMENTS.maxSize) {
      errors.push(`Logo exceeds maximum size of ${BIMI_LOGO_REQUIREMENTS.maxSize / 1024}KB`);
    }

    // Check title element (recommended)
    if (!svg.includes('<title>')) {
      warnings.push('Logo should include a <title> element for accessibility');
    }

  } catch (error) {
    errors.push(`Failed to validate logo: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Generate DNS instructions for BIMI setup
 */
export function getBIMISetupInstructions(domain: string, logoUrl: string, certificateUrl?: string): {
  dnsRecord: {
    type: string;
    name: string;
    value: string;
  };
  requirements: string[];
  steps: string[];
} {
  return {
    dnsRecord: {
      type: 'TXT',
      name: `default._bimi.${domain}`,
      value: generateBIMIRecord(logoUrl, certificateUrl),
    },
    requirements: [
      'DMARC policy must be at enforcement (p=quarantine or p=reject)',
      'Logo must be SVG Tiny Portable/Secure format',
      'Logo must be square aspect ratio',
      'Logo file size should be under 32KB',
      'Logo must not contain scripts, animations, or external references',
    ],
    steps: [
      '1. Ensure your DMARC policy is p=quarantine or p=reject',
      '2. Create an SVG Tiny PS version of your logo',
      '3. Host the logo at a publicly accessible HTTPS URL',
      '4. (Optional) Obtain a Verified Mark Certificate (VMC) for your logo',
      '5. Add the BIMI DNS TXT record',
      '6. Wait for DNS propagation (up to 48 hours)',
    ],
  };
}

// Helper functions

async function checkDMARCForBIMI(domain: string): Promise<{ valid: boolean; error?: string }> {
  return new Promise((resolve) => {
    dns.resolveTxt(`_dmarc.${domain}`, (err, records) => {
      if (err || !records?.length) {
        resolve({ valid: false, error: 'No DMARC record found' });
        return;
      }

      const dmarcRecord = records.flat().join('');
      
      // Check for enforcement policy
      const policyMatch = dmarcRecord.match(/p=(quarantine|reject)/i);
      if (!policyMatch) {
        resolve({ 
          valid: false, 
          error: 'DMARC policy must be p=quarantine or p=reject for BIMI' 
        });
        return;
      }

      // Check for subdomain policy (sp=)
      const spMatch = dmarcRecord.match(/sp=(none)/i);
      if (spMatch) {
        resolve({
          valid: false,
          error: 'DMARC subdomain policy (sp=none) may prevent BIMI on subdomains',
        });
        return;
      }

      resolve({ valid: true });
    });
  });
}

async function checkBIMIDNSRecord(
  domain: string,
  selector: string
): Promise<{ found: boolean; record?: BIMIRecord }> {
  return new Promise((resolve) => {
    dns.resolveTxt(`${selector}._bimi.${domain}`, (err, records) => {
      if (err || !records?.length) {
        resolve({ found: false });
        return;
      }

      const txtValue = records.flat().join('');
      
      // Parse BIMI record: v=BIMI1; l=<url>; a=<url>
      const versionMatch = txtValue.match(/v=BIMI1/i);
      const logoMatch = txtValue.match(/l=([^;\s]+)/i);
      const certMatch = txtValue.match(/a=([^;\s]+)/i);

      if (versionMatch && logoMatch) {
        resolve({
          found: true,
          record: {
            version: 'BIMI1',
            logoUrl: logoMatch[1]!,
            certificateUrl: certMatch?.[1],
            selector,
          },
        });
      } else {
        resolve({ found: false });
      }
    });
  });
}

async function validateVMC(certificateUrl: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const result = await fetchContent(certificateUrl, 100000); // 100KB max for cert
    
    if (!result.success) {
      return { valid: false, error: result.error };
    }

    // Basic PEM structure check
    const content = result.content!;
    if (!content.includes('-----BEGIN CERTIFICATE-----')) {
      return { valid: false, error: 'Invalid certificate format' };
    }

    // In production, you would:
    // 1. Parse the X.509 certificate
    // 2. Verify it's issued by an approved Mark Verifying Authority (MVA)
    // 3. Check the certificate hasn't expired
    // 4. Verify the logoHash matches the logo

    return { valid: true };
  } catch (error) {
    return { 
      valid: false, 
      error: error instanceof Error ? error.message : 'Certificate validation failed' 
    };
  }
}

function fetchContent(
  url: string,
  maxSize: number
): Promise<{ success: boolean; content?: string; error?: string }> {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      
      if (parsedUrl.protocol !== 'https:') {
        resolve({ success: false, error: 'URL must use HTTPS' });
        return;
      }

      const req = https.get(
        {
          hostname: parsedUrl.hostname,
          path: parsedUrl.pathname + parsedUrl.search,
          timeout: 10000,
          headers: {
            'User-Agent': 'ApexMail-BIMI-Validator/1.0',
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            resolve({ success: false, error: `HTTP ${res.statusCode}` });
            return;
          }

          let data = '';
          let size = 0;

          res.on('data', (chunk) => {
            size += chunk.length;
            if (size > maxSize) {
              req.destroy();
              resolve({ success: false, error: `Content exceeds maximum size of ${maxSize} bytes` });
              return;
            }
            data += chunk;
          });

          res.on('end', () => {
            resolve({ success: true, content: data });
          });
        }
      );

      req.on('error', (error) => {
        resolve({ success: false, error: error.message });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, error: 'Request timed out' });
      });
    } catch (error) {
      resolve({ 
        success: false, 
        error: error instanceof Error ? error.message : 'Invalid URL' 
      });
    }
  });
}

/**
 * BIMI indicator for mailbox providers
 */
export interface BIMIIndicator {
  logoUrl: string;
  selector: string;
  verified: boolean;  // VMC verified
  timestamp: Date;
}

/**
 * Get BIMI indicator for display (used by receiving email servers)
 */
export async function getBIMIIndicator(
  domain: string,
  dmarcPassed: boolean
): Promise<BIMIIndicator | null> {
  if (!dmarcPassed) {
    return null; // BIMI only shows for DMARC-passing messages
  }

  const verification = await verifyBIMI(domain);
  
  if (!verification.supported || !verification.record || !verification.logoValid) {
    return null;
  }

  return {
    logoUrl: verification.record.logoUrl,
    selector: verification.record.selector,
    verified: verification.certificateValid,
    timestamp: new Date(),
  };
}
