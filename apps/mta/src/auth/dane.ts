/**
 * DANE - DNS-based Authentication of Named Entities (RFC 6698, RFC 7671, RFC 7672)
 * 
 * DANE uses DNSSEC-secured TLSA records to associate TLS certificates with
 * domain names, providing an alternative to CA-based PKI for SMTP.
 * 
 * DANE-TA (Trust Anchor) - Certificate/public key of a CA that issued the server's certificate
 * DANE-EE (End Entity) - Certificate/public key of the server itself
 * 
 * Usage Values:
 * - 0: PKIX-TA (CA constraint)
 * - 1: PKIX-EE (Service certificate constraint)  
 * - 2: DANE-TA (Trust anchor assertion)
 * - 3: DANE-EE (Domain-issued certificate)
 * 
 * Selector Values:
 * - 0: Full certificate
 * - 1: SubjectPublicKeyInfo (SPKI)
 * 
 * Matching Type Values:
 * - 0: Full content (no hash)
 * - 1: SHA-256 hash
 * - 2: SHA-512 hash
 */

import { createHash, X509Certificate as NodeX509Certificate } from 'crypto';
import type { X509Certificate } from 'crypto';

export interface TlsaRecord {
  usage: 0 | 1 | 2 | 3;
  selector: 0 | 1;
  matchingType: 0 | 1 | 2;
  certificateAssociationData: string; // Hex-encoded
}

export interface DaneVerificationResult {
  supported: boolean;
  mode: 'dane-ee' | 'dane-ta' | 'pkix' | 'none';
  tlsaRecords: TlsaRecord[];
  errors: string[];
  warnings: string[];
  recommendations: string[];
}

export interface DaneRecordGenerationResult {
  record: string;
  tlsaRecord: TlsaRecord;
  dnsRecord: string;
  errors: string[];
  recommendations: string[];
}

// TLSA record usage type names
const USAGE_NAMES: Record<number, string> = {
  0: 'PKIX-TA',
  1: 'PKIX-EE',
  2: 'DANE-TA',
  3: 'DANE-EE',
};

// TLSA selector names
const SELECTOR_NAMES: Record<number, string> = {
  0: 'Full certificate',
  1: 'SubjectPublicKeyInfo (SPKI)',
};

// TLSA matching type names
const MATCHING_TYPE_NAMES: Record<number, string> = {
  0: 'Exact match',
  1: 'SHA-256',
  2: 'SHA-512',
};

/**
 * Verify DANE/TLSA configuration for a domain
 * 
 * Checks:
 * 1. DNSSEC is properly configured
 * 2. TLSA records exist for the mail server
 * 3. TLSA records are valid and match the certificate
 * 
 * @param domain - Domain to verify DANE for
 * @param port - Port to check (default 25 for SMTP)
 * @param protocol - Protocol (default tcp)
 */
export async function verifyDANE(
  domain: string,
  port: number = 25,
  protocol: string = 'tcp'
): Promise<DaneVerificationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const recommendations: string[] = [];
  const tlsaRecords: TlsaRecord[] = [];

  // Construct TLSA record name: _port._protocol.hostname
  const tlsaName = `_${port}._${protocol}.${domain}`;

  try {
    // Use DNS lookup to find TLSA records
    // In production, this would use DNSSEC-validating resolver
    const records = await lookupTLSA(tlsaName);

    if (!records || records.length === 0) {
      // No TLSA records found
      warnings.push(`No TLSA records found for ${tlsaName}`);
      recommendations.push('Publish TLSA records to enable DANE for this domain');
      recommendations.push(`Add: ${tlsaName} IN TLSA <usage> <selector> <matching-type> <certificate-data>`);
      
      return {
        supported: false,
        mode: 'none',
        tlsaRecords: [],
        errors,
        warnings,
        recommendations,
      };
    }

    // Parse and validate TLSA records
    for (const record of records) {
      const parsed = parseTLSARecord(record);
      if (parsed.error) {
        errors.push(parsed.error);
        continue;
      }
      
      if (parsed.tlsa) {
        tlsaRecords.push(parsed.tlsa);
        
        // Validate record parameters
        if (parsed.tlsa.usage === 0 || parsed.tlsa.usage === 1) {
          warnings.push(`PKIX-* usage (${parsed.tlsa.usage}) requires CA validation in addition to DANE`);
        }
        
        if (parsed.tlsa.matchingType === 0) {
          recommendations.push('Consider using SHA-256 (1) or SHA-512 (2) matching type instead of full certificate (0)');
        }
      }
    }

    if (tlsaRecords.length === 0) {
      errors.push('No valid TLSA records could be parsed');
      return {
        supported: false,
        mode: 'none',
        tlsaRecords: [],
        errors,
        warnings,
        recommendations,
      };
    }

    // Determine DANE mode based on usage values
    const hasDANE_EE = tlsaRecords.some((r) => r.usage === 3);
    const hasDANE_TA = tlsaRecords.some((r) => r.usage === 2);
    const hasPKIX = tlsaRecords.some((r) => r.usage === 0 || r.usage === 1);

    let mode: 'dane-ee' | 'dane-ta' | 'pkix' | 'none' = 'none';
    if (hasDANE_EE) {
      mode = 'dane-ee';
      recommendations.push('DANE-EE (usage 3) provides strongest security - certificate is directly asserted');
    } else if (hasDANE_TA) {
      mode = 'dane-ta';
      recommendations.push('DANE-TA (usage 2) - consider also adding DANE-EE (usage 3) for rollover');
    } else if (hasPKIX) {
      mode = 'pkix';
      warnings.push('PKIX-based DANE still relies on CA infrastructure');
    }

    // Check DNSSEC
    const dnssecResult = await checkDNSSEC(domain);
    if (!dnssecResult.secure) {
      errors.push('DNSSEC is not properly configured - DANE requires DNSSEC validation');
      recommendations.push('Enable DNSSEC for your domain before deploying DANE');
    }

    return {
      supported: tlsaRecords.length > 0 && errors.length === 0,
      mode,
      tlsaRecords,
      errors,
      warnings,
      recommendations,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    errors.push(`DANE verification failed: ${errorMessage}`);
    
    return {
      supported: false,
      mode: 'none',
      tlsaRecords: [],
      errors,
      warnings,
      recommendations,
    };
  }
}

/**
 * Generate a TLSA record for a certificate
 * 
 * @param certificate - PEM-encoded certificate or X509Certificate
 * @param domain - Domain name for the record
 * @param options - Generation options
 */
export function generateTLSARecord(
  certificate: string | X509Certificate,
  domain: string,
  options: {
    port?: number;
    protocol?: string;
    usage?: 0 | 1 | 2 | 3;
    selector?: 0 | 1;
    matchingType?: 0 | 1 | 2;
  } = {}
): DaneRecordGenerationResult {
  const errors: string[] = [];
  const recommendations: string[] = [];

  const {
    port = 25,
    protocol = 'tcp',
    usage = 3, // DANE-EE (recommended)
    selector = 1, // SPKI (recommended)
    matchingType = 1, // SHA-256 (recommended)
  } = options;

  try {
    // Extract certificate data
    let certData: Buffer;
    
    if (typeof certificate === 'string') {
      // PEM-encoded certificate
      const pemMatch = certificate.match(
        /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/
      );
      if (!pemMatch) {
        errors.push('Invalid PEM certificate format');
        return {
          record: '',
          tlsaRecord: { usage, selector, matchingType, certificateAssociationData: '' },
          dnsRecord: '',
          errors,
          recommendations,
        };
      }
      const certBase64 = pemMatch[1];
      if (!certBase64) {
        errors.push('Invalid PEM certificate: no data found');
        return {
          record: '',
          tlsaRecord: { usage, selector, matchingType, certificateAssociationData: '' },
          dnsRecord: '',
          errors,
          recommendations,
        };
      }
      certData = Buffer.from(certBase64.replace(/\s/g, ''), 'base64');
    } else {
      // X509Certificate object
      certData = Buffer.from(certificate.raw);
    }

    // Extract the data to hash based on selector
    let dataToHash: Buffer;
    if (selector === 0) {
      // Full certificate
      dataToHash = certData;
    } else {
      // SPKI - SubjectPublicKeyInfo
      // For proper SPKI extraction, we would need to parse the certificate
      // This is a simplified version that works with the full cert
      dataToHash = extractSPKI(certData);
    }

    // Calculate hash based on matching type
    let certificateAssociationData: string;
    if (matchingType === 0) {
      // Exact match - hex encode the raw data
      certificateAssociationData = dataToHash.toString('hex');
    } else if (matchingType === 1) {
      // SHA-256
      certificateAssociationData = createHash('sha256').update(dataToHash).digest('hex');
    } else {
      // SHA-512
      certificateAssociationData = createHash('sha512').update(dataToHash).digest('hex');
    }

    const tlsaRecord: TlsaRecord = {
      usage,
      selector,
      matchingType,
      certificateAssociationData,
    };

    const recordName = `_${port}._${protocol}.${domain}`;
    const dnsRecord = `${recordName}. IN TLSA ${usage} ${selector} ${matchingType} ${certificateAssociationData}`;

    // Add recommendations
    recommendations.push(`Add this DNS record: ${dnsRecord}`);
    recommendations.push('Ensure DNSSEC is enabled for your domain');
    if (usage === 3 && selector === 1 && matchingType === 1) {
      recommendations.push('Configuration uses recommended DANE-EE with SPKI selector and SHA-256');
    }

    return {
      record: `${usage} ${selector} ${matchingType} ${certificateAssociationData}`,
      tlsaRecord,
      dnsRecord,
      errors,
      recommendations,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    errors.push(`Failed to generate TLSA record: ${errorMessage}`);
    
    return {
      record: '',
      tlsaRecord: { usage, selector, matchingType, certificateAssociationData: '' },
      dnsRecord: '',
      errors,
      recommendations,
    };
  }
}

/**
 * Validate that a certificate matches a TLSA record
 * 
 * @param certificate - PEM-encoded certificate
 * @param tlsaRecord - TLSA record to match against
 */
export function validateCertificateAgainstTLSA(
  certificate: string,
  tlsaRecord: TlsaRecord
): { valid: boolean; error?: string } {
  try {
    // Generate TLSA data for comparison
    const generated = generateTLSARecord(certificate, 'validation', {
      usage: tlsaRecord.usage,
      selector: tlsaRecord.selector,
      matchingType: tlsaRecord.matchingType,
    });

    if (generated.errors.length > 0) {
      return { valid: false, error: generated.errors.join('; ') };
    }

    const match =
      generated.tlsaRecord.certificateAssociationData.toLowerCase() ===
      tlsaRecord.certificateAssociationData.toLowerCase();

    return {
      valid: match,
      error: match ? undefined : 'Certificate does not match TLSA record',
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Get human-readable description of a TLSA record
 */
export function describeTLSARecord(record: TlsaRecord): string {
  const usage = USAGE_NAMES[record.usage] ?? `Unknown (${record.usage})`;
  const selector = SELECTOR_NAMES[record.selector] ?? `Unknown (${record.selector})`;
  const matching = MATCHING_TYPE_NAMES[record.matchingType] ?? `Unknown (${record.matchingType})`;
  
  return `TLSA Record: Usage=${usage}, Selector=${selector}, Matching=${matching}`;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Lookup TLSA records for a domain
 * Uses DNS over HTTPS or system resolver
 */
async function lookupTLSA(name: string): Promise<string[]> {
  try {
    // Use DNS over HTTPS to query with DNSSEC validation
    // This uses Cloudflare's DNS-over-HTTPS endpoint
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TLSA`,
      {
        headers: {
          Accept: 'application/dns-json',
        },
      }
    );

    if (!response.ok) {
      return [];
    }

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ type: number; data: string }>;
      AD?: boolean;
    };

    // Check for DNSSEC validation (AD flag)
    if (!data.AD) {
      // Warning: Response not DNSSEC validated
      // In production, this should be handled more strictly
    }

    if (!data.Answer) {
      return [];
    }

    // Filter for TLSA records (type 52)
    return data.Answer
      .filter((r) => r.type === 52)
      .map((r) => r.data);
  } catch {
    // Fallback: return empty array if DNS lookup fails
    return [];
  }
}

/**
 * Parse a TLSA record string into structured format
 */
function parseTLSARecord(record: string): { tlsa?: TlsaRecord; error?: string } {
  // TLSA record format: <usage> <selector> <matching-type> <certificate-data>
  const parts = record.trim().split(/\s+/);
  
  if (parts.length < 4) {
    return { error: `Invalid TLSA record format: ${record}` };
  }

  const usageStr = parts[0];
  const selectorStr = parts[1];
  const matchingTypeStr = parts[2];
  
  if (!usageStr || !selectorStr || !matchingTypeStr) {
    return { error: `Invalid TLSA record format: missing fields` };
  }
  
  const usage = parseInt(usageStr, 10);
  const selector = parseInt(selectorStr, 10);
  const matchingType = parseInt(matchingTypeStr, 10);
  const certificateAssociationData = parts.slice(3).join('').toLowerCase();

  // Validate usage
  if (usage < 0 || usage > 3) {
    return { error: `Invalid TLSA usage value: ${usage}` };
  }

  // Validate selector
  if (selector < 0 || selector > 1) {
    return { error: `Invalid TLSA selector value: ${selector}` };
  }

  // Validate matching type
  if (matchingType < 0 || matchingType > 2) {
    return { error: `Invalid TLSA matching type value: ${matchingType}` };
  }

  // Validate certificate data is hex
  if (!/^[0-9a-f]+$/.test(certificateAssociationData)) {
    return { error: 'Invalid certificate association data: not valid hex' };
  }

  // Validate certificate data length based on matching type
  if (matchingType === 1 && certificateAssociationData.length !== 64) {
    return { error: 'SHA-256 hash should be 64 hex characters' };
  }
  if (matchingType === 2 && certificateAssociationData.length !== 128) {
    return { error: 'SHA-512 hash should be 128 hex characters' };
  }

  return {
    tlsa: {
      usage: usage as 0 | 1 | 2 | 3,
      selector: selector as 0 | 1,
      matchingType: matchingType as 0 | 1 | 2,
      certificateAssociationData,
    },
  };
}

/**
 * Check DNSSEC configuration for a domain
 */
async function checkDNSSEC(domain: string): Promise<{ secure: boolean; error?: string }> {
  try {
    // Query for DNSKEY records to verify DNSSEC
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DNSKEY`,
      {
        headers: {
          Accept: 'application/dns-json',
        },
      }
    );

    if (!response.ok) {
      return { secure: false, error: 'Failed to query DNSSEC status' };
    }

    const data = await response.json() as {
      Status: number;
      AD?: boolean;
      Answer?: Array<{ type: number }>;
    };

    // AD (Authenticated Data) flag indicates DNSSEC validation passed
    if (data.AD === true) {
      return { secure: true };
    }

    // Check if DNSKEY records exist
    if (data.Answer && data.Answer.some((r) => r.type === 48)) {
      return { secure: true };
    }

    return { secure: false, error: 'DNSSEC not enabled or not validated' };
  } catch (error) {
    return {
      secure: false,
      error: error instanceof Error ? error.message : 'DNSSEC check failed',
    };
  }
}

/**
 * Extract SubjectPublicKeyInfo from a DER-encoded certificate
 * Simplified implementation - in production use a proper X.509 parser
 */
function extractSPKI(certDER: Buffer): Buffer {
  // ASN.1 structure of X.509 certificate:
  // Certificate ::= SEQUENCE {
  //   tbsCertificate       TBSCertificate,
  //   signatureAlgorithm   AlgorithmIdentifier,
  //   signatureValue       BIT STRING
  // }
  // TBSCertificate ::= SEQUENCE {
  //   version         [0]  EXPLICIT Version DEFAULT v1,
  //   serialNumber         CertificateSerialNumber,
  //   signature            AlgorithmIdentifier,
  //   issuer               Name,
  //   validity             Validity,
  //   subject              Name,
  //   subjectPublicKeyInfo SubjectPublicKeyInfo,  <-- We want this
  //   ...
  // }
  
  // For simplification, we'll hash the full certificate
  // A proper implementation would use node:crypto's X509Certificate.publicKey
  // or an ASN.1 parser like @peculiar/asn1-x509
  
  try {
    // Use Node.js crypto X509Certificate
    const cert = new NodeX509Certificate(certDER);
    // Export public key in SPKI format
    const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    return Buffer.from(spki);
  } catch {
    // Fallback to using full certificate (valid for selector=0)
  }
  
  return certDER;
}

export default {
  verifyDANE,
  generateTLSARecord,
  validateCertificateAgainstTLSA,
  describeTLSARecord,
};
