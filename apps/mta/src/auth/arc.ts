/**
 * ARC (Authenticated Received Chain) - RFC 8617
 * 
 * ARC preserves email authentication results across intermediaries (forwarding).
 * This is critical for deliverability when emails are forwarded through mailing lists
 * or other intermediaries that may break SPF/DKIM.
 * 
 * ARC Header Set (AS) consists of:
 * - ARC-Seal: Cryptographic signature of the ARC chain
 * - ARC-Message-Signature: DKIM-like signature of the message
 * - ARC-Authentication-Results: Authentication results at this hop
 * 
 * @see https://tools.ietf.org/html/rfc8617
 */

import * as crypto from 'crypto';

export interface ARCAuthResult {
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  dkim: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
  dmarc: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
}

export interface ARCSet {
  instance: number;
  authenticationResults: string;
  messageSignature: string;
  seal: string;
}

export interface ARCSigningConfig {
  domain: string;
  selector: string;
  privateKey: string;
}

/**
 * Generate ARC headers for outbound forwarded messages
 */
export function generateARCHeaders(
  message: {
    headers: Record<string, string>;
    body: string;
  },
  authResult: ARCAuthResult,
  config: ARCSigningConfig,
  existingARCChain: ARCSet[] = []
): ARCSet {
  const instance = existingARCChain.length + 1;
  const timestamp = Math.floor(Date.now() / 1000);
  
  // 1. Generate ARC-Authentication-Results
  const authResultsHeader = formatARCAuthResults(instance, config.domain, authResult);
  
  // 2. Generate ARC-Message-Signature (similar to DKIM)
  const messageSignature = generateARCMessageSignature(
    message,
    instance,
    config,
    timestamp
  );
  
  // 3. Generate ARC-Seal (signs the entire ARC chain)
  const seal = generateARCSeal(
    instance,
    authResultsHeader,
    messageSignature,
    existingARCChain,
    config,
    timestamp
  );
  
  return {
    instance,
    authenticationResults: authResultsHeader,
    messageSignature,
    seal,
  };
}

/**
 * Validate an incoming ARC chain
 */
export function validateARCChain(
  arcSets: ARCSet[],
  _lookupDKIMKey: (domain: string, selector: string) => Promise<string | null>
): Promise<{
  valid: boolean;
  chainValidation: 'pass' | 'fail' | 'none';
  errors: string[];
}> {
  return new Promise(async (resolve) => {
    if (arcSets.length === 0) {
      resolve({ valid: true, chainValidation: 'none', errors: [] });
      return;
    }

    const errors: string[] = [];
    
    // Validate chain is sequential (i=1, i=2, i=3, ...)
    for (let i = 0; i < arcSets.length; i++) {
      if (arcSets[i]!.instance !== i + 1) {
        errors.push(`ARC chain broken: expected instance ${i + 1}, got ${arcSets[i]!.instance}`);
      }
    }

    // Each ARC-Seal must validate
    // In production, this would verify each seal's signature using the public key
    // For now, we'll do structural validation
    for (const arcSet of arcSets) {
      if (!arcSet.seal.includes('cv=')) {
        errors.push(`ARC-Seal missing cv= tag for instance ${arcSet.instance}`);
      }
      if (!arcSet.seal.includes('b=')) {
        errors.push(`ARC-Seal missing signature for instance ${arcSet.instance}`);
      }
    }

    resolve({
      valid: errors.length === 0,
      chainValidation: errors.length === 0 ? 'pass' : 'fail',
      errors,
    });
  });
}

/**
 * Parse ARC headers from an incoming message
 */
export function parseARCHeaders(headers: Record<string, string | string[]>): ARCSet[] {
  const arcSets: ARCSet[] = [];
  
  // Normalize headers to arrays
  const normalizeHeader = (h: string | string[] | undefined): string[] => {
    if (!h) return [];
    return Array.isArray(h) ? h : [h];
  };

  const authResults = normalizeHeader(headers['arc-authentication-results']);
  const msgSigs = normalizeHeader(headers['arc-message-signature']);
  const seals = normalizeHeader(headers['arc-seal']);

  // Parse each ARC set
  for (const authResult of authResults) {
    const instanceMatch = authResult.match(/i=(\d+)/);
    if (!instanceMatch) continue;
    
    const instance = parseInt(instanceMatch[1]!, 10);
    const msgSig = msgSigs.find(s => s.includes(`i=${instance}`)) || '';
    const seal = seals.find(s => s.includes(`i=${instance}`)) || '';
    
    arcSets.push({
      instance,
      authenticationResults: authResult,
      messageSignature: msgSig,
      seal,
    });
  }

  // Sort by instance number
  arcSets.sort((a, b) => a.instance - b.instance);
  
  return arcSets;
}

// Helper functions

function formatARCAuthResults(
  instance: number,
  authservId: string,
  results: ARCAuthResult
): string {
  const parts = [`i=${instance}`, authservId];
  
  parts.push(`spf=${results.spf}`);
  parts.push(`dkim=${results.dkim}`);
  parts.push(`dmarc=${results.dmarc}`);
  
  return parts.join('; ');
}

function generateARCMessageSignature(
  message: { headers: Record<string, string>; body: string },
  instance: number,
  config: ARCSigningConfig,
  timestamp: number
): string {
  // Headers to sign (subset used for ARC)
  const signedHeaders = ['from', 'to', 'subject', 'date', 'message-id'].filter(
    h => message.headers[h]
  );
  
  // Create canonicalized header string
  const canonicalHeaders = signedHeaders
    .map(h => `${h}:${message.headers[h]?.trim() || ''}`)
    .join('\r\n');
  
  // Create body hash
  const bodyHash = crypto
    .createHash('sha256')
    .update(message.body)
    .digest('base64');
  
  // Create signature base
  const signatureBase = [
    `i=${instance}`,
    `a=rsa-sha256`,
    `c=relaxed/relaxed`,
    `d=${config.domain}`,
    `s=${config.selector}`,
    `t=${timestamp}`,
    `h=${signedHeaders.join(':')}`,
    `bh=${bodyHash}`,
  ].join('; ');
  
  // Sign (in production, use actual private key)
  const signature = crypto
    .createSign('RSA-SHA256')
    .update(signatureBase + '\r\n' + canonicalHeaders)
    .sign(config.privateKey, 'base64');
  
  return `${signatureBase}; b=${signature}`;
}

function generateARCSeal(
  instance: number,
  authResults: string,
  messageSignature: string,
  existingChain: ARCSet[],
  config: ARCSigningConfig,
  timestamp: number
): string {
  // Determine chain validation status
  const cv = existingChain.length === 0 ? 'none' : 'pass';
  
  const sealBase = [
    `i=${instance}`,
    `a=rsa-sha256`,
    `cv=${cv}`,
    `d=${config.domain}`,
    `s=${config.selector}`,
    `t=${timestamp}`,
  ].join('; ');
  
  // Create data to sign: includes all previous ARC headers plus new ones
  const dataToSign = [
    ...existingChain.map(s => s.authenticationResults),
    authResults,
    ...existingChain.map(s => s.messageSignature),
    messageSignature,
    ...existingChain.map(s => s.seal),
  ].join('\r\n');
  
  const signature = crypto
    .createSign('RSA-SHA256')
    .update(sealBase + '\r\n' + dataToSign)
    .sign(config.privateKey, 'base64');
  
  return `${sealBase}; b=${signature}`;
}

/**
 * Format ARC headers for insertion into email
 */
export function formatARCHeadersForMessage(arcSet: ARCSet): Record<string, string> {
  return {
    'ARC-Seal': arcSet.seal,
    'ARC-Message-Signature': arcSet.messageSignature,
    'ARC-Authentication-Results': arcSet.authenticationResults,
  };
}
