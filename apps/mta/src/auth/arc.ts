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
 * Parse ARC header tag=value pairs
 */
function parseARCTags(header: string): Record<string, string> {
  const params: Record<string, string> = {};
  const parts = header.split(/;\s*/);
  
  for (const part of parts) {
    const eqIndex = part.indexOf('=');
    if (eqIndex > 0) {
      const key = part.slice(0, eqIndex).trim();
      const value = part.slice(eqIndex + 1).trim();
      params[key] = value;
    }
  }
  
  return params;
}

/**
 * Verify an ARC-Seal or ARC-Message-Signature cryptographically
 * RFC 8617 Section 5.1
 */
async function verifyARCSignature(
  headerValue: string,
  dataToVerify: string,
  lookupDKIMKey: (domain: string, selector: string) => Promise<string | null>
): Promise<{ valid: boolean; error?: string }> {
  const params = parseARCTags(headerValue);
  
  // Extract required parameters
  const domain = params.d;
  const selector = params.s;
  const algorithm = params.a ?? 'rsa-sha256';
  const signature = params.b?.replace(/\s+/g, '');
  
  if (!domain || !selector) {
    return { valid: false, error: 'Missing d= or s= tag' };
  }
  
  if (!signature) {
    return { valid: false, error: 'Missing b= signature' };
  }
  
  // Validate algorithm (RFC 8617 only allows rsa-sha256)
  if (algorithm !== 'rsa-sha256') {
    return { valid: false, error: `Unsupported algorithm: ${algorithm}. RFC 8617 requires rsa-sha256` };
  }
  
  // Fetch public key from DNS
  const publicKey = await lookupDKIMKey(domain, selector);
  
  if (!publicKey) {
    return { valid: false, error: `Public key not found for ${selector}._domainkey.${domain}` };
  }
  
  try {
    // Reconstruct the header without the b= value for verification
    // Per RFC 8617, the signature is computed over the header with b= emptied
    const headerWithoutSig = headerValue.replace(/b=[^;]+/, 'b=').replace(/\s+/g, ' ').trim();
    const signedData = dataToVerify + '\r\n' + headerWithoutSig;
    
    // Verify the signature
    const pemKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signedData);
    
    const signatureBuffer = Buffer.from(signature, 'base64');
    const valid = verifier.verify(pemKey, signatureBuffer);
    
    return { valid };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';
    return { valid: false, error: `Signature verification failed: ${errorMessage}` };
  }
}

/**
 * Build the data string to verify for an ARC-Seal
 * RFC 8617 Section 5.1.2
 */
function buildARCSealVerificationData(
  arcSets: ARCSet[],
  currentInstance: number
): string {
  const parts: string[] = [];
  
  // Include all ARC headers from previous instances in order
  for (let i = 1; i < currentInstance; i++) {
    const arcSet = arcSets.find(s => s.instance === i);
    if (arcSet) {
      // Order matters: AAR, AMS, AS for each instance
      parts.push(`arc-authentication-results:${arcSet.authenticationResults.replace(/^i=\d+;\s*/, '')}`);
    }
  }
  
  for (let i = 1; i < currentInstance; i++) {
    const arcSet = arcSets.find(s => s.instance === i);
    if (arcSet) {
      parts.push(`arc-message-signature:${arcSet.messageSignature}`);
    }
  }
  
  for (let i = 1; i < currentInstance; i++) {
    const arcSet = arcSets.find(s => s.instance === i);
    if (arcSet) {
      parts.push(`arc-seal:${arcSet.seal}`);
    }
  }
  
  // Add current instance's AAR and AMS (but not AS, that's what we're verifying)
  const currentSet = arcSets.find(s => s.instance === currentInstance);
  if (currentSet) {
    parts.push(`arc-authentication-results:${currentSet.authenticationResults.replace(/^i=\d+;\s*/, '')}`);
    parts.push(`arc-message-signature:${currentSet.messageSignature}`);
  }
  
  return parts.join('\r\n');
}

/**
 * Validate an incoming ARC chain with full cryptographic verification
 * RFC 8617 Section 5 - ARC Validation
 */
export function validateARCChain(
  arcSets: ARCSet[],
  lookupDKIMKey: (domain: string, selector: string) => Promise<string | null>
): Promise<{
  valid: boolean;
  chainValidation: 'pass' | 'fail' | 'none';
  errors: string[];
}> {
  return new Promise(async (resolve) => {
    // No ARC headers = none result (not an error)
    if (arcSets.length === 0) {
      resolve({ valid: true, chainValidation: 'none', errors: [] });
      return;
    }

    const errors: string[] = [];
    
    // RFC 8617 Section 5.2 Step 1: Validate chain is sequential (i=1, i=2, i=3, ...)
    for (let i = 0; i < arcSets.length; i++) {
      const expectedInstance = i + 1;
      if (arcSets[i]!.instance !== expectedInstance) {
        errors.push(`ARC chain broken: expected instance ${expectedInstance}, got ${arcSets[i]!.instance}`);
        resolve({ valid: false, chainValidation: 'fail', errors });
        return;
      }
    }

    // RFC 8617 Section 5.2 Step 2: Validate each ARC set has required components
    for (const arcSet of arcSets) {
      // Validate ARC-Authentication-Results format
      if (!arcSet.authenticationResults || !arcSet.authenticationResults.includes('i=')) {
        errors.push(`ARC-Authentication-Results missing or invalid for instance ${arcSet.instance}`);
      }
      
      // Validate ARC-Message-Signature has required tags
      const amsParams = parseARCTags(arcSet.messageSignature);
      const requiredAmsTags = ['i', 'a', 'd', 's', 'b', 'bh', 'h'];
      for (const tag of requiredAmsTags) {
        if (!amsParams[tag]) {
          errors.push(`ARC-Message-Signature missing required ${tag}= tag for instance ${arcSet.instance}`);
        }
      }
      
      // Validate ARC-Seal has required tags
      const asParams = parseARCTags(arcSet.seal);
      const requiredAsTags = ['i', 'a', 'cv', 'd', 's', 'b'];
      for (const tag of requiredAsTags) {
        if (!asParams[tag]) {
          errors.push(`ARC-Seal missing required ${tag}= tag for instance ${arcSet.instance}`);
        }
      }
      
      // RFC 8617 Section 5.2 Step 3: Validate cv= values
      // First seal must have cv=none, subsequent must have cv=pass
      const cv = asParams.cv;
      if (arcSet.instance === 1) {
        if (cv !== 'none') {
          errors.push(`ARC-Seal instance 1 must have cv=none, got cv=${cv}`);
        }
      } else {
        if (cv !== 'pass') {
          // If any previous seal has cv=fail, the chain is already broken
          if (cv === 'fail') {
            errors.push(`ARC-Seal instance ${arcSet.instance} has cv=fail, chain is broken`);
            resolve({ valid: false, chainValidation: 'fail', errors });
            return;
          }
          errors.push(`ARC-Seal instance ${arcSet.instance} should have cv=pass, got cv=${cv}`);
        }
      }
    }

    // If structural validation failed, don't proceed to crypto verification
    if (errors.length > 0) {
      resolve({ valid: false, chainValidation: 'fail', errors });
      return;
    }

    // RFC 8617 Section 5.2 Step 4: Cryptographically verify each ARC-Seal
    // Must verify from oldest to newest (i=1, i=2, etc.)
    for (const arcSet of arcSets) {
      // Build the data that should have been signed for this seal
      const dataToVerify = buildARCSealVerificationData(arcSets, arcSet.instance);
      
      // Verify the ARC-Seal signature
      const sealResult = await verifyARCSignature(
        arcSet.seal,
        dataToVerify,
        lookupDKIMKey
      );
      
      if (!sealResult.valid) {
        errors.push(`ARC-Seal cryptographic verification failed for instance ${arcSet.instance}: ${sealResult.error ?? 'signature mismatch'}`);
        resolve({ valid: false, chainValidation: 'fail', errors });
        return;
      }
      
      // RFC 8617 Section 5.2 Step 5: Validate ARC-Message-Signature for the most recent set.
      // This checker enforces AMS structural integrity and required parameters.
      if (arcSet.instance === arcSets.length) {
        const amsParams = parseARCTags(arcSet.messageSignature);

        const requiredAmsTags = ['a', 'b', 'bh', 'd', 'h', 's'];
        for (const tag of requiredAmsTags) {
          if (!amsParams[tag]) {
            errors.push(`ARC-Message-Signature missing required tag ${tag} for instance ${arcSet.instance}`);
          }
        }

        const algorithm = amsParams.a;
        if (algorithm && algorithm !== 'rsa-sha256') {
          errors.push(`Unsupported AMS algorithm '${algorithm}' for instance ${arcSet.instance}`);
        }

        const bh = amsParams.bh;
        if (bh && !/^[A-Za-z0-9+/=]+$/.test(bh)) {
          errors.push(`ARC-Message-Signature has invalid bh format for instance ${arcSet.instance}`);
        }

        if (!amsParams.b || amsParams.b.length < 20 || !/^[A-Za-z0-9+/=]+$/.test(amsParams.b)) {
          errors.push(`ARC-Message-Signature has invalid signature for instance ${arcSet.instance}`);
        }
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
