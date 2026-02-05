/**
 * Email Authentication Module
 * 
 * Validates inbound email using SPF, DKIM, and DMARC
 */

import { promises as dns } from 'dns';
import { createVerify, createHash } from 'crypto';
import type { Logger } from '@apexmail/lib';
import type { ParsedMail, Headers } from 'mailparser';

export interface SPFResult {
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  domain: string;
  explanation?: string;
}

export interface DKIMResult {
  result: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
  domain: string;
  selector?: string;
  explanation?: string;
}

export interface DMARCResult {
  result: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
  domain: string;
  policy: 'none' | 'quarantine' | 'reject';
  alignment: {
    spf: boolean;
    dkim: boolean;
  };
}

export interface AuthenticationResults {
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  authResultsHeader: string;
}

export interface EmailAuthConfig {
  requireSPF: boolean;
  requireDKIM: boolean;
  enforceDMARC: boolean;
  allowSoftFail: boolean;
  trustedRelays: string[];
  logger: Logger;
}

const DEFAULT_CONFIG: EmailAuthConfig = {
  requireSPF: true,
  requireDKIM: true,
  enforceDMARC: true,
  allowSoftFail: true,
  trustedRelays: [],
  logger: console as unknown as Logger,
};

/**
 * Email Authentication class for validating SPF, DKIM, and DMARC
 * SECURITY FIX (MEM-008): Added LRU eviction to prevent unbounded DNS cache growth
 */
export class EmailAuthenticator {
  private readonly config: EmailAuthConfig;
  private readonly logger: Logger;
  private readonly dnsCache: Map<string, { value: string[]; expires: number }> = new Map();
  private readonly DNS_CACHE_TTL = 300000; // 5 minutes
  private readonly DNS_CACHE_MAX_SIZE = 10000; // Maximum cache entries
  private cacheCleanupTimer: NodeJS.Timeout | null = null;
  
  /**
   * RFC 7208 Section 4.6.4: SPF implementations MUST limit DNS lookups to 10
   * This counter tracks TOTAL lookups across the entire SPF evaluation, not just depth
   */
  private spfDnsLookupCount = 0;
  private readonly SPF_MAX_DNS_LOOKUPS = 10; // RFC 7208 mandated limit

  constructor(config: Partial<EmailAuthConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = this.config.logger;
    
    // Start periodic cache cleanup to remove expired entries
    this.cacheCleanupTimer = setInterval(() => this.cleanupExpiredCache(), 60000);
    if (this.cacheCleanupTimer.unref) {
      this.cacheCleanupTimer.unref();
    }
  }

  /**
   * Clean up expired cache entries and enforce max size
   */
  private cleanupExpiredCache(): void {
    const now = Date.now();
    let deletedCount = 0;
    
    // Remove expired entries
    for (const [key, entry] of this.dnsCache) {
      if (entry.expires < now) {
        this.dnsCache.delete(key);
        deletedCount++;
      }
    }
    
    // If still over max size, remove oldest entries (LRU eviction)
    if (this.dnsCache.size > this.DNS_CACHE_MAX_SIZE) {
      const entries = Array.from(this.dnsCache.entries())
        .sort((a, b) => a[1].expires - b[1].expires);
      
      const toRemove = entries.slice(0, this.dnsCache.size - this.DNS_CACHE_MAX_SIZE);
      for (const [key] of toRemove) {
        this.dnsCache.delete(key);
        deletedCount++;
      }
    }
    
    if (deletedCount > 0) {
      this.logger.debug('DNS cache cleanup completed', { 
        deleted: deletedCount, 
        remaining: this.dnsCache.size 
      });
    }
  }

  /**
   * Shutdown cleanup
   */
  shutdown(): void {
    if (this.cacheCleanupTimer) {
      clearInterval(this.cacheCleanupTimer);
      this.cacheCleanupTimer = null;
    }
    this.dnsCache.clear();
  }

  /**
   * Perform full authentication check on an inbound email
   */
  async authenticate(
    email: ParsedMail,
    rawMessage: Buffer,
    clientIP: string,
    heloHostname: string,
    mailFrom: string
  ): Promise<AuthenticationResults> {
    const fromDomain = this.extractDomain(mailFrom);
    const headerFromDomain = this.extractDomain(this.extractFromAddress(email.from));

    // Perform all checks in parallel
    const [spf, dkim] = await Promise.all([
      this.checkSPF(clientIP, mailFrom, heloHostname, fromDomain),
      this.checkDKIM(rawMessage, email.headers),
    ]);

    // DMARC requires both SPF and DKIM results
    const dmarc = await this.checkDMARC(headerFromDomain, fromDomain, spf, dkim);

    // Generate Authentication-Results header
    const authResultsHeader = this.generateAuthResultsHeader(
      spf,
      dkim,
      dmarc,
      clientIP,
      mailFrom
    );

    return { spf, dkim, dmarc, authResultsHeader };
  }

  /**
   * Check if the email passes authentication requirements
   */
  shouldAccept(results: AuthenticationResults): {
    accept: boolean;
    action: 'accept' | 'quarantine' | 'reject';
    reason?: string;
  } {
    // DMARC policy takes precedence
    if (this.config.enforceDMARC && results.dmarc.result === 'fail') {
      switch (results.dmarc.policy) {
        case 'reject':
          return { accept: false, action: 'reject', reason: 'DMARC policy is reject' };
        case 'quarantine':
          return { accept: true, action: 'quarantine', reason: 'DMARC policy is quarantine' };
        case 'none':
          // Log but accept
          this.logger.info('DMARC failed but policy is none', {
            domain: results.dmarc.domain,
          });
          return { accept: true, action: 'accept' };
      }
    }

    // Check SPF if required
    if (this.config.requireSPF) {
      if (results.spf.result === 'fail') {
        return { accept: false, action: 'reject', reason: 'SPF validation failed' };
      }
      if (results.spf.result === 'softfail' && !this.config.allowSoftFail) {
        return { accept: false, action: 'reject', reason: 'SPF softfail not allowed' };
      }
    }

    // Check DKIM if required
    if (this.config.requireDKIM && results.dkim.result === 'fail') {
      return { accept: false, action: 'reject', reason: 'DKIM validation failed' };
    }

    return { accept: true, action: 'accept' };
  }

  /**
   * SPF (Sender Policy Framework) validation
   * RFC 7208
   */
  private async checkSPF(
    clientIP: string,
    _mailFrom: string,
    _heloHostname: string,
    domain: string
  ): Promise<SPFResult> {
    try {
      // Reset DNS lookup counter for this SPF evaluation (RFC 7208 Section 4.6.4)
      this.spfDnsLookupCount = 0;
      
      if (!domain) {
        return { result: 'none', domain: '', explanation: 'No domain in MAIL FROM' };
      }

      // Check if IP is a trusted relay
      if (this.config.trustedRelays.includes(clientIP)) {
        return { result: 'pass', domain, explanation: 'Trusted relay' };
      }

      // Look up SPF record (counts as 1 lookup)
      this.spfDnsLookupCount++;
      const spfRecords = await this.lookupTXT(domain);
      const spfRecord = spfRecords.find(r => r.startsWith('v=spf1 '));

      if (!spfRecord) {
        return { result: 'none', domain, explanation: 'No SPF record found' };
      }

      // Parse and evaluate SPF record
      const result = await this.evaluateSPF(spfRecord, clientIP, domain, 0);
      return { ...result, domain };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      // DNS errors are temperror
      if (errorMessage.includes('ENOTFOUND') || errorMessage.includes('SERVFAIL')) {
        return { result: 'temperror', domain, explanation: `DNS error: ${errorMessage}` };
      }
      
      return { result: 'permerror', domain, explanation: errorMessage };
    }
  }

  /**
   * Evaluate SPF record mechanisms
   * RFC 7208 Section 4.6.4: SPF implementations MUST limit "ichanism" DNS lookups to 10
   * This includes: a, mx, ptr, include, exists, and redirect
   * Note: ip4, ip6, and all mechanisms don't require DNS lookups
   */
  private async evaluateSPF(
    record: string,
    clientIP: string,
    domain: string,
    _depth: number // Kept for API compatibility but we use total counter now
  ): Promise<Omit<SPFResult, 'domain'>> {
    // RFC 7208 Section 4.6.4: Check total DNS lookup limit (prevents infinite loops)
    if (this.spfDnsLookupCount > this.SPF_MAX_DNS_LOOKUPS) {
      return { 
        result: 'permerror', 
        explanation: `SPF evaluation exceeded RFC 7208 limit of ${this.SPF_MAX_DNS_LOOKUPS} DNS lookups (count: ${this.spfDnsLookupCount})` 
      };
    }

    const mechanisms = record.replace('v=spf1 ', '').trim().split(/\s+/);
    const isIPv6 = clientIP.includes(':');

    for (const mechanism of mechanisms) {
      if (!mechanism) continue;
      
      // Parse qualifier (default is +)
      let qualifier = '+';
      let mech = mechanism;
      const firstChar = mechanism[0] ?? '';
      if (['+', '-', '~', '?'].includes(firstChar)) {
        qualifier = firstChar;
        mech = mechanism.slice(1);
      }

      // Evaluate mechanism
      const match = await this.matchesMechanism(mech, clientIP, domain, isIPv6, _depth);
      
      if (match) {
        switch (qualifier) {
          case '+': return { result: 'pass' };
          case '-': return { result: 'fail' };
          case '~': return { result: 'softfail' };
          case '?': return { result: 'neutral' };
        }
      }
    }

    // Default result if no mechanism matches
    return { result: 'neutral', explanation: 'No matching mechanism' };
  }

  /**
   * Check if an SPF mechanism matches
   * RFC 7208 Section 4.6.4: Count DNS lookups for mechanisms that require them
   */
  private async matchesMechanism(
    mech: string,
    clientIP: string,
    domain: string,
    isIPv6: boolean,
    depth: number
  ): Promise<boolean> {
    // Check DNS lookup limit before any DNS-requiring mechanism
    const checkDnsLimit = (): boolean => {
      if (this.spfDnsLookupCount >= this.SPF_MAX_DNS_LOOKUPS) {
        this.logger.warn('SPF DNS lookup limit reached', { 
          count: this.spfDnsLookupCount, 
          limit: this.SPF_MAX_DNS_LOOKUPS,
          mechanism: mech 
        });
        return false; // Will trigger permerror on next evaluateSPF call
      }
      return true;
    };
    
    // Handle 'all' mechanism (no DNS lookup needed)
    if (mech === 'all') {
      return true;
    }

    // Handle IP mechanisms (no DNS lookup needed per RFC 7208)
    if (mech.startsWith('ip4:') && !isIPv6) {
      return this.ipMatchesCIDR(clientIP, mech.slice(4));
    }
    if (mech.startsWith('ip6:') && isIPv6) {
      return this.ipMatchesCIDR(clientIP, mech.slice(4));
    }

    // Handle 'a' mechanism (requires DNS lookup - RFC 7208 Section 5.3)
    if (mech === 'a' || mech.startsWith('a:') || mech.startsWith('a/')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      const targetDomain = mech.includes(':') ? mech.split(':')[1]?.split('/')[0] ?? domain : domain;
      const ips = isIPv6 ? await this.lookupAAAA(targetDomain) : await this.lookupA(targetDomain);
      return ips.includes(clientIP);
    }

    // Handle 'mx' mechanism (requires DNS lookup - RFC 7208 Section 5.4)
    // Note: RFC 7208 also limits MX record lookups to 10 (implicit in total limit)
    if (mech === 'mx' || mech.startsWith('mx:') || mech.startsWith('mx/')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      const targetDomain = mech.includes(':') ? mech.split(':')[1]?.split('/')[0] ?? domain : domain;
      const mxRecords = await this.lookupMX(targetDomain);
      
      // RFC 7208 Section 4.6.4: MX mechanism should also limit A/AAAA lookups
      // We limit to first 10 MX records to prevent abuse
      const limitedMxRecords = mxRecords.slice(0, 10);
      for (const mx of limitedMxRecords) {
        if (!checkDnsLimit()) return false;
        this.spfDnsLookupCount++;
        const ips = isIPv6 ? await this.lookupAAAA(mx) : await this.lookupA(mx);
        if (ips.includes(clientIP)) return true;
      }
      return false;
    }

    // Handle 'include' mechanism (requires DNS lookup - RFC 7208 Section 5.2)
    if (mech.startsWith('include:')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      const includeDomain = mech.slice(8);
      const records = await this.lookupTXT(includeDomain);
      const spfRecord = records.find(r => r.startsWith('v=spf1 '));
      if (spfRecord) {
        const result = await this.evaluateSPF(spfRecord, clientIP, includeDomain, depth + 1);
        return result.result === 'pass';
      }
      return false;
    }

    // Handle 'redirect' modifier (requires DNS lookup - RFC 7208 Section 6.1)
    if (mech.startsWith('redirect=')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      const redirectDomain = mech.slice(9);
      const records = await this.lookupTXT(redirectDomain);
      const spfRecord = records.find(r => r.startsWith('v=spf1 '));
      if (spfRecord) {
        const result = await this.evaluateSPF(spfRecord, clientIP, redirectDomain, depth + 1);
        return result.result === 'pass';
      }
      return false;
    }
    
    // Handle 'exists' mechanism (requires DNS lookup - RFC 7208 Section 5.7)
    if (mech.startsWith('exists:')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      const existsDomain = mech.slice(7);
      const ips = await this.lookupA(existsDomain);
      return ips.length > 0;
    }
    
    // Handle 'ptr' mechanism (deprecated but must be supported - RFC 7208 Section 5.5)
    // Note: PTR is expensive and discouraged, but we must handle it
    if (mech === 'ptr' || mech.startsWith('ptr:')) {
      if (!checkDnsLimit()) return false;
      this.spfDnsLookupCount++;
      this.logger.warn('SPF ptr mechanism used - this is deprecated per RFC 7208');
      // PTR lookup is expensive; skip actual implementation but count the lookup
      return false;
    }

    return false;
  }

  /**
   * DKIM (DomainKeys Identified Mail) validation
   * RFC 6376
   */
  private async checkDKIM(rawMessage: Buffer, headers: Headers): Promise<DKIMResult> {
    try {
      // Look for DKIM-Signature header
      const dkimHeader = headers.get('dkim-signature');
      
      if (!dkimHeader) {
        return { result: 'none', domain: '', explanation: 'No DKIM signature' };
      }

      const signatureValue = typeof dkimHeader === 'string' 
        ? dkimHeader 
        : (dkimHeader as { value?: string })?.value ?? '';

      // Parse DKIM signature
      const params = this.parseDKIMSignature(signatureValue);
      
      if (!params.d || !params.s || !params.b || !params.bh) {
        return {
          result: 'permerror',
          domain: params.d ?? '',
          explanation: 'Invalid DKIM signature format',
        };
      }

      // Fetch public key from DNS
      const selector = params.s;
      const domain = params.d;
      const dkimDomain = `${selector}._domainkey.${domain}`;
      
      const records = await this.lookupTXT(dkimDomain);
      const dkimRecord = records.find(r => r.includes('v=DKIM1') || r.includes('k=rsa'));

      if (!dkimRecord) {
        return {
          result: 'temperror',
          domain,
          selector,
          explanation: 'DKIM public key not found',
        };
      }

      // Parse and validate public key
      const keyParams = this.parseDKIMKey(dkimRecord);
      if (!keyParams.valid) {
        return {
          result: 'permerror',
          domain,
          selector,
          explanation: keyParams.error ?? 'Invalid DKIM public key',
        };
      }

      // Verify body hash
      const bodyHashValid = this.verifyDKIMBodyHash(rawMessage, params);
      if (!bodyHashValid) {
        return {
          result: 'fail',
          domain,
          selector,
          explanation: 'Body hash mismatch',
        };
      }

      // Verify signature
      const signatureValid = await this.verifyDKIMSignature(rawMessage, params, keyParams.p!);
      
      return {
        result: signatureValid ? 'pass' : 'fail',
        domain,
        selector,
        explanation: signatureValid ? undefined : 'Signature verification failed',
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return { result: 'temperror', domain: '', explanation: errorMessage };
    }
  }

  /**
   * Parse DKIM-Signature header
   */
  private parseDKIMSignature(header: string): Record<string, string> {
    const params: Record<string, string> = {};
    const parts = header.split(/;\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      if (key && valueParts.length > 0) {
        params[key.trim()] = valueParts.join('=').trim();
      }
    }
    
    return params;
  }

  /**
   * Parse and validate DKIM DNS record
   * RFC 6376 Section 3.6.1 - Key Record Format
   */
  private parseDKIMKey(record: string): any {
    const params: any = { valid: true };
    const parts = record.split(/;\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      if (key && valueParts.length > 0) {
        params[key.trim()] = valueParts.join('=').trim().replace(/\s+/g, '');
      }
    }
    
    // Validate required public key (p=)
    if (!params.p) {
      params.valid = false;
      params.error = 'Missing public key (p= tag)';
      return params;
    }
    
    // Check for revoked key (empty p= tag means key is revoked per RFC 6376)
    if (params.p === '') {
      params.valid = false;
      params.error = 'DKIM key has been revoked (empty p= tag)';
      return params;
    }
    
    // Validate key type (k= tag, default is rsa)
    const keyType = params.k ?? 'rsa';
    const supportedKeyTypes = ['rsa', 'ed25519'];
    if (!supportedKeyTypes.includes(keyType)) {
      params.valid = false;
      params.error = `Unsupported key type: ${keyType}. Supported: ${supportedKeyTypes.join(', ')}`;
      return params;
    }
    
    // Validate public key format (must be valid base64)
    const base64Regex = /^[A-Za-z0-9+/]+=*$/;
    if (!base64Regex.test(params.p)) {
      params.valid = false;
      params.error = 'Invalid public key format: not valid base64';
      return params;
    }
    
    // Validate minimum key length for RSA (RFC 8301 requires >= 1024 bits, recommends >= 2048)
    if (keyType === 'rsa') {
      try {
        const keyBuffer = Buffer.from(params.p, 'base64');
        // RSA public key in DER format: rough estimate is key size ~= buffer length * 8 / 1.2
        // More accurate: the modulus is roughly the key size
        // A 1024-bit key has ~128 bytes, 2048-bit has ~256 bytes in DER
        const estimatedBits = keyBuffer.length * 8 * 0.85; // Approximate for DER overhead
        if (estimatedBits < 1024) {
          this.logger.warn('DKIM key may be too short', { 
            estimatedBits, 
            recommendation: 'Use at least 2048-bit RSA keys per RFC 8301'
          });
        }
      } catch {
        params.valid = false;
        params.error = 'Failed to decode public key';
        return params;
      }
    }
    
    // Validate hash algorithms if specified (h= tag)
    if (params.h) {
      const hashAlgos = params.h.split(':');
      const supportedHashes = ['sha1', 'sha256'];
      for (const algo of hashAlgos) {
        if (!supportedHashes.includes(algo)) {
          params.valid = false;
          params.error = `Unsupported hash algorithm: ${algo}`;
          return params;
        }
      }
      // SHA-1 is deprecated per RFC 8301
      if (hashAlgos.includes('sha1') && !hashAlgos.includes('sha256')) {
        this.logger.warn('DKIM key only allows SHA-1 which is deprecated per RFC 8301');
      }
    }
    
    // Validate service type if specified (s= tag)
    if (params.s && params.s !== '*') {
      const serviceTypes = params.s.split(':');
      if (!serviceTypes.includes('email') && !serviceTypes.includes('*')) {
        params.valid = false;
        params.error = `DKIM key not valid for email service (s=${params.s})`;
        return params;
      }
    }
    
    // Check flags (t= tag) for testing mode
    if (params.t) {
      const flags = params.t.split(':');
      if (flags.includes('y')) {
        this.logger.info('DKIM key is in testing mode (t=y)');
      }
      if (flags.includes('s')) {
        // Strict mode: domain must match exactly (no subdomains)
        params._strictMode = 'true';
      }
    }
    
    return params;
  }

  /**
   * Verify DKIM body hash
   */
  private verifyDKIMBodyHash(rawMessage: Buffer, params: Record<string, string>): boolean {
    const messageString = rawMessage.toString('utf-8');
    const bodyStart = messageString.indexOf('\r\n\r\n');
    
    if (bodyStart === -1) {
      return false;
    }

    let body = messageString.slice(bodyStart + 4);
    
    // Apply canonicalization (simple or relaxed)
    const canon = (params.c ?? 'relaxed/simple').split('/');
    const bodyCanon = canon[1] ?? 'simple';
    
    if (bodyCanon === 'relaxed') {
      // Relaxed body canonicalization
      body = body
        .replace(/[ \t]+\r\n/g, '\r\n') // WSP before CRLF
        .replace(/[ \t]+/g, ' ')         // Multiple WSP to single space
        .replace(/\r\n+$/, '\r\n');      // Trailing blank lines
    } else {
      // Simple canonicalization - just ensure trailing CRLF
      body = body.replace(/(\r\n)*$/, '\r\n');
    }

    // Handle length limit
    const l = params.l ? parseInt(params.l, 10) : undefined;
    if (l !== undefined && l > 0) {
      body = body.slice(0, l);
    }

    // Calculate hash
    const algorithm = params.a?.includes('sha256') ? 'sha256' : 'sha1';
    const hash = createHash(algorithm).update(body).digest('base64');
    
    return hash === params.bh;
  }

  /**
   * Verify DKIM signature
   */
  private async verifyDKIMSignature(
    rawMessage: Buffer,
    params: Record<string, string>,
    publicKey: string
  ): Promise<boolean> {
    try {
      const messageString = rawMessage.toString('utf-8');
      const headerEnd = messageString.indexOf('\r\n\r\n');
      const headersSection = messageString.slice(0, headerEnd);
      
      // Get signed headers
      const signedHeaders = (params.h ?? '').toLowerCase().split(':').map(h => h.trim());
      
      // Apply canonicalization
      const canon = (params.c ?? 'relaxed/simple').split('/');
      const headerCanon = canon[0] ?? 'relaxed';
      
      // Build canonical headers
      const headerLines = headersSection.split('\r\n');
      const canonicalHeaders: string[] = [];
      
      for (const headerName of signedHeaders) {
        const headerLine = headerLines.find(
          line => line.toLowerCase().startsWith(headerName + ':')
        );
        
        if (headerLine) {
          if (headerCanon === 'relaxed') {
            // Relaxed header canonicalization
            const [name, ...valueParts] = headerLine.split(':');
            const value = valueParts.join(':').trim().replace(/\s+/g, ' ');
            canonicalHeaders.push(`${name?.toLowerCase()}:${value}`);
          } else {
            canonicalHeaders.push(headerLine);
          }
        }
      }
      
      // Add DKIM-Signature header without the b= value
      const dkimLine = `dkim-signature:${this.canonicalizeDKIMHeader(params, headerCanon)}`;
      canonicalHeaders.push(dkimLine);
      
      const signedData = canonicalHeaders.join('\r\n');
      
      // Verify signature
      const algorithm = params.a?.includes('sha256') ? 'RSA-SHA256' : 'RSA-SHA1';
      const signature = Buffer.from(params.b?.replace(/\s+/g, '') ?? '', 'base64');
      const pemKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;
      
      const verifier = createVerify(algorithm);
      verifier.update(signedData);
      
      return verifier.verify(pemKey, signature);
    } catch {
      return false;
    }
  }

  /**
   * Canonicalize DKIM header for signing
   */
  private canonicalizeDKIMHeader(params: Record<string, string>, canon: string): string {
    // Rebuild DKIM signature without b= value
    const parts: string[] = [];
    
    for (const [key, value] of Object.entries(params)) {
      if (key === 'b') {
        parts.push('b='); // Empty b value for verification
      } else {
        parts.push(`${key}=${value}`);
      }
    }
    
    let header = parts.join('; ');
    
    if (canon === 'relaxed') {
      header = header.trim().replace(/\s+/g, ' ');
    }
    
    return header;
  }

  /**
   * DMARC (Domain-based Message Authentication, Reporting & Conformance) validation
   * RFC 7489
   */
  private async checkDMARC(
    headerFromDomain: string,
    envelopeFromDomain: string,
    spfResult: SPFResult,
    dkimResult: DKIMResult
  ): Promise<DMARCResult> {
    try {
      if (!headerFromDomain) {
        return {
          result: 'none',
          domain: '',
          policy: 'none',
          alignment: { spf: false, dkim: false },
        };
      }

      // Look up DMARC record
      const dmarcDomain = `_dmarc.${headerFromDomain}`;
      const records = await this.lookupTXT(dmarcDomain);
      const dmarcRecord = records.find(r => r.startsWith('v=DMARC1'));

      if (!dmarcRecord) {
        // Try organizational domain
        const orgDomain = this.getOrganizationalDomain(headerFromDomain);
        if (orgDomain !== headerFromDomain) {
          const orgRecords = await this.lookupTXT(`_dmarc.${orgDomain}`);
          const orgDmarcRecord = orgRecords.find(r => r.startsWith('v=DMARC1'));
          if (orgDmarcRecord) {
            return this.evaluateDMARC(orgDmarcRecord, orgDomain, headerFromDomain, envelopeFromDomain, spfResult, dkimResult);
          }
        }
        
        return {
          result: 'none',
          domain: headerFromDomain,
          policy: 'none',
          alignment: { spf: false, dkim: false },
        };
      }

      return this.evaluateDMARC(dmarcRecord, headerFromDomain, headerFromDomain, envelopeFromDomain, spfResult, dkimResult);

    } catch (error) {
      return {
        result: 'temperror',
        domain: headerFromDomain,
        policy: 'none',
        alignment: { spf: false, dkim: false },
      };
    }
  }

  /**
   * Evaluate DMARC record
   */
  private evaluateDMARC(
    record: string,
    dmarcDomain: string,
    headerFromDomain: string,
    envelopeFromDomain: string,
    spfResult: SPFResult,
    dkimResult: DKIMResult
  ): DMARCResult {
    // Parse DMARC record
    const params: Record<string, string> = {};
    const parts = record.split(/;\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      if (key && valueParts.length > 0) {
        params[key.trim()] = valueParts.join('=').trim();
      }
    }

    // Get policy
    const policy = (params.p as 'none' | 'quarantine' | 'reject') ?? 'none';
    
    // Get alignment modes (default is relaxed)
    const aspf = params.aspf ?? 'r';
    const adkim = params.adkim ?? 'r';

    // Check SPF alignment
    let spfAligned = false;
    if (spfResult.result === 'pass') {
      if (aspf === 's') {
        // Strict alignment - domains must match exactly
        spfAligned = envelopeFromDomain.toLowerCase() === headerFromDomain.toLowerCase();
      } else {
        // Relaxed alignment - organizational domains must match
        spfAligned = this.getOrganizationalDomain(envelopeFromDomain) === 
                     this.getOrganizationalDomain(headerFromDomain);
      }
    }

    // Check DKIM alignment
    let dkimAligned = false;
    if (dkimResult.result === 'pass' && dkimResult.domain) {
      if (adkim === 's') {
        // Strict alignment
        dkimAligned = dkimResult.domain.toLowerCase() === headerFromDomain.toLowerCase();
      } else {
        // Relaxed alignment
        dkimAligned = this.getOrganizationalDomain(dkimResult.domain) === 
                      this.getOrganizationalDomain(headerFromDomain);
      }
    }

    // DMARC passes if either SPF or DKIM passes AND is aligned
    const dmarcPass = spfAligned || dkimAligned;

    return {
      result: dmarcPass ? 'pass' : 'fail',
      domain: dmarcDomain,
      policy,
      alignment: {
        spf: spfAligned,
        dkim: dkimAligned,
      },
    };
  }

  /**
   * Generate Authentication-Results header
   * RFC 8601
   */
  private generateAuthResultsHeader(
    spf: SPFResult,
    dkim: DKIMResult,
    dmarc: DMARCResult,
    _clientIP: string,
    mailFrom: string
  ): string {
    const hostname = process.env.MTA_HOSTNAME ?? 'mail.apexmail.local';
    const parts: string[] = [hostname];

    // SPF result
    parts.push(`spf=${spf.result} smtp.mailfrom=${mailFrom}`);

    // DKIM result
    if (dkim.domain) {
      parts.push(`dkim=${dkim.result} header.d=${dkim.domain}${dkim.selector ? ` header.s=${dkim.selector}` : ''}`);
    } else {
      parts.push(`dkim=${dkim.result}`);
    }

    // DMARC result
    parts.push(`dmarc=${dmarc.result} header.from=${dmarc.domain}`);

    return parts.join(';\r\n\t');
  }

  /**
   * Public Suffix List for organizational domain extraction
   * Source: https://publicsuffix.org/list/
   * This is a curated subset - in production, consider using the 'psl' npm package
   * or fetching the full list from https://publicsuffix.org/list/public_suffix_list.dat
   * 
   * Format: Map of suffix -> true for exact match, or nested suffixes
   * LIMITATION: This is not the complete PSL. For full RFC 7489 compliance,
   * use the 'psl' npm package or implement full PSL fetching.
   */
  private static readonly PUBLIC_SUFFIX_LIST: Set<string> = new Set([
    // Generic TLDs that act as public suffixes
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
    'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum',
    
    // Country-code second-level domains (cc-SLDs)
    // United Kingdom
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
    // Australia  
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    // New Zealand
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'geek.nz', 'gen.nz',
    // Japan
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
    // Brazil
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'art.br',
    // China
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'mil.cn', 'ac.cn',
    // India
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'gen.in', 'firm.in', 'ind.in',
    // South Africa
    'co.za', 'net.za', 'org.za', 'gov.za', 'edu.za', 'ac.za',
    // Germany (most are single-level but some special)
    'com.de', 'net.de', 'org.de',
    // France
    'com.fr', 'asso.fr', 'nom.fr', 'prd.fr', 'tm.fr',
    // Spain
    'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
    // Italy
    'com.it', 'org.it', 'edu.it', 'gov.it',
    // Netherlands
    'co.nl',
    // Belgium
    'ac.be',
    // Russia
    'com.ru', 'net.ru', 'org.ru', 'pp.ru',
    // South Korea
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr', 'ac.kr', 'hs.kr', 'ms.kr', 'es.kr', 'sc.kr', 'kg.kr',
    // Taiwan
    'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw', 'game.tw', 'ebiz.tw', 'club.tw',
    // Hong Kong
    'com.hk', 'edu.hk', 'gov.hk', 'idv.hk', 'net.hk', 'org.hk',
    // Singapore
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    // Malaysia
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'mil.my', 'name.my',
    // Indonesia
    'co.id', 'ac.id', 'go.id', 'mil.id', 'net.id', 'or.id', 'sch.id', 'web.id',
    // Thailand
    'co.th', 'in.th', 'go.th', 'mi.th', 'or.th', 'net.th', 'ac.th',
    // Vietnam
    'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn', 'int.vn', 'ac.vn', 'biz.vn', 'info.vn', 'name.vn', 'pro.vn', 'health.vn',
    // Philippines
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph', 'ngo.ph', 'mil.ph',
    // Pakistan
    'com.pk', 'net.pk', 'edu.pk', 'org.pk', 'fam.pk', 'biz.pk', 'web.pk', 'gov.pk', 'gob.pk', 'gok.pk', 'gon.pk', 'gop.pk', 'gos.pk',
    // Turkey
    'com.tr', 'net.tr', 'org.tr', 'biz.tr', 'info.tr', 'tv.tr', 'gen.tr', 'web.tr', 'tel.tr', 'av.tr', 'dr.tr', 'bbs.tr', 'name.tr', 'gov.tr', 'pol.tr', 'mil.tr', 'k12.tr', 'edu.tr',
    // Israel
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il', 'idf.il',
    // United Arab Emirates
    'co.ae', 'net.ae', 'org.ae', 'sch.ae', 'ac.ae', 'gov.ae', 'mil.ae',
    // Mexico
    'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
    // Argentina
    'com.ar', 'edu.ar', 'gob.ar', 'gov.ar', 'int.ar', 'mil.ar', 'net.ar', 'org.ar', 'tur.ar',
    // Chile
    'co.cl', 'gob.cl', 'gov.cl', 'mil.cl',
    // Colombia
    'com.co', 'edu.co', 'gov.co', 'mil.co', 'net.co', 'nom.co', 'org.co',
    // Peru
    'com.pe', 'edu.pe', 'gob.pe', 'mil.pe', 'net.pe', 'nom.pe', 'org.pe',
    // Venezuela
    'com.ve', 'net.ve', 'org.ve', 'info.ve', 'co.ve', 'web.ve', 'edu.ve', 'gob.ve', 'gov.ve', 'mil.ve',
  ]);

  /**
   * Extract organizational domain (e.g., mail.example.com -> example.com)
   * Uses Public Suffix List for accurate extraction per RFC 7489
   * 
   * LIMITATION NOTICE: This implementation uses a static subset of the Public Suffix List.
   * For complete RFC 7489 compliance in production, consider:
   * 1. Using the 'psl' npm package (npm install psl @types/psl)
   * 2. Fetching and caching the full list from https://publicsuffix.org/list/public_suffix_list.dat
   * 
   * @see https://publicsuffix.org/
   * @see RFC 7489 Section 3.2 - Organizational Domain
   */
  private getOrganizationalDomain(domain: string): string {
    const normalizedDomain = domain.toLowerCase().trim();
    const parts = normalizedDomain.split('.');
    
    if (parts.length <= 1) return normalizedDomain;
    if (parts.length === 2) return normalizedDomain;
    
    // Try to find the longest matching public suffix
    // Start from the rightmost parts and work left
    for (let i = 1; i < parts.length; i++) {
      const potentialSuffix = parts.slice(i).join('.');
      
      if (EmailAuthenticator.PUBLIC_SUFFIX_LIST.has(potentialSuffix)) {
        // Found a public suffix - organizational domain is one level above
        if (i > 0) {
          return parts.slice(i - 1).join('.');
        }
        // The entire domain is a public suffix (shouldn't happen for valid email domains)
        return normalizedDomain;
      }
    }
    
    // No multi-part suffix found, check if TLD itself is in the list
    const tld = parts[parts.length - 1]!;
    if (EmailAuthenticator.PUBLIC_SUFFIX_LIST.has(tld)) {
      // Standard TLD - organizational domain is last two parts
      return parts.slice(-2).join('.');
    }
    
    // Unknown TLD - log warning and default to last two parts
    // This handles new gTLDs and ccTLDs not in our list
    this.logger.debug('Unknown TLD encountered, using default organizational domain extraction', { 
      domain: normalizedDomain, 
      tld,
      note: 'Consider updating PUBLIC_SUFFIX_LIST or using psl package'
    });
    return parts.slice(-2).join('.');
  }

  /**
   * Extract domain from email address
   */
  private extractDomain(email: string): string {
    if (!email) return '';
    const atIndex = email.indexOf('@');
    return atIndex >= 0 ? email.slice(atIndex + 1).toLowerCase() : '';
  }

  /**
   * Extract email address from parsed from field
   */
  private extractFromAddress(from: ParsedMail['from']): string {
    if (!from) return '';
    const address = from.value?.[0];
    return address?.address ?? '';
  }

  /**
   * Check if IP matches CIDR notation
   */
  private ipMatchesCIDR(ip: string, cidr: string): boolean {
    const [network, prefixStr] = cidr.split('/');
    if (!network) return false;
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 32;
    
    // Simple IPv4 implementation
    if (!ip.includes(':')) {
      const ipParts = ip.split('.').map(Number);
      const networkParts = network.split('.').map(Number);
      
      const ipNum = (ipParts[0]! << 24) | (ipParts[1]! << 16) | (ipParts[2]! << 8) | ipParts[3]!;
      const netNum = (networkParts[0]! << 24) | (networkParts[1]! << 16) | (networkParts[2]! << 8) | networkParts[3]!;
      const mask = prefix === 0 ? 0 : ~((1 << (32 - prefix)) - 1);
      
      return (ipNum & mask) === (netNum & mask);
    }
    
    // IPv6 - simplified check
    return ip.toLowerCase() === network.toLowerCase();
  }

  // DNS lookup helpers with caching

  private async lookupTXT(domain: string): Promise<string[]> {
    const cacheKey = `txt:${domain}`;
    const cached = this.dnsCache.get(cacheKey);
    
    if (cached && cached.expires > Date.now()) {
      return cached.value;
    }

    try {
      const records = await dns.resolveTxt(domain);
      const values = records.map(r => r.join(''));
      this.dnsCache.set(cacheKey, { value: values, expires: Date.now() + this.DNS_CACHE_TTL });
      return values;
    } catch {
      return [];
    }
  }

  private async lookupA(domain: string): Promise<string[]> {
    const cacheKey = `a:${domain}`;
    const cached = this.dnsCache.get(cacheKey);
    
    if (cached && cached.expires > Date.now()) {
      return cached.value;
    }

    try {
      const addresses = await dns.resolve4(domain);
      this.dnsCache.set(cacheKey, { value: addresses, expires: Date.now() + this.DNS_CACHE_TTL });
      return addresses;
    } catch {
      return [];
    }
  }

  private async lookupAAAA(domain: string): Promise<string[]> {
    const cacheKey = `aaaa:${domain}`;
    const cached = this.dnsCache.get(cacheKey);
    
    if (cached && cached.expires > Date.now()) {
      return cached.value;
    }

    try {
      const addresses = await dns.resolve6(domain);
      this.dnsCache.set(cacheKey, { value: addresses, expires: Date.now() + this.DNS_CACHE_TTL });
      return addresses;
    } catch {
      return [];
    }
  }

  private async lookupMX(domain: string): Promise<string[]> {
    const cacheKey = `mx:${domain}`;
    const cached = this.dnsCache.get(cacheKey);
    
    if (cached && cached.expires > Date.now()) {
      return cached.value;
    }

    try {
      const records = await dns.resolveMx(domain);
      const exchanges = records.sort((a, b) => a.priority - b.priority).map(r => r.exchange);
      this.dnsCache.set(cacheKey, { value: exchanges, expires: Date.now() + this.DNS_CACHE_TTL });
      return exchanges;
    } catch {
      return [];
    }
  }
}
