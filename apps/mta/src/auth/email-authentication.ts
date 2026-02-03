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
 */
export class EmailAuthenticator {
  private readonly config: EmailAuthConfig;
  private readonly logger: Logger;
  private readonly dnsCache: Map<string, { value: string[]; expires: number }> = new Map();
  private readonly DNS_CACHE_TTL = 300000; // 5 minutes

  constructor(config: Partial<EmailAuthConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = this.config.logger;
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
      if (!domain) {
        return { result: 'none', domain: '', explanation: 'No domain in MAIL FROM' };
      }

      // Check if IP is a trusted relay
      if (this.config.trustedRelays.includes(clientIP)) {
        return { result: 'pass', domain, explanation: 'Trusted relay' };
      }

      // Look up SPF record
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
   */
  private async evaluateSPF(
    record: string,
    clientIP: string,
    domain: string,
    depth: number
  ): Promise<Omit<SPFResult, 'domain'>> {
    // Prevent infinite loops with include/redirect
    if (depth > 10) {
      return { result: 'permerror', explanation: 'Too many DNS lookups' };
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
      const match = await this.matchesMechanism(mech, clientIP, domain, isIPv6, depth);
      
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
   */
  private async matchesMechanism(
    mech: string,
    clientIP: string,
    domain: string,
    isIPv6: boolean,
    depth: number
  ): Promise<boolean> {
    // Handle 'all' mechanism
    if (mech === 'all') {
      return true;
    }

    // Handle IP mechanisms
    if (mech.startsWith('ip4:') && !isIPv6) {
      return this.ipMatchesCIDR(clientIP, mech.slice(4));
    }
    if (mech.startsWith('ip6:') && isIPv6) {
      return this.ipMatchesCIDR(clientIP, mech.slice(4));
    }

    // Handle 'a' mechanism
    if (mech === 'a' || mech.startsWith('a:') || mech.startsWith('a/')) {
      const targetDomain = mech.includes(':') ? mech.split(':')[1]?.split('/')[0] ?? domain : domain;
      const ips = isIPv6 ? await this.lookupAAAA(targetDomain) : await this.lookupA(targetDomain);
      return ips.includes(clientIP);
    }

    // Handle 'mx' mechanism
    if (mech === 'mx' || mech.startsWith('mx:') || mech.startsWith('mx/')) {
      const targetDomain = mech.includes(':') ? mech.split(':')[1]?.split('/')[0] ?? domain : domain;
      const mxRecords = await this.lookupMX(targetDomain);
      for (const mx of mxRecords) {
        const ips = isIPv6 ? await this.lookupAAAA(mx) : await this.lookupA(mx);
        if (ips.includes(clientIP)) return true;
      }
      return false;
    }

    // Handle 'include' mechanism
    if (mech.startsWith('include:')) {
      const includeDomain = mech.slice(8);
      const records = await this.lookupTXT(includeDomain);
      const spfRecord = records.find(r => r.startsWith('v=spf1 '));
      if (spfRecord) {
        const result = await this.evaluateSPF(spfRecord, clientIP, includeDomain, depth + 1);
        return result.result === 'pass';
      }
      return false;
    }

    // Handle 'redirect' modifier
    if (mech.startsWith('redirect=')) {
      const redirectDomain = mech.slice(9);
      const records = await this.lookupTXT(redirectDomain);
      const spfRecord = records.find(r => r.startsWith('v=spf1 '));
      if (spfRecord) {
        const result = await this.evaluateSPF(spfRecord, clientIP, redirectDomain, depth + 1);
        return result.result === 'pass';
      }
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

      // Parse public key
      const keyParams = this.parseDKIMKey(dkimRecord);
      if (!keyParams.p) {
        return {
          result: 'permerror',
          domain,
          selector,
          explanation: 'Invalid DKIM public key',
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
      const signatureValid = await this.verifyDKIMSignature(rawMessage, params, keyParams.p);
      
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
   * Parse DKIM DNS record
   */
  private parseDKIMKey(record: string): Record<string, string> {
    const params: Record<string, string> = {};
    const parts = record.split(/;\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      if (key && valueParts.length > 0) {
        params[key.trim()] = valueParts.join('=').trim().replace(/\s+/g, '');
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
   * Extract organizational domain (e.g., mail.example.com -> example.com)
   */
  private getOrganizationalDomain(domain: string): string {
    // Simple implementation - in production, use Public Suffix List
    const parts = domain.toLowerCase().split('.');
    if (parts.length <= 2) return domain.toLowerCase();
    
    // Handle common multi-part TLDs
    const commonMultiPartTLDs = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.cn'];
    const lastTwo = parts.slice(-2).join('.');
    
    if (commonMultiPartTLDs.includes(lastTwo)) {
      return parts.slice(-3).join('.');
    }
    
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
