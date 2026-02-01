/**
 * Internationalized Email (EAI) Service
 * 
 * Handles UTF-8 in email addresses and content per RFC 6531
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import punycode from 'punycode/';
import { UNICODE_NORMALIZATION, SMTPUTF8_EXTENSION } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export interface EmailAddress {
  localPart: string;
  domain: string;
  original: string;
  normalized: string;
  isInternationalized: boolean;
  punycodeDomain?: string;
}

export interface ParsedEmail {
  address: EmailAddress;
  displayName?: string;
  requiresSMTPUTF8: boolean;
}

export interface EAIValidationResult {
  isValid: boolean;
  requiresSMTPUTF8: boolean;
  normalizedAddress: string;
  errors: string[];
  warnings: string[];
}

export interface ContentNormalization {
  originalCharset: string;
  normalizedCharset: string;
  hasUnicode: boolean;
  contentType: string;
}

/**
 * EAI Service for internationalized email handling
 */
export class EAIService {
  private pool: Pool;
  private redis: Redis;
  private eaiDomainCache: Map<string, boolean>;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
    this.eaiDomainCache = new Map();
  }

  /**
   * Parse and validate an email address
   */
  async parseEmailAddress(email: string, displayName?: string): Promise<Result<ParsedEmail>> {
    try {
      // Trim and normalize
      email = email.trim();
      
      // Extract display name and address if in format "Name <email>"
      const angleMatch = email.match(/^(.+?)\s*<(.+)>$/);
      if (angleMatch) {
        displayName = displayName || angleMatch[1].trim().replace(/^["']|["']$/g, '');
        email = angleMatch[2].trim();
      }

      // Split into local and domain parts
      const atIndex = email.lastIndexOf('@');
      if (atIndex === -1 || atIndex === 0 || atIndex === email.length - 1) {
        return {
          ok: false,
          error: new Error('Invalid email format: missing or misplaced @ symbol'),
        };
      }

      const localPart = email.substring(0, atIndex);
      const domain = email.substring(atIndex + 1).toLowerCase();

      // Normalize Unicode using NFC
      const normalizedLocal = this.normalizeUnicode(localPart);
      const normalizedDomain = this.normalizeUnicode(domain);

      // Check if email contains non-ASCII characters
      const isInternationalized = this.containsNonAscii(email);

      // Convert domain to punycode if needed
      let punycodeDomain: string | undefined;
      if (this.containsNonAscii(domain)) {
        try {
          punycodeDomain = punycode.toASCII(normalizedDomain);
        } catch (e) {
          return {
            ok: false,
            error: new Error(`Invalid internationalized domain: ${domain}`),
          };
        }
      }

      // Validate local part
      const localValidation = this.validateLocalPart(normalizedLocal, isInternationalized);
      if (!localValidation.isValid) {
        return {
          ok: false,
          error: new Error(`Invalid local part: ${localValidation.error}`),
        };
      }

      // Validate domain
      const domainValidation = this.validateDomain(normalizedDomain, punycodeDomain);
      if (!domainValidation.isValid) {
        return {
          ok: false,
          error: new Error(`Invalid domain: ${domainValidation.error}`),
        };
      }

      const address: EmailAddress = {
        localPart: normalizedLocal,
        domain: normalizedDomain,
        original: email,
        normalized: `${normalizedLocal}@${normalizedDomain}`,
        isInternationalized,
        punycodeDomain,
      };

      return {
        ok: true,
        value: {
          address,
          displayName,
          requiresSMTPUTF8: isInternationalized || this.containsNonAscii(normalizedLocal),
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Validate a list of email addresses
   */
  async validateEmailAddresses(emails: string[]): Promise<Result<EAIValidationResult[]>> {
    const results: EAIValidationResult[] = [];

    for (const email of emails) {
      const result = await this.validateEmail(email);
      if (!result.ok) {
        return { ok: false, error: result.error };
      }
      results.push(result.value);
    }

    return { ok: true, value: results };
  }

  /**
   * Validate a single email address
   */
  async validateEmail(email: string): Promise<Result<EAIValidationResult>> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Parse the email
      const parseResult = await this.parseEmailAddress(email);
      if (!parseResult.ok) {
        return {
          ok: true,
          value: {
            isValid: false,
            requiresSMTPUTF8: false,
            normalizedAddress: email,
            errors: [parseResult.error.message],
            warnings: [],
          },
        };
      }

      const { address, requiresSMTPUTF8 } = parseResult.value;

      // Check domain MX records (cached)
      const hasMX = await this.checkDomainMX(address.punycodeDomain || address.domain);
      if (!hasMX) {
        warnings.push('Domain may not have valid MX records');
      }

      // Check if domain supports SMTPUTF8
      if (requiresSMTPUTF8) {
        const supportsEAI = await this.checkEAISupport(address.punycodeDomain || address.domain);
        if (!supportsEAI) {
          warnings.push('Recipient domain may not support internationalized email (SMTPUTF8)');
        }
      }

      // Check for common typos in domain
      const typoCheck = this.checkCommonTypos(address.domain);
      if (typoCheck) {
        warnings.push(`Possible typo: did you mean ${typoCheck}?`);
      }

      return {
        ok: true,
        value: {
          isValid: errors.length === 0,
          requiresSMTPUTF8,
          normalizedAddress: address.normalized,
          errors,
          warnings,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Normalize Unicode to NFC form
   */
  normalizeUnicode(text: string): string {
    return text.normalize(UNICODE_NORMALIZATION);
  }

  /**
   * Check if string contains non-ASCII characters
   */
  containsNonAscii(text: string): boolean {
    return /[^\x00-\x7F]/.test(text);
  }

  /**
   * Validate local part of email
   */
  private validateLocalPart(localPart: string, isInternationalized: boolean): { isValid: boolean; error?: string } {
    // Check length (max 64 characters per RFC 5321)
    if (localPart.length === 0) {
      return { isValid: false, error: 'Local part cannot be empty' };
    }
    if (localPart.length > 64) {
      return { isValid: false, error: 'Local part exceeds 64 character limit' };
    }

    // Check for consecutive dots
    if (/\.\./.test(localPart)) {
      return { isValid: false, error: 'Consecutive dots are not allowed' };
    }

    // Check for leading/trailing dots
    if (localPart.startsWith('.') || localPart.endsWith('.')) {
      return { isValid: false, error: 'Leading or trailing dots are not allowed' };
    }

    // For ASCII-only addresses, apply strict validation
    if (!isInternationalized) {
      // Check for valid characters (RFC 5321)
      const validChars = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
      if (!validChars.test(localPart)) {
        return { isValid: false, error: 'Invalid characters in local part' };
      }
    } else {
      // For internationalized addresses, ensure valid UTF-8
      try {
        Buffer.from(localPart, 'utf8');
      } catch (e) {
        return { isValid: false, error: 'Invalid UTF-8 encoding' };
      }

      // Check for disallowed Unicode categories
      // Control characters, surrogates, etc.
      if (/[\u0000-\u001F\u007F-\u009F\uFEFF\uFFFE\uFFFF]/.test(localPart)) {
        return { isValid: false, error: 'Control characters are not allowed' };
      }
    }

    return { isValid: true };
  }

  /**
   * Validate domain part of email
   */
  private validateDomain(domain: string, punycode?: string): { isValid: boolean; error?: string } {
    // Check overall length
    if (domain.length === 0) {
      return { isValid: false, error: 'Domain cannot be empty' };
    }
    if (domain.length > 255) {
      return { isValid: false, error: 'Domain exceeds 255 character limit' };
    }

    // Validate punycode if available
    const domainToCheck = punycode || domain;

    // Split into labels
    const labels = domainToCheck.split('.');
    if (labels.length < 2) {
      return { isValid: false, error: 'Domain must have at least two labels' };
    }

    for (const label of labels) {
      // Check label length
      if (label.length === 0) {
        return { isValid: false, error: 'Empty label in domain' };
      }
      if (label.length > 63) {
        return { isValid: false, error: 'Domain label exceeds 63 character limit' };
      }

      // Check label format (for punycode/ASCII domains)
      if (!punycode || domainToCheck === punycode) {
        // Must start and end with alphanumeric
        if (!/^[a-zA-Z0-9]/.test(label) || !/[a-zA-Z0-9]$/.test(label)) {
          return { isValid: false, error: 'Domain labels must start and end with alphanumeric characters' };
        }
        // Can only contain alphanumeric and hyphen
        if (!/^[a-zA-Z0-9-]+$/.test(label)) {
          return { isValid: false, error: 'Invalid characters in domain label' };
        }
      }
    }

    // Check TLD is not all numeric
    const tld = labels[labels.length - 1];
    if (/^\d+$/.test(tld)) {
      return { isValid: false, error: 'TLD cannot be all numeric' };
    }

    return { isValid: true };
  }

  /**
   * Check if domain has valid MX records
   */
  private async checkDomainMX(domain: string): Promise<boolean> {
    // Check cache first
    const cacheKey = `mx:${domain}`;
    const cached = await this.redis.get(cacheKey);
    if (cached !== null) {
      return cached === '1';
    }

    try {
      const { promises: dns } = await import('dns');
      const mxRecords = await dns.resolveMx(domain);
      const hasMX = mxRecords && mxRecords.length > 0;
      
      // Cache for 1 hour
      await this.redis.setex(cacheKey, 3600, hasMX ? '1' : '0');
      
      return hasMX;
    } catch (error) {
      // If MX lookup fails, try A record
      try {
        const { promises: dns } = await import('dns');
        await dns.resolve4(domain);
        await this.redis.setex(cacheKey, 3600, '1');
        return true;
      } catch {
        await this.redis.setex(cacheKey, 3600, '0');
        return false;
      }
    }
  }

  /**
   * Check if domain supports SMTPUTF8 extension
   */
  private async checkEAISupport(domain: string): Promise<boolean> {
    // Check cache
    if (this.eaiDomainCache.has(domain)) {
      return this.eaiDomainCache.get(domain)!;
    }

    const cacheKey = `eai:${domain}`;
    const cached = await this.redis.get(cacheKey);
    if (cached !== null) {
      const result = cached === '1';
      this.eaiDomainCache.set(domain, result);
      return result;
    }

    // Query from database
    try {
      const result = await this.pool.query(`
        SELECT supports_smtputf8 FROM edge_domain_capabilities
        WHERE domain = $1 AND checked_at > NOW() - INTERVAL '7 days'
      `, [domain]);

      if (result.rows.length > 0) {
        const supports = result.rows[0].supports_smtputf8;
        this.eaiDomainCache.set(domain, supports);
        await this.redis.setex(cacheKey, 86400, supports ? '1' : '0');
        return supports;
      }
    } catch (error) {
      console.error('Error checking EAI support:', error);
    }

    // Default to unknown (assume support)
    return true;
  }

  /**
   * Check for common email domain typos
   */
  private checkCommonTypos(domain: string): string | null {
    const typoMap: Record<string, string> = {
      'gmial.com': 'gmail.com',
      'gmai.com': 'gmail.com',
      'gmal.com': 'gmail.com',
      'gamil.com': 'gmail.com',
      'gnail.com': 'gmail.com',
      'hotmal.com': 'hotmail.com',
      'hotmial.com': 'hotmail.com',
      'hotmai.com': 'hotmail.com',
      'outlok.com': 'outlook.com',
      'outloo.com': 'outlook.com',
      'outloook.com': 'outlook.com',
      'yahooo.com': 'yahoo.com',
      'yaho.com': 'yahoo.com',
      'yhoo.com': 'yahoo.com',
      'yhaoo.com': 'yahoo.com',
    };

    return typoMap[domain.toLowerCase()] || null;
  }

  /**
   * Normalize email content charset
   */
  normalizeContent(content: string, declaredCharset?: string): ContentNormalization {
    // Detect if content has non-ASCII characters
    const hasUnicode = this.containsNonAscii(content);

    // Default to UTF-8
    const normalizedCharset = 'utf-8';

    // Determine original charset
    let originalCharset = declaredCharset?.toLowerCase() || 'utf-8';
    
    // Map common charset aliases
    const charsetMap: Record<string, string> = {
      'iso-8859-1': 'latin1',
      'windows-1252': 'cp1252',
      'us-ascii': 'ascii',
    };
    
    if (charsetMap[originalCharset]) {
      originalCharset = charsetMap[originalCharset];
    }

    return {
      originalCharset,
      normalizedCharset,
      hasUnicode,
      contentType: `text/html; charset=${normalizedCharset}`,
    };
  }

  /**
   * Build SMTPUTF8 MAIL FROM command if needed
   */
  buildMailFromCommand(from: EmailAddress, requiresSMTPUTF8: boolean): string {
    if (requiresSMTPUTF8) {
      return `MAIL FROM:<${from.normalized}> SMTPUTF8`;
    }
    return `MAIL FROM:<${from.punycodeDomain ? `${from.localPart}@${from.punycodeDomain}` : from.normalized}>`;
  }

  /**
   * Build RCPT TO command with optional SMTPUTF8
   */
  buildRcptToCommand(to: EmailAddress, requiresSMTPUTF8: boolean): string {
    const address = requiresSMTPUTF8 
      ? to.normalized 
      : (to.punycodeDomain ? `${to.localPart}@${to.punycodeDomain}` : to.normalized);
    return `RCPT TO:<${address}>`;
  }

  /**
   * Update domain EAI capability in database
   */
  async updateDomainCapability(domain: string, supportsSMTPUTF8: boolean): Promise<Result<void>> {
    try {
      await this.pool.query(`
        INSERT INTO edge_domain_capabilities (domain, supports_smtputf8, checked_at, check_count)
        VALUES ($1, $2, NOW(), 1)
        ON CONFLICT (domain) DO UPDATE SET
          supports_smtputf8 = $2,
          checked_at = NOW(),
          check_count = edge_domain_capabilities.check_count + 1
      `, [domain, supportsSMTPUTF8]);

      // Update caches
      this.eaiDomainCache.set(domain, supportsSMTPUTF8);
      await this.redis.setex(`eai:${domain}`, 86400, supportsSMTPUTF8 ? '1' : '0');

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }
}
