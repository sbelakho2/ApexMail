/**
 * Tracking ID Codec - Encode/decode tracking information in URLs
 */

import {
  encryptAES128GCM,
  decryptAES128GCM,
  deriveKeyHMAC,
  hmacBuffer,
  timingSafeCompareBuffers,
} from '@apexmail/lib/crypto';

// Using a compact binary format for minimal URL length
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

interface TrackingData {
  tenantId: string;
  messageId: string;
  recipient: string;
  linkId?: string;
  /** Original click URL — included inside encrypted token to prevent tampering */
  originalUrl?: string;
}

/**
 * TrackingCodec handles encoding and decoding of tracking data in URLs.
 * Uses AES-128-GCM for encryption and HMAC-SHA256 for signatures.
 */
export class TrackingCodec {
  private readonly encryptionKey: Buffer;
  private readonly signatureKey: Buffer;

  constructor(secretKey: string) {
    // Derive encryption and signature keys from the secret
    this.encryptionKey = deriveKeyHMAC(secretKey, 'encryption', 16); // 128 bits for AES-128
    this.signatureKey = deriveKeyHMAC(secretKey, 'signature', 32);
  }

  /**
   * Encode tracking data into a URL-safe string
   */
  encode(data: TrackingData): string {
    // Create compact binary representation
    const payload = this.serializeData(data);
    
    // Encrypt using AES-128-GCM
    const { ciphertext, iv, authTag } = encryptAES128GCM(payload, this.encryptionKey);
    
    // Combine: iv + authTag + encrypted
    const combined = Buffer.concat([iv, authTag, ciphertext]);
    
    // Base64url encode
    return this.base64UrlEncode(combined);
  }

  /**
   * Decode a tracking string back into data
   */
  decode(encoded: string): TrackingData | null {
    try {
      const combined = this.base64UrlDecode(encoded);
      
      if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
        return null;
      }
      
      const iv = combined.subarray(0, IV_LENGTH);
      const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
      const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
      
      const result = decryptAES128GCM(ciphertext, this.encryptionKey, iv, authTag);
      
      if (!result.ok) {
        return null;
      }
      
      return this.deserializeData(result.value);
      
    } catch {
      return null;
    }
  }

  /**
   * Generate a signed token for unsubscribe links (simpler, verifiable)
   */
  generateUnsubscribeToken(tenantId: string, recipient: string): string {
    const payload = `${tenantId}:${recipient}:${Date.now()}`;
    const signature = hmacBuffer(this.signatureKey, payload, 'sha256')
      .subarray(0, 16); // Truncate to 128 bits
    
    const combined = Buffer.concat([
      Buffer.from(payload, 'utf-8'),
      signature,
    ]);
    
    return this.base64UrlEncode(combined);
  }

  /**
   * Verify and decode an unsubscribe token
   */
  verifyUnsubscribeToken(
    token: string,
    options?: { maxAgeDays?: number }
  ): { tenantId: string; recipient: string; timestamp: number } | null {
    try {
      const combined = this.base64UrlDecode(token);
      
      if (combined.length < 17) {
        return null;
      }
      
      const payloadBuffer = combined.subarray(0, combined.length - 16);
      const providedSig = combined.subarray(combined.length - 16);
      
      const payload = payloadBuffer.toString('utf-8');
      
      // Verify signature
      const expectedSig = hmacBuffer(this.signatureKey, payload, 'sha256')
        .subarray(0, 16);
      
      if (!this.timingSafeEqualBuffers(providedSig, expectedSig)) {
        return null;
      }
      
      // Parse payload
      const parts = payload.split(':');
      if (parts.length < 3) {
        return null;
      }
      
      const tenantId = parts[0];
      const timestamp = parts[parts.length - 1];
      if (!tenantId || !timestamp) {
        return null;
      }

      const parsedTimestamp = parseInt(timestamp, 10);

      // Check token age — default 90 days max
      const maxAgeDays = options?.maxAgeDays ?? 90;
      const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
      if (Date.now() - parsedTimestamp > maxAgeMs) {
        return null;
      }
      
      return {
        tenantId,
        recipient: parts.slice(1, -1).join(':'), // Handle emails with colons (unlikely but safe)
        timestamp: parsedTimestamp,
      };
      
    } catch {
      return null;
    }
  }

  /**
   * Generate a preferences token with tenant and recipient
   */
  generatePreferencesToken(tenantId: string, recipient: string): string {
    return this.generateUnsubscribeToken(tenantId, recipient);
  }

  /**
   * Verify preferences token
   */
  verifyPreferencesToken(token: string): { tenantId: string; recipient: string } | null {
    const result = this.verifyUnsubscribeToken(token);
    if (!result) return null;
    
    // Check token age (max 30 days)
    const maxAge = 30 * 24 * 60 * 60 * 1000;
    if (Date.now() - result.timestamp > maxAge) {
      return null;
    }
    
    return {
      tenantId: result.tenantId,
      recipient: result.recipient,
    };
  }

  private serializeData(data: TrackingData): Buffer {
    // Compact binary format:
    // 1 byte: version
    //   v1: UInt8 field lengths (legacy)
    //   v2: UInt16 field lengths
    //   v3: UInt16 field lengths + originalUrl field (FIX-041)
    // 2 bytes: tenantId length
    // N bytes: tenantId
    // 2 bytes: messageId length
    // N bytes: messageId
    // 2 bytes: recipient length
    // N bytes: recipient
    // 2 bytes: linkId length (0 if not present)
    // N bytes: linkId (if present)
    // v3 only:
    // 2 bytes: originalUrl length (0 if not present)
    // N bytes: originalUrl (if present)
    
    const tenantIdBuf = Buffer.from(data.tenantId, 'utf-8');
    const messageIdBuf = Buffer.from(data.messageId, 'utf-8');
    const recipientBuf = Buffer.from(data.recipient, 'utf-8');
    const linkIdBuf = data.linkId ? Buffer.from(data.linkId, 'utf-8') : Buffer.alloc(0);
    const originalUrlBuf = data.originalUrl ? Buffer.from(data.originalUrl, 'utf-8') : Buffer.alloc(0);

    // Use v3 if originalUrl is present, otherwise v2 for backward compat
    const version = data.originalUrl ? 3 : 2;
    
    let totalLength = 1 + 2 + tenantIdBuf.length + 2 + messageIdBuf.length + 
                      2 + recipientBuf.length + 2 + linkIdBuf.length;
    if (version === 3) {
      totalLength += 2 + originalUrlBuf.length;
    }
    
    const buffer = Buffer.alloc(totalLength);
    let offset = 0;
    
    buffer.writeUInt8(version, offset++);
    
    // TenantId
    buffer.writeUInt16BE(tenantIdBuf.length, offset);
    offset += 2;
    tenantIdBuf.copy(buffer, offset);
    offset += tenantIdBuf.length;
    
    // MessageId
    buffer.writeUInt16BE(messageIdBuf.length, offset);
    offset += 2;
    messageIdBuf.copy(buffer, offset);
    offset += messageIdBuf.length;
    
    // Recipient
    buffer.writeUInt16BE(recipientBuf.length, offset);
    offset += 2;
    recipientBuf.copy(buffer, offset);
    offset += recipientBuf.length;
    
    // LinkId
    buffer.writeUInt16BE(linkIdBuf.length, offset);
    offset += 2;
    if (linkIdBuf.length > 0) {
      linkIdBuf.copy(buffer, offset);
      offset += linkIdBuf.length;
    }
    
    // OriginalUrl (v3 only)
    if (version === 3) {
      buffer.writeUInt16BE(originalUrlBuf.length, offset);
      offset += 2;
      if (originalUrlBuf.length > 0) {
        originalUrlBuf.copy(buffer, offset);
      }
    }
    
    return buffer;
  }

  private deserializeData(buffer: Buffer): TrackingData | null {
    try {
      let offset = 0;
      
      // Version
      const version = buffer.readUInt8(offset++);
      if (version !== 1 && version !== 2 && version !== 3) {
        return null;
      }
      
      // v2/v3 use UInt16 for field lengths; v1 uses UInt8
      const readLen = (version >= 2)
        ? () => { const v = buffer.readUInt16BE(offset); offset += 2; return v; }
        : () => buffer.readUInt8(offset++);
      
      // TenantId
      const tenantIdLen = readLen();
      const tenantId = buffer.subarray(offset, offset + tenantIdLen).toString('utf-8');
      offset += tenantIdLen;
      
      // MessageId
      const messageIdLen = readLen();
      const messageId = buffer.subarray(offset, offset + messageIdLen).toString('utf-8');
      offset += messageIdLen;
      
      // Recipient
      const recipientLen = readLen();
      const recipient = buffer.subarray(offset, offset + recipientLen).toString('utf-8');
      offset += recipientLen;
      
      // LinkId
      const linkIdLen = readLen();
      const linkId = linkIdLen > 0 
        ? buffer.subarray(offset, offset + linkIdLen).toString('utf-8')
        : undefined;
      offset += linkIdLen;

      // OriginalUrl (v3 only)
      let originalUrl: string | undefined;
      if (version === 3 && offset < buffer.length) {
        const originalUrlLen = readLen();
        if (originalUrlLen > 0) {
          originalUrl = buffer.subarray(offset, offset + originalUrlLen).toString('utf-8');
        }
      }
      
      return { tenantId, messageId, recipient, linkId, originalUrl };
      
    } catch {
      return null;
    }
  }

  private base64UrlEncode(buffer: Buffer): string {
    return buffer.toString('base64url');
  }

  private base64UrlDecode(str: string): Buffer {
    return Buffer.from(str, 'base64url');
  }

  private timingSafeEqualBuffers(a: Buffer, b: Buffer): boolean {
    return timingSafeCompareBuffers(a, b);
  }
}

/**
 * LinkRewriter handles URL rewriting for click tracking
 */
export class LinkRewriter {
  private readonly baseUrl: string;
  private readonly codec: TrackingCodec;
  private readonly clickPath: string;
  private readonly signatureKey: Buffer;

  constructor(baseUrl: string, codec: TrackingCodec, signatureKey: Buffer, clickPath: string = '/c') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.codec = codec;
    this.signatureKey = signatureKey;
    this.clickPath = clickPath;
  }

  /**
   * Rewrite a URL for click tracking
   */
  rewriteUrl(
    originalUrl: string,
    tenantId: string,
    messageId: string,
    recipient: string,
    linkId: string
  ): string {
    const trackingData = this.codec.encode({
      tenantId,
      messageId,
      recipient,
      linkId,
      // SECURITY FIX (FIX-041): Include original URL inside encrypted token
      // to prevent tampering via query parameter manipulation
      originalUrl,
    });
    
    // Keep query param for backward compat / transparency, but the
    // authoritative URL is inside the encrypted token
    const encodedOriginal = encodeURIComponent(originalUrl);
    
    return `${this.baseUrl}${this.clickPath}/${trackingData}?r=${encodedOriginal}`;
  }

  /**
   * Extract original URL from tracking URL
   */
  extractOriginalUrl(trackingUrl: string): string | null {
    try {
      const url = new URL(trackingUrl);
      const original = url.searchParams.get('r');
      return original ? decodeURIComponent(original) : null;
    } catch {
      return null;
    }
  }

  /**
   * Generate a link ID from URL and position
   * SECURITY: Uses instance signatureKey derived from secure random secret
   */
  generateLinkId(url: string, position: number): string {
    const hash = hmacBuffer(this.signatureKey, `${url}:${position}`, 'sha256')
      .toString('hex')
      .substring(0, 8);
    return `lnk_${hash}`;
  }
}
