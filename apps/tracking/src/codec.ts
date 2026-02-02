/**
 * Tracking ID Codec - Encode/decode tracking information in URLs
 */

import {
  encryptAES128GCM,
  decryptAES128GCM,
  deriveKeyHMAC,
  hmacBuffer,
  hmacSign,
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
  verifyUnsubscribeToken(token: string): { tenantId: string; recipient: string; timestamp: number } | null {
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
      
      return {
        tenantId,
        recipient: parts.slice(1, -1).join(':'), // Handle emails with colons (unlikely but safe)
        timestamp: parseInt(timestamp, 10),
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
    // 1 byte: tenantId length
    // N bytes: tenantId
    // 1 byte: messageId length
    // N bytes: messageId
    // 1 byte: recipient length
    // N bytes: recipient
    // 1 byte: linkId length (0 if not present)
    // N bytes: linkId (if present)
    
    const tenantIdBuf = Buffer.from(data.tenantId, 'utf-8');
    const messageIdBuf = Buffer.from(data.messageId, 'utf-8');
    const recipientBuf = Buffer.from(data.recipient, 'utf-8');
    const linkIdBuf = data.linkId ? Buffer.from(data.linkId, 'utf-8') : Buffer.alloc(0);
    
    const totalLength = 1 + 1 + tenantIdBuf.length + 1 + messageIdBuf.length + 
                       1 + recipientBuf.length + 1 + linkIdBuf.length;
    
    const buffer = Buffer.alloc(totalLength);
    let offset = 0;
    
    // Version
    buffer.writeUInt8(1, offset++);
    
    // TenantId
    buffer.writeUInt8(tenantIdBuf.length, offset++);
    tenantIdBuf.copy(buffer, offset);
    offset += tenantIdBuf.length;
    
    // MessageId
    buffer.writeUInt8(messageIdBuf.length, offset++);
    messageIdBuf.copy(buffer, offset);
    offset += messageIdBuf.length;
    
    // Recipient
    buffer.writeUInt8(recipientBuf.length, offset++);
    recipientBuf.copy(buffer, offset);
    offset += recipientBuf.length;
    
    // LinkId
    buffer.writeUInt8(linkIdBuf.length, offset++);
    if (linkIdBuf.length > 0) {
      linkIdBuf.copy(buffer, offset);
    }
    
    return buffer;
  }

  private deserializeData(buffer: Buffer): TrackingData | null {
    try {
      let offset = 0;
      
      // Version
      const version = buffer.readUInt8(offset++);
      if (version !== 1) {
        return null;
      }
      
      // TenantId
      const tenantIdLen = buffer.readUInt8(offset++);
      const tenantId = buffer.subarray(offset, offset + tenantIdLen).toString('utf-8');
      offset += tenantIdLen;
      
      // MessageId
      const messageIdLen = buffer.readUInt8(offset++);
      const messageId = buffer.subarray(offset, offset + messageIdLen).toString('utf-8');
      offset += messageIdLen;
      
      // Recipient
      const recipientLen = buffer.readUInt8(offset++);
      const recipient = buffer.subarray(offset, offset + recipientLen).toString('utf-8');
      offset += recipientLen;
      
      // LinkId
      const linkIdLen = buffer.readUInt8(offset++);
      const linkId = linkIdLen > 0 
        ? buffer.subarray(offset, offset + linkIdLen).toString('utf-8')
        : undefined;
      
      return { tenantId, messageId, recipient, linkId };
      
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

  constructor(baseUrl: string, codec: TrackingCodec, clickPath: string = '/c') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.codec = codec;
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
    });
    
    // Encode original URL in query param for transparency
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
   */
  generateLinkId(url: string, position: number): string {
    const hash = hmacSign('link-id', `${url}:${position}`, 'sha256')
      .substring(0, 8);
    return `lnk_${hash}`;
  }
}
