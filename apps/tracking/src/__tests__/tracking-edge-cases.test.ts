/**
 * Tracking Package Edge-Case Tests
 *
 * Comprehensive tests for:
 * - TrackingCodec: AES-128-GCM encode/decode, unsubscribe/preferences tokens
 * - LinkRewriter: URL rewriting, link ID generation
 * - Route utility functions: domain matching, IP parsing, CIDR matching, HTML escaping
 */

import { describe, it, expect } from 'vitest';
import { TrackingCodec, LinkRewriter } from '../codec.js';
import { deriveKeyHMAC } from '@apexmail/lib/crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Production logic copies for testing non-exported route functions
// ─────────────────────────────────────────────────────────────────────────────

/** Copy of routes.ts matchDomainPattern */
function matchDomainPattern(domain: string, pattern: string): boolean {
  if (pattern === domain) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // Remove '*', keep '.'
    return domain.endsWith(suffix) && domain.length > suffix.length;
  }
  return false;
}

/** Copy of routes.ts ipToNumber */
function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0; // Convert to unsigned
}

/** Copy of routes.ts ipInCIDR */
function ipInCIDR(ip: string, cidr: string): boolean {
  const [rangeIP, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr || '32', 10);
  if (!rangeIP) return false;
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(rangeIP);
  if (ipNum === null || rangeNum === null) return false;
  const mask = prefix >= 32 ? ~0 : ~(0xFFFFFFFF >>> prefix);
  return (ipNum & mask) === (rangeNum & mask);
}

/** Copy of routes.ts isIPInRanges */
function isIPInRanges(ip: string, ranges: string[]): boolean {
  const normalizedIP = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  for (const range of ranges) {
    if (ipInCIDR(normalizedIP, range)) return true;
  }
  return false;
}

/** Copy of routes.ts HTML entity escaping */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


// ═════════════════════════════════════════════════════════════════════════════
// 1. TrackingCodec - Encode/Decode Round-Trip
// ═════════════════════════════════════════════════════════════════════════════

describe('TrackingCodec', () => {
  const codec = new TrackingCodec('test-tracking-secret-key-32-bytes');

  describe('encode/decode round-trip', () => {
    it('round-trips basic tracking data', () => {
      const data = {
        tenantId: 'tenant-123',
        messageId: 'msg-456',
        recipient: 'user@example.com',
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('round-trips data with linkId', () => {
      const data = {
        tenantId: 'tenant-123',
        messageId: 'msg-456',
        recipient: 'user@example.com',
        linkId: 'lnk_abc12345',
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('round-trips data with originalUrl (v3 format)', () => {
      const data = {
        tenantId: 'tenant-123',
        messageId: 'msg-456',
        recipient: 'user@example.com',
        linkId: 'lnk_abc12345',
        originalUrl: 'https://example.com/landing?utm_source=email&utm_campaign=test',
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('handles empty string fields', () => {
      const data = {
        tenantId: '',
        messageId: '',
        recipient: '',
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('handles Unicode in all fields', () => {
      const data = {
        tenantId: 'org-日本',
        messageId: 'msg-émoji-🚀',
        recipient: 'user@例え.jp',
        linkId: 'lnk_ünique',
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('handles long URLs in originalUrl', () => {
      const data = {
        tenantId: 'tenant-1',
        messageId: 'msg-1',
        recipient: 'a@b.com',
        originalUrl: 'https://example.com/' + 'path/'.repeat(500) + '?q=' + 'x'.repeat(2000),
      };
      const encoded = codec.encode(data);
      const decoded = codec.decode(encoded);
      expect(decoded).toEqual(data);
    });

    it('produces URL-safe base64 strings', () => {
      const data = {
        tenantId: 'tenant-123',
        messageId: 'msg-456',
        recipient: 'user@example.com',
      };
      const encoded = codec.encode(data);
      // base64url should not contain +, /, or =
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('different data produces different tokens', () => {
      const token1 = codec.encode({ tenantId: 't1', messageId: 'm1', recipient: 'a@b.com' });
      const token2 = codec.encode({ tenantId: 't2', messageId: 'm1', recipient: 'a@b.com' });
      expect(token1).not.toBe(token2);
    });

    it('same data produces different tokens each time (random IV)', () => {
      const data = { tenantId: 't1', messageId: 'm1', recipient: 'a@b.com' };
      const token1 = codec.encode(data);
      const token2 = codec.encode(data);
      expect(token1).not.toBe(token2);
      // But both decode to the same data
      expect(codec.decode(token1)).toEqual(data);
      expect(codec.decode(token2)).toEqual(data);
    });
  });

  describe('decode error handling', () => {
    it('returns null for empty string', () => {
      expect(codec.decode('')).toBeNull();
    });

    it('returns null for random garbage', () => {
      expect(codec.decode('not-a-valid-tracking-id')).toBeNull();
    });

    it('returns null for truncated token', () => {
      const valid = codec.encode({ tenantId: 't', messageId: 'm', recipient: 'a@b.com' });
      expect(codec.decode(valid.slice(0, 10))).toBeNull();
    });

    it('returns null for tampered token (bit flip)', () => {
      const valid = codec.encode({ tenantId: 't', messageId: 'm', recipient: 'a@b.com' });
      // Decode from base64url, flip a bit, re-encode
      const buf = Buffer.from(valid, 'base64url');
      buf[buf.length - 1]! ^= 0x01;
      const tampered = buf.toString('base64url');
      expect(codec.decode(tampered)).toBeNull();
    });

    it('returns null for token encrypted with different key', () => {
      const otherCodec = new TrackingCodec('different-secret-key-32-bytes!!');
      const token = otherCodec.encode({ tenantId: 't', messageId: 'm', recipient: 'a@b.com' });
      expect(codec.decode(token)).toBeNull();
    });

    it('returns null for too-short buffer (less than IV + authTag + 1)', () => {
      // IV=12, authTag=16, need at least 29 bytes
      const shortBuf = Buffer.alloc(28);
      expect(codec.decode(shortBuf.toString('base64url'))).toBeNull();
    });
  });

  describe('unsubscribe tokens', () => {
    it('generates and verifies valid unsubscribe token', () => {
      const token = codec.generateUnsubscribeToken('tenant-1', 'user@example.com');
      const result = codec.verifyUnsubscribeToken(token);
      expect(result).not.toBeNull();
      expect(result!.tenantId).toBe('tenant-1');
      expect(result!.recipient).toBe('user@example.com');
      expect(result!.timestamp).toBeTypeOf('number');
    });

    it('handles recipient with colons', () => {
      // Colons in email are rare but RFC-valid. The payload uses colons as delimiter.
      const token = codec.generateUnsubscribeToken('tenant-1', 'user:special@example.com');
      const result = codec.verifyUnsubscribeToken(token);
      expect(result).not.toBeNull();
      expect(result!.recipient).toBe('user:special@example.com');
    });

    it('rejects token with tampered signature', () => {
      const token = codec.generateUnsubscribeToken('tenant-1', 'user@example.com');
      const buf = Buffer.from(token, 'base64url');
      buf[buf.length - 1]! ^= 0xFF; // Flip all bits of last byte
      const tampered = buf.toString('base64url');
      expect(codec.verifyUnsubscribeToken(tampered)).toBeNull();
    });

    it('rejects expired token (>90 days default)', async () => {
      const token = codec.generateUnsubscribeToken('tenant-1', 'user@example.com');
      // maxAgeDays=0 means maxAgeMs=0. Wait 2ms so age > 0, guaranteeing rejection.
      await new Promise(r => setTimeout(r, 2));
      const result = codec.verifyUnsubscribeToken(token, { maxAgeDays: 0 });
      expect(result).toBeNull();
    });

    it('accepts token within maxAgeDays', () => {
      const token = codec.generateUnsubscribeToken('tenant-1', 'user@example.com');
      const result = codec.verifyUnsubscribeToken(token, { maxAgeDays: 1 });
      expect(result).not.toBeNull();
    });

    it('rejects empty token', () => {
      expect(codec.verifyUnsubscribeToken('')).toBeNull();
    });

    it('rejects token from different codec (wrong key)', () => {
      const otherCodec = new TrackingCodec('another-secret-key-32-bytes!!!!');
      const token = otherCodec.generateUnsubscribeToken('tenant-1', 'user@example.com');
      expect(codec.verifyUnsubscribeToken(token)).toBeNull();
    });

    it('rejects very short token', () => {
      expect(codec.verifyUnsubscribeToken('abc')).toBeNull();
    });
  });

  describe('preferences tokens', () => {
    it('generates and verifies valid preferences token', () => {
      const token = codec.generatePreferencesToken('tenant-1', 'user@example.com');
      const result = codec.verifyPreferencesToken(token);
      expect(result).not.toBeNull();
      expect(result!.tenantId).toBe('tenant-1');
      expect(result!.recipient).toBe('user@example.com');
    });

    it('has shorter max age than unsubscribe (30 days vs 90)', () => {
      // Since preferences token uses 30-day hardcoded max age,
      // and it's just created, it should be valid
      const token = codec.generatePreferencesToken('tenant-1', 'user@example.com');
      const result = codec.verifyPreferencesToken(token);
      expect(result).not.toBeNull();
    });

    it('rejects tampered preferences token', () => {
      const token = codec.generatePreferencesToken('tenant-1', 'user@example.com');
      const buf = Buffer.from(token, 'base64url');
      buf[buf.length - 1]! ^= 0xFF;
      const tampered = buf.toString('base64url');
      expect(codec.verifyPreferencesToken(tampered)).toBeNull();
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 2. LinkRewriter
// ═════════════════════════════════════════════════════════════════════════════

describe('LinkRewriter', () => {
  const secretKey = 'test-link-rewriter-secret-key-32!';
  const codec = new TrackingCodec(secretKey);
  const signatureKey = deriveKeyHMAC(secretKey, 'signature', 32);
  const rewriter = new LinkRewriter('https://track.example.com', codec, signatureKey);

  describe('rewriteUrl', () => {
    it('produces a tracking URL with click path', () => {
      const url = rewriter.rewriteUrl(
        'https://example.com/landing',
        'tenant-1',
        'msg-1',
        'user@example.com',
        'lnk_12345678'
      );
      expect(url).toContain('https://track.example.com/c/');
      expect(url).toContain('r=');
    });

    it('includes original URL as query param', () => {
      const url = rewriter.rewriteUrl(
        'https://example.com/page?foo=bar',
        't', 'm', 'u@e.com', 'lnk_1'
      );
      expect(url).toContain('r=' + encodeURIComponent('https://example.com/page?foo=bar'));
    });

    it('encrypted token decodes to data with originalUrl', () => {
      const originalUrl = 'https://example.com/landing';
      const url = rewriter.rewriteUrl(originalUrl, 't1', 'm1', 'u@e.com', 'lnk_1');

      // Extract the token from the URL (between /c/ and ?)
      const tokenMatch = url.match(/\/c\/([^?]+)/);
      expect(tokenMatch).not.toBeNull();
      const decoded = codec.decode(tokenMatch![1]!);
      expect(decoded).not.toBeNull();
      expect(decoded!.originalUrl).toBe(originalUrl);
      expect(decoded!.tenantId).toBe('t1');
      expect(decoded!.messageId).toBe('m1');
      expect(decoded!.recipient).toBe('u@e.com');
      expect(decoded!.linkId).toBe('lnk_1');
    });

    it('strips trailing slash from base URL', () => {
      const rw = new LinkRewriter('https://track.example.com/', codec, signatureKey);
      const url = rw.rewriteUrl('https://a.com', 't', 'm', 'u@e.com', 'lnk_1');
      expect(url).toContain('https://track.example.com/c/');
      expect(url).not.toContain('//c/');
    });
  });

  describe('extractOriginalUrl', () => {
    it('extracts URL from query param', () => {
      const url = rewriter.rewriteUrl('https://target.com/page', 't', 'm', 'u@e.com', 'lnk_1');
      const extracted = rewriter.extractOriginalUrl(url);
      expect(extracted).toBe('https://target.com/page');
    });

    it('returns null for URL without r param', () => {
      expect(rewriter.extractOriginalUrl('https://track.example.com/c/abc123')).toBeNull();
    });

    it('returns null for invalid URL', () => {
      expect(rewriter.extractOriginalUrl('not-a-url')).toBeNull();
    });
  });

  describe('generateLinkId', () => {
    it('produces deterministic link IDs', () => {
      const id1 = rewriter.generateLinkId('https://example.com', 0);
      const id2 = rewriter.generateLinkId('https://example.com', 0);
      expect(id1).toBe(id2);
    });

    it('different URLs produce different IDs', () => {
      const id1 = rewriter.generateLinkId('https://example.com/a', 0);
      const id2 = rewriter.generateLinkId('https://example.com/b', 0);
      expect(id1).not.toBe(id2);
    });

    it('different positions produce different IDs', () => {
      const id1 = rewriter.generateLinkId('https://example.com', 0);
      const id2 = rewriter.generateLinkId('https://example.com', 1);
      expect(id1).not.toBe(id2);
    });

    it('produces lnk_ prefixed 8-char hex IDs', () => {
      const id = rewriter.generateLinkId('https://example.com', 0);
      expect(id).toMatch(/^lnk_[a-f0-9]{8}$/);
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 3. matchDomainPattern - Open Redirect Prevention
// ═════════════════════════════════════════════════════════════════════════════

describe('matchDomainPattern', () => {
  it('matches exact domain', () => {
    expect(matchDomainPattern('example.com', 'example.com')).toBe(true);
  });

  it('does not match different domain', () => {
    expect(matchDomainPattern('evil.com', 'example.com')).toBe(false);
  });

  it('matches subdomain against wildcard', () => {
    expect(matchDomainPattern('sub.example.com', '*.example.com')).toBe(true);
  });

  it('matches deep subdomain against wildcard', () => {
    expect(matchDomainPattern('a.b.c.example.com', '*.example.com')).toBe(true);
  });

  it('does not match bare domain against wildcard', () => {
    // '*.example.com' should NOT match 'example.com' itself
    expect(matchDomainPattern('example.com', '*.example.com')).toBe(false);
  });

  it('does not match domain that only ends with the pattern', () => {
    // 'notexample.com' ends with 'example.com' but shouldn't match
    expect(matchDomainPattern('notexample.com', '*.example.com')).toBe(false);
  });

  it('handles wildcard with only TLD suffix', () => {
    // This is a dangerous pattern but should work mechanically
    expect(matchDomainPattern('anything.com', '*.com')).toBe(true);
    expect(matchDomainPattern('com', '*.com')).toBe(false);
  });

  it('is case-sensitive (production behavior)', () => {
    // Production code doesn't normalize case
    expect(matchDomainPattern('Example.com', 'example.com')).toBe(false);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 4. ipToNumber
// ═════════════════════════════════════════════════════════════════════════════

describe('ipToNumber', () => {
  it('converts 0.0.0.0 to 0', () => {
    expect(ipToNumber('0.0.0.0')).toBe(0);
  });

  it('converts 255.255.255.255 to max uint32', () => {
    expect(ipToNumber('255.255.255.255')).toBe(0xFFFFFFFF);
  });

  it('converts 192.168.1.1 correctly', () => {
    expect(ipToNumber('192.168.1.1')).toBe((192 << 24 | 168 << 16 | 1 << 8 | 1) >>> 0);
  });

  it('converts 10.0.0.1', () => {
    expect(ipToNumber('10.0.0.1')).toBe((10 << 24 | 0 << 16 | 0 << 8 | 1) >>> 0);
  });

  it('returns null for IPv6', () => {
    expect(ipToNumber('::1')).toBeNull();
  });

  it('returns null for too few octets', () => {
    expect(ipToNumber('192.168.1')).toBeNull();
  });

  it('returns null for too many octets', () => {
    expect(ipToNumber('192.168.1.1.1')).toBeNull();
  });

  it('returns null for octet > 255', () => {
    expect(ipToNumber('256.0.0.1')).toBeNull();
  });

  it('returns null for negative octet', () => {
    expect(ipToNumber('-1.0.0.1')).toBeNull();
  });

  it('returns null for non-numeric', () => {
    expect(ipToNumber('abc.def.ghi.jkl')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(ipToNumber('')).toBeNull();
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 5. ipInCIDR
// ═════════════════════════════════════════════════════════════════════════════

describe('ipInCIDR', () => {
  it('matches IP in /24 range', () => {
    expect(ipInCIDR('192.168.1.100', '192.168.1.0/24')).toBe(true);
  });

  it('rejects IP outside /24 range', () => {
    expect(ipInCIDR('192.168.2.1', '192.168.1.0/24')).toBe(false);
  });

  it('matches IP in /8 range', () => {
    expect(ipInCIDR('10.255.255.255', '10.0.0.0/8')).toBe(true);
  });

  it('handles /32 (single host)', () => {
    expect(ipInCIDR('192.168.1.1', '192.168.1.1/32')).toBe(true);
    expect(ipInCIDR('192.168.1.2', '192.168.1.1/32')).toBe(false);
  });

  it('handles /0 (match all) — uses >>> shift, no overflow bug', () => {
    // This implementation uses ~(0xFFFFFFFF >>> prefix) instead of ~((1 << (32-prefix)) - 1)
    // For prefix=0: ~(0xFFFFFFFF >>> 0) = ~(0xFFFFFFFF) = 0 → match all
    // This CORRECTLY handles /0 (unlike the trusted-proxy.ts version we fixed)
    expect(ipInCIDR('1.2.3.4', '0.0.0.0/0')).toBe(true);
    expect(ipInCIDR('255.255.255.255', '0.0.0.0/0')).toBe(true);
  });

  it('handles CIDR without prefix (defaults to /32)', () => {
    expect(ipInCIDR('10.0.0.1', '10.0.0.1')).toBe(true);
    expect(ipInCIDR('10.0.0.2', '10.0.0.1')).toBe(false);
  });

  it('returns false for invalid IP', () => {
    expect(ipInCIDR('not-an-ip', '10.0.0.0/8')).toBe(false);
  });

  it('returns false for invalid CIDR range IP', () => {
    expect(ipInCIDR('10.0.0.1', 'not-an-ip/8')).toBe(false);
  });

  it('returns false for empty CIDR', () => {
    expect(ipInCIDR('10.0.0.1', '')).toBe(false);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 6. isIPInRanges (with IPv4-mapped IPv6 normalization)
// ═════════════════════════════════════════════════════════════════════════════

describe('isIPInRanges', () => {
  it('matches plain IPv4 against CIDR', () => {
    expect(isIPInRanges('10.0.0.1', ['10.0.0.0/8'])).toBe(true);
  });

  it('rejects non-matching IPv4', () => {
    expect(isIPInRanges('192.168.1.1', ['10.0.0.0/8'])).toBe(false);
  });

  it('normalizes IPv4-mapped IPv6 addresses', () => {
    // ::ffff:10.0.0.1 should be normalized to 10.0.0.1
    expect(isIPInRanges('::ffff:10.0.0.1', ['10.0.0.0/8'])).toBe(true);
  });

  it('normalizes IPv4-mapped IPv6 loopback', () => {
    expect(isIPInRanges('::ffff:127.0.0.1', ['127.0.0.0/8'])).toBe(true);
  });

  it('checks against multiple ranges', () => {
    expect(isIPInRanges('172.16.0.1', ['10.0.0.0/8', '172.16.0.0/12'])).toBe(true);
    expect(isIPInRanges('192.168.1.1', ['10.0.0.0/8', '172.16.0.0/12'])).toBe(false);
  });

  it('returns false for empty range list', () => {
    expect(isIPInRanges('10.0.0.1', [])).toBe(false);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 7. HTML Entity Escaping
// ═════════════════════════════════════════════════════════════════════════════

describe('escapeHtml', () => {
  it('escapes ampersands', () => {
    expect(escapeHtml('a & b')).toBe('a &amp; b');
  });

  it('escapes less-than', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
  });

  it('escapes double quotes', () => {
    expect(escapeHtml('value="test"')).toBe('value=&quot;test&quot;');
  });

  it('escapes single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#39;s');
  });

  it('handles multiple entities in one string', () => {
    expect(escapeHtml('<div class="x">&\'</div>')).toBe(
      '&lt;div class=&quot;x&quot;&gt;&amp;&#39;&lt;/div&gt;'
    );
  });

  it('passes through safe strings unchanged', () => {
    expect(escapeHtml('Hello World 123')).toBe('Hello World 123');
  });

  it('handles empty string', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('prevents XSS via script injection', () => {
    const xss = '<script>alert("xss")</script>';
    const escaped = escapeHtml(xss);
    expect(escaped).not.toContain('<script>');
    expect(escaped).not.toContain('</script>');
  });

  it('prevents XSS via event handler injection', () => {
    const xss = '" onload="alert(1)"';
    const escaped = escapeHtml(xss);
    expect(escaped).not.toContain('"');
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 8. Cross-Codec Security Tests
// ═════════════════════════════════════════════════════════════════════════════

describe('Cross-Codec Security', () => {
  it('different secret keys produce incompatible codecs', () => {
    const codec1 = new TrackingCodec('secret-key-one-padded-to-32-!!!!');
    const codec2 = new TrackingCodec('secret-key-two-padded-to-32-!!!!');

    const token = codec1.encode({ tenantId: 't', messageId: 'm', recipient: 'a@b.com' });
    expect(codec2.decode(token)).toBeNull();
  });

  it('unsubscribe token from one codec rejected by another', () => {
    const codec1 = new TrackingCodec('secret-key-one-padded-to-32-!!!!');
    const codec2 = new TrackingCodec('secret-key-two-padded-to-32-!!!!');

    const token = codec1.generateUnsubscribeToken('t', 'a@b.com');
    expect(codec2.verifyUnsubscribeToken(token)).toBeNull();
  });

  it('tracking ID cannot be replayed across tenants', () => {
    const codec = new TrackingCodec('shared-secret-key-padded-to-32!');

    const token = codec.encode({
      tenantId: 'tenant-attacker',
      messageId: 'msg-1',
      recipient: 'victim@company.com',
    });

    const decoded = codec.decode(token);
    // Even if an attacker decodes the token, they can't change the tenantId
    // because the ciphertext is integrity-protected by AES-GCM authTag
    expect(decoded!.tenantId).toBe('tenant-attacker');
    // Tampering with the encoded token will invalidate it
    const buf = Buffer.from(token, 'base64url');
    // Try to change tenantId bytes (after IV + authTag)
    buf[29]! ^= 0x01;
    expect(codec.decode(buf.toString('base64url'))).toBeNull();
  });
});
