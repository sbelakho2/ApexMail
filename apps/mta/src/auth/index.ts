/**
 * Advanced Email Authentication Module Index
 * 
 * This module provides comprehensive email authentication beyond basic SPF/DKIM/DMARC:
 * 
 * - **ARC (RFC 8617)**: Authenticated Received Chain for preserving authentication
 *   across email forwarding intermediaries
 * 
 * - **MTA-STS (RFC 8461)**: Strict Transport Security to ensure TLS is enforced
 *   (not opportunistic) for email delivery
 * 
 * - **BIMI**: Brand Indicators for Message Identification to display brand logos
 *   in supporting email clients
 * 
 * - **TLSRPT (RFC 8460)**: TLS Reporting for receiving feedback about TLS issues
 * 
 * These standards are critical for:
 * 1. Maximum deliverability with major providers (Gmail, Microsoft, Yahoo)
 * 2. Brand visibility and trust
 * 3. Security against man-in-the-middle attacks
 * 4. Proper handling of forwarded/mailing list emails
 */

export * from './arc.js';
export * from './mta-sts.js';
export * from './bimi.js';
