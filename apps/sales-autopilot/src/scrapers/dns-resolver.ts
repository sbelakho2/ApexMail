/**
 * DNS MX Record Resolver
 * Checks email providers via MX records for lead qualification
 */

import { Resolver } from 'node:dns/promises';
import { createLogger } from '@apexmail/lib';
import type { MxRecord } from '../types.js';

const logger = createLogger({ name: 'dns-resolver', level: 'info' });

const resolver = new Resolver();
resolver.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

// Known email provider patterns
const EMAIL_PROVIDERS: Record<string, string[]> = {
    'Google Workspace': [
        'google.com',
        'googlemail.com',
        'aspmx.l.google.com',
        'alt1.aspmx.l.google.com',
        'alt2.aspmx.l.google.com',
    ],
    'Microsoft 365': [
        'outlook.com',
        'protection.outlook.com',
        'mail.protection.outlook.com',
    ],
    Zoho: ['zoho.com', 'zoho.eu', 'zohomail.com'],
    Fastmail: ['fastmail.com', 'messagingengine.com'],
    ProtonMail: ['protonmail.ch', 'proton.me'],
    'Amazon SES': ['amazonses.com', 'inbound-smtp.us-east-1.amazonaws.com'],
    'Amazon WorkMail': ['awsapps.com'],
    'Rackspace Email': ['emailsrvr.com', 'rackspace.com'],
    Mimecast: ['mimecast.com'],
    Barracuda: ['barracudanetworks.com'],
    'Self-Hosted': [],
};

/**
 * Resolves MX records for a domain
 */
export async function resolveMxRecords(domain: string): Promise<MxRecord[]> {
    try {
        const records = await resolver.resolveMx(domain);
        return records
            .sort((a, b) => a.priority - b.priority)
            .map((r) => ({
                exchange: r.exchange.toLowerCase(),
                priority: r.priority,
            }));
    } catch (error) {
        const err = error as NodeJS.ErrnoException;
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            logger.debug('No MX records found', { domain });
            return [];
        }
        logger.error('Failed to resolve MX records', { domain, error });
        throw error;
    }
}

/**
 * Identifies the email provider based on MX records
 */
export function identifyEmailProvider(mxRecords: MxRecord[]): string | null {
    if (mxRecords.length === 0) {
        return null;
    }

    const firstRecord = mxRecords[0];
    if (!firstRecord) {
        return null;
    }
    const primaryMx = firstRecord.exchange;

    for (const [provider, patterns] of Object.entries(EMAIL_PROVIDERS)) {
        for (const pattern of patterns) {
            if (primaryMx.includes(pattern)) {
                return provider;
            }
        }
    }

    // Check for common self-hosted patterns
    if (
        primaryMx.startsWith('mail.') ||
        primaryMx.startsWith('mx.') ||
        primaryMx.startsWith('smtp.')
    ) {
        return 'Self-Hosted';
    }

    return 'Unknown';
}

/**
 * Checks if a domain has valid email capability
 */
export async function hasEmailCapability(domain: string): Promise<boolean> {
    const records = await resolveMxRecords(domain);
    return records.length > 0;
}

/**
 * Gets full email infrastructure info for a domain
 */
export async function getEmailInfrastructure(domain: string): Promise<{
    hasMx: boolean;
    mxRecords: MxRecord[];
    provider: string | null;
    spfRecord: string | null;
    dmarcRecord: string | null;
}> {
    const [mxRecords, spfRecord, dmarcRecord] = await Promise.all([
        resolveMxRecords(domain),
        resolveSpfRecord(domain),
        resolveDmarcRecord(domain),
    ]);

    return {
        hasMx: mxRecords.length > 0,
        mxRecords,
        provider: identifyEmailProvider(mxRecords),
        spfRecord,
        dmarcRecord,
    };
}

/**
 * Resolves SPF record for a domain
 */
async function resolveSpfRecord(domain: string): Promise<string | null> {
    try {
        const records = await resolver.resolveTxt(domain);
        for (const record of records) {
            const txt = record.join('');
            if (txt.startsWith('v=spf1')) {
                return txt;
            }
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Resolves DMARC record for a domain
 */
async function resolveDmarcRecord(domain: string): Promise<string | null> {
    try {
        const records = await resolver.resolveTxt(`_dmarc.${domain}`);
        for (const record of records) {
            const txt = record.join('');
            if (txt.startsWith('v=DMARC1')) {
                return txt;
            }
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Validates an email address exists via SMTP
 * Note: Many servers don't support VRFY, so this is best-effort
 */
export async function validateEmailExists(
    email: string
): Promise<{ valid: boolean; reason: string }> {
    const [, domain] = email.split('@');

    if (!domain) {
        return { valid: false, reason: 'Invalid email format' };
    }

    // First check if domain has MX records
    const mxRecords = await resolveMxRecords(domain);
    if (mxRecords.length === 0) {
        return { valid: false, reason: 'No MX records for domain' };
    }

    // Treat valid MX as potentially deliverable; SMTP-level mailbox validation
    // is intentionally skipped because many servers block VRFY/RCPT probing.
    return { valid: true, reason: 'MX records present' };
}

/**
 * Batch resolve MX records for multiple domains
 */
export async function batchResolveMx(
    domains: string[]
): Promise<Map<string, { mxRecords: MxRecord[]; provider: string | null }>> {
    const results = new Map<
        string,
        { mxRecords: MxRecord[]; provider: string | null }
    >();

    // Process in batches to avoid DNS server rate limits
    const batchSize = 10;

    for (let i = 0; i < domains.length; i += batchSize) {
        const batch = domains.slice(i, i + batchSize);

        const batchResults = await Promise.allSettled(
            batch.map(async (domain) => {
                const mxRecords = await resolveMxRecords(domain);
                return {
                    domain,
                    mxRecords,
                    provider: identifyEmailProvider(mxRecords),
                };
            })
        );

        for (const result of batchResults) {
            if (result.status === 'fulfilled') {
                results.set(result.value.domain, {
                    mxRecords: result.value.mxRecords,
                    provider: result.value.provider,
                });
            }
        }

        // Small delay between batches
        if (i + batchSize < domains.length) {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }

    return results;
}
