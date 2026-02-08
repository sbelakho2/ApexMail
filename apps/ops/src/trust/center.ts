/**
 * @apexmail/ops - Trust Center
 * 
 * Public trust center with security information, compliance certifications,
 * and data processing agreements.
 *
 * FIX-500-156: All Maps backed by Postgres for production persistence.
 * L1 in-memory cache with write-through to DB on every mutation.
 */

import { Pool } from 'pg';
import {
    TrustCenterData,
    TrustCenterCertification,
    TrustCenterDocument,
} from '../types.js';
import { EventEmitter } from 'events';

export interface TrustCenterConfig {
    publicUrl: string;
    companyName: string;
    legalEntity: string;
    supportEmail: string;
    dpoEmail: string;
}

interface SecurityControl {
    id: string;
    category: string;
    name: string;
    description: string;
    status: 'implemented' | 'partial' | 'planned';
    evidence?: string;
    lastVerified?: Date;
}

interface SubProcessor {
    id: string;
    name: string;
    purpose: string;
    location: string;
    dataCategories: string[];
    website: string;
    dpaUrl?: string;
    addedAt: Date;
}

interface DataPractice {
    id: string;
    category: string;
    practice: string;
    description: string;
}

export class TrustCenterService extends EventEmitter {
    private config: TrustCenterConfig;
    private db: Pool | null;
    private certifications: Map<string, TrustCenterCertification> = new Map();
    private documents: Map<string, TrustCenterDocument> = new Map();
    private securityControls: Map<string, SecurityControl> = new Map();
    private subProcessors: Map<string, SubProcessor> = new Map();
    private dataPractices: Map<string, DataPractice> = new Map();
    private faq: { question: string; answer: string; category: string }[] = [];
    private dbLoaded = false;

    constructor(config: TrustCenterConfig, db?: Pool) {
        super();
        this.setMaxListeners(50); // FIX-500-332: Prevent maxListeners warning
        this.config = config;
        this.db = db ?? null;
        this.initializeDefaultData();
    }

    /**
     * FIX-500-156: Load trust center data from DB into cache.
     */
    async loadFromDb(): Promise<void> {
        if (!this.db || this.dbLoaded) return;
        try {
            const { rows: certRows } = await this.db.query('SELECT * FROM trust_certifications');
            if (certRows.length > 0) {
                this.certifications.clear();
                for (const r of certRows) {
                    this.certifications.set(r.id, { id: r.id, name: r.name, description: r.description, issuer: r.issuer, validFrom: r.valid_from ? new Date(r.valid_from) : undefined, validUntil: r.valid_until ? new Date(r.valid_until) : undefined, status: r.status, documentUrl: r.document_url } as TrustCenterCertification);
                }
            }
            const { rows: docRows } = await this.db.query('SELECT * FROM trust_documents');
            if (docRows.length > 0) {
                this.documents.clear();
                for (const r of docRows) {
                    this.documents.set(r.id, { id: r.id, name: r.name, description: r.description, type: r.type, url: r.url, lastUpdated: new Date(r.last_updated), version: r.version } as TrustCenterDocument);
                }
            }
            const { rows: ctrlRows } = await this.db.query('SELECT * FROM trust_security_controls');
            if (ctrlRows.length > 0) {
                this.securityControls.clear();
                for (const r of ctrlRows) {
                    this.securityControls.set(r.id, { id: r.id, category: r.category, name: r.name, description: r.description, status: r.status, evidence: r.evidence, lastVerified: r.last_verified ? new Date(r.last_verified) : undefined });
                }
            }
            const { rows: spRows } = await this.db.query('SELECT * FROM trust_sub_processors');
            if (spRows.length > 0) {
                this.subProcessors.clear();
                for (const r of spRows) {
                    this.subProcessors.set(r.id, { id: r.id, name: r.name, purpose: r.purpose, location: r.location, dataCategories: r.data_categories || [], website: r.website, dpaUrl: r.dpa_url, addedAt: new Date(r.added_at) });
                }
            }
            const { rows: dpRows } = await this.db.query('SELECT * FROM trust_data_practices');
            if (dpRows.length > 0) {
                this.dataPractices.clear();
                for (const r of dpRows) {
                    this.dataPractices.set(r.id, { id: r.id, category: r.category, practice: r.practice, description: r.description });
                }
            }
            const { rows: faqRows } = await this.db.query('SELECT * FROM trust_faq ORDER BY sort_order');
            if (faqRows.length > 0) {
                this.faq = faqRows.map(r => ({ category: r.category, question: r.question, answer: r.answer }));
            }
            this.dbLoaded = true;
        } catch {
            this.dbLoaded = true; // Tables may not exist yet
        }
    }

    /**
     * Initializes default trust center data
     */
    private initializeDefaultData(): void {
        // Security Controls
        this.registerSecurityControls();

        // Certifications
        this.registerCertifications();

        // Documents
        this.registerDocuments();

        // Sub-processors
        this.registerSubProcessors();

        // Data Practices
        this.registerDataPractices();

        // FAQ
        this.initializeFAQ();
    }

    /**
     * Registers security controls
     */
    private registerSecurityControls(): void {
        const controls: SecurityControl[] = [
            {
                id: 'enc-transit',
                category: 'Data Encryption',
                name: 'Encryption in Transit',
                description: 'All data transmitted using TLS 1.3 with strong cipher suites',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'enc-rest',
                category: 'Data Encryption',
                name: 'Encryption at Rest',
                description: 'All data encrypted using AES-256-GCM at rest',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'enc-keys',
                category: 'Data Encryption',
                name: 'Key Management',
                description: 'HSM-backed key management with automatic rotation',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'auth-mfa',
                category: 'Authentication',
                name: 'Multi-Factor Authentication',
                description: 'MFA available for all user accounts with TOTP and WebAuthn support',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'auth-sso',
                category: 'Authentication',
                name: 'SSO Integration',
                description: 'SAML 2.0 and OIDC support for enterprise SSO',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'auth-rbac',
                category: 'Access Control',
                name: 'Role-Based Access Control',
                description: 'Granular RBAC with custom roles and permissions',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'audit-logs',
                category: 'Monitoring',
                name: 'Audit Logging',
                description: 'Comprehensive audit logging with tamper-proof storage',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'monitor-security',
                category: 'Monitoring',
                name: 'Security Monitoring',
                description: '24/7 security monitoring with automated threat detection',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'infra-cloud',
                category: 'Infrastructure',
                name: 'Cloud Security',
                description: 'Infrastructure hosted on SOC 2 compliant cloud providers',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'infra-network',
                category: 'Infrastructure',
                name: 'Network Security',
                description: 'Network segmentation, WAF, and DDoS protection',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'vuln-scanning',
                category: 'Vulnerability Management',
                name: 'Vulnerability Scanning',
                description: 'Automated vulnerability scanning with remediation SLAs',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'vuln-pentest',
                category: 'Vulnerability Management',
                name: 'Penetration Testing',
                description: 'Annual third-party penetration testing',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'ir-plan',
                category: 'Incident Response',
                name: 'Incident Response Plan',
                description: 'Documented incident response plan with regular testing',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'bc-dr',
                category: 'Business Continuity',
                name: 'Disaster Recovery',
                description: 'Multi-region disaster recovery with tested failover',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'data-retention',
                category: 'Data Management',
                name: 'Data Retention',
                description: 'Configurable data retention with secure deletion',
                status: 'implemented',
                lastVerified: new Date(),
            },
            {
                id: 'data-export',
                category: 'Data Management',
                name: 'Data Portability',
                description: 'Full data export in standard formats',
                status: 'implemented',
                lastVerified: new Date(),
            },
        ];

        for (const control of controls) {
            this.securityControls.set(control.id, control);
        }
    }

    /**
     * Registers certifications
     */
    private registerCertifications(): void {
        const certs: TrustCenterCertification[] = [
            {
                id: 'soc2-type2',
                name: 'SOC 2 Type II',
                description: 'Service Organization Control 2 Type II certification for security, availability, and confidentiality',
                issuer: 'Independent Auditor',
                validFrom: new Date('2024-01-15'),
                validUntil: new Date('2025-01-15'),
                status: 'valid',
                documentUrl: '/docs/soc2-type2-report.pdf',
            },
            {
                id: 'iso27001',
                name: 'ISO 27001:2022',
                description: 'Information Security Management System certification',
                issuer: 'Certification Body',
                validFrom: new Date('2024-02-01'),
                validUntil: new Date('2027-02-01'),
                status: 'valid',
                documentUrl: '/docs/iso27001-certificate.pdf',
            },
            {
                id: 'gdpr-compliant',
                name: 'GDPR Compliance',
                description: 'General Data Protection Regulation compliance verified',
                issuer: 'Data Protection Authority',
                validFrom: new Date('2024-01-01'),
                status: 'valid',
            },
            {
                id: 'ccpa-compliant',
                name: 'CCPA Compliance',
                description: 'California Consumer Privacy Act compliance',
                issuer: 'Self-Assessment',
                validFrom: new Date('2024-01-01'),
                status: 'valid',
            },
            {
                id: 'hipaa-baa',
                name: 'HIPAA BAA Available',
                description: 'Business Associate Agreement available for healthcare customers',
                issuer: 'Internal',
                validFrom: new Date('2024-01-01'),
                status: 'valid',
            },
        ];

        for (const cert of certs) {
            this.certifications.set(cert.id, cert);
        }
    }

    /**
     * Registers documents
     */
    private registerDocuments(): void {
        const docs: TrustCenterDocument[] = [
            {
                id: 'privacy-policy',
                name: 'Privacy Policy',
                description: 'How we collect, use, and protect your data',
                type: 'policy',
                url: '/legal/privacy-policy',
                lastUpdated: new Date('2024-03-01'),
                version: '3.0',
            },
            {
                id: 'terms-of-service',
                name: 'Terms of Service',
                description: 'Terms and conditions for using our services',
                type: 'policy',
                url: '/legal/terms-of-service',
                lastUpdated: new Date('2024-03-01'),
                version: '3.0',
            },
            {
                id: 'dpa',
                name: 'Data Processing Agreement',
                description: 'Standard DPA for GDPR compliance',
                type: 'agreement',
                url: '/legal/dpa',
                lastUpdated: new Date('2024-03-01'),
                version: '2.0',
            },
            {
                id: 'security-whitepaper',
                name: 'Security Whitepaper',
                description: 'Detailed overview of our security architecture',
                type: 'whitepaper',
                url: '/docs/security-whitepaper.pdf',
                lastUpdated: new Date('2024-02-15'),
                version: '2.1',
            },
            {
                id: 'compliance-guide',
                name: 'Compliance Guide',
                description: 'Guide to compliance features and configurations',
                type: 'guide',
                url: '/docs/compliance-guide.pdf',
                lastUpdated: new Date('2024-02-01'),
                version: '1.5',
            },
            {
                id: 'acceptable-use',
                name: 'Acceptable Use Policy',
                description: 'Guidelines for acceptable use of our services',
                type: 'policy',
                url: '/legal/acceptable-use',
                lastUpdated: new Date('2024-01-15'),
                version: '2.0',
            },
            {
                id: 'sla',
                name: 'Service Level Agreement',
                description: 'Our commitments to service availability and support',
                type: 'agreement',
                url: '/legal/sla',
                lastUpdated: new Date('2024-03-01'),
                version: '2.0',
            },
            {
                id: 'subprocessor-list',
                name: 'Sub-processor List',
                description: 'Current list of sub-processors',
                type: 'disclosure',
                url: '/legal/subprocessors',
                lastUpdated: new Date(),
                version: '1.0',
            },
        ];

        for (const doc of docs) {
            this.documents.set(doc.id, doc);
        }
    }

    /**
     * Registers sub-processors
     */
    private registerSubProcessors(): void {
        const processors: SubProcessor[] = [
            {
                id: 'aws',
                name: 'Amazon Web Services',
                purpose: 'Cloud infrastructure hosting',
                location: 'United States, European Union',
                dataCategories: ['All customer data'],
                website: 'https://aws.amazon.com',
                dpaUrl: 'https://aws.amazon.com/compliance/gdpr-center/',
                addedAt: new Date('2023-01-01'),
            },
            {
                id: 'sendgrid',
                name: 'SendGrid (Twilio)',
                purpose: 'Email delivery infrastructure',
                location: 'United States',
                dataCategories: ['Email addresses', 'Email content'],
                website: 'https://sendgrid.com',
                dpaUrl: 'https://www.twilio.com/legal/data-protection-addendum',
                addedAt: new Date('2023-01-01'),
            },
            {
                id: 'stripe',
                name: 'Stripe',
                purpose: 'Payment processing',
                location: 'United States',
                dataCategories: ['Billing information', 'Payment details'],
                website: 'https://stripe.com',
                dpaUrl: 'https://stripe.com/legal/dpa',
                addedAt: new Date('2023-01-01'),
            },
            {
                id: 'datadog',
                name: 'Datadog',
                purpose: 'Application monitoring and logging',
                location: 'United States',
                dataCategories: ['System logs', 'Performance metrics'],
                website: 'https://www.datadoghq.com',
                dpaUrl: 'https://www.datadoghq.com/legal/data-processing-addendum/',
                addedAt: new Date('2023-06-01'),
            },
            {
                id: 'zendesk',
                name: 'Zendesk',
                purpose: 'Customer support platform',
                location: 'United States',
                dataCategories: ['Support tickets', 'Contact information'],
                website: 'https://www.zendesk.com',
                dpaUrl: 'https://www.zendesk.com/company/customers-partners/data-processing-agreement/',
                addedAt: new Date('2023-03-01'),
            },
        ];

        for (const processor of processors) {
            this.subProcessors.set(processor.id, processor);
        }
    }

    /**
     * Registers data practices
     */
    private registerDataPractices(): void {
        const practices: DataPractice[] = [
            {
                id: 'collection-minimal',
                category: 'Data Collection',
                practice: 'Minimal Data Collection',
                description: 'We only collect data necessary to provide our services',
            },
            {
                id: 'collection-consent',
                category: 'Data Collection',
                practice: 'Consent-Based Collection',
                description: 'Personal data is collected only with explicit consent',
            },
            {
                id: 'storage-encrypted',
                category: 'Data Storage',
                practice: 'Encrypted Storage',
                description: 'All data is encrypted at rest using AES-256',
            },
            {
                id: 'storage-location',
                category: 'Data Storage',
                practice: 'Regional Data Storage',
                description: 'Data can be stored in customer-specified regions',
            },
            {
                id: 'retention-configurable',
                category: 'Data Retention',
                practice: 'Configurable Retention',
                description: 'Customers can configure data retention periods',
            },
            {
                id: 'retention-deletion',
                category: 'Data Retention',
                practice: 'Secure Deletion',
                description: 'Data is securely deleted after retention period',
            },
            {
                id: 'access-limited',
                category: 'Data Access',
                practice: 'Limited Access',
                description: 'Employee access to data is strictly limited and logged',
            },
            {
                id: 'access-audit',
                category: 'Data Access',
                practice: 'Access Auditing',
                description: 'All data access is logged and auditable',
            },
            {
                id: 'rights-export',
                category: 'Data Rights',
                practice: 'Data Export',
                description: 'Full data export available in standard formats',
            },
            {
                id: 'rights-deletion',
                category: 'Data Rights',
                practice: 'Right to Deletion',
                description: 'Data can be deleted upon request',
            },
        ];

        for (const practice of practices) {
            this.dataPractices.set(practice.id, practice);
        }
    }

    /**
     * Initializes FAQ
     */
    private initializeFAQ(): void {
        this.faq = [
            {
                category: 'Security',
                question: 'How is my data encrypted?',
                answer: 'All data is encrypted in transit using TLS 1.3 and at rest using AES-256-GCM. Encryption keys are managed using HSM-backed key management with automatic rotation.',
            },
            {
                category: 'Security',
                question: 'Do you perform penetration testing?',
                answer: 'Yes, we conduct annual penetration testing by independent third-party security firms. We also perform continuous vulnerability scanning and bug bounty programs.',
            },
            {
                category: 'Compliance',
                question: 'Are you GDPR compliant?',
                answer: 'Yes, we are fully GDPR compliant. We offer Data Processing Agreements (DPA), support data portability, and have appointed a Data Protection Officer.',
            },
            {
                category: 'Compliance',
                question: 'Can I get a copy of your SOC 2 report?',
                answer: 'SOC 2 Type II reports are available to customers and prospects under NDA. Please contact our sales team to request a copy.',
            },
            {
                category: 'Data',
                question: 'Where is my data stored?',
                answer: 'Data is stored in secure cloud infrastructure. Enterprise customers can choose their preferred data residency region (US, EU, or APAC).',
            },
            {
                category: 'Data',
                question: 'How long do you retain my data?',
                answer: 'Data retention is configurable by customers. After account deletion or retention period expiry, data is securely deleted within 30 days.',
            },
            {
                category: 'Data',
                question: 'Can I export my data?',
                answer: 'Yes, you can export all your data at any time in standard formats (JSON, CSV). Data export is available through the dashboard or API.',
            },
            {
                category: 'Access',
                question: 'Who has access to my data?',
                answer: 'Access to customer data is strictly limited to essential personnel with a legitimate business need. All access is logged and audited.',
            },
            {
                category: 'Access',
                question: 'Do you support SSO?',
                answer: 'Yes, we support SAML 2.0 and OIDC for enterprise SSO integration with identity providers like Okta, Azure AD, and Google Workspace.',
            },
            {
                category: 'Incident',
                question: 'What happens if there is a security incident?',
                answer: 'We have a documented incident response plan. In case of a data breach, affected customers are notified within 72 hours as required by GDPR.',
            },
        ];
    }

    /**
     * Gets full trust center data
     */
    getTrustCenterData(): TrustCenterData {
        const securityControlsByCategory = new Map<string, SecurityControl[]>();
        for (const control of this.securityControls.values()) {
            const existing = securityControlsByCategory.get(control.category) || [];
            existing.push(control);
            securityControlsByCategory.set(control.category, existing);
        }

        return {
            company: {
                name: this.config.companyName,
                legalEntity: this.config.legalEntity,
                supportEmail: this.config.supportEmail,
                dpoEmail: this.config.dpoEmail,
            },
            certifications: Array.from(this.certifications.values()),
            documents: Array.from(this.documents.values()),
            securityControls: Object.fromEntries(securityControlsByCategory),
            subProcessors: Array.from(this.subProcessors.values()),
            dataPractices: Array.from(this.dataPractices.values()),
            faq: this.faq,
            lastUpdated: new Date(),
        };
    }

    /**
     * Gets certifications
     */
    getCertifications(): TrustCenterCertification[] {
        return Array.from(this.certifications.values());
    }

    /**
     * Gets valid certifications only
     */
    getValidCertifications(): TrustCenterCertification[] {
        const now = new Date();
        return Array.from(this.certifications.values()).filter(
            (cert) =>
                cert.status === 'valid' &&
                (!cert.validFrom || cert.validFrom <= now) &&
                (!cert.validUntil || cert.validUntil > now)
        );
    }

    /**
     * Gets documents by type
     */
    getDocuments(type?: TrustCenterDocument['type']): TrustCenterDocument[] {
        let docs = Array.from(this.documents.values());
        if (type) {
            docs = docs.filter((d) => d.type === type);
        }
        return docs;
    }

    /**
     * Gets security controls
     */
    getSecurityControls(category?: string): SecurityControl[] {
        let controls = Array.from(this.securityControls.values());
        if (category) {
            controls = controls.filter((c) => c.category === category);
        }
        return controls;
    }

    /**
     * Gets security control categories
     */
    getSecurityControlCategories(): string[] {
        const categories = new Set<string>();
        for (const control of this.securityControls.values()) {
            categories.add(control.category);
        }
        return Array.from(categories);
    }

    /**
     * Gets sub-processors
     */
    getSubProcessors(): SubProcessor[] {
        return Array.from(this.subProcessors.values());
    }

    /**
     * Adds a sub-processor
     * FIX-500-156: Write-through to DB.
     */
    addSubProcessor(processor: Omit<SubProcessor, 'id' | 'addedAt'>): SubProcessor {
        const id = processor.name.toLowerCase().replace(/\s+/g, '-');
        const full: SubProcessor = {
            id,
            ...processor,
            addedAt: new Date(),
        };

        this.subProcessors.set(id, full);

        if (this.db) {
            this.db.query(
                `INSERT INTO trust_sub_processors (id, name, purpose, location, data_categories, website, dpa_url)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, purpose = EXCLUDED.purpose,
                   location = EXCLUDED.location, data_categories = EXCLUDED.data_categories,
                   website = EXCLUDED.website, dpa_url = EXCLUDED.dpa_url`,
                [id, processor.name, processor.purpose, processor.location, processor.dataCategories, processor.website, processor.dpaUrl]
            ).catch(() => { /* best-effort */ });
        }

        this.emit('subprocessor:added', full);

        // Update sub-processor list document
        const doc = this.documents.get('subprocessor-list');
        if (doc) {
            doc.lastUpdated = new Date();
        }

        return full;
    }

    /**
     * Removes a sub-processor
     * FIX-500-156: Write-through to DB.
     */
    removeSubProcessor(processorId: string): void {
        this.subProcessors.delete(processorId);
        if (this.db) {
            this.db.query('DELETE FROM trust_sub_processors WHERE id = $1', [processorId]).catch(() => { /* best-effort */ });
        }
        this.emit('subprocessor:removed', { processorId });
    }

    /**
     * Gets data practices
     */
    getDataPractices(category?: string): DataPractice[] {
        let practices = Array.from(this.dataPractices.values());
        if (category) {
            practices = practices.filter((p) => p.category === category);
        }
        return practices;
    }

    /**
     * Gets FAQ
     */
    getFAQ(category?: string): typeof this.faq {
        if (category) {
            return this.faq.filter((f) => f.category === category);
        }
        return this.faq;
    }

    /**
     * Gets FAQ categories
     */
    getFAQCategories(): string[] {
        const categories = new Set<string>();
        for (const item of this.faq) {
            categories.add(item.category);
        }
        return Array.from(categories);
    }

    /**
     * Adds certification
     * FIX-500-156: Write-through to DB.
     */
    addCertification(cert: TrustCenterCertification): void {
        this.certifications.set(cert.id, cert);
        if (this.db) {
            this.db.query(
                `INSERT INTO trust_certifications (id, name, description, issuer, valid_from, valid_until, status, document_url)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
                   issuer = EXCLUDED.issuer, valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                   status = EXCLUDED.status, document_url = EXCLUDED.document_url`,
                [cert.id, cert.name, cert.description, cert.issuer, cert.validFrom, cert.validUntil, cert.status, cert.documentUrl]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('certification:added', cert);
    }

    /**
     * Updates certification
     * FIX-500-156: Write-through to DB.
     */
    updateCertification(certId: string, updates: Partial<TrustCenterCertification>): void {
        const cert = this.certifications.get(certId);
        if (!cert) return;

        Object.assign(cert, updates);
        if (this.db) {
            this.db.query(
                `UPDATE trust_certifications SET name = $1, description = $2, issuer = $3, valid_from = $4,
                 valid_until = $5, status = $6, document_url = $7 WHERE id = $8`,
                [cert.name, cert.description, cert.issuer, cert.validFrom, cert.validUntil, cert.status, cert.documentUrl, certId]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('certification:updated', cert);
    }

    /**
     * Adds document
     * FIX-500-156: Write-through to DB.
     */
    addDocument(doc: TrustCenterDocument): void {
        this.documents.set(doc.id, doc);
        if (this.db) {
            this.db.query(
                `INSERT INTO trust_documents (id, name, description, type, url, last_updated, version)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
                   type = EXCLUDED.type, url = EXCLUDED.url, last_updated = EXCLUDED.last_updated, version = EXCLUDED.version`,
                [doc.id, doc.name, doc.description, doc.type, doc.url, doc.lastUpdated, doc.version]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('document:added', doc);
    }

    /**
     * Updates document
     * FIX-500-156: Write-through to DB.
     */
    updateDocument(docId: string, updates: Partial<TrustCenterDocument>): void {
        const doc = this.documents.get(docId);
        if (!doc) return;

        Object.assign(doc, updates);
        doc.lastUpdated = new Date();
        if (this.db) {
            this.db.query(
                `UPDATE trust_documents SET name = $1, description = $2, type = $3, url = $4,
                 last_updated = $5, version = $6 WHERE id = $7`,
                [doc.name, doc.description, doc.type, doc.url, doc.lastUpdated, doc.version, docId]
            ).catch(() => { /* best-effort */ });
        }
        this.emit('document:updated', doc);
    }

    /**
     * Generates compliance summary
     */
    generateComplianceSummary(): {
        certifications: number;
        securityControls: { implemented: number; partial: number; planned: number };
        documents: number;
        subProcessors: number;
        lastUpdated: Date;
    } {
        const controls = Array.from(this.securityControls.values());

        return {
            certifications: this.getValidCertifications().length,
            securityControls: {
                implemented: controls.filter((c) => c.status === 'implemented').length,
                partial: controls.filter((c) => c.status === 'partial').length,
                planned: controls.filter((c) => c.status === 'planned').length,
            },
            documents: this.documents.size,
            subProcessors: this.subProcessors.size,
            lastUpdated: new Date(),
        };
    }

    /**
     * Exports trust center data for reporting
     */
    exportData(): string {
        return JSON.stringify(this.getTrustCenterData(), null, 2);
    }
}
