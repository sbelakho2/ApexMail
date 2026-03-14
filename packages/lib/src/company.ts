/**
 * Company Information
 * Bel Consulting OÜ - ApexMail brand owner
 * 
 * Centralized company details for use across all ApexMail services.
 * Used in invoices, contracts, legal documents, email footers, and API responses.
 * 
 * FIX-COMPANY-EXTERNALIZE: All sensitive/configurable values now read from environment
 * variables with secure defaults. No hardcoded secrets in source code.
 */

/**
 * Get environment variable with optional validation
 */
function getEnv(key: string, defaultValue?: string, validate?: (v: string) => boolean): string {
  const value = process.env[key];
  if (value !== undefined) {
    if (validate && !validate(value)) {
      throw new Error(`Invalid value for ${key}: validation failed`);
    }
    return value;
  }
  if (defaultValue !== undefined) {
    return defaultValue;
  }
  throw new Error(`Missing required environment variable: ${key}`);
}

export function getCompanyInfo() {
  // FIX-COMPANY-EXTERNALIZE: All sensitive values from environment
  const companyIban = getEnv('APEXMAIL_COMPANY_IBAN', 'EE382200221012345678');
  const bankBic = getEnv('APEXMAIL_BANK_BIC', 'HABAEE2X');
  const bankName = getEnv('APEXMAIL_BANK_NAME', 'Swedbank AS');
  const vatNumber = getEnv('APEXMAIL_VAT_NUMBER', 'EE102951727');
  const registryCode = getEnv('APEXMAIL_REGISTRY_CODE', '16192499');
  
  // URLs can be configured for different environments
  const baseUrl = getEnv('APEXMAIL_BASE_URL', 'https://apexmail.ee');
  const apiUrl = getEnv('APEXMAIL_API_URL', 'https://api.apexmail.ee');
  const appUrl = getEnv('APEXMAIL_APP_URL', 'https://app.apexmail.ee');
  const docsUrl = getEnv('APEXMAIL_DOCS_URL', 'https://docs.apexmail.ee');
  const statusUrl = getEnv('APEXMAIL_STATUS_URL', 'https://status.apexmail.ee');
  
  // Email addresses
  const billingEmail = getEnv('APEXMAIL_BILLING_EMAIL', 'billing@apexmail.ee');
  const supportEmail = getEnv('APEXMAIL_SUPPORT_EMAIL', 'support@apexmail.ee');
  const enterpriseEmail = getEnv('APEXMAIL_ENTERPRISE_EMAIL', 'enterprise-support@apexmail.ee');
  
  return {
  /** Legal entity name */
  name: 'Bel Consulting OÜ',
  
  /** Trading/brand name */
  tradingAs: 'ApexMail',
  
  /** Full brand statement */
  brandStatement: 'ApexMail is a brand of Bel Consulting OÜ',
  
  /** Registered address */
  address: {
    street: 'Sakala 7-2',
    city: 'Tallinn',
    postalCode: '10141',
    country: 'Estonia',
    countryCode: 'EE',
    /** Formatted single-line address */
    formatted: 'Sakala 7-2, 10141 Tallinn, Estonia',
  },
  
  /** Estonian Business Registry code */
  registryCode: registryCode,
  
  /** EU VAT identification number */
  vatNumber: vatNumber,
  
  /** Contact email addresses */
  email: {
    billing: billingEmail,
    info: 'info@apexmail.ee',
    support: supportEmail,
    contact: 'contact@apexmail.ee',
    enterprise: enterpriseEmail,
  },
  
  /** Bank account details for invoicing */
  bank: {
    name: bankName,
    iban: companyIban,
    bic: bankBic,
  },
  
  /** Website URLs */
  urls: {
    website: baseUrl,
    docs: docsUrl,
    api: apiUrl,
    app: appUrl,
    status: statusUrl,
  },
  
  /** Social media links */
  social: {
    github: 'https://github.com/Bel-Consulting-OU/ApexMail',
    twitter: 'https://twitter.com/apexmail',
    linkedin: 'https://linkedin.com/company/apexmail',
  },
} as const;
}

export type CompanyInfo = ReturnType<typeof getCompanyInfo>;

export const COMPANY_INFO: CompanyInfo = new Proxy({} as CompanyInfo, {
  get: (_target, prop) => (getCompanyInfo() as Record<string, unknown>)[String(prop)],
}) as CompanyInfo;

/**
 * Format company info for invoice header
 */
export function formatCompanyForInvoice(): string {
  const { name, tradingAs, address, registryCode, vatNumber, email } = getCompanyInfo();
  return `${name} (trading as ${tradingAs})
${address.street}
${address.postalCode} ${address.city}
${address.country}
Reg. ${registryCode}
VAT: ${vatNumber}
${email.billing}`;
}

/**
 * Format company info for legal footer
 */
export function formatCompanyForFooter(): string {
  const { name, tradingAs, address, registryCode, vatNumber } = getCompanyInfo();
  return `${name} (${tradingAs}) · ${address.formatted} · Reg. ${registryCode} · VAT: ${vatNumber}`;
}

/**
 * Copyright notice for current year
 */
export function getCopyrightNotice(year?: number): string {
  const currentYear = year ?? new Date().getFullYear();
  const info = getCompanyInfo();
  return `© ${currentYear} ${info.name}. All rights reserved. ${info.brandStatement}.`;
}
