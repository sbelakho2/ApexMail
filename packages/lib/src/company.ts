/**
 * Company Information
 * Bel Consulting OÜ - ApexMail brand owner
 * 
 * Centralized company details for use across all ApexMail services.
 * Used in invoices, contracts, legal documents, email footers, and API responses.
 */

export const COMPANY_INFO = {
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
  registryCode: '16192499',
  
  /** EU VAT identification number */
  vatNumber: 'EE102951727',
  
  /** Contact email addresses */
  email: {
    billing: 'billing@apexmail.ee',
    info: 'info@apexmail.ee',
    support: 'support@apexmail.ee',
    contact: 'contact@apexmail.ee',
    enterprise: 'enterprise-support@apexmail.ee',
  },
  
  /** Bank account details for invoicing */
  bank: {
    name: 'Swedbank AS',
    iban: 'EE382200221012345678',
    bic: 'HABAEE2X',
  },
  
  /** Website URLs */
  urls: {
    website: 'https://apexmail.ee',
    docs: 'https://docs.apexmail.ee',
    api: 'https://api.apexmail.ee',
    app: 'https://app.apexmail.ee',
    status: 'https://status.apexmail.ee',
  },
  
  /** Social media links */
  social: {
    github: 'https://github.com/Bel-Consulting-OU/ApexMail',
    twitter: 'https://twitter.com/apexmail',
    linkedin: 'https://linkedin.com/company/apexmail',
  },
} as const;

/** Type for company information */
export type CompanyInfo = typeof COMPANY_INFO;

/**
 * Format company info for invoice header
 */
export function formatCompanyForInvoice(): string {
  const { name, tradingAs, address, registryCode, vatNumber, email } = COMPANY_INFO;
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
  const { name, tradingAs, address, registryCode, vatNumber } = COMPANY_INFO;
  return `${name} (${tradingAs}) · ${address.formatted} · Reg. ${registryCode} · VAT: ${vatNumber}`;
}

/**
 * Copyright notice for current year
 */
export function getCopyrightNotice(year?: number): string {
  const currentYear = year ?? new Date().getFullYear();
  return `© ${currentYear} ${COMPANY_INFO.name}. All rights reserved. ${COMPANY_INFO.brandStatement}.`;
}
