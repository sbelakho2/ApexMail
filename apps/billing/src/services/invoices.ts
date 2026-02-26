/**
 * Invoice Generation Service
 * PDF invoices with VAT support and Estonian e-Invoice XML export
 */

import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';
import { randomBytes } from 'node:crypto';
import { COMPANY_INFO } from '../config.js';

// BUG-004 FIX: Helper for generating random hex strings
function generateRandomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex');
}

export interface InvoiceLineItem {
  description: string;
  quantity: number;
  unitPrice: number;     // In cents
  amount: number;        // In cents (quantity * unitPrice)
  vatRate: number;       // e.g., 22 for 22%
  vatAmount: number;     // In cents
}

export interface Invoice {
  id: string;
  tenantId: string;
  stripeInvoiceId: string | null;
  invoiceNumber: string;
  status: 'draft' | 'pending' | 'paid' | 'void' | 'uncollectible';
  currency: string;
  subtotal: number;      // In cents
  vatTotal: number;      // In cents
  total: number;         // In cents
  lineItems: InvoiceLineItem[];
  billingAddress: BillingAddress;
  issuedAt: Date;
  dueAt: Date;
  paidAt: Date | null;
  periodStart: Date;
  periodEnd: Date;
  purchaseOrderNumber: string | null;
  notes: string | null;
  pdfUrl: string | null;
  xmlUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingAddress {
  companyName: string;
  vatNumber: string | null;
  addressLine1: string;
  addressLine2: string | null;
  city: string;
  state: string | null;
  postalCode: string;
  country: string;
  email: string;
}

const ESTONIA_VAT_RATE = 22; // 22% VAT for Estonian companies
const EU_COUNTRIES = [
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
  'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
  'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
];
const EU_VAT_RATES: Record<string, number> = {
  AT: 20,
  BE: 21,
  BG: 20,
  HR: 25,
  CY: 19,
  CZ: 21,
  DK: 25,
  EE: 22,
  FI: 24,
  FR: 20,
  DE: 19,
  GR: 24,
  HU: 27,
  IE: 23,
  IT: 22,
  LV: 21,
  LT: 21,
  LU: 17,
  MT: 18,
  NL: 21,
  PL: 23,
  PT: 23,
  RO: 19,
  SK: 20,
  SI: 22,
  ES: 21,
  SE: 25,
};

/**
 * Invoice generation service
 */
export class InvoiceService {
  constructor(private readonly db: DatabasePool) {}

  /**
   * Generate invoice number with tenant isolation
   * BUG-004 FIX: Uses tenant ID prefix + random component instead of global sequence
   * Format: YYYY-XXXX-RRRRRR (year-tenantPrefix-random)
   */
  async generateInvoiceNumber(tenantId: string): Promise<Result<string, Error>> {
    const year = new Date().getUTCFullYear();
    // Use first 4 chars of tenant UUID for prefix (tenant-isolated)
    const tenantPrefix = tenantId.replace(/-/g, '').slice(0, 4).toUpperCase();
    // Use 6 random hex chars for uniqueness
    const randomPart = generateRandomHex(3).toUpperCase();
    return Result.ok(`${year}-${tenantPrefix}-${randomPart}`);
  }

  /**
   * Calculate VAT based on customer location
   */
  calculateVat(
    subtotal: number,
    customerCountry: string,
    customerVatNumber: string | null
  ): { vatRate: number; vatAmount: number } {
    const computeVatAmount = (amountCents: number, ratePercent: number): number =>
      Math.floor((amountCents * ratePercent + 50) / 100);

    // Estonia: Always charge VAT
    if (customerCountry === 'EE') {
      return {
        vatRate: ESTONIA_VAT_RATE,
        vatAmount: computeVatAmount(subtotal, ESTONIA_VAT_RATE),
      };
    }

    // EU B2B with valid VAT: Reverse charge (0% VAT)
    if (EU_COUNTRIES.includes(customerCountry) && customerVatNumber) {
      return { vatRate: 0, vatAmount: 0 };
    }

    // EU B2C: Charge destination VAT rate
    if (EU_COUNTRIES.includes(customerCountry)) {
      const rate = EU_VAT_RATES[customerCountry] ?? ESTONIA_VAT_RATE;
      return {
        vatRate: rate,
        vatAmount: computeVatAmount(subtotal, rate),
      };
    }

    // Non-EU: No VAT
    return { vatRate: 0, vatAmount: 0 };
  }

  /**
   * Create invoice from line items
   */
  async createInvoice(input: {
    tenantId: string;
    stripeInvoiceId?: string;
    lineItems: Array<{
      description: string;
      quantity: number;
      unitPrice: number;
    }>;
    periodStart: Date;
    periodEnd: Date;
    dueAt?: Date;
    purchaseOrderNumber?: string;
    notes?: string;
  }): Promise<Result<Invoice, Error>> {
    // Get tenant billing info
    const tenantResult = await this.db.query<{
      name: string;
      settings: string;
    }>(
      `SELECT name, settings FROM tenants WHERE id = $1`,
      [input.tenantId]
    );

    if (!tenantResult.ok) return Result.err(tenantResult.error);
    
    const tenant = tenantResult.value.rows[0];
    if (!tenant) return Result.err(new Error('Tenant not found'));

    // Get billing address
    const addressResult = await this.db.query<{
      company_name: string;
      vat_number: string | null;
      address_line1: string;
      address_line2: string | null;
      city: string;
      state: string | null;
      postal_code: string;
      country: string;
      email: string;
    }>(
      `SELECT company_name, vat_number, address_line1, address_line2,
              city, state, postal_code, country, email
       FROM billing_addresses WHERE tenant_id = $1`,
      [input.tenantId]
    );

    if (!addressResult.ok) return Result.err(addressResult.error);

    const addressRow = addressResult.value.rows[0];
    if (!addressRow) return Result.err(new Error('Billing address not found'));

    const billingAddress: BillingAddress = {
      companyName: addressRow.company_name,
      vatNumber: addressRow.vat_number,
      addressLine1: addressRow.address_line1,
      addressLine2: addressRow.address_line2,
      city: addressRow.city,
      state: addressRow.state,
      postalCode: addressRow.postal_code,
      country: addressRow.country,
      email: addressRow.email,
    };

    // Generate invoice number
    const numberResult = await this.generateInvoiceNumber();
    if (!numberResult.ok) return Result.err(numberResult.error);

    // Calculate VAT on subtotal to avoid per-line rounding drift, then allocate VAT across lines
    const baseLineItems = input.lineItems.map(item => ({
      description: item.description,
      quantity: item.quantity,
      unitPrice: item.unitPrice,
      amount: item.quantity * item.unitPrice,
    }));

    const subtotal = baseLineItems.reduce((sum, item) => sum + item.amount, 0);
    const { vatRate, vatAmount: vatTotal } = this.calculateVat(
      subtotal,
      billingAddress.country,
      billingAddress.vatNumber
    );

    let allocatedVat = 0;
    const lineItems: InvoiceLineItem[] = baseLineItems.map((item, index) => {
      let vatAmount = 0;
      if (vatTotal > 0 && subtotal > 0) {
        if (index === baseLineItems.length - 1) {
          vatAmount = vatTotal - allocatedVat;
        } else {
          vatAmount = Math.floor((vatTotal * item.amount) / subtotal);
          allocatedVat += vatAmount;
        }
      }

      return {
        description: item.description,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        amount: item.amount,
        vatRate,
        vatAmount,
      };
    });

    const total = subtotal + vatTotal;

    const now = new Date();
    const dueAt = input.dueAt ?? new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // Default: Net 30

    // Insert invoice
    const insertResult = await this.db.query<{
      id: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO invoices (
        id, tenant_id, stripe_invoice_id, invoice_number, status, currency,
        subtotal, vat_total, total, line_items, billing_address,
        issued_at, due_at, period_start, period_end,
        purchase_order_number, notes, created_at, updated_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, $3, 'draft', 'EUR', $4, $5, $6, $7, $8,
        $9, $10, $11, $12, $13, $14, NOW(), NOW()
      )
      RETURNING id, created_at, updated_at`,
      [
        input.tenantId,
        input.stripeInvoiceId ?? null,
        numberResult.value,
        subtotal,
        vatTotal,
        total,
        JSON.stringify(lineItems),
        JSON.stringify(billingAddress),
        now,
        dueAt,
        input.periodStart,
        input.periodEnd,
        input.purchaseOrderNumber ?? null,
        input.notes ?? null,
      ]
    );

    if (!insertResult.ok) return Result.err(insertResult.error);

    const row = insertResult.value.rows[0];
    if (!row) return Result.err(new Error('Failed to create invoice'));

    return Result.ok({
      id: row.id,
      tenantId: input.tenantId,
      stripeInvoiceId: input.stripeInvoiceId ?? null,
      invoiceNumber: numberResult.value,
      status: 'draft',
      currency: 'EUR',
      subtotal,
      vatTotal,
      total,
      lineItems,
      billingAddress,
      issuedAt: now,
      dueAt,
      paidAt: null,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
      purchaseOrderNumber: input.purchaseOrderNumber ?? null,
      notes: input.notes ?? null,
      pdfUrl: null,
      xmlUrl: null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }

  /**
   * Generate PDF content for invoice
   */
  generateInvoiceHtml(invoice: Invoice): string {
    const esc = (value: unknown): string => {
      const input = value == null ? '' : String(value);
      return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    };

    const formatCurrency = (cents: number): string => 
      `€${(cents / 100).toFixed(2)}`;

    const formatDate = (date: Date): string => {
      const parts = date.toISOString().split('T');
      return parts[0] ?? date.toISOString();
    };

    const paymentTermsDays = Math.max(
      0,
      Math.ceil((invoice.dueAt.getTime() - invoice.issuedAt.getTime()) / (1000 * 60 * 60 * 24))
    );
    const vatRates = [...new Set(invoice.lineItems.map(item => item.vatRate))].sort((a, b) => a - b);
    const vatLabel = vatRates.length <= 1
      ? `VAT (${vatRates[0] ?? 0}%)`
      : `VAT (Mixed: ${vatRates.map(rate => `${rate}%`).join(', ')})`;

    // This generates a simple HTML template that can be converted to PDF
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Invoice ${invoice.invoiceNumber}</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 12px; color: #333; margin: 40px; }
    .header { display: flex; justify-content: space-between; margin-bottom: 40px; }
    .logo { font-size: 24px; font-weight: bold; color: #1a1a1a; }
    .invoice-info { text-align: right; }
    .invoice-number { font-size: 18px; font-weight: bold; }
    .addresses { display: flex; justify-content: space-between; margin-bottom: 40px; }
    .address { width: 45%; }
    .address h3 { font-size: 10px; text-transform: uppercase; color: #666; margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    th { background: #f5f5f5; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #ddd; }
    td { padding: 12px; border-bottom: 1px solid #eee; }
    .amount { text-align: right; }
    .totals { margin-left: auto; width: 300px; }
    .totals table { margin-bottom: 0; }
    .totals td { border: none; padding: 8px 12px; }
    .total-row { font-weight: bold; font-size: 14px; background: #f5f5f5; }
    .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #eee; font-size: 10px; color: #666; }
    .vat-note { font-style: italic; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">ApexMail</div>
    <div class="invoice-info">
      <div class="invoice-number">Invoice ${invoice.invoiceNumber}</div>
      <div>Issued: ${formatDate(invoice.issuedAt)}</div>
      <div>Due: ${formatDate(invoice.dueAt)}</div>
      ${invoice.purchaseOrderNumber ? `<div>PO: ${esc(invoice.purchaseOrderNumber)}</div>` : ''}
    </div>
  </div>

  <div class="addresses">
    <div class="address">
      <h3>From</h3>
      <strong>Bel Consulting OÜ</strong><br>
      (trading as ApexMail)<br>
      Sakala 7-2<br>
      10141 Tallinn<br>
      Estonia<br>
      Reg. 16192499<br>
      VAT: EE102951727<br>
      billing@apexmail.ee
    </div>
    <div class="address">
      <h3>Bill To</h3>
      <strong>${esc(invoice.billingAddress.companyName)}</strong><br>
      ${esc(invoice.billingAddress.addressLine1)}<br>
      ${invoice.billingAddress.addressLine2 ? `${esc(invoice.billingAddress.addressLine2)}<br>` : ''}
      ${esc(invoice.billingAddress.postalCode)} ${esc(invoice.billingAddress.city)}<br>
      ${invoice.billingAddress.state ? `${esc(invoice.billingAddress.state)}, ` : ''}${esc(invoice.billingAddress.country)}<br>
      ${invoice.billingAddress.vatNumber ? `VAT: ${esc(invoice.billingAddress.vatNumber)}<br>` : ''}
      ${esc(invoice.billingAddress.email)}
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Description</th>
        <th>Qty</th>
        <th class="amount">Unit Price</th>
        <th class="amount">VAT</th>
        <th class="amount">Amount</th>
      </tr>
    </thead>
    <tbody>
      ${invoice.lineItems.map(item => `
        <tr>
          <td>${esc(item.description)}</td>
          <td>${item.quantity}</td>
          <td class="amount">${formatCurrency(item.unitPrice)}</td>
          <td class="amount">${item.vatRate}%</td>
          <td class="amount">${formatCurrency(item.amount)}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div class="totals">
    <table>
      <tr>
        <td>Subtotal</td>
        <td class="amount">${formatCurrency(invoice.subtotal)}</td>
      </tr>
      <tr>
        <td>${vatLabel}</td>
        <td class="amount">${formatCurrency(invoice.vatTotal)}</td>
      </tr>
      <tr class="total-row">
        <td>Total</td>
        <td class="amount">${formatCurrency(invoice.total)}</td>
      </tr>
    </table>
  </div>

  ${invoice.billingAddress.vatNumber && invoice.billingAddress.country !== 'EE' ? `
    <div class="vat-note">
      Reverse charge: VAT to be paid by the recipient per Article 196, EU VAT Directive 2006/112/EC
    </div>
  ` : ''}

  ${invoice.notes ? `<div style="margin-top: 30px;"><strong>Notes:</strong> ${esc(invoice.notes)}</div>` : ''}

  <div class="footer">
    <p>Payment terms: Net ${paymentTermsDays} days. Please include invoice number in payment reference.</p>
    <p>Bel Consulting OÜ (trading as ApexMail) | Reg. 16192499 | VAT: EE102951727 | IBAN: EE38 2200 2210 1234 5678 | BIC: HABAEE2X</p>
    <p>Sakala 7-2, 10141 Tallinn, Estonia</p>
    <p>Period: ${formatDate(invoice.periodStart)} to ${formatDate(invoice.periodEnd)}</p>
  </div>
</body>
</html>`;
  }

  /**
   * Generate Estonian e-Invoice XML (Estonian e-Invoice standard)
   */
  generateEInvoiceXml(invoice: Invoice): string {
    const formatDate = (date: Date): string => {
      const parts = date.toISOString().split('T');
      return parts[0] ?? date.toISOString();
    };

    return `<?xml version="1.0" encoding="UTF-8"?>
<E_Invoice xmlns="http://www.pangaliit.ee/e-arve/e-arve">
  <Header>
    <Date>${formatDate(invoice.issuedAt)}</Date>
    <FileId>${invoice.id}</FileId>
    <Version>1.2</Version>
  </Header>
  <Invoice>
    <InvoiceParties>
      <SellerParty>
        <Name>Bel Consulting OÜ</Name>
        <RegNumber>16192499</RegNumber>
        <VATRegNumber>EE102951727</VATRegNumber>
        <ContactData>
          <LegalAddress>
            <PostalAddress1>Sakala 7-2</PostalAddress1>
            <City>Tallinn</City>
            <PostalCode>10141</PostalCode>
            <Country>EE</Country>
          </LegalAddress>
            <PhoneNumber>${this.escapeXml(process.env['BILLING_COMPANY_PHONE'] ?? '+37200000000')}</PhoneNumber>
          <E-mailAddress>billing@apexmail.ee</E-mailAddress>
        </ContactData>
        <AccountInfo>
            <AccountNumber>${this.escapeXml(COMPANY_INFO.bank.iban)}</AccountNumber>
          <BIC>HABAEE2X</BIC>
          <BankName>Swedbank AS</BankName>
        </AccountInfo>
      </SellerParty>
      <BuyerParty>
        <Name>${this.escapeXml(invoice.billingAddress.companyName)}</Name>
        ${invoice.billingAddress.vatNumber ? `<VATRegNumber>${invoice.billingAddress.vatNumber}</VATRegNumber>` : ''}
        <ContactData>
          <LegalAddress>
            <PostalAddress1>${this.escapeXml(invoice.billingAddress.addressLine1)}</PostalAddress1>
            ${invoice.billingAddress.addressLine2 ? `<PostalAddress2>${this.escapeXml(invoice.billingAddress.addressLine2)}</PostalAddress2>` : ''}
            <City>${this.escapeXml(invoice.billingAddress.city)}</City>
            <PostalCode>${invoice.billingAddress.postalCode}</PostalCode>
            <Country>${invoice.billingAddress.country}</Country>
          </LegalAddress>
          <E-mailAddress>${invoice.billingAddress.email}</E-mailAddress>
        </ContactData>
      </BuyerParty>
    </InvoiceParties>
    <InvoiceInformation>
      <Type Type="DEB"/>
      <InvoiceNumber>${invoice.invoiceNumber}</InvoiceNumber>
      <InvoiceDate>${formatDate(invoice.issuedAt)}</InvoiceDate>
      <DueDate>${formatDate(invoice.dueAt)}</DueDate>
      <InvoiceContentCode>SERVICES</InvoiceContentCode>
      <Currency>EUR</Currency>
      ${invoice.purchaseOrderNumber ? `<ReferenceNumber>${invoice.purchaseOrderNumber}</ReferenceNumber>` : ''}
    </InvoiceInformation>
    <InvoiceSumGroup>
      <InvoiceSum>${(invoice.total / 100).toFixed(2)}</InvoiceSum>
      <PaidAmount>0.00</PaidAmount>
      <PayableAmount>${(invoice.total / 100).toFixed(2)}</PayableAmount>
      <Currency>EUR</Currency>
    </InvoiceSumGroup>
    <InvoiceItem>
${invoice.lineItems.map((item, index) => `      <ItemEntry>
        <RowNo>${index + 1}</RowNo>
        <Description>${this.escapeXml(item.description)}</Description>
        <ItemDetailInfo>
          <ItemUnit>PCS</ItemUnit>
          <ItemAmount>${item.quantity}</ItemAmount>
          <ItemPrice>${(item.unitPrice / 100).toFixed(2)}</ItemPrice>
        </ItemDetailInfo>
        <ItemSum>
          <Amount>${(item.amount / 100).toFixed(2)}</Amount>
          <VAT>
            <VATRate>${item.vatRate}</VATRate>
            <VATSum>${(item.vatAmount / 100).toFixed(2)}</VATSum>
            <SumBeforeVAT>${(item.amount / 100).toFixed(2)}</SumBeforeVAT>
            <SumAfterVAT>${((item.amount + item.vatAmount) / 100).toFixed(2)}</SumAfterVAT>
            <Currency>EUR</Currency>
          </VAT>
          <TotalSum>${((item.amount + item.vatAmount) / 100).toFixed(2)}</TotalSum>
        </ItemSum>
      </ItemEntry>`).join('\n')}
    </InvoiceItem>
    <PaymentInfo>
      <Currency>EUR</Currency>
      <PaymentDescription>Invoice ${invoice.invoiceNumber}</PaymentDescription>
      <Payable>YES</Payable>
      <DueDate>${formatDate(invoice.dueAt)}</DueDate>
      <PaymentId>${invoice.invoiceNumber}</PaymentId>
      <PaymentTotalSum>${(invoice.total / 100).toFixed(2)}</PaymentTotalSum>
      <PayerName>${this.escapeXml(invoice.billingAddress.companyName)}</PayerName>
      <PayToAccount>${this.escapeXml(COMPANY_INFO.bank.iban)}</PayToAccount>
      <PayToBIC>HABAEE2X</PayToBIC>
      <PayToName>Bel Consulting OÜ</PayToName>
    </PaymentInfo>
  </Invoice>
</E_Invoice>`;
  }

  /**
   * Mark invoice as paid
   */
  async markAsPaid(invoiceId: string, paidAt?: Date): Promise<Result<void, Error>> {
    const result = await this.db.query(
      `UPDATE invoices 
       SET status = 'paid', paid_at = $2, updated_at = NOW()
       WHERE id = $1`,
      [invoiceId, paidAt ?? new Date()]
    );

    if (!result.ok) return Result.err(result.error);
    return Result.ok(undefined);
  }

  /**
   * Get invoice by ID
   */
  async getInvoice(invoiceId: string): Promise<Result<Invoice | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      stripe_invoice_id: string | null;
      invoice_number: string;
      status: Invoice['status'];
      currency: string;
      subtotal: number;
      vat_total: number;
      total: number;
      line_items: string;
      billing_address: string;
      issued_at: Date;
      due_at: Date;
      paid_at: Date | null;
      period_start: Date;
      period_end: Date;
      purchase_order_number: string | null;
      notes: string | null;
      pdf_url: string | null;
      xml_url: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, tenant_id, stripe_invoice_id, invoice_number, status, currency,
              subtotal, vat_total, total, line_items, billing_address,
              issued_at, due_at, paid_at, period_start, period_end,
              purchase_order_number, notes, pdf_url, xml_url, created_at, updated_at
       FROM invoices WHERE id = $1`,
      [invoiceId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    // Safe JSON parsing to prevent crashes from corrupted data
    let lineItems: InvoiceLineItem[] = [];
    let billingAddress: BillingAddress = { 
      companyName: '', 
      vatNumber: null, 
      addressLine1: '', 
      addressLine2: null, 
      city: '', 
      state: null, 
      postalCode: '', 
      country: '', 
      email: '' 
    };
    
    try {
      lineItems = JSON.parse(row.line_items || '[]');
    } catch {
      console.warn(`[Invoices] Failed to parse line_items for invoice ${row.id}`);
    }
    
    try {
      billingAddress = JSON.parse(row.billing_address || '{}');
    } catch {
      console.warn(`[Invoices] Failed to parse billing_address for invoice ${row.id}`);
    }

    return Result.ok({
      id: row.id,
      tenantId: row.tenant_id,
      stripeInvoiceId: row.stripe_invoice_id,
      invoiceNumber: row.invoice_number,
      status: row.status,
      currency: row.currency,
      subtotal: row.subtotal,
      vatTotal: row.vat_total,
      total: row.total,
      lineItems,
      billingAddress,
      issuedAt: row.issued_at,
      dueAt: row.due_at,
      paidAt: row.paid_at,
      periodStart: row.period_start,
      periodEnd: row.period_end,
      purchaseOrderNumber: row.purchase_order_number,
      notes: row.notes,
      pdfUrl: row.pdf_url,
      xmlUrl: row.xml_url,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }

  /**
   * List invoices for tenant
   */
  async listInvoices(
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<Result<{ invoices: Invoice[]; totalCount: number }, Error>> {
    const limit = options?.limit ?? 50;
    const offset = options?.offset ?? 0;

    const totalCountResult = await this.db.query<{ total_count: string }>(
      `SELECT COUNT(*)::text AS total_count FROM invoices WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!totalCountResult.ok) return Result.err(totalCountResult.error);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      stripe_invoice_id: string | null;
      invoice_number: string;
      status: Invoice['status'];
      currency: string;
      subtotal: number;
      vat_total: number;
      total: number;
      line_items: string;
      billing_address: string;
      issued_at: Date;
      due_at: Date;
      paid_at: Date | null;
      period_start: Date;
      period_end: Date;
      purchase_order_number: string | null;
      notes: string | null;
      pdf_url: string | null;
      xml_url: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, tenant_id, stripe_invoice_id, invoice_number, status, currency,
              subtotal, vat_total, total, line_items, billing_address,
              issued_at, due_at, paid_at, period_start, period_end,
              purchase_order_number, notes, pdf_url, xml_url, created_at, updated_at
       FROM invoices 
       WHERE tenant_id = $1
       ORDER BY issued_at DESC
       LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset]
    );

    if (!result.ok) return Result.err(result.error);

    const invoices = result.value.rows.map(row => {
      // Safe JSON parsing to prevent crashes
      let lineItems: InvoiceLineItem[] = [];
      let billingAddress: BillingAddress = { 
        companyName: '', 
        vatNumber: null, 
        addressLine1: '', 
        addressLine2: null, 
        city: '', 
        state: null, 
        postalCode: '', 
        country: '', 
        email: '' 
      };
      
      try { lineItems = JSON.parse(row.line_items || '[]'); } catch { /* use default */ }
      try { billingAddress = JSON.parse(row.billing_address || '{}'); } catch { /* use default */ }
      
      return {
        id: row.id,
        tenantId: row.tenant_id,
        stripeInvoiceId: row.stripe_invoice_id,
        invoiceNumber: row.invoice_number,
        status: row.status,
        currency: row.currency,
        subtotal: row.subtotal,
        vatTotal: row.vat_total,
        total: row.total,
        lineItems,
        billingAddress,
        issuedAt: row.issued_at,
        dueAt: row.due_at,
        paidAt: row.paid_at,
        periodStart: row.period_start,
        periodEnd: row.period_end,
        purchaseOrderNumber: row.purchase_order_number,
        notes: row.notes,
        pdfUrl: row.pdf_url,
        xmlUrl: row.xml_url,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      };
    });

    return Result.ok({
      invoices,
      totalCount: parseInt(totalCountResult.value.rows[0]?.total_count ?? '0', 10),
    });
  }

  private escapeXml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }
}
