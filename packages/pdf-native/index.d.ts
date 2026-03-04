/**
 * Result of rendering a PDF from a Typst template.
 */
export interface PdfResult {
  /** Raw PDF bytes */
  pdf: Buffer;
  /** Size in bytes */
  size: number;
  /** Template name that was rendered */
  template: string;
}

/**
 * Render a PDF from a Typst template name and JSON data string.
 * Runs the compilation off the main thread (libuv threadpool).
 *
 * @param template - Template name: "invoice" | "dpa" | "compliance_report" | "analytics_export" | "qbr"
 * @param data - JSON-serialised data string for the template's variables
 * @returns Promise resolving to a PdfResult with the raw PDF bytes
 *
 * @example
 * ```ts
 * import { renderPdf } from '@apexmail/pdf-native';
 *
 * const result = await renderPdf('invoice', JSON.stringify({
 *   invoice_number: 'INV-2024-001',
 *   currency: 'EUR',
 *   subtotal: 9900,
 *   vat_total: 2178,
 *   total: 12078,
 *   line_items: [{ description: 'Pro Plan', quantity: 1, unit_price: 9900, total: 9900 }],
 * }));
 * fs.writeFileSync('invoice.pdf', result.pdf);
 * ```
 */
export function renderPdf(template: string, data: string): Promise<PdfResult>;

/**
 * Synchronous PDF render — blocks the event loop.
 * Prefer `renderPdf()` (async) unless you need synchronous behaviour.
 *
 * @param template - Template name
 * @param data - JSON data string
 */
export function renderPdfSync(template: string, data: string): PdfResult;

/**
 * List available template names compiled into the binary.
 * @returns Array of template name strings
 */
export function listTemplates(): string[];
