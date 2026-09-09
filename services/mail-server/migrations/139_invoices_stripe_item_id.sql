-- 139: separate Stripe invoice-item ids from invoice ids (audit F34).
--
-- The overage collection ladder stored the id of the Stripe INVOICE ITEM
-- it created (`ii_...`) into invoices.stripe_invoice_id — a column the
-- invoice.paid webhook matches against real Stripe invoice ids (`in_...`).
-- The two namespaces must never share a column. Add a dedicated column,
-- backfill the corrupted rows (any `ii_%` value is an item id, never an
-- invoice id), and leave stripe_invoice_id to real invoices only.

ALTER TABLE invoices ADD COLUMN IF NOT EXISTS stripe_invoice_item_id VARCHAR(128);

UPDATE invoices
SET stripe_invoice_item_id = stripe_invoice_id,
    stripe_invoice_id = NULL,
    updated_at = NOW()
WHERE stripe_invoice_id LIKE 'ii_%'
  AND stripe_invoice_item_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_invoices_stripe_item
    ON invoices (stripe_invoice_item_id)
    WHERE stripe_invoice_item_id IS NOT NULL;
