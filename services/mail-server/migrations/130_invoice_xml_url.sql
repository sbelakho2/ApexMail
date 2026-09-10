-- Migration 130: invoices.xml_url (audit F05).
--
-- The canonical invoice list/detail query in api-server billing.rs selects
-- `xml_url`, but no migration ever created the column — every list/detail
-- call failed with 42703 and fell into the legacy fallback, which itself
-- selected columns (`amount_cents`, `due_date`) that the canonical chain no
-- longer guarantees. Add the nullable column so the canonical path works;
-- it stays NULL unless an XML export artifact is actually persisted (the
-- e-invoice XML route renders on demand and stores no artifact today).

ALTER TABLE invoices ADD COLUMN IF NOT EXISTS xml_url TEXT;
