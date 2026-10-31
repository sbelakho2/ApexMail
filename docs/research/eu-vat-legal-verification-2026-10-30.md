# EU VAT legal verification — triple-sourced against the primary law (30 Oct 2026)

This directory now carries the legal verification of the VAT treatment, done as
the owner demanded: re-confirmed from the laws, three times, from three angles,
by three independent research passes that each cite the primary texts and
cross-check every proposition against two further source classes.

- [`eu-vat-law-place-of-supply.md`](eu-vat-law-place-of-supply.md) — ANGLE 1:
  VAT Directive 2006/112/EC Arts. 14a/28/44/45/58/59c/196/262-271 and the OSS
  Union scheme (369a-369k), ViDA (Directive (EU) 2025/516) effective dates,
  Estonia's KMS mapping, CJEU duty-of-care corrections.
- [`eu-vat-law-evidence-and-invoicing.md`](eu-vat-law-evidence-and-invoicing.md)
  — ANGLE 2: Reg (EU) 282/2011 Art. 18 (verbatim) and Art. 25, VIES/Reg
  904/2010 Art. 31, the no-grace-period finding, invoice content Arts.
  219a-240/226 (incl. 226(7), 226(8), 226(11a)), Estonia KMS Section 37, ESL/VD.
- [`eu-vat-law-price-display-and-rates.md`](eu-vat-law-price-display-and-rates.md)
  — ANGLE 3: Price Indication Directive 98/6/EC as amended by (EU) 2019/2161,
  CRD 2011/83/EU Art. 6(1)(e)/8(2), UCPD, the 27-state dated standard-rate
  table (EC TEDB + PwC + Tax Foundation, national instruments for every
  2024-2026 change), and the consumer-display verdict.

The DEEP RESEARCH follow-up (2026-10-31, the five accountant-open items
closed from the laws):

- [`eu-vat-law-tax-point-and-identity.md`](eu-vat-law-tax-point-and-identity.md)
  — the renewal tax point (Art 65 payment receipt, else the Art 64(1)
  period completion; the invoice date is never the tax point) and the
  VIES name/address association check (Reg 282/2011 Art 18(1)(a) +
  Reg 904/2010 Art 31(2)): a returned-name mismatch IS "information to the
  contrary" and defeats the presumption.
- [`eu-vat-law-earve-and-fixed-establishment.md`](eu-vat-law-earve-and-fixed-establishment.md)
  — the official e-arve 1.2 XSD (ITL package; snippets xmllint-validated)
  and the fixed-establishment rules (Reg 282/2011 Art 11(1), Dong Yang,
  Berlin Chemie, the DE-HQ/EE-FE risk scenario worked explicitly).
- [`eu-vat-law-evidence-freshness.md`](eu-vat-law-evidence-freshness.md)
  — the freshness question exhausted: NO rule exists anywhere in EU law or
  guidance (VAT Committee 609/947 good-faith guidelines; VIES FAQ Q6/Q20;
  the German two-month case law — BFH XI R 38/18); the implemented policy is
  re-validate at every tax point with a DERIVED 60-day outage cap.

## What the verification changed in the code

Rates (angle 3): every CURRENT standard rate was numerically correct; the
dated table gained the verified history — Czechia 21 % since 2013-01-01
(Act 500/2012; the 2024 consolidation cut only the reduced rate), Germany
16 % for H2 2020, Ireland 21 % for 2020-09-01..2021-02-28, Luxembourg 16 %
for calendar 2023 — with boundary tests.

Evidence (angle 2): the evidence model now carries the Art. 18(1)(a) VIES
name/address confirmation and the consultation provenance the table already
stored; the invoice loader takes the last-known-VALID determination instead of
letting a later outage row shadow it; the statutory reverse-charge reference is
gated on the evidence row (never a structural VAT-number check) and EU scope.

Invoices (angle 2): the PDF now carries the per-rate taxable amount and VAT
(Art. 226(8)), the deemed supply date for the continuous period (Art. 64(2) /
226(7)) and the evidence-backed Art. 226(11a) reference.

Pricing display (angle 3): the consumer note no longer claims the net price
table is VAT-inclusive — the corrected four-language sentence states that the
table is business net pricing and consumers see the VAT-inclusive total before
paying.

Location evidence (angle 1): checkout records the place-of-supply evidence rows
(declaration + billing address), adjudicates them against Reg 282/2011
Art. 24b(d) (two non-contradictory items; one item at or below EUR 100,000),
and warns when the presumption is not established. The library also models the
Art. 59c EUR 10,000 threat and the TBE-vs-general service class (B2C general
services are taxed at the supplier's establishment, not destination).

## The fixed-establishment policy (VATDEEP-B, 2026-10-31)

The customer-declaration policy, as implemented (migration 294):

> We treat the supply as made to the customer's business establishment
> unless the customer declares a fixed establishment. A business that
> declares a fixed establishment is invoiced THERE: an Estonian
> establishment makes the supply domestic and the invoice carries 24 %
> Estonian VAT (the supplier is established where the tax is due, so the
> reverse-charge rule does not apply); an establishment in another member
> state is reverse-charged only against a VERIFIED VAT number of that same
> state — an unmatched or missing number fails closed to destination VAT.

Supporting rules: the declaration is one written checkout question
(`fixed_establishment_country`), stored with a timestamp and the terms
version on the billing record (Art. 23(2) due diligence), and kept as its
own `customer_location_evidence` row. The supplier does not audit the
customer's subsidiaries (Dong Yang) — red flags (billing/VAT country
mismatch, third-country payer) raise a review question, never an automatic
reclassification (Reg 282/2011 Art. 22; VEG 108). The one direction that
costs the supplier real money — a foreign-HQ customer receiving the service
at its Estonian establishment — is prevented by the EE branch.

## The freshness policy (VATDEEP-C, 2026-10-31)

No freshness rule exists anywhere in EU law or guidance — verified across the
Reg 282/2011 Art 18 recitals, Reg 904/2010 Arts 17/31, the full VAT Committee
guideline compilation and the Commission's VIES FAQ (Q6: a confirmation is
valid "only for the current day"; no question on re-check frequency exists).
The law's actual demand (VAT Committee 609 guidelines 043-045; 947 guideline
058, raised by Estonia): collect evidence and perform appropriate checks;
where evidence cannot be had, the supplier must charge the tax.

Implemented policy (a state machine, not a wish):

- VALID state = a VIES-confirmed number whose returned NAME matches the
  declared identity (Art 18(1)(a) association check — a mismatch is
  "information to the contrary" and fails closed to VAT until reconciled)
  and no other contrary information.
- Re-validate at EVERY tax point (the chargeable-event date).
- During a documented VIES outage, the last-known-VALID answer is honoured
  for at most **60 days** — derived as the outer edge of the only re-check
  case law in the EU (Germany: BFH XI R 38/18 "at least every two months
  presumed sufficient"), inside the only published vendor cadence
  (Chargebee: every 3 months). Past the cap: charge VAT and escalate.
- INVALID/OUTAGE with no valid history: charge VAT. Blank name returns are
  not contrary (member states need not publish names).

## The tax point (VATDEEP-A, 2026-10-31)

Settled: the tax point is **payment receipt** when funds arrive before the
supply completes (Art 65 + Art 93(2)(a); KMS Section 11), otherwise the
**period completion** (Art 64(1)). The invoice date is never the tax point
(EMTA: "No supply is created from issuing an invoice alone"). A card renewal
settling on day 20 keeps the rate of day 20; the invoice carries the
tax-point date per Art 226(7). A rate drift between quote and settlement
becomes a recorded finance incident (`tax_point_rate_changed`) carrying both
corrected splits — never a silent re-split of a charged amount.

## What remains for the accountant

- The 60-day outage cap is a POLICY derived from German case law (the only
  EU law on the question); confirm it suits the Estonian practice.
- The VIES name/address mismatch policy FAILS CLOSED to VAT pending
  reconciliation; the documented override path (an operator clearing a
  resolved mismatch) is the one remaining build item.
- The e-arve 1.2 reverse-charge mark ("Pöördmaksustamine") is implemented per
  EMTA; which banks' importers render `AdditionalInformation` blocks is
  UNVERIFIED (the mark is also mirrored in `InvoiceContentText`).
