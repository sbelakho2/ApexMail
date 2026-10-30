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

## What remains for the accountant (documented, not silently assumed)

- The bounded 90-day VIES grace period is a POLICY choice: the law has no
  grace period, and the code comment now says so. Bounded last-known-valid is
  defensible; the accountant should confirm the policy and the period.
- Invoice tax point for monthly renewals: the code quotes at the charge date;
  the alternative reading (Art 64(2) period expiry) should be confirmed.
- The e-arve XML export has no reverse-charge element and no supply date; the
  element names could not be verified against the published schema offline, so
  none were invented. Confirm the correct e-arve 1.2 field for the statutory
  reference.
- Fixed establishments: no customer fixed-establishment field exists (Art. 44
  second limb); the accountant should confirm no customer has one.
- A VIES name/address mismatch is not yet treated as "information to the
  contrary" (Art. 18); confirm the desired policy.
