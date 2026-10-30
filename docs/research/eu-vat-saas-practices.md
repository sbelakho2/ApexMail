# EU VAT practice for an Estonian SaaS seller — B2B/B2C, OSS, price display, renewals, and the V30 consumer-pricing decision

**Prepared for:** ApexMail, V30 open decision  
**Prepared:** 29 October 2026  
**Status:** Research memo. Not legal or tax advice. No repository code changes were made.  
**Scope:** EU VAT place-of-supply rules, B2B/B2C determination, VIES/reverse charge, OSS and the EUR 10,000 threshold, consumer price-display law, invoicing, renewal tax points, a dated EU standard-rate table, and an actionable V30 recommendation for consumer pricing.

---

## Executive summary

1. **B2B EU sales:** under Article 44 of Directive 2006/112/EC the place of supply is the customer's business establishment (or the fixed establishment receiving the service). Under Article 196 the customer accounts for VAT by reverse charge; the supplier charges 0% only when the customer is a taxable person and the supplier has the evidence required by Article 18 of Implementing Regulation 282/2011 — in practice, a VIES confirmation of the customer's VAT number and associated name/address at the time of supply.
2. **B2C EU sales:** under Article 58 the place of supply of electronically supplied services is where the consumer is established, has a permanent address or usually resides. Destination VAT applies. The OSS Union scheme (Articles 369a–369k) lets an Estonian seller report and pay all cross-border B2C VAT through Estonia, quarterly, with 10-year records.
3. **EUR 10,000 threshold:** Article 59c disapplies destination taxation only while the supplier is established in one Member State and total cross-border B2C TBE services (plus intra-EU distance goods) in the current and preceding calendar year do not exceed EUR 10,000. Below it, Estonian 24% VAT may be charged; above it, destination rates apply, and if the threshold is crossed mid-year destination rules apply from that point.
4. **Estonia:** the standard rate is **24% from 1 July 2025** (22% in 2024, 20% before 2024). Reduced rates are 13% (accommodation) and 9% (books, periodicals including electronic, listed pharmaceuticals); general email SaaS is standard-rated at 24%. Estonian invoices must generally be issued within seven calendar days; 7-year retention applies.
5. **Consumer price display:** Directive 98/6/EC defines the "selling price" as the final price **including VAT and all other taxes**, and Directive 2011/83/EU Article 6(1)(e) requires the **total price inclusive of taxes**, including total costs per billing period for subscriptions and total monthly costs for fixed-rate subscriptions, before the consumer is bound. A consumer-facing "EUR 20 excl. VAT" price is the wrong legal starting point. The order button must also make the payment obligation clear (Article 8(2)).
6. **Vendor practice:** Stripe recommends automatic tax behaviour, which is **inclusive for EUR** and exclusive for USD/CAD; Paddle supports inclusive, exclusive and location-based tax treatment; FastSpring offers gross (tax-inclusive) and net modes and notes that EU buyers are tax-inclusive in gross mode; Chargebee supports inclusive/exclusive configuration and revalidates EU VAT numbers via VIES at customer creation, VAT-number update and subscription renewal. The common consumer-facing model is a tax-inclusive gross price; the common B2B model is net plus VAT.
7. **Recommendation for V30:** adopt **Option A for consumers** — one deliberate VAT-inclusive gross price per self-serve plan for all consumers, with a separate B2B net price list — and keep B2B net pricing/reverse charge. Do not show a net price or "excl. VAT" on any consumer-facing surface. If the owner prefers Option B for net-revenue reasons, it is defensible only if the price offered to consumers — on the pricing page, in any advertisement that states a price, and at checkout — is the gross total for the consumer's country; "net list + VAT only at checkout" is the risky version.
8. **Rate table:** Romania is **21% from 1 August 2025** (Law 141/2025), not a 2026 change; the audit's 19% is stale. Estonia is 24% from 1 July 2025; Finland 25.5% from 1 September 2024; Slovakia 23% from 1 January 2025; Czechia 21% since the 2024 consolidation. No other EU standard-rate change was identified for 2025–2026. The full 27-state table is in section 6.
9. **Renewals:** the tax point is not the invoice date as such. Under Article 63 the chargeable event is when the service is supplied; Article 64 treats successive statements/payments as completed at the end of each period; Article 65 makes an advance payment taxable on receipt; Article 93 applies the rate in force at the chargeable event (or chargeability, for advance payments). Estonia's VAT Act §11 uses the earlier of supply or payment. Revalidate VIES at each renewal because VIES answers only for the current day.
10. **What needs confirmation:** the consumer gross price points, the final A/B decision, the treatment of unverified business customers and OSS use for them, the VIES evidence sufficiency where name/address is not returned, annual prepayments spanning a rate change, territorial exclusions/regional rates, e-invoicing/retention, penalties and non-EU/UK/US taxes. These are listed in section 7.

---

## 0. Method, date and limitations

- **Research date:** 29 October 2026. Sources were accessed on 29–30 October 2026. Rates and rules are stated as at that date.
- **Primary law:** the consolidated VAT Directive 2006/112/EC (CELEX 02006L0112-20240101), Implementing Regulation 282/2011 (CELEX 32011R0282), Implementing Regulation 1042/2013 (CELEX 32013R1042), Directive 98/6/EC (consolidated 28 May 2022, CELEX 01998L0006-20220528) and Directive 2011/83/EU (consolidated 28 May 2022, CELEX 02011L0083-20220528).
- **EUR-Lex access note:** direct EUR-Lex fetches were blocked by an AWS WAF challenge. The consolidated texts were retrieved through the Jina Reader proxy of the same EUR-Lex URLs. The article text quoted below is the official consolidated text as rendered by that proxy; the citation is to EUR-Lex. This is a retrieval limitation, not a change in the law.
- **Rates:** cross-checked against the European Commission's VAT rates pages, the Taxes in Europe Database (TEDB), Tax Foundation's 2026 table and the PwC Worldwide Tax Summaries country pages. The TEDB REST API was not machine-accessible in this session; PwC/Tax Foundation were used as dated secondary confirmations. Where a historical effective date could not be confirmed, it is marked **UNVERIFIED** rather than guessed.
- **No repository changes:** this memo is research only. The working tree was observed to contain concurrent V30 changes (section 8.11); those are not part of this memo and were not modified.

---

## 1. Place-of-supply rules, OSS and the EUR 10,000 threshold

### 1.1 B2B electronically supplied services — Article 44 and Article 196

Article 44 of Directive 2006/112/EC provides:

> "The place of supply of services to a taxable person acting as such shall be the place where that person has established his business. However, if those services are provided to a fixed establishment of the taxable person located in a place other than the place where he has established his business, the place of supply of those services shall be the place where that fixed establishment is located. In the absence of such place of establishment or fixed establishment, the place of supply of services shall be the place where the taxable person who receives such services has his permanent address or usually resides." [S1, Art. 44]

Article 196 then makes the customer liable for the VAT:

> "VAT shall be payable by any taxable person, or non-taxable legal person identified for VAT purposes, to whom the services referred to in Article 44 are supplied, if the services are supplied by a taxable person not established within the territory of the Member State." [S1, Art. 196]

Consequences for ApexMail:

- A sale of email SaaS to an EU business in another Member State is located in the customer's Member State. ApexMail charges **0% VAT** and the customer self-assesses under the reverse-charge mechanism, **provided** the customer is a taxable person (or an identified non-taxable legal person) and ApexMail has the evidence required by Article 18 of Implementing Regulation 282/2011 (section 2.2).
- If ApexMail has a fixed establishment in the customer's Member State and the supply is made from that establishment, the place of supply may be that fixed establishment and the Article 196 reverse charge may not apply in the same way. ApexMail is assumed to sell from Estonia only; this assumption should be confirmed with the accountant if there are employees, branches or dependent agents outside Estonia.
- If ApexMail were established in the customer's Member State, Article 196 would not apply because the supplier would be established there; local VAT registration and charging rules would apply. This is a fixed-establishment question, not a customer-status question.
- Article 196 covers services referred to in Article 44. It does not apply to B2C supplies; B2C e-services are governed by Article 58 (section 1.2).
- A non-taxable legal person (for example, a public body or association) that is identified for VAT purposes is treated as a taxable person for place-of-supply purposes by Article 43 of the VAT Directive and Article 17(2) of Implementing Regulation 282/2011. It can therefore be reverse-charged if the other conditions are met. [S1, Art. 43; S2, Art. 17]

### 1.2 B2C electronically supplied services — Articles 45 and 58

Article 45 states the general B2C rule: the place of supply is where the supplier is established (or the supplier's relevant fixed establishment, or permanent address/usual residence). Article 58 then provides the specific rule for telecommunications, broadcasting and electronically supplied services:

> "The place of supply of the following services to a non-taxable person shall be the place where that person is established, has his permanent address or usually resides: (a) telecommunications services; (b) radio and television broadcasting services; (c) electronically supplied services, in particular those referred to in Annex II." [S1, Art. 58]

The same Article adds that communicating by electronic mail does not by itself make a service an electronically supplied service. ApexMail's email SaaS is nevertheless an electronically supplied service in substance: it is delivered over the internet and is largely automated. The classification should be confirmed against Annex II and the VAT Committee/Commission explanatory notes, but the commercial description (email API/SaaS) points to Article 58, not to a generic Article 45 B2C service.

Consequences:

- For a consumer in another Member State, the place of supply is the consumer's Member State; destination VAT applies.
- For an Estonian consumer, the place of supply is Estonia; 24% VAT applies.
- For a consumer outside the EU, Article 58 places the supply outside the EU; no EU VAT applies. Local taxes (for example, UK VAT or US state sales tax) are separate and out of scope here.
- Article 58 applies to "electronically supplied services" broadly. There is no reduced rate specific to general SaaS in any Member State; the standard rate applies (section 1.6). Reduced rates for e-publications or press are not applicable to ApexMail's email SaaS.

### 1.3 The EUR 10,000 EU-wide threshold — Article 59c

Article 59c(1) disapplies Article 58 (and Article 33(a) for distance goods) only where all of the following are met:

- the supplier is established, or has its permanent address/usual residence, in only one Member State;
- the supplies are made to non-taxable persons in other Member States (or goods are dispatched/transported to another Member State); and
- the total value, **exclusive of VAT**, of those supplies does not exceed **EUR 10,000** in the current calendar year, and did not do so in the preceding calendar year. [S1, Art. 59c(1)]

If the threshold is exceeded during a calendar year, Article 58 applies **as of that time** (Article 59c(2)). Member States must allow taxable persons to opt into the destination rules, and the option must cover at least two calendar years (Article 59c(3)). [S1, Art. 59c(2)–(3)]

For an Estonian seller:

- **Below EUR 10,000:** Article 58 does not apply; the place of supply falls back to Estonia under Article 45, so Estonian 24% VAT may be charged on all cross-border B2C e-services. The seller may instead opt into destination taxation for at least two years.
- **Above EUR 10,000:** destination VAT applies to each Member State of consumption. The seller can use OSS (section 1.4) or register directly in each Member State.
- **Threshold calculation:** it is EU-wide and combined across TBE services and intra-EU distance goods, not per country. For ApexMail, only TBE services are relevant. The value is exclusive of VAT. The test is current year **or** preceding year; if the preceding year exceeded EUR 10,000, destination rules apply from 1 January of the current year even before the current-year total reaches the threshold.
- **Mid-year breach:** destination rules apply from the moment the threshold is exceeded; the earlier part of the year is not retroactively re-taxed under Article 58, but the seller must start applying destination VAT from that point and report accordingly.
- **OSS registration is not itself the threshold:** a seller below the threshold can opt into destination taxation for at least two years under Article 59c(3), and then use OSS; OSS is designed for destination-taxed supplies. Registration timing and the option are discussed below.

The Commission's OSS page summarises the same rule: below EUR 10,000, TBE services and intra-EU distance goods "may remain subject to VAT in the Member State where the taxable person is established"; above it, destination-country VAT rules apply and OSS can be used. [S9]

### 1.4 OSS / One Stop Shop — Articles 369a–369k

The Union scheme is the relevant OSS scheme for an Estonian-established supplier. Key features:

- **Who may use it:** a taxable person not established in the Member State of consumption supplying services to a non-taxable person (Article 369b(c)), and a taxable person making intra-Community distance sales of goods. The scheme applies to all covered supplies in the EU. [S1, Art. 369b]
- **Member State of identification (MSI):** for an EU-established business, the Member State where it has established its business. For ApexMail, that is Estonia. The business uses its existing Estonian VAT number; no separate OSS VAT number is needed for the Union scheme. [S1, Art. 369a(2); S10]
- **Registration timing:** in general, registration takes effect on the first day of the calendar quarter after the request. If supplies began earlier, the scheme can apply from the first supply provided the MSI is informed by the tenth day of the month following that first supply. Changes must be reported by the tenth day of the month after the change. [S10]
- **Quarterly return:** the taxable person must submit a VAT return for each calendar quarter by the end of the month following the quarter (Article 369f). In Estonia the deadlines are 30 April, 31 July, 31 October and 31 January. [S1, Art. 369f; S16]
- **Return content:** for each Member State of consumption, the total value exclusive of VAT, the applicable VAT rates, the VAT amount per rate and the total VAT due (Article 369g). Corrections for previous periods are made in a subsequent return within three years of the original due date (Article 369g(4)). [S1, Art. 369g]
- **Records:** records must be sufficiently detailed to allow the Member State of consumption to verify the return, made available electronically on request, and kept for **10 years from 31 December of the year in which the transaction was carried out** (Article 369k). [S1, Art. 369k]
- **Exclusion:** repeated failure to file or pay can lead to exclusion; Estonia's guidance says a removed business cannot rejoin for two years. [S16]
- **Scope:** OSS covers B2C supplies. It does **not** cover B2B supplies; those are reverse-charged and reported in the recapitulative statement/VD report (section 1.1 and 4.4). [S1, Arts. 369b, 262; S16]

The Commission's guidance page lists the original Explanatory Notes and OSS Guidelines dated 30 July 2021, plus revised versions dated 24 July 2026 that include changes entering into force on 1 January 2027 (ViDA-related). The revised guidance was not analysed for this memo; it is a horizon item. [S11]

### 1.5 Estonia's domestic rate and reduced rates; e-services

The Estonian Tax and Customs Board states:

- Standard rate **24% from 1 July 2025**; it rose from 22% to 24% on that date.
- The standard rate had risen from 20% to 22% on 1 January 2024.
- Reduced rate **13%** for accommodation and accommodation with breakfast, up from 9% on 1 January 2025.
- Reduced rate **9%** for press publications (including electronic), books, and listed pharmaceuticals, up from 5% on 1 January 2025 (with transitional rules for press publications).
- 0% applies to specified goods and services (for example, certain transport, supplies to armed forces, COVID-19-related supplies). [S15]

For email SaaS, the standard 24% applies. There is no reduced rate for general electronically supplied services. The 9% press rate does not apply to ApexMail's email API/SaaS; it applies to press publications. If ApexMail sells an "email newsletter" product that is a press publication, that would need separate classification; the core SaaS is standard-rated.

Estonia's VAT registration threshold is EUR 40,000; ApexMail is already VAT-registered, so the threshold is not the operative issue. [S15]

### 1.6 Which rate applies to e-services in each Member State

General rule: **the standard rate applies to general electronically supplied services in all 27 Member States.** No Member State applies a reduced rate to general SaaS/email services. Reduced rates exist for specified goods and services (Annex III categories), including some e-publications, but those are product-specific and do not cover ApexMail's email SaaS.

The Commission's VAT rates page confirms the framework: the standard rate must be no less than 15% with no maximum; Member States may apply up to two reduced rates as low as 5% to Annex III categories; a super-reduced rate below 5% and a zero rate are possible only for limited basic-needs categories; and parking rates of at least 12% may be retained for certain goods. [S7]

The current standard rates are in section 6. For e-services specifically:

- Estonia: 24%.
- Romania: 21%.
- Finland: 25.5%.
- Slovakia: 23%.
- Czechia: 21%.
- All other Member States: the standard rate in the table.

A Member State's reduced rate for e-books, e-newspapers, accommodation, restaurant services, etc. does not change the standard rate for SaaS. If ApexMail's product were classified as an e-publication, a reduced rate might apply in some countries; that is not the product described in the brief.

### 1.7 ApexMail customer matrix

| Customer | Country | VAT number / VIES | VAT rate | Invoice | Reporting |
|---|---|---|---|---|---|
| Consumer | Estonia | None | 24% | Consumer invoice optional in Estonia; if issued, show VAT | KMD |
| Consumer | Other EU | None | Destination standard rate | B2C invoice; OSS-compliant | OSS quarterly return |
| Consumer | Non-EU | None | 0% / outside EU VAT | Outside-scope invoice; local taxes separate | None for EU VAT |
| Business | Estonia | Any/no VAT number | 24% | Full VAT invoice; buyer VAT number if provided | KMD |
| Business | Other EU | Valid VAT number + VIES evidence | 0% reverse charge | Invoice with both VAT numbers and "Reverse charge" | VD report (recapitulative statement); KMD |
| Business | Other EU | Invalid/unverified VAT number or VIES outage | Destination standard rate | Invoice with VAT; no reverse-charge note | OSS if treated as B2C (confirm), otherwise local registration |
| Business | Non-EU | Business evidence | 0% / outside EU VAT | Outside-scope invoice | None for EU VAT; US sales tax separately |

The matrix assumes ApexMail has no fixed establishment outside Estonia and that the customer is not established in Estonia through a fixed establishment. Both assumptions should be confirmed.

---

## 2. B2B vs B2C determination, VIES and reverse-charge risk

### 2.1 The legal test

The place-of-supply rules depend on whether the customer is a taxable person acting as such (Article 44) or a non-taxable person (Article 45/58). The status is determined under Articles 9–13 and Article 43 of the VAT Directive and Articles 17–20 of Implementing Regulation 282/2011. [S1, Arts. 9–13, 43; S2, Arts. 17–20]

Operationally, a customer is a business for VAT purposes if:

- it is a taxable person carrying on an economic activity (including a sole trader, partnership, company, or an identified non-taxable legal person); and
- it is acting as such for this purchase, not for private use.

A non-taxable legal person identified for VAT purposes is treated as a taxable person for place-of-supply purposes (Article 43; Implementing Regulation Article 17(2)). A business that is not VAT-registered may still be a taxable person in principle, but if it does not communicate a VAT number, the supplier may treat it as non-taxable under Article 18(2) of the Implementing Regulation.

### 2.2 What "verified VAT number" means operationally — Article 18

Article 18(1) of Implementing Regulation 282/2011 is the key operational rule:

> "Unless he has information to the contrary, the supplier may regard a customer established within the Community as a taxable person: (a) where the customer has communicated his individual VAT identification number to him, and the supplier obtains confirmation of the validity of that identification number and of the associated name and address in accordance with Article 31 of Council Regulation (EC) No 904/2010 ...; (b) where the customer has not yet received an individual VAT identification number, but informs the supplier that he has applied for it and the supplier obtains any other proof which demonstrates that the customer is a taxable person ... and carries out a reasonable level of verification of the accuracy of the information provided by the customer, by normal commercial security measures such as those relating to identity or payment checks." [S2, Art. 18(1)]

Article 18(2) adds:

> "Unless he has information to the contrary, the supplier may regard a customer established within the Community as a non-taxable person when he can demonstrate that the customer has not communicated his individual VAT identification number to him." [S2, Art. 18(2)]

Article 19 provides that, absent information to the contrary, the supplier may consider the services to be for the customer's business use if the customer has communicated its individual VAT number for that transaction. Article 20 requires the supplier to establish the customer's location based on information from the customer and to verify it by normal commercial security measures such as identity or payment checks. [S2, Arts. 19–20]

Therefore, "verified VAT number" means, at a minimum:

1. the customer has communicated its individual VAT identification number;
2. the supplier has obtained a VIES confirmation of validity and, where available, the associated name and address; and
3. the supplier has no information to the contrary (for example, a residential address, a free email domain, a payment method inconsistent with the business, or a VAT number that VIES says is invalid).

A structural regex check ("looks like a VAT number") is **not** verification. The current code's own comments say this; the legal rule is Article 18. A VIES confirmation is point-in-time evidence, not a permanent status.

### 2.3 VIES: what it does and does not prove

The Commission's VIES FAQ is explicit:

- VIES sends the number to the relevant national database; if the number is recorded, "Valid" is displayed; if not, "Invalid" is displayed. Some Member States also display the name and address; some do not. [S12, Q1–Q2]
- "If the customer does not have a valid VAT number, then the supplier will charge VAT." [S12, Q3]
- "It is not possible to confirm the validity of a VAT number in the past. It is possible to do it only for the current day." [S12, Q6]
- If a number is invalid, the supplier should first check the format with the customer and ask the customer to contact its tax administration to correct VIES. [S12, Q7]
- Some Member States require an additional registration for intra-EU transactions and record only those numbers in VIES; a correct VAT number may therefore not validate if the owner is not registered for intra-EU transactions. [S12, Q7]
- If the supplier cannot check the validity of the customer's number and believes the customer is not a taxable person, it "should not exempt the supply but should charge VAT." [S12, Q20]
- VIES may be unavailable for parts of the system at certain times due to backups. [S12, Q14]

Legal effect and operational consequences:

- A VIES "Valid" response supports the Article 18(1)(a) presumption, but it is evidence for the date of the consultation. It does not prove that the number was valid at an earlier tax point, and it does not prove that the customer was acting as a business for the purchase.
- A VIES "Invalid" response means the Article 18(1)(a) presumption is unavailable. The supplier must charge VAT unless it can rely on Article 18(1)(b) (customer has applied for a number but not yet received it, plus other proof and reasonable verification). For an established business with a number that VIES says is invalid, Article 18(1)(b) is not a safe fallback.
- A VIES outage is **not** valid evidence. The correct treatment is to fail closed: charge VAT, retain the outage evidence, and retry. The current code's `VatValidationOutcome::Outage` behaviour is consistent with this.
- VIES does not return a name/address for every Member State. Where it does not, the supplier should retain the VIES response plus other commercial evidence (contract, company website, purchase order, payment from a business bank account) and consider whether Article 18(1)(a)'s "associated name and address" requirement is met. This is a point for accountant confirmation; some advisers treat a valid status as sufficient where the Member State does not publish name/address, but the regulation's text is broader. **UNVERIFIED** as a universal practice.
- The VIES portal's own specific disclaimer should be retained/printed with the evidence. The FAQ says the databases are maintained by national administrations and changes are not validated by the Commission. [S12, Q4]

### 2.4 Reverse-charge mechanics

When the conditions are met:

- **VAT charged:** 0%. This is not an exemption; it is a reverse-charge supply. ApexMail retains its input VAT deduction.
- **Invoice:** the supplier's VAT number (Article 226(3)), the customer's VAT number (Article 226(4)), the taxable amount per rate (Article 226(8)), and the notation **"Reverse charge"** (Article 226(11a)). No VAT amount is charged; the invoice should make clear that the customer is liable. [S1, Art. 226]
- **Customer:** accounts for the VAT in its own Member State under Article 196. The customer must be a taxable person or an identified non-taxable legal person.
- **Supplier reporting:** the supply is included in the recapitulative statement (EC Sales List/VIES statement) under Article 262(1)(c) and Article 264, showing the customer's VAT number and the value. In Estonia this is the **VD report**, filed monthly by the 20th of the following month. [S1, Arts. 262–264; S24]
- **Invoice timing:** for supplies covered by Article 196, the invoice must be issued no later than the fifteenth day of the month following that in which the chargeable event occurs (Article 222). Estonia's §37(2¹) reflects this. [S1, Art. 222; S22]
- **Invoicing rules:** for a cross-border B2B reverse-charge supply, the invoicing rules of the supplier's Member State apply (Article 219a(2)(a)(i)); for ApexMail, Estonian rules. [S1, Art. 219a]

### 2.5 Risk if the VAT number is invalid or unverifiable

The primary risk is under-collection of VAT. The legal chain is:

1. Article 196 makes the customer liable only if the customer is a taxable person (or an identified non-taxable legal person).
2. Article 18(1)(a) allows the supplier to presume that status only with a valid VAT number and VIES confirmation.
3. If the number is invalid, the presumption fails; the supplier must charge VAT (VIES FAQ Q3 and Q20). The destination rate applies because the place of supply is still the customer's country under Article 44 or, if the customer is treated as non-taxable, Article 58.
4. If the supplier nevertheless zero-rates, the tax authority can assess the VAT, interest and penalties; the invoice is incorrect and must be corrected. The customer may also be liable, but the supplier cannot rely on that to avoid its own invoice/reporting obligations.
5. If the supplier knew or should have known that the transaction was connected with VAT fraud, the exemption/reverse charge can be refused under the case law (C-131/13). A VIES check is part of reasonable diligence but is not a safe harbour if there are red flags. [S6]
6. A later VIES check cannot prove past validity (FAQ Q6). Retroactive zero-rating after a late validation is therefore uncertain; it depends on the Member State's correction rules and other evidence. This needs accountant confirmation.

Operational policy that follows:

- Do not zero-rate on a structural check alone.
- Do not zero-rate on a VIES outage.
- Do not zero-rate on an invalid number; charge VAT and tell the customer how to fix the number.
- If the customer fixes the number before the tax point, re-run VIES and re-quote; if the tax point has passed, correct prospectively and take advice on the prior period.
- Treat repeated invalid numbers, mismatched names, residential addresses, free email domains and payment methods inconsistent with the business as red flags requiring review.

### 2.6 Evidence to retain per transaction

At minimum:

- Customer's business declaration (the `is_business` flag and the checkout confirmation), with the terms version and timestamp.
- Customer's legal name, address, country and VAT number as entered.
- The VIES response: date/time, outcome (valid/invalid/outage), the VAT number and country checked, the name/address returned (if any), any consultation/reference number the portal provides, and the raw response if available.
- The quote/calculation snapshot: net, VAT, gross, rate, rate-table version, tax-point date.
- The invoice PDF/XML, with the evidence ID and "Reverse charge" notation.
- For B2C: two non-contradictory location evidence items (billing address, IP address, card/bank country) and the timestamp; Article 24b(d) and Article 24f of Implementing Regulation 282/2011. [S3]
- For B2B: contract/purchase order, payment method, company website or other commercial evidence where VIES does not return name/address.
- The OSS return, KMD, VD report and any credit notes.
- Retention: 10 years for OSS records (Article 369k); 7 years for Estonian invoices (§36); recommend retaining all VAT evidence for at least 10 years to cover OSS and audit cycles. [S1, Art. 369k; S18]

### 2.7 Renewal revalidation

Because VIES answers only for the current day, a check at signup is not evidence for a renewal tax point months later. Chargebee's documentation states that it validates the VAT number via VIES when a customer is added, when the VAT number is updated, and **at subscription renewal**; if validation fails, "the reverse charge fails to apply" and the invoice is generated with taxes. [S65]

Recommended ApexMail policy:

- Revalidate VIES before each renewal charge (or at least before each invoice/tax point), not only at onboarding.
- Store each renewal's VIES evidence separately and snapshot the evidence ID on the renewal invoice.
- If the number is invalid/outage at renewal, fail closed: charge VAT, notify the customer, and allow them to fix the number and request a correction for future periods.
- Do not reuse an old `valid_until = NULL` evidence row indefinitely. The current code allows open-ended evidence; a bounded validity horizon (for example, next renewal or 12 months) plus a re-check is the safer operational rule. The legal requirement is evidence at the tax point, not a fixed statutory validity period; the horizon is a control, not a law. **UNVERIFIED** as to any Member State's specific acceptance period.

---

## 3. Consumer price-display law

### 3.1 Directive 98/6/EC — the selling price includes VAT

Directive 98/6/EC on consumer protection in the indication of prices provides:

> "'selling price' shall mean the final price for a unit of the product, or a given quantity of the product, including VAT and all other taxes." [S4, Art. 2(a)]

> "The selling price and the unit price shall be indicated for all products referred to in Article 1 ..." [S4, Art. 3(1)]

> "The selling price and the unit price must be unambiguous, easily identifiable and clearly legible." [S4, Art. 4(1)]

The Directive's unit-price rules are aimed at products sold by quantity; Article 3(2) allows Member States not to apply the unit-price obligation to "products supplied in the course of the provision of a service." But the core definition of the selling price as VAT-inclusive, and the requirement to indicate it, is the EU baseline. For services and subscriptions, the Consumer Rights Directive (section 3.2) supplies the express total-price rule. Member States implement and enforce both; the practical rule for ApexMail is the same: **a price offered to a consumer must be the final price including VAT**, not a net price with VAT added later.

### 3.2 Consumer Rights Directive 2011/83/EU — total price and subscriptions

Article 6(1)(e) requires, before the consumer is bound by a distance contract:

> "the total price of the goods or services inclusive of taxes, or where the nature of the goods or services is such that the price cannot reasonably be calculated in advance, the manner in which the price is to be calculated, as well as, where applicable, all additional freight, delivery or postal charges and any other costs ... In the case of a contract of indeterminate duration or a contract containing a subscription, the total price shall include the total costs per billing period. Where such contracts are charged at a fixed rate, the total price shall also mean the total monthly costs. Where the total costs cannot be reasonably calculated in advance, the manner in which the price is to be calculated shall be provided." [S5, Art. 6(1)(e)]

Article 8(2) adds that, for distance contracts concluded by electronic means, the trader must make the consumer aware in a clear and prominent manner, **directly before the consumer places the order**, of the information in points (a), (e), (o) and (p) of Article 6(1), and the order button must be labelled "order with obligation to pay" or an equivalent unambiguous formulation. [S5, Art. 8(2)]

For recurring SaaS this means:

- A monthly plan must show the **total monthly cost including VAT** (or the total per billing period, if the billing period is not monthly).
- An annual plan must show the **total annual cost including VAT**; a monthly equivalent is additional information, not a substitute.
- The total must be shown before the consumer is bound, not only after payment or on the invoice.
- The order button must make the payment obligation clear.
- If the price cannot be calculated in advance (for example, usage-based overage), the manner of calculation must be explained; for fixed plans, the total per period is required.

### 3.3 Omnibus Directive — price reductions

Directive (EU) 2019/2161 inserted Article 6a into Directive 98/6/EC:

> "Any announcement of a price reduction shall indicate the prior price applied by the trader for a determined period of time prior to the application of the price reduction." [S4, Art. 6a]

The prior price is the lowest price applied during a period not shorter than 30 days before the reduction, subject to the Directive's rules for progressively increased reductions. If ApexMail advertises discounts, the prior price must be shown; a fictitious "was" price is not compliant. This is adjacent to the VAT question but relevant to the pricing page.

### 3.4 Recurring SaaS — monthly display and the "one total" rule

The legally required consumer price is the total per billing period, VAT included. There is no EU rule that the gross price must be identical across Member States; VAT rates differ, so either the gross or the net must vary if the other is held constant. The choice is commercial/structural:

- **Option A:** hold the **gross** constant across consumer markets; the net varies by country. The consumer sees one price; ApexMail absorbs the rate differences.
- **Option B:** hold the **net** constant; the gross varies by country. The consumer sees a country-specific gross if the display is done correctly; if only the net is displayed and VAT is added at checkout, the consumer-facing price is not the legal total.

The legal issue with Option B is not that gross prices differ; it is **where** the gross is shown. If the pricing page advertises "EUR 20 excl. VAT" or "EUR 20 + VAT," that is a net price, and it does not satisfy Article 6(1)(e)/98/6/EC for consumers. If the pricing page shows "EUR 23.80 incl. VAT" for a German consumer and "EUR 25.40 incl. VAT" for a Hungarian consumer, Option B can be compliant. The phrase in the brief — "net list price + local VAT shown as one total at checkout" — describes the risky version if the pricing page itself shows net.

### 3.5 How EU-facing SaaS vendors actually do it

**Stripe Tax.** Stripe's documentation says:

- Tax behaviour determines how tax is presented. Stripe recommends **Automatic**, which "selects exclusive pricing for USD and CAD and inclusive pricing for all other currencies, matching the conventions most customers expect in each market." [S57]
- "Tax-inclusive prices are common for B2C sales in many markets outside the US. When set to inclusive, the amount your customer pays remains constant, regardless of the tax amount (zero or positive). This applies to sales subject to reverse charge as well." [S57]
- For inclusive prices, if tax is positive, the unit price is lower (the gross minus tax); if no tax applies, the gross is the unit price. [S57]
- Stripe's tax-rate object has an `inclusive` boolean; prices cannot be changed from inclusive to exclusive after they are set. [S59]
- Stripe Tax applies reverse charge based on a tax ID and the jurisdictions; the invoice specifies reverse charge and does not include tax in the total. [S58]

**Paddle.** Paddle supports three settings: tax-inclusive, tax-exclusive, and automatic (location-based). With inclusive pricing, "the price you've input will be the price the customer sees"; with exclusive pricing, the local rate is added. Paddle is a merchant of record and validates business VAT IDs at checkout so cross-border B2B purchases are not charged VAT upfront; it issues compliant invoices and reverse-charges VAT-registered business buyers. [S60, S61]

**FastSpring.** FastSpring offers Gross Pricing Mode (tax folded in; the customer sees the total) and Net Pricing Mode (tax added at checkout; the default for new stores). It has three gross variants: Gross Worldwide, Standard Gross (tax-inclusive everywhere except the US and Canada), and a legacy variant. The documentation notes that under Gross modes EU buyers receive tax-inclusive treatment, while under Net mode a EUR 10.00 price becomes EUR 11.90 in Germany with 19% VAT. Gross vs net describes how the total is calculated, not how it is displayed; non-US/Canadian buyers usually see one total with a note that tax is included. [S62]

**Chargebee.** Chargebee lets the merchant configure inclusive or exclusive tax at currency and country level. If a currency is inclusive but a country requires exclusive display, Chargebee extracts the tax from the price; the invoice shows the net and tax separately. Its inclusive-pricing example (EUR 100 plan, Belgium 21% origin, France 24% destination) illustrates that the gross can vary with the destination depending on configuration. Chargebee also documents VIES validation at customer creation, VAT-number update and subscription renewal, and that a failed validation means the reverse charge does not apply and tax is charged. [S63, S64, S65]

**What this means.** The market convention is:

- Consumer-facing prices in the EU are usually **tax-inclusive**; the customer sees the final gross.
- B2B prices are usually **net**, with VAT added or reverse-charged.
- Merchant-of-record platforms (Paddle, FastSpring) can localise the gross automatically because they are the seller; ApexMail, as merchant of record itself, bears the VAT and price-display liability directly. Their practice is evidence of convention, not a legal safe harbour.

### 3.6 Option A vs Option B — legal and commercial analysis

**Option A: one VAT-inclusive gross price per plan for all consumers (net varies by country).**

Legal:

- The displayed price is the legal total by construction. There is no net price to mislead the consumer.
- No geolocation is needed to display a compliant price; the country is needed only to split the gross into net and VAT for the invoice.
- The invoice must still show the statutory rate and VAT amount that reconcile to the gross. Rounding must be handled gross-first: VAT = round(gross × rate / (100 + rate)), net = gross − VAT.
- Rate changes do not change the consumer price; ApexMail's net revenue absorbs the change. This avoids consumer re-pricing notices at each rate change, but requires periodic margin review.

Commercial:

- One price across markets; simpler advertising, comparison and checkout; no "+VAT" surprise; better conversion and trust.
- Net revenue varies by country (for example, at a EUR 24.80 gross: about EUR 19.53 in Hungary at 27%, EUR 20.00 in Estonia at 24%, EUR 21.20 in Luxembourg at 17%). The spread is about 8.6% of net, which is manageable but must be priced in.
- ApexMail may need to set a deliberate consumer gross price that differs from the B2B net list; the consumer product becomes a separate price card. That is normal, but it is a product/pricing decision.
- If the owner wants to preserve the current consumer outlay of EUR 20, the gross would be EUR 20 and the net would fall to about EUR 16.13 in Estonia; that undercuts the B2B net price and is not recommended unless it is a deliberate consumer acquisition price.

**Option B: net list price + local VAT shown as one total (gross varies by country).**

Legal:

- It can be compliant **only if the price offered to the consumer — on the pricing page, in ads that state a price, and at checkout — is the gross total for the consumer's country**. At minimum, the pricing page and checkout must show the gross before the order; the net is a B2B-only figure.
- If the pricing page shows "EUR 20 excl. VAT" or "EUR 20 + VAT," it is a net price and does not satisfy the consumer total-price rule. The fact that checkout later shows a gross total does not cure the pricing-page omission.
- Country-specific gross display requires reliable location determination before display. IP geolocation alone can be wrong (VPN, travel); the billing address is more reliable but is often entered at checkout. A misdisplayed price is a consumer-law risk.
- Rate changes flow through to consumers at renewal; the contract/terms must allow the change, and the consumer must be told the new total before renewal. This can create notice/consent issues.

Commercial:

- Preserves net revenue per plan in every country; tax is passed through.
- Gross prices differ by country (for example, EUR 23.40 in Luxembourg to EUR 25.40 in Hungary for a EUR 20 net plan), which can confuse cross-border consumers and complicate advertising.
- More complex checkout and customer support; higher risk of "why did the price change at checkout?" complaints.
- It aligns with the B2B net catalog, which is operationally simpler for a single product catalog but legally more demanding for consumers.

### 3.7 Recommendation

**Adopt Option A for consumers.** Specifically:

1. Keep the B2B catalog **net**: EUR 20 / 89 / 229 / 699 per month, Compliance EUR 990, Enterprise Cloud EUR 1,750, Dedicated Tenant EUR 4,000+; add VAT where applicable (Estonia 24%; destination VAT for unverified businesses; 0% reverse charge for verified EU businesses).
2. Introduce a separate **consumer gross price card**: one gross price per self-serve plan for all consumers, VAT included. Set it deliberately (for example, anchor at the current net × 1.24 and round to a marketing price point; the exact numbers are an owner decision). The net is derived per country and varies.
3. Remove "excl. VAT" and any net price from consumer-facing surfaces in all four languages. Show "incl. VAT" / "inkl. MwSt." / "TTC" / "IVA incluido."
4. Keep a business toggle or separate business page showing net prices and the reverse-charge/VIES note.
5. **Control the consumer/business price gap.** With a B2B net of EUR 20 and a consumer gross of EUR 24.80, a self-declared business without a VAT number pays EUR 20 + local VAT = EUR 23.40–25.40. In most Member States (all with a rate below 24%) that is below the consumer gross, so a consumer could claim business status to pay less. Either require a valid VAT number for the business net price, or treat unverified businesses as consumers for pricing (they can still receive a VAT invoice), or accept and price for the leakage. This is a commercial/control decision, not a VAT-rate decision.
6. If the owner rejects Option A for net-revenue reasons, Option B is legally possible, but only with a **gross-first** display on every consumer surface; do not implement "net list + VAT only at checkout."

The legal reasoning is that Option A makes the displayed price the statutory total by construction, while Option B depends on getting the display right on every surface and at every location. The commercial reasoning is that one consumer price is simpler, more trustworthy and easier to advertise across the four languages, at the cost of margin variance that can be priced in.

---

## 4. Invoicing requirements

### 4.1 EU requirements

Article 219a determines which Member State's invoicing rules apply:

- In general, the rules of the Member State where the supply is deemed to be made (Article 219a(1)).
- By derogation, the supplier's Member State rules apply where the supplier is not established in the Member State of taxation and the customer is liable for the VAT (reverse charge), unless the customer issues the invoice (self-billing) (Article 219a(2)(a)(i)); and where the supplier uses an OSS special scheme, the Member State of identification's rules apply (Article 219a(2)(b)). [S1, Art. 219a]

For ApexMail:

- Cross-border B2B reverse charge: Estonian invoicing rules apply.
- B2C OSS supplies: Estonian invoicing rules apply because Estonia is the Member State of identification.
- Domestic Estonian supplies: Estonian rules.

Article 226 lists the required invoice details. The ones that matter most here:

- date of issue (1);
- sequential number (2);
- supplier's VAT identification number (3);
- customer's VAT identification number where the customer is liable for VAT or the supply is an intra-Community supply (4);
- full name and address of supplier and customer (5);
- quantity/nature of goods or extent/nature of services (6);
- date of supply/payment if different from invoice date (7);
- taxable amount per rate or exemption, unit price exclusive of VAT and discounts (8);
- VAT rate applied (9);
- VAT amount payable (10);
- in the case of exemption, a reference to the applicable provision (11);
- where the customer is liable for VAT, the mention **"Reverse charge"** (11a). [S1, Art. 226]

Article 222 requires an invoice for Article 196 services no later than the fifteenth day of the month following the month in which the chargeable event occurs. Article 219 treats a document that amends and specifically refers to the initial invoice as an invoice (credit note). Article 223 permits summary invoices for supplies in the same calendar month. [S1, Arts. 219, 222, 223]

### 4.2 Estonian invoicing rules

The Estonian Tax and Customs Board's guidance states:

- An invoice must generally be issued within **seven calendar days** of dispatch/making goods available or provision of services (§37(1)).
- For long-term services or goods/services sold regularly, the invoice must be issued within seven calendar days from the final day of the taxable period under §11(4).
- If the supply is triggered by full or partial payment, an invoice is due within seven calendar days of receiving the payment (§37(2)).
- For intra-Community supplies of goods and certain services to a taxable person in another Member State (§10(4)9)), invoicing may wait until the fifteenth day of the month after dispatch/provision (§37(2¹)).
- Invoices may be paper or, with the recipient's acceptance, electronic (§37(6)).
- Self-billing requires a prior written agreement (§37(5)); credit invoices amending an original are themselves invoices (§37(4)).
- No §37-compliant invoice is required for supplies to natural persons for personal use (except distance selling, new means of transport, or tax-free exports), or for certain exempt supplies (§37(1), (3)). [S22]

The mandatory content under §37, as summarised by EMTA:

- serial number and issue date;
- date goods were dispatched/services provided (or payment date) if different and determinable;
- seller's name, address and VAT registration number;
- buyer's name and address;
- buyer's VAT registration number if the buyer has tax liabilities on the transaction; for intra-Community supplies, only a valid purchaser's VAT number entitles the sale to be treated as an intra-Community supply at the zero rate;
- name/description of goods or services and quantity/extent;
- price excluding VAT, discounts not included in the price;
- taxable amount broken down by VAT rate with the applicable rates;
- VAT amount payable in euros, except in cases provided by law;
- special references (place of supply outside Estonia, 0% rate, exempt, special provisions, other notes). [S19]

The reverse-charge reference: EMTA's "Other references and notes" page states that an invoice involving a reverse-charge supply must state **"reverse charge"**, whether the supply is exempt or zero-rated, and that the reference is also needed where the place of supply is another Member State with a broad reverse charge (Article 194). [S21]

Retention: taxable persons must keep copies of issued and received invoices in chronological order for **7 years** from issue/receipt, in their original form (electronic invoices electronically), and make them available to the tax authority. [S18]

### 4.3 Consumer (B2C) invoices

- Estonia does not require a §37-compliant invoice for supplies to natural persons for personal use, except distance selling, new means of transport and tax-free exports (§37(1), (3)). ApexMail may still issue one for transparency and customer service.
- If issued, the invoice should show the gross total, the VAT rate and the VAT amount, and reconcile net + VAT = gross. A simplified invoice is allowed for amounts up to EUR 160 excluding VAT, with at least the date, supplier name/VAT number, description, taxable amount and VAT. [S23]
- For OSS B2C supplies, the invoice should show the supplier's Estonian VAT number, the customer's country and the destination VAT rate/amount. The OSS return, not the invoice, is the primary reporting instrument.
- The consumer-facing price display rules (section 3) apply independently of whether an invoice is issued.

### 4.4 B2B reverse-charge invoice

A compliant invoice should include:

- supplier's full name, address and Estonian VAT number;
- customer's full name, address and VAT number (the number validated by VIES);
- unique sequential invoice number and issue date;
- date of supply if different;
- description/extent of the SaaS service and the billing period;
- net taxable amount;
- VAT rate 0% and no VAT amount;
- the notation **"Reverse charge"** (and optionally "Article 196, VAT Directive 2006/112/EC");
- currency EUR;
- reference to the evidence/transaction if internal;
- for Estonian rules, the §37(8) reference requirements. [S1, Art. 226; S19; S21]

Do not show a positive VAT amount on a reverse-charge invoice. Do not use the word "exempt" as a substitute for "reverse charge"; they are different legal treatments.

### 4.5 Domestic Estonian and non-EU invoices

- **Estonian business:** charge 24% VAT; show the supplier's and (if provided) the buyer's VAT numbers; show the VAT amount. No reverse-charge note. The buyer deducts input VAT under the normal rules.
- **Non-EU business:** the place of supply is outside the EU under Article 44; no EU VAT. The invoice should state that the supply is outside the scope of EU VAT (or equivalent), show no VAT, and retain evidence that the customer is a business (Article 18(3) of Implementing Regulation 282/2011: certificate from the customer's tax authority, or VAT/similar number plus reasonable verification). [S2, Art. 18(3)]
- **Non-EU consumer:** outside the scope of EU VAT under Article 58; local taxes are separate.

### 4.6 Evidence per transaction

See section 2.6. Add the invoice-specific evidence:

- invoice PDF/XML and the rate/evidence snapshot;
- credit notes and their reference to the original invoice (Article 219);
- proof of sending/availability of the invoice;
- for e-invoices, the recipient's acceptance and the original electronic format (Estonia requires electronic invoices to be preserved electronically). [S18]

---

## 5. Renewals, tax points and rate changes

### 5.1 EU tax-point rules

- **Article 63:** the chargeable event occurs and VAT becomes chargeable when the goods or services are supplied. [S1, Art. 63]
- **Article 64(1):** where a supply gives rise to successive statements of account or successive payments, the supply of services is regarded as completed on expiry of the periods to which those statements or payments relate. [S1, Art. 64(1)]
- **Article 65:** where a payment is made on account before the supply, VAT becomes chargeable on receipt of the payment and on the amount received. [S1, Art. 65]
- **Article 66:** Member States may derogate and make VAT chargeable no later than invoice issue, payment receipt, or a specified time after the chargeable event; this derogation does not apply to Article 196 services. [S1, Art. 66]
- **Article 93:** the rate applicable is that in force at the time of the chargeable event; for advance payments and Article 66 cases, the rate at the time VAT becomes chargeable. [S1, Art. 93]
- **Article 95:** where rates change, Member States may make adjustments in Article 65/66 cases and adopt transitional measures. [S1, Art. 95]

### 5.2 Estonia's tax point — §11

The Estonian VAT Act §11(1) sets the tax point at the earliest of:

- dispatch/making goods available or provision of services; or
- receipt of full or partial payment (or payment made, for received services). [S25, §11(1)]

Section 11(4) addresses long-running services and recurring supplies: services are treated as provided in the period in which they end; recurring supplies fall in the period overlapping the invoicing/payment deadline, capped at twelve calendar months; for services taxed in the recipient's hands lasting over a year, the supply arises each 31 December from commencement if unpaid and incomplete. [S25, §11(4)]

### 5.3 Invoice date vs payment date

For an Estonian seller, the invoice date is not the tax point as such. The tax point is the earlier of service provision or payment. The invoice must be issued within seven days of the tax point (or by the fifteenth of the following month for intra-EU B2B services). [S22; S25]

Practical consequences for recurring SaaS:

- If the renewal charge is collected on the renewal date before the new month's service starts, the tax point is the payment date. The rate in force on that date applies.
- If the service starts before the payment succeeds (for example, a grace period or retry), the tax point is the service start; the rate on that date applies.
- If the invoice is generated on the first of the month but payment is collected later, the tax point may be the service start (earlier), not the invoice date. Do not use the invoice generation timestamp as the tax point.
- For B2B reverse charge, the customer accounts for VAT; the supplier's invoice must still be issued by the fifteenth of the following month. The supplier's VD report follows the supply.

### 5.4 Revalidation at renewal

See section 2.7. The renewal is a new tax point; the VIES evidence must cover it. A pre-onboarding VIES check does not. Chargebee's practice is to revalidate at renewal; ApexMail should do the same. If VIES is unavailable at renewal, fail closed and charge VAT; do not zero-rate on stale evidence.

### 5.5 Rate changes mid-contract

- The rate at the tax point applies, not the rate at contract signature, quote date or invoice generation date. [S1, Art. 93]
- For a monthly subscription, each month's charge is a separate tax point; a rate change applies from the first tax point on or after the change. The prior month is not retroactively re-rated.
- For an annual prepayment, the payment is an advance payment; VAT becomes chargeable on receipt (Article 65; Estonia §11(1)). The rate at receipt generally applies to the prepaid amount. If the service spans a rate change, Article 95 allows Member States to make adjustments/transitional measures; Estonia's precise treatment of an annual prepayment spanning a rate change is **UNVERIFIED** and needs accountant confirmation.
- For a credit note correcting a past invoice, the original tax point and rate should be used; do not apply the current rate to a historical correction. The credit note must refer specifically to the original invoice (Article 219; Estonia §37(4)).
- For a mid-term upgrade/downgrade with proration, each charge has its own tax point; apply the rate in force at each charge date. Do not blend rates across periods unless the invoice clearly shows the rate per period and the tax authority accepts it.

### 5.6 Renewal notices and consumer price changes

- Under Option A, the gross consumer price does not change when VAT rates change; no consumer price-change notice is needed for a rate change, though the invoice VAT split changes.
- Under Option B, the gross changes with the rate; the terms must allow the change, and the consumer should be told the new total before renewal. Consumer law may require notice and may restrict unilateral price changes; this needs legal review.
- In both options, the renewal date, billing period and cancellation terms should be disclosed before the consumer subscribes (CRD Article 6(1)(e) and national law).

---

## 6. Dated EU standard-rate table

### 6.1 Table as at 29 October 2026

The rates below are the **standard VAT rates** applicable to general electronically supplied services. They were cross-checked against Tax Foundation's 2026 table (published 26 January 2026, updated 27 January 2026) and the PwC Worldwide Tax Summaries pages (last reviewed dates shown). Where the exact historical effective date could not be confirmed, the table says so; the "2020-01-01 floor" is a code baseline, not a legal effective date.

| Code | Country | Standard rate | Source last updated | Effective from (verified) | Source / note |
|---|---|---:|---|---|---|
| AT | Austria | 20.0% | 2026-07-23 | 2020-01-01 floor — **UNVERIFIED** | PwC Austria [S28]; no standard-rate change 2024–2026 identified |
| BE | Belgium | 21.0% | 2026-09-10 | 2020-01-01 floor — **UNVERIFIED** | PwC Belgium [S29]; no standard-rate change 2024–2026 identified |
| BG | Bulgaria | 20.0% | 2026-08-02 | 2020-01-01 floor — **UNVERIFIED** | PwC Bulgaria [S30]; no standard-rate change 2024–2026 identified |
| HR | Croatia | 25.0% | 2026-08-27 | 2020-01-01 floor — **UNVERIFIED** | PwC Croatia [S31]; no standard-rate change 2024–2026 identified |
| CY | Cyprus | 19.0% | 2026-08-04 | 2020-01-01 floor — **UNVERIFIED** | PwC Cyprus [S32]; no standard-rate change 2024–2026 identified |
| CZ | Czechia | 21.0% | 2026-07-27 | 2024-01-01 (reported; exact standard-rate start date not stated on the PwC page) — **partly UNVERIFIED** | PwC Czechia [S33] confirms 21% current and 12% reduced from 2024-01-01; the 2024 consolidation introduced 21% |
| DK | Denmark | 25.0% | 2026-07-31 | 2020-01-01 floor — **UNVERIFIED** | PwC Denmark [S34]; no standard-rate change 2024–2026 identified |
| EE | Estonia | 24.0% | 2025-08-08 | **2025-07-01** (verified) | EMTA [S15]: 22% from 2024-01-01, 24% from 2025-07-01; 20% before 2024 |
| FI | Finland | 25.5% | 2026-01-01 | **2024-09-01** (verified) | Vero [S56]: 25.5% from 2024-09-01; 24% before. Fractional rate; do not round |
| FR | France | 20.0% | 2026-04-24 | 2020-01-01 floor — **UNVERIFIED** | PwC France [S37]; no standard-rate change 2024–2026 identified |
| DE | Germany | 19.0% | 2026-06-30 | 2020-01-01 floor — **UNVERIFIED** | PwC Germany [S38]; no standard-rate change 2024–2026 identified |
| GR | Greece | 24.0% | 2026-09-08 | 2020-01-01 floor — **UNVERIFIED** | PwC Greece [S39]; no standard-rate change 2024–2026 identified |
| HU | Hungary | 27.0% | 2026-07-01 | 2020-01-01 floor — **UNVERIFIED** | PwC Hungary [S40]; no standard-rate change 2024–2026 identified |
| IE | Ireland | 23.0% | 2026-08-11 | 2020-01-01 floor — **UNVERIFIED** | PwC Ireland [S41]; no standard-rate change 2024–2026 identified |
| IT | Italy | 22.0% | 2026-07-13 | 2020-01-01 floor — **UNVERIFIED** | PwC Italy [S42]; no standard-rate change 2024–2026 identified |
| LV | Latvia | 21.0% | 2026-06-30 | 2020-01-01 floor — **UNVERIFIED** | PwC Latvia [S43]; no standard-rate change 2024–2026 identified; a 22% proposal is not in force |
| LT | Lithuania | 21.0% | 2026-10-01 | 2020-01-01 floor — **UNVERIFIED** | PwC Lithuania [S44]; standard rate unchanged; reduced rate changes in 2026 do not affect SaaS |
| LU | Luxembourg | 17.0% | 2026-07-31 | 2020-01-01 floor — **UNVERIFIED** | PwC Luxembourg [S45]; 17% confirmed; a stray "16%" claim is not supported |
| MT | Malta | 18.0% | 2026-09-30 | 2020-01-01 floor — **UNVERIFIED** | PwC Malta [S46]; no standard-rate change 2024–2026 identified |
| NL | Netherlands | 21.0% | 2026-05-29 | 2020-01-01 floor — **UNVERIFIED** | PwC Netherlands [S47]; standard rate unchanged; accommodation moved 9%→21% in 2026 |
| PL | Poland | 23.0% | 2026-08-11 | 2020-01-01 floor — **UNVERIFIED** | PwC Poland [S48]; no standard-rate change 2024–2026 identified |
| PT | Portugal | 23.0% | 2026-07-24 | 2020-01-01 floor — **UNVERIFIED** | PwC Portugal [S49]; mainland 23%; regional rates in Azores/Madeira are a separate question |
| RO | Romania | 21.0% | 2026-09-25 | **2025-08-01** (verified) | Law 141/2025; EY [S55] and PwC [S50]: 19%→21%, reduced 5%/9%→11% from 2025-08-01 |
| SK | Slovakia | 23.0% | 2026-09-09 | **2025-01-01** (verified) | PwC Slovakia [S51]: 20%→23% from 2025-01-01 |
| SI | Slovenia | 22.0% | 2026-07-15 | 2020-01-01 floor — **UNVERIFIED** | PwC Slovenia [S52]; no standard-rate change 2024–2026 identified |
| ES | Spain | 21.0% | 2026-06-30 | 2020-01-01 floor — **UNVERIFIED** | PwC Spain [S53]; mainland/Balearics 21%; Canary Islands/Ceuta/Melilla are outside the EU VAT territory |
| SE | Sweden | 25.0% | 2026-09-22 | 2020-01-01 floor — **UNVERIFIED** | PwC Sweden [S54]; no standard-rate change 2024–2026 identified |

**Important:** the "2020-01-01 floor" is not a claim that the rate started on that date. It is the earliest baseline used by the current dated table and by this memo; the exact historical start date of a long-stable rate is not relevant to current invoices, but it is **UNVERIFIED**. For back-dated invoices before 2020, do not use this table without checking the historical rate.

### 6.2 Recent changes that are verified

| Country | Change | Effective date | Source | Status |
|---|---|---|---|---|
| Estonia | Standard 22% → 24% (20% before 2024; 22% from 2024-01-01) | **2025-07-01** | EMTA [S15] | Verified |
| Romania | Standard 19% → 21%; reduced 5%/9% → 11% | **2025-08-01** | Law 141/2025; EY [S55]; PwC [S50] | Verified |
| Finland | Standard 24% → 25.5% | **2024-09-01** | Vero [S56] | Verified |
| Finland | Reduced 14% → 13.5% | **2026-01-01** | Vero [S56] | Verified; does not affect SaaS standard rate |
| Slovakia | Standard 20% → 23%; reduced 19%/5% | **2025-01-01** | PwC [S51] | Verified |
| Czechia | Standard 20% → 21%; reduced 12% | **2024-01-01** | PwC [S33] | Rate verified; exact standard-rate start date not directly quoted |
| Netherlands | Accommodation 9% → 21% | **2026-01-01** | PwC [S47] | Verified; does not affect SaaS standard rate |
| Germany | Restaurant food 19% → 7% | **2026-01-01** | Tax Foundation [S27] | Reported; does not affect SaaS standard rate; exact scope **UNVERIFIED** |
| Austria | Some hygiene products zero-rated | **2026** | Tax Foundation [S27] | Reported; does not affect SaaS standard rate; exact scope **UNVERIFIED** |
| Lithuania | Reduced rate 9% → 12% (standard unchanged at 21%) | **2026-01-01** | Tax Foundation [S27] flags Lithuania as changed; secondary summaries report 9%→12% | Reported; does not affect SaaS standard rate; exact scope **UNVERIFIED** |

No other **standard-rate** change was identified for 2024–2026. The Tax Foundation 2026 table and the PwC pages (reviewed through September/October 2026) show the same 27 standard rates.

### 6.3 Claims that need correction

- **"Romania's 2026 change."** The change is not a 2026 change. Romania raised the standard rate from 19% to 21% with effect from **1 August 2025** under Law No. 141/2025, published 25 July 2025; the 5% and 9% reduced rates were replaced by a single 11% reduced rate. EY's alert is dated 30 July 2025; PwC's Romania page (last reviewed 25 September 2026) still shows 21%/11%. There was reportedly a proposal for a further increase to 23% in 2026, but the current verified rate is 21%; the denial article could not be fetched (VATCalc returned HTTP 403), so the proposal's precise status is **UNVERIFIED**, while the current 21% rate is verified. [S55; S50]
- **Luxembourg 16%.** A stray claim that Luxembourg's standard rate is 16% is not supported. PwC (last reviewed 31 July 2026) and Tax Foundation both show **17%**. The 16% reference appears to be a typo in one secondary table. [S45; S27]
- **Latvia 22%.** Latvia's standard rate is **21%**; the 22% figure is a proposal that is not in force. PwC (last reviewed 30 June 2026) shows 21%. [S43]
- **Cyprus 20%.** Cyprus remains **19%** according to PwC (last reviewed 4 August 2026) and Tax Foundation. No 2026 standard-rate increase was identified. [S32; S27]
- **"Estonia 2024→2025 change to 24%"** is correct: 20% until 2023-12-31, 22% in 2024, 24% from 2025-07-01. [S15]
- **"Finland, Slovakia, etc."** are correct as recent changes; see 6.2.

### 6.4 Reduced rates and e-services

Every Member State except Denmark has one or more reduced rates, but none applies to general SaaS/email services. Reduced rates apply to Annex III categories such as food, medicines, books, newspapers, accommodation, restaurant services, passenger transport, cultural events, etc. Some e-publications benefit (for example, Estonia's 9% press rate, Finland's 10% newspapers, Czechia's zero rate for books), but an email API/SaaS is not an e-publication. The standard rate in the table applies.

If ApexMail later sells a product that is classified as an e-publication or a broadcasting service, the analysis changes; that is outside this memo.

### 6.5 Territorial exclusions and regional rates

The 27-country table is not the whole story for every address:

- **Outside the EU VAT territory even though the country code is EU:** Åland Islands (Finland), Canary Islands/Ceuta/Melilla (Spain), Faroe Islands/Greenland (Denmark), Büsingen/Heligoland (Germany), Livigno/Campione d'Italia/Vatican City (Italy), Mount Athos (Greece), French overseas territories (France), Bonaire/Curaçao/Saba/Sint Eustatius/Sint Maarten (Netherlands). Stripe's tax documentation lists these exclusions; they should be confirmed with the national authority. [S58]
- **Regional rates within the VAT territory:** Portugal's Azores and Madeira have regional rates; Spain's Canary Islands use IGIC (not VAT) and Ceuta/Melilla use IPSI; Greece has reduced rates for certain islands. The exact scope and whether they apply to e-services is **UNVERIFIED** and needs accountant confirmation.
- **Monaco:** treated as part of the French VAT territory in practice, but the treatment of digital services to Monaco residents should be confirmed; **UNVERIFIED**.
- **United Kingdom:** not in the EU; UK VAT has its own registration threshold and place-of-supply rules. Out of scope; separate research is needed.

Implementation implication: a two-letter country code is not sufficient to determine EU VAT for every customer. If ApexMail sells to these territories, the checkout needs a region/territory field or a postcode-based rule, and the rate table needs territory-specific rows. Do not assume "ES" always means 21% Spanish VAT.

### 6.6 Seed table (CSV)

The following CSV mirrors the current dated-table shape: `code,rate_pct,effective_from,verified_on,source,note`. For stable rates, `effective_from` is the 2020-01-01 baseline used by the current code and is marked UNVERIFIED as a legal start date. For recent changes, the verified effective date is used.

```csv
code,rate_pct,effective_from,verified_on,source,note
AT,20.00,2020-01-01,2026-10-29,PwC 2026-07-23,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
BE,21.00,2020-01-01,2026-10-29,PwC 2026-09-10,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
BG,20.00,2020-01-01,2026-10-29,PwC 2026-08-02,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
HR,25.00,2020-01-01,2026-10-29,PwC 2026-08-27,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
CY,19.00,2020-01-01,2026-10-29,PwC 2026-08-04,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
CZ,20.00,2020-01-01,2026-10-29,PwC 2026-07-27,historical baseline
CZ,21.00,2024-01-01,2026-10-29,PwC 2026-07-27,2024 consolidation; exact standard-rate start date not directly quoted (partly UNVERIFIED)
DK,25.00,2020-01-01,2026-10-29,PwC 2026-07-31,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
EE,20.00,2020-01-01,2026-10-29,EMTA 2025-08-08,historical baseline
EE,22.00,2024-01-01,2026-10-29,EMTA 2025-08-08,2024 rate
EE,24.00,2025-07-01,2026-10-29,EMTA 2025-08-08,current rate
FI,24.00,2020-01-01,2026-10-29,Vero 2026-01-01,historical baseline
FI,25.50,2024-09-01,2026-10-29,Vero 2026-01-01,current rate; fractional
FR,20.00,2020-01-01,2026-10-29,PwC 2026-04-24,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
DE,19.00,2020-01-01,2026-10-29,PwC 2026-06-30,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
GR,24.00,2020-01-01,2026-10-29,PwC 2026-09-08,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
HU,27.00,2020-01-01,2026-10-29,PwC 2026-07-01,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
IE,23.00,2020-01-01,2026-10-29,PwC 2026-08-11,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
IT,22.00,2020-01-01,2026-10-29,PwC 2026-07-13,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
LV,21.00,2020-01-01,2026-10-29,PwC 2026-06-30,historical effective date UNVERIFIED; 22% proposal not in force
LT,21.00,2020-01-01,2026-10-29,PwC 2026-10-01,historical effective date UNVERIFIED; standard unchanged; reduced-rate changes do not affect SaaS
LU,17.00,2020-01-01,2026-10-29,PwC 2026-07-31,historical effective date UNVERIFIED; 17% (not 16%)
MT,18.00,2020-01-01,2026-10-29,PwC 2026-09-30,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
NL,21.00,2020-01-01,2026-10-29,PwC 2026-05-29,historical effective date UNVERIFIED; accommodation 9->21 in 2026 does not affect SaaS
PL,23.00,2020-01-01,2026-10-29,PwC 2026-08-11,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
PT,23.00,2020-01-01,2026-10-29,PwC 2026-07-24,historical effective date UNVERIFIED; mainland rate; regional rates separate
RO,19.00,2020-01-01,2026-10-29,Law 141/2025; EY 2025-07-30,historical baseline
RO,21.00,2025-08-01,2026-10-29,Law 141/2025; EY 2025-07-30; PwC 2026-09-25,current rate; 11% reduced rate
SK,20.00,2020-01-01,2026-10-29,PwC 2026-09-09,historical baseline
SK,23.00,2025-01-01,2026-10-29,PwC 2026-09-09,current rate
SI,22.00,2020-01-01,2026-10-29,PwC 2026-07-15,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
ES,21.00,2020-01-01,2026-10-29,PwC 2026-06-30,historical effective date UNVERIFIED; mainland/Balearics; Canary/Ceuta/Melilla outside EU VAT
SE,25.00,2020-01-01,2026-10-29,PwC 2026-09-22,historical effective date UNVERIFIED; no standard-rate change 2024-2026 identified
```

Do not use the 2020-01-01 rows as proof of a historical rate. Use them only as the earliest supported baseline for current-rate lookups.

---

## 7. Settled law vs accountant/owner confirmation

### 7.1 Settled law (with sources)

| Issue | Position | Source |
|---|---|---|
| B2B place of supply | Customer's business establishment or fixed establishment receiving the service; otherwise permanent address/usual residence | VAT Directive Art. 44 [S1] |
| B2B reverse charge | Customer liable if supplier not established in the customer's Member State; 0% VAT | VAT Directive Art. 196 [S1] |
| B2C e-services place of supply | Customer's establishment/permanent address/usual residence | VAT Directive Art. 58 [S1] |
| EUR 10,000 threshold | EU-wide, combined TBE services + distance goods; below = origin (EE) possible; above = destination; mid-year breach = from that point | VAT Directive Art. 59c [S1]; EC OSS [S9] |
| OSS Union scheme | Estonian MSI; quarterly return; 10-year records; corrections within 3 years | VAT Directive Arts. 369a–369k [S1]; EMTA [S16] |
| Verified VAT number | Customer VAT ID + VIES confirmation of validity and associated name/address; no contrary information | Implementing Regulation 282/2011 Art. 18 [S2]; VIES FAQ [S12] |
| Invalid/unverifiable number | Supplier must charge VAT; outage is not valid evidence | VIES FAQ Q3, Q20 [S12]; Implementing Regulation Art. 18(2) [S2] |
| Reverse-charge invoice | Supplier and customer VAT numbers; "Reverse charge"; 0% VAT; no VAT amount | VAT Directive Art. 226(3),(4),(8)–(11a) [S1]; EMTA [S21] |
| Recapitulative statement | Report B2B services under Art. 44 where recipient liable; Estonia VD monthly by 20th | VAT Directive Arts. 262–264 [S1]; EMTA [S24] |
| Invoice timing | Reverse charge: by 15th of following month; Estonia: generally 7 days | VAT Directive Art. 222 [S1]; EMTA [S22] |
| Consumer price display | Selling price includes VAT; total price inclusive of taxes; subscription total per billing period; total monthly costs for fixed-rate subscriptions | Directive 98/6/EC Arts. 2(a), 3(1), 4(1) [S4]; Directive 2011/83/EU Art. 6(1)(e), 8(2) [S5] |
| Price reductions | Prior price = lowest price in at least 30 days before the reduction | Directive 98/6/EC Art. 6a [S4] |
| Tax point | When service supplied; successive payments completed at period end; advance payment on receipt; rate at chargeable event | VAT Directive Arts. 63–66, 93, 95 [S1] |
| Estonian standard rate | 24% from 1 July 2025; 22% in 2024; 20% before | EMTA [S15] |
| Estonian reduced rates | 13% accommodation; 9% books/press/pharma | EMTA [S15] |
| Estonian invoice retention | 7 years | EMTA [S18] |
| Recent rates | RO 21% from 2025-08-01; EE 24% from 2025-07-01; FI 25.5% from 2024-09-01; SK 23% from 2025-01-01; CZ 21% current (2024 consolidation; exact standard-rate start date partly UNVERIFIED) | EY [S55]; PwC [S50, S35, S36, S51, S33]; Vero [S56]; EMTA [S15] |

### 7.2 Needs accountant/owner confirmation

| Issue | Why it needs confirmation | Who |
|---|---|---|
| Consumer gross price points (EUR 24.80 vs 24.99 vs 25, etc.) | Commercial pricing decision; affects revenue and conversion; not a legal constant | Owner/Finance |
| Final Option A vs B | Legal recommendation is A, but the owner must accept the margin/price consequences; B is possible with gross-first display | Owner + accountant |
| Treatment of unverified business customers | Whether to treat as B2C and report via OSS, or require local registration; depends on customer status and risk appetite | Accountant |
| Business price eligibility / consumer-to-business leakage | Whether the business net price requires a VIES-verified VAT number; otherwise a consumer can self-declare business and pay net + VAT (lower than the consumer gross in most countries) | Owner + accountant |
| VIES name/address sufficiency | Some Member States do not return name/address; whether a valid status alone satisfies Art. 18(1)(a) in the relevant Member State | Accountant |
| VIES evidence validity horizon and revalidation frequency | No fixed EU statutory period; VIES is current-day only; operational control needed | Accountant |
| Annual prepayment spanning a rate change | Article 95 transitional measures; Estonia's precise treatment under §11(4) | Accountant |
| Territorial exclusions/regional rates (Canary, Åland, Azores/Madeira, Greek islands, Monaco) | Country code alone is insufficient; local rules may differ | Accountant |
| Estonian e-invoicing/B2B mandate status | Not confirmed in this research; EMTA guidance found only paper/electronic with recipient consent and B2G rules | Accountant |
| Penalties, interest, voluntary disclosure | National law; not researched | Accountant/lawyer |
| Non-EU/UK/US taxes | Out of scope; separate regimes | Accountant |
| ViDA changes from 1 January 2027 | Revised OSS guidance dated 24 July 2026; not analysed | Accountant |
| Contract terms for price changes/renewal notices | Consumer law and contract law; Option B rate pass-through may require notice/consent | Lawyer |
| Order button and withdrawal waiver | CRD Art. 8(2), Art. 16; consumer law | Lawyer |

---

## 8. V30 implementation inputs

### 8.1 Decision

**V30-CONSUMER-PRICING = Option A.**

- Consumer self-serve prices are **gross, VAT-inclusive, one price per plan across consumer markets**.
- B2B prices remain **net**, with VAT added where applicable and reverse charge for verified EU businesses.
- No consumer-facing surface displays a net price or "excl. VAT."
- If the owner rejects Option A, the fallback is Option B with a **gross-first** display on every consumer surface; the current "net list + VAT only at checkout" pattern is not the recommended fallback.

### 8.2 Price architecture

| Audience | Price base | Display | VAT treatment | Invoice |
|---|---|---|---|---|
| Consumer, EE | Gross | Gross incl. 24% VAT | 24% included | Gross, net + 24% VAT |
| Consumer, other EU | Gross | Gross incl. destination VAT | Destination standard rate included | Gross, net + local VAT |
| Consumer, non-EU | Gross/local | Local price; no EU VAT | Outside EU VAT | Outside-scope invoice |
| Business, EE | Net | Net excl. VAT; 24% added | 24% | Net + 24% VAT |
| Business, other EU, valid VIES | Net | Net excl. VAT; reverse charge | 0% reverse charge | Net; "Reverse charge"; both VAT numbers |
| Business, other EU, invalid/outage | Net | Net excl. VAT; destination VAT added | Destination standard rate | Net + local VAT |
| Business, non-EU | Net | Net; outside scope | 0% / outside EU VAT | Outside-scope invoice |

Arithmetic for the consumer gross (illustrative, EUR 24.80 gross):

| Country | Rate | Net | VAT | Gross |
|---|---:|---:|---:|---:|
| Estonia | 24.0% | 20.00 | 4.80 | 24.80 |
| Germany | 19.0% | 20.84 | 3.96 | 24.80 |
| France | 20.0% | 20.67 | 4.13 | 24.80 |
| Spain | 21.0% | 20.50 | 4.30 | 24.80 |
| Italy | 22.0% | 20.33 | 4.47 | 24.80 |
| Netherlands | 21.0% | 20.50 | 4.30 | 24.80 |
| Finland | 25.5% | 19.76 | 5.04 | 24.80 |
| Romania | 21.0% | 20.50 | 4.30 | 24.80 |
| Slovakia | 23.0% | 20.16 | 4.64 | 24.80 |
| Hungary | 27.0% | 19.53 | 5.27 | 24.80 |
| Luxembourg | 17.0% | 21.20 | 3.60 | 24.80 |

Compute gross-first: VAT = round(gross × rate / (100 + rate)), net = gross − VAT. This guarantees the invoice reconciles to the charged gross. The existing half-up helper can be reused with a gross-first formula; do not compute net first and then round VAT separately if that would make net + VAT differ from the gross by a cent.

One rounding nuance: at 21% on a EUR 24.80 gross, gross-first gives VAT of EUR 4.30 (24.80 × 21/121 = 4.3041) and net of EUR 20.50. Recomputing net × 21% gives 4.305, which half-up rounds to 4.31 and would make the invoice total 24.81. The statutory rate is still 21%; the invoice should show the gross-first split (20.50 + 4.30 = 24.80), not a net-first recomputation. Stripe documents the same phenomenon: rounding can make the effective rate appear slightly above or below the statutory rate, and the charged total must remain the price the customer saw. [S57]

Arithmetic for Option B (illustrative, EUR 20.00 net):

| Country | Rate | VAT | Gross |
|---|---:|---:|---:|
| Estonia | 24.0% | 4.80 | 24.80 |
| Germany | 19.0% | 3.80 | 23.80 |
| France | 20.0% | 4.00 | 24.00 |
| Spain | 21.0% | 4.20 | 24.20 |
| Italy | 22.0% | 4.40 | 24.40 |
| Finland | 25.5% | 5.10 | 25.10 |
| Romania | 21.0% | 4.20 | 24.20 |
| Slovakia | 23.0% | 4.60 | 24.60 |
| Hungary | 27.0% | 5.40 | 25.40 |
| Luxembourg | 17.0% | 3.40 | 23.40 |

Option B preserves net revenue but makes the consumer price vary from EUR 23.40 to EUR 25.40 across the EU for the same plan.

**Price-leakage check.** Under Option A, the B2B net price and the consumer gross price are different price cards. If any self-declared "business" can obtain the net price without a valid VAT number, a consumer can select "business" and pay net + local VAT. At a EUR 20 net / EUR 24.80 gross, that is cheaper in every Member State with a standard rate below 24% (for example, EUR 23.40 in Luxembourg, EUR 23.80 in Germany, EUR 24.20 in Spain/Romania, EUR 24.60 in Slovakia/Poland/Portugal/Ireland), equal in Estonia and Greece, and more expensive in Sweden/Denmark/Croatia (25%), Finland (25.5%) and Hungary (27%). The gap is up to EUR 1.40 per month in Luxembourg. To prevent leakage, either (a) require a VIES-verified VAT number for the business net price, or (b) route unverified businesses to the consumer gross price (with a VAT invoice showing the embedded net/VAT), or (c) accept the leakage as a business discount. This is a commercial/control decision and should be recorded in the V30 decision log.

### 8.3 Checkout questions and sequence

Ask/verify **before creating the payment**:

1. **Audience:** "Is this purchase for business or personal use?" Required, no default. If unanswered, treat as consumer (the safe default; the current `is_business` default is false).
2. **Country:** country of establishment (business) or residence (consumer). Required; validate ISO 3166-1 alpha-2 and the EU list. Do not infer from card country or IP alone.
3. **Business details (if business):** legal name, address, VAT number. The VAT number is optional for a business that does not claim reverse charge, but without a valid number the business pays VAT.
4. **Business declaration:** "I confirm I am a taxable person and authorised to use this VAT number." Store the terms version and timestamp.
5. **Consumer location evidence:** billing address plus at least one other non-contradictory item (IP address, card/bank country, MCC). Article 24b(d) and 24f require two items for the Article 58 presumption. Store both.
6. **VIES (if business, EU, non-EE, VAT number supplied):** validate before the quote and before payment. If valid, quote 0% reverse charge. If invalid or outage, quote with VAT (destination or EE), tell the customer, and allow them to correct the number and retry. Never create a 0% payment without valid evidence.
7. **Final total:** display net + VAT for business, or gross incl. VAT for consumer, before the payment button. For consumer Option A, the gross is fixed; show "incl. VAT" and, if useful, the VAT amount/rate.
8. **Consent:** terms accepted; for consumers, immediate-access/withdrawal acknowledgement if applicable (CRD Art. 16); order button labelled with the payment obligation (CRD Art. 8(2)).
9. **Persist:** declaration, country, VAT number, VIES evidence, location evidence, quote snapshot, rate-table version, and the final total.
10. **Create payment:** only after 1–9. The current code's `resolve_checkout_quote` order (persist declaration → VIES → quote → create checkout) is the right sequence; under Option A the quote function must use the consumer gross price rather than `list + destination VAT`.

### 8.4 Timing

| Event | What to do | When |
|---|---|---|
| Pricing page view | Show consumer gross incl. VAT; business net only on business surface | Before plan selection |
| Checkout start | Ask audience, country, VAT number | Before quote |
| Quote | VIES for business reverse charge; two location items for consumer; calculate tax | Before payment creation |
| Payment creation | Use the final gross/net+VAT amount; idempotency key includes amount | After quote |
| Invoice | Snapshot rate, evidence ID, tax point; show "Reverse charge" where applicable | Within 7 days (EE) or 15th of following month (intra-EU B2B) |
| Renewal | Revalidate VIES; re-quote at the new tax point; notify if the total changes | Before each renewal charge |
| Rate change | Use the new rate from the first tax point on/after the change; no retroactive re-rating | On the effective date |
| OSS return | Aggregate by Member State/rate; file quarterly | By 30 Apr / 31 Jul / 31 Oct / 31 Jan |
| KMD/VD | File monthly | By the 20th of the following month |

### 8.5 Evidence

Retain per transaction (at least 10 years; 7 years is the Estonian minimum, 10 years is the OSS requirement):

- Business declaration and terms version; consumer/business flag.
- Country, billing address, IP address, card/bank country; two non-contradictory items for B2C.
- VAT number, VIES response (date/time, outcome, name/address, reference/consultation number if any, raw response), evidence ID.
- Quote snapshot: net, VAT, gross, rate, rate-table version, tax point.
- Invoice PDF/XML, credit notes, "Reverse charge" notation, both VAT numbers.
- OSS return, KMD, VD report, payment records.
- If VIES is unavailable: outage evidence, the VAT-charged quote, and the retry record.
- GDPR: retain only what is necessary for tax/legal obligations; restrict access; document the legal basis.

### 8.6 Pricing page copy — en/de/fr/es

Use the consumer gross price (illustrative EUR 24.80) and the business net price (EUR 20.00). Do not show "excl. VAT" on consumer pages.

| Surface | English | German | French | Spanish |
|---|---|---|---|---|
| Consumer monthly | "EUR 24.80 / month incl. VAT" | "24,80 EUR / Monat inkl. MwSt." | "24,80 EUR / mois TTC" | "24,80 EUR / mes IVA incluido" |
| Consumer annual | "EUR 297.60 / year incl. VAT (12 × EUR 24.80)" | "297,60 EUR / Jahr inkl. MwSt. (12 × 24,80 EUR)" | "297,60 EUR / an TTC (12 × 24,80 EUR)" | "297,60 EUR / año IVA incluido (12 × 24,80 EUR)" |
| Consumer note | "The price shown includes VAT. The applicable rate depends on your country and is shown on your invoice." | "Der angezeigte Preis enthält die gesetzliche MwSt. Der Satz richtet sich nach Ihrem Land und steht auf Ihrer Rechnung." | "Le prix affiché inclut la TVA. Le taux applicable dépend de votre pays et figure sur votre facture." | "El precio mostrado incluye el IVA. El tipo aplicable depende de su país y figura en su factura." |
| Business monthly | "EUR 20.00 / month excl. VAT" | "20,00 EUR / Monat zzgl. USt." | "20,00 EUR / mois HT" | "20,00 EUR / mes sin IVA" |
| Business note | "VAT is added at checkout. EU businesses with a valid VAT number are reverse-charged." | "Die USt. wird an der Kasse hinzugefügt. Für EU-Unternehmen mit gültiger USt-IdNr. gilt das Reverse-Charge-Verfahren." | "La TVA est ajoutée au paiement. Les entreprises de l'UE disposant d'un numéro de TVA valide relèvent de l'autoliquidation." | "El IVA se añade al pagar. Las empresas de la UE con un NIF-IVA válido aplican la inversión del sujeto pasivo." |
| Business VAT-ID prompt | "VAT number (for reverse charge)" | "USt-IdNr. (für Reverse Charge)" | "Numéro de TVA (pour autoliquidation)" | "NIF-IVA (para inversión del sujeto pasivo)" |

Additional rules:

- Consumer pages: never use "excl. VAT," "zzgl. USt.," "HT," or "sin IVA" as the primary price. Those are business-only.
- Business pages: show net clearly; add "VAT added at checkout unless reverse charge applies."
- Annual plans: show the total per billing period, not only a monthly equivalent.
- Discounts: show the prior price for at least 30 days (Omnibus).
- Renewal: show the renewal date, period and total; under Option B, show the new gross before renewal.
- Localisation: use comma decimals in de/fr/es, euro symbol and local wording; keep the legal note in the page language.

### 8.7 Invoices

- **Consumer:** gross total, net, VAT rate, VAT amount; local rate; EUR; if the invoice is optional under Estonian §37, still issue it for transparency. The invoice must reconcile net + VAT = gross.
- **Business, EE:** net + 24% VAT; both VAT numbers if provided; no reverse-charge note.
- **Business, EU verified:** net; 0% VAT; both VAT numbers; "Reverse charge"; reference to Article 196; VD report.
- **Business, EU unverified:** net + destination VAT; no reverse-charge note; invoice shows the rate and amount.
- **Business, non-EU:** outside-scope invoice; no EU VAT; retain business evidence.
- **Credit notes:** refer specifically to the original invoice; use the original rate; sequential numbering.
- **E-invoicing:** paper or electronic with recipient acceptance under §37(6); retain the original electronic format; B2B mandate status to be confirmed.

### 8.8 OSS and filing

- Confirm whether ApexMail's cross-border B2C TBE turnover exceeds EUR 10,000 in the current or preceding year. If yes, register for OSS Union scheme in Estonia (or apply destination rules directly).
- If below, decide whether to charge EE 24% or opt into destination taxation for at least two years. The option is a commercial/administrative choice; document it.
- File OSS quarterly; include each Member State of consumption, taxable value, rate and VAT. Corrections within three years via a subsequent return.
- Keep OSS records 10 years.
- File KMD monthly and VD monthly for B2B reverse-charge supplies. KMD INF threshold is EUR 1,000 per counterparty; confirm whether ApexMail's invoice volume triggers it.
- Reconcile the OSS return, KMD, VD and invoice ledger; investigate differences by country/rate.

### 8.9 Rate-table update process

- Treat the dated table as data, not code: `(country, rate, effective_from)` rows; never overwrite history; add a new row for a change.
- Source of truth: EC TEDB and national tax authorities; cross-check with PwC/Tax Foundation. The EC's TEDB is the official database; PwC/Tax Foundation are dated secondary confirmations. [S7, S8, S27]
- Monitor at least quarterly and before each OSS return; set alerts for Romania, Estonia, Finland, Slovakia, Czechia and any national budget announcements.
- Add `verified_on` and `source` fields in the operational runbook (not necessarily in code) so an auditor can see why a rate was used.
- Snapshot the rate and table version on every invoice; credit notes use the original rate.
- Test boundary dates (for example, RO 2025-07-31 vs 2025-08-01; EE 2024-06-30 vs 2024-07-01; FI 2024-08-31 vs 2024-09-01; SK 2024-12-31 vs 2025-01-01).
- Add a stale-rate test: RO must resolve to 21% on/after 2025-08-01, not 19%.

### 8.10 Acceptance criteria

- [ ] Consumer-facing surfaces (pricing, checkout, ads, comparison pages, emails) show gross prices incl. VAT in en/de/fr/es; no net price or "excl. VAT."
- [ ] Business surfaces show net prices and the VAT/reverse-charge note; business net pricing is either gated on a valid VAT number or the consumer-to-business price leakage is explicitly accepted and monitored.
- [ ] Checkout asks audience, country and VAT number before payment; VIES runs before payment for business reverse charge; evidence is stored.
- [ ] Consumer location uses two non-contradictory evidence items; conflicting evidence is flagged, not silently resolved.
- [ ] Renewals revalidate VIES and re-quote at the new tax point; stale evidence does not authorise 0%.
- [ ] Rate table includes RO 21% from 2025-08-01, EE 24% from 2025-07-01, FI 25.5% from 2024-09-01, SK 23% from 2025-01-01, CZ 21% from 2024-01-01; no stale RO 19%.
- [ ] Invoices show the statutory rate/amount; net + VAT = gross; "Reverse charge" where applicable; both VAT numbers.
- [ ] OSS/KMD/VD reports reconcile to the ledger and invoices.
- [ ] Tests cover: consumer gross extraction, business net + VAT, reverse charge, EE, invalid VIES, VIES outage, non-EU, fractional rate 25.5%, rounding, and rate-change boundaries.
- [ ] Accountant sign-off on the items in section 7.2.

### 8.11 Current implementation observations (not part of the research conclusion)

At the time of writing, the working tree contains uncommitted V30-related changes. These observations are for the caller's context; they are not a code review and no changes were made by this memo:

- `services/mail-server/crates/billing-common/src/vat_rates.rs` now has a dated `DEFAULT_VAT_RATE_PERIODS` table with RO 19%→21% (2025-08-01), EE 22%→24% (2025-07-01), FI 24%→25.5% (2024-09-01), SK 20%→23% (2025-01-01), and CZ 20%→21% (2024-01-01). Baselines are 2020-01-01 and marked UNVERIFIED in the code comments. `get_eu_vat_rate_on(country, at)` resolves the rate at a tax point.
- `quote_list_price` treats the list price as **net** and adds VAT; consumers get `list + destination VAT` (Option B) displayed as one total. This is not Option A. If the owner adopts Option A, the consumer quote needs a gross-first path (gross fixed; VAT extracted; net derived), while the B2B path stays net + VAT.
- `services/mail-server/crates/billing-service/src/tax.rs` runs VIES before checkout and fails closed to VAT; `resolve_checkout_quote` persists the declaration before quoting. This matches the recommended sequence.
- `services/mail-server/migrations/288_billing_tax_status.sql` stores `is_business` with a default of false (consumer), which is the right safe default.
- `services/mail-server/crates/billing-service/src/invoices.rs` snapshots the VIES evidence ID on the invoice and treats the list price as net; the invoice writer reconciles `net + VAT + US sales tax = gross`.
- The remaining V30 gap is the **consumer price basis/display**: the code currently implements Option B (net + destination VAT), not Option A (one gross price everywhere). The pricing page/marketing surfaces should be audited for "excl. VAT" wording before launch.

---

## 9. Sources

All URLs were accessed on 29–30 October 2026 unless a last-updated date is shown. EUR-Lex direct access was blocked by a WAF; the consolidated texts were retrieved through the Jina Reader proxy of the same EUR-Lex URLs.

### Primary law

- **[S1]** Directive 2006/112/EC (VAT Directive), consolidated version 1 January 2024, CELEX 02006L0112-20240101. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02006L0112-20240101. Articles 43, 44, 45, 58, 59c, 63–66, 93–95, 196, 219–226, 262–264, 369a–369k.
- **[S2]** Council Implementing Regulation (EU) No 282/2011, CELEX 32011R0282. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32011R0282. Articles 17–20.
- **[S3]** Council Implementing Regulation (EU) No 1042/2013, CELEX 32013R1042. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32013R1042. Articles 24a–24f.
- **[S4]** Directive 98/6/EC, consolidated 28 May 2022, CELEX 01998L0006-20220528. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:01998L0006-20220528. Articles 2(a), 3(1), 4(1), 6a.
- **[S5]** Directive 2011/83/EU, consolidated 28 May 2022, CELEX 02011L0083-20220528. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02011L0083-20220528. Articles 6(1)(e), 8(2), 16.
- **[S6]** CJEU, C-131/13, judgment of 18 December 2014, CELEX 62013CJ0131. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62013CJ0131.

### European Commission

- **[S7]** European Commission, VAT rates. https://taxation-customs.ec.europa.eu/taxation/vat/vat-rates_en. No date shown; accessed 2026-10-29.
- **[S8]** European Commission, Country-specific information on VAT. https://taxation-customs.ec.europa.eu/taxation/vat/vat-rates/country-specific-information-vat_en. No date shown; accessed 2026-10-29.
- **[S9]** European Commission, One Stop Shop. https://vat-one-stop-shop.ec.europa.eu/index_en. No date shown; accessed 2026-10-29.
- **[S10]** European Commission, Register for OSS. https://vat-one-stop-shop.ec.europa.eu/one-stop-shop/register-oss_en. No date shown; accessed 2026-10-29.
- **[S11]** European Commission, OSS Guides and Explanatory Notes. https://vat-one-stop-shop.ec.europa.eu/guides_en. Original notes 30 July 2021; revised notes 24 July 2026; changes from 1 January 2027.
- **[S12]** European Commission, VIES on-the-Web FAQ. https://ec.europa.eu/taxation_customs/vies/faq.html. No date shown; accessed 2026-10-29. Q1–Q7, Q13–Q14, Q20.
- **[S13]** European Commission, VIES VAT number validation. https://ec.europa.eu/taxation_customs/vies/#/vat-validation. Accessed 2026-10-29.
- **[S14]** European Commission, VAT Directive. https://taxation-customs.ec.europa.eu/taxation/vat/vat-directive_en. Accessed 2026-10-29.

### Estonia

- **[S15]** Estonian Tax and Customs Board, Value added tax. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax. Last updated 08.08.2025.
- **[S16]** Estonian Tax and Customs Board, Special schemes of e-commerce and services (OSS). https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/special-schemes-e-commerce-and-services. Accessed 2026-10-29.
- **[S17]** Estonian Tax and Customs Board, General principles of the VAT Act (time of supply). https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/general-principles-vat-act. Last updated 31.07.2026.
- **[S18]** Estonian Tax and Customs Board, VAT accounting and invoices. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices. Last updated 08.01.2025; footer 31.03.2026.
- **[S19]** Estonian Tax and Customs Board, Information included on invoices. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices/information-included-invoices. Last updated 20.05.2026.
- **[S20]** Estonian Tax and Customs Board, References noted on invoices. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices/references-noted-invoices. Last updated 08.01.2025.
- **[S21]** Estonian Tax and Customs Board, Other references and notes. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices/other-references-and-notes. Last updated 19.08.2026.
- **[S22]** Estonian Tax and Customs Board, Issuance of invoices. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices/issuance-invoices. Last updated 08.01.2025.
- **[S23]** Estonian Tax and Customs Board, Issuance of simplified invoices. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices/issuance-simplified-invoices. Accessed 2026-10-29.
- **[S24]** Estonian Tax and Customs Board, Filing VAT returns and reports. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/filing-vat-returns-and-reports. Accessed 2026-10-29.
- **[S25]** Estonian Value Added Tax Act, English consolidated text, §11. https://www.riigiteataja.ee/en/eli/ee/511072022006/consolide/current. Accessed 2026-10-29 via Jina Reader; §11 text.
- **[S26]** Estonian Tax and Customs Board, Registration as a VAT payer. https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/registration-vat-payer. Referenced from [S15]; not separately fetched.

### Rates and country summaries

- **[S27]** Tax Foundation, "2026 VAT Rates in Europe." https://taxfoundation.org/data/all/eu/value-added-tax-vat-rates-europe/. Published 26 January 2026; updated 27 January 2026.
- **[S28]** PwC, Austria — Other taxes. https://taxsummaries.pwc.com/austria/corporate/other-taxes. Last reviewed 23 July 2026.
- **[S29]** PwC, Belgium — Other taxes. https://taxsummaries.pwc.com/belgium/corporate/other-taxes. Last reviewed 10 September 2026.
- **[S30]** PwC, Bulgaria — Other taxes. https://taxsummaries.pwc.com/bulgaria/corporate/other-taxes. Last reviewed 02 August 2026.
- **[S31]** PwC, Croatia — Other taxes. https://taxsummaries.pwc.com/croatia/corporate/other-taxes. Last reviewed 27 August 2026.
- **[S32]** PwC, Cyprus — Other taxes. https://taxsummaries.pwc.com/cyprus/corporate/other-taxes. Last reviewed 04 August 2026.
- **[S33]** PwC, Czech Republic — Other taxes. https://taxsummaries.pwc.com/czech-republic/corporate/other-taxes. Last reviewed 27 July 2026.
- **[S34]** PwC, Denmark — Other taxes. https://taxsummaries.pwc.com/denmark/corporate/other-taxes. Last reviewed 31 July 2026.
- **[S35]** PwC, Estonia — Other taxes. https://taxsummaries.pwc.com/estonia/corporate/other-taxes. Last reviewed 29 May 2026.
- **[S36]** PwC, Finland — Other taxes. https://taxsummaries.pwc.com/finland/corporate/other-taxes. Last reviewed 09 September 2026.
- **[S37]** PwC, France — Other taxes. https://taxsummaries.pwc.com/france/corporate/other-taxes. Last reviewed 24 April 2026.
- **[S38]** PwC, Germany — Other taxes. https://taxsummaries.pwc.com/germany/corporate/other-taxes. Last reviewed 30 June 2026.
- **[S39]** PwC, Greece — Other taxes. https://taxsummaries.pwc.com/greece/corporate/other-taxes. Last reviewed 08 September 2026.
- **[S40]** PwC, Hungary — Other taxes. https://taxsummaries.pwc.com/hungary/corporate/other-taxes. Last reviewed 01 July 2026.
- **[S41]** PwC, Ireland — Other taxes. https://taxsummaries.pwc.com/ireland/corporate/other-taxes. Last reviewed 11 August 2026.
- **[S42]** PwC, Italy — Other taxes. https://taxsummaries.pwc.com/italy/corporate/other-taxes. Last reviewed 13 July 2026.
- **[S43]** PwC, Latvia — Other taxes. https://taxsummaries.pwc.com/latvia/corporate/other-taxes. Last reviewed 30 June 2026.
- **[S44]** PwC, Lithuania — Other taxes. https://taxsummaries.pwc.com/lithuania/corporate/other-taxes. Last reviewed 01 October 2026.
- **[S45]** PwC, Luxembourg — Other taxes. https://taxsummaries.pwc.com/luxembourg/corporate/other-taxes. Last reviewed 31 July 2026.
- **[S46]** PwC, Malta — Other taxes. https://taxsummaries.pwc.com/malta/corporate/other-taxes. Last reviewed 30 September 2026.
- **[S47]** PwC, Netherlands — Other taxes. https://taxsummaries.pwc.com/netherlands/corporate/other-taxes. Last reviewed 29 May 2026.
- **[S48]** PwC, Poland — Other taxes. https://taxsummaries.pwc.com/poland/corporate/other-taxes. Last reviewed 11 August 2026.
- **[S49]** PwC, Portugal — Other taxes. https://taxsummaries.pwc.com/portugal/corporate/other-taxes. Last reviewed 24 July 2026.
- **[S50]** PwC, Romania — Other taxes. https://taxsummaries.pwc.com/romania/corporate/other-taxes. Last reviewed 25 September 2026.
- **[S51]** PwC, Slovak Republic — Other taxes. https://taxsummaries.pwc.com/slovak-republic/corporate/other-taxes. Last reviewed 09 September 2026.
- **[S52]** PwC, Slovenia — Other taxes. https://taxsummaries.pwc.com/slovenia/corporate/other-taxes. Last reviewed 15 July 2026.
- **[S53]** PwC, Spain — Other taxes. https://taxsummaries.pwc.com/spain/corporate/other-taxes. Last reviewed 30 June 2026.
- **[S54]** PwC, Sweden — Other taxes. https://taxsummaries.pwc.com/sweden/corporate/other-taxes. Last reviewed 22 September 2026.
- **[S55]** EY, "Romanian tax changes introduced by new fiscal and budgetary measures," 30 July 2025. https://www.ey.com/en_gl/technical/tax-alerts/romanian-tax-changes-introduced-by-new-fiscal-and-budgetary-measures.
- **[S56]** Finnish Tax Administration (Vero), Rates of VAT. https://www.vero.fi/en/businesses-and-corporations/taxes-and-charges/vat/rates-of-vat/. Last updated 01 January 2026.

### Vendor practice

- **[S57]** Stripe, "Specify product tax codes and tax behavior." https://docs.stripe.com/tax/products-prices-tax-codes-tax-behavior.md. No date shown; accessed 2026-10-29.
- **[S58]** Stripe, "Zero tax amounts and reverse charges." https://docs.stripe.com/tax/zero-tax.md. No date shown; accessed 2026-10-29.
- **[S59]** Stripe, "The Tax Rate object." https://docs.stripe.com/api/tax_rates/object.md. No date shown; accessed 2026-10-29.
- **[S60]** Paddle, "Do you support tax inclusive/exclusive pricing?" https://www.paddle.com/help/sell/tax/do-you-support-tax-inclusiveexclusive-pricing. No date shown; accessed 2026-10-29.
- **[S61]** Paddle, "How Paddle handles VAT on your behalf." https://paddle.com/help/sell/tax/how-paddle-handles-vat-on-your-behalf. No date shown; accessed 2026-10-29.
- **[S62]** FastSpring, "Gross pricing mode and net pricing mode." https://developer.fastspring.com/docs/gross-pricing-mode-and-net-pricing-mode.md. Updated 2026-09-03.
- **[S63]** Chargebee, "How to configure inclusive or exclusive taxes in Chargebee." https://www.chargebee.com/docs/billing/2.0/kb/billing/how-to-configure-inclusive-or-exclusive-taxes-in-chargebee. No date shown; accessed 2026-10-29.
- **[S64]** Chargebee, "Inclusive pricing calculation." https://www.chargebee.com/docs/billing/2.0/kb/billing/inclusive-pricing-calculation. No date shown; accessed 2026-10-29.
- **[S65]** Chargebee, "My customer is charged taxes on his invoice even after the EU VAT number has been updated — why is this happening?" https://www.chargebee.com/docs/billing/2.0/kb/billing/my-customer-is-charged-taxes-on-his-invoice-even-after-the-eu-vat-number-has-been-updated-why-is-this-happening. No date shown; accessed 2026-10-29.

### Repository observations (context only; not sources of law)

- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` — dated `DEFAULT_VAT_RATE_PERIODS`; `get_eu_vat_rate_on`; `quote_list_price`.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` — VIES before checkout; `resolve_checkout_quote`; `quote_for_tenant`.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/invoices.rs` — net list + VAT; evidence snapshot.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/migrations/288_billing_tax_status.sql` — `is_business` default false.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/migrations/218_vat_truth_foundation.sql` — `vat_validation_evidence`, `invoices.vat_evidence_id`.

---

## 10. UNVERIFIED list

The following items were not confirmed to the standard required for a definitive statement. They are marked so the reader does not treat them as settled.

1. **Historical effective dates for long-stable rates.** The 2020-01-01 baseline for 22 Member States is a code/table floor, not a legal start date. Only EE, FI, RO, SK and CZ (2024) have recent change dates verified. Back-dated invoices before 2020 need separate research.
2. **Czechia's exact standard-rate start date.** PwC confirms 21% is current and that the 12% reduced rate applies from 1 January 2024; the PwC page does not quote the standard-rate start date. The 1 January 2024 date is widely reported as the 2024 consolidation but is only partly verified here.
3. **Romania's 2026 proposal.** The current rate is 21% (PwC 25 September 2026). A reported proposal to raise it to 23% in 2026 is not reflected in the current rate, but the VATCalc denial article returned HTTP 403, so the precise status of that proposal is **UNVERIFIED**. The current 21% is verified.
4. **Estonian B2B e-invoicing mandate.** EMTA guidance found covers paper/electronic invoices with recipient acceptance, B2G e-invoicing and retention; a general B2B e-invoicing mandate was not confirmed. Confirm with the accountant before relying on PDF invoices for all B2B customers.
5. **VIES name/address sufficiency.** Article 18(1)(a) refers to confirmation of validity and associated name/address, but VIES does not return name/address for every Member State (for example, Spain requires input; some countries do not display it). Whether a valid status alone is sufficient in each Member State is **UNVERIFIED**; retain other commercial evidence.
6. **OSS use for unverified business customers.** If a business customer's VAT number is invalid, the supplier may treat it as non-taxable and use OSS for the e-service, or may need a local registration depending on the customer's status and the Member State's view. This characterization needs accountant confirmation.
7. **Annual prepayment spanning a rate change.** Article 95 allows transitional measures, but Estonia's precise treatment of an annual prepayment under §11(4) when the rate changes mid-period is **UNVERIFIED**.
8. **Penalties, interest and voluntary disclosure.** National law; not researched. The memo states the risk qualitatively, not the amounts.
9. **Territorial exclusions and regional rates.** The list of excluded territories is drawn from Stripe's tax documentation (a vendor source) and general EU VAT territory rules; the precise treatment of e-services to Åland, Canary Islands, Ceuta/Melilla, Azores/Madeira, Greek islands and Monaco is **UNVERIFIED** and needs national confirmation.
10. **National consumer price-display implementations.** The memo relies on the EU directives (98/6/EC and 2011/83/EU). Member State statutes (for example, Germany's Preisangabenverordnung, France's Code de la consommation, Spain's consumer rules) were not individually verified; they are consistent with the EU rule but the exact wording/enforcement is **UNVERIFIED**.
11. **VAT rates after 29 October 2026.** The table is a snapshot. Any change after that date (including a Romanian 2026/2027 change) is not captured.
12. **ViDA changes from 1 January 2027.** The Commission's revised OSS guidance is dated 24 July 2026 and refers to changes entering into force on 1 January 2027. The substance was not analysed; monitor.
13. **Non-EU/UK/US taxes.** Out of scope. UK VAT, US state sales tax and other local taxes need separate research.
14. **Paddle, Stripe and Chargebee document dates.** These vendor docs show no last-updated date in the fetched content; they are cited as accessed 2026-10-29, not as dated law.
15. **Direct EUR-Lex access.** EUR-Lex blocked direct fetching with an AWS WAF challenge; the consolidated text was retrieved via the Jina Reader proxy. The article text is the official consolidated text, but the retrieval path is not an official EUR-Lex API response.
16. **EU average standard rate.** Tax Foundation states 21.9%; this is a compilation, not an official EU statistic. It is not used for any calculation in this memo.

---

## Appendix A — Consumer pricing arithmetic (Option A vs Option B)

### A.1 Option A: gross fixed at EUR 24.80

Formula: `VAT = round_half_up(gross × rate / (100 + rate))`; `net = gross − VAT`.

| Country | Rate | Net | VAT | Gross |
|---|---:|---:|---:|---:|
| Luxembourg | 17% | 21.20 | 3.60 | 24.80 |
| Malta | 18% | 21.02 | 3.78 | 24.80 |
| Germany | 19% | 20.84 | 3.96 | 24.80 |
| Cyprus | 19% | 20.84 | 3.96 | 24.80 |
| France | 20% | 20.67 | 4.13 | 24.80 |
| Austria | 20% | 20.67 | 4.13 | 24.80 |
| Bulgaria | 20% | 20.67 | 4.13 | 24.80 |
| Spain | 21% | 20.50 | 4.30 | 24.80 |
| Netherlands | 21% | 20.50 | 4.30 | 24.80 |
| Belgium | 21% | 20.50 | 4.30 | 24.80 |
| Romania | 21% | 20.50 | 4.30 | 24.80 |
| Latvia | 21% | 20.50 | 4.30 | 24.80 |
| Lithuania | 21% | 20.50 | 4.30 | 24.80 |
| Italy | 22% | 20.33 | 4.47 | 24.80 |
| Slovenia | 22% | 20.33 | 4.47 | 24.80 |
| Slovakia | 23% | 20.16 | 4.64 | 24.80 |
| Poland | 23% | 20.16 | 4.64 | 24.80 |
| Portugal | 23% | 20.16 | 4.64 | 24.80 |
| Ireland | 23% | 20.16 | 4.64 | 24.80 |
| Estonia | 24% | 20.00 | 4.80 | 24.80 |
| Greece | 24% | 20.00 | 4.80 | 24.80 |
| Sweden | 25% | 19.84 | 4.96 | 24.80 |
| Denmark | 25% | 19.84 | 4.96 | 24.80 |
| Croatia | 25% | 19.84 | 4.96 | 24.80 |
| Finland | 25.5% | 19.76 | 5.04 | 24.80 |
| Hungary | 27% | 19.53 | 5.27 | 24.80 |

The net spread is EUR 19.53–21.20, about 8.6% of the gross. The gross is identical for every consumer.

### A.2 Option B: net fixed at EUR 20.00

Formula: `VAT = round_half_up(net × rate)`; `gross = net + VAT`.

| Country | Rate | VAT | Gross |
|---|---:|---:|---:|
| Luxembourg | 17% | 3.40 | 23.40 |
| Malta | 18% | 3.60 | 23.60 |
| Germany | 19% | 3.80 | 23.80 |
| Cyprus | 19% | 3.80 | 23.80 |
| France | 20% | 4.00 | 24.00 |
| Austria | 20% | 4.00 | 24.00 |
| Bulgaria | 20% | 4.00 | 24.00 |
| Spain | 21% | 4.20 | 24.20 |
| Netherlands | 21% | 4.20 | 24.20 |
| Belgium | 21% | 4.20 | 24.20 |
| Romania | 21% | 4.20 | 24.20 |
| Latvia | 21% | 4.20 | 24.20 |
| Lithuania | 21% | 4.20 | 24.20 |
| Italy | 22% | 4.40 | 24.40 |
| Slovenia | 22% | 4.40 | 24.40 |
| Slovakia | 23% | 4.60 | 24.60 |
| Poland | 23% | 4.60 | 24.60 |
| Portugal | 23% | 4.60 | 24.60 |
| Ireland | 23% | 4.60 | 24.60 |
| Estonia | 24% | 4.80 | 24.80 |
| Greece | 24% | 4.80 | 24.80 |
| Sweden | 25% | 5.00 | 25.00 |
| Denmark | 25% | 5.00 | 25.00 |
| Croatia | 25% | 5.00 | 25.00 |
| Finland | 25.5% | 5.10 | 25.10 |
| Hungary | 27% | 5.40 | 25.40 |

The gross spread is EUR 23.40–25.40, about 8.5% of the gross. The net is identical for every consumer. Under Option B, the gross must be the price displayed to the consumer; the net is a B2B/back-office figure.

### A.3 Which model is easier to reconcile?

Both can reconcile exactly if the rounding is done in the right direction:

- Option A (gross fixed): compute VAT from the gross, then net = gross − VAT. This guarantees net + VAT = gross. If you compute net first and round VAT independently, you can be one cent off; avoid that.
- Option B (net fixed): compute VAT from the net, then gross = net + VAT. This also reconciles exactly.

The current invoice writer's `vat_amount_half_up` and allocation logic can support either, but the quote function must know which base is fixed. Under Option A, the consumer quote is a gross-first calculation; under Option B, it is a net-first calculation. Do not use one formula for both audiences without an explicit `tax_behavior`/price-base flag.

---

## Appendix B — Quick answers to the brief's questions

1. **Place of supply B2B:** Article 44; customer's business establishment/fixed establishment; reverse charge under Article 196. **B2C:** Article 58; customer's establishment/permanent address/usual residence.
2. **OSS/threshold:** Union scheme in Estonia; quarterly returns; EUR 10,000 EU-wide combined threshold for TBE services + distance goods; below = EE 24% possible; above = destination; mid-year breach = from that point.
3. **Estonia:** 24% from 1 July 2025; 13%/9% reduced; e-services standard 24%.
4. **B2B/B2C determination:** customer declaration + VAT number + VIES confirmation of validity/name/address (Article 18); no valid number = charge VAT; outage = fail closed; retain evidence; revalidate at renewal.
5. **Reverse charge:** 0%; both VAT numbers; "Reverse charge"; VD/ESL; customer self-assesses; invalid number = VAT.
6. **Consumer price display:** 98/6/EC selling price includes VAT; CRD Article 6(1)(e) total incl. taxes and per-billing-period total; Article 8(2) order button; Omnibus prior-price rule.
7. **Vendor practice:** Stripe automatic = inclusive for EUR; Paddle inclusive/exclusive/automatic; FastSpring gross/net; Chargebee inclusive/exclusive + VIES at renewal. Consumer-facing convention = gross; B2B = net.
8. **Invoicing:** Article 226 content; Estonia §37, 7 days, 15th for intra-EU B2B, 7-year retention; "reverse charge" wording.
9. **Renewals:** tax point earlier of supply/payment (EE §11); rate at tax point; advance payment on receipt; revalidate VIES; credit notes at original rate.
10. **Rates:** RO 21% from 1 Aug 2025; EE 24% from 1 Jul 2025; FI 25.5% from 1 Sep 2024; SK 23% from 1 Jan 2025; CZ 21% current (2024 consolidation; exact start date partly UNVERIFIED); no other standard changes 2024–2026.
11. **V30:** recommend Option A for consumers, B2B net; checkout asks audience/country/VAT number; VIES before payment; two location evidence items; revalidate at renewal; gross display in en/de/fr/es.
