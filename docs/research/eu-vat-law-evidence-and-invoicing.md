# VAT-LAW-B — Evidence, verification and invoicing: the duty-of-care layer

**Angle:** 2 of 3 (evidence / verification / invoicing). Sisters: place of supply (1), consumer display + rates (3).
**Prepared:** 30 October 2026. **Retrieval date for every source below:** 30 October 2026.
**Status:** research memo from primary law. Not legal or tax advice. **No repository changes were made.**
**Repo baseline read:** `docs/research/eu-vat-saas-practices.md` (29 Oct 2026), `services/mail-server/crates/billing-common/src/vat_rates.rs`, `services/mail-server/crates/billing-service/src/{tax.rs,invoices.rs,plan_billing.rs,credit_notes.rs}`, `services/mail-server/crates/compliance/src/vat_vies.rs`, `services/mail-server/crates/api-server/src/routes/billing.rs`, `services/mail-server/migrations/218_vat_truth_foundation.sql`.

---

## 0. Method, source classes and what "three times" means here

Every proposition below is marked with its three legs:

| Tag | Source class | What is used |
|---|---|---|
| **[L]** | Primary law | VAT Directive 2006/112/EC (consolidated 01.01.2025); Implementing Regulation 282/2011 (consolidated 01.07.2022); Regulation 904/2010; Estonian VAT Act (KMS), English consolidated text in force 01.01.2024–30.12.2024; CJEU judgments |
| **[G]** | Official administrative guidance | European Commission VIES FAQ and the Commission's VAT-invoicing page; Estonian Tax and Customs Board (EMTA) English guidance |
| **[P]** | Independent practitioner / vendor documentation | PwC Worldwide Tax Summaries (Estonia, reviewed 29 May 2026); Stripe Tax documentation (vendor practice, used as practitioner-class evidence of how the market resolves the question) |

A leg that could not be confirmed is marked **UNVERIFIED** rather than filled in. Disagreements are resolved in §7 by quoting the primary text.

**Retrieval limitation.** Direct `eur-lex.europa.eu` fetches are blocked by an AWS WAF challenge from this environment; the official texts were retrieved through the Jina Reader proxy of the same EUR-Lex URLs. The quoted article text is the official consolidated text as rendered. This is a retrieval limitation, not a change in the law. The Estonian English text was retrieved from the Riigi Teataja public API XML for ELI `503012024001` (see S13); the HTML front end is a JavaScript single-page app and does not render server-side.

**What this memo does not decide.** Whether ApexMail has a fixed establishment outside Estonia, whether its product is an "electronically supplied service" under Annex II, and the consumer gross-price policy are angle 1 / angle 3 questions. They are assumed here as stated by the repo (Estonian seller, no foreign fixed establishment, email SaaS = electronically supplied service).

---

## 1. Verification of VAT status (B2B reverse charge)

### 1.1 Article 18 of Implementing Regulation 282/2011 — verbatim

Consolidated text of 1 July 2022 (the latest consolidation that resolves on EUR-Lex; checked 2023-01-01, 2024-01-01, 2024-07-01, 2025-01-01 — none exist; the 2022 consolidation carries the Reg 1042/2013 marker on Art 18(2)):

> **Article 18**
>
> 1. Unless he has information to the contrary, the supplier may regard a customer established within the Community as a taxable person:
>
> (a) where the customer has communicated his individual VAT identification number to him, and the supplier obtains confirmation of the validity of that identification number and of the associated name and address in accordance with Article 31 of Council Regulation (EC) No 904/2010 of 7 October 2010 on administrative cooperation and combating fraud in the field of value added tax;
>
> (b) where the customer has not yet received an individual VAT identification number, but informs the supplier that he has applied for it and the supplier obtains any other proof which demonstrates that the customer is a taxable person or a non-taxable legal person required to be identified for VAT purposes and carries out a reasonable level of verification of the accuracy of the information provided by the customer, by normal commercial security measures such as those relating to identity or payment checks.
>
> 2. Unless he has information to the contrary, the supplier may regard a customer established within the Community as a non-taxable person when he can demonstrate that the customer has not communicated his individual VAT identification number to him.
>
> **However, irrespective of information to the contrary, the supplier of telecommunications, broadcasting or electronically supplied services may regard a customer established within the Community as a non-taxable person as long as that customer has not communicated his individual VAT identification number to him.**
>
> 3. Unless he has information to the contrary, the supplier may regard a customer established outside the Community as a taxable person:
>
> (a) if he obtains from the customer a certificate issued by the customer's competent tax authorities as confirmation that the customer is engaged in economic activities in order to enable him to obtain a refund of VAT under Council Directive 86/560/EEC …;
>
> (b) where the customer does not possess that certificate, if the supplier has the VAT number, or a similar number attributed to the customer by the country of establishment and used to identify businesses or any other proof which demonstrates that the customer is a taxable person and if the supplier carries out a reasonable level of verification of the accuracy of the information provided by the customer, by normal commercial security measures such as those relating to identity or payment checks.

*(S2, Art. 18. The second subparagraph of Art. 18(2) is printed in the consolidation under the `▼M2` (Reg 1042/2013) marker.)*

**Why the second subparagraph of Art. 18(2) matters and is missing from the repo memo.** For *telecommunications, broadcasting and electronically supplied services*, a supplier may treat a Community customer as non-taxable **"irrespective of information to the contrary"**, provided only that the customer **has not communicated** a VAT number. That is the clean legal basis for the "no number ⇒ consumer treatment ⇒ destination VAT" branch. It is *not* a basis for ignoring an invalid number once a number *has* been communicated: the proviso ("as long as that customer has not communicated his individual VAT identification number") excludes that case. The repo memo quotes Art 18(1) and 18(2) first sentence but omits this subparagraph (see conflict C4).

### 1.2 The surrounding articles that do the real work

**Article 17 (status).** Status is determined under Arts 9–13 and 43 of the Directive. Art 17(2) treats identified non-taxable legal persons as taxable persons for Art 43 purposes.

**Article 19 (capacity).** Communication of the individual VAT number lets the supplier consider the service to be for business use "unless he has information to the contrary, such as information on the nature of the services provided".

**Article 20 (location).**
> "The supplier shall establish that place based on information from the customer, and verify that information by normal commercial security measures such as those relating to identity or payment checks."

This is the general due-diligence standard; it is a *verification* duty, not a VIES duty. Art 20 is not about evidence of intra-Community supplies (the brief's aside is right).

**Article 25 (time).** The single most important provision for the renewal question:
> "For the application of the rules governing the place of supply of services, **only the circumstances existing at the time of the chargeable event shall be taken into account.** Any subsequent changes to the use of the service received shall not affect the determination of the place of supply, provided there is no abusive practice."

Recital 22 explains why the article exists: "The time at which the supplier of the service must determine the status, the capacity and the location of the customer, whether a taxable person or not, should also be specified."

**Recital 18** frames the whole section: "In order to determine the customer's status as a taxable person, it is necessary to establish what the supplier should be required to obtain as evidence from his customer."

### 1.3 VIES: legal basis and what an answer legally evidences

**Legal basis.** Regulation (EU) No 904/2010, Article 31(1):

> "The competent authorities of each Member State shall ensure that persons involved in the intra-Community supply of goods or of services and non-established taxable persons supplying telecommunication services, broadcasting services and electronically supplied services, in particular those referred to in Annex II to Directive 2006/112/EC, are allowed to obtain, for the purposes of such transactions, confirmation by electronic means of the validity of the VAT identification number of any specified person as well as the associated name and address. This information shall correspond to the data referred to in Article 17."

**What the member states must hold.** Reg 904/2010 Art 17(1):
> "(b) data on the identity, activity, legal form and address of persons to whom it has issued a VAT identification number, collected pursuant to Article 213 of Directive 2006/112/EC, as well as the date on which that number was issued;
> (c) data on VAT identification numbers it has issued which have become invalid, **and the dates on which those numbers became invalid**".

This is a precise and useful point: the *database* holds invalidity dates, but the *confirmation service* under Art 31(1) is drafted in the present tense — "confirmation … of the validity … as well as the associated name and address". There is no duty to give historical confirmation. That is exactly what the Commission says.

**What a VIES answer evidences.** It evidences the registration status of the number *on the date of the consultation* and, where the member state publishes it, the associated name and address. It does not evidence (i) that the customer was registered at an earlier date, (ii) that the customer is acting as a business for this purchase (Art 19 is a separate presumption), or (iii) that the customer's name/address on file matches the VIES record.

**Invalid number.** The Art 18(1)(a) presumption is unavailable. The Art 18(2) second-subparagraph route is also unavailable, because the customer *did* communicate a number. The supplier therefore has to determine status on the facts (Art 17) and, if it cannot, charge VAT. Commission FAQ Q3: "If the customer does not have a valid VAT number, then the supplier will charge VAT." FAQ Q7 tells the supplier to check the format with the customer and ask the customer to have the national database corrected, and warns that some member states require an additional registration for intra-EU transactions, so a correct number may still not validate.

**Outage.** No confirmation is "obtained", so the Art 18(1)(a) presumption does not arise. Art 18(1)(b) does not help: it applies only where the customer "has not yet received" a number and has told the supplier it applied. No provision of the Directive or the Regulation shifts the evidential risk to the customer, to the Commission or to the member state on outage, and there is no force-majeure relief. Commission FAQ Q20 is the operative guidance: "If you believe that your customer is not a taxable person, you should not exempt the supply but should charge VAT." Note the condition — the FAQ does not say that an outage *by itself* compels VAT; it says that if you cannot establish taxable status, you charge VAT.

**Minimum that the law requires vs what prudence requires** — see §1.5.

### 1.4 CJEU doctrine — actual holdings, and a correction to the brief

The brief asks for C-587/10 VSTR, C-324/11 Tóth, C-285/11 Bonik and C-21/16 Euro Tyre. **All four are goods / input-deduction cases.** None is a services reverse-charge case and none interprets Art 18 of Reg 282/2011. They are relevant by analogy only, and two of them (Tóth, Bonik) are about the *buyer's* right to deduct, not the *seller's* duty to check its customer. This matters: they cannot be cited as direct authority for an Art 18 verification duty. What they do establish is the general standard.

**C-587/10 VSTR (27 Sept 2012), operative part (verbatim):**
> "The first subparagraph of Article 28c(A)(a) of Sixth Council Directive 77/388/EEC … should be interpreted as not precluding the tax authority of a Member State from making the exemption from VAT of an intra-Community supply subject to the provision by the supplier of the VAT identification number of the person acquiring the goods, with the proviso that the grant of that exemption should not be refused on the sole ground that that requirement was not fulfilled where the supplier, acting in good faith and having taken all the measures which can reasonably be required of him, is unable to provide that identification number but provides other information which is such as to demonstrate sufficiently that the person acquiring the goods is a taxable person acting as such in the transaction at issue."

Key reasoning, ¶49–52:
> "… the definition of 'taxable person' … does not make the capacity of taxable person subject to the possession by that person of a VAT identification number" (¶49)
> "… although a VAT identification number provides proof of the tax status of the taxable person and facilitates the tax audit of intra-Community transactions, it constitutes only a formal requirement which cannot undermine the right of exemption from VAT where the substantive conditions for an intra-Community supply are satisfied" (¶51)
> "… although it is legitimate to require that the supplier act in good faith and take every measure which can reasonably be required of him to ensure that the transaction that he effects does not lead to his participation in tax evasion …" (¶52)

**C-21/16 Euro Tyre (9 Feb 2017):**
> "The registration of taxable persons carrying out intra-Community transactions in the VIES system is also of particular importance in that context. The purpose of that system is to enable operators to obtain confirmation of the VAT identification number of their trading partners and the national tax administrations to monitor intra-Community transactions and to detect any irregularities." (¶28)
> "… neither the acquisition by the purchaser of a VAT identification number valid for the purpose of carrying out intra-Community transactions nor the inclusion of that number in the VIES system constitute substantive conditions for exemption from VAT of an intra-Community supply. Those are merely formal requirements which cannot undermine the vendor's entitlement to exemption from VAT where the substantive conditions for an intra-Community supply are satisfied." (¶32)

**C-324/11 Tóth (6 Sept 2012), operative part, point 3:**
> "Directive 2006/112 must be interpreted as meaning that the fact that a taxable person did not verify either whether a legal relationship existed between the workers employed on a work site and the issuer of the invoice or whether the latter had declared those workers does not constitute an objective factor which demonstrates that the addressee of the invoice knew or ought to have known that he was participating in a transaction involving fraudulent evasion of value added tax, where the addressee was not in possession of any material justifying the suspicion that irregularities or fraud had been committed within that invoice issuer's sphere of activity."

**C-285/11 Bonik (6 Dec 2012), operative part:**
> "… a taxable person may not be refused the right to deduct VAT in relation to a supply of goods on the ground that, in view of fraud or irregularities committed upstream or downstream of that supply, the supply is considered not to have actually taken place, where it has not been established on the basis of objective evidence that the taxable person knew, or should have known, that the transaction relied on as a basis for the right of deduction was connected with VAT fraud committed upstream or downstream in the chain of supply …"

**C-273/11 Mecsek-Gabona (6 Sept 2012) — the closest case on stale/retroactively invalidated confirmations** (not requested in the brief, added because it is the only authority on the point):
> "… given that the obligation to check the status of the taxable person must be discharged by the competent national authority before it assigns that person a VAT identification number, possible irregularities affecting the register cannot deprive a trader who has relied on the information entered in that register of the right of exemption from VAT to which it is entitled." (¶63)
> "… it is contrary to the principle of proportionality that the vendor be held liable for the VAT solely on the ground that the purchaser's VAT identification number was removed from the register with retroactive effect." (¶64)

**What the case law does and does not give ApexMail.**
1. It does **not** create an obligation to re-query VIES at every renewal. The general standard is good faith plus "every measure which can reasonably be required" (VSTR ¶52; Mecsek ¶48), and the tax authority cannot demand verification where there is no material suggesting irregularities (Tóth point 3; Bonik).
2. It **does** put the burden of proving the conditions on the supplier (VSTR ¶43).
3. It **does** protect a supplier who relied on a register entry that was valid when it was made, even if the number is later cancelled with retroactive effect (Mecsek ¶63–64). That is a reliance principle, not a time-limited grace period.
4. It **does not** say that a months-old confirmation can support a *new* tax point. Art 25 of Reg 282/2011 is the provision that speaks to that, and it points to the chargeable event.

**UNVERIFIED:** no CJEU judgment was found that directly interprets Art 18 of Reg 282/2011 for services, or that addresses a VIES outage. Treat the service-side conclusions as textual + analogical, not as settled case law.

### 1.5 Minimum the law requires, versus what prudence requires

**Minimum (what a tax authority could insist on from the texts).**
1. Determine the customer's status on the circumstances at the chargeable event (Reg 282 Art 25; Directive Art 63).
2. To presume taxable status: a communicated individual VAT number **plus** a confirmation of validity **and** of the associated name and address obtained through the Art 31 Reg 904/2010 system (Art 18(1)(a)); or, for a customer that has applied for but not received a number, other proof plus reasonable verification by normal commercial security measures (Art 18(1)(b)).
3. If no number was communicated for an electronic service, the supplier may treat the customer as non-taxable (Art 18(2) second subparagraph) and apply destination VAT under Art 58 / the OSS rules.
4. If a number was communicated but cannot be confirmed, do not presume taxable status; charge VAT unless taxable status can be established by other proof (Art 17; Art 18(1)(b) logic; VSTR ¶52).
5. Keep accounts in sufficient detail for VAT to be applied and checked (Art 242); store issued and received invoices (Art 244) for the national period (Art 247; KMS §36(1): 7 years) and for 10 years for OSS transactions (Art 369k(2)).
6. Invoice content per Art 226 (including 11a) and KMS §37(7)–(8); invoice timing per Art 222 and KMS §37(1), (2¹).
7. Report reverse-charged services in the recapitulative statement (Arts 262–264); in Estonia, the VD report.

**Prudence (defensible controls that the texts do not compel).**
1. Re-query VIES before each renewal / tax point, because a confirmation speaks only to its own date (FAQ Q6).
2. Compare the VIES-returned name/address with the customer's declared name/address and record the result.
3. Retain the raw response, its hash, the consultation timestamp and any request reference (the DB already does; the decision object does not).
4. Fail closed on outage — but label it as a policy, not as the only lawful result.
5. A bounded freshness horizon (the repo's 90 days) — a control, not a statutory period.
6. Record the customer's business declaration and its timestamp/terms version, and record any "information to the contrary".
7. For B2C, two non-contradictory location evidence items (Reg 282 Arts 24b(d), 24f) — adjacent to this angle but part of the same evidence file.

### 1.6 Propositions with three confirmations

**V1. A 0 % intra-EU B2B SaaS sale is a reverse-charge supply; the supplier may zero-rate only on the Art 18 evidence, not on the number's format.**
- [L] Directive Arts 44, 196; Reg 282 Arts 17–18. Art 196: "VAT shall be payable by any taxable person … to whom the services referred to in Article 44 are supplied, if the services are supplied by a taxable person not established within the territory of the Member State."
- [G] EMTA, *The place of supply of services is not Estonia*: services to a taxable person registered in another member state are "Reverse charge" and "subject to value-added tax at the rate of 0 %"; EC VIES FAQ Q3.
- [P] Stripe Tax documentation confirms tax IDs drive the reverse-charge outcome — but see conflict C9: Stripe applies reverse charge on the number's **format** "regardless of the government verification result", which is *not* the Art 18 standard.

**V2. Art 18(1)(a) requires confirmation of validity *and* of the associated name and address.**
- [L] Reg 282 Art 18(1)(a), quoted above.
- [G] EC VIES FAQ Q2: "Depending on the national rules on data protection, some Member States … will also provide the name and address linked to the given VAT number"; FAQ Q22: for Spain the name/address must be entered with the number.
- [P] Stripe: "This process only verifies the validity of the tax ID, and not whether the customer's name and address match what's on the customers page in the Dashboard" — i.e. the industry treats the name/address leg as the merchant's own control, which confirms the gap is real rather than theoretical.

**V3. An "invalid" VIES answer defeats the Art 18(1)(a) presumption, and Art 18(2)'s electronic-services route is unavailable once a number was communicated.**
- [L] Reg 282 Art 18(1)(a) and the proviso in Art 18(2) second subparagraph ("as long as that customer has not communicated his individual VAT identification number").
- [G] EC VIES FAQ Q3 ("the supplier will charge VAT") and Q7.
- [P] Stripe: merchant decides what to do with an `unverified` tax ID; the platform displays it "whether or not it's valid".

**V4. A VIES outage is not evidence of anything; the presumption is not obtained; absent other proof the supplier must charge VAT. No provision shifts that risk.**
- [L] Reg 282 Art 18(1)(a) ("obtains confirmation"); Art 18(1)(b) is limited to numbers not yet issued; Art 25.
- [G] EC VIES FAQ Q20; FAQ Q14 (parts of the system may be unavailable).
- [P] Stripe: "Stripe automatically handles VIES downtime and attempts retries for you" — retries, not a legal substitute for confirmation.
- **UNVERIFIED:** no judicial authority on outage; the "no risk-shift" conclusion is a reading of the absence of any such provision.

**V5. Art 18 is a presumption, not the only means of proof: the substantive question is whether the customer is a taxable person, and other evidence can establish it.**
- [L] Directive Arts 9, 43; Reg 282 Art 17 and Art 18(1)(b) ("any other proof"); VSTR ¶52 (other information may suffice).
- [J] VSTR ¶49–52; Euro Tyre ¶29–32.
- [G] EC VIES FAQ Q7 (a correct number may not validate because the member state requires a separate intra-EU registration) — a case where a VIES "invalid" does not prove non-taxable status.

**V6. VIES cannot confirm past validity; a check speaks only to its own date.**
- [L] Reg 904/2010 Art 31(1) (present-tense confirmation); Art 17(1)(c) (invalidity dates held, but no historical query duty).
- [G] EC VIES FAQ Q6: "It is not possible to confirm the validity of a VAT number in the past. It is possible to do it only for the current day."
- [P] Stripe: "After a tax ID is confirmed as valid or invalid, it won't be validated again automatically."

**V7. There is no grace period in law for last-known-valid evidence.** See §2.

**V8. Records must be sufficient for VAT to be applied and checked; invoices retained per national law; OSS records 10 years.**
- [L] Directive Arts 242, 244, 247; Art 369k(2); KMS §36(1)1) and §36(1)7).
- [G] EMTA VAT accounting page: invoices kept "in chronological order for 7 years as of the date of their issue or receipt" (§36(1)).
- [P] PwC Estonia (reviewed 29 May 2026) does not cover retention; **UNVERIFIED** at practitioner level, but two classes are satisfied.

**V9. The Art 226 list is exhaustive for VAT purposes and the reverse-charge mention is a separate element.**
- [L] Art 226 chapeau ("only the following details are required"); Art 226(11) (exemption reference) and Art 226(11a) ("where the customer is liable for the payment of the VAT, the mention 'Reverse charge'"). KMS §37(7)–(8).
- [G] EC invoicing page: "Where the customer is liable for tax under the reverse-charge procedure, the invoice must include the words 'reverse charge'"; EMTA *Other references and notes*: "If supply is subject to reverse charge, the invoice must contain 'reverse charge' regardless of whether such supply is tax-exempt supply or the supply is subject to the 0% rate."
- [P] Stripe (tax IDs printed on invoice and credit-note PDFs).

**V10. For a cross-border reverse charge the supplier's member-state invoicing rules apply; for OSS the member state of identification's rules apply.**
- [L] Art 219a(2)(a)(i) and (2)(b).
- [G] EC invoicing page (general framework).
- [P] **UNVERIFIED** — no practitioner source retrieved specifically on this point; two classes satisfied.

**V11. Invoice timing: 15th of the following month for Art 196 services; Estonia 7 days generally.**
- [L] Art 222; KMS §37(1) (7 calendar days from supply or from the last day of the taxable period under §11(4)) and §37(2¹) (15th of the following month for intra-Community supplies and §10(4)9) services).
- [G] EMTA *Issuance of invoices* — same three rules.
- [P] PwC Estonia confirms the monthly return deadline (20th) but not invoice timing; two classes satisfied.

**V12. Estonian reporting: cross-border B2B services go in the VD (recapitulative) statement, not KMD INF.**
- [L] Directive Arts 262(1)(c), 263, 264.
- [G] EMTA *Filing VAT returns and reports*: KMD INF parts A/B cover domestic sales/purchases where the partner total is at least EUR 1,000; the VD report covers cross-border B2B services "subject to taxation … in the Member State of the recipient", entered in "column 5 of Form VD", monthly, due "by the 20th day of the month following the taxable period".
- [P] **UNVERIFIED**; two classes satisfied.

**V13. Tax point for recurring SaaS is per period, not per invoice generation.**
- [L] Arts 63, 64(1), 65; Art 66's final paragraph excludes Art 196 services from the invoice/payment derogations; KMS §11(1) and §11(4) (quoted in §6 below).
- [G] EMTA *Issuance of invoices*: for long-term and recurring services the invoice is due within 7 days of the last day of the taxable period under §11(4).
- [P] **UNVERIFIED**; two classes satisfied.

**V14. The rate is the one in force at the tax point; a rate change does not re-rate earlier periods.**
- [L] Art 93 first paragraph; Art 95.
- [G] EMTA rate guidance (24 % from 1 July 2025).
- [P] PwC Estonia (24 % standard rate).

**V15. Re-verification at each renewal: the evidence must support the position at each tax point, but there is no statutory duty to query VIES every time.**
- [L] Reg 282 Art 25; Directive Art 63; Tóth point 3 (no general verification duty absent red flags); VSTR ¶52 (good faith + every reasonable measure).
- [G] EC VIES FAQ Q6 (current day only).
- [P] Stripe: no automatic re-validation; the merchant decides when and how to re-check.

**V16. If the supplier charges VAT, it owes that VAT even if the charge was unnecessary; correcting it requires a credit note that specifically and unambiguously refers to the original invoice.**
- [L] Art 203 ("VAT shall be payable by any person who enters the VAT on an invoice"); Art 219; KMS §37(4).
- [G] EC invoicing page (credit note must contain "specific, unambiguous reference to the initial invoice").
- [P] **UNVERIFIED**; two classes satisfied.

---

## 2. A3 — The grace-period question, answered explicitly

**There is no grace period in law.** No provision of Directive 2006/112/EC, Implementing Regulation 282/2011 or Regulation 904/2010 permits a supplier to rely on a confirmation obtained at an earlier date for a bounded period. Specifically:

1. **Art 18 does not state a validity period.** It states a condition: the supplier "obtains confirmation". It says nothing about how long a confirmation lasts, and nothing about relying on one that has aged.
2. **Art 25 supplies the temporal rule and it points the other way:** "only the circumstances existing at the time of the chargeable event shall be taken into account". A confirmation obtained 80 days before the tax point is a circumstance existing *then*, not at the tax point. Recital 22 confirms that the time of determination is meant to be fixed.
3. **The confirmation service itself cannot produce historical evidence.** Reg 904/2010 Art 31(1) is present-tense; the Commission states flatly that "It is not possible to confirm the validity of a VAT number in the past. It is possible to do it only for the current day" (FAQ Q6). A later check therefore cannot retroactively cure an earlier supply, and an earlier check cannot prospectively cure a later one.
4. **No administrative guidance recognises a grace period.** Neither the Commission's VIES FAQ nor EMTA's invoicing/reporting guidance contains a "last known valid for N days" rule. (Searched; none found.)
5. **The closest judicial doctrine is reliance, not a clock.** Mecsek-Gabona ¶63–64 protects a supplier who relied on a register entry that was valid when it was made, where the register was later corrected **with retroactive effect**. That is materially different from a supplier who simply has not checked since onboarding: in Mecsek the supplier *had* checked and the *register itself* changed afterwards. It is authority for "a later retroactive cancellation does not retroactively destroy a valid check", not for "an old check stays good for 90 days".

**Conclusion.** The repo's `VAT_EVIDENCE_MAX_AGE_DAYS = 90` is a **POLICY choice**, not a legal entitlement. It is a defensible control (it bounds exposure and forces periodic re-checks), but:
- it is **not** a statutory validity period and must not be described as one;
- it is **over-inclusive** in one direction: the law does not say a 91-day-old confirmation is worthless if there is no information to the contrary and the substantive conditions are met (VSTR ¶52; Euro Tyre ¶32) — charging VAT on that basis is conservative, not compelled;
- it is **under-inclusive** in the other: a one-day-old confirmation does not help if the supplier has other "information to the contrary" (Art 18 chapeau) — the age test does not test the thing the article actually tests.

The comment in `vat_rates.rs` that "90 days … roughly matches the cadence at which member states re-check registration data" is an assertion with no source. No such cadence is published in Reg 904/2010 or by the Commission. It should be removed or marked as an internal control rationale.

---

## 3. A4 — Record-keeping

**Directive.**
- **Art 242:** "Every taxable person shall keep accounts in sufficient detail for VAT to be applied and its application checked by the tax authorities." This is the general standard; it is outcome-based, not a field list.
- **Art 244:** copies of invoices issued and all invoices received must be stored.
- **Art 247(1):** "Each Member State shall determine the period throughout which taxable persons must ensure the storage of invoices relating to the supply of goods or services in its territory and invoices received by taxable persons established in its territory." Retention length is therefore national.
- **Art 369k(1)–(2)** (Union OSS): records of the transactions covered by the scheme, "sufficiently detailed to enable the tax authorities of the Member State of consumption to verify that the VAT return is correct", available electronically, kept "for a period of 10 years from 31 December of the year during which the transaction was carried out."
- **Art 242a** (electronic interfaces): 10 years — not applicable to ApexMail as a seller unless it operates a marketplace.
- **Art 233** (invoice integrity): authenticity of origin, integrity of content and legibility must be ensured from issue to the end of the storage period; the taxable person chooses the business controls.

**Estonia (KMS).**
- **§36(1)1):** preserve copies of issued invoices and received invoices "in chronological order for seven years as of the date of their issue or receipt. The information set out in an invoice shall be preserved in its original form."
- **§36(1)7):** marketplace records — 10 years from the end of the year of supply.
- **§36(4):** the taxable person may choose where and how invoices are preserved, provided immediate availability on request.

**Applied to ApexMail.** The binding retention floor for ordinary invoices is 7 years (KMS §36(1)1)). The OSS record duty is 10 years (Art 369k(2)), and it attaches to the OSS transactions regardless of the domestic 7-year rule. The practical retention period for *all* VAT evidence is therefore 10 years, which is what the repo memo recommends and what a system building audit trails should implement. Reg 282/2011 Art 42 is about card-handling fees in the taxable amount and is not a record-keeping provision — the brief's guess is wrong.

---

## 4. A5 — Invoicing

### 4.1 Which rules apply (Art 219a)

- General rule: the rules of the member state where the supply is deemed to be made (Art 219a(1)).
- Derogation: the supplier's member state where the supplier is not established in the member state of taxation and the customer is liable (reverse charge), unless the customer issues the invoice (self-billing) — Art 219a(2)(a)(i).
- Derogation: the member state of identification where the supplier uses an OSS scheme — Art 219a(2)(b).

For ApexMail: Estonian rules apply to (i) cross-border reverse-charge B2B, (ii) OSS B2C, and (iii) domestic supplies.

### 4.2 The Art 226 list (verbatim, including the reverse-charge element)

> **Article 226**
> Without prejudice to the particular provisions laid down in this Directive, only the following details are required for VAT purposes on invoices issued pursuant to Articles 220 and 221:
> (1) the date of issue;
> (2) a sequential number, based on one or more series, which uniquely identifies the invoice;
> (3) the VAT identification number referred to in Article 214 under which the taxable person supplied the goods or services;
> (4) the customer's VAT identification number, as referred to in Article 214, under which the customer received a supply of goods or services in respect of which he is liable for payment of VAT, or received a supply of goods as referred to in Article 138;
> (5) the full name and address of the taxable person and of the customer;
> (6) the quantity and nature of the goods supplied or the extent and nature of the services rendered;
> (7) the date on which the supply of goods or services was made or completed or the date on which the payment on account referred to in points (4) and (5) of Article 220 was made, in so far as that date can be determined and differs from the date of issue of the invoice;
> (7a) where the VAT becomes chargeable at the time when the payment is received in accordance with Article 66(b) … the mention 'Cash accounting';
> (8) the taxable amount per rate or exemption, the unit price exclusive of VAT and any discounts or rebates if they are not included in the unit price;
> (9) the VAT rate applied;
> (10) the VAT amount payable, except where a special arrangement is applied …;
> (10a) where the customer receiving a supply issues the invoice instead of the supplier, the mention 'Self-billing';
> (11) in the case of an exemption, reference to the applicable provision of this Directive, or to the corresponding national provision, or any other reference indicating that the supply of goods or services is exempt;
> (11a) where the customer is liable for the payment of the VAT, the mention 'Reverse charge';
> (12) … new means of transport …;
> (13) … 'Margin scheme — Travel agents';
> (14) … 'Margin scheme — Second-hand goods' …;
> (15) … tax representative ….

Points (7a), (10a) and (11a) are all separate elements. **Art 226(11) is the exemption reference; the reverse-charge notation is Art 226(11a).** They are not interchangeable.

Related provisions:
- **Art 219:** "Any document or message that amends and refers specifically and unambiguously to the initial invoice shall be treated as an invoice." (This, not Art 224, is the credit-note rule. Art 224 is self-billing.)
- **Art 220(1)(1):** an invoice is required for supplies to another taxable person or a non-taxable legal person. B2C invoices are not mandatory at EU level; Art 221 lets member states require them.
- **Art 222:** for Art 196 services, "an invoice shall be issued no later than on the fifteenth day of the month following that in which the chargeable event occurs."
- **Art 223:** summary invoices are allowed where VAT becomes chargeable in the same calendar month.
- **Art 226a:** a supplier not established in the member state of taxation may omit points (8), (9) and (10) and instead indicate the taxable amount by reference to quantity/extent and nature. This is an option, not an obligation; ApexMail does not need it.
- **Art 230:** amounts may be in any currency, but the VAT payable must be expressed in the national currency using the Art 91 mechanism. For Estonia (euro) this is moot.
- **Art 232–233:** electronic invoicing requires the recipient's acceptance; authenticity/integrity/legibility must be ensured for the storage period.

### 4.3 Estonia — KMS §37 (verbatim, English consolidated text in force 1 Jan 2024 – 30 Dec 2024)

**Timing.**
> §37(1): "A taxable person shall issue an invoice for the transfer of goods or provision of services within seven calendar days as of the date on which the goods are dispatched or made available to the purchaser or the services are provided or as of the last day of the taxable period specified in subsection 4 of § 11 of this Act …"

> §37(2): "If the supply is created upon receipt of full or partial payment for the goods or services, an invoice shall be issued within seven calendar days as of the date of receipt of full or partial payment …"

> §37(2¹): "In the event of the Intra-Community supply of goods or upon the provision of service specified in clause 9 of subsection 4 of § 10 of this Act to a taxable person or taxable person with limited liability in another Member State, a taxable person shall issue an invoice by the fifteenth day of the month following the month in which the goods are dispatched or made available or the service is provided."

**Scope.**
> §37(1¹): an invoice under §37 is required where the place of supply is Estonia, and also where the place of supply is a third country, and for supplies taxable in the member state of the customer to a person registered there — unless the customer self-bills.

> §37(3): no §37-compliant invoice is required for supplies to a natural person for personal use, except intra-Community distance selling, a new means of transport, or an export treated as such.

**Credit notes and self-billing.**
> §37(4): "A document, including a credit invoice, which amends an initial invoice and which contains a reference to the initial invoice shall be deemed to be an invoice."

> §37(5): self-billing requires a prior written agreement with a procedure for acceptance of each invoice.

**Content.**
> §37(7): "The following shall be set out in an invoice:
> 1) the serial number and date of issue of the invoice;
> 2) the name and address of the taxable person and the person's registration number as a taxable person;
> 3) the name and address of the acquirer of goods or the recipient of services;
> 4) the registration number of the acquirer of goods or the recipient of services as a taxable person if the acquirer of goods or the recipient of services has tax liabilities upon the acquisition of goods or receipt of services;
> 5) the name or a description of the goods or services;
> 6) the quantity of goods or extent of the services;
> 7) the date of dispatch of the goods or provision of the services or the date of receipt of full or partial payment for the goods or services if the date can be determined and differs from the date of issue of the invoice;
> 8) the price of the goods or services exclusive of value added tax and any discounts, if these are not included in the price;
> 9) the taxable amount broken down by different rates of value added tax together with the applicable rates of value added tax or the amount of supply exempt from tax;
> 10) the amount of value added tax payable, except in the cases provided by law. The amount of value added tax shall be indicated in euros."

> §37(8)2): "where the acquirer of goods or the recipient of services is liable to pay the tax, the reference 'reverse charge' if the place of supply of goods is not Estonia and in the cases specified in § 41¹ of this Act".

**The notation.** The Directive requires "Reverse charge" wherever the customer is liable (Art 226(11a)). EMTA says the note is required "regardless of whether such supply is tax-exempt supply or the supply is subject to the 0% rate", and also where the supply is in another member state under the broad reverse charge (Art 194). The Estonian English text of §37(8)2) says "if the place of supply of **goods** is not Estonia" — see conflict C7; that is either a translation artefact or a narrower domestic drafting. For a service sold from Estonia to a taxable person in another member state, the Directive requires the note; EMTA's guidance says to add it; the repo adds it. That is the right result.

**§37¹.** The brief refers to "§37¹ (invoice content)". In the English consolidated text in force 1 January 2024 – 30 December 2024 there is **no §37¹**: the paragraph sequence runs §36, §36¹, §37, §38, and invoice content is §37(7)–(8). The Estonian-language current version may have added a §37¹ after that translation (e.g. an e-invoicing or amendment provision); **UNVERIFIED**. The substantive rules the brief is asking about are in §37.

---

## 5. A6 — Estonia specifics

**Place of supply for B2B services (KMS §10(4)9)):**
> "services are provided in the cases not specified in clauses 1–8 of this subsection and subsection 2 of this section through a seat or permanent business establishment in Estonia to a taxable person or taxable person with limited liability registered in another Member State or to a third country person engaged in business." *(i.e. the place of supply is not Estonia)*

This is the domestic implementation of Art 44. It is keyed to the customer being **registered** in another member state — which is why the VAT number matters operationally even though Art 18 is a presumption.

**Which return carries what.**

| Supply | Return / statement | Legal basis | Deadline |
|---|---|---|---|
| Cross-border B2B service, reverse charge (this case) | **VD report**, column 5 (services) | Directive Arts 262(1)(c), 263, 264; KMD/VD rules | Monthly, by the **20th** of the following month (EMTA) |
| Domestic B2B / B2C sales and purchases | **KMD** + **KMD INF** parts A (sales) and B (purchases), only where the partner total is at least **EUR 1,000** ex-VAT | EMTA | Monthly, with KMD |
| B2C cross-border (OSS) | **KMD** + OSS quarterly return | Arts 369a–369k | Quarterly, end of month following the quarter |

**KMD INF is not the EU Sales List.** The ESL is the VD report. KMD INF is a domestic transaction annex with a EUR 1,000 per-partner threshold. The brief's parenthetical "(EU Sales List / KMD INF?)" conflates two different returns; the correct answer is VD.

The VD report must show the customer's VAT identification number and the value of the services (Art 264(1)(a)–(b)); services that are exempt in the member state where they are taxable are excluded from Art 262(1)(c), but reverse-charged SaaS is taxable, so it belongs in the VD.

---

## 6. B — Renewals across tax points

### 6.1 The tax point for recurring services

**Directive.**
- **Art 63:** "The chargeable event shall occur and VAT shall become chargeable when the goods or the services are supplied."
- **Art 64(1):** "Where it gives rise to successive statements of account or successive payments, … the supply of services shall be regarded as being completed on expiry of the periods to which such statements of account or payments relate." A monthly subscription is the paradigm: each month's period completes on its expiry.
- **Art 64(2), second subparagraph:** "Supplies of services for which VAT is payable by the customer pursuant to Article 196, which are supplied continuously over a period of more than one year and which do not give rise to statements of account or payments during that period, shall be regarded as being completed on expiry of each calendar year until such time as the supply of services comes to an end." This is the long-term reverse-charge service rule; a monthly-billed SaaS does not need it, but a multi-year prepaid enterprise contract with no interim billing does.
- **Art 65:** an advance payment is taxable on receipt.
- **Art 66:** member states may move the tax point to invoice or payment — but the final paragraph says: "The derogation provided for in the first paragraph shall not, however, apply to supplies of services in respect of which VAT is payable by the customer pursuant to Article 196". So for the reverse-charge B2B SaaS, the tax point cannot be deferred to the invoice date. This is a point the repo's comments get wrong (see F9).

**Estonia (KMS §11).**
> §11(1): "The time of supply or the time of receipt of services is deemed to be the date on which the first of one of the following acts is performed: 1) the goods are dispatched or made available to the purchaser, or the services are provided; 2) full or partial payment is received for the goods or services or, in the case of the receipt of services, full or partial payment is made; 3) in the case of self-supply, …"

> §11(3): "If, according to subsection 1 of this section, the time of supply is the time at which full or partial payment is received or made for the goods or services, supply is deemed to have been effected in the amount of the payment."

> §11(4): "If the provision of services continues for longer than a period of taxation, the services are deemed to have been provided and received during the taxable period in which the provision of the services terminates. In the case of the provision of services or regular transfers of goods to the same purchaser, the time at which the goods are dispatched or made available to the purchaser or the time at which the services are provided and received is deemed to be the taxable period overlapping with the end of the period of time for which an invoice is submitted or during which payment for goods or services received is to be made as agreed, **but not later than after twelve calendar months**. Upon provision of service, in the case of which a tax liability arises for the recipient of the service, within a longer period of time than one year, the supply of the service shall be deemed to have been created or the service received, as of the commencement of the provision of the service, **on 31 of December of each calendar year** if the services have not been paid for and the provision of the services has not been completed within the period."

**Applied.** For a monthly SaaS subscription billed monthly, Estonia's §11(1) makes the tax point the **earlier** of the service being provided or the payment being received. The invoice generation date is not the tax point. If the subscription is billed annually in advance, the payment date is the tax point for the prepaid amount (§11(1)2), §11(3); Art 65 and Art 93 then fix the rate at the time VAT becomes chargeable. If the contract is a multi-year reverse-charge service with no interim billing, §11(4) imposes an annual 31 December tax point.

### 6.2 Is re-verification at each renewal legally required?

Distinguish three questions:

**(a) Must the supplier's evidence be current at the tax point?** Yes, in substance. Art 25 requires the status to be determined on the circumstances at the chargeable event, and Art 18's presumption is about what the supplier "obtains". A check performed at onboarding cannot, by itself, establish the position at a renewal eleven months later if the position is challenged, because VIES answers only for the day of the check (FAQ Q6) and cannot confirm the past (or the future).

**(b) Must the supplier query VIES at every renewal?** No provision says so. The general standard is good faith and "every measure which can reasonably be required" (VSTR ¶52; Mecsek ¶48), and the authorities cannot demand verification where there is no material suggesting irregularities (Tóth point 3; Bonik). A supplier that has a valid recent confirmation tends to satisfy that standard; a supplier that has none carries the burden (VSTR ¶43).

**(c) What is the difference?** The obligation is **evidential**, not procedural. The law does not prescribe a query schedule; it prescribes a result — the supplier must be able to show that the conditions were met at each tax point. A re-query at each renewal is the cleanest way to produce that evidence, and is what the market does (Chargebee's documented behaviour is validation at creation, at VAT-number update and at renewal — cited in the repo memo; the Chargebee page itself could not be re-fetched on 30 Oct 2026, so that leg is **UNVERIFIED** here). But a supplier that can prove taxable status by other evidence at the tax point is not in breach merely because it did not re-query. Conversely, a supplier that re-queries but ignores "information to the contrary" (Art 18 chapeau) is in breach despite the query.

**The repo's cadence.** `plan_billing.rs` calls `revalidate_for_tenant` before computing each renewal quote, and `quote_for_tenant` re-reads the persisted evidence at `Utc::now().date_naive()`. That is a prudent cadence and is consistent with (a) and (b). Two caveats in §8 (F9, F10): the date used is the invoice date, not the chargeable-event date; and a recorded outage row shadows the prior valid row.

### 6.3 Rate changes mid-contract

- **Art 93:** "The rate applicable to taxable transactions shall be that in force at the time of the chargeable event." Second paragraph: for advance payments (Art 65) and Art 66 cases, the rate at the time VAT becomes chargeable.
- **Art 95:** where rates change, member states may make adjustments in Art 65/66 cases and adopt transitional measures.
- **Applied:** each monthly period is a separate tax point, so a rate change applies from the first tax point on or after the change; earlier periods are not retroactively re-rated. For an annual prepayment, the payment is the tax point (Art 65; KMS §11(1)2)), so the rate at receipt generally governs the prepaid amount; Art 95 lets Estonia adjust. Whether Estonia has exercised that option for subscriptions spanning a rate change could not be confirmed from primary Estonian material — **UNVERIFIED**, consistent with the repo memo's own flag.
- **Credit notes** use the original tax point's rate and must refer specifically and unambiguously to the original invoice (Art 219; KMS §37(4)).

---

## 7. Conflict list (primary text quoted where the sources disagree)

**C1. The brief's "Art. 226(11) reverse-charge notation" is off by one element.**
Primary text: Art 226(11) is the *exemption* reference; Art 226(11a) is "where the customer is liable for the payment of the VAT, the mention 'Reverse charge'". Both exist; they are not alternatives. The repo memo gets this right in §2.4 but the brief's shorthand does not. Resolution: cite **Art 226(11a)**.

**C2. The brief's "credit notes Art. 224?" is a mis-citation.**
Art 224 is **self-billing** ("Invoices may be drawn up by the customer … where there is a prior agreement between the two parties"). The credit-note rule is **Art 219**: "Any document or message that amends and refers specifically and unambiguously to the initial invoice shall be treated as an invoice." Estonia: KMS §37(4).

**C3. Simplified-invoice threshold: Directive EUR 100 vs Estonian §37(9) EUR 160.**
Directive Art 220a(1)(a): "where the amount of the invoice is not higher than EUR 100 or the equivalent in national currency". KMS §37(9): "A simplified invoice may be issued, provided that the amount indicated in the invoice does not exceed 160 euros exclusive of value added tax". The repo memo repeats the EUR 160 figure without noting the Directive's EUR 100. Resolution: for ApexMail this is immaterial (no simplified invoices are intended), but the memo's statement is domestically correct and EU-questionable; flag it rather than rely on it.

**C4. The repo memo omits Art 18(2), second subparagraph — the legal basis for the "no number ⇒ consumer" branch.**
Repo memo §2.2 quotes Art 18(1) and the first sentence of Art 18(2) only. The consolidated Regulation adds: "However, irrespective of information to the contrary, the supplier of telecommunications, broadcasting or electronically supplied services may regard a customer established within the Community as a non-taxable person as long as that customer has not communicated his individual VAT identification number to him." Without this sentence the memo's "if it does not communicate a VAT number, the supplier may treat it as non-taxable" has no clean citation for TBE services. Correction: cite Art 18(2) second subparagraph.

**C5. The repo memo overstates the outage rule.**
Repo memo §2.3: "A VIES outage is not valid evidence. The correct treatment is to fail closed: charge VAT." The Commission's answer is conditional: "**If you believe that your customer is not a taxable person**, you should not exempt the supply but should charge VAT" (FAQ Q20). An outage is not evidence of non-taxable status; it is the absence of evidence. If the supplier has other proof of taxable status, the law does not compel VAT (Art 18(1)(b) logic; VSTR ¶52). Fail-closed is prudent and defensible; it is not the only lawful outcome. Correction: label it "prudent default", not "the correct treatment".

**C6. The code's justification for 90 days contradicts the memo's own "UNVERIFIED".**
`vat_rates.rs` comments: "90 days is deliberately shorter than a quarterly OSS cycle and roughly matches the cadence at which member states re-check registration data." The memo itself says (§2.7) "The legal requirement is evidence at the tax point, not a fixed statutory validity period; the horizon is a control, not a law. **UNVERIFIED** as to any Member State's specific acceptance period." No cadence of member-state re-checking is published in Reg 904/2010 or by the Commission. Resolution: delete the "cadence" sentence; keep "internal control".

**C7. KMS §37(8)2) says "goods"; Art 226(11a) says "the customer is liable".**
KMS §37(8)2) (English): "where the acquirer of goods or the recipient of services is liable to pay the tax, the reference 'reverse charge' if the place of supply of **goods** is not Estonia and in the cases specified in § 41¹ of this Act". Art 226(11a): "where the customer is liable for the payment of the VAT, the mention 'Reverse charge'" — no goods/services limitation. EMTA's guidance resolves it in favour of the Directive: the note is required for reverse-charge supplies regardless of exemption or 0 % rate. Resolution: follow Art 226(11a) + EMTA; treat the English "goods" as a translation artefact. **UNVERIFIED** as to the Estonian-language wording.

**C8. "KMS §37 / §37¹" — §37¹ does not exist in the English consolidated text in force 1 Jan 2024 – 30 Dec 2024.**
The paragraph sequence is §36, §36¹, §37, §38. Invoice content is §37(7)–(8); timing is §37(1), (2), (2¹); credit notes §37(4); self-billing §37(5). Either the brief refers to a later Estonian amendment not yet translated, or it is a mis-citation. Resolution: cite §37; do not cite §37¹ without the Estonian text.

**C9. Vendor practice conflicts with Art 18.**
Stripe Tax documentation: "If you use Stripe Tax, Stripe Tax applies the reverse charge or zero rate according to applicable laws when the tax ID has the required number format, **regardless of the government verification result**." That is a format-only test. Art 18(1)(a) requires an obtained confirmation of validity and associated name/address. Resolution: vendor practice is evidence of market convention, not a safe harbour; the repo is right to reject the structural check.

**C10. "ESL / KMD INF" conflation.**
KMD INF parts A/B are domestic, with a EUR 1,000 per-partner threshold. The EU Sales List is the **VD report**, column 5 for services, monthly by the 20th (EMTA). Resolution: VD, not KMD INF.

**C11. The code's "tax point = renewal invoice date" conflicts with Art 63/64 and KMS §11.**
`plan_billing.rs` comments: "re-resolve the buyer's tax status and the dated rate AT THIS TAX POINT (the renewal invoice date)" and passes `now.date_naive()`. Art 63 fixes the chargeable event at the supply; Art 64(1) at the expiry of the period; KMS §11(1) at the earlier of supply or payment. The invoice date is not the tax point. Resolution: use the chargeable-event date (period start or payment date), and store it.

**C12. Art 66 does not let Estonia move the reverse-charge tax point to the invoice date.**
Art 66 final paragraph: "The derogation provided for in the first paragraph shall not, however, apply to supplies of services in respect of which VAT is payable by the customer pursuant to Article 196". Any design that treats the invoice date as the tax point for reverse-charged B2B services is wrong as a matter of EU law, not merely Estonian law.

**C13. Reg 282/2011 Art 42 is not a record-keeping provision.**
The brief asks whether "Reg 282/2011 Art 42? (if relevant)" applies to record-keeping. It does not: Art 42 is about card-handling fees forming part of the taxable amount. There is no service-sector record-keeping article in Reg 282/2011; the obligation is Art 242 of the Directive plus national law.

**C14. The repo memo's "evidence at the tax point" is right, but the code tests age, not information.**
The memo (§2.7, §5.4) says the requirement is evidence at the tax point. The code's test is `at - valid_from <= 90 days`. That is a proxy. It does not test the Art 18 chapeau ("unless he has information to the contrary"), which is the actual legal condition. Resolution: keep the age bound as a control, but do not present it as the legal test.

---

## 8. Code-facing findings

### 8.1 The policy, branch by branch

| Branch | What the code does | Legal basis | CJEU support | Label |
|---|---|---|---|---|
| Verified EU business abroad ⇒ 0 % reverse charge | `reverse_charge_authorised` requires source=VIES, outcome=Valid, no outage, matching number/country, `at >= valid_from`, `at <= valid_until`, age ≤ 90 d; invoice snapshots `vat_evidence_id` | Directive Arts 44, 196; Reg 282 Art 18(1)(a); KMS §10(4)9) | VSTR ¶49–52; Euro Tyre ¶28–32; Mecsek ¶63–64 | **Law**, with a policy overlay (the 90-day bound is not law) |
| Unverified ⇒ VAT | `calculate_vat_with_evidence` falls through to the destination rate | No number communicated: Reg 282 Art 18(2) 2nd subpara → non-taxable → Art 58 destination VAT. Number communicated but invalid/outage: Art 18(1)(a) presumption unavailable → charge VAT as the prudent default | VSTR ¶52 (other proof may suffice, so VAT is not always compelled) | **Law** where no number was communicated; **POLICY (conservative)** where a number was communicated but could not be confirmed |
| VIES outage ⇒ last-known-valid within 90 days, else VAT | Documented in `tax.rs` and `vat_rates.rs` | **None.** No provision permits reliance on prior evidence for a bounded period; Art 25 points to the chargeable event; FAQ Q6 says VIES is current-day only | Mecsek ¶63–64 protects reliance on a register entry that was valid when made and later cancelled retroactively — not a time-limited grace | **POLICY, no direct legal basis** |

Two further branch-level points:

- **The "unverified ⇒ VAT" branch is not always legally compelled.** If the supplier has other proof that the customer is a taxable person (contract, business registry extract, certificate, payment from a business account), Art 18(1)(b)'s logic and VSTR ¶52 permit zero-rating in good faith. The code's binary is deliberately stricter; that is defensible, but it should be described as a policy of refusing to use other proof, not as a legal requirement.
- **Charging VAT is not a neutral fallback.** Art 203 makes the supplier liable for VAT it enters on an invoice. If the customer was in fact a taxable person, the supplier has over-collected and must correct by credit note (Art 219; KMS §37(4)) and repay or credit the customer. The code's fail-closed default therefore creates a correction workload, not just a conservative tax outcome.

### 8.2 The evidence table

**What exists (migration 218, `vat_validation_evidence`):** `id`, `customer_id`, `tenant_id`, `vat_number`, `country`, `source` (CHECK = 'VIES'), `requested_at` (timestamptz), `valid`, `returned_name`, `returned_address`, `authority_request_id`, `response_hash`, `valid_from` (date), `valid_until` (date, nullable), `outage_state`, `created_at`, plus CHECKs that an outage is never valid and that `valid_until >= valid_from`. This is a good audit record.

**What the decision actually sees (`VatValidationEvidence`):** `id`, `vat_number`, `country`, `source`, `outcome`, `valid_from`, `valid_until`, `outage_state`. **The struct drops `requested_at`, `returned_name`, `returned_address`, `authority_request_id` and `response_hash`.** Consequences:

1. **Art 18(1)(a)'s "associated name and address" cannot be evaluated at decision time.** The data is stored but not passed to `reverse_charge_authorised`, which never compares the VIES name/address with the billing name/address. The rule authorises a reverse charge on number + country + date alone. That is weaker than the article's text.
2. **The time of consultation is lost.** `valid_from` is a `DATE`; two consultations on the same day are indistinguishable, and the decision cannot reason about the exact instant. That is probably acceptable, but it means "evidence at the tax point" is tested at day granularity.
3. **There is no field for "information to the contrary".** Art 18's presumption is expressly defeasible. Red flags (mismatched name, residential address, free-mail domain, payment instrument inconsistent with the business, a number that VIES says is registered to a different entity) have nowhere to live in the decision, and `reverse_charge_authorised` has no parameter for them.
4. **There is no field for the customer's declaration.** `billing_addresses.is_business` and `vat_number` are the declaration, but the evidence row does not record which declaration version/timestamp the consultation was performed against. The DB has `customer_id`/`tenant_id`, not the declared name/address that was compared.
5. **`valid_until` is always NULL in practice.** `record_vat_validation_evidence` inserts `NULL` unconditionally. The operator-set horizon is therefore dead; the only horizon is the hard-coded 90 days.

**Minimum additional fields the law expects, on this evidence:**
- the name and address returned by VIES, and a match/no-match result against the customer's declared name/address;
- the date/time of the consultation and the VIES request reference;
- a record of contrary information (or an explicit "none known" at the decision time);
- the customer declaration (is_business, country, number, terms version, timestamp);
- the tax point the evidence is being applied to (stored on the invoice as `vat_evidence_id` is good; also store the chargeable-event date).

Art 242's "sufficient detail" standard is met by the DB; it is not met by the in-memory decision object, because the decision cannot reconstruct the name/address test that Art 18(1)(a) requires.

### 8.3 Invoice content against Art 226 and KMS §37

Cross-check of the repository's HTML invoice (`api-server/src/routes/billing.rs`, `render_invoice_html`) and the Estonian e-invoice XML (`render_invoice_xml`):

| Element | Required by | Present? | Finding |
|---|---|---|---|
| Date of issue | Art 226(1); KMS §37(7)1) | Yes ("Issued:") | OK |
| Sequential number | Art 226(2); KMS §37(7)1) | Yes (`invoice_number`, `YYYY-NNNNNN`) | OK |
| Supplier VAT number | Art 226(3); KMS §37(7)2) | Yes (`company_vat`) | OK |
| Customer VAT number | Art 226(4); KMS §37(7)4) | Conditional (`VAT: …` only if provided) | Present for reverse charge, but not labelled as the number under which the supply is received; no check that the printed number equals the one the evidence row validated |
| Full names and addresses | Art 226(5); KMS §37(7)2)–3) | Yes | OK |
| Nature and extent of services | Art 226(6); KMS §37(7)5)–6) | Description + quantity; billing period in the footer | Acceptable, but the period is a footnote rather than part of the line description |
| Date of supply if different from issue date | Art 226(7); KMS §37(7)7) | **No explicit tax-point field.** The template prints "Period: {start} to {end}" in the footnote | **Gap.** The chargeable-event date is not labelled as such, and for reverse charge (where Art 66's derogation does not apply) that date is the legally significant one |
| Taxable amount per rate | Art 226(8); KMS §37(7)9) | Per-line amounts and one subtotal; no per-rate summary | **Gap where more than one rate appears.** A single-rate invoice is fine; mixed-rate invoices need a per-rate breakdown |
| Unit price ex VAT | Art 226(8); KMS §37(7)8) | Yes | OK |
| VAT rate applied | Art 226(9); KMS §37(7)9) | Per line | OK |
| VAT amount payable | Art 226(10); KMS §37(7)10) | Yes (`vat_total`) | OK; label depends on `invoice_vat_label` |
| "Reverse charge" | Art 226(11a); KMS §37(8)2); EMTA | Yes, but conditionally | **Defect (F1 below)** |
| Currency | Art 230 | EUR assumed | OK for Estonia |

### 8.4 Findings, numbered

**F1 — The HTML invoice re-derives reverse charge from a structural check, not from the evidence row.** `billing.rs` (`render_invoice_html`, ~lines 2437–2462) computes `reverse_charge_applied = vat_total == 0 && country != "EE" && is_valid_vat_number(vat, Some(country))`. `is_valid_vat_number` is explicitly documented in `vat_rates.rs` as "structural" and "must never, by itself, authorise a 0 % reverse charge". The renderer therefore contradicts the module's own contract and can disagree with `invoices.vat_evidence_id`. It can also print "Reverse charge" on a **non-EU** 0 % invoice (any two-letter prefix with 8–12 body characters passes; only `EE` is excluded), where the correct statement is "outside the scope of EU VAT", not reverse charge. Fix: gate the note on the invoice's evidence row / a stored `reverse_charge` flag, and exclude non-EU countries.

**F2 — The e-invoice XML has no reverse-charge note and no supply date.** `render_invoice_xml` emits the Baltic e-invoice schema with `InvoiceDate`, `DueDate`, parties, items and totals, but no "Reverse charge" element and no chargeable-event date. If the XML is used as the statutory invoice (KMS §37(6) allows electronic invoices), it is missing Art 226(11a) and arguably Art 226(7).

**F3 — The evidence struct cannot perform the Art 18(1)(a) name/address test.** See §8.2. `returned_name`/`returned_address` are stored but never read by the decision; `reverse_charge_authorised` compares only number, country and dates.

**F4 — There is no representation of "information to the contrary".** Art 18's chapeau is the operative condition. The code has no field, no parameter and no test for it. A VIES "Valid" therefore always wins, even where the billing name is obviously different from the VIES name, the address is residential, or the payment instrument is a consumer card. This is the single largest gap between the code and the article.

**F5 — A recorded outage row shadows the previous valid row; the documented 90-day grace is unreachable in the common outage case.** `load_vat_evidence_for_tenant` (`invoices.rs` ~line 126) selects the newest row by `requested_at DESC` with no `valid = TRUE` filter. `validate_and_record` persists an outage row (`valid = FALSE`, `outage_state = …`) and returns `Ok`. So on a VIES fault at renewal, the newest row is the outage, `authorises_reverse_charge` fails, and the quote charges VAT — **immediately**, not after 90 days. The grace applies only when the HTTP call fails at the transport level (`Err`, no row written) or when no revalidation is attempted. Either the query should prefer the newest *valid* row within the bound (if the policy really is "last known valid"), or the docs/comments in `tax.rs` and `vat_rates.rs` should stop promising a grace that the query does not implement.

**F6 — `valid_until` is never set, so the only horizon is the hard-coded 90 days.** `record_vat_validation_evidence` binds `NULL` for `valid_until`. The "optional operator-set refresh horizon" is dead. If operators are expected to be able to shorten validity (e.g. for high-risk customers), the write path needs to accept a value.

**F7 — The 90-day bound is applied to fresh evidence too, and flips a genuinely valid customer to VAT on day 91.** `evidence_within_freshness_bound` is a hard gate inside `authorises_reverse_charge`. On day 91 after a valid check, with no contrary information and no new consultation, the customer is charged VAT. The law does not require that (Art 18 is about information, not age; VSTR ¶52; Euro Tyre ¶32). This is a policy decision that should be documented as such and, ideally, paired with an automatic re-query before the bound expires so that the flip is rare.

**F8 — `reverse_charge_authorised` cannot authorise a past tax point from a later check.** The `at >= valid_from` condition means a VIES check performed after the chargeable event can never support that event. That is correct on Art 25 and FAQ Q6, and is worth keeping explicitly (it prevents retroactive zero-rating by re-checking later). Do not "fix" it.

**F9 — The renewal path treats the invoice date as the tax point.** `plan_billing.rs` passes `now.date_naive()` to `quote_for_tenant` and the comment calls that "the renewal invoice date". Under Art 63/64 the chargeable event is the completion of the period (or the payment, under Art 65), and KMS §11(1) takes the earlier of provision or payment, with §11(4) fixing the period for recurring services. Where a renewal invoice is generated a day or two before/after the period boundary, or where payment lands in a different month, the rate and the evidence date can be wrong. Fix: resolve the chargeable-event date from the subscription period/payment and pass that to `quote_for_tenant`; store it on the invoice.

**F10 — Revalidation happens before the quote, which is right, but its failure mode is inconsistent.** `revalidate_for_tenant` returns `Err` only on a transport failure; a VIES fault is `Ok` + an outage row, which then (F5) blocks the grace. The log message "a VIES outage is logged and the quote falls back to the persisted evidence" is therefore wrong for fault responses. Fix the log/comment, or make the loader prefer the last valid row.

**F11 — The invoice stores the evidence id but not the evidence *date* or the chargeable-event date.** `invoices.vat_evidence_id` allows an auditor to join back to `vat_validation_evidence` (good), but the invoice itself does not show the tax point or the consultation date. Art 242's "sufficient detail" is met via the join; Art 226(7) is not met on the face of the document. Add the supply/tax-point date to the rendered invoice (and to the XML).

**F12 — The credit-note path references the invoice by `invoice_id`, which satisfies Art 219 in the database, but the rendered credit document was not verified to print the original invoice number.** `credit_notes.rs` links `invoice_id` and sums credits per invoice; the human-readable document must also contain a "specific and unambiguous reference to the initial invoice" (Art 219; KMS §37(4)). This needs a check on the renderer, not just the FK.

**F13 — Consumer invoices and OSS.** Estonia does not require a §37 invoice for a natural person's personal use (KMS §37(3)), so the repo's practice of issuing one is a service feature, not a statutory duty. If issued for an OSS supply, it should show the supplier's Estonian VAT number, the destination rate and the VAT amount (Art 226(3), (9), (10) applied through Art 219a(2)(b); Art 369g reporting). The invoice is not the OSS reporting instrument; the quarterly OSS return is.

**F14 — The 7-day/15th-day invoice deadlines are not enforced in code.** KMS §37(1) requires issue within 7 calendar days of the supply (or the end of the §11(4) period); §37(2¹) allows the 15th of the following month for §10(4)9) services. The renewal path invoices when the cycle end is due, which may be within 7 days in the normal case, but there is no guard that fails or alerts when an invoice is generated late (e.g. after dunning retries, `DUNNING_RETRY_COOLDOWN_SQL`). A late invoice is a compliance breach independent of the VAT amount.

**F15 — Retention.** The DB keeps evidence rows indefinitely (no delete path seen), which is compatible with the 7-year KMS / 10-year OSS floor. If a retention/pruning job is added later, it must not prune before 10 years for OSS-covered transactions.

---

## 9. What is settled, what is policy, what is unresolved

**Settled by primary law.**
1. Reverse charge for intra-EU B2B services: Arts 44, 196; Estonian §10(4)9).
2. Art 18(1)(a) evidence = communicated number + confirmation of validity + associated name and address via the Art 31 Reg 904/2010 system.
3. Art 18(2) second subparagraph: for TBE services, no communicated number ⇒ may treat as non-taxable, irrespective of contrary information.
4. Art 25: status is determined on the circumstances at the chargeable event.
5. VIES gives no historical confirmation (Reg 904 Art 31; EC FAQ Q6).
6. No grace period exists in the Directive, the Regulation or the Commission's guidance.
7. Invoice content: Art 226 (including 11a), KMS §37(7)–(8); timing Art 222 and KMS §37(1), (2¹).
8. Records: Art 242, Art 244, Art 247, Art 369k (10 years), KMS §36(1) (7 years).
9. Reporting: reverse-charged services in the VD (Arts 262–264), not KMD INF.
10. Tax point: Arts 63, 64(1), 65; Art 66 does not apply to Art 196 services; KMS §11(1), (4).
11. Rate: Art 93 (tax point governs).

**Policy, not law.**
1. The 90-day freshness bound (`VAT_EVIDENCE_MAX_AGE_DAYS`).
2. Refusing to use "other proof" of taxable status where VIES is unavailable or invalid.
3. Treating an outage as automatic VAT (the law permits it only where taxable status cannot be established).
4. Retaining evidence for 10 years rather than 7 (prudent, driven by OSS).

**Unresolved / UNVERIFIED.**
1. Whether Estonia has a current §37¹ and what it says (English text in force 1 Jan 2024 has none).
2. The Estonian-language wording of §37(8)2) ("goods" vs "goods or services").
3. Whether Estonia has exercised Art 95 for annual prepayments spanning a rate change.
4. Any CJEU authority directly on Art 18 for services, or on VIES outages (none found).
5. Chargebee's current renewal-validation documentation (page 404 on 30 Oct 2026; the repo memo's citation could not be re-confirmed).
6. Whether any member state operates an administrative tolerance for stale confirmations (none found in EU-level material; national tolerances were not surveyed).

---

## 10. Sources

| ID | Source | URL | Retrieved |
|---|---|---|---|
| S1 | Directive 2006/112/EC, consolidated 01.01.2025 (CELEX 02006L0112-20250101) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02006L0112-20250101 | 30 Oct 2026 (via `r.jina.ai`) |
| S2 | Implementing Regulation (EU) No 282/2011, consolidated 01.07.2022 (CELEX 02011R0282-20220701) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02011R0282-20220701 | 30 Oct 2026 (via `r.jina.ai`) |
| S3 | Implementing Regulation (EU) No 282/2011, original (CELEX 32011R0282) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32011R0282 | 30 Oct 2026 (via `r.jina.ai`) |
| S4 | Council Regulation (EU) No 904/2010 (CELEX 32010R0904) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32010R0904 | 30 Oct 2026 (via `r.jina.ai`) |
| S5 | C-587/10 VSTR (27 Sept 2012) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62010CJ0587 | 30 Oct 2026 |
| S6 | C-324/11 Tóth (6 Sept 2012) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62011CJ0324 | 30 Oct 2026 |
| S7 | C-285/11 Bonik (6 Dec 2012) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62011CJ0285 | 30 Oct 2026 |
| S8 | C-21/16 Euro Tyre (9 Feb 2017) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62016CJ0021 | 30 Oct 2026 |
| S9 | C-273/11 Mecsek-Gabona (6 Sept 2012) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62011CJ0273 | 30 Oct 2026 |
| S10 | European Commission, VIES FAQ | https://ec.europa.eu/taxation_customs/vies/faq.html | 30 Oct 2026 (via `r.jina.ai`) |
| S11 | European Commission, VAT invoicing rules | https://taxation-customs.ec.europa.eu/taxation/vat/vat-businesses/invoicing_en | 30 Oct 2026 |
| S12 | EMTA (Estonian Tax and Customs Board), *VAT accounting and invoices* and subpages (*Issuance of invoices*, *Information included on invoices*, *Other references and notes*, *The place of supply of services is not Estonia*) | https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-accounting-and-invoices | 30 Oct 2026 |
| S13 | Estonian VAT Act (KMS), English consolidated text in force 01.01.2024–30.12.2024, ELI `503012024001` | https://www.riigiteataja.ee/en/eli/ee/503012024001/consolide/current ; XML: https://www.riigiteataja.ee/public-api/api/v1/en/akt/503012024001/xml | 30 Oct 2026 |
| S14 | EMTA, *Filing VAT returns and reports* (KMD, KMD INF, VD) | https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/filing-vat-returns-and-reports | 30 Oct 2026 |
| S15 | PwC Worldwide Tax Summaries, Estonia — Other taxes (last reviewed 29 May 2026) | https://taxsummaries.pwc.com/estonia/corporate/other-taxes | 30 Oct 2026 |
| S16 | Stripe, *Account and customer tax IDs with Invoicing* | https://docs.stripe.com/tax/tax-ids | 30 Oct 2026 |

**Access note.** EUR-Lex returns an AWS WAF challenge (HTTP 202, zero bytes) to direct fetches from this environment; the WAF-free mirror used is the Jina Reader proxy of the same canonical URL. Riigi Teataja's HTML front end is an Angular SPA that renders only a shell without JavaScript; the act text was obtained from its public API's XML endpoint, which is the same underlying data the site renders. EMTA and the Commission pages were fetched directly.

---

*End of memo. No repository changes were made.*
