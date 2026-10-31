# VATDEEP-C — The VIES evidence freshness grace period: what is actually defensible

**Item:** accountant-open item 1 of 5 — the 90-day bound (`VAT_EVIDENCE_MAX_AGE_DAYS = 90`, billing-common `vat_rates.rs`), labelled "POLICY, no direct legal basis". This memo determines what IS defensible and supplies the replacement.

**Prepared:** 31 October 2026. **Retrieval date for every source below: 31 October 2026** (the VIES FAQ via a 26 June 2022 Wayback snapshot of the retired static page + the live REST API; see S5). **Status:** research memo. Not legal or tax advice. **No repository changes were made.**

**Sisters:** `docs/research/eu-vat-law-evidence-and-invoicing.md` (30 Oct 2026, "Sister-memo" below) established the baseline; this memo goes deep on the freshness question only.

**Method.** Three-source discipline per proposition: **[L]** primary law (Directive, Implementing Regulations, CJEU, Estonian acts), **[G]** official administrative guidance (Commission FAQ, VAT Committee guidelines, EMTA, BZSt/UStAE as reported), **[P]** practitioner/vendor class (German tax-firm analysis with case dockets, vendor documentation, court-of-instances case law as reported). Legs that could not be confirmed are marked **UNVERIFIED**. EUR-Lex was fetched through the Jina Reader proxy (direct fetches face an AWS WAF challenge, as in the sister memo).

---

## 1. The exact legal treatment of a stale VIES confirmation

### 1.1 Art 18 and the recitals — what the text does and does not say

**Reg 282/2011 Art 18(1)(a)** (consolidated 1 July 2022, verbatim; S2):

> "Unless he has information to the contrary, the supplier may regard a customer established within the Community as a taxable person: (a) where the customer has communicated his individual VAT identification number to him, and the supplier **obtains confirmation of the validity of that identification number and of the associated name and address** in accordance with Article 31 of Council Regulation (EC) No 904/2010 …"

The operative verb is present-tense and event-shaped: the supplier "obtains confirmation". **No validity period, no re-check interval, no shelf-life of a confirmation appears anywhere in the article.**

**Recitals** (original act, S3 — the consolidated text omits the preamble):

> (18) "The correct application of the rules governing the place of supply of services relies mainly on the status of the customer as a taxable or non-taxable person, and on the capacity in which he is acting. In order to determine the customer's status as a taxable person, it is necessary to establish what the supplier should be required to obtain as evidence from his customer."

> (19) "… Communication by the customer of his VAT identification number to the supplier is sufficient to establish that the customer is acting in his capacity as a taxable person, unless the supplier has information to the contrary. …"

> (20) "In order to determine the customer's place of establishment precisely, the supplier of the service is required to verify the information provided by the customer."

> (22) "The time at which the supplier of the service must determine the status, the capacity and the location of the customer, whether a taxable person or not, should also be specified."

Recital 22 + **Art 25** fix the *time* of assessment ("only the circumstances existing at the time of the chargeable event shall be taken into account"), and recital 18 frames Art 18 as an **evidence rule** ("what the supplier should be required to obtain as evidence"). Neither the recitals nor the article say how recent the evidence must be. **The regulation distinguishes nothing between a confirmation obtained the day before the tax point and one obtained 89 days before it.**

**Reg 904/2010 Art 31(1)** (S4, verbatim): the confirmation service evidences "the validity of the VAT identification number of any specified person as well as the associated name and address", in the **present tense**, "for the purposes of such transactions". Art 17(1)(c) requires member states to hold "data on VAT identification numbers it has issued which have become invalid, **and the dates on which those numbers became invalid**" — the database knows history; the confirmation service does not expose it. No duty to give historical (or forward-looking) confirmation exists.

**Answer to the brief's question: is there ANY statement in EU law about how fresh a confirmation must be?** **No.** Specifically: nothing in Directive 2006/112/EC, Reg 282/2011 (Art 18, Art 25, or any recital), or Reg 904/2010 (Art 17, Art 31) states a validity period, a re-check interval, or a staleness threshold. [L] verified across all three texts (S1–S4).

### 1.2 The Commission's FAQ — Q6 and Q20 quoted in full

The VIES FAQ (S5; live site is now a JavaScript SPA — text taken from the retired static page preserved at the Wayback Machine, cross-checked against the live `rest-api/faq` endpoint which still serves questions 1–25 keyed `vatFaq_quesNN`/`vatFaq_respNN`, and against identical quotes retrieved by the sister memo on 30 Oct 2026). **The full question list is Q1–Q25; there is NO question about re-validation frequency, staleness, or how long an answer is good for.** The two operative answers verbatim:

> **Q6 : Will further information be made available?**
> "No. Only confirmation on whether or not a number is valid. **It is not possible to confirm the validity of a VAT number in the past. It is possible to do it only for the current day.**"

> **Q20 : What do I have to do if I cannot check the validity of the VAT number of my customer?**
> "**If you believe that your customer is not a taxable person, you should not exempt the supply but should charge VAT.**"

Supporting answers:

> **Q3** (excerpt): "If the customer does not have a valid VAT number, then the supplier will charge VAT."

> **Q8** (excerpt): "It is necessary to ensure that the person you are supplying to in another Member State … is a taxable person as this is one of the elements that define the correct VAT treatment. … The valid VAT number of your customer should be mentioned on your invoice." *(asked as "before I make an intra-EU supply" — per-supply framing)*

> **Q14** (excerpt): "Some parts of the system may be unavailable at certain times due to the necessity to back-up the Member States' … databases. This is a known problem…"

Two consequences: (i) a confirmation evidences **its own day only** (Q6) — so evidence at a tax point N days old is, strictly, evidence about day −N, not about the tax point; (ii) Q20 is **conditional** ("If you believe that your customer is not a taxable person") — an outage is the *absence* of evidence, not evidence of non-taxable status. The FAQ nowhere instructs a supplier to re-check, and nowhere blesses a period of reliance.

### 1.3 VAT Committee Working Papers — the numbers, the contents, and the silence

All VAT Committee guidelines (1977–2023) are compiled in the official *Guidelines resulting from meetings of the VAT Committee* PDF (S6; 328 pp.) with an index (S7). The Committee's own caveat:

> "guidelines issued by the VAT Committee are merely views of a consultative committee. They do not constitute an official interpretation of EU law … They do not bind the European Commission or the Member States who are free not to follow them."

**The two on-point documents:**

**(a) Working paper No 609 (TAXUD/2412/09), 86th meeting of 18–19 March 2009, item 5.6 → guidelines 043–044–045** — "Follow-up to the VAT package – how to determine the scope of either of the main rules – identification of a customer as a taxable person acting as such or as a non-taxable person" (S6):

> "When it comes to the assessment of the status of the customer, the supplier is assumed to have acted in good faith when he has:
> (a) established whether the customer is a taxable person via the VAT number communicated to him or through any other proof presented to him to show that the customer is a taxable person …, and
> (b) **obtained confirmation of the validity of the VAT number of the customer and carried out a reasonable level of verification via existing security procedures.**
> …
> Where these conditions are met, the supplier is presumed to have been acting in good faith and is released from any further liability in the case of an incorrect assessment of the status of the customer, provided no evidence of abuse of law exists. Under such circumstances, the customer may, in accordance with Article 205, be designated as liable for payment of the VAT due in place of the supplier."

**(b) Working paper No 947 (taxud.c.1(2018)1735106), 110th meeting of 13 April 2018, item 4.5 → guideline 058** — "Article 18 of the VAT Implementing Regulation – the significance of the VAT identification number". **The question was raised by Estonia** (index row: "Linked to Article 18 of Council Implementing Regulation (EU) No 282/2011"). Verbatim key passages (S6):

> "1. The VAT Committee unanimously recognises that … the holding of a VAT identification number is not a prerequisite to become a taxable person … At the same time, the VAT Committee unanimously confirms that for the purposes of a customer providing proof of his status as a taxable person, the VAT identification number of that customer must be seen as a very important piece of evidence for the supplier. The VAT Committee unanimously acknowledges that Article 18 … provides elements on which the supplier can base himself in the context of making sufficient efforts to verify the status of his customer…"

> "2. … in accordance with the second subparagraph of Article 18(2) …, the supplier of telecommunications, broadcasting or electronically supplied services can treat the customer as a non-taxable person when that customer does not provide his VAT identification number and can do so without any additional checks. … the VAT Committee almost unanimously agrees that the burden of proof is on the supplier and – in order to avoid liability – he must hold sufficient information to substantiate the status of his customer being a taxable person."

> "4. The VAT Committee almost unanimously agrees that **in order to be seen to be acting in good faith, the supplier … must collect evidence from the customer and perform appropriate checks within the range of his possibilities.** Where because of the lack of cooperation of a customer, the supplier does not have sufficient evidence of the status of that customer and this is relevant from the point of who is liable for VAT, it is the almost unanimous view of the VAT Committee that **to be seen as having acted in good faith the supplier must charge the tax.** The VAT Committee almost unanimously concurs that any corrections should be possible only after proper cooperation of the customer in providing sufficient evidence."

**(c) Working paper No 989 (taxud.c.1(2020)971538), 116th meeting of 12 June 2020, item 6.1** — Quick Fixes, "VAT identification number obtained after the moment of chargeability" (goods, Art 138): a large majority allows the supplier to correct the invoice and apply the exemption if the acquirer communicates the number later, "still within the period in which a correction of the invoice can be made according to the rules of the Member State" and absent suspicion of fraud.

**The frequency question is nowhere addressed.** The full 328-page compilation was text-searched for "how often", "re-check", "still valid", "remains valid", "valid for", "annually", "every time", "each invoice/supply/transaction", "frequently", "regular basis": **no guideline, in the whole 1977–2023 series, states or discusses how often a supplier should re-verify a customer's VAT number, or how long a confirmation remains usable.** [G] negative finding, verified against the official compilation + index (S6, S7). The published working-paper series on CIRCABC (post-2013) could not be enumerated from this environment (the CIRCABC SPA would not boot; direct API routes 404) — **UNVERIFIED** whether any unpublished/non-guideline working paper (as opposed to agreed guidelines) contains frequency discussion; the agreed-guidelines corpus contains none.

**Net legal position on staleness:** the law's test is not age but (i) the circumstances at the chargeable event (Art 25), (ii) the Art 18 chapeau ("unless he has information to the contrary"), and (iii) the general good-faith/reasonable-measures standard (CJEU + WP 609/947). Age is at most a **proxy** for (i). A 91-day-old confirmation is not legally "void"; a 1-day-old confirmation does not save a supplier holding contrary information. But the burden of proof of the customer's status at the tax point sits on the supplier (VSTR ¶43; WP 947 ¶2), and older evidence is weaker evidence — which is why a *bounded* age is a defensible control even though it is not a legal rule.

---

## 2. The CJEU good-faith / due-diligence doctrine in depth

### 2.1 Mecsek-Gabona C-273/11 (6 Sept 2012) — ¶¶ 58–65 quoted (goods; IC supply exemption)

The only CJEU authority squarely on reliance against a register later changed. **Scope: goods, intra-Community supply exemption (Art 138), the vendor's good faith.** Not services; not Art 18; but the reliance principle is the closest thing in the case law to protection for a stale-but-honest check. Verbatim (S8):

> "**58** Under Article 214(1)(b) … every taxable person who makes intra-Community acquisitions is identified by means of an individual number. Under Article 226(4) … the customer's VAT identification number … must be indicated on the invoice …
> **59** However, neither the wording of Article 138(1) … nor the case-law … mentions – as one of the substantive conditions, listed exhaustively, for an intra-Community supply – the obligation to have a VAT identification number.
> **60** Admittedly, a VAT identification number provides proof of the tax status of the taxable person for the purposes of the application of VAT and facilitates the tax audit of intra-Community transactions. However, **it constitutes a formal requirement which cannot undermine the right of exemption from VAT where the substantive conditions for an intra-Community supply are satisfied** …
> **61** According to the case-law, a national measure which, in essence, makes the right of exemption … conditional upon compliance with formal obligations, without any account being taken of the substantive requirements, goes further than is necessary to ensure the correct levying and collection of the tax (Collée, paragraph 29). The only exception is if non-compliance with such formal requirements would effectively prevent the production of conclusive evidence that the substantive requirements have been satisfied …
> **62** In the present case, it is common ground that **the purchaser's identification number was valid at the time of the transaction** but that, several months later, that number was removed from the register of taxable persons by the Italian tax authority, **with retroactive effect**.
> **63** However, given that the obligation to check the status of the taxable person must be discharged by the competent national authority before it assigns that person a VAT identification number, possible irregularities affecting the register **cannot deprive a trader who has relied on the information entered in that register** of the right of exemption from VAT to which it is entitled.
> **64** As the European Commission rightly observes, it is contrary to the principle of proportionality that the vendor be held liable for the VAT **solely on the ground that the purchaser's VAT identification number was removed from the register with retroactive effect**.
> **65** Accordingly, the answer to Question 3 is that a vendor may not be refused the VAT exemption … **solely on the ground** that the tax authority of another Member State has removed the purchaser's VAT identification number from the register, with retroactive effect from a date prior to the sale of the goods even though the number was removed after the goods had been supplied."

**What it protects:** reliance on the content of the register **at the time of the enquiry** — the supplier *had* checked, the number *was* valid then, and the authority later rewrote history. The holding is a proportionality rule against retroactive destruction of a good-faith reliance position.

**What it does NOT protect:** a supplier who has *not* checked (or whose check is so old it no longer speaks to the chargeable event). ¶62 turns on the fact of validity "at the time of the transaction"; ¶65's answer is framed around retroactive removal. Mecsek is authority for "a later retroactive cancellation does not retroactively destroy a valid check", **not** for "an old check stays good for N days". It gives zero support to a grace period; it gives strong support to *documented* reliance (which is why the outage-tolerance branch below is built on records, not on the clock alone).

### 2.2 Vădan — scope check (the brief's citation is wrong)

The brief says "Vădan C-414/17 (scope: goods?)". Verified: **Vădan is Case C-664/16, Lucreţiu Hadrian Vădan v Agenţia Naţională de Administrare Fiscală, judgment of 21 November 2018** (S9). **C-414/17 is a different case: AREX CZ a.s. v Odvolací finanční ředitelství (19 Dec 2018)** — chain transactions with excise-duty goods transported under suspension, input deduction (S10). Both are **buyer-side input-deduction cases about goods/immovable-property transactions**; neither touches a supplier's verification of its customer, and neither interprets Art 18.

Vădan C-664/16, operative part verbatim:

> "Council Directive 2006/112/EC … must be interpreted as meaning that, in circumstances such as those at issue in the main proceedings, a taxable person who is unable to provide evidence of the amount of input VAT he has paid, by producing invoices or any other document, cannot benefit from a right to deduct VAT solely on the basis of an assessment resulting from an expert report commissioned by a national court."

Holding: no deduction without documentary evidence (invoices or equivalent); a court-ordered expert valuation is not a substitute. Scope: real-estate transactions (supplies of immovable property), Romanian property developer's own input tax. Relevance to ApexMail: only the general evidence-discipline theme — **taxpayers carry their evidential burden and substitutes do not plug gaps** — by analogy to VSTR ¶43's burden-of-proof rule for the supplier.

### 2.3 Tóth C-324/11 and Bonik C-285/11 — scope check: buyer's deduction; irrelevant to the seller's duty

**Tóth C-324/11** (6 Sept 2012, Hungary; construction labour; S11): the addressee's **right to deduct** cannot be refused because he failed to verify the invoice-issuer's employment relationships, absent material justifying suspicion. Operative part 3 verbatim:

> "… the fact that a taxable person did not verify either whether a legal relationship existed between the workers employed on a work site and the issuer of the invoice or whether the latter had declared those workers **does not constitute an objective factor which demonstrates that the addressee of the invoice knew or ought to have known** that he was participating in a transaction involving fraudulent evasion of value added tax, **where the addressee was not in possession of any material justifying the suspicion** that irregularities or fraud had been committed within that invoice issuer's sphere of activity. Accordingly, the right to deduct may not be refused on that ground…"

**Bonik C-285/11** (6 Dec 2012, Belgium; goods; S12): same structure — deduction may not be refused for upstream/downstream fraud absent objective evidence of the taxpayer's knowledge.

Both are **buyer-side (input deduction)** cases and say nothing about a *supplier's* duty to verify its *customer's* status. They are cited in the sister memo's brief lineage as if seller-relevant; they are not, except as statements of the general principle that **verification duties are bounded by red flags**: absent "material justifying the suspicion", the law does not require proactive investigation. That principle maps onto the Art 18 chapeau: the duty sharpens when "information to the contrary" exists — not on a calendar.

### 2.4 The Kittel line — and whether it imposes ACTIVE monitoring on the supplier

**Citation correction: Kittel is Joined Cases C-439/04 and C-440/04 (Axel Kittel v Belgian State / Belgian State v Recolta Recycling SPRL), judgment 6 July 2006** (S13). The brief's "C-438/05" is Viking Line (transport workers) and "C-438/04" is Mobistar (telecoms) — neither is Kittel.

Kittel ¶¶ 51, 56 verbatim:

> "51 … it is apparent that **traders who take every precaution which could reasonably be required of them** to ensure that their transactions are not connected with fraud … **must be able to rely on the legality of those transactions** without the risk of losing their right to deduct the input VAT…"
> "56 … **a taxable person who knew or should have known** that, by his purchase, he was taking part in a transaction connected with fraudulent evasion of VAT must … be regarded as a participant in that fraud…"

**Mahagében/Dávid C-80/11 & C-142/11** (21 June 2012; S14) completes the line:

> "53 … traders who take every precaution which could reasonably be required of them … must be able to rely on the legality of those transactions… (see Kittel …, paragraph 51).
> 54 On the other hand, it is not contrary to European Union law to require a trader to take **every step which could reasonably be required of him** to satisfy himself that the transaction which he is effecting does not result in his participation in tax evasion…
> 59 … determination of the measures which may, in a particular case, reasonably be required … **depends essentially on the circumstances of that particular case.**
> 60 It is true that **when there are indications pointing to an infringement or fraud, a reasonable trader could, depending on the circumstances of the case, be obliged to make enquiries** about another trader …
> 66 … [the right to deduct may not be refused where] … the taxable person is **not in possession of any material justifying the suspicion** that irregularities or fraud have been committed…"

**Does Kittel impose an ACTIVE monitoring duty on ApexMail?** **No — not in this context, and not as a matter of settled law.** Reasons, precisely:
1. Kittel/Mahagében are **deduction** cases: they attach consequences to a *relief the taxpayer claims*. For ApexMail's reverse-charge services the analogue is not the deduction but the **status presumption** under Art 18 and the Art 196 liability allocation; the CJEU has never transplanted Kittel to Art 18 services. **UNVERIFIED:** no CJEU judgment directly applies the "knew or ought to have known" test to a supplier relying on a VAT-number check for B2B services reverse charge (searched; none found).
2. Even in its own field, Kittel imposes no schedule of checks: the trigger is knowledge/constructive knowledge **of fraud** ("indications pointing to an infringement or fraud", Mahagében ¶60), i.e. the Art 18 chapeau's "information to the contrary", not calendar time.
3. What Kittel DOES establish for ApexMail: the **safe-harbour shape** of "every precaution which could reasonably be required" (¶51), which is the same standard as VSTR ¶52 and WP 609(b). A documented, regular, per-tax-point VIES regime is precisely the kind of precaution that converts "should have known" exposure into "could not have known" protection.

**The seller-side services question** (does stale VIES evidence lose the reverse charge?) is governed by: Art 25 (circumstances at the chargeable event) + Art 18(1)(a) (obtained confirmation) + the good-faith standard (VSTR ¶52; WP 609) + Mecsek's reliance/proportionality principle (by analogy). There is no direct CJEU authority. **UNVERIFIED** as settled case law; the conclusions below are textual + analogical.

---

## 3. National practice and penalties

### 3.1 Estonia — EMTA practice

**EMTA, "How to check the background of a business partner"** (S15) is the official due-diligence page. On EU numbers, verbatim:

> "European Union value-added tax identification number (VIES VAT number) verification — By using this search tool you can check if a person such as your business partner has been registered as a VAT payer in any European Union Member State and if the VAT number is valid. **It is important to check if the name of the counterparty corresponds to the VAT number. If no valid VAT number exists, the relevant rules must be adhered to regarding taxation of the transaction** (for example, intra-Community supply must be taxed at the rate of 20% instead of 0%)."

(The "20%" is stale wording on EMTA's page; the Estonian standard rate is 24% since 1 July 2025 per the sister memo.)

Three points: (i) EMTA tells suppliers to check the number **and the name match** — the name/address leg of Art 18(1)(a) is expected in practice; (ii) no valid number ⇒ tax the transaction (the conservative default); (iii) **EMTA publishes no re-check frequency and no validity period for a check.** Searches of EMTA's English guidance found no cadence statement. [G] negative finding.

### 3.2 Estonia — what happens if reverse charge is applied on an invalid number (penalty anatomy)

1. **The tax itself.** If the customer was not a taxable person, the supply is taxable in Estonia and the supplier owed VAT at 24% (KMS §10(1)/§5; Art 196 logic reversed). EMTA assesses the missing VAT through tax control. The reverse charge on an invalid number is simply an under-declared liability. (If VAT was wrongly *shown* on an invoice, KMS §5(6)2): "a person not registered as a taxable person, on transactions concerning which the person has issued an invoice or other sales document in which the amount of value added tax is indicated" must pay it — the Estonian Art 203 analogue. [L] S16.)
2. **Interest.** Estonian tax interest on arrears: **0.06% per day (21.9% per year)** from the day after the due date until payment (EMTA, "Payment of interests", S17; Taxation Act §§ 97, 118). Interest amounts are rounded to whole euros; below €0.50 they expire.
3. **Misdemeanour fines.** Taxation Act (S18) **§ 153¹ "Concealment of tax liability and increase of claim for refund without basis"**: intentional false information decreasing the tax obligation is "punishable by a fine of up to 300 fine units"; "the same act, if committed by a legal person, is punishable by a fine of up to **32,000 euros**". **§ 154 "Obstruction of activities of tax authority"**: failure to file/keep records/comply with orders — fine up to 300 fine units (legal-person ceiling in the same section family). *(Fine-unit-to-euro conversion: 1 fine unit = €4? **UNVERIFIED** — not confirmed from primary text this session.)*
4. **Criminal tax fraud** (Penal Code §§ 389¹–389²) for intentional evasion — referenced as disqualifying misconduct in KMS (S16).
5. **No "additional tax liability" in the VAT Act itself** for this scenario; the "non-compliance levy" (täiendav maksukohustus) machinery in the Taxation Act is an enforcement device (e.g. employment registration, up to €3,300), not the standard VAT penalty. [L] S18.

So the assessment for a wrong reverse charge is: **back-tax + 0.06%/day interest + (intentional concealment ⇒ Taxation Act § 153¹ fines; record failures ⇒ § 154) + fraud exposure only where intentional evasion is established.** A documented, regular VIES-check regime goes directly to the mens-rea/record legs: it is the difference between "concealment" and "error despite reasonable measures".

### 3.3 Germany — the only jurisdiction with case law on re-check frequency

**Correction to the brief:** § 18g UStG is the **foreign-refund** procedure (application for refund of input VAT in another member state; S19). The VAT-ID confirmation procedure ("Bestätigungsverfahren") has no statutory validity period: the historical UStDV provisions (§§ 18e, 19 UStDV) are repealed (S20, S21); the procedure and its due-diligence framing live in administrative guidance (UStAE Abschn. 6a.8, 18e.1, 18.11) and case law. The substantive Quick-Fix condition is **§ 6a Abs. 1 Satz 1 Nr. 4 UStG** — the customer's valid German/other-Member-State VAT ID is a **material condition of exemption for intra-Community supplies of goods** since 1 Jan 2020.

The definitive practitioner synthesis (REB Steuerberatung, Prof. Dr. Manzur Esskandari & Dr. Daniela Bick, "Qualifizierte Bestätigungsanfrage beim BZSt: Wie oft Sie die USt-IdNr. Ihres EU-Kunden prüfen müssen", 8 June 2026; S21) — retrieved and read in full; the court dockets below are as reported there (**UNVERIFIED at primary-judgment level**; dockets are given so the accountant can pull them):

> "**Eine feste Frist existiert nicht**, denn gesetzlich ist nicht geregelt, wie regelmäßig der Lieferer die USt-IdNr. seines Abnehmers bestätigen lassen muss, und die Rechtsprechung ist insoweit uneinheitlich. Maßstab ist die Sorgfalt eines ordentlichen Kaufmanns." *(No fixed period exists; the standard is the due diligence of a prudent businessman.)*

The frequency spectrum, as tabulated by the authors:

| Court / authority | Docket / date | Required frequency |
|---|---|---|
| FG München | 10.2.2009, 14 V 3396/08 | **bei jeder Lieferung** (at every supply) |
| FG Berlin-Brandenburg | 15.11.2018, 7 K 7196/15 | before first supply, **then every two weeks** |
| BFH | 2.7.2021, **XI R 40/19** | near in time to the first supply, **then at regular intervals** (no fixed interval) |
| BFH | 11.3.2020, **XI R 38/18** | regular intervals; **at least every two months presumed sufficient** ("zumindest alle zwei Monate (voraussichtlich ausreichend)") |
| FG Nürnberg | 14.5.2019, 2 K 482/17 | **at least every two months** |
| Finanzverwaltung (tax authority) | UStAE Abschn. 6a.8 Abs. 6 S. 1 | apparently **for every single transaction** |

Their conclusions, verbatim fragments:

> "Die Finanzverwaltung selbst tendiert zum strengsten Maßstab. Sie scheint inzwischen davon auszugehen, dass die Überprüfung für jeden einzelnen Umsatz zu erfolgen hat…"
> "In der Beratung empfehlen wir, sich am strengen Maßstab der Finanzverwaltung zu orientieren und die qualifizierte Abfrage so eng an den einzelnen Umsatz zu binden, wie es der Geschäftsbetrieb zulässt. Wer regelmäßig an denselben Abnehmer liefert, sollte zumindest den vom FG Berlin-Brandenburg genannten Zwei-Wochen-Takt nicht überschreiten…"
> "Eine Bestätigung, die Wochen vor der Lieferung eingeholt und dann nie aktualisiert wurde, trägt diesen Nachweis nur eingeschränkt." *(A confirmation obtained weeks before the supply and never refreshed carries the proof only to a limited extent.)*
> On retroactive invalidation: "Maßgeblich bleibt der Zeitpunkt der Lieferung… War die Nummer im Lieferzeitpunkt gültig und konnte der Lieferer die spätere Ungültigkeit bei Anwendung der Sorgfalt eines ordentlichen Kaufmanns nicht erkennen, bleibt der Weg über den Vertrauensschutz nach § 6a Abs. 4 UStG offen." *(Good-faith protection survives retroactive cancellation where the number was valid at the time of supply — Mecsek, domesticated.)*
> Documentation: the written/electronic BZSt confirmation must be linked to the specific transaction and kept for the 8-year German retention (§ 14b UStG), with a GoBD-compliant procedural record of the check.

Also note the German insistence on the **qualified** confirmation (name + legal form + city + postcode + street), not a bare valid/invalid — the same name/address leg as Art 18(1)(a) and EMTA's advice.

**Scope caveat (important):** the German case law is about **intra-Community supplies of goods**, where the valid VAT ID is a *substantive* exemption condition (Quick Fixes). For ApexMail's **services** under Arts 44/196 the VAT ID is evidential (Art 18 presumption; the substantive question is status under Arts 9/43). The German line is therefore **persuasive-by-analogy on the Sorgfalt standard in repeat supplies**, not binding authority. It is also the *only* body of decided cases in the EU on re-check frequency — which makes it the best available answer to "what would an auditor accept".

**"Unbedenklichkeitsbescheinigung" analogy (the brief's aside):** the German tax-clearance certificate (export refunds) is point-in-time evidence whose usability decays under administrative rules; the analogy is only that German administrative practice never treats official confirmations as evergreen — timeliness is the trader's problem. No Estonian counterpart; no grace-period rule anywhere in it. [P] analogy only.

---

## 4. What the major players actually do (practitioner class)

| Player | Documented behaviour | Source |
|---|---|---|
| **Stripe Tax** | EU VAT numbers validated against VIES **once**, on creation/update: "**After a tax ID is confirmed as valid or invalid, it won't be validated again automatically.**" Validity only — "This process only verifies the validity of the tax ID, and not whether the customer's name and address match…". On outage: "Stripe automatically handles VIES downtime and attempts retries for you." And the important one: "**If you use Stripe Tax, Stripe Tax applies the reverse charge or zero rate according to applicable laws when the tax ID has the required number format, regardless of the government verification result**" — i.e. Stripe's *tax determination* runs on format, not on the check. Merchant "responsible for determining how to handle an unverified tax ID". | S22 (docs.stripe.com/tax/tax-ids, fetched 31 Oct 2026) |
| **Chargebee** | "Chargebee uses VIES to validate a merchant's VAT number. You can choose to perform EU VAT validation … on signup and renewal." **"Note: VAT validation happens in the following instances: 1. Every 3 months 2. When the VAT number is added or updated."** Reverse charge applied for cross-EU customers "if a VAT number is present in Chargebee" (validation toggle under tax-region settings). | S23 (support.chargebee.com/solutions/articles/247808 "Enable VAT number validation", modified 5 Sep 2020, fetched 31 Oct 2026) |
| **TaxJar** | Validation API (`taxjar.validate({vat})`, the `v2/validation` endpoint): validates against VIES and returns business name and address; **on caller demand** — "When VIES is available, we'll reach out to their service… **When it isn't, which happens often, we fall back to a regex validation**" with `vies_available` + `vies_response` in the payload. Cadence is the caller's choice; Zapier exposes it as a "Validate a VAT Number" action. Note the regex fallback is **not** the Art 18 standard and would not support a reverse charge. | S24 (developers.taxjar.com/blog/summarized-tax-rates-and-vat-validation/, fetched 31 Oct 2026) |
| **Paddle (MoR)** | **UNVERIFIED** — Paddle's help center has been rebuilt; the previously cited help article 404s and the sitemap exposes no VAT article (fetched 31 Oct 2026). Secondary sources consistently describe Paddle as Merchant of Record that computes/collects VAT and validates buyer VAT numbers at checkout, with the tax liability sitting on Paddle — which internalises the freshness problem (Paddle is the debtor if it gets it wrong). No cadence statement retrievable. | secondary only; **UNVERIFIED** |
| **Avalara** | **UNVERIFIED** — knowledge-center pages did not resolve from this environment (31 Oct 2026). Public marketing positions AvaTax/VAT Expert as per-transaction determination with tax-ID validation services; no retrievable cadence statement. | **UNVERIFIED** |
| **Market practice around Stripe** | The subscription-billing ecosystem re-checks **per invoice/renewal**: e.g. the n8n template "Re-check EU VAT numbers on Stripe invoices with VIES" (Sept 2026) triggers on Stripe invoice draft and re-validates before the invoice; a widely-circulated subscription-engineering tutorial ("How to Automate VAT Number Checks for Recurring Payments") likewise prescribes re-validation before every renewal. | S25 (search results, 31 Oct 2026) |
| **Big-4 (Deloitte/PwC/KPMG/EY)** | **No public Big-4 alert recommending a VIES re-check cadence was found.** Retrievable Big-4 indirect-tax alerts on VAT-ID checks are generic ("verify the number and keep evidence"); PwC Worldwide Tax Summaries (Estonia) contains no cadence. Treat as a negative finding: the Big-4 do not publish a number — the defensible range comes from the German courts instead. | **UNVERIFIED/negative**, searched 31 Oct 2026 |

**The market's answer in one line:** validate at onboarding and at every invoice/renewal (Stripe ecosystem, Chargebee's renewal hook), with a documented quarterly backstop (Chargebee "every 3 months"); nobody serious treats a check as evergreen; the strictest vendors' *tax engines* (Stripe on format) are known to be looser than the Art 18 evidence standard (sister-memo conflict C9).

---

## 5. The defensible policy for an Estonian OSS-filing SaaS

### 5.1 The three options

**Option A — re-validate at EVERY tax point.**
Legally the cleanest: Art 25 judges status at the chargeable event; a same-day confirmation is the only evidence that speaks to that date (FAQ Q6). Cost: one VIES SOAP call per renewal per customer (VIES is free; the REST/SOAP service supports it; FAQ Q18 documents the SOAP endpoint). Outage handling is still required (VIES member-state DBs go down for backups, FAQ Q14). Is charging VAT on every outage REQUIRED? **No.** FAQ Q20 is conditional ("if you believe your customer is not a taxable person"); an outage is absence of evidence, and VSTR ¶52 / WP 609(a) allow "any other proof"; WP 609 even releases a good-faith supplier from liability for an incorrect status assessment and permits an Art 205 shift to the customer. Charging VAT on outage is a **risk-managed choice** (it is also the choice WP 947 ¶4 endorses where evidence is lacking and the customer will not cooperate: "to be seen as having acted in good faith the supplier must charge the tax"). The alternative — continue on last-known-good during a documented outage with a hard cap — is analysed under Option C.

**Option B — pure cadence (monthly / quarterly / 90 days), no per-tax-point check.**
Defensible only up to the judicial outer edge: German case law accepts "regular intervals" (BFH XI R 40/19) and "at least every two months" (BFH XI R 38/18; FG Nürnberg), and the German tax authority wants per-transaction. A **quarterly** (OSS-cycle) cadence sits at/just beyond every judicial data point and inside Chargebee's market convention; a **90-day** bound is longer than every interval any German court has accepted (two months ≈ 60 days) and has **no source of any kind** — neither law, guidance, case law, nor vendor documentation. The code comment's claimed derivation ("roughly matches the cadence at which member states re-check registration data") is unsourced and must go (sister-memo C6).

**Option C — hybrid (recommended): re-validate at every tax point + bounded outage tolerance on last-known-valid + hard age cap + escalation.**

### 5.2 Recommendation: Option C, with a 60-day hard cap

**Why hybrid:** per-tax-point checking meets the strictest standard (FG München, German Finanzverwaltung, the market's per-invoice practice) and makes the age bound almost never load-bearing — the bound then does exactly the work it should: it is the **fallback ceiling** when the system cannot check (VIES outage, transport failure) and the safety net if a check is ever skipped. The outage-tolerance branch is where law meets operations: pure fail-closed on every glitch churns customers and generates Art 203 correction workloads for no legal reason (FAQ Q20 is conditional; charging VAT is prudent, not compelled), while unlimited tolerance is indefensible (Art 18(1)(a) wants an *obtained* confirmation).

**Why 60 days, derived — not invented:**
1. **Judicial outer edge:** the most generous interval any EU court has accepted for repeated supplies is **two months** — BFH 11.3.2020, XI R 38/18 ("zumindest alle zwei Monate … voraussichtlich ausreichend") and FG Nürnberg 14.5.2019, 2 K 482/17 ("mindestens alle zwei Monate"). 60 days ≈ two months; the strict end of the range (per-transaction / 2 weeks) is already satisfied by the per-tax-point rule. Anything above two months (including 90) has **zero judicial support anywhere in the EU**.
2. **Market convention floor:** Chargebee — the one vendor publishing a number — re-validates "every 3 months"; 60 days is comfortably inside that.
3. **Reporting cycle:** 60 days < one OSS quarter, so every quarterly OSS return is backed by at least one (in practice ~4–5) confirmations per customer-quarter; the VD report month is likewise always inside the window.
4. **Art 25 logic:** the shorter the gap between confirmation date and chargeable event, the stronger the inference that the confirmation evidences the circumstances *at* the event. Two months is the longest gap for which a court has said "presumably sufficient".

**The escalation trigger (N):** after **7 consecutive days** of documented VIES unavailability for a customer with no fresh confirmation, ops escalates (alert + manual review). N=7 is an **operational** threshold (longer than any routine backup window per FAQ Q14; shorter than the legal cap), not a legal bound — the legal bound is the 60-day cap.

**Why this survives an Estonian audit:** EMTA's own advice is "check the number and that the name matches" (S15); the evidence file (per §6 below — request IDs, response hashes, timestamps, name/address comparison) demonstrates exactly the WP 609(b) standard ("obtained confirmation … and carried out a reasonable level of verification") and the WP 947 ¶4 good-faith standard ("collect evidence … and perform appropriate checks within the range of his possibilities"). On penalties: the regime in §3.2 punishes concealment and record failure; a per-tax-point logged check defeats both. On the German comparator: the policy is *stricter* than every accepted German interval (checks at every tax point; cap at the outer judicial edge). On Mecsek: the outage branch is reliance-on-a-real-check, not lazy staleness — the exact fact pattern ¶¶62–64 protects.

**Residual risk, stated honestly:** if a number is cancelled *with retroactive effect* and the customer was never taxable, Mecsek protects goods vendors by analogy but there is **no services authority**; the supplier would rely on Mecsek's proportionality reasoning + WP 609's release-of-liability clause (which does cover services!) + Art 205 shift possibilities. Flagged **UNVERIFIED** for the accountant.

---

## 6. Outage policy precision (brief item 6)

**Q20 exact text:** "If you believe that your customer is not a taxable person, you should not exempt the supply but should charge VAT." **The condition is a *belief about the customer*, not the outage.** The lawful outcomes at a tax point where VIES is unreachable:

1. **Other proof of taxable status** (Art 17; Art 18(1)(b) "any other proof" logic; VSTR ¶52: "other information … such as to demonstrate sufficiently that the person … is a taxable person"; WP 609(a) "or through any other proof"). The current repo policy refuses other proof — defensible as a policy, but it is a choice (sister-memo §8.1).
2. **Continue reverse charge on documented last-known-valid evidence** within the hard cap (Option C). Lawful *if* at audit the supplier can otherwise establish the customer's taxable status at the tax point — the burden is the supplier's (VSTR ¶43; WP 947 ¶2). The documented outage does not *cure* anything; it *evidences good faith* (and good faith is what the whole doctrine rewards).
3. **Charge VAT** (the sister memo's "conservative" default). Always safe for the VAT amount; never risk-free (Art 203 makes wrongly-shown VAT payable and forces credit-note correction + customer remediation).

**What if the supplier continues reverse charge through a multi-day outage and the number turns out invalid?** The Art 18(1)(a) presumption is unavailable for those tax points (no confirmation "obtained"). If the customer was in fact non-taxable, the supplier owes the VAT (Estonian assessment per §3.2: back-tax + 0.06%/day interest; fines only on concealment/record failure). **Documented outage helps in exactly two ways:** (i) it rebuts concealment/fraud characterisations (Tóth/Kittel: consequences attach to *knowledge*; a logged outage is the opposite of concealment); (ii) if the number was valid at the last consultation and later cancelled retroactively, Mecsek ¶¶63–64 (goods; persuasive for services) says the vendor may not be liable **solely** on that ground. **Documented outage does not help** where the number was already invalid at the last successful check and the supplier proceeded anyway — that is an "information to the contrary" failure, and WP 947 ¶4's answer is blunt: "to be seen as having acted in good faith the supplier must charge the tax".

---

## 7. Conflict list

**X1. The 90-day number has no source anywhere.** Law: none (§1.1). Guidance: none (FAQ Q6/Q8; WP 609/947). Case law: the only intervals ever accepted top out at **two months** (BFH XI R 38/18; FG Nürnberg 2 K 482/17), with the strict end at per-supply (FG München 14 V 3396/08) or two weeks (FG Berlin-Brandenburg 7 K 7196/15). Vendors: Chargebee "every 3 months" (convention, not law); Stripe: no re-validation at all. **Resolution: replace 90 with 60 (two months, the judicial outer edge) and stop implying a legal basis.**

**X2. The code comment's "member states re-check registration data" cadence is fabricated.** No such cadence is published in Reg 904/2010, by the Commission, or by EMTA. **Resolution: delete the sentence (sister-memo C6 already flagged it).**

**X3. Brief citation "Vădan C-414/17" conflates two cases.** Vădan = C-664/16 (real-estate input deduction, no invoices ⇒ no deduction). C-414/17 = AREX CZ (excise goods chain). Neither is seller-side. **Resolution: cite Vădan as C-664/16 with its actual holding; do not cite it for verification duties.**

**X4. Brief citation "Kittel C-438/05" is wrong.** C-438/05 = Viking Line; C-438/04 = Mobistar. **Kittel = Joined Cases C-439/04 & C-440/04.** Resolution: corrected citation throughout.

**X5. Brief's "§ 18g / Unbedenklichkeitsbescheinigung" framing.** § 18g UStG is the refund-application procedure; the confirmation/due-diligence regime is § 6a UStG + UStAE 6a.8/18e.1 + BFH/FG case law. The Unbedenklichkeitsbescheinigung is an export instrument; analogy only. **Resolution: cite § 6a Abs. 1 S. 1 Nr. 4 UStG + the interval case law.**

**X6. German authority vs EU-law silence.** German courts/authority set frequency expectations for **goods**; EU law for **services** (Art 18) is silent and the CJEU has not ruled. **Resolution: treat the German line as the due-diligence benchmark by analogy (Sorgfalt standard is identical in Kittel ¶51 / VSTR ¶52 / WP 609(b)), scope-flagged; do not present it as binding for services.** (Minor: the REB article cites "Art. 138 Abs. 1 Buchst. b MwStSystRL" for the VAT-ID condition; the communication-of-number condition sits in Art 138(1)(a) as amended by Dir (EU) 2018/1910 — **UNVERIFIED** lettering at primary text; immaterial to the analysis.)

**X7. Q20 conditional vs the repo's unconditional "fail closed".** FAQ Q20 conditions VAT-charging on a *belief* of non-taxable status. Fail-closed remains the right **default** for an unattended pipeline (WP 947 ¶4 supports it where evidence is missing), but it must be labelled a policy, and the outage branch must not pretend Q20 compels it. (Sister-memo C5 stands; this memo supplies the missing alternative: bounded last-known-valid with records.)

**X8. The sister memo's F5 implementation gap becomes state-machine law.** The current loader takes the *newest* evidence row, so an outage row shadows the last valid row and the documented grace is dead code. **Resolution: the decision must look through Outage rows to the newest Valid row within the cap (that is what "last-known-valid" means), and an Invalid row must always win.**

**X9. Vendor practice is not the standard.** Stripe determines tax "regardless of the government verification result" (format test); TaxJar falls back to regex on VIES downtime. Neither is the Art 18 standard (name/address confirmation + no contrary info). Use vendor behaviour only as market-convention evidence.

**X10. Estonian penalties are asymmetric and the memo should say so.** No penalty attaches merely for being wrong; interest runs automatically (0.06%/day), fines attach to concealment (Taxation Act § 153¹: up to 300 fine units / €32,000 legal persons) or record/obstruction failures (§ 154), fraud only on intent (Penal Code §§ 389¹–389²). The evidence log is therefore primarily a **penalty-shield**, secondarily a tax-position defence.

---

## 8. CODE-READY ANSWERS

### 8.1 The recommended freshness policy as a state machine

**Scope:** every EU B2B supply where the customer has communicated a VAT number and the supplier seeks the Art 18(1)(a) presumption for a 0% reverse charge. `at` = the **chargeable-event date** (Art 63/64; KMS §11 — NOT the invoice date; sister-memo F9/C11 remain binding).

**Inputs at a tax point:**
- `attempted`: whether a VIES consultation was attempted for (customer, vat_number, country) in the run-up to/at the tax point;
- `outcome`: the newest consultation result at or before `at`: `Valid | Invalid | Outage | None` (`Outage` rows are looked *through* for `Valid` history; `Invalid` always dominates);
- `evidence`: the newest `Valid` evidence row (with `valid_from` = consultation date, name/address comparison result, response hash, request id);
- `contrary`: any "information to the contrary" (name/address mismatch not resolved, red flags, customer dispute, mixed signals);
- `outage_days`: consecutive days VIES has been unavailable for this customer's checks.

**Constants (policy):**
- `VAT_EVIDENCE_MAX_AGE_DAYS = 60` — hard cap (≈ two months; derivation in §5.2). Replaces 90.
- `OUTAGE_ESCALATION_DAYS = 7` — operational alert threshold (not a legal bound).

**Decision function (outputs: REVERSE_CHARGE | REVERSE_CHARGE_OUTAGE_TOLERATED | VAT | ESCALATE):**

```
state at tax point `at`:
  1. if outcome == Invalid                      -> VAT                       (Art 18(1)(a) unavailable; FAQ Q3/Q7)
  2. if contrary                                -> ESCALATE                  (Art 18 chapeau; suspend RC until cleared;
                                                                                if not cleared before invoicing -> VAT)
  3. if outcome == Valid
        and no contrary
        and name/address match (or documented mismatch resolution)
        and 0 <= (at - valid_from) <= 60d                                -> REVERSE_CHARGE
  4. if (outcome == Outage or attempted failed or no attempt possible):
        if newest Valid evidence exists
           and name/address match ok
           and 0 <= (at - valid_from) <= 60d
           and outage_days <= 7 (or < 60d cap regardless)                -> REVERSE_CHARGE_OUTAGE_TOLERATED
                                                                         (documented last-known-valid; alert; retry loop)
        else                                                             -> VAT   (and ESCALATE if outage_days > 7)
  5. outcome == None (no evidence ever)                                  -> VAT
```

**Invariants (do not "fix"):**
- A consultation dated **after** `at` can never authorise `at` (`at >= valid_from`; sister-memo F8 — prevents retroactive zero-rating).
- `valid_until = NULL` means "no explicit invalidation", never "valid forever": the 60-day cap always applies.
- An `Invalid` result kills reverse charge for that tax point immediately (no grace on invalidity — grace is only an *outage* concept).
- `Escalate` does not itself change tax treatment; it holds the invoice for review (within the KMS §37(1) 7-day / §37(2¹) 15th-of-month invoice deadlines) and records the decision either way.

**Outage runbook (what the state machine is saying operationally):** retry VIES with backoff (Stripe's model: retries, not substitution); keep serving REVERSE_CHARGE_OUTAGE_TOLERATED while within cap; at day 7 of continuous outage page ops; at cap expiry flip to VAT and notify the customer that VAT will be charged until the number re-validates (WP 947 ¶4: charge the tax where evidence cannot be had).

### 8.2 Evidence to retain per consultation (Art 242 "sufficient detail"; survives Estonian audit)

Per VIES consultation, on the existing `vat_validation_evidence` table (migration 218 already stores most of it — the *decision path* must start reading it, sister-memo F3):
1. `requested_at` (timestamptz, exact instant) + `authority_request_id` + `response_hash` (raw response archived) — already in schema;
2. returned `name` + `address`, and the **comparison result** against the customer's declared name/address (add a `name_address_match` verdict field; Art 18(1)(a) requires the associated name and address, EMTA expects the match);
3. outcome (`Valid/Invalid/Outage`) + `outage_state` detail (error class, HTTP status);
4. the customer declaration snapshot the check ran against (is_business, number, country, terms version, timestamp);
5. a "no contrary information known at decision time" flag (explicit — Art 18 chapeau is the actual legal test);
6. the **tax point** the evidence is applied to (chargeable-event date) and `invoices.vat_evidence_id` join (exists) — plus the decision code path taken (RC / RC-outage / VAT / escalated);
7. retention: **10 years** (Art 369k(2) for OSS transactions; KMS §36(1) 7-year floor for domestic invoices — use 10 for all VAT evidence).

### 8.3 Re-validation cadence and its justification (one paragraph for the accountant)

Re-validate **at every tax point** (each renewal/period completion; also on number change, country change, onboarding, and account reactivation), with a scheduled background refresh **at least every 60 days** for active subscriptions (belt-and-braces for annual/prepaid plans and mid-period number changes), and a hard cap of **60 days** on reliance when a check cannot be made. Justification: Art 25 judges status at the chargeable event and FAQ Q6 confines a confirmation to its own day, so same-day evidence is the only evidence that directly speaks to the tax point; no EU law, Commission guidance, or VAT Committee guideline sets any period (verified against the full guidelines compilation); the only decided EU case law on frequency (German, goods, persuasive by analogy on the identical "prudent businessman"/"every precaution reasonably required" standard — Kittel ¶51, VSTR ¶52, WP 609(b)) accepts intervals only up to **two months** (BFH XI R 38/18; FG Nürnberg 2 K 482/17), demands per-transaction at the strict end (FG München 14 V 3396/08; UStAE 6a.8(6)), and two weeks for repeat customers (FG Berlin-Brandenburg 7 K 7196/15; the REB authors' recommendation); market convention (Chargebee) re-validates every 3 months; per-invoice re-checking is the subscription-engineering norm. 90 days exceeds every one of these data points and is therefore indefensible; 60 days at the judicial outer edge + per-tax-point checks is stricter than anything any authority or court has required.

### 8.4 Exact replacement wording

**(a) `services/mail-server/crates/billing-common/src/vat_rates.rs` — replace the doc comment on `VAT_EVIDENCE_MAX_AGE_DAYS` (keep the constant name; change the value to 60):**

```rust
/// Hard cap on the age of VIES evidence that may authorise a 0 % reverse
/// charge at a tax point. POLICY, not law: EU law sets no validity period
/// for a VIES confirmation (Reg 282/2011 Art 18 asks only that the supplier
/// "obtains confirmation"; Art 25 judges status at the chargeable event;
/// Commission VIES FAQ Q6: a confirmation is valid "only for the current
/// day"). Nothing in Reg 282/2011, Reg 904/2010, the Commission's guidance
/// or the VAT Committee guidelines (1977-2023, full compilation searched)
/// states a grace period.
///
/// 60 days is the outer edge of the only interval case law in the EU
/// (German, goods, persuasive by analogy on the shared "due diligence of a
/// prudent businessman" standard): BFH 11.3.2020, XI R 38/18 and FG
/// Nuernberg 14.5.2019, 2 K 482/17 accept "at least every two months";
/// FG Berlin-Brandenburg 15.11.2018, 7 K 7196/15 wants two-week checks for
/// repeat customers; FG Muenchen 10.2.2009, 14 V 3396/08 and the German tax
/// authority (UStAE 6a.8(6)) want every supply checked. We re-validate at
/// every tax point anyway (the strict end), so this cap only bounds the
/// outage fallback (last-known-valid) and any skipped check. It is also
/// inside the market convention (Chargebee re-validates "every 3 months")
/// and shorter than one OSS quarter.
///
/// `valid_until = NULL` means "no explicit invalidation", never "valid
/// forever": this age bound still applies. An `Invalid` outcome is never
/// excused by this bound; only an outage (no answer) may fall back to
/// last-known-valid evidence within it.
pub const VAT_EVIDENCE_MAX_AGE_DAYS: i64 = 60;
```

**(b) Policy section of `docs/research/eu-vat-law-evidence-and-invoicing.md` — replacement for the §8.1 row "VIES outage ⇒ …" and the §2 conclusion ("POLICY, no direct legal basis" wording):**

```markdown
| VIES outage ⇒ last-known-valid within 60 days, else VAT | Documented in
| `tax.rs` / `vat_rates.rs`; state machine in VATDEEP-C §8.1 | POLICY built
| on four legs: (i) Mecsek-Gabona C-273/11 ¶¶62-65 (reliance on a register
| entry valid when consulted cannot be destroyed by later retroactive
| change — goods, by analogy); (ii) VAT Committee guideline 058 / WP 947
| (110th meeting, question raised by Estonia): good faith = "collect
| evidence … and perform appropriate checks within the range of his
| possibilities", and charge the tax only where evidence cannot be had;
| guideline 043-045 / WP 609: "obtained confirmation of the validity … and
| carried out a reasonable level of verification" releases the supplier
| from liability for an incorrect status assessment; (iii) FAQ Q20 is
| conditional ("If you believe that your customer is not a taxable person")
| — an outage is absence of evidence, not such a belief; (iv) the 60-day
| cap is the outer edge of the only EU interval case law (BFH XI R 38/18;
| FG Nürnberg 2 K 482/17: "at least every two months"), inside Chargebee's
| 3-month convention. No statute or guidance grants a grace period;
| the policy is a risk-managed reliance window with mandatory re-validation
| at every tax point | **POLICY (risk-managed), no statutory grace period;
| 60-day cap derived from case law, replaces the unsourced 90-day bound** |
```

And the A3 conclusion sentence "The repo's `VAT_EVIDENCE_MAX_AGE_DAYS = 90` is a POLICY choice" is amended to: "**`VAT_EVIDENCE_MAX_AGE_DAYS = 60`** is a POLICY choice, derived from the outer edge of the German two-month interval case law (BFH XI R 38/18; FG Nürnberg 2 K 482/17) and the Chargebee quarterly convention; it is not a statutory period, and the system re-validates at every tax point so the bound only governs outage fallback."

---

## 9. Sources

| ID | Source | URL | Retrieved |
|---|---|---|---|
| S1 | Directive 2006/112/EC, consolidated 01.01.2025 (as in sister memo) | eur-lex CELEX:02006L0112-20250101 | 30–31 Oct 2026 |
| S2 | Implementing Regulation (EU) No 282/2011, consolidated 01.07.2022 (Art 18 verbatim) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02011R0282-20220701 | 31 Oct 2026 (via r.jina.ai) |
| S3 | Reg 282/2011 original (recitals 18–22) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32011R0282 | 31 Oct 2026 (via r.jina.ai) |
| S4 | Council Regulation (EU) No 904/2010, Arts 17, 31 | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32010R0904 | 31 Oct 2026 (via r.jina.ai) |
| S5 | European Commission VIES FAQ Q1–Q25 (static page via Wayback wb-20220601; live API `/rest-api/faq` confirms 25 keyed entries) | https://ec.europa.eu/taxation_customs/vies/faq.html ; https://web.archive.org/web/20220601id_/…/faq.html | 31 Oct 2026 |
| S6 | *Guidelines resulting from meetings of the VAT Committee* (1977–2023 compilation, 328 pp.; WP 609 → guidelines 043-045; WP 947 → guideline 058; WP 989) | https://taxation-customs.ec.europa.eu/document/download/474e7e57-7e01-4de0-ac94-e55537e505ae_en?filename=guidelines-vat-committee-meetings_en.pdf | 31 Oct 2026 |
| S7 | INDEX of Guidelines (PDF) | https://taxation-customs.ec.europa.eu/document/download/f0670fb2-7115-45ab-95a0-3ce44ed3bfb6_en?filename=index_guidelines.pdf | 31 Oct 2026 |
| S8 | C-273/11 Mecsek-Gabona (6 Sept 2012), ¶¶58–65 | CELEX:62011CJ0273 | 31 Oct 2026 (via r.jina.ai) |
| S9 | C-664/16 Vădan (21 Nov 2018) | CELEX:62016CJ0664 | 31 Oct 2026 (via r.jina.ai) |
| S10 | C-414/17 AREX CZ (19 Dec 2018) | CELEX:62017CJ0414 | 31 Oct 2026 (via r.jina.ai) |
| S11 | C-324/11 Tóth (6 Sept 2012) | CELEX:62011CJ0324 | 31 Oct 2026 (via r.jina.ai) |
| S12 | C-285/11 Bonik (6 Dec 2012) | CELEX:62011CJ0285 | 31 Oct 2026 (via r.jina.ai) |
| S13 | Joined Cases C-439/04 & C-440/04 Kittel/Recolta (6 July 2006), ¶¶51, 56 | CELEX:62004CJ0439 | 31 Oct 2026 (via r.jina.ai) |
| S14 | Joined Cases C-80/11 & C-142/11 Mahagében/Dávid (21 June 2012), ¶¶53–60, 66 | CELEX:62011CJ0080 | 31 Oct 2026 (via r.jina.ai) |
| S15 | EMTA, *How to check the background of a business partner* (VIES + name-match advice) | https://www.emta.ee/en/business-client/e-services-training-courses/advice/how-check-background-business-partner | 31 Oct 2026 |
| S16 | Estonian VAT Act (KMS), English consolidated (ELI 503012024001), incl. §5(6)2) | Riigi Teataja public API XML | 31 Oct 2026 |
| S17 | EMTA, *Payment of interests* (0.06%/day; Taxation Act §§ 97, 118) | https://www.emta.ee/en/private-client/taxes-and-payment/payment-arrears/payment-interests | 31 Oct 2026 |
| S18 | Estonian Taxation Act (MKMS), English consolidated (ELI 505012022008), §§ 153¹, 154, non-compliance levy provisions | Riigi Teataja public API XML | 31 Oct 2026 |
| S19 | UStG § 18g (refund procedure — scope check) | https://www.gesetze-im-internet.de/ustg_1980/__18g.html | 31 Oct 2026 |
| S20 | UStDV §§ 17a, 18e, 19 (confirmation provisions repealed) | https://www.gesetze-im-internet.de/ustdv_1980/ | 31 Oct 2026 |
| S21 | REB Steuerberatung (Esskandari/Bick), *Qualifizierte Bestätigungsanfrage beim BZSt: Wie oft Sie die USt-IdNr. … prüfen müssen*, 8 June 2026 (FG/BFH interval table: 14 V 3396/08; 7 K 7196/15; XI R 40/19; XI R 38/18; 2 K 482/17; UStAE 6a.8(6), 18e.1(4), 18.11(1a)) | https://reb-steuerberatung.de/insights/qualifizierte-bestaetigungsanfrage-bzst-ust-idnr-pruefen.html | 31 Oct 2026 |
| S22 | Stripe, *Account and customer tax IDs with Invoicing* (validate-once; format-based RC; VIES retries) | https://docs.stripe.com/tax/tax-ids | 31 Oct 2026 |
| S23 | Chargebee, *Enable VAT number validation* ("every 3 months + on add/update"; validation on signup and renewal) | https://support.chargebee.com/support/solutions/articles/247808-enable-vat-number-validation | 31 Oct 2026 |
| S24 | TaxJar developer blog, *Summarized Sales Tax Rates & VAT Validation* (VIES validation API; regex fallback on outage) | https://developers.taxjar.com/blog/summarized-tax-rates-and-vat-validation/ | 31 Oct 2026 |
| S25 | n8n template "Re-check EU VAT numbers on Stripe invoices with VIES" (Sept 2026) + subscription-engineering tutorial on re-validation before renewal (market practice) | search results | 31 Oct 2026 |

**Access note.** EUR-Lex via Jina Reader (WAF on direct fetch). The live VIES FAQ is a JavaScript SPA; its text was taken from the retired static page (Wayback) and cross-checked against the live `rest-api/faq` endpoint and the sister memo's 30 Oct 2026 quotes (identical for Q6/Q20). CIRCABC (VAT Committee working-paper register) would not render from this environment; the guidelines corpus was retrieved from the Commission's own compilation instead. Paddle and Avalara documentation: **UNVERIFIED** (sites unreachable/404). Big-4 cadence guidance: searched, none found publicly — negative finding.

*End of memo. No repository changes were made.*
