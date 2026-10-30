# VAT-LAW-A — Angle 1: place of supply, OSS and the B2B/B2C boundary

**Prepared:** 30 October 2026
**Prepared for:** ApexMail V30 VAT re-verification (angle 1 of 3)
**Status:** Research memo. Not legal or tax advice. No repository changes were made.
**Scope:** Place of supply of services under Directive 2006/112/EC (Arts 44, 45, 58, 59c, 196, 226, 262–264, 358a–369x), the definition of electronically supplied services (Annex II; Implementing Regulation 282/2011 Art 7 and Annex I), the OSS Union scheme (Arts 369a–369k), the deemed-supplier rules (Arts 14a, 28 and the new Art 28a), ViDA (Directive (EU) 2025/516 and its package), the B2B/B2C boundary (Art 9, Art 43, Regulation 282/2011 Arts 17–20 and 22–24f), the CJEU duty-of-care cases, and Estonia's *Käibemaksuseadus* (KMS) implementation. Angle 2 covers evidence and invoicing; angle 3 covers consumer price display and the rate table. This memo does not duplicate them; it states the place-of-supply rule and flags only the evidence consequences that are inseparable from it.

---

## 0. Bottom line — the four code-facing questions

| # | Repo assumption | Verdict | Short reason |
|---|---|---|---|
| Q1 | "B2B verified-EU-abroad reverse-charges at 0% regardless of the supplier's OSS status" | **CORRECT in substance, with three qualifications** | Art 44 places the supply at the customer's business establishment; Art 196 makes the customer liable. OSS (Arts 369a–369k) covers only supplies to non-taxable persons (Art 369b(c)), so OSS status is irrelevant to B2B. The "0%" is Estonia's zero rate for services whose place of supply is not Estonia (KMS § 15(4)(1)); it is not an EU-wide "reverse-charge rate". The reverse charge still depends on the Art 18 presumption/evidence and on ApexMail not having a fixed establishment in the customer's Member State. |
| Q2 | "B2C total = net + destination rate, destination = customer's country as declared" | **PARTLY CORRECT** | The arithmetic and the Art 58 destination rule are correct for TBE B2C above the threshold (or opted in). The declared country alone is not the legal test: Art 23(2) requires factual information from the customer verified by normal commercial security measures, and Art 24b(d) presumes the place on two non-contradictory items of evidence (Art 24f) — or, below EUR 100,000 of relevant turnover, one item from a person other than the supplier or the customer. The code stores only the declared billing country. |
| Q3 | "EUR 10,000 threshold relevant at ApexMail's scale; must use OSS destination rates" | **CORRECT if turnover > EUR 10,000; the threshold is NOT MODELLED** | Art 59c disapplies Art 58 only below EUR 10,000 (current and preceding year, EU-wide, VAT-exclusive). Above it, destination VAT is mandatory and OSS is the practical mechanism. Below it, Estonia may tax at 24% and OSS is not available for those supplies unless the Art 59c(3) opt-in is made (deemed exercised by OSS registration from 1 January 2027, ViDA Art 2(4)(b)). The code neither measures the threshold nor models the opt-in. |
| Q4 | "Does ViDA change anything before 2028?" | **YES — first substantive date 1 January 2027 (entry into force 14 April 2025)** | Directive (EU) 2025/516 entered into force 14 April 2025. Article 2 applies from 1 January 2027 and includes the amended Art 59c(3) (OSS registration deems the option exercised) and OSS/IOSS clarifications. Article 3 (new Art 28a deemed supplier for short-term accommodation/passenger transport) applies from 1 July 2028 (Art 3(1) may be delayed to 1 January 2030); Article 4 from 1 July 2029; Article 5 (e-invoicing/DRR) from 1 July 2030, with 1 January 2035 for Member States with domestic real-time reporting. Apart from that deemed-option change for below-threshold OSS-registered sellers, nothing changes the general B2C TBE place-of-supply rule or rates before 2028. |

---

## 1. Method, sources and retrieval limitations

### 1.1 Source classes

The brief requires three independent confirmations per proposition from at least two source classes. This memo uses:

1. **Primary legal text:** the consolidated VAT Directive 2006/112/EC (CELEX 02006L0112-20240101 and 02006L0112-20250414), Directive (EU) 2025/516 (CELEX 32025L0516), Implementing Regulation 282/2011 (CELEX 02011R0282-20250414), Implementing Regulation 2025/518 (CELEX 32025R0518), the Estonian KMS official English translation, and the CJEU judgments.
2. **Official administrative guidance:** European Commission OSS and ViDA pages; Estonian Tax and Customs Board (Maksu- ja Tolliamet, "EMTA") pages on VAT, services, OSS and VD reports.
3. **Independent practitioner:** PwC Worldwide Tax Summaries (Estonia), Avalara's Estonia country guide, and Deloitte's ViDA page.

### 1.2 Retrieval limitations (material to how the citations should be read)

- **EUR-Lex WAF.** Direct EUR-Lex fetches returned an AWS WAF challenge (HTTP 202 with an empty body). The consolidated texts and judgments were retrieved through the Jina Reader proxy of the same EUR-Lex URLs. The quoted article text is the official consolidated text as rendered by that proxy; the citation is to EUR-Lex. This is a retrieval limitation, not a change in the law.
- **KMS English translation.** The official English translation at `https://www.riigiteataja.ee/en/eli/ee/511072022006/consolide/current` is the redaction in force on 1 July 2022 (`511072022006`). Its rate section still shows 20%, which is stale. The section numbers used here (§ 10, § 10¹, § 15, § 27, § 28, § 36, § 37, § 43) were cross-checked against EMTA's **current** guidance, which cites the same sections for the same rules. The translation's internal numbering of § 10¹ is garbled in places; the citation is to the Estonian section, not to the translation's duplicated paragraph numbers.
- **Current Estonian redaction.** I did not obtain a current Estonian-language consolidated redaction of the KMS (Riigi Teataja is now an Angular SPA; the act page rendered through Jina is the 2022 redaction). The section mapping is therefore confirmed against the official translation plus current EMTA guidance, not against a 2026 KMS redaction. This is sufficient for the section mapping but not for quoting a 2026 amendment.
- **Not re-verified in this session:** the VIES FAQ, the Commission's OSS Explanatory Notes (including the 24 July 2026 revision mentioned in the existing repo memo), the Council press release (blocked by a browser check), and the Estonian-language KMS. Where the existing repo memo relies on these, I mark the reliance as secondary.
- **No repository changes by this agent.** The working tree was read only. During the session, however, the working tree changed under five billing files (`billing.rs`, `vat_rates.rs`, `invoices.rs`, `tax.rs`, `types.rs`) — apparently concurrent angle-2 work, uncommitted at 30 October 22:02. The code findings below describe the code as read; where the concurrent edit changes a finding, the finding says so (F4, F8, F9). Re-check the commit under review.

### 1.3 Date

All URLs were retrieved on **30 October 2026**. The law is stated as at that date.

---

## 2. Place of supply — the primary text

### 2.1 The B2B default: Article 44

Article 44 of Directive 2006/112/EC (consolidated text, CELEX 02006L0112-20250414) provides verbatim:

> "The place of supply of services to a taxable person acting as such shall be the place where that person has established his business. However, if those services are provided to a fixed establishment of the taxable person located in a place other than the place where he has established his business, the place of supply of those services shall be the place where that fixed establishment is located. In the absence of such place of establishment or fixed establishment, the place of supply of services shall be the place where the taxable person who receives such services has his permanent address or usually resides."

Three consequences follow directly from the text:

1. **The customer must be a "taxable person acting as such."** The status test is not "has a VAT number" as such; it is the Art 9/Art 43 status, for which Art 18 of Regulation 282/2011 supplies rebuttable presumptions (section 3 below).
2. **The place is the customer's business establishment, not the place of consumption.** If the service is provided to a fixed establishment of the customer in another Member State, the place is that fixed establishment. The supplier must examine the nature and use of the service and the contract/order/VAT number to identify the establishment (Regulation 282/2011 Art 22).
3. **If the customer has no establishment or fixed establishment, the place is the customer's permanent address or usual residence.** This limb is mainly relevant to sole traders and to customers outside the EU.

**Fixed establishment.** For Article 44, Regulation 282/2011 Art 11(1) defines a fixed establishment as:

> "any establishment, other than the place of establishment of a business referred to in Article 10 of this Regulation, characterised by a sufficient degree of permanence and a suitable structure in terms of human and technical resources to enable it to receive and use the services supplied to it for its own needs."

Art 11(3) adds: "The fact of having a VAT identification number shall not in itself be sufficient to consider that a taxable person has a fixed establishment." The CJEU in **C-605/12 Welmory** held that a customer has a fixed establishment in another Member State for Art 44 purposes if the establishment has "a sufficient degree of permanence and a suitable structure in terms of human and technical resources to enable it to receive the services supplied to it and use them for its business" (operative part). For the supplier's side, Art 11(2)(a) uses the same concept for Art 45: an establishment with a suitable structure in terms of human and technical resources "to enable it to provide the services which it supplies."

**ApexMail fact to confirm.** The repository's architecture documents state that production runs on "a single Hetzner host, Finland" (`/Users/sabelakhoua/IdeaProjects/ApexMail/ARCHITECTURE.md` line 12; `/Users/sabelakhoua/IdeaProjects/ApexMail/docs/architecture/overview.md` line 12). A rented host operated remotely is not automatically a fixed establishment, but it is also not automatically *not* one. If ApexMail were found to have a Finnish fixed establishment from which supplies are made, then for Finnish B2B customers (i) the place of supply would still be Finland under Art 44, but (ii) ApexMail would be "established" in Finland for Art 192a/Art 196 purposes and the reverse charge would not apply; ApexMail would have to register and charge Finnish VAT. The code has no fixed-establishment model and assumes Estonia-only supply. This is a fact for the accountant, not a conclusion of this memo. **UNVERIFIED (fact-dependent).**

### 2.2 Article 196 — who is liable

Article 196 provides verbatim:

> "VAT shall be payable by any taxable person, or non-taxable legal person identified for VAT purposes, to whom the services referred to in Article 44 are supplied, if the services are supplied by a taxable person not established within the territory of the Member State."

The conditions are cumulative:

- the supply is one referred to in Article 44 (i.e., B2B);
- the supplier is a taxable person **not established** in the Member State where the VAT is due;
- the customer is a taxable person, or a non-taxable legal person identified for VAT purposes.

"Not established" is tested against the place of business and any fixed establishment that intervenes in the supply (Art 192a). For ApexMail, the assumption is that it has no establishment or intervening fixed establishment outside Estonia. If that assumption fails for a given Member State, Art 196 does not apply there and ApexMail must charge that Member State's VAT.

Article 196 does **not** apply to B2C supplies. B2C e-services are governed by Art 58 (and, where relevant, the OSS scheme), not by Art 196.

### 2.3 The B2C rules: Articles 45 and 58

Article 45 states the general B2C rule verbatim:

> "The place of supply of services to a non-taxable person shall be the place where the supplier has established his business. However, if those services are provided from a fixed establishment of the supplier located in a place other than the place where he has established his business, the place of supply of those services shall be the place where that fixed establishment is located. In the absence of such place of establishment or fixed establishment, the place of supply of services shall be the place where the supplier has his permanent address or usually resides."

Article 58(1) then provides the specific rule for telecommunications, broadcasting and electronically supplied services verbatim:

> "The place of supply of the following services to a non-taxable person shall be the place where that person is established, has his permanent address or usually resides:
> (a) telecommunications services;
> (b) radio and television broadcasting services;
> (c) electronically supplied services, in particular those referred to in Annex II.
> Where the supplier of a service and the customer communicate via electronic mail, that shall not of itself mean that the service supplied is an electronically supplied service."

The relationship is important:

- **Article 45 is the default.** If a B2C service is not a telecommunications, broadcasting or electronically supplied service, the place of supply is the supplier's establishment — Estonia — even for a customer abroad. Estonian 24% VAT applies (unless an Article 59 rule moves it outside the EU).
- **Article 58 is the exception.** For TBE services, the place is the customer's establishment/permanent address/usual residence. This is the rule that makes cross-border B2C SaaS a destination-taxed supply.
- **The last sentence of Article 58 is a classification caveat, not an exclusion of email services.** It says that the mere fact that supplier and customer communicate by email does not make the service electronically supplied. It does not say that a hosted email platform is not electronically supplied. The object of the supply (the email infrastructure) is different from the channel used to discuss it. Regulation 282/2011 Art 7(3)(i) makes the same point for professionals who advise clients by email.

**Non-EU customers.** Article 58 is not limited to EU customers: it places the supply wherever the non-taxable customer is established, has a permanent address or usually resides. For a US consumer, the place is the US; the supply is outside the EU and no EU VAT applies. Article 45 would otherwise place a non-TBE B2C supply in Estonia, but Article 59 moves certain listed services to the customer's non-EU location; for TBE services, Article 58 already does so.

### 2.4 What is an "electronically supplied service"?

The statutory definition is in Regulation 282/2011 Art 7(1) verbatim:

> "'Electronically supplied services' as referred to in Directive 2006/112/EC shall include services which are delivered over the Internet or an electronic network and the nature of which renders their supply essentially automated and involving minimal human intervention, and impossible to ensure in the absence of information technology."

Art 7(2) adds a non-exhaustive list, including:

> "(a) the supply of digitised products generally, including software and changes to or upgrades of software;
> (b) services providing or supporting a business or personal presence on an electronic network such as a website or a webpage;
> (c) services automatically generated from a computer via the Internet or an electronic network, in response to specific data input by the recipient;
> ...
> (e) Internet Service Packages (ISP) of information in which the telecommunications component forms an ancillary and subordinate part (i.e. packages going beyond mere Internet access and including other elements such as content pages giving access to news, weather or travel reports; playgrounds; website hosting; access to online debates etc.);
> (f) the services listed in Annex I."

Art 7(3) excludes, among others:

> "(b) telecommunications services;
> ...
> (i) services of professionals such as lawyers and financial consultants, who advise clients by e-mail;"

Annex II to the VAT Directive (the indicative list referred to in Art 58(1)(c)) includes:

> "(1) Website supply, web-hosting, distance maintenance of programmes and equipment;
> (2) supply of software and updating thereof;
> (3) supply of images, text and information and making available of databases;
> (4) supply of music, films and games, including games of chance and gambling games, and of political, cultural, artistic, sporting, scientific and entertainment broadcasts and events;
> (5) supply of distance teaching."

Annex I to Regulation 282/2011 gives the detailed examples, including:

> "(1)(a) Website hosting and webpage hosting;
> (1)(c) remote systems administration;
> (1)(d) online data warehousing where specific data is stored and retrieved electronically;
> (1)(e) online supply of on-demand disc space.
> (2)(a) Accessing or downloading software (including procurement/accountancy programmes and anti-virus software) plus updates."

**Why hosted email/API sending qualifies.** A hosted email platform/API has the following features:

1. It is delivered over the internet or an electronic network (SMTP/API/dashboard), not physically.
2. Its supply is essentially automated and involves minimal human intervention: the customer configures domains, sends via API/SMTP, and the platform routes, stores and reports automatically.
3. It is impossible to ensure in the absence of information technology: there is no non-IT way to provide it.
4. It falls within the Annex II categories: it is web-hosting/remote maintenance of programmes (Annex II(1)), supply of software and updates (Annex II(2)), and/or making available information/databases (Annex II(3)); Regulation 282/2011 Annex I(1)(a), (c), (d) and (2)(a) confirm the same.
5. It is not the kind of "professional advice by email" excluded by Art 7(3)(i): the email is the object of the service, not merely the channel.

**The alternative classification does not change the result.** Email transmission is also capable of being a "telecommunications service" under Art 24(2):

> "'Telecommunications services' shall mean services relating to the transmission, emission or reception of signals, words, images and sounds or information of any nature by wire, radio, optical or other electromagnetic systems, including the related transfer or assignment of the right to use capacity for such transmission, emission or reception, with the inclusion of the provision of access to global information networks."

If ApexMail's service were classified as telecommunications rather than as an electronically supplied service, Art 58(1)(a) applies the **same** destination rule, and the Art 59c threshold covers "supplies of services covered by Article 58" without distinguishing between the three categories. So the place-of-supply conclusion (destination, threshold, OSS) is robust across the two classifications. The classification matters for other purposes (e.g., the Annex II/Annex I evidence narrative, and any sector-specific rules), but not for the B2C destination result.

**The real classification risk is different: non-TBE components.** A human-delivered onboarding, migration, consulting or on-site setup service is not automatically part of the TBE supply. If it is a separate supply, its B2C place of supply is Estonia under Art 45 (24%), not the customer's country; its B2B place is the customer's establishment under Art 44 (reverse charge), which happens to look the same as the TBE result but for a different reason. A single contract can contain a principal TBE supply with ancillary non-TBE elements; the classification must be per supply. The code has no tax-classification field and applies the same rule to every line item. This is a code-facing finding (F10).

### 2.5 The EUR 10,000 threshold: Article 59c

Article 59c(1) provides verbatim:

> "Point (a) of Article 33 and Article 58 shall not apply, where the following conditions are met:
> (a) the supplier is established or, in the absence of an establishment, has his permanent address or usually resides only in one Member State;
> (b) services are supplied to non-taxable persons who are established, have their permanent address or usually reside in any Member State other than the Member State referred to in point (a) or goods are dispatched or transported to a Member State other than the Member State referred to in point (a); and
> (c) the total value, exclusive of VAT, of the supplies referred to in point (b) does not in the current calendar year exceed EUR 10 000, or the equivalent in national currency, nor did it do so in the course of the preceding calendar year."

Article 59c(2): "Where, during a calendar year, the threshold referred to in point (c) of paragraph 1 is exceeded, point (a) of Article 33 and Article 58 shall apply as of that time."

Article 59c(3): the Member State of establishment "shall grant taxable persons carrying out supplies eligible under paragraph 1 the right to opt for the place of supply to be determined in accordance with point (a) of Article 33 and Article 58, which shall in any event cover two calendar years."

What the text does and does not do:

- **It applies only to Article 58 supplies and Article 33(a) distance goods.** It does not apply to Article 44 B2B supplies, and it does not apply to B2C services outside Article 58 (those remain under Art 45, i.e. Estonian VAT, regardless of the threshold). This is the textual answer to the "threshold interaction with B2B" question.
- **It is EU-wide and combined.** The threshold is the total of the Article 58 services plus the Article 33(a) goods, exclusive of VAT, in the current and preceding calendar year. It is not per country. It is also **not** Estonia's VAT registration threshold (EUR 40,000; KMS § 19 in the official translation, cited by EMTA as § 19¹; EMTA; PwC). The EUR 10,000 figure is a place-of-supply threshold, not a registration threshold.
- **It requires the supplier to be established in only one Member State.** If ApexMail has a fixed establishment in Finland, the condition in point (a) fails and the threshold is unavailable — destination taxation applies regardless (subject to the Art 58/44 analysis for the Finnish establishment).
- **Below the threshold, Article 58 does not apply.** The place of supply falls back to Article 45: Estonia. Estonian 24% VAT may be charged. The supplier may instead opt into destination taxation for at least two calendar years under Art 59c(3), and then use OSS.
- **Above the threshold (or if the preceding year exceeded it), Article 58 applies from 1 January of the current year; a mid-year breach applies "as of that time" (Art 59c(2)).** The earlier part of the year is not retroactively re-taxed under Art 58.
- **The option is not the same as OSS registration before 2027.** From 1 January 2027, ViDA Art 2(4)(b) amends Art 59c(3) so that "the option referred to in the first subparagraph of this paragraph is deemed to have been exercised by taxable persons registered in the special scheme provided for in Title XII, Chapter 6, Section 3" (the Union scheme). So after 2027, an OSS-registered seller cannot simultaneously rely on the threshold to charge Estonian VAT.

The Commission's OSS guidance confirms the same rule in administrative language:

> "An annual EUR 10 000 turnover threshold for cross-border supplies of B2C TBE services has been introduced on 1 January 2019, up to which the place of supply of such services remains in the Member State where the supplier is established... As from 1 July 2021, this threshold also covers intra-Community distance sales of goods..."
> "The threshold of EUR 10 000 only applies to TBE services and intra-Community distance sales of goods. It does not apply to other services than TBE services nor to distance sales of imported goods."
> "If all these conditions are met, these supplies are subject to VAT in accordance with the rules applicable in the Member State of the supplier. The One Stop Shop (Union scheme) is not relevant in this situation, because the supplies will be domestic supplies and cannot be declared in the OSS supply."

EMTA's current OSS guidance says the same:

> "The all-in threshold 10 000 euros is introduced for gross supply of intra-Community distance selling of goods (to all Member States together) and digital services provided to the end users of other Member States. If this threshold is not exceeded, the VAT rate of the country of the seller can be applied upon the taxation of these supplies."
> "Abovementioned 10 000 euros threshold is not applied for other services (besides digital services) where the place of supply is the country of the place of residence of the end user."

**The separate EUR 100,000 threshold.** Regulation 282/2011 Art 24b, second paragraph, contains a **different** threshold: where the total value of the relevant supplies does not exceed EUR 100,000 in the current and preceding calendar year, the Art 24b(d) presumption may be made on the basis of **one** item of evidence "provided by a person involved in the supply of the services other than the supplier or the customer." This is an **evidence** threshold, not the place-of-supply threshold. Confusing the two is a common error; they answer different questions and have different amounts.

### 2.6 The OSS Union scheme: Articles 369a–369k

The chapter range in the brief (Arts 358a–369x) is the whole of Title XII, Chapter 6. The chapter has four sections:

| Section | Articles | Scheme | Who it is for |
|---|---|---|---|
| 1 | 358 | General provisions / definitions | — |
| 2 | 358a–369 | Non-Union scheme | Taxable persons **not established in the Community** (Art 358a(1)) |
| 3 | 369a–369k | **Union scheme** | Taxable persons established in the Community but not in the Member State of consumption (Art 369a(1)) |
| 4 | 369l–369x | Import scheme (IOSS) | Distance sales of imported goods ≤ EUR 150 |

For an Estonian-established seller, **Section 3 (the Union scheme) is the relevant scheme**. Section 2 does not apply because ApexMail has established its business in the Community. The scheme is **optional**: the legal obligation above the threshold is to apply destination VAT, and the seller can instead register in each Member State of consumption. OSS is the single-registration mechanism that makes destination taxation practical; it is not itself the source of the destination obligation (Art 58 is).

The key Union-scheme provisions, verbatim:

**Article 369a(1):**

> "'taxable person not established in the Member State of consumption' means a taxable person who has established his business in the Community or has a fixed establishment there but who has not established his business and has no fixed establishment within the territory of the Member State of consumption."

**Article 369a(2), first subparagraph:**

> "'Member State of identification' means the Member State in the territory of which the taxable person has established his business or, if he has not established his business in the Community, where he has a fixed establishment."

For ApexMail, the Member State of identification (MSI) is **Estonia**.

**Article 369b:**

> "Member States shall permit the following taxable persons to use this special scheme:
> (a) a taxable person carrying out intra-Community distance sales of goods;
> (b) a taxable person facilitating the supply of goods in accordance with Article 14a(2) where the dispatch or transport of the goods supplied begins and ends in the same Member State;
> (c) a taxable person not established in the Member State of consumption supplying services to a non-taxable person.
> This special scheme applies to all those goods or services supplied in the Community by the taxable person concerned."

**Article 369d:**

> "A taxable person making use of this special scheme shall, for the taxable transactions carried out under this scheme, be identified for VAT purposes in the Member State of identification only. For that purpose the Member State shall use the individual VAT identification number already allocated to the taxable person in respect of his obligations under the internal system."

**Article 369f:**

> "The taxable person making use of this special scheme shall submit by electronic means to the Member State of identification a VAT return for each calendar quarter, whether or not supplies of goods and services covered by this special scheme have been carried out. The VAT return shall be submitted by the end of the month following the end of the tax period covered by the return."

**Article 369g(4):**

> "Where any amendments to the VAT return are required after its submission, such amendments shall be included in a subsequent return within three years of the date on which the initial return was required to be submitted pursuant to Article 369f. That subsequent VAT return shall identify the relevant Member State of consumption, the tax period and the amount of VAT for which any amendments are required."

**Article 369k:**

> "1. The taxable person making use of this special scheme shall keep records of the transactions covered by this special scheme. Those records must be sufficiently detailed to enable the tax authorities of the Member State of consumption to verify that the VAT return is correct.
> 2. The records referred to in paragraph 1 must be made available electronically on request to the Member State of consumption and to the Member State of identification.
> Those records must be kept for a period of 10 years from 31 December of the year during which the transaction was carried out."

**What the Union scheme does and does not cover for ApexMail:**

- It covers cross-border B2C supplies of services to non-taxable persons in Member States where ApexMail is **not** established (Art 369b(c), Art 369a(1)). It is not limited to TBE services: since 1 July 2021 the Union scheme covers all B2C services, not only TBE. But only supplies whose place of supply is another Member State can be declared in OSS.
- It does **not** cover B2B supplies. Those are outside the scheme (Art 369b(c) is limited to "a non-taxable person") and are reported in the recapitulative statement (Art 262(1)(c)).
- It does **not** cover supplies to Estonian consumers. The place of supply is Estonia (Art 45 or Art 10¹ KMS), and those supplies are declared in the Estonian VAT return (KMD), not OSS. Regulation 282/2011 Art 57c states this expressly: "The Union scheme shall not apply to services supplied in a Member State where the taxable person has established his business or has a fixed establishment. The supply of those services shall be declared to the competent tax authorities of that Member State in the VAT return as provided for in Article 250 of Directive 2006/112/EC." The Commission states the same in its OSS guidance: "Services supplied to non-taxable persons that take place in a Member State in which the supplier has an establishment cannot be declared in the Union scheme, but have to be declared in the national VAT return of the respective Member State."
- It applies to **all** eligible supplies of the taxable person (Art 369b, last sentence). A seller cannot cherry-pick which B2C supplies go into OSS.
- **Registration timing.** Regulation 282/2011 Art 57d(1): the scheme applies from the first day of the following calendar quarter; where the first covered supply takes place before that date, it applies from the date of that first supply, provided the MSI is informed no later than the tenth day of the month following that first supply.
- The return is **quarterly**, due at the end of the month following the quarter (Art 369f). EMTA's deadlines are 30 April, 31 July, 31 October and 31 January.
- Records are kept for **10 years from 31 December of the transaction year** (Art 369k(2)); corrections are made in a subsequent return within **three years** of the original due date (Art 369g(4)).

**The brief's article numbers.** The brief refers to "358a definitions, 359 registration, 361 identification member state, 363a? returns, 365 quarterly filing, 369 records 10 years". Those are the **non-Union scheme** numbers (Section 2), not the Union scheme:

- Art 358a defines the non-Union scheme's "taxable person not established within the Community", MSI and Member State of consumption.
- Art 359 permits the non-Union scheme; Art 361 lists the registration information.
- There is **no Article 363a**.
- Art 364 is the non-Union quarterly return; Art 365 is its content (not the filing obligation).
- Art 369 is the non-Union 10-year records rule.

For an Estonian seller, the correct citations are **Art 369b (who may use), Art 369a(2) and 369d (MSI/identification), Art 369f (quarterly return), Art 369g (content and three-year corrections), Art 369k (10-year records)**. The existing repo memo's "Articles 369a–369k" is correct; the brief's range is the whole chapter, and its specific article numbers belong to the other scheme.

### 2.7 Deemed-supplier rules: what applies to a direct sale?

The pre-ViDA deemed receipt-and-supply rules that could matter are:

- **Article 14a** (goods): a taxable person who facilitates, through an electronic interface, (i) distance sales of goods imported from third countries in consignments ≤ EUR 150, or (ii) the supply of goods within the Community by a taxable person not established in the Community to a non-taxable person, is deemed to have received and supplied those goods himself. Article 14a is about **goods**, not services.
- **Article 28** (services): "Where a taxable person acting in his own name but on behalf of another person takes part in a supply of services, he shall be deemed to have received and supplied those services himself." This is the commissionnaire rule. It applies if ApexMail acts as principal for a third party's service; it does not apply to ApexMail's own service.

There is **no Article 9a** in the current consolidated text. I searched both the 2024 and 2025 consolidations and the ViDA directive; no Article 9a exists. The brief's "Arts. 9a, 28a" therefore needs correction:

- **Article 9a:** does not exist.
- **Article 28a:** inserted by ViDA Directive (EU) 2025/516, Article 3(1), with effect from **1 July 2028** (Member States may delay Article 3(1) to **1 January 2030**). It applies to a taxable person who facilitates, through an electronic interface, the supply within the Union of **short-term accommodation rental services** (uninterrupted rental to the same person for a maximum of 30 nights) or **passenger transport services by road**. It deems that person to have received and supplied those services unless the underlying supplier has provided its VAT identification number and declared that it will charge the VAT due. It is irrelevant to ApexMail's email SaaS.

**ApexMail's direct-sale position.** ApexMail sells its own email service. It is the supplier, not a deemed supplier. The payment providers (Stripe, Mollie) are payment processors, not merchants of record: the repository's payments module states that Stripe is "PAYMENTS-ONLY: no provider-owned subscription objects — ApexMail owns scheduling" (`/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/payments/mod.rs`, lines 1–30). On that model, ApexMail is the supplier for VAT and there is no deemed-supply chain.

**The boundary to watch.** If ApexMail ever switches to a merchant-of-record/reseller model (e.g., Paddle, FastSpring), the VAT analysis changes: the MoR becomes the supplier to the consumer, and ApexMail's sale to the MoR is a B2B supply. That is a contractual/business-model change, not a code detail. The current architecture keeps ApexMail as the supplier; that is the correct model for the existing VAT treatment.

### 2.8 Non-EU customers: no EU VAT, no export formalities

- **B2B non-EU:** Article 44 places the supply at the customer's business establishment (or permanent address/usual residence), which is outside the EU. The supply is outside the territorial scope of EU VAT. No EU VAT is due. Estonian KMS § 15(4)(1) zero-rates "services where the place of supply is not Estonia, excluding cases where the supply of such services is exempt from tax pursuant to § 16". So the Estonian return shows a 0% supply, not an exempt one.
- **B2C non-EU:** Article 58 places the supply at the customer's establishment/permanent address/usual residence, outside the EU. No EU VAT. The same KMS § 15(4)(1) 0% treatment applies.
- **No export/customs formalities.** The export exemption in Articles 146–166 concerns **goods** and customs procedures. Services are not "exported" in the customs sense; there is no export declaration, no EORI requirement and no customs procedure for a service. The territorial result comes from the place-of-supply rule, not from an export exemption.
- **Documentation, not a customs formality.** KMS § 15(5) requires that the 0% rate be certified by "a contract concluded for the provision of such service, a written order, invoice or other document in proof of the provision of the service", and the tax authority may request additional documents. For a non-EU business customer, the supplier should also hold the evidence described in Regulation 282/2011 Art 18(3): a certificate from the customer's tax authority, or the customer's VAT/similar number plus reasonable verification by normal commercial security measures. There is no customs declaration, but there is a documentary burden.

### 2.9 ViDA: Directive (EU) 2025/516 and the package

The ViDA package is:

| Instrument | Number and date | OJ | CELEX |
|---|---|---|---|
| Council Directive | (EU) 2025/516 of 11 March 2025, amending Directive 2006/112/EC as regards VAT rules for the digital age | OJ L, 2025/516, 25.3.2025 | 32025L0516 |
| Council Regulation | (EU) 2025/517 of 11 March 2025, amending Regulation (EU) No 904/2010 as regards the VAT administrative cooperation arrangements needed for the digital age | OJ L, 2025/517, 25.3.2025 | 32025R0517 |
| Council Implementing Regulation | (EU) 2025/518 of 11 March 2025, amending Implementing Regulation (EU) No 282/2011 as regards information requirements for certain VAT schemes | OJ L, 2025/518, 25.3.2025 | 32025R0518 |

**Entry into force.** Article 7 of Directive 2025/516: "This Directive shall enter into force on the twentieth day following that of its publication in the Official Journal of the European Union." Publication was 25 March 2025, so entry into force was **14 April 2025**. The Commission's ViDA page confirms: "Upon entry into force (14 April 2025), Member States are able to introduce mandatory e-invoicing under specific conditions, and improvements were made to the Import One-Stop-Shop (IOSS) framework."

**The phased application dates.** Article 6 of Directive 2025/516:

| Article of 2025/516 | Subject | Transposition deadline | Application date |
|---|---|---|---|
| Art 1 | Amendments with effect from entry into force: Art 218(2) option for domestic e-invoicing; Art 232 acceptance derogation; Art 143(1a) IOSS control | — (Member States may apply Art 1(2),(3) from 14 April 2025) | 14 April 2025 |
| Art 2 | Amendments with effect from **1 January 2027**: Art 14a replacement; Art 17a; Art 59c(3) deemed option; Art 66; Art 167a; Art 226(7a); non-Union scheme (Arts 359, 361, 368, 369j, 369p, 369w) | 31 December 2026 | **1 January 2027** |
| Art 3 | Amendments with effect from **1 July 2028**: new Art 28a (deemed supplier for short-term accommodation/passenger transport); new Art 46a (facilitation service place of supply); Art 135; Art 136b; Art 194; Art 242a; Art 262; Art 369a/b/g/p/t | 30 June 2028 | **1 July 2028**; Art 3(1) (Art 28a) at the earliest 1 July 2028 and at the latest **1 January 2030** |
| Art 4 | Amendments with effect from **1 July 2029**: deletion of Art 243(3) and Art 262(2) (call-off stock) | 30 June 2029 | **1 July 2029** |
| Art 5 | Amendments with effect from **1 July 2030**: e-invoicing and digital reporting (Arts 217, 218, 222, 223, 226, 232, 235, 236, 262–264, 271a–271c); Art 273 | 30 June 2030 | **1 July 2030**; Member States with a domestic real-time transaction-based reporting obligation on 1 January 2024 apply the domestic e-invoicing/reporting measures by **1 January 2035** |

**What changes for ApexMail, and when:**

1. **14 April 2025 — entry into force / optional domestic e-invoicing.** Member States may require e-invoicing for domestic supplies (Art 218(2), inserted by Art 1(2) of 2025/516). This does not change the place of supply or the OSS. On the sources retrieved, a general Estonian B2B e-invoicing mandate was not confirmed (the existing repo memo flags the same gap); this is an angle-2/horizon item.
2. **1 January 2027 — the first date that touches ApexMail's OSS position.** Art 2(4)(b) amends Art 59c(3): the option to tax at destination is deemed exercised by taxable persons registered in the Union scheme. For an above-threshold seller already in OSS, this changes nothing in the VAT result; for a below-threshold seller, it removes the ability to be OSS-registered while charging Estonian VAT. The other Art 2 changes are mostly technical/non-Union/IOSS clarifications. The Commission describes them as "minor legislative clarifications [that] will impact users of the One-Stop Shop (OSS) and IOSS schemes."
3. **1 July 2028 — the platform-economy deemed supplier and Single VAT Registration reforms.** Art 28a makes platforms deemed suppliers for short-term accommodation rental and passenger transport by road (with a possible delay to 1 January 2030). Art 369b is amended to add certain **B2B goods** supplies and own-goods transfers to the Union scheme, and a new Section 5 (transfer-of-own-goods scheme) is added. This is the "Single VAT Registration" reform. It does **not** extend OSS to B2B **services**; B2B services remain under Art 44/196 and the recapitulative statement. Art 194 is replaced to make the reverse charge mandatory for non-established suppliers in certain cases. None of this changes ApexMail's direct B2C SaaS or its B2B services.
4. **1 July 2029 — call-off stock clean-up.** Art 262(2) and Art 243(3) are deleted. Not relevant to ApexMail.
5. **1 July 2030 — e-invoicing and digital reporting for intra-EU B2B.** Art 5 replaces Art 218 (e-invoices as the default), Art 222 (10-day invoice deadline), Art 226 (new points (16), (17)), and Arts 262–264 (the recapitulative statement is replaced by transaction-by-transaction digital reporting). For ApexMail's cross-border B2B invoices, this will require structured e-invoices and near-real-time reporting; the B2C OSS return remains quarterly. **1 January 2035** is the alignment deadline for Member States with a domestic real-time reporting system, not a second EU-wide phase.

**Answer to "does ViDA change anything before 2028?"** Yes: 14 April 2025 (entry into force; optional domestic e-invoicing) and **1 January 2027** (Art 59c(3) deemed option and OSS/IOSS clarifications). For an above-threshold seller, neither changes the B2C TBE place-of-supply result, the destination principle, or the rates. For a below-threshold seller, the 2027 deemed option **does** change the place of supply: OSS registration makes destination taxation apply even though the threshold is not exceeded. The first date on which ApexMail's **substantive** VAT position could change is therefore 1 January 2027, and only if it is OSS-registered and below the threshold. The 2028 changes are platform-economy/goods reforms that do not apply to ApexMail's own email service.

---

## 3. The B2B/B2C boundary

### 3.1 The legal test

Article 9(1) of the VAT Directive defines a taxable person:

> "'Taxable person' shall mean any person who, independently, carries out in any place any economic activity, whatever the purpose or results of that activity.
> Any activity of producers, traders or persons supplying services, including mining and agricultural activities and activities of the professions, shall be regarded as 'economic activity'. The exploitation of tangible or intangible property for the purposes of obtaining income therefrom on a continuing basis shall in particular be regarded as an economic activity."

Article 43 adds two place-of-supply-specific rules:

> "For the purpose of applying the rules concerning the place of supply of services:
> 1. a taxable person who also carries out activities or transactions that are not considered to be taxable supplies of goods or services in accordance with Article 2(1) shall be regarded as a taxable person in respect of all services rendered to him;
> 2. a non-taxable legal person who is identified for VAT purposes shall be regarded as a taxable person."

Regulation 282/2011 Art 17(1) confirms that the status of the customer is determined "on the basis of Articles 9 to 13 and Article 43 of Directive 2006/112/EC"; Art 17(2) confirms the identified non-taxable legal person.

### 3.2 The presumptions and the evidence

The supplier does not have to prove the customer's status in the abstract. Regulation 282/2011 provides rebuttable presumptions.

**Article 18(1):**

> "Unless he has information to the contrary, the supplier may regard a customer established within the Community as a taxable person:
> (a) where the customer has communicated his individual VAT identification number to him, and the supplier obtains confirmation of the validity of that identification number and of the associated name and address in accordance with Article 31 of Council Regulation (EC) No 904/2010 ...;
> (b) where the customer has not yet received an individual VAT identification number, but informs the supplier that he has applied for it and the supplier obtains any other proof which demonstrates that the customer is a taxable person or a non-taxable legal person required to be identified for VAT purposes and carries out a reasonable level of verification of the accuracy of the information provided by the customer, by normal commercial security measures such as those relating to identity or payment checks."

**Article 18(2):**

> "Unless he has information to the contrary, the supplier may regard a customer established within the Community as a non-taxable person when he can demonstrate that the customer has not communicated his individual VAT identification number to him.
> However, irrespective of information to the contrary, the supplier of telecommunications, broadcasting or electronically supplied services, or of services under Article 54(1), second subparagraph, of Directive 2006/112/EC, may regard a customer established within the Community as a non-taxable person as long as that customer has not communicated their individual VAT identification number to the supplier of those services."

The second subparagraph is the practical key for ApexMail: for TBE services, the VAT number is the boundary. If the customer does not communicate a VAT number, the supplier may treat it as non-taxable (B2C) even if it has contrary information. If the customer does communicate a VAT number, the supplier can rely on the Art 18(1)(a) presumption only with the VIES confirmation of validity and associated name/address; if that is unavailable or the number is invalid, the supplier must charge VAT unless it can establish taxable status by other proof and reasonable verification.

**Article 19 (capacity):**

> "For the purpose of applying the rules concerning the place of supply of services laid down in Articles 44 and 45 of Directive 2006/112/EC, a taxable person, or a non-taxable legal person deemed to be a taxable person, who receives services exclusively for private use, including use by his staff, shall be regarded as a non-taxable person.
> Unless he has information to the contrary, such as information on the nature of the services provided, the supplier may consider that the services are for the customer's business use if, for that transaction, the customer has communicated his individual VAT identification number.
> Where one and the same service is intended for both private use, including use by the customer's staff, and business use, the supply of that service shall be covered exclusively by Article 44 of Directive 2006/112/EC, provided there is no abusive practice."

**Article 20 (location of a B2B customer):**

> "Where a supply of services carried out for a taxable person, or a non-taxable legal person deemed to be a taxable person, falls within the scope of Article 44 of Directive 2006/112/EC, and where that taxable person is established in a single country, or, in the absence of a place of establishment of a business or a fixed establishment, has his permanent address and usually resides in a single country, that supply of services shall be taxable in that country.
> The supplier shall establish that place based on information from the customer, and verify that information by normal commercial security measures such as those relating to identity or payment checks.
> The information may include the VAT identification number attributed by the Member State where the customer is established."

**Article 23(2) (location of a B2C customer):**

> "Where, in accordance with Article 54(1), second subparagraph, and Articles 58 and 59 of Directive 2006/112/EC, a supply of services is taxable at the place where the customer is established, or, in the absence of an establishment, where the customer has their permanent address or usually resides, the supplier shall establish that place based on factual information provided by the customer, and verify that information by normal commercial security measures such as those relating to identity or payment checks."

**Article 24b(d) (presumption for TBE B2C):**

> "For the application of Article 54(1), second subparagraph, or Article 58 of Directive 2006/112/EC, where the activities are streamed or otherwise made virtually available to a non-taxable person, or where telecommunications, broadcasting or electronically supplied services are supplied to a non-taxable person:
> ...
> (d) under circumstances other than those referred to in Article 24a and in points (a), (b) and (c) of this Article, it shall be presumed that the customer is established, has his permanent address or usually resides at the place identified as such by the supplier on the basis of two items of non-contradictory evidence as listed in Article 24f of this Regulation."

The second paragraph adds the EUR 100,000 evidence threshold:

> "Without prejudice to point (d) of the first paragraph, for supplies of services falling under that point, where the total value of such supplies, exclusive of VAT, provided by a taxable person from his business establishment or a fixed establishment located in a Member State, does not exceed EUR 100 000, or the equivalent in national currency, in the current and the preceding calendar year, the presumption shall be that the customer is established, has his permanent address or usually resides at the place identified as such by the supplier on the basis of one item of evidence provided by a person involved in the supply of the services other than the supplier or the customer, as listed in points (a) to (e) of Article 24f."

**Article 24f (evidence list):**

> "(a) the billing address of the customer;
> (b) the internet Protocol (IP) address of the device used by the customer or any method of geolocation;
> (c) bank details such as the location of the bank account used for payment or the billing address of the customer held by that bank;
> (d) the Mobile Country Code (MCC) of the International Mobile Subscriber Identity (IMSI) stored on the Subscriber Identity Module (SIM) card used by the customer;
> (e) the location of the customer's fixed land line through which the service is supplied to him;
> (f) other commercially relevant information."

**Article 24d(1) (rebuttal):**

> "Where a supplier supplies a service under Article 54(1), second subparagraph, of Directive 2006/112/EC, or a service listed in Article 58(1) of that Directive, the supplier may rebut a presumption referred to in Article 24a or Article 24b, first subparagraph, point (a), (b) or (c), of this Regulation on the basis of three items of non-contradictory evidence indicating that the customer is established, has their permanent address or usually resides elsewhere."

**Article 25 (time):** "For the application of the rules governing the place of supply of services, only the circumstances existing at the time of the chargeable event shall be taken into account. Any subsequent changes to the use of the service received shall not affect the determination of the place of supply, provided there is no abusive practice."

**Practical test for ApexMail:**

- **B2B:** a business customer with a VAT number + VIES confirmation of validity and associated name/address (Art 18(1)(a)); or, if no number yet, other proof + reasonable verification (Art 18(1)(b)). The supplier must have no information to the contrary. The supplier should also verify the customer's location by normal commercial security measures (Art 20).
- **B2C:** the supplier must establish the customer's location on factual information and verify it (Art 23(2)); the Art 24b(d) presumption requires two non-contradictory items from Art 24f (or one third-party item under EUR 100,000). A declared country is at most **one** item (part of the billing address, Art 24f(a)); it is not two, and it is not from a third party. A second item (IP address/geolocation, bank country, MCC, landline, other commercial information) is needed to rely on the presumption.
- **If the customer provides no VAT number:** Art 18(2) second subparagraph permits treating it as non-taxable for TBE services. That is the B2C branch. A self-declared "business" flag without a VAT number does **not** displace that presumption; the code's treatment (business but no VAT number → destination VAT) is correct.
- **If the customer provides an invalid number:** the Art 18(1)(a) presumption is unavailable; the supplier must charge VAT unless Art 18(1)(b) applies. The supplier cannot rely on the structural shape of the number alone.

### 3.3 The CJEU duty-of-care cases — what each actually holds

The four cases in the brief are not place-of-supply cases. They are about the right to deduct and the exemption for intra-Community supplies of goods. Their common principle — good faith and all reasonable measures; no automatic refusal without objective evidence — is applied by analogy to the supplier's status/evidence judgments for services, but the **operative rule for services is Regulation 282/2011 Art 18**, not these judgments. I state each holding precisely so the repo does not over-read them.

**C-587/10 Vogtländische Straßen-, Tief- und Rohrleitungsbau GmbH Rodewisch (VSTR), judgment of 27 September 2012.** Operative part:

> "The first subparagraph of Article 28c(A)(a) of Sixth Council Directive 77/388/EEC ... should be interpreted as not precluding the tax authority of a Member State from making the exemption from VAT of an intra-Community supply subject to the provision by the supplier of the VAT identification number of the person acquiring the goods, with the proviso that the grant of that exemption should not be refused on the sole ground that that requirement was not fulfilled where the supplier, acting in good faith and having taken all the measures which can reasonably be required of him, is unable to provide that identification number but provides other information which is such as to demonstrate sufficiently that the person acquiring the goods is a taxable person acting as such in the transaction at issue."

At paragraph 52 the Court adds:

> "although it is legitimate to require that the supplier act in good faith and take every measure which can reasonably be required of him to ensure that the transaction that he effects does not lead to his participation in tax evasion ..., the Member States would be going further than the measures strictly necessary for the correct collection of tax if they refused to grant the VAT exemption ... on the sole ground that the VAT identification number was not provided by the supplier, where that supplier, acting in good faith and having taken all the measures which can reasonably be required of him, is unable to provide that number but provides other information which is such as to demonstrate sufficiently that the person acquiring the goods is a taxable person acting as such..."

**What it holds:** the supplier must act in good faith and take every reasonable measure; the exemption cannot be refused **solely** for a missing VAT number if the supplier has other sufficient information. It is a goods/intra-Community-supply case, but the good-faith/reasonable-measures test is general.

**C-324/11 Tóth, judgment of 6 September 2012.** Operative part (points 1–3):

> "1. Council Directive 2006/112/EC ... and the principle of tax neutrality must be interpreted as meaning that they preclude the tax authority from refusing a taxable person the right to deduct value added tax due or paid for services provided to him solely on the ground that the business operator's licence of the issuer of the invoice had been withdrawn before he provided the services in question or issued the invoice for them, where that invoice contains all the information required by Article 226 of that directive...
> 2. Directive 2006/112 must be interpreted as meaning that it precludes the tax authority from refusing a taxable person the right to deduct value added tax due or paid for services provided to him on the ground that the issuer of the invoice relating to those services did not declare the workers he employed, without that authority establishing, on the basis of objective evidence, that the taxable person concerned knew, or ought to have known, that the transaction relied on as a basis for the right to deduct was connected with fraud committed by the issuer of the invoice or by another trader acting earlier in the chain of supply.
> 3. ... the fact that a taxable person did not verify either whether a legal relationship existed between the workers employed on a work site and the issuer of the invoice or whether the latter had declared those workers does not constitute an objective factor which demonstrates that the addressee of the invoice knew or ought to have known that he was participating in a transaction involving fraudulent evasion of VAT, where the addressee was not in possession of any material justifying the suspicion that irregularities or fraud had been committed within that invoice issuer's sphere of activity."

**What it holds:** no automatic loss of deduction because the issuer's business licence had been withdrawn or its workers were undeclared; the authority must prove knowledge or constructive knowledge on objective evidence. It concerns the **recipient's** deduction, not the supplier's zero-rating.

**C-285/11 Bonik, judgment of 6 December 2012.** Operative part:

> "Articles 2, 9, 14, 62, 63, 167, 168 and 178 of Directive 2006/112/EC ... must be interpreted as meaning that, in circumstances such as those of the case before the referring court, a taxable person may not be refused the right to deduct VAT in relation to a supply of goods on the ground that, in view of fraud or irregularities committed upstream or downstream of that supply, the supply is considered not to have actually taken place, where it has not been established on the basis of objective evidence that the taxable person knew, or should have known, that the transaction relied on as a basis for the right of deduction was connected with VAT fraud committed upstream or downstream in the chain of supply — a matter which it is for the referring court to determine."

**What it holds:** the same objective-evidence/knowledge test for deduction; no strict liability for upstream fraud.

**C-21/16 Euro Tyre, judgment of 9 February 2017.** Operative part:

> "Article 131 and Article 138(1) of Directive 2006/112/EC ... must be interpreted as precluding the tax authority of a Member State from refusing to exempt an intra-Community supply from value added tax on the sole ground that, at the time of that supply, the purchaser domiciled in the territory of the Member State of destination and who was in possession of a valid identification number for the purposes of value added tax in that Member State is neither registered in the Value Added Tax Information Exchange System nor comes under a system of taxation on intra-Community acquisitions of goods, where there is no sound evidence pointing to the existence of fraud and it is established that the basic conditions of the exemption are fulfilled. In that case, Article 138(1) of that directive, interpreted in the light of the principle of proportionality, also precludes such refusal where the vendor was aware of the circumstances of the situation of the purchaser with regard to the application of value added tax and was convinced that subsequently the purchaser would be registered as an intra-Community operator with retroactive effect."

At paragraph 40 the Court restates the general principle:

> "it is not contrary to EU law to require an operator to act in good faith and to take every step which could reasonably be asked of it to satisfy itself that the transaction which it is carrying out does not result in its participation in tax evasion ... If the taxable person concerned knew or should have known that the transaction which it had carried out was part of a fraud committed by the purchaser and that the taxable person had not taken every step which could reasonably be asked of it to prevent that fraud from being committed, that person would have to be refused a VAT exemption..."

**What it holds:** a valid VAT number plus fulfilled substantive conditions cannot be defeated solely by a VIES-registration defect, absent sound evidence of fraud. It is a goods/intra-Community-supply case.

**C-273/11 Mecsek-Gabona, judgment of 6 September 2012** (cited by Euro Tyre). Operative part:

> "1. Article 138(1) ... is to be interpreted as not precluding ... refusal to grant a vendor the right to the VAT exemption for an intra-Community supply, provided that it has been established, on the basis of objective evidence, that the vendor has failed to fulfil its obligations as regards evidence, or that it knew or should have known that the transaction which it carried out was part of a tax fraud committed by the purchaser, and that it had not taken every reasonable step within its power to prevent its own participation in that fraud.
> 2. A vendor may not be refused the VAT exemption ... solely on the ground that the tax authority of another Member State has removed the purchaser's VAT identification number from the register, with retroactive effect from a date prior to the sale of the goods even though the number was removed after the goods had been supplied."

**What it holds:** the exemption can be refused where the supplier failed its evidence obligations or knew/should have known of fraud and did not take every reasonable step; but not solely because of a later retroactive deregistration.

**Synthesis for ApexMail.** The cases establish a **good-faith/reasonable-measures** standard, not a duty to guarantee the customer's status. For B2B services, the operative safe harbour is Regulation 282/2011 Art 18: a valid VAT number plus VIES confirmation of validity and associated name/address, absent contrary information. A VIES check is evidence, not a guarantee; the supplier must act on red flags. The cases do **not** hold that a VIES check is mandatory for services, and they do **not** convert the Art 18 presumption into a strict-liability rule.

### 3.4 Reverse-charge mechanics and the recapitulative statement

**Invoice content.** Article 226 requires, among other things:

- the supplier's VAT identification number (point (3));
- the customer's VAT identification number, "under which the customer received a supply of goods or services in respect of which he is liable for payment of VAT" (point (4));
- the taxable amount per rate or exemption, the unit price exclusive of VAT and discounts (point (8));
- the VAT rate applied (point (9));
- the VAT amount payable (point (10));
- in the case of an exemption, a reference to the applicable provision (point (11));
- **where the customer is liable for the payment of the VAT, the mention "Reverse charge" (point (11a)).**

The brief's "Art. 226(11)" is wrong: point (11) is the exemption reference; the reverse-charge mention is **point (11a)**.

**Recapitulative statement.** Article 262(1)(c) requires every taxable person identified for VAT purposes to submit a recapitulative statement of:

> "the taxable persons, and the non-taxable legal persons identified for VAT purposes, to whom he has supplied services other than services that are exempted from VAT in the Member State where the transaction is taxable and for which the recipient is liable to pay the tax pursuant to Article 196."

Article 263(1): the statement is drawn up for each calendar month within a period not exceeding one month. Article 263(1c) allows Member States to permit quarterly statements for services, but Estonia requires monthly (KMS § 28(2)). Article 264(1)(a), (b) and (d) require the supplier's VAT number, the customer's VAT number, and the total value of the services supplied.

**Estonia.** KMS § 28(1)(2) requires a report on intra-Community supply where a taxable person has provided to a taxable person of another Member State a service specified in § 10(4)(9) "which is subject to taxation except the taxation with 0 per cent taxation rate, in the Member State of the recipient of the service." KMS § 28(2): the report is submitted by the 20th day of the month following each calendar month. EMTA's VD form page confirms the report and its electronic filing.

**Answer:** an Estonian seller **must** file the VD report (the Estonian ESL) for cross-border B2B e-services that are taxable in the customer's Member State and are not exempt there — which is the normal case for a reverse-charged SaaS supply. The supplier's Estonian 0% under § 15(4)(1) is not an exemption, so it does not remove the reporting duty; the statutory exception is for supplies that are 0%-taxed **in the recipient's** Member State, not for the supplier's 0%.

**Invoice timing.** Article 222 (current text) requires an invoice for Article 196 services "no later than on the fifteenth day of the month following that in which the chargeable event occurs." KMS § 37(2¹) reflects this for § 10(4)(9) services. ViDA Art 5(6) replaces Art 222 from 1 July 2030 with a 10-day deadline for the new e-invoicing/DRR regime (Article 222, first paragraph, as replaced: "no later than 10 days following the chargeable event" for Article 138 supplies and Article 194–197 reverse-charge supplies). This is a 2030 change, not a current one.

### 3.5 The threshold interaction with B2B

The textual answer is short: **Article 59c applies only to "Point (a) of Article 33 and Article 58"**. B2B supplies are governed by Article 44. Article 59c does not mention Article 44 and cannot disapply it. Therefore:

- A B2B supply of TBE services to an EU business is **always** destination-taxed (customer's establishment) and reverse-charged under Article 196, regardless of the EUR 10,000 threshold.
- The threshold is relevant only to B2C TBE supplies (and intra-EU distance goods).
- The code's B2B branch ignores the threshold, which is correct. The risk is the reverse: the code's B2C branch also ignores the threshold, which is correct only if the seller is above it or has opted in.

### 3.6 Estonia's implementation — KMS section mapping

The Estonian *Käibemaksuseadus* (KMS; RT I 2003, 82, 554) implements the Directive. The official English translation (redaction `511072022006`, in force 1 July 2022) and EMTA's current guidance give the following mapping. The section numbers are the point; the quoted text is from the official translation, with the caveat that its rate section (20%) is stale and the current standard rate is 24% from 1 July 2025 (EMTA; PwC).

| Directive provision | KMS section | What it says (translation/EMTA) |
|---|---|---|
| Art 9 (taxable person), Art 43 | § 2(2), § 3(1)–(2) | § 2(2) defines "business" as independent economic activity; § 3(1) defines a taxable person as a person engaged in business and registered/required to register; § 3(2) defines a taxable person with limited liability. |
| Art 44 (B2B default) — inbound | § 10(1) | "The place of supply of services is Estonia if the services are provided to a taxable person or taxable person with limited liability registered in Estonia or if the services are provided through a seat or permanent business establishment located in Estonia to a person who is not registered ... in any of the Member States or who is not a third country person engaged in business..." |
| Art 44 (B2B default) — outbound | § 10(4)(9) | "services are provided in the cases not specified in clauses 1–8 of this subsection and subsection 2 of this section through a seat or permanent business establishment in Estonia to a taxable person or taxable person with limited liability registered in another Member State or to a third country person engaged in business." The place is **not** Estonia. |
| Art 45 (B2C default) | § 10(1), § 10(2) | The general B2C rule is the supplier's establishment (Estonia); the specific B2C rules in § 10(2) cover immovables, cultural/sporting/educational events, passenger transport, restaurant/catering, short-term vehicle hire, work on movables, goods transport, ancillary transport, and intermediation. |
| Art 58 (B2C TBE destination) | § 10¹(2), (6) | § 10¹(2): "The place of supply of services is Estonia if the electronic communications service or the electronically provided service is provided to a person, established or residing in Estonia, who is not registered as a taxable person or a taxable person with limited liability in any of the Member States." § 10¹(6): the place is **not** Estonia if the service is provided to a person residing in another Member State who is not registered. |
| Art 59c (EUR 10,000 threshold) | § 10¹(6)–(9) | § 10¹(6) places the TBE supply outside Estonia for a customer in another Member State; § 10¹(7) applies the origin rule only if the supplier has no seat/permanent establishment outside Estonia, the customer is in another Member State, and the total supply did not exceed EUR 10,000 in the previous year and does not exceed it in the current year; § 10¹(8) allows the supplier to opt for destination for at least two calendar years; § 10¹(9) applies destination as of the date the threshold is exceeded. EMTA's current table cites "subsections 6 and 7 of § 10¹" for the B2C EU rule. |
| Art 196 (reverse charge) / Art 226(11a) | § 37(8)(2) | "where the acquirer of goods or the recipient of services is liable to pay the tax, the reference 'reverse charge' if the place of supply of goods is not Estonia and in the cases specified in § 41¹ of this Act." (§ 41¹ is Estonia's **domestic** reverse charge for immovables, scrap metal and precious metals; it is not the cross-border services rule. The translation's first limb says "goods"; for a cross-border B2B **service**, the Art 226(11a) "Reverse charge" mention applies and EMTA's invoice guidance requires the reference where the customer is liable. The Estonian original should be checked for the precise scope of § 37(8)(2), because the English translation may have dropped "or services" in that limb.) |
| Art 262–264 (recapitulative statement) | § 28 | § 28(1)(2) requires the report on intra-Community supply for § 10(4)(9) services taxable in the recipient Member State (other than at a 0% rate there); § 28(2) monthly by the 20th. |
| Arts 369a–369k (Union scheme) | § 43 | § 43(1) lists the persons who may use the special arrangements (including an Estonian-seated taxable person supplying services with a place of supply in another Member State to a non-taxable person); § 43(10) quarterly return by the end of the first month of the next quarter; § 43(13) corrections within three years; § 43(15) 10-year records; § 43(20) two-year exclusion for repeated failure. |
| Art 45/58 zero rate (services outside Estonia) | § 15(4)(1) | "services where the place of supply is not Estonia, excluding cases where the supply of such services is exempt from tax pursuant to § 16 of this Act" are taxed at **0%**. § 15(5) requires documentary proof (contract, written order, invoice or other document). |
| Art 196 inbound reverse charge (Estonian recipient) | § 3(4)(2), § 21(1) | § 3(4)(2) makes an Estonian taxable person liable for VAT on services received from a foreign person not registered in Estonia; § 21(1) requires registration as a taxable person with limited liability. This is the mirror of the outbound rule and is not ApexMail's sale. |
| Art 226 / national invoicing | § 37 | § 37(1) invoice within seven calendar days; § 37(2¹) cross-border B2B invoice by the 15th of the following month; § 37(7) mandatory content; § 37(8)(2) "reverse charge" reference. |
| Art 369k / national records | § 36(1)(1), § 43(15) | § 36(1)(1) seven-year retention of invoices; § 43(15) 10-year OSS records. |
| Art 250 / national return | § 27(1) | Taxable period is one calendar month; the VAT return is due by the 20th day of the following month. |

**Mapping conclusion.** The Estonian implementation matches the Directive's structure: § 10(1) and § 10(4)(9) are the Art 44 inbound/outbound pair; § 10¹ is the Art 58/59c TBE B2C rule; § 28 is the Art 262–264 recapitulative statement; § 37(8)(2) is the Art 226(11a) notation; § 43 is the Art 369a–369k Union scheme; § 15(4)(1) is the 0% mechanism for out-of-scope services. The English translation's § 10¹ paragraph numbering is garbled (it repeats "(3)"), so cite the Estonian section and the EMTA table, not the translation's sub-paragraph numbers.

---

## 4. Three-times confirmation matrix

Each row records the primary text, the official guidance, and the independent practitioner confirmation. "Indirect" means the practitioner source supports the proposition by stating the surrounding rule rather than the exact sentence; "UNVERIFIED" means no independent confirmation was obtained and the proposition rests on the primary text alone.

| # | Proposition | (1) Primary text | (2) Official guidance | (3) Independent practitioner | Verdict |
|---|---|---|---|---|---|
| P1 | B2B services: place = customer's business establishment (or fixed establishment receiving the service) | Art 44, quoted above | EMTA "Taxation of services" table: B2B to a taxable person of another MS → "Country of the location of the recipient of the service (clause 9 of subsection 4 of § 10)", 0% (clause 1 of subsection 4 of § 15), KMD fields 3, 3.1, VD "+" | PwC Estonia: "Taxable supplies of goods and services (the place of supply of which is Estonia)"; domestic reverse charge applies only to specified goods — i.e. cross-border services are not charged Estonian VAT (indirect) | **CONFIRMED** |
| P2 | The customer is liable under Art 196; the supplier does not charge VAT; the invoice says "Reverse charge" | Art 196; Art 226(11a); Art 262(1)(c); Art 264(1)(a),(b),(d) | EMTA table: 0%, KMD 3/3.1, VD "+"; EMTA VD form page | PwC: domestic reverse charge limited to real estate, scrap, precious metals; cross-border services outside the Estonian charge (indirect) | **CONFIRMED** (subject to fixed-establishment caveat) |
| P3 | B2C TBE services: place = customer's establishment/permanent address/usual residence | Art 58(1), quoted above | EC OSS page: TBE services are taxed where the customer is established; the Union scheme covers cross-border B2C services; EMTA digital-services table: EU non-taxable person → Estonia until EUR 10,000, then the customer's MS, 24% or destination rate + OSS | Avalara Estonia: "Cross-border business-to-consumer (B2C) sellers based in the EU are subject to the €10,000 EU-wide threshold and can use the One-Stop Shop (OSS)" | **CONFIRMED** |
| P4 | Hosted email/API is an electronically supplied service (or, alternatively, a telecommunications service); either way Art 58 applies | Art 58(1)(a),(c); Art 24(2); Annex II(1)–(3); Reg 282/2011 Art 7(1), (2)(a)–(f), (3)(b),(i); Annex I(1)(a),(c),(d), (2)(a) | EMTA "Digitally provided services" table: "Digital services, and cultural, artistic, sports, scientific or entertainment services provided virtually..." → § 10¹ applies; EC OSS page: OSS covers TBE services | Avalara treats "digital services" as within the €10,000/OSS rule; no direct practitioner statement on the email-API classification (indirect) | **CONFIRMED** as TBE or telecom; both Art 58. The classification of a separate human-delivered onboarding/consulting component is **UNVERIFIED** and must be per supply |
| P5 | EUR 10,000 threshold: EU-wide, current + preceding year, VAT-exclusive, TBE services + distance goods; above → destination; below → origin possible; opt-in for two years | Art 59c(1)–(3), quoted above | EC OSS page: "The threshold of EUR 10 000 only applies to TBE services and intra-Community distance sales of goods. It does not apply to other services than TBE services..."; EMTA OSS page: "The all-in threshold 10 000 euros is introduced..." | Avalara Estonia: "subject to the €10,000 EU-wide threshold" | **CONFIRMED** |
| P6 | Union OSS: Estonian MSI, existing VAT ID, quarterly return, 10-year records, three-year corrections, all eligible supplies | Arts 369a(1),(2), 369b, 369d, 369f, 369g(4), 369k, quoted above | EC OSS page: Union scheme for EU-established businesses; quarterly; MSI; EMTA OSS page: Union scheme for an Estonian-established person, VAT ID (KMKR), quarterly deadlines 30 Apr/31 Jul/31 Oct/31 Jan | Avalara Estonia: OSS for EU B2C sellers (indirect) | **CONFIRMED** |
| P7 | Cross-border B2B e-services **to another Member State** require the recapitulative statement (Estonian VD), monthly by the 20th | Art 262(1)(c); Art 263(1); Art 264(1); KMS § 28(1)(2), (2) | EMTA VD form page: "report on intra-Community supply (forms VD and VDP)"; EMTA table: VD "+" for B2B to another MS | PwC Estonia: VAT return monthly by the 20th (indirect on the VD cadence) | **CONFIRMED** |
| P8 | The EUR 10,000 threshold does not apply to B2B; B2B TBE is always destination/reverse charge | Art 59c(1) applies only to "Point (a) of Article 33 and Article 58"; Art 44 is untouched | EMTA table: B2B to another MS → recipient country, 0%, VD "+", with no EUR 10,000 condition | PwC/Avalara: the €10,000/OSS rule is described as a B2C rule (indirect) | **CONFIRMED** |
| P9 | Direct sales are not a deemed-supply chain; Art 14a (goods), Art 28 (commissionnaire), Art 28a (ViDA 2028) do not apply to ApexMail's own service | Art 14a; Art 28; Art 28a (ViDA 2025/516 Art 3(1)); no Art 9a | EC ViDA page: the platform deemed-supplier rules concern short-term accommodation and passenger transport by road; EC OSS page: Union-scheme deemed supplier is for goods | Deloitte ViDA: the platform-economy pillar concerns specific sectors (indirect) | **CONFIRMED** for the current direct-sale model; **WATCH** if ApexMail becomes a merchant of record/reseller |
| P10 | ViDA dates: entry into force 14 Apr 2025; Art 2 from 1 Jan 2027; Art 3 from 1 Jul 2028 (Art 3(1) to 1 Jan 2030); Art 4 from 1 Jul 2029; Art 5 from 1 Jul 2030; 1 Jan 2035 for MS with domestic real-time reporting | Directive 2025/516 Arts 6(1)–(5), 7; Art 2 heading; Art 3 heading; Art 4 heading; Art 5 heading; Art 59c(3) as amended; Art 28a as inserted | EC ViDA page: "Upon entry into force (14 April 2025)... Effective by 1 January 2027... From July 1, 2028... Digital Reporting Requirements ... from 1 July 2030. By 1 January 2035..." | Deloitte: ViDA phased to 2030, with fragmentation until at least 2035 (indirect on the exact 2027/2028 dates) | **CONFIRMED** |
| P11 | Estonia's KMS maps as: § 10(1)/(4)(9) = Art 44; § 10¹ = Art 58/59c; § 28 = Art 262–264; § 37(8)(2) = Art 226(11a); § 43 = Art 369a–369k; § 15(4)(1) = 0% for out-of-scope services | KMS § 10, § 10¹, § 15(4)(1), § 28, § 37(8)(2), § 43 (official English translation) | EMTA services table cites the same sections; EMTA OSS page; EMTA VAT rates page (24%) | PwC Estonia: 24% standard rate, EUR 40,000 registration, monthly return by the 20th | **CONFIRMED** (translation is the 2022 redaction; section numbers cross-checked against current EMTA guidance) |
| P12 | Non-EU B2B/B2C: place outside the EU; no EU VAT; no export/customs formality; Estonian 0% under § 15(4)(1) with documentary proof | Art 44; Art 58; KMS § 15(4)(1), (5) | EMTA table: third-country business → recipient country, 0%, no VD; third-country non-business → recipient country, 0% | Avalara: non-EU sales outside the EU VAT/OSS rules (indirect) | **CONFIRMED** (no customs formality; § 15(5) proof required) |

---

## 5. Conflict list

Where sources disagree, the primary text controls. "CORRECTED" means a secondary source's claim is wrong or imprecise and the memo adopts the primary text.

| # | Claim | Source 1 says | Source 2 says | Primary text says | Verdict |
|---|---|---|---|---|---|
| C1 | The OSS Union scheme is "Arts 358a–369x" | Brief: "OSS Union scheme: Arts. 358a–369x" | Existing repo memo: "Articles 369a–369k" | Chapter 6 runs 358a–369x, but the **Union** scheme is Section 3, **Arts 369a–369k**; Section 2 (358a–369) is the **non-Union** scheme for non-EU-established suppliers; Section 4 (369l–369x) is IOSS | **CORRECTED**: for an Estonian seller, cite 369a–369k |
| C2 | "359 registration, 361 identification Member State, 363a? returns, 365 quarterly filing, 369 records 10 years" | Brief | Existing memo cites 369b/369a(2)/369f/369k | Art 359 = non-Union permission; Art 361 = non-Union registration information; **no Art 363a**; Art 364 = non-Union quarterly return; Art 365 = non-Union return content; Art 369 = non-Union records. Union equivalents: 369b, 369a(2)/369d, 369f, 369g, 369k | **CORRECTED**: the brief's numbers are the non-Union scheme; the Union scheme uses 369-series articles |
| C3 | Reverse-charge invoice notation is "Art 226(11)" | Brief: "invoice notation (Art 196 + Art 226(11))" | Existing memo: "Article 226(11a)" | Art 226(11) is the **exemption** reference; Art 226(11a) is "where the customer is liable for the payment of the VAT, the mention 'Reverse charge'" | **CORRECTED**: cite Art 226(11a) |
| C4 | "Art 59b/59c scope" | Brief: "Art. 59b/59c scope" | Existing memo does not mention 59b | The current consolidated text has **no Article 59b**. Chapter 3a contains Article 59c alone; the preceding provisions are Art 59 (services to non-taxable persons outside the EU) and Art 59a (effective use and enjoyment) | **CORRECTED**: no Art 59b in the current consolidation; cite 59, 59a, 59c |
| C5 | Deemed-supplier rules are "Arts 9a, 28a" | Brief: "Arts. 9a, 28a where relevant" | — | **No Article 9a exists.** Article 28a is inserted by ViDA 2025/516 Art 3(1) with effect from 1 July 2028 (may be delayed to 1 January 2030) and covers short-term accommodation/passenger transport. The pre-existing deemed receipt-and-supply rules are Art 14a (goods) and Art 28 (services) | **CORRECTED**: 9a does not exist; 28a is a future platform rule, not the current direct-sale rule |
| C6 | "0% reverse charge" is a single rate/mechanism | Existing memo: "VAT charged: 0%. This is not an exemption; it is a reverse-charge supply." | EMTA table: 0% under § 15(4)(1), VD "+" | The supply is zero-rated in Estonia under KMS § 15(4)(1) because the place of supply is not Estonia; the customer's liability is Art 196. "0%" and "reverse charge" are two separate features, not one rate | **CLARIFIED**: 0% is the Estonian zero rate; reverse charge is the Art 196 liability; the invoice must state "Reverse charge" (Art 226(11a)) |
| C7 | A VIES confirmation of validity and name/address is "required" for B2B | Existing memo: "the supplier has the evidence required by Article 18 ... in practice, a VIES confirmation..." | EC OSS/VIES guidance and Art 18 | Art 18(1) is a **presumption**: "Unless he has information to the contrary, the supplier may regard..." Art 18(1)(b) allows other proof + reasonable verification. VIES is the safe route, not the only lawful route | **CORRECTED**: "required" is too strong; the regulation creates a rebuttable presumption |
| C8 | The Union scheme lets an Estonian seller report "all cross-border B2C VAT" through Estonia | Existing memo: "lets an Estonian seller report and pay all cross-border B2C VAT through Estonia" | EC OSS page: supplies in a Member State where the supplier is established cannot be declared in OSS | Art 369b(c) requires the supplier to be **not established in the Member State of consumption**; Estonian consumers are declared in the KMD. OSS covers only cross-border supplies to MS where ApexMail is not established | **CORRECTED**: "all cross-border B2C VAT" is too broad; Estonian domestic B2C is KMD, not OSS |
| C9 | The 2035 ViDA date is a second EU-wide e-invoicing phase | Brief: "e-invoicing 2030/2035 phases" | EC ViDA page: "By 1 January 2035, Member States with a domestic digital real-time transaction reporting obligation must align their systems..." | Art 5 applies from 1 July 2030; the 2035 date is a **derogation/alignment deadline** for Member States with domestic real-time reporting, for domestic e-invoicing/reporting. It is not a second EU-wide cross-border phase | **CLARIFIED**: cross-border B2B DRR = 1 July 2030; 1 January 2035 = alignment for certain Member States' domestic systems |
| C10 | ViDA's "Single VAT Registration" extends OSS to B2B services | Brief: "single VAT registration/OSS extension" | EC ViDA page: SVR "will allow more businesses selling to consumers in another EU country to fulfil their VAT obligations via an online portal"; the reforms include a transfer-of-own-goods module | Art 3 (from 1 July 2028) amends Art 369b to add certain **B2B goods** supplies and own-goods transfers, and adds Section 5. It does **not** add B2B services; those remain Art 44/196 | **CORRECTED**: SVR is about goods/own-goods and consumer supplies, not B2B services |
| C11 | "EUR 10,000" is the only threshold relevant to evidence | Brief/angle 1 asks about the EUR 10,000 threshold | Existing memo mentions Art 24b(d) but not the EUR 100,000 evidence threshold | Art 24b, second paragraph, has a **EUR 100,000** evidence threshold (one third-party item instead of two items). It is separate from Art 59c's EUR 10,000 place-of-supply threshold | **CLARIFIED**: two different thresholds; do not conflate |
| C12 | The Estonian KMS English translation is current | Some secondary citations use the translation without a date | EMTA current pages cite § 10/§ 10¹/§ 15/§ 28/§ 37/§ 43 | The translation is the **1 July 2022** redaction and still shows 20%; the current standard rate is 24% from 1 July 2025. Section numbers remain the same against EMTA's current guidance | **CORRECTED**: cite the translation for section text, EMTA for the current rate; do not quote its 20% as current |
| C13 | "Art 45/58" is a single B2C rule | Brief: "Art. 45/58 — B2C place of supply for electronically supplied services (customer's location)" | Existing memo distinguishes Art 45 (supplier) and Art 58 (customer) | Art 45 is the **general** B2C rule (supplier's establishment); Art 58 is the **specific** TBE rule (customer's location). They are not interchangeable; non-TBE B2C services stay in Estonia under Art 45 | **CORRECTED**: distinguish the two; the destination result depends on Art 58 |
| C14 | The CJEU cases are B2B-services place-of-supply authority | Brief lists VSTR/Tóth/Bonik/Euro Tyre as "the CJEU doctrine that the supplier must act with due diligence" | The judgments themselves | VSTR and Euro Tyre are **intra-Community supply of goods** exemption cases; Tóth and Bonik are **deduction** cases. Their good-faith/reasonable-measures principle is general, but the operative services rule is Reg 282/2011 Art 18 | **CLARIFIED**: use the cases for the principle, not as direct services authority |
| C15 | The code's 90-day VIES freshness bound is a legal rule | Code comment: "the documented grace bound (VAT_EVIDENCE_MAX_AGE_DAYS — 90 days)" | Existing memo: "no fixed EU statutory period; the horizon is a control, not a law" | Art 18 requires confirmation at the time of supply; there is no statutory 90-day validity period. The 90-day bound is a **policy** choice, not a legal rule | **CLARIFIED**: the policy is lawful as a conservative control, but it is not required by the Directive; it can over-collect VAT on verified B2B usage invoices |

---

## 6. Code-facing findings

The following table maps the place-of-supply conclusions to the repository. All paths are absolute. The "Action" column is a recommendation for the owner/engineer, not a legal instruction.

| # | Repo assumption / implementation | Verdict | Legal basis | Code evidence | Action |
|---|---|---|---|---|---|
| F1 | A verified EU business outside Estonia is reverse-charged at 0%, regardless of OSS status | **CORRECT** | Art 44; Art 196; Art 369b(c); Art 226(11a); Art 262(1)(c); KMS § 10(4)(9), § 15(4)(1), § 28(1)(2), § 37(8)(2) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` (`reverse_charge_authorised`, `quote_list_price`); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` (`requires_vies_consultation`, `resolve_checkout_quote`) | Keep. Add a fixed-establishment review (F7). Ensure the invoice also carries the KMS § 15(4)(1) 0% reference, not only the Art 196 note (angle 2). |
| F2 | B2C total = net + destination rate; destination = the customer's declared country | **PARTLY CORRECT** — arithmetic correct; place-of-supply evidence insufficient | Art 58; Art 23(2); Art 24b(d); Art 24f; Art 24d(1) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` (`CheckoutTaxDeclaration`, `persist_declaration`); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` (`quote_consumer_gross`, `quote_list_price`); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/compliance/src/vat_oss.rs` (consumption country = `billing_country`) | Keep the destination arithmetic. Add a second, non-contradictory location item (IP/geolocation, bank country, MCC, landline, or other commercial information) and record it per invoice/OSS entry. Until then, the Art 24b(d) presumption is not met. Angle 2 owns the evidence design; this memo states the rule. |
| F3 | EUR 10,000 threshold is relevant at ApexMail's scale; destination rates are always used | **NOT MODELLED** | Art 59c(1)–(3); ViDA 2025/516 Art 2(4)(b) (from 1 Jan 2027) | No threshold logic in `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` or `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/compliance/src/vat_oss.rs`; the code always applies destination for EU B2C | Measure the cross-border B2C TBE turnover (current + preceding year, EU-wide, VAT-exclusive). If above EUR 10,000, document that fact and keep OSS. If below, do not charge destination VAT unless the Art 59c(3) opt-in is made (and from 1 Jan 2027, OSS registration deems it). Add an annual threshold monitor. |
| F4 | Non-EU customers: 0%, no EU VAT, no formalities | **CORRECT in substance**; the invoice-note defect present at the start of the session appears addressed by the concurrent angle-2 edit (verify the commit) | Art 44; Art 58; KMS § 15(4)(1), (5) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` (`calculate_vat_with_evidence`: non-EU → (0,0); `quote_list_price`: `reverse_charge` false for non-EU); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/api-server/src/routes/billing.rs` lines 2446–2456: the working tree now gates `reverse_charge_applied` on `vat_total == 0 && vat_evidence_id.is_some() && is_eu_country(country) && country != "EE"` (the earlier code checked a structural VAT number and did not check `is_eu_country`) | Keep the evidence-backed gate. If the concurrent edit is not in the commit under review, apply it; add a non-EU regression test. Retain KMS § 15(5) documentary proof (contract/order/invoice) and Art 18(3) business evidence. |
| F5 | OSS Union scheme: Estonia MSI, quarterly, 10-year records | **CORRECT in structure**; the code's consumption country is the billing country, with no evidence adjudication | Arts 369a–369k; KMS § 43 | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/compliance/src/vat_oss.rs` (docstring lines 39–43 says place-of-supply adjudication is not implemented; SQL lines 170–185 uses `billing_country` as `consumption_country`); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/migrations/219_oss_vd_filing_scaffold.sql` (`customer_location_evidence` table exists but is unused by the derivation) | Keep the Union scheme and quarterly/10-year controls. Populate and use `customer_location_evidence` for the OSS consumption country; do not default to `'EE'` for a missing country in a way that hides an evidence gap. Confirm the OSS registration is active before filing. |
| F6 | Direct sales are not a deemed-supply chain; the PSP is a processor, not a merchant of record | **CORRECT for the current model** | Art 14a (goods); Art 28 (services); Art 28a (ViDA 2028); Art 369b(c) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/payments/mod.rs` lines 1–30 (Stripe is payments-only; ApexMail owns scheduling); `templates/legal/dpa.md` line 8 (Bel Consulting OÜ, VAT EE102951727) | Keep the processor model. If ApexMail adopts a merchant-of-record/reseller, re-run the analysis: the MoR becomes the supplier to consumers; ApexMail's sale is B2B. Document this as a business-model invariant. |
| F7 | ApexMail is established only in Estonia; no fixed establishment outside Estonia | **UNVERIFIED fact** | Art 44; Art 192a; Art 196; Reg 282/2011 Art 11; C-605/12 Welmory | `/Users/sabelakhoua/IdeaProjects/ApexMail/ARCHITECTURE.md` line 12 (production host in Finland); the code has no fixed-establishment model and treats every EU country other than EE as a reverse-charge destination | Confirm with the accountant whether the Finnish host (or any other infrastructure/people) is a fixed establishment. If yes: Finnish B2B supplies may require Finnish VAT registration and cannot be reverse-charged; B2C services supplied from that establishment are outside the Union scheme and must be declared in Finland (Reg 282/2011 Art 57c, not Art 369g(3), because Art 57c excludes services supplied in a Member State where the supplier has a fixed establishment); the EUR 10,000 threshold is unavailable (Art 59c(1)(a)). |
| F8 | VIES evidence is valid for 90 days; renewals revalidate; usage invoices use the persisted evidence without a live revalidation | **POLICY, not law**; over-collection risk | Reg 282/2011 Art 18; Art 25 (time of chargeable event) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` `VAT_EVIDENCE_MAX_AGE_DAYS = 90`; `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` `revalidate_for_tenant`; `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/plan_billing.rs` lines ~1330–1345 (revalidation at renewal); `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/invoices.rs` line ~207 (`calculate_vat_with_evidence` for the invoice writer/usage path, no live revalidation) | Keep the fail-closed policy if the owner accepts the over-collection risk, but align the revalidation cadence for usage invoices with the 90-day bound, or document why the bound is 90 days. Do not describe the 90 days as a statutory rule. Also compare the VIES `returned_name`/`returned_address` with the customer's declared name/address. The concurrent angle-2 edit now carries `requested_at`, `returned_name`, `returned_address`, `authority_request_id` and `response_hash` in `VatValidationEvidence` and loads them from the row, but `authorises_reverse_charge` still decides on source/outcome/number/country/freshness only; the name/address comparison is not yet in the rule. |
| F9 | The invoice's "Reverse charge" note is printed when VAT is zero, the country is not EE, and the VAT number looks structurally valid | **DEFECT at the start of the session; appears FIXED in the working tree** by the concurrent angle-2 edit (uncommitted at 30 Oct 22:02; verify the commit) | Art 196; Art 226(11a); KMS § 37(8)(2) | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/api-server/src/routes/billing.rs` lines 2446–2456 now requires `vat_evidence_id.is_some()` and `is_eu_country(...)` in addition to `vat_total == 0` and `country != "EE"`; the earlier code did not | Keep the evidence-backed gate. Add a non-EU and a non-reverse-charge zero-VAT regression test (the existing test at line ~6519 covers FI and EE only). Angle 2 owns the invoice text; this is the place-of-supply consequence. |
| F10 | Every B2C sale is a TBE service taxed at the destination rate | **OVERBROAD** if the catalog contains non-TBE services | Art 45 (non-TBE B2C = Estonia); Art 58 (TBE B2C = destination); Art 44 (B2B) | No tax-classification field in `vat_rates.rs`, `tax.rs` or the billing schema; `quote_list_price`/`quote_consumer_gross` apply the same rule to all line items; `docs/marketing/billing-definitions.md` lists setup/onboarding fees (EUR 10,000–60,000) and add-ons | Add a per-product/per-line tax classification (TBE vs non-TBE vs mixed). A human-delivered onboarding/migration/consulting service is not automatically TBE; if it is a separate supply, B2C is Estonian 24% under Art 45. Confirm the classification of the Private Cloud setup fees with the accountant. |
| F11 | Cross-border B2B e-services **to another Member State** are reported in the VD/ESL | **CORRECT**; ensure the code's OSS/VD derivation sets the recognition reason from the buyer's status, not from the country | Art 262(1)(c); Art 263(1); Art 264(1); KMS § 28 | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/compliance/src/vat_oss.rs` derives `oss_supply_entries` from `vat_recognition_entries` with `reason = 'eu_b2c'` and `vd_entries` from zero-rated invoices with VIES evidence | Keep the B2B/B2C split. Verify that the recognition `reason` (`eu_b2c` vs the B2B reason) is set from the buyer's taxable status, not inferred from the billing country; the OSS SQL filters on `reason = 'eu_b2c'` and `billing_country <> 'EE'`, so a mis-set reason would put a B2B invoice in OSS or omit a B2C one. |
| F12 | The customer is located in the single billing country entered at checkout | **SIMPLIFICATION**; Art 44 has a second limb for a customer fixed establishment receiving the service | Art 44, second sentence; Reg 282/2011 Arts 21–22 | `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` (`CheckoutTaxDeclaration.country` is one ISO code); no customer fixed-establishment field | For a business customer with establishments in more than one country, Art 44 places the supply where the customer has established its business, unless the service is provided to a fixed establishment and used for its own needs (Art 21; Art 22). A US business with a German fixed establishment receiving the service is a German supply, not a non-EU 0% supply. Capture the customer's fixed establishment where the contract/order/VAT number identifies it, or document that ApexMail's self-serve flow only accepts single-establishment customers. |


---

## 7. Sources

All URLs retrieved on **30 October 2026** unless otherwise stated. EUR-Lex direct access was blocked by an AWS WAF challenge; the EUR-Lex texts were retrieved through `https://r.jina.ai/` of the same EUR-Lex URLs. The article text is the official consolidated text as rendered by that proxy.

### 7.1 Primary law — EU

| ID | Source | URL | What was verified |
|---|---|---|---|
| S1 | Directive 2006/112/EC, consolidated text, CELEX **02006L0112-20250414** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02006L0112-20250414` (via Jina) | Arts 9, 24(2), 43, 44, 45, 58, 59, 59a, 59c, 196, 218, 222, 226(3),(4),(8)–(11a), 262, 263, 264, 358a–369k, Annex II |
| S2 | Directive 2006/112/EC, consolidated text, CELEX **02006L0112-20240101** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02006L0112-20240101` (via Jina) | Clean article text used for the verbatim quotes; cross-checked against S1 |
| S3 | Council Directive (EU) 2025/516 of 11 March 2025 (ViDA), CELEX **32025L0516** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025L0516` (via Jina) | Arts 1–8; Art 2 (1 Jan 2027), Art 3 (1 Jul 2028; Art 3(1) to 1 Jan 2030), Art 4 (1 Jul 2029), Art 5 (1 Jul 2030; 1 Jan 2035), Art 6, Art 7; new Art 28a; amended Art 59c(3) |
| S4 | Council Implementing Regulation (EU) No 282/2011, consolidated text, CELEX **02011R0282-20250414** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02011R0282-20250414` (via Jina) | Arts 7, 11, 17–20, 22, 23, 24a–24f, 57c, 57d, Annex I |
| S5 | Council Implementing Regulation (EU) 2025/518 of 11 March 2025, CELEX **32025R0518** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025R0518` (via Jina) | Amendments to Arts 18(2), 23(2), 24b, 24d, 24f; new Arts 9b–9g (ViDA platform rules) |
| S6 | Council Regulation (EU) 2025/517 of 11 March 2025, CELEX **32025R0517** | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025R0517` (not separately fetched; cited from the EC ViDA page) | Administrative-cooperation part of the package |

### 7.2 Primary law — Estonia

| ID | Source | URL | What was verified |
|---|---|---|---|
| S7 | *Käibemaksuseadus* (Value Added Tax Act), official English translation, redaction **511072022006** (in force 1 July 2022) | `https://www.riigiteataja.ee/en/eli/ee/511072022006/consolide/current` (via Jina; final URL `https://www.riigiteataja.ee/en/akt/511072022006?leiaKehtiv`) | § 2(2), § 3(1)–(2), § 10(1),(4)(9),(5), § 10¹(1)–(10), § 15(4)(1),(5), § 27(1), § 28(1)(2),(2), § 36(1)(1), § 37(1),(2¹),(7),(8)(2), § 43(1),(10),(13),(15),(20) |

### 7.3 Official administrative guidance

| ID | Source | URL | What was verified |
|---|---|---|---|
| S8 | European Commission, VAT in the Digital Age (ViDA) | `https://taxation-customs.ec.europa.eu/taxation/vat/vat-digital-age-vida_en` | Adoption 11 March 2025; entry into force 14 April 2025; 1 Jan 2027; 1 Jul 2028; 1 Jul 2030; 1 Jan 2035; the three legal acts |
| S9 | European Commission, One Stop Shop | `https://vat-one-stop-shop.ec.europa.eu/one-stop-shop_en` | Union scheme for EU-established businesses; quarterly returns; the EUR 10,000 threshold and its conditions; TBE-only scope; the statement that supplies in an MS where the supplier is established cannot be declared in OSS |
| S10 | European Commission, VAT rates (framework) | `https://taxation-customs.ec.europa.eu/taxation/vat/vat-rates_en` | Standard rate ≥ 15%; reduced rates; Annex III (framework only; the country table is angle 3) |
| S11 | Estonian Tax and Customs Board, Value added tax | `https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax` | Standard rate 24% from 1 July 2025; 22% from 1 Jan 2024; registration threshold EUR 40,000; the 2027 XBRL return change (horizon) |
| S12 | Estonian Tax and Customs Board, Taxation of services | `https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/taxation-services` | The place-of-supply table for B2B/B2C/third-country; digital-services table; 0% under § 15(4)(1); VD "+" for B2B to another MS; § 10¹ EUR 10,000 rule |
| S13 | Estonian Tax and Customs Board, Special schemes of e-commerce and services (OSS) | `https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/special-schemes-e-commerce-and-services` | Union vs non-Union scheme; MSI; quarterly deadlines; EUR 10,000 threshold; registration timing; exclusion/two-year rule |
| S14 | Estonian Tax and Customs Board, VAT rates and supply exempt from tax | `https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax/vat-rates-and-supply-exempt-tax` | 24% standard rate; 13%/9% reduced rates; 0% cases |
| S15 | Estonian Tax and Customs Board, VAT return, forms VD and VDP | `https://www.emta.ee/en/business-client/taxes-and-payment/tax-returns-exchange-information/vat-return-forms-vd-and-vdp` | The VD report exists and is filed electronically; the form instructions |

### 7.4 Independent practitioner

| ID | Source | URL | What was verified |
|---|---|---|---|
| S16 | PwC Worldwide Tax Summaries, Estonia — Other taxes | `https://taxsummaries.pwc.com/estonia/corporate/other-taxes` | 24% standard rate; 13%/9% reduced; EUR 40,000 registration; monthly return by the 20th; domestic reverse charge limited to specified goods; the territorial principle ("taxable supplies ... the place of supply of which is Estonia") |
| S17 | Avalara, Estonia VAT rates / country guide | `https://www.avalara.com/vatlive/en/country-guides/europe/estonia/estonian-vat-rates.html` | 24% standard rate; EUR 10,000 EU-wide threshold and OSS for EU B2C sellers; monthly returns by the 20th; reverse charge on services received by a non-VAT-registered company |
| S18 | Deloitte, "Preparing for ViDA: EU VAT reform" | `https://www.deloitte.com/global/en/services/tax/perspectives/vat-in-the-digital-age.html` | ViDA adopted 11 March 2025; phased to 2030/2035; digital reporting/e-invoicing and single VAT registration pillars (general timeline; not the precise 2027/2028 dates) |

### 7.5 CJEU

| ID | Case | CELEX | URL | What was verified |
|---|---|---|---|---|
| S19 | C-587/10 VSTR, judgment 27 September 2012 | 62010CJ0587 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62010CJ0587` | Operative part; para 52 (good faith; all reasonable measures; other sufficient information) |
| S20 | C-324/11 Tóth, judgment 6 September 2012 | 62011CJ0324 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62011CJ0324` | Operative part points 1–3 (no automatic refusal; objective evidence of knowledge) |
| S21 | C-285/11 Bonik, judgment 6 December 2012 | 62011CJ0285 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62011CJ0285` | Operative part (objective evidence of knowledge; no strict liability) |
| S22 | C-21/16 Euro Tyre, judgment 9 February 2017 | 62016CJ0021 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62016CJ0021` | Operative part; para 40 (good faith; every step; knowledge/constructive knowledge) |
| S23 | C-273/11 Mecsek-Gabona, judgment 6 September 2012 | 62011CJ0273 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62011CJ0273` | Operative part (evidence obligations; every reasonable step; no refusal solely for retroactive deregistration) |
| S24 | C-605/12 Welmory, judgment 16 October 2014 | 62012CJ0605 | `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62012CJ0605` | Operative part (fixed establishment: permanence + suitable human/technical resources) |

### 7.6 Repository files inspected (context only; not sources of law)

| Path | Relevance |
|---|---|
| `/Users/sabelakhoua/IdeaProjects/ApexMail/docs/research/eu-vat-saas-practices.md` | The existing research memo; verified against the primary texts; its article numbers are mostly correct, with the corrections in section 5 |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` | Dated rate table; `reverse_charge_authorised`; `calculate_vat_with_evidence`; `quote_list_price`; `VAT_EVIDENCE_MAX_AGE_DAYS = 90` |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/tax.rs` | Checkout declaration; VIES consultation; renewal revalidation; `quote_for_tenant` |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/compliance/src/vat_oss.rs` | OSS/VD derivation; `consumption_country = billing_country`; no place-of-supply adjudication |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/api-server/src/routes/billing.rs` | Checkout declaration (lines ~1594–1660); invoice reverse-charge note (lines ~2437–2458); tests (~6519) |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/migrations/218_vat_truth_foundation.sql` | `vat_validation_evidence` (`returned_name`, `returned_address`, `valid_from`, `valid_until`, `outage_state`) |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/migrations/219_oss_vd_filing_scaffold.sql` | `customer_location_evidence` table (exists, unused by the derivation) |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-service/src/payments/mod.rs` | Stripe/Mollie are payment processors; ApexMail owns scheduling (not a merchant of record) |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/ARCHITECTURE.md` line 12; `/Users/sabelakhoua/IdeaProjects/ApexMail/docs/architecture/overview.md` line 12 | Production host in Finland (fixed-establishment fact) |
| `/Users/sabelakhoua/IdeaProjects/ApexMail/templates/legal/dpa.md` line 8 | Bel Consulting OÜ, registry code 16588745, VAT EE102951727, Tallinn (the Estonian supplier) |

---

## 8. UNVERIFIED / limitations

1. **The Finnish host as a fixed establishment.** The legal test is in Reg 282/2011 Art 11 and C-605/12 Welmory; the factual application to a rented Hetzner host operated remotely is **UNVERIFIED**. This is the single largest fact-dependent risk in the B2B branch. If the host is a fixed establishment, Finnish B2B supplies and the EUR 10,000 threshold analysis change.
2. **ApexMail's cross-border B2C TBE turnover.** The EUR 10,000 threshold conclusion depends on the actual current and preceding-year figures. The repository does not measure them. **UNVERIFIED.**
3. **The current Estonian KMS redaction.** The official English translation is the 1 July 2022 redaction; a 2026 Estonian-language consolidation was not obtained. The section mapping is confirmed against current EMTA guidance, but a 2023–2026 amendment to § 10/§ 10¹ cannot be excluded on the evidence retrieved. **UNVERIFIED (low risk; EMTA's current table cites the same sections).**
4. **The classification of the Private Cloud setup/onboarding fees.** The marketing definitions list EUR 10,000–60,000 setup fees. Whether they are part of a single TBE supply or a separate non-TBE service is **UNVERIFIED** and must be classified per supply.
5. **VIES name/address sufficiency.** Art 18(1)(a) refers to confirmation of the validity "and of the associated name and address"; VIES does not return name/address for every Member State. Whether a valid status alone is sufficient in each Member State is **UNVERIFIED**; the code stores `returned_name`/`returned_address` but the in-memory authorization does not compare them.
6. **The 24 July 2026 revised OSS Explanatory Notes** mentioned in the existing repo memo were not fetched or analysed. The ViDA analysis in this memo is from the directive text and the Commission's ViDA page, not from those notes. **UNVERIFIED (secondary).**
7. **The Council press release** was blocked by a browser check; the entry-into-force and application dates are verified from the directive (Art 6, Art 7) and the Commission's ViDA page, not from the press release.
8. **Article 59a (effective use and enjoyment).** Member States may reallocate the place of supply where the effective use/enjoyment occurs elsewhere. Whether any Member State applies Art 59a to ApexMail's e-services is **UNVERIFIED**; the general rule (Art 58) is stated in the memo. This is a low-risk horizon item.
9. **The 2026 rates and the full 27-state table** are angle 3's scope. This memo uses only the Estonian 24% and the destination-rate mechanism; it does not re-verify every national rate.
10. **The exact penalty/interest consequences** of an incorrect place-of-supply determination are national law and were not researched.

---

## 9. One-paragraph answer for the owner

The place-of-supply position in the repo is **substantially right and should not be reversed**: a verified EU business outside Estonia is outside the Estonian charge under Art 44, the customer is liable under Art 196, and ApexMail invoices at the Estonian 0% rate with the "Reverse charge" notation and reports the supply in the VD/ESL; OSS is irrelevant to that B2B supply. A consumer in another Member State is taxed at the destination rate under Art 58, but only because the supply is a TBE service; the EUR 10,000 threshold in Art 59c is a B2C-only, EU-wide, current-and-preceding-year test, and the code does not measure it. The two things that need owner/accountant attention are **facts, not article numbers**: (i) whether the Finnish production host is a fixed establishment (if it is, Finnish B2B supplies cannot be reverse-charged and the EUR 10,000 threshold is unavailable), and (ii) whether the consumer's declared country is supported by the second non-contradictory location item that Art 24b(d) requires (the code currently uses the billing country alone). On ViDA, the first date that touches this seller is **1 January 2027** (Art 59c(3) deemed option and OSS/IOSS clarifications); the 2028 deemed-supplier and Single VAT Registration changes are platform/goods reforms that do not apply to ApexMail's own email service, and the e-invoicing/digital-reporting change is 1 July 2030 (2035 for certain Member States' domestic systems).
