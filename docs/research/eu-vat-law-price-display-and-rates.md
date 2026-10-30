# VAT-LAW-C — Angle 3: consumer price display and the dated 27-state rate table

**Prepared:** 30 October 2026. **Scope:** Directive 98/6/EC as amended by Directive (EU) 2019/2161; Directive 2011/83/EU Art. 6(1)(e) and 8(2); Directive 2005/29/EC Arts. 6–7 and the Omnibus amendments; Estonian implementation; the standard VAT rate in force in all 27 Member States on 30 October 2026 and every 2024–2026 change.
**Repository:** read-only for this session; no repository files were changed. The only file written is this memo. A final `git status` showed five concurrently modified files (billing routes/evidence work) that were **not** made by this session and do not touch `DEFAULT_VAT_RATE_PERIODS`; the rate table rows quoted below were unchanged.
**Retrieval date for every source below: 30 October 2026** unless a source carries its own last-updated date.

---

## 0. Bottom line

1. **A consumer-facing page that displays a net price plus “VAT calculated at checkout, total shown before you pay” does not satisfy the pre-contractual price-display rules.** The checkout total can satisfy the *timing* rule in Art. 8(2) CRD (“directly before the consumer places the order”), but the pricing page is itself an “invitation to purchase” under the UCPD and a “corresponding offer” under Art. 6(1) CRD; it must carry the total inclusive of VAT (or a country-localised gross). The “manner of calculation” exception is narrow and does not cover VAT that the trader can calculate or design around. It is lawful only if the page is genuinely gated to businesses (net + clear “excl. VAT” statement) and consumers are routed to a VAT-inclusive price.
2. **The defensible model for one global site selling to both audiences** is: a consumer view showing **one VAT-inclusive gross per plan** (Option A), and an explicit business view showing **net prices “excl. VAT”** with the reverse-charge note. Checkout repeats the same gross and the recurring amount; the order button states the payment obligation.
3. **All 27 current standard rates in `crates/billing-common/src/vat_rates.rs` are numerically correct as at 30 October 2026.** The table has **one wrong baseline/effective date (Czechia)** and **three missing historical rate periods (Germany H2 2020, Ireland Sep 2020–Feb 2021, Luxembourg 2023)**. These are back-dated-invoice defects, not current-rate defects.
4. **Czechia is the material finding:** the 21 % standard rate has been in force since **1 January 2013** (Act No. 500/2012 Coll., § 47(1)(a), 20 → 21). The 2024 consolidation (Act No. 349/2023 Coll.) changed only the **reduced** rate (15 % → 12 %); it did **not** change the standard rate. The repo’s “20 % until 2023-12-31, 21 % from 2024-01-01” is factually wrong and under-charges every invoice dated 2020-01-01 to 2023-12-31 by 1 percentage point.
5. **No Member State has an announced future standard-rate change as at 30 October 2026.** Bulgaria adopted the euro on 1 January 2026 (€1 = 1.95583 BGN) but kept its 20 % standard rate; Bulgarian VAT invoices are in EUR from that date, the registration threshold became EUR 51,130, and compulsory dual BGN/EUR price display ran from 8 August 2025 to 8 August 2026.

---

## 1. Method and evidence classes

| Class | What was used | Notes |
|---|---|---|
| Primary law | EUR-Lex consolidated texts of 98/6/EC (28.05.2022), 2011/83/EU (28.05.2022), 2005/29/EC (28.05.2022); Directive 2000/31/EC Art. 5(2) | Retrieved via the EUR-Lex HTML endpoint through the Jina Reader proxy (the direct EUR-Lex WAF returns empty pages to curl). |
| Official rates (class 1) | European Commission **TEDB** (Taxes in Europe Database) SOAP service `VatRetrievalService`, `retrieveVatRates`, `situationOn = 2026-10-30`, and range queries `from = 2014-01-01`, `to = 2026-10-30` | TEDB is the Commission’s official rates database, populated by Member States. It is expressly **non-binding**; national law prevails. The range queries return dated rate periods; the data floor is 2016-01-01. Greece is keyed **EL**, not GR. |
| National authorities (class 1) | EMTA (Estonia), Vero (Finland), European Commission “Bulgaria and the euro”, Czech Acts 235/2004, 349/2023 and 500/2012 | Where an authority page was JS-only/unreachable, the national legal text or the EC country page was used. |
| Trackers (class 2) | **PwC Worldwide Tax Summaries** (“Other taxes” page per country; last-reviewed dates 23 Jul – 01 Oct 2026) and **Tax Foundation, “VAT Rates in Europe, 2026”** (published 26 Jan 2026, updated 27 Jan 2026) | Two independent trackers. KPMG’s and Deloitte’s global rate tables are JavaScript applications and were not machine-readable in this session; EY’s worldwide VAT guide is a gated landing page. EY tax alerts were used for Romania (class 3). |
| Dated instruments/news (class 3) | Act No. 500/2012 Coll. (CZ, 2013); Act No. 349/2023 Coll. (CZ, 2024); EMTA 08.08.2025 (EE); Vero 01.01.2026 (FI); EY alert 30.07.2025 and Law 141/2025 (RO); PwC 09.09.2026 / Act No. 465/2024 Coll. (SK); EC “Bulgaria and the euro” (BG) | See §3.2 and §5. |

**Triple-check rule applied.** Every rate row has (i) the official EC TEDB value and dated history, (ii) PwC, and (iii) Tax Foundation. Every 2024–2026 **change** additionally has a dated instrument or authority page. Where sources conflict, the conflict is stated in §3.4.

---

## 2. Consumer price display — the law from the texts

### 2.1 Directive 98/6/EC (consolidated 28 May 2022, as amended by Directive (EU) 2019/2161)

**Article 1 (purpose):**

> “The purpose of this Directive is to stipulate indication of the selling price and the price per unit of measurement of products offered by traders to consumers in order to improve consumer information and to facilitate comparison of prices.”

**Article 2(a) — verbatim:**

> “selling price shall mean the final price for a unit of the product, or a given quantity of the product, including VAT and all other taxes;”

**Article 3 — verbatim:**

> “1. The selling price and the unit price shall be indicated for all products referred to in Article 1, the indication of the unit price being subject to the provisions of Article 5. The unit price need not be indicated if it is identical to the sales price.
>
> 2. Member States may decide not to apply paragraph 1 to:
> — products supplied in the course of the provision of a service,
> — sales by auction and sales of works of art and antiques.
>
> 3. For products sold in bulk, only the unit price must be indicated.
>
> 4. Any advertisement which mentions the selling price of products referred to in Article 1 shall also indicate the unit price subject to Article 5.”

**Article 4(1):**

> “The selling price and the unit price must be unambiguous, easily identifiable and clearly legible. Member States may provide that the maximum number of prices to be indicated be limited.”

**Article 6a (inserted by Directive (EU) 2019/2161) — price reductions:**

> “1. Any announcement of a price reduction shall indicate the prior price applied by the trader for a determined period of time prior to the application of the price reduction.
>
> 2. The prior price means the lowest price applied by the trader during a period of time not shorter than 30 days prior to the application of the price reduction.”

**Article 8(1) (penalties):**

> “Member States shall lay down the rules on penalties applicable to infringements of national provisions adopted pursuant to this Directive and shall take all measures necessary to ensure that they are implemented. The penalties provided for shall be effective, proportionate and dissuasive.”

**Enforcement and scope.** Article 8(2)–(3) lists the penalty criteria and the notification duty; Article 9 extends the nine-year transition period and repeals Directives 79/581/EEC and 88/314/EEC; Article 10 permits Member States to adopt or maintain provisions more favourable to consumer information and price comparison. The **unit-price** rules (Art. 3(1), Art. 5) are quantity-based and are not the operative rule for SaaS; Article 3(2) is the services carve-out that can remove the indication duty altogether.

**What 98/6/EC does and does not do for SaaS.** The “selling price” definition is VAT-inclusive and is the Directive’s core. But Article 3(2) expressly permits a Member State to disapply the *indication* obligation to “products supplied in the course of the provision of a service”. Whether 98/6/EC itself requires a displayed price for ApexMail’s SaaS therefore depends on whether the relevant Member State used that carve-out. Estonia transposed 98/6/EC through the **Consumer Protection Act (Tarbijakaitseseadus)** — the official EUR-Lex national-transposition record for Directive 98/6/EC names that Act as Estonia’s measure (NIM:25290). The Estonian Act’s treatment of services, and the exact section, need Estonian counsel; but the CRD and UCPD below apply to the service independently of the 98/6 carve-out. So the practical answer does not turn on 98/6’s services point.

### 2.2 Directive 2011/83/EU (CRD), Art. 6(1)(e) and Art. 8(2)

The chapeau of Article 6(1): “Before the consumer is bound by a distance or off-premises contract, **or any corresponding offer**, the trader shall provide the consumer with the following information in a clear and comprehensible manner”.

**Article 6(1)(e) — verbatim:**

> “the total price of the goods or services inclusive of taxes, or where the nature of the goods or services is such that the price cannot reasonably be calculated in advance, the manner in which the price is to be calculated, as well as, where applicable, all additional freight, delivery or postal charges and any other costs or, where those charges cannot reasonably be calculated in advance, the fact that such additional charges may be payable. In the case of a contract of indeterminate duration or a contract containing a subscription, the total price shall include the total costs per billing period. Where such contracts are charged at a fixed rate, the total price shall also mean the total monthly costs. Where the total costs cannot be reasonably calculated in advance, the manner in which the price is to be calculated shall be provided;”

**Article 8(2) — verbatim:**

> “If a distance contract to be concluded by electronic means places the consumer under an obligation to pay, the trader shall make the consumer aware in a clear and prominent manner, and directly before the consumer places his order, of the information provided for in points (a), (e), (o) and (p) of Article 6(1).
>
> The trader shall ensure that the consumer, when placing his order, explicitly acknowledges that the order implies an obligation to pay. If placing an order entails activating a button or a similar function, the button or similar function shall be labelled in an easily legible manner only with the words ‘order with obligation to pay’ or a corresponding unambiguous formulation indicating that placing the order entails an obligation to pay the trader. If the trader has not complied with this subparagraph, the consumer shall not be bound by the contract or order.”

Two timing points follow from the text itself:

- Article 6(1) attaches **before the consumer is bound by a distance contract *or any corresponding offer***. A published pricing page that a consumer can accept is a “corresponding offer”.
- Article 8(2) adds a second, later duty **directly before the order**. Complying at that later point does not discharge the earlier Article 6(1) duty.

### 2.3 Directive 2005/29/EC (UCPD) and the Omnibus amendments

**Article 6(1)(d) — misleading actions:** a practice is misleading if it deceives about

> “the price or the manner in which the price is calculated, or the existence of a specific price advantage;”

**Article 7(4)(c) — misleading omissions; material information in an invitation to purchase:**

> “the price inclusive of taxes, or where the nature of the product means that the price cannot reasonably be calculated in advance, the manner in which the price is calculated, as well as, where appropriate, all additional freight, delivery or postal charges or, where these charges cannot reasonably be calculated in advance, the fact that such additional charges may be payable;”

**Annex I, point 20 (blacklist):**

> “Describing a product as ‘gratis’, ‘free’, ‘without charge’ or similar if the consumer has to pay anything other than the unavoidable cost of responding to the commercial practice and collecting or paying for delivery of the item.”

**What the Omnibus actually did — the brief’s cross-check.** Directive (EU) 2019/2161 did **not** insert an Article 6(1)(e) into the UCPD. UCPD Art. 6(1)(e) remains “the need for a service, part, replacement or repair” — an element of misleading action unrelated to price. The Omnibus:

- inserted **Article 6a into Directive 98/6/EC** (prior-price rule for reductions), not into the UCPD;
- amended UCPD Art. 7(4)(d), inserted Art. 7(4)(f) (online marketplaces), Art. 7(4a) (ranking transparency) and Art. 7(6) (reviews);
- inserted UCPD Art. 6(2)(c) (dual-quality marketing);
- inserted Annex I points 23a–23c (ticket resale, fake reviews);
- inserted Article 11a (remedies: compensation, price reduction, termination).

It did **not** add a general “hidden costs” blacklist point. The “costs” blacklist point on the books is point 20 (the “free” claim); hidden or omitted costs are handled through Art. 6(1)(d), Art. 7(1)–(2) and Art. 7(4)(c). This matters because the audit’s question is about a *price statement*, not a “free” claim: the operative provisions are Art. 6(1)(d) and Art. 7(4)(c).

**Official Commission guidance on the total-price rule (UCPD Guidance, 2021/C 526/01):**

> “Article 7(4)(c) requires traders to state the total (or final) price in an invitation to purchase. This must include all applicable taxes (e.g. VAT) and charges. The final price must include applicable charges and taxes which are unavoidable and foreseeable when the offer is published. When the nature of the product means that the price cannot reasonably be calculated in advance, consumers should be properly informed about the manner in which the price is calculated…”

The same guidance gives a directly relevant enforcement example:

> “A company advertised the sale of apartments using statements such as ‘It’s cheaper than you might think. Prices starting from EUR 2 150 per square metre’. However, it turned out that there were no apartments available at the price indicated. Moreover, the price indicated did not include VAT. This commercial practice was found to be misleading by a consumer authority.”

It also applies the CJEU’s *Canal Digital Danmark* reasoning to subscriptions: where a trader highlights a monthly charge but omits or under-emphasises a six-monthly charge, that is a misleading omission under Article 7. The analogy to a net headline price with VAT relegated to checkout is direct.

The guidance is the Commission’s interpretive view; it is not binding on national courts, but it is the authoritative enforcement-policy statement and is routinely relied on by consumer authorities.

### 2.4 Directive 2000/31/EC (e-Commerce Directive), Art. 5(2)

> “In addition to other information requirements established by Community law, Member States shall at least ensure that, where information society services refer to prices, these are to be indicated clearly and unambiguously and, in particular, must indicate whether they are inclusive of tax and delivery costs.”

This is the provision that makes an **“excl. VAT”** label lawful *as such* for an information-society service: the law requires clarity about tax status, not that every price reference be gross. But Article 5(2) is a transparency rule; it does not override the CRD’s total-price rule or the UCPD’s invitation-to-purchase rule for consumers. It supports the business view (net, clearly marked), not a consumer view that shows net.

### 2.5 The crux: does “VAT calculated at checkout, total shown before you pay” satisfy the pre-contractual stage?

**The question restated for ApexMail’s one-site-many-countries model.** The pricing page displays plan prices (currently €20 / €89 / €229 / €699 / €1,750 in `apps/marketing-zola/data/pricing.json`), a footnote saying business prices exclude VAT and that consumers see the total including VAT before paying, and an optional consumer gross card. Checkout computes destination VAT and shows the total before payment.

**Analysis from the texts:**

1. **The pricing page is an invitation to purchase.** UCPD Art. 2(i) defines an invitation to purchase as a commercial communication that indicates characteristics and the price in a way that enables the consumer to make a purchase. A plan table with prices and a “Get started” path does exactly that. Art. 7(4)(c) then requires “the price inclusive of taxes” — not a net price plus a promise of a later total.
2. **The “manner of calculation” exception is narrow.** Both Art. 6(1)(e) CRD and Art. 7(4)(c) UCPD allow the manner of calculation only where “the nature of the goods or services is such that the price cannot reasonably be calculated in advance” / “the nature of the product means that the price cannot reasonably be calculated in advance”. Country-dependent VAT is not a property of the *nature of the service*; it is a function of the seller’s pricing and geo-localisation design. The seller can (a) set one EU gross price, (b) localise the gross by country, or (c) require the consumer to choose a country before showing a price. A net figure is not a “manner of calculation”.
3. **CRD Art. 6(1) attaches to “any corresponding offer”.** Even if the checkout total arrives before the contract is bound, the pricing page is an offer; the Article 6(1)(e) information must accompany it. Art. 8(2) is an *additional* “directly before the order” duty, not a substitute.
4. **98/6/EC points the same way where it applies.** If the Member State has not disapplied the indication duty for services, the “selling price” must be the final price “including VAT and all other taxes” (Art. 2(a)), and it must be “unambiguous, easily identifiable and clearly legible” (Art. 4(1)). A net price is not that final price.
5. **A note is not a price.** The sentence “VAT calculated at checkout per your country, total shown before you pay” is accurate as a description of the checkout mechanics, but it does not state the total. Under Art. 7(4)(c), the information required is the price inclusive of taxes; a description of how a later price will be computed is permitted only in the narrow “cannot reasonably be calculated” case. The Commission’s guidance example (an apartment price excluding VAT, found misleading by a consumer authority) confirms that an omitted VAT component is not cured by the fact that it is calculable.
6. **The “country is unknown” counter-argument fails.** It can be argued that at the pricing page the consumer’s country is unknown, so the total “cannot reasonably be calculated in advance”. But the exception is about the **nature of the product**, not the seller’s information architecture. The seller controls the display: it can show one EU gross, localise the gross by country, or ask for the country before showing a price. A net figure is none of those. The counter-argument would also swallow the rule for every cross-border digital seller, which is not what Art. 6(1)(e) or Art. 7(4)(c) says.

**Verdict.**

| Scenario | Is the note sufficient at the pre-contractual stage? | Why |
|---|---|---|
| Consumer-facing pricing page showing net prices + “VAT calculated at checkout, total shown before you pay” | **No** | The page is an invitation to purchase/corresponding offer; the total inclusive of VAT must be there. Checkout compliance does not cure the earlier omission. |
| Consumer-facing page showing a **country-localised gross** for the consumer’s country, with the note explaining that the rate depends on the country | **Yes**, provided the displayed figure is the gross for the selected/known country and the country is determined reliably before display (not a generic net figure) | The displayed price is then the Art. 2(a)/6(1)(e)/7(4)(c) total. |
| Consumer-facing page showing **one EU gross** for all consumers | **Yes** — the safest model | The displayed figure is the total by construction; no geo-dependency. |
| Page gated to businesses only, showing net prices clearly marked “excl. VAT”, with reverse-charge note; consumers routed elsewhere | **Yes for the business page** | B2B buyers are outside 98/6/CRD consumer protections; e-Commerce Art. 5(2) requires the tax status to be clear, which “excl. VAT” is. The consumer must not be able to buy from that page without seeing a gross. |
| Checkout total shown before payment | **Necessary but not sufficient on its own** | It satisfies Art. 8(2) timing; it does not satisfy the pricing-page invitation-to-purchase rule. |

**The two compliant models, restated precisely:**

- **Model (i) — single consumer gross (recommended).** One VAT-inclusive gross per plan for all consumers; the net is derived per country for the invoice (gross-first arithmetic: VAT = gross × rate / (100 + rate), net = gross − VAT). The displayed price is the statutory total by construction; no geolocation is needed to display it.
- **Model (ii) — country-localised gross.** Net list plus the consumer’s local VAT, but the **gross for the consumer’s country is displayed at the first price indication** (pricing page, ads that state a price, checkout), not only at checkout. This is compliant only if the country is determined reliably before display and the page shows the gross, not the net. A “VAT calculated at checkout” note on a net page is the non-compliant version of Model (ii).

### 2.6 Subscriptions specifically

For a monthly SaaS plan, Art. 6(1)(e) requires the **total costs per billing period** — i.e. the full monthly amount including VAT, not a net monthly amount plus a later VAT line. For an annual plan, the total per billing period is the **annual total including VAT**; a monthly equivalent (“€16.67/month, billed annually”) is additional information, not a substitute for the annual total. Where the contract is at a fixed rate, the total monthly costs are also required. If the total cannot reasonably be calculated in advance (usage-based overage), the manner of calculation must be explained; for fixed plans it must be the total.

Art. 8(2) then requires the total and the recurring nature to be presented **clearly and prominently directly before the order**, and the order button must be labelled “order with obligation to pay” or an equivalent unambiguous formulation. The UCPD Guidance adds that “both the amount of a one-off payment as well as the amount of recurring payments that may follow should be clearly provided to the consumer.”

**Application to ApexMail’s current marketing page (observation only, no change made).** `apps/marketing-zola/templates/partials/pricing/plans.html` currently:

- displays the **net** `monthly_price_display` in the plan table;
- carries the footnote “Business prices exclude VAT. Consumers see the total including VAT before paying. The price shown to consumers includes VAT; the applicable rate depends on the buyer’s country and appears on the invoice. Annual prices are shown as the total per billing period.”;
- shows a consumer gross card **only if** `plan.consumer_gross_display` exists; `data/pricing.json` currently has **no** `consumer_gross_display` for any plan;
- shows the annual column as the **yearly total divided by twelve** (a monthly equivalent), not the annual total per billing period.

Two concrete legal defects follow: (a) the sentence “The price shown to consumers includes VAT” is contradicted by the net table — a UCPD Art. 6(1)(d)/7(2) misleading-presentation risk; (b) the annual column is a monthly equivalent, not the Art. 6(1)(e) total per billing period. Both are fixable by display, not by code.

### 2.7 Estonia — national implementation

- **Transposing act:** Estonia notified the **Consumer Protection Act (Tarbijakaitseseadus)** as its measure transposing Directive 98/6/EC (EUR-Lex national transposition record, NIM:25290). The Act is the national instrument that carries the final-price/price-indication duty for consumers.
- **Enforcement:** the Consumer Protection and Technical Regulatory Authority (TTJA) enforces the Consumer Protection Act; the VAT rate itself is administered by EMTA. A consumer-price display breach is a consumer-law matter, not a VAT-assessment matter, but the two can run in parallel (a net consumer price can be both a consumer-law breach and, if VAT is under-collected, a VAT issue).
- **What Estonia adds:** the Act’s general information duties apply to distance contracts; the price must be presented clearly and understandably. Whether Estonia used the Art. 3(2) services carve-out, and the exact section number for the price-display duty, are national-law points to confirm with Estonian counsel. The CRD/UCPD duties apply regardless.
- **Language:** the CRD requires information in a “clear and comprehensible manner”; it does not require all 24 EU languages. Estonia does not, in the sources reviewed, impose an English-language ban for online B2C offers, but the information must be intelligible to the Estonian consumer. The four site languages (EN/DE/FR/ES) do not include Estonian; if the site targets Estonian consumers, an Estonian version or a clear language-selection route should be considered. Local counsel should confirm any Language Act requirement.

### 2.8 Exact sentences the pricing page must carry (English)

These are the sentences to use; they satisfy 98/6/EC (where applicable), CRD Art. 6(1)(e)/8(2) and UCPD Art. 7(4)(c). The figures are illustrative (€20 net / €24.80 gross at 24 %).

**Consumer view (Option A — one EU gross):**

> **€24.80 per month, including VAT.** You will be charged €24.80 each month until you cancel.

> **€297.60 per year, including VAT** (12 monthly payments of €24.80). You will be charged €297.60 each year until you cancel.

**Business view (net, gated):**

> **€20.00 per month, excluding VAT.** VAT is added at checkout at your local rate. If you provide a valid EU VAT number and it is verified, the supply is zero-rated under the reverse-charge mechanism and you account for VAT.

**If the owner insists on country-localised gross (Model ii, done properly):**

> **Prices include VAT.** The VAT rate depends on your country of residence. The total you will pay, including VAT, is shown on this page and again before you place your order.

— but this sentence is only compliant if the figure displayed on that page is the **gross for the selected country**, not the net list.

**Order button (Art. 8(2)):**

> **Subscribe and pay €24.80 per month** (or “Order with obligation to pay — €24.80 per month”).

**If a discount is advertised (98/6 Art. 6a):**

> **€24.80 per month (was €29.90; lowest price in the last 30 days: €29.90).**

**Four-language constraints.** The existing labels are correct in principle: “incl. VAT” / “inkl. MwSt.” / “TTC” / “IVA incluido”; business: “excl. VAT” / “zzgl. USt.” / “HT” / “sin IVA”. Three constraints:

1. Do not translate “incl. VAT” as a generic “tax included” where the national convention is a specific VAT label (FR “TTC”, ES “IVA incluido”, DE “inkl. MwSt.”, IT “IVA inclusa”).
2. The consumer sentence must state the **amount and period**, not only the tax treatment. “Consumers see the total including VAT before paying” is a timing statement, not a price.
3. Some Member States impose local-language duties for consumer offers (notably France; Belgium’s regional language rules; in practice Italy, Spain and Poland expect the local language for consumer-facing terms). EN/DE/FR/ES covers the four current site languages but not PL, IT, NL, etc. If the site sells into those markets, local counsel should confirm that the English version is acceptable; the CRD’s “clear and comprehensible” test is consumer-facing, not a safe harbour for English-only.

**Three-angle check for the price-display conclusion (mandatory discipline):**

| Angle | Source used | What it establishes |
|---|---|---|
| Directive text | 98/6/EC Arts. 2(a), 3, 4(1), 6a; CRD Arts. 6(1)(e), 8(2); UCPD Arts. 6(1)(d), 7(4)(c), Annex I point 20; e-Commerce Art. 5(2) | The legal rules: final price incl. VAT; total per billing period; invitation-to-purchase total; order-button obligation; tax-status clarity. |
| Official guidance / national implementation | EC UCPD Guidance 2021/C 526/01 (total-price rule; net-price enforcement example; subscription omission); EUR-Lex NIM for 98/6/EC (Estonia: *Tarbijakaitseseadus*); EC “Bulgaria and the euro” (dual display) | How the Commission and consumer authorities read the rules; the Estonian transposing act; the Bulgarian changeover display duty. |
| Practitioner | Stripe tax-behavior documentation; Paddle inclusive/exclusive pricing documentation | Market convention: B2C prices are normally tax-inclusive; B2B prices are normally net; merchant-of-record platforms localise the gross. Practice is evidence of convention, not a safe harbour. |

---

## 3. The dated standard-rate table — 27 Member States, triple-verified

### 3.1 Table as at 30 October 2026

All rates are the **standard** rate applicable to general electronically supplied services (no Member State is known to apply a reduced rate to general SaaS; the standard rate is the rate that applies). “Effective from” is the start of the **current rate period**; where the only evidence is TEDB’s 2016-01-01 data floor, the cell says “≤2016-01-01 (TEDB floor)” rather than inventing a legal date. “Next announced change” is “none identified” unless stated.

| # | Country | ISO | Standard rate now | Effective from | Next announced change (date, rate, instrument) | Three sources |
|---:|---|---|---:|---|---|---|
| 1 | Austria | AT | 20.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Reduced 4.9 %/4 % from 2026-07-01; standard unchanged.) | TEDB 2026-10-30; PwC AT rev. 2026-07-23; TF 2026 |
| 2 | Belgium | BE | 21.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Hotels 6→12 % and phytopharma 12→21 % from 2026-03-01; standard unchanged.) | TEDB 2026-10-30; PwC BE rev. 2026-09-10; TF 2026 |
| 3 | Bulgaria | BG | 20.0 % | ≤2016-01-01 (TEDB floor) | None. Euro adoption 2026-01-01 (€1 = 1.95583 BGN); **no rate change**; EUR invoices; threshold EUR 51,130; dual display 2025-08-08–2026-08-08 | TEDB 2026-10-30; PwC BG rev. 2026-08-02; TF 2026; EC “Bulgaria and the euro” |
| 4 | Croatia | HR | 25.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC HR rev. 2026-08-27; TF 2026 |
| 5 | Cyprus | CY | 19.0 % | ≤2016-01-01 (TEDB floor) | None identified. (5 % renovation conditions changed 2026-09-01; standard unchanged.) | TEDB 2026-10-30; PwC CY rev. 2026-08-04; TF 2026 |
| 6 | Czechia | CZ | **21.0 %** | **2013-01-01** (Act No. 500/2012 Coll., § 47(1)(a): 20→21) | None identified. The 2024 consolidation (Act No. 349/2023 Coll., eff. 2024-01-01) changed only the reduced rate 15→12 %; standard untouched | TEDB 2026-10-30; PwC CZ rev. 2026-07-27; TF 2026; Act 500/2012; Act 349/2023 |
| 7 | Denmark | DK | 25.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC DK rev. 2026-07-31; TF 2026 |
| 8 | Estonia | EE | **24.0 %** | **2025-07-01** (22 % from 2024-01-01; 20 % before) | None identified | TEDB 2026-10-30; PwC EE rev. 2026-05-29; TF 2026; EMTA “From 1 July 2025 … 24 % instead of 22 %” |
| 9 | Finland | FI | **25.5 %** | **2024-09-01** (24 % before; fractional rate, do not round) | None identified. (Reduced 14→13.5 % from 2026-01-01; standard unchanged.) | TEDB 2026-10-30; PwC FI rev. 2026-09-09; TF 2026; Vero “1 September 2024 the general VAT rate changed from 24 % to 25.5 %” |
| 10 | France | FR | 20.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC FR rev. 2026-04-24; TF 2026 |
| 11 | Germany | DE | 19.0 % | **2021-01-01** (16 % 2020-07-01–2020-12-31; 19 % before) | None identified | TEDB 2026-10-30; PwC DE rev. 2026-06-30; TF 2026 |
| 12 | Greece (EL in TEDB) | GR | 24.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30 (EL); PwC GR rev. 2026-09-08; TF 2026 |
| 13 | Hungary | HU | 27.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Meat 5 % from 2026-01-01; standard unchanged.) | TEDB 2026-10-30; PwC HU rev. 2026-07-01; TF 2026 |
| 14 | Ireland | IE | 23.0 % | **2021-03-01** (21 % 2020-09-01–2021-02-28; 23 % before) | None identified | TEDB 2026-10-30; PwC IE rev. 2026-08-11; TF 2026 |
| 15 | Italy | IT | 22.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC IT rev. 2026-07-13; TF 2026 |
| 16 | Latvia | LV | 21.0 % | ≤2016-01-01 (TEDB floor) | **None in force.** A 22 % proposal was reported in 2025 but is not law on 2026-10-30 (TEDB and PwC both 21 %) | TEDB 2026-10-30; PwC LV rev. 2026-06-30; TF 2026 |
| 17 | Lithuania | LT | 21.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Reduced 9→12 % from 2026-01-01; standard unchanged.) | TEDB 2026-10-30; PwC LT rev. 2026-10-01; TF 2026; TEDB reduced series 2026-01-01 |
| 18 | Luxembourg | LU | 17.0 % | **2024-01-01** (16 % 2023-01-01–2023-12-31; 17 % before) | None identified | TEDB 2026-10-30; PwC LU rev. 2026-07-31; TF 2026 |
| 19 | Malta | MT | 18.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC MT rev. 2026-09-30; TF 2026 |
| 20 | Netherlands | NL | 21.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Accommodation 9→21 % from 2026-01-01; standard unchanged.) | TEDB 2026-10-30; PwC NL rev. 2026-05-29; TF 2026 |
| 21 | Poland | PL | 23.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC PL rev. 2026-08-11; TF 2026 |
| 22 | Portugal | PT | 23.0 % | ≤2016-01-01 (TEDB floor) | None identified. Mainland rate; Madeira 22 %, Azores 16 % are regional (see §3.4) | TEDB 2026-10-30; PwC PT rev. 2026-07-24; TF 2026 |
| 23 | Romania | RO | **21.0 %** | **2025-08-01** (19 % before; Law No. 141/2025) | None identified | TEDB 2026-10-30; PwC RO rev. 2026-09-25; TF 2026; EY alert 2025-07-30; Law 141/2025 |
| 24 | Slovakia | SK | **23.0 %** | **2025-01-01** (20 % before; consolidation package, Act No. 465/2024 Coll.) | None identified. (Selected goods 19→23 % from 2026-01-01 is a reduced-rate change, not the standard rate.) | TEDB 2026-10-30; PwC SK rev. 2026-09-09; TF 2026 |
| 25 | Slovenia | SI | 22.0 % | ≤2016-01-01 (TEDB floor) | None identified | TEDB 2026-10-30; PwC SI rev. 2026-07-15; TF 2026 |
| 26 | Spain | ES | 21.0 % | ≤2016-01-01 (TEDB floor) | None identified. Mainland/Balearics 21 %; Canary Islands IGIC 7 % (TEDB’s second “STANDARD” row is the Canary Islands, not mainland VAT) | TEDB 2026-10-30; PwC ES rev. 2026-06-30; TF 2026 |
| 27 | Sweden | SE | 25.0 % | ≤2016-01-01 (TEDB floor) | None identified. (Dance events 25→6 % from 2026-07-01; food 12→6 % from 2026-04-01 to 2027-12-31; standard unchanged.) | TEDB 2026-10-30; PwC SE rev. 2026-09-22; TF 2026 |

**TEDB query evidence.** The official TEDB `retrieveVatRates` response for `situationOn = 2026-10-30` returned exactly one standard-rate row per country (except Germany and Spain, which have duplicate/category rows — see §3.4), with these values: AT 20, BE 21, BG 20, HR 25, CY 19, CZ 21, DK 25, EE 24, FI 25.5, FR 20, DE 19, EL 24, HU 27, IE 23, IT 22, LV 21, LT 21, LU 17, MT 18, NL 21, PL 23, PT 23, RO 21, SK 23, SI 22, ES 21, SE 25. The dated range queries (2014-01-01 to 2026-10-30) returned the changes in §3.2.

### 3.2 Every 2024–2026 change found (standard and reduced)

**Standard-rate changes (the only ones that affect the table):**

| Country | Change | Effective date | Instrument / dated source | Status |
|---|---|---|---|---|
| Estonia | 22 % → 24 % | **2025-07-01** | EMTA, “From 1 July 2025, the standard rate of VAT in Estonia is 24 % instead of 22 %” (last updated 08.08.2025); TEDB series 2025-07-01 | Verified |
| Finland | 24 % → 25.5 % | **2024-09-01** | Vero, “1 September 2024 the general VAT rate changed from 24 % to 25.5 %” (last updated 01.01.2026); TEDB series 2024-09-01 | Verified |
| Romania | 19 % → 21 %; reduced 5 %/9 % → 11 % | **2025-08-01** | Law No. 141/2025; EY Global Tax Alert, 30 July 2025 (“Starting from 1 August 2025, the standard VAT rate will increase from 19 % to 21 %”); TEDB series 2025-08-01 | Verified |
| Slovakia | 20 % → 23 %; reduced 10 %/5 % → 19 %/5 % | **2025-01-01** | Consolidation package, Act No. 465/2024 Coll.; PwC SK rev. 2026-09-09 (“From 1 January 2025, a basic VAT rate of 23 % (previously 20 %) applies”); TEDB series 2025-01-01 | Verified (act number from the consolidation package; act text not machine-fetched) |
| Czechia | **No standard-rate change.** 21 % throughout; the 2024 consolidation changed the reduced rate 15 % → 12 % | 2024-01-01 (reduced rate only) | Act No. 349/2023 Coll., Čl. LX, point 5: “V § 47 odst. 1 písm. b) se slovo ‘první’ zrušuje a slova ‘15 %, nebo’ nahrazují textem ‘12 %.’”; standard paragraph (a) untouched | Verified — **corrects the prior memo** |
| Germany | 19 % → 16 % (COVID) → 19 % | 2020-07-01 → 2021-01-01 | TEDB series; outside the 2024-2026 window but relevant to the repo’s 2020 floor | Verified (official EC) |
| Ireland | 23 % → 21 % (COVID) → 23 % | 2020-09-01 → 2021-03-01 | TEDB series | Verified (official EC) |
| Luxembourg | 17 % → 16 % → 17 % | 2023-01-01 → 2024-01-01 | TEDB series | Verified (official EC) |

**Reduced-rate changes in 2024–2026 (no effect on the standard-rate table, but the brief asked to check for “any others”):**

| Country | Change | Effective date | Source |
|---|---|---|---|
| Austria | New 4.9 % super-reduced rate (TEDB; PwC describes “4 %”) | 2026-07-01 | TEDB reduced series; PwC AT rev. 2026-07-23 |
| Belgium | Hotels/camping 6 % → 12 %; phytopharma 12 % → 21 % | 2026-03-01 | PwC BE rev. 2026-09-10 |
| Cyprus | 5 % renovation/repair conditions tightened (residence ≥3 years, used ≥18 months) | 2026-09-01 | PwC CY rev. 2026-08-04 |
| Estonia | Accommodation 9 % → 13 % | 2025-01-01 | TEDB reduced series; EMTA |
| Finland | Reduced 14 % → 13.5 % | 2026-01-01 | Vero; TEDB reduced series |
| Hungary | Meat 5 % | 2026-01-01 | PwC HU rev. 2026-07-01 |
| Lithuania | Reduced 9 % → 12 % | 2026-01-01 | TEDB reduced series; PwC LT rev. 2026-10-01 (12 % reduced) |
| Luxembourg | 8 % super-reduced (new) | 2025-01-01 | TEDB reduced series |
| Netherlands | Accommodation 9 % → 21 % | 2026-01-01 | PwC NL rev. 2026-05-29 (TEDB’s reduced series still shows 9 % only; conflict noted in §3.4) |
| Poland | 8 % super-reduced (new) | 2025-01-01 | TEDB reduced series |
| Romania | 5 %/9 % → 11 % | 2025-08-01 | Law 141/2025; EY |
| Slovakia | 10 %/5 % → 19 %/5 %; selected goods 19 → 23 % | 2025-01-01; 2026-01-01 | PwC SK rev. 2026-09-09 |
| Spain | 4 % super-reduced (food) | 2025-01-01 | TEDB reduced series |
| Sweden | Dance events 25 → 6 %; food 12 → 6 % (to 2027-12-31) | 2026-07-01; 2026-04-01 | PwC SE rev. 2026-09-22 |

### 3.3 Bulgaria’s euro adoption (2026-01-01) — verified

- **Adoption date:** 1 January 2026. European Commission, “Bulgaria and the euro”: “Bulgaria joined the euro area on 1 January 2026.”
- **Conversion rate:** “Fixed conversion rate €1 = 1.95583 Bulgarian lev” (same EC page).
- **Dual price display:** “The dual display of prices in lev and euro became compulsory on 8 August 2025 and will apply until 8 August 2026” (same page). By 30 October 2026 that period has ended; prices are in EUR.
- **VAT consequences:** the standard rate remains **20 %** (TEDB, PwC, TF) and the reduced rate 9 %; the euro change does **not** change the rate. What changes for ApexMail: (i) Bulgarian VAT invoices from 2026-01-01 are in EUR; (ii) the VAT registration threshold became **EUR 51,130** from 2026-01-01 (PwC BG, rev. 2026-08-02, which also notes the new 7-day registration deadline); (iii) any historical BGN amounts convert at 1.95583; (iv) consumer price display during 2025-08-08–2026-08-08 had to be dual BGN/EUR — a point for any Bulgarian marketing archive or invoice template.
- **Rate-table effect:** none. Bulgaria stays 20 % with the same effective-date caveat (≤2016-01-01 TEDB floor).

### 3.4 Conflicts, corrections and UNVERIFIED items

1. **Czechia — CORRECTED.** The prior research memo (`docs/research/eu-vat-saas-practices.md` §6.1 and §6.2) and the repo comment say 21 % “since 2024-01-01 (20 % before)”. That is wrong. Act No. 500/2012 Coll., effective 2013-01-01, § 47(1)(a): “se číslo ‘20’ nahrazuje číslem ‘21’”. Act No. 349/2023 Coll., effective 2024-01-01, amended § 47(1)(b) only: “slova ‘15 %, nebo’ nahrazují textem ‘12 %’”. The 2024 consolidation introduced the 12 % reduced rate; it did not touch the 21 % standard rate. TEDB’s series shows 21 % at its 2016 floor and no 2024 change. **Status: CORRECTED.**
2. **Greece — TEDB key is EL.** Querying `GR` returns a SOAP fault (“Request is not valid”); `EL` returns 24 %. The repo correctly uses ISO `GR`; no action, but tooling that queries TEDB must map GR→EL.
3. **Spain — two “STANDARD” rows.** TEDB returns 21 % (mainland/Balearics) and 7 % with comment “VAT - Canary Islands”. The 7 % is IGIC, not mainland VAT. The repo’s 21 % is correct; a naive TEDB parser that takes the last row would wrongly pick 7 %.
4. **Germany — duplicate 19 % rows.** Two STANDARD/19 % rows (different categories); harmless for the current rate, but a parser must deduplicate.
5. **Austria 4.9 % vs PwC 4 %.** TEDB’s reduced series shows a 4.9 % super-reduced rate from 2026-07-01; PwC AT describes “a reduced VAT rate of 4.” This is a reduced-rate detail (not standard) and the exact scope is **UNVERIFIED**; it does not affect SaaS.
6. **Netherlands accommodation.** PwC NL says accommodation 9→21 % from 2026-01-01; TEDB’s reduced series still shows only 9 %. The standard rate is 21 % either way; the reduced-rate conflict is **UNVERIFIED** and irrelevant to SaaS.
7. **Latvia 22 %.** A 22 % proposal was reported in 2025 but is not in force on 2026-10-30: TEDB 21 % through 2026-10-30; PwC LV (rev. 2026-06-30) 21 %. **Status: proposal only.**
8. **Cyprus/Malta/Belgium/Poland/Hungary/Croatia.** No 2024–2026 standard-rate change found in TEDB, PwC or TF. The brief’s “Cyprus 20 %” and “Malta ?” concerns are not supported: Cyprus 19 %, Malta 18 %, Belgium 21 %, Poland 23 %, Hungary 27 %, Croatia 25 %.
9. **Slovakia act number.** Act No. 465/2024 Coll. is the consolidation/VAT package cited by the trackers; the act text was not machine-fetched (Slov-Lex is JavaScript-only). The **rate and date** are verified by TEDB + PwC; the act number is **UNVERIFIED** at the text level.
10. **TEDB data floor.** TEDB’s range series starts at 2016-01-01 and, for long-stable rates, shows the current rate at the floor rather than a true historical series (the floor is a data artefact, not a legal effective date: a rate that changed during 2016 would still be shown at its current value on 2016-01-01). For that reason the table’s “effective from” uses “≤2016-01-01 (TEDB floor)” for unchanged rates and only asserts exact dates where a dated change appears in the series or a national instrument proves it. Pre-2016 invoices need national-law research, not this table.
11. **Regional rates.** Portugal (Madeira 22 %, Azores 16 %), Spain (Canary Islands IGIC 7 %, Ceuta/Melilla IPSI), Greece (island reduced rates), Finland (Åland), Germany (Büsingen/Heligoland), Italy (Livigno/Campione), France (overseas), Netherlands (Caribbean) and Denmark (Faroe/Greenland) are outside or inside the VAT territory on special terms. The 27-row table is the **mainland/standard** table; a two-letter country code is not sufficient for every address.
12. **Research-doc audit.** Every row of `docs/research/eu-vat-saas-practices.md` §6.1 was re-checked against TEDB, PwC and Tax Foundation. All 27 **current** values match. The only substantive correction is Czechia: the 2020 baseline should be **21 %**, and there was **no 2024 standard-rate change** (the 2024 consolidation changed the reduced rate 15 % → 12 %). The research doc’s statement “No other standard-rate change was identified for 2024–2026” is confirmed. The doc’s CZ row should be corrected in §6.1, in §6.2 and in the §6.6 CSV.

---

## 4. Repository differences — `crates/billing-common/src/vat_rates.rs`

The repo file is `services/mail-server/crates/billing-common/src/vat_rates.rs` (the brief’s path `crates/billing-common/src/vat_rates.rs` resolves under `services/mail-server/`). The dated table is `DEFAULT_VAT_RATE_PERIODS` (lines 52–86); `VAT_RATE_PERIODS` is its parsed form.

### 4.1 Current-rate differences

**None.** All 27 current standard rates in the repo match the verified values as at 2026-10-30. The repo’s `latest_default_rates()` therefore returns the correct current map.

### 4.2 Dated-table differences (back-dated invoices)

| Repo value | Verified value | Instrument / evidence | Action |
|---|---|---|---|
| `("CZ", 20.0, (2020, 1, 1))` | **21.0 % from 2013-01-01** | Act No. 500/2012 Coll., eff. 2013-01-01, § 47(1)(a) 20→21; TEDB 21 % at 2016 floor; Act 349/2023 changed only § 47(1)(b) | **Delete the 20 % row; set the Czech row to `("CZ", 21.0, (2013, 1, 1))`.** A 2020–2023 invoice currently resolves 20 % and under-charges 1 pp. (The table’s documented 2020 floor means pre-2013 dates remain out of scope; the 2013 row makes 2013–2019 correct, and the resolver still returns 21 % for dates before 2013, which is outside the documented range.) |
| `("CZ", 21.0, (2024, 1, 1))` | 21.0 % from **2013-01-01** | same | **Correct the effective date to 2013-01-01** (or remove the duplicate row). The 2024 date is not a standard-rate change. |
| `("DE", 19.0, (2020, 1, 1))` only | 19 % 2020-01-01–2020-06-30; **16 % 2020-07-01–2020-12-31**; 19 % from 2021-01-01 | TEDB series: 2020-07-01 16.0, 2021-01-01 19.0 (COVID temporary rate) | **Add `("DE", 16.0, (2020, 7, 1))` and `("DE", 19.0, (2021, 1, 1))`.** H2-2020 invoices currently over-charge 3 pp. |
| `("IE", 23.0, (2020, 1, 1))` only | 23 % to 2020-08-31; **21 % 2020-09-01–2021-02-28**; 23 % from 2021-03-01 | TEDB series: 2020-09-01 21.0, 2021-03-01 23.0 (COVID temporary rate) | **Add `("IE", 21.0, (2020, 9, 1))` and `("IE", 23.0, (2021, 3, 1))`.** Invoices in that window currently over-charge 2 pp. |
| `("LU", 17.0, (2020, 1, 1))` only | 17 % to 2022-12-31; **16 % 2023-01-01–2023-12-31**; 17 % from 2024-01-01 | TEDB series: 2023-01-01 16.0, 2024-01-01 17.0 | **Add `("LU", 16.0, (2023, 1, 1))` and `("LU", 17.0, (2024, 1, 1))`.** 2023 invoices currently over-charge 1 pp. |
| `RO` 19 % → 21 % (2025-08-01) | Correct | TEDB; Law 141/2025; EY | No change |
| `EE` 20/22/24 (2024-01-01, 2025-07-01) | Correct | TEDB; EMTA | No change |
| `FI` 24 → 25.5 (2024-09-01) | Correct | TEDB; Vero | No change |
| `SK` 20 → 23 (2025-01-01) | Correct | TEDB; PwC | No change |
| All other 23 current rates | Correct | TEDB; PwC; TF | No change |

### 4.3 Comment/test differences (not current-rate bugs, but false statements)

| Location | Repo statement | Verified position | Action |
|---|---|---|---|
| `vat_rates.rs` lines 44–45 | “Czechia: 21 % is the standard rate since 2024-01-01 (20 % before).” | 21 % since 2013-01-01; 2024 changed only the reduced rate | Correct the comment |
| `vat_rates.rs` lines 45–47 | “Every other baseline is the rate in force on 2020-01-01” | True for all except Czechia (the 2020-01-01 rate was 21 %, not 20 %) | Correct after the CZ row fix |
| `vat_rates.rs` test `dated_rate_table_resolves_romania_and_the_recent_changes` | `get_eu_vat_rate_on("DE", d(1999, 1, 1)) == Some(19.0)` | Germany’s 1999 standard rate was **16 %** (19 % only from 2007-01-01); the assertion tests the 2020 floor, not history | Relabel as a floor-behaviour test, or change the date to 2020-06-30 if the intent is a true 19 % date |
| `docs/research/eu-vat-saas-practices.md` §6.1 (CZ row) and §6.2 (“Czechia 20 % → 21 %”) | 2024 standard-rate change | No 2024 standard-rate change; 21 % since 2013 | Correct the research memo (separate from this memo) |

### 4.4 What the repo does not need

- **No country is missing.** `DEFAULT_EU_COUNTRIES` has all 27, including GR (not EL).
- **No rate is missing for the current date.** `get_eu_vat_rate_on` resolves all 27.
- **No future change to add.** None identified as at 2026-10-30.
- **No fractional-rate defect.** Finland 25.5 % is stored and used unrounded; `vat_amount_half_up` handles tenths of a percent.
- **No Bulgaria change.** 20 % unchanged; the euro adoption is a currency/invoicing issue, not a rate-table row.

---

## 5. Sources (URLs; retrieved 2026-10-30 unless dated)

### Primary law
- **Directive 98/6/EC**, consolidated 28.05.2022, CELEX 01998L0006-20220528. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:01998L0006-20220528 (Arts. 1, 2(a), 3, 4, 5, 6a, 8–10.)
- **Directive 2011/83/EU**, consolidated 28.05.2022, CELEX 02011L0083-20220528. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02011L0083-20220528 (Art. 6(1)(e), Art. 8(2).)
- **Directive 2005/29/EC**, consolidated 28.05.2022, CELEX 02005L0029-20220528. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02005L0029-20220528 (Arts. 6(1)(d), 7(4)(c), Annex I point 20, points 23a–23c.)
- **Directive 2000/31/EC**, CELEX 32000L0031. https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32000L0031 (Art. 5(2).)

### Official Commission guidance and databases
- **Commission Guidance on the interpretation and application of Directive 2005/29/EC**, OJ C 526, 29.12.2021, CELEX 52021XC1229(05). https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:52021XC1229(05) (total price, Art. 7(4)(c), subscription omissions, net-price enforcement example.)
- **European Commission, VAT rates.** https://taxation-customs.ec.europa.eu/taxation/vat/vat-rates_en (framework; redirects to `/taxation/vat/vat-directive/vat-rates_en`).
- **European Commission, Taxes in Europe Database (TEDB), VAT retrieval SOAP service.** WSDL: https://ec.europa.eu/taxation_customs/tedb/ws/VatRetrievalService.wsdl; endpoint: https://ec.europa.eu/taxation_customs/tedb/ws/; operations: `retrieveVatRates` with `situationOn=2026-10-30` and `from=2014-01-01`/`to=2026-10-30`. The database is MS-populated and non-binding.
- **European Commission, “Bulgaria and the euro.”** https://commission.europa.eu/business-economy-euro/euro-area/euro/eu-countries-and-euro/bulgaria-and-euro_en (adoption 2026-01-01; €1 = 1.95583 BGN; dual display 2025-08-08–2026-08-08.)

### National authorities and legal instruments
- **EMTA (Estonia), Value added tax.** https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax (last updated 08.08.2025; “From 1 July 2025 … 24 % instead of 22 %.”)
- **Vero (Finland), Rates of VAT.** https://www.vero.fi/en/businesses-and-corporations/taxes-and-charges/vat/rates-of-vat/ (last updated 01.01.2026; “1 September 2024 the general VAT rate changed from 24 % to 25.5 %.”)
- **Czech VAT Act No. 235/2004 Coll., § 47.** https://www.zakonyprolidi.cz/cs/2004-235#p47 (current: 21 % standard, 12 % reduced.)
- **Czech Act No. 349/2023 Coll.** (consolidation, effective 2024-01-01). https://www.zakonyprolidi.cz/cs/2023-349 (Čl. LX, point 5: § 47(1)(b) 15 % → 12 %; standard untouched.)
- **Czech Act No. 500/2012 Coll.** (effective 2013-01-01). https://www.zakonyprolidi.cz/cs/2012-500 (§ 47(1)(a): 20 → 21.)
- **EUR-Lex national transposition measure for 98/6/EC — Estonia.** https://eur-lex.europa.eu/legal-content/EN/NIM/?uri=CELEX:31998L0006 (Estonia: *Tarbijakaitseseadus*, NIM:25290.)
- **EY Global Tax Alert, “Romanian tax changes introduced by new fiscal and budgetary measures,” 30 July 2025.** https://www.ey.com/en_gl/technical/tax-alerts/romanian-tax-changes-introduced-by-new-fiscal-and-budgetary-measures (“Starting from 1 August 2025, the standard VAT rate will increase from 19 % to 21 %.”)

### Trackers
- **PwC Worldwide Tax Summaries**, “Other taxes,” per country (last-reviewed dates: AT 23 Jul 2026; BE 10 Sep 2026; BG 02 Aug 2026; HR 27 Aug 2026; CY 04 Aug 2026; CZ 27 Jul 2026; DK 31 Jul 2026; EE 29 May 2026; FI 09 Sep 2026; FR 24 Apr 2026; DE 30 Jun 2026; GR 08 Sep 2026; HU 01 Jul 2026; IE 11 Aug 2026; IT 13 Jul 2026; LV 30 Jun 2026; LT 01 Oct 2026; LU 31 Jul 2026; MT 30 Sep 2026; NL 29 May 2026; PL 11 Aug 2026; PT 24 Jul 2026; RO 25 Sep 2026; SK 09 Sep 2026; SI 15 Jul 2026; ES 30 Jun 2026; SE 22 Sep 2026). Pattern: `https://taxsummaries.pwc.com/{country}/corporate/other-taxes`.
- **Tax Foundation, “VAT Rates in Europe, 2026,” published 26 January 2026, updated 27 January 2026.** https://taxfoundation.org/data/all/eu/value-added-tax-vat-rates-europe/

### Practitioner evidence (price-display convention)
- **Stripe, “Specify product tax codes and tax behavior.”** https://docs.stripe.com/tax/products-prices-tax-codes-tax-behavior (“Tax-inclusive prices are common for B2C sales in many markets outside the US … the amount your customer pays remains constant.”)
- **Paddle, “Do you support tax inclusive/exclusive pricing?”** https://www.paddle.com/help/sell/tax/do-you-support-tax-inclusiveexclusive-pricing (inclusive: “the price you’ve input will be the price the customer sees”; automatic location-based option.)

### Repository files inspected (no changes)
- `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server/crates/billing-common/src/vat_rates.rs` — `DEFAULT_VAT_RATE_PERIODS`, `VAT_RATE_PERIODS`, `get_eu_vat_rate_on`, `quote_consumer_gross`, `quote_list_price`.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/docs/research/eu-vat-saas-practices.md` — §3 (price display), §6 (rate table), §9 (sources).
- `/Users/sabelakhoua/IdeaProjects/ApexMail/apps/marketing-zola/templates/partials/pricing/plans.html` — pricing table and VAT-basis footnote.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/apps/marketing-zola/data/pricing.json` — net `monthly_price_display`, no `consumer_gross_display`.
- `/Users/sabelakhoua/IdeaProjects/ApexMail/apps/marketing-zola/data/i18n.json` — `pricing.vat_basis_business`, `vat_basis_consumer`, `vat_basis_note`, `vat_included_label` in de/fr/es.

---

## 6. What needs local counsel (not resolvable from the texts alone)

1. **Estonia:** whether the Consumer Protection Act applies the 98/6 price-indication duty to services (the Art. 3(2) carve-out), the exact section, and any Estonian-language requirement for consumer offers.
2. **Country-localised gross (Model ii):** the reliability of the country determination (IP geolocation vs billing address vs country selector) and the consumer-law risk of a wrong localisation. The legal rule is clear; the factual reliability is not.
3. **France/Belgium/Italy/Spain/Poland:** local-language and local price-display requirements for consumer offers; the four site languages do not cover all markets.
4. **Slovakia:** the exact act number and text of the consolidation package (Act No. 465/2024 Coll. is the tracker citation; not machine-verified).
5. **Bulgaria:** the post-euro invoice-content rules and any residual dual-display obligation for archived/auto-renewed offers; the EC page confirms the changeover dates, but the Bulgarian VAT invoicing rules are a national-law detail.
6. **Consumer vs business classification:** the self-declared business toggle without a VAT number is a commercial/controls decision; it also affects which price the consumer sees. This memo treats it as a pricing-control issue, not a rate issue.

---

*End of memo. No repository changes were made.*
