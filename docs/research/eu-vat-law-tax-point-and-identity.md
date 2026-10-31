# VATDEEP-A — Renewal tax points for recurring SaaS; VIES name/address mismatch as "information to the contrary"

**Prepared:** 31 October 2026. **Retrieval date for every source below: 31 October 2026** unless stated otherwise.
**Status:** research memo from primary law, official guidance and practitioner sources. Not legal or tax advice.
**No repository changes were made.** This memo builds on and goes deeper than
`docs/research/eu-vat-law-evidence-and-invoicing.md` (30 Oct 2026, angle 2), whose quotations are re-verified
here from the primary texts on the retrieval date.

**Scope.** Two of the five accountant-open items from the 30 Oct triple-law verification:
(1) the renewal tax point for recurring subscriptions (card vs SEPA Direct Debit; the date the invoice must
show; the rate at a mid-month change; re-validation cadence);
(2) the VIES name/address mismatch as "information to the contrary" (Reg 282/2011 Art 18): what the law
requires when the returned name/address disagrees with the declared one, Estonian penalty exposure, and a
recommended policy.

**Method — three-source discipline.** Each proposition carries its source classes:

| Tag | Source class | Instances used here |
|---|---|---|
| **[L]** | Primary law | VAT Directive 2006/112/EC consolidated 14.04.2025; Implementing Reg 282/2011 consolidated 01.07.2022; Council Reg 904/2010 (original OJ text); CJEU judgments; Estonian KMS and MKS current Estonian originals |
| **[G]** | Official administrative guidance | EMTA pages and rate-change examples; EC VIES FAQ; EC "Your Europe" VIES page; DG TAXUD explanatory notes (invoicing; e-commerce) |
| **[P]** | Independent practitioner / vendor | minuari.ee (Estonian practitioner advisory); vatnode.dev; vatvalidate.eu; tttarkvara.ee (accounting-software vendor); PwC Worldwide Tax Summaries (via 30 Oct memo) |

Conflicts are resolved by the primary text in the CONFLICT LIST at the end. Unreachable items are marked
**UNVERIFIED**. Retrieval limitations: EUR-Lex HTML is served through the Jina reader proxy (direct fetches
hit an AWS WAF challenge, as in the 30 Oct memo); Riigi Teataja's HTML front end is a JS SPA, so Estonian law
is taken from its public API XML; EMTA/EC pages fetched directly; some search engines captcha-blocked
plain fetches (browser rendering used where needed).

---

# SECTION 1 — Item 1: the renewal tax point for recurring subscriptions

## 1.1 Primary law — Directive 2006/112/EC, Arts 62–71 (verbatim, consolidated 14.04.2025)

The whole chargeable-event chapter was pulled and read. The operative provisions (S1):

**Art 62 (definitions):**
> "(1) 'chargeable event' shall mean the occurrence by virtue of which the legal conditions necessary for VAT to
> become chargeable are fulfilled; (2) VAT shall become 'chargeable' when the tax authority becomes entitled under
> the law, at a given moment, to claim the tax from the person liable to pay, even though the time of payment may
> be deferred."

**Art 63:**
> "The chargeable event shall occur and VAT shall become chargeable when the goods or the services are supplied."

**Art 64(1):**
> "Where it gives rise to successive statements of account or successive payments, the supply of goods, other than
> that consisting in the hire of goods for a certain period or the sale of goods on deferred terms, as referred to in
> point (b) of Article 14(2), or the supply of services shall be regarded as being completed on expiry of the periods
> to which such statements of account or payments relate."

**Art 64(2)** (marker ▼M9; three subparagraphs):
> "1st subpara: Continuous supplies of goods over a period of more than one calendar month which are dispatched or
> transported to a Member State other than that in which the dispatch or transport of those goods begins and which
> are supplied VAT-exempt … shall be regarded as being completed on expiry of each calendar month …
> **2nd subpara: Supplies of services for which VAT is payable by the customer pursuant to Article 196, which are
> supplied continuously over a period of more than one year and which do not give rise to statements of account or
> payments during that period, shall be regarded as being completed on expiry of each calendar year until such time
> as the supply of services comes to an end.**
> 3rd subpara: Member States may provide that, in certain cases other than those referred to in the first and second
> subparagraphs, the continuous supply of goods or services over a period of time is to be regarded as being
> completed at least at intervals of one year."

**Art 65:**
> "Where a payment is to be made on account before the goods or services are supplied, VAT shall become chargeable
> on receipt of the payment and on the amount received."

**Art 66:**
> "By way of derogation from Articles 63, 64 and 65, Member States may provide that VAT is to become chargeable, in
> respect of certain transactions or certain categories of taxable person at one of the following times: (a) no later
> than the time the invoice is issued; (b) no later than the time the payment is received; (c) where an invoice is not
> issued, or is issued late, within a specified time no later than on expiry of the time-limit for issue of invoices …
> **The derogation provided for in the first paragraph shall not, however, apply to supplies of services in respect of
> which VAT is payable by the customer pursuant to Article 196** and to supplies or transfers of goods referred to in
> Article 67."

**Arts 64a / 66a / 67 / 69 / 70 — scope check:**
- **There is no Article 64a in the current consolidated text** (checked 01.01.2025 and 14.04.2025
  consolidations; the chapter runs 62, 63, 64, 65, 66, 66a, 67, 68, 69, 70, 71). The brief's "Art 64a (goods on
  approval)" is a phantom citation (see conflicts A5). Irrelevant to SaaS either way.
- **Art 66a** (▼M24): chargeable event for goods deemed received/supplied under Art 14a, when payment is
  accepted — a goods/marketplace rule; irrelevant.
- **Art 67** disapplies Art 64(1), Art 64(2) third subpara and Art 65 for VAT-exempt intra-Community
  goods/own goods — a goods rule; irrelevant to services.
- **Art 68/69** (intra-Community acquisitions of goods: chargeable event / chargeable on invoice issue) and
  **Art 70/71** (importation) are goods chapters. The brief's "Art 69/70 (tax point where payments precede the
  invoice)" is a mis-citation (conflict A6): the provision where payments precede completion for **services** is
  **Art 65**, with Arts 220(4)–(5) and 226(7) as the invoicing consequences.

**Rate — Art 93:**
> "The rate applicable to taxable transactions shall be that in force at the time of the chargeable event.
> **However, in the following situations, the rate applicable shall be that in force when VAT becomes chargeable:
> (a) in the cases referred to in Articles 65 and 66;** (b) in the case of an intra-Community acquisition of goods;
> (c) in the cases, concerning the importation of goods …"

**Art 95:**
> "Where rates are changed, Member States may, in the cases referred to in Articles 65 and 66, effect adjustments in
> order to take account of the rate applying at the time when the goods or services were supplied. Member States may
> also adopt all appropriate transitional measures."

**Invoice dates — Art 220(1)(4)–(5) and Art 226(7):**
> Art 220(1): an invoice shall be issued in respect of "(4) any payment on account made to him before one of the
> supplies of goods referred to in points (1) and (2) was carried out; **(5) any payment on account made to him by
> another taxable person or non-taxable legal person before the provision of services was completed.**"
> Art 226(7): "the date on which the supply of goods or services was made or completed **or the date on which the
> payment on account referred to in points (4) and (5) of Article 220 was made, in so far as that date can be
> determined and differs from the date of issue of the invoice**".

*The 14.04.2025 consolidation is the current one (EUR-Lex "current consolidated version: 14/04/2025"); Arts
62–71 and 93 were diffed against the 01.01.2025 consolidation used in the 30 Oct memo and are identical.*

## 1.2 Primary law — Estonia, KMS §11 (current Estonian original)

The current Estonian consolidated KMS is version **130062026129**, in force **2026-10-01 – 2026-12-31**
(published RT I 2026, 30.06.2026), retrieved from the Riigi Teataja public API XML (S2). Verbatim:

**§ 11(1)** ("Käibe tekkimise, kauba importimise, teenuse saamise, kauba ühendusesisese soetamise ja internetipõhist
kauplemiskohta omava isiku poolt kauba soetamise aeg"):
> "Käive on tekkinud või teenus on saadud päeval, mil esimesena tehti üks alljärgnevaist toiminguist:
> 1) kauba ostjale lähetamine või kättesaadavaks tegemine või teenuse osutamine;
> 2) kauba või teenuse eest osalise või täieliku makse laekumine, teenuse saamisel osaline või täielik maksmine;
> 3) omatarbe puhul …"

*(Time of supply / receipt of services = the date on which the FIRST of the following is done: 1) dispatch or
making available of the goods or provision of the service; 2) receipt of full or partial payment for the goods or
services, or, on the receipt of services, the making of full or partial payment; 3) self-supply.)*

**§ 11(3):**
> "Kui käesoleva paragrahvi lõike 1 kohaselt on käibe tekkimise ajaks kauba või teenuse eest osalise või täieliku
> makse laekumine või maksmine, on käive tekkinud makstud osa ulatuses."

*(Where the time of supply is the receipt/making of payment, turnover arises to the extent of the amount paid —
the KMS twin of Art 65's "on the amount received".)*

**§ 11(4):**
> "Teenus, mille osutamine kestab kauem kui maksustamisperiood, loetakse osutatuks ja saaduks maksustamisperioodil,
> mil selle teenuse osutamine lõpeb. Samale ostjale teenuste osutamisel või kaupade regulaarsel võõrandamisel
> loetakse kauba ostjale lähetamise või kättesaadavaks tegemise või teenuse osutamise või saamise ajaks
> maksustamisperiood, mil lõpeb ajavahemik, mille kohta arve esitatakse või mille kestel saadud kaupade või
> teenuste eest tasumine on kokku lepitud, kuid mitte hiljem kui 12 kalendrikuu möödumisel. Kui teenust osutatakse
> pikema ajavahemiku jooksul kui üks aasta ja selle puhul tekib maksukohustus teenuse saajal, loetakse käive
> tekkinuks või teenus saaduks teenuse osutamise algusest arvates iga kalendriaasta 31. detsembril, kui selle
> perioodi jooksul ei ole teenuse eest tasutud ning selle osutamist ei ole lõpetatud."

*(Sentence 1: a service lasting longer than a taxation period is deemed provided/received in the taxation period in
which its provision ends. Sentence 2: for services to the same purchaser or regular supplies of goods, the time of
supply is deemed to be the taxation period at the end of which falls the period covered by the invoice or during
which payment is agreed, **but not later than after 12 calendar months**. Sentence 3: a reverse-charge service
supplied over more than one year, unpaid and uncompleted, is taxed at 31 December of each calendar year.)*

**Related Estonian provisions (same text, same retrieval):**
- **§ 15(1):** "Käibemaksumäär on 24 protsenti maksustatavast väärtusest …" (standard rate **24 %**; the 22→24
  change is RT I 2025-01-02, 2, in force 2025-07-01; before that 20→22 was in force 2024-01-01).
- **§ 37(1):** invoice within 7 calendar days of dispatch/provision "või käesoleva seaduse § 11 lõikes 4 nimetatud
  maksustamisperioodi viimasest päevast" (or from the last day of the § 11(4) taxation period).
- **§ 37(2):** "Kui käive tekib kauba või teenuse eest osalisel või täielikul makse laekumisel, tuleb arve väljastada
  seitsme kalendripäeva jooksul, arvates kauba või teenuse eest osalise või täieliku makse laekumise päevast."
  (Where turnover arises on receipt of full or partial payment, the invoice is due within 7 days **of the date of
  receipt of payment**.)
- **§ 37(2¹):** for intra-Community supplies and § 10(4) 9) services to a taxable person in another Member State,
  invoice by the 15th of the following month.
- **§ 37(7) 7):** "kauba väljastamise või teenuse osutamise kuupäev või kauba või teenuse eest osalise või täieliku
  makse laekumise kuupäev, kui see on kindlaksmääratav ja erineb arve väljastamise kuupäevast" — the date of
  dispatch/provision **or the date of receipt of payment, if determinable and different from the invoice date**.
- **§ 37(8) 2):** "kauba soetajal või teenuse saajal lasuva maksukohustuse puhul märge „pöördmaksustamine", kui
  käibe tekkimise koht ei ole Eesti ning käesoleva seaduse §-s 41¹ nimetatud juhtudel" — the reverse-charge note
  where the tax falls on the recipient and the place of supply is not Estonia, plus the § 41¹ domestic cases. The
  Estonian original says "place of supply is not Estonia" with **no goods-only limitation** (this closes the angle-2
  conflict C7: the EN translation's "place of supply of **goods**" is a translation artefact).

**EN-translation staleness (the brief's 20 % point).** Two English redactions exist in circulation and both are
stale versus the Estonian original: (a) redaction `511072022006` (in force 1 July 2022), used in the angle-1 memo,
still shows **20 %** — the brief's "the EN text still shows 20 %" is true of this redaction; (b) the newest EN
redaction located, `503012024001` (in force 2024-01-01 – 2024-12-31), shows **22 %**. The current Estonian
original shows **24 %** (§ 15(1)). Substantively, § 11(1), (3), (4) and § 37 are unchanged between the 2024 EN
redaction and the current ET text (compared word-for-word on the quoted parts); the divergences are the rate and
the § 37(8) 2) "goods" artefact. **Quote the Estonian original for anything money-bearing.**

## 1.3 The two readings against the text

The code "quotes the renewal VAT at the charge date"; the 30 Oct memo floats "Art 64(2) period expiry" as the
alternative. Walked against the texts:

1. **"Art 64(2) period expiry" is the wrong citation for monthly renewals.** Monthly SaaS billed monthly is
   "successive statements of account or successive payments" — that is **Art 64(1)** (each period's supply
   "completed on expiry of the periods to which such statements of account or payments relate"). Art 64(2) 2nd
   subpara is only the >1-year-continuous-reverse-charge-supply-with-no-statement-or-payment case (taxed at each
   calendar-year expiry); Art 64(2) 1st subpara is goods; Art 64(2) 3rd subpara is the member-state annual-interval
   option, which Estonia exercises through § 11(4)'s 12-month cap. Estonia's § 11(4) sentence 2 is the domestic
   twin of Art 64(1) (+ the 12-month cap): the deemed provision is "the taxation period at the end of which falls
   the invoiced/agreed period".
2. **Art 65 pulls the tax point earlier when payment is received before that completion.** "Where a payment is to
   be made on account before the goods or services are supplied, VAT shall become chargeable on receipt of the
   payment and on the amount received." For a periodic supply whose completion is deemed at period expiry (Art
   64(1)), a payment received during or before the period is a payment on account **before the supply is
   completed**; VAT becomes chargeable on receipt, for the amount received. Estonia codifies the interaction
   explicitly: § 11(1) takes "the first of" provision (§ 11(4) taxation period) and payment receipt; § 11(3)
   limits the tax to the amount paid.
3. **Art 93 second paragraph (a) settles the rate consequence of the advance-payment route:** for Arts 65/66
   cases the rate is the one in force **when VAT becomes chargeable** — i.e. at payment receipt, not at period
   end. A reading that always used period expiry would read Art 93(2)(a) and Art 65 out of the periodic-supply
   picture.
4. **The invoice moment is never the tax point.** EMTA's rate-change example 7 is flat: "Invoice is issued in June
   2025, goods are delivered and the invoice is paid in August 2025. **No supply is created from issuing an invoice
   alone.**" And Art 66's invoice-date derogation **cannot apply to Art 196 services** (final paragraph) — so
   neither Estonia nor any member state may move the reverse-charge service tax point to the invoice date. The
   code's phrase "the renewal invoice date" is wrong as a legal concept even where the invoice date happens to
   equal the true tax point.
5. **Where the directive genuinely admits both outcomes** — a payment received before period completion vs the
   completion date — the texts give the payment-date answer priority for the amount received (Art 65 + Art
   93(2)(a)), and Estonian law removes the ambiguity entirely (§ 11(1) "the first of"). For an Estonian OSS filer
   the payment-date (charge-date) reading is therefore not merely defensible but **required** for paid renewals;
   the period-expiry reading is the **fallback for unpaid periods** (Art 64(1); § 11(4)), not an alternative
   default.

## 1.4 The concrete cases

Notation: subscription period = the covered month (period end = its last day); the renewal invoice is issued at
period start "for the coming month"; the rate changes on day 15 of that month (hypothetical; Estonia's real
changes were on 1 January 2024 and 1 July 2025 — month boundaries — but OSS means customer-state mid-month
changes are live).

**Case A — card charged immediately at period start (charge settles same day as issue).**
- **Tax point [L]:** the date the payment is received = period start. Art 65 (payment on account before the
  service is supplied → VAT chargeable on receipt, for the amount received); KMS § 11(1) 2) + § 11(3) (first of
  provision/payment; turnover to the extent paid). Art 64(1)/§ 11(4) fixes only the **latest** alternative (period
  expiry), which never arrives because payment precedes it.
- **Rate [L][G][P]:** the rate in force at the payment date — Art 93 second para (a) ("the rate applicable shall be
  that in force when VAT becomes chargeable" in Art 65 cases); KMS § 15. EMTA: "The correct tax rate must be
  chosen on the basis of the time of supply", and example 5 ("If the full amount is paid in advance before 1 July
  2025, the supply is created in the month of receipt of the advance payment and the VAT rate applied is 22 %");
  example 2 (partial advance → advance at old rate, balance at the rate of its own tax point). Practitioner
  (minuari.ee): "Otsustav on käibe tekkimise kuupäev, mitte arve väljastamise kuupäev … Ettemaks laekunud juunis,
  kaup tarnitakse juulis → ettemaksult 22 %, järelmakselt 24 %." So at a day-15 rate change: **old rate**
  (charge date day 1 < day 15).
- **Invoice date to show [L][G]:** the tax-point date. Since it equals the issue date, Art 226(7)/KMS § 37(7) 7)
  require **no separate** date ("in so far as that date can be determined and differs from the date of issue"), but
  the invoice should still identify the covered period and the tax-point date as good practice (and the tax-point
  date must appear in the accounts, Art 242 / KMS § 36). Invoice timing: 7 days from the payment date (KMS
  § 37(2); § 37(2¹) allows the 15th of the following month for § 10(4) 9) services).

**Case B — SEPA Direct Debit, invoice issued at period start, funds settle days later (e.g. day 3), before period end.**
- **Tax point [L]:** the date the payment is **received** (funds booked/credited to the supplier's account) = the
  settlement date, not the mandate date, not the scheduled collection date, not the invoice date. Art 65 ("on
  receipt of the payment"); KMS § 11(1) 2) ("makse laekumine" — receipt of payment). It is still a payment on
  account before the deemed completion of the month's supply (Art 64(1)), so Art 65 applies as in Case A. (The
  SEPA Core DD payer-refund window is a payment-system feature; it does not move the VAT tax point — a later
  refund is a price adjustment under Art 90/credit note Art 219 / KMS § 37(4). **UNVERIFIED** at practitioner
  level for the DD-refund interaction specifically; the legal rule above is from the primary text.)
- **Rate [L][G][P]:** rate at the settlement date (Art 93(2)(a)). At a day-15 change with settlement day 3:
  **old rate**. If settlement slips to day 20 (retry) and that is still before period end, the tax point moves with
  it: **new rate** (the rate follows the actual receipt). If no payment is received by period end, the tax point is
  the period expiry (Case C).
- **Invoice date to show [L][G]:** the settlement date, "in so far as that date can be determined and differs from
  the date of issue" (Art 226(7); KMS § 37(7) 7)). Two workable implementations, both lawful: (i) issue after
  settlement — KMS § 37(2) gives 7 days from the payment receipt date, and the invoice then shows its tax point;
  (ii) issue at period start with the scheduled settlement date, and if actual settlement differs, record the actual
  tax point in the accounts and correct the document (credit note + re-invoice, Art 219 / KMS § 37(4)) where the
  difference changes the rate or the period shown. Do not leave a rate or date on the invoice that contradicts the
  tax point actually recorded.

**Case C — payment fails and is not collected before period end (dunning collects later, or never).**
- **Tax point [L]:** period expiry — the last day of the § 11(4) taxation period (Art 64(1) "completed on expiry of
  the periods"; KMS § 11(4) sentence 2; for invoicing the "last day of the taxable period" per KMS § 37(1)).
  A payment received afterwards is settlement of an already-chargeable supply, not an Art 65 advance (Art 65 is
  limited to payments made "before the goods or services are supplied").
- **Rate [L][G]:** rate in force at period expiry (Art 93 first para). At a day-15 change: **new rate**. EMTA
  example 5 scenario 1 confirms the pattern for multi-month periods: no prepayment → the whole period is taxed at
  the rate of the period-expiry month; example 7: a payment arriving with the delivery in July → July's rate and
  "the VAT rate indicated on the invoice must also be 24 %".
- **Invoice date to show:** the period-end (supply-completion) date — Art 226(7) first limb / KMS § 37(7) 7).

**Case D — multi-year reverse-charge contract, no interim statements/payments (the Art 64(2) 2nd subpara case).**
- Tax point = each **31 December** (Art 64(2) 2nd subpara; KMS § 11(4) sentence 3) until completion. Not the
  renewal case of ApexMail's monthly SaaS, but the correct citation if a prepaid multi-year enterprise deal ever
  bills nothing per period.

**Which rate, one table (rate change on day 15 of the covered month):**

| Case | Tax point | Rate at day-15 change |
|---|---|---|
| Card settled day 1 (= issue date) | day 1 (Art 65; § 11(1) 2)) | old rate (Art 93(2)(a)) |
| SEPA settled day 3 | day 3 (Art 65; § 11(1) 2)) | old rate (Art 93(2)(a)) |
| SEPA retried, settles day 20 | day 20 (Art 65) | new rate |
| No payment by period end | period end (Art 64(1); § 11(4)) | new rate (Art 93 first para) |
| Per-period invoicing of one long service (EMTA ex. 5, scenario 3) | each period's own completion | each period at its own rate |

**B2C/OSS vs B2B reverse charge.** For B2B Art 196 renewals the supplier's invoice carries no rate-driven VAT
(0 % treatment + "reverse charge" note, Art 226(11a); KMS § 37(8) 2)); the rate question resolves at the
customer's self-assessment in its own member state and tax point. The mid-month-change table bites for **B2C OSS
supplies** (destination rate at the tax point, Arts 58 + 93 + OSS) and domestic Estonian supplies (24 % at the tax
point, § 15(1)). The rate lookup date in the quote engine must therefore be the resolved tax point in all cases.

**Estonia and Art 95 (closing the angle-2 open item).** Estonia has exercised Art 95-style transitional measures
for its rate changes, but not a general Art 65 adjustment: (i) a time-limited grandfathering for written
long-term contracts fixing 20 % concluded before 1 May 2023 without a rate-change price clause (KMS § 46(25), as
applied per EMTA's 2024 examples); (ii) time-limited rules for cash-accounting (kassapõhine) users (KMS § 44
scheme). Ordinary advance payments keep the payment-date rate (EMTA examples 1–2, 4–5). The angle-2
"UNVERIFIED whether Estonia exercised Art 95" is thereby answered: **yes, selectively and time-limited; no
general adjustment for ordinary prepayments.**

## 1.5 Re-validation cadence (the brief's item 1.4)

- **What the law requires [L]:** Reg 282/2011 **Art 25**: "For the application of the rules governing the place of
  supply of services, **only the circumstances existing at the time of the chargeable event shall be taken into
  account.** Any subsequent changes to the use of the service received shall not affect the determination of the
  place of supply, provided there is no abusive practice." Each renewal period is its own chargeable event (Arts
  63/64/65), so the customer's status must be supportable **at that date**. The law prescribes an evidential
  result, not a query schedule: the general standard is good faith and "every step which could reasonably be asked"
  (C-273/11 Mecsek-Gabona ¶48), and no verification can be demanded absent material suggesting irregularity
  (C-324/11 Tóth, operative point 3; C-285/11 Bonik) — as set out in the angle-2 memo § 1.4.
- **What the confirmation can and cannot do [G]:** VIES FAQ Q6: "It is not possible to confirm the validity of a
  VAT number in the past. It is possible to do it only for the current day." Your Europe: "It is recommended that
  you keep track of your validation in case of tax control."
- **What practice does [P]:** vatnode.dev (16 Sep 2026): "A VAT ID checked once at purchase tells you the number
  was valid on that day. It says nothing about the day the next invoice is generated. For a subscription, that's a
  problem: every renewal is a new supply … hooking your own billing provider's renewal event and re-checking the
  VAT ID right before the next invoice is built … There's no EU rule that says how often you have to re-check.
  Cadence is a risk decision, made with a tax adviser, not a legal deadline. But the billing cycle is a natural
  place to hang that decision …"; vatnode.dev (17 Aug 2026) organises the moments as onboarding, **before
  applying reverse charge on an invoice** ("the trigger that carries the real compliance weight"), renewal, and a
  periodic sweep.
- **Verdict:** the legal minimum is evidence at each tax point (Art 25); re-validating **at each renewal / before
  each zero-rated invoice** is the market answer and the defensible default for ApexMail (it produces exactly the
  Art 25 evidence at the moment it is needed). Quarterly or annual re-checks are legal only if the supplier can
  still prove status at each tax point by other means; they are weaker, not forbidden. Keep the 90-day freshness
  bound only as a control on top of per-tax-point revalidation, never as the legal test (angle-2 memo § 2).

## 1.6 Propositions with three confirmations

**I1. Each renewal period of a monthly SaaS subscription is a separate supply completed at period expiry; the
tax point moves earlier to payment receipt when a payment is received before that completion.**
- [L] Art 63; Art 64(1); Art 65; KMS § 11(1) ("the first of"), § 11(3), § 11(4).
- [G] EMTA *Issuance of invoices* ("If the supply is created upon receipt of full or partial payment …, an invoice
  shall be issued within seven calendar days as of the date of receipt …" and the § 11(4) rule for regular
  services); EMTA rate-change examples 2, 5.
- [P] minuari.ee: "Otsustav on käibe tekkimise kuupäev, mitte arve väljastamise kuupäev. Käive tekib päeval, mil
  esimesena toimub kas kauba lähetamine, teenuse osutamine või osalise/täieliku makse laekumine."

**I2. For an advance payment (card or SEPA), the rate is the one in force at payment receipt, for the amount
received; the balance takes the rate of its own tax point.**
- [L] Art 65 ("on receipt of the payment and on the amount received"); Art 93 second para (a); KMS § 11(3), § 15.
- [G] EMTA examples 2 and 5 ("If the full amount is paid in advance before 1 July 2025, the supply is created in
  the month of receipt of the advance payment and the VAT rate applied is 22 %"); EMTA *Standard VAT rate*:
  "The correct tax rate must be chosen on the basis of the time of supply."
- [P] minuari.ee: "Ettemaks laekunud juunis, kaup tarnitakse juulis → ettemaksult 22 %, järelmakselt 24 %."

**I3. The invoice date is not a tax point; issuing an invoice alone creates no supply; the Art 66 invoice-date
derogation is unavailable for Art 196 services.**
- [L] Art 66 final paragraph; Art 226(7) keys on the supply/payment date, not the issue date.
- [G] EMTA example 7: "No supply is created from issuing an invoice alone."
- [P] minuari.ee (see I1); tttarkvara.ee's vendor default "rate = rate in force on the invoice date" is a software
  heuristic that only coincides with the law when invoice date = tax point (see conflicts A7).

**I4. The invoice must show the tax-point date — the payment date where Art 65 applies, otherwise the
supply-completion date — in so far as it is determinable and differs from the issue date.**
- [L] Art 226(7) with Art 220(1)(4)–(5); KMS § 37(7) 7) (verbatim above).
- [G] EMTA *Information included on invoices* handbook chapter (the same element list); EMTA *Issuance of
  invoices* (§ 37(2) seven-day rule from payment receipt).
- [P] minuari.ee (tax point, not invoice date). *Partially UNVERIFIED at Big-4 level; two classes satisfied.*

**I5. Continuous services spanning a rate change are split by tax points: prepayment keeps the old rate; unpaid
periods take the period-expiry rate; separately invoiced months take their own rates.**
- [L] Arts 64(1), 65, 93, 95; KMS § 11, § 15.
- [G] EMTA rate-change example 5 (all three scenarios) and examples 1–2, 4.
- [P] minuari.ee: "Kestva teenuse puhul (rent, abonement, hooldus) jagatakse arve perioodideks ja maksustatakse
  iga osa selle perioodi määraga."

**I6. For monthly-billed SaaS the period-expiry rule is Art 64(1) (plus § 11(4)), not Art 64(2); Art 64(2) 2nd
subpara is the >1-year-unbilled reverse-charge case (31 December tax points).**
- [L] Art 64(1)–(2) verbatim; KMS § 11(4) three sentences.
- [G] EMTA *Issuance of invoices* ("long-term services and goods sold on a regular basis … within seven calendar
  days from the last day of the taxable period specified in § 11 (4)").
- [P] vatnode.dev (each renewal is a new supply; per-invoice triggers). *Two classes + text; the practitioner leg
  is about cadence rather than the article number.*

**I7. Estonia's standard rate is 24 % (since 1 July 2025); the EN translations of the KMS are stale (20 % / 22 %).**
- [L] KMS § 15(1) (ET current): "Käibemaksumäär on 24 protsenti …"; RT I 2025-01-02, 2.
- [G] EMTA: "From 1 July 2025, the standard rate of VAT is 24 % in Estonia."
- [P] PwC Worldwide Tax Summaries (Estonia, 24 % standard rate, per the 30 Oct memo).

**I8. Re-validation cadence: the law requires status supportable at each tax point (Art 25), not a query
schedule; practice re-checks at each renewal/each zero-rated invoice and keeps the results.**
- [L] Reg 282/2011 Art 25; Arts 63–65; Mecsek ¶48; Tóth point 3.
- [G] VIES FAQ Q6 (current-day confirmation only); Your Europe ("keep track of your validation in case of tax
  control").
- [P] vatnode.dev (renewal trigger; "no EU rule that says how often you have to re-check … the billing cycle is a
  natural place to hang that decision").

---

# SECTION 2 — Item 2: VIES name/address mismatch as "information to the contrary"

## 2.1 Primary text again — Reg 282/2011 Art 18 and its anchors

**Art 18(1)(a)** (consolidated 01.07.2022, re-fetched 31 Oct 2026; identical to the 30 Oct quote):
> "Unless he has information to the contrary, the supplier may regard a customer established within the Community
> as a taxable person: (a) where the customer has communicated his individual VAT identification number to him, and
> **the supplier obtains confirmation of the validity of that identification number and of the associated name and
> address** in accordance with Article 31 of Council Regulation (EC) No 904/2010 …"

**Reg 904/2010 Art 31** (original OJ text; re-fetched 31 Oct 2026 — note para 2, omitted in the angle-2 memo):
> "1. The competent authorities of each Member State shall ensure that persons involved in the intra-Community
> supply of goods or of services … are allowed to obtain, for the purposes of such transactions, confirmation by
> electronic means of the validity of the VAT identification number of any specified person **as well as the
> associated name and address. This information shall correspond to the data referred to in Article 17.**
> 2. **Each Member State shall provide confirmation by electronic means of the name and address of the person to
> whom the VAT identification number has been issued in accordance with its national data protection rules.**"

Art 17(1)(b)–(c) (same regulation): member states hold "data on the identity, activity, legal form and address of
persons to whom it has issued a VAT identification number … as well as the date on which that number was issued;
(c) data on VAT identification numbers it has issued which have become invalid, and the dates on which those
numbers became invalid".

**Art 18(2) second subparagraph** (the TBE rule): "However, **irrespective of information to the contrary**, the
supplier of telecommunications, broadcasting or electronically supplied services may regard a customer established
within the Community as a non-taxable person **as long as that customer has not communicated his individual VAT
identification number to him.**"

**Art 25** (quoted in § 1.5 above): only circumstances at the time of the chargeable event count.

## 2.2 What "confirmation of the associated name and address" means operationally

The question: must the supplier **compare** the returned name/address with the declared one, or merely
**obtain** the confirmation?

- **The confirmation is an association check.** The authoritative plain-language statement is the EC's own
  "Your Europe" portal (S7): where VIES does not show the data, "you should request more information at national
  level with your national authorities. You should then be able to confirm: if the VAT number is valid or not; **if
  the VAT number is 'associated with' a certain name and address** … **Due to data protection, the national
  authorities will not supply the name and address corresponding to a VAT number. They will only confirm if there
  is a certain name and address associated with a specific VAT number or not.**" That is the data-protection
  implementation of Reg 904 Art 31(2): the confirmation product is a yes/no on the association of **the** name and
  address with the number. To ask "is number X associated with name/address Y?" you must have a Y — the
  customer's declared identity. A confirmation that is not matched to the declared identity does not confirm the
  association for this customer; it only confirms that *someone* is registered.
- **Some member states return the name/address through VIES.** VIES FAQ Q2: "Depending on the national rules on
  data protection, some Member States / Northern Ireland will also provide the name and address linked to the given
  VAT number as they are recorded in the national databases." FAQ Q17: "Certain Member States / Northern Ireland
  permit the display of the name and address of the taxable person where the VAT number is currently valid. If no
  name/address is displayed, this means that the relevant Member State / Northern Ireland does not permit the
  display of this data." FAQ Q22 (Spain): "the name, address and the type of company need to be entered together
  with the VAT number to be validated" — an explicit member-state matching procedure.
- **Operational reading (the memo's answer to the brief):** the supplier must (i) **obtain** the confirmation
  through the Art 31 service (the VIES query), and (ii) where the service returns a name/address, **treat the
  returned data as the register's answer to the association question** — i.e. compare it with the declared
  name/address and record the result. "Merely obtain" is not enough as a practical control, because the
  presumption in Art 18(1)(a) is defeasible ("Unless he has information to the contrary") and the returned
  name/address is exactly the information the article tells the supplier to obtain. Conversely, where the member
  state does not publish the data, the supplier has obtained what the service offers (FAQ Q17); the residual step
  is the national-authority association check (Your Europe) where the risk warrants it.
- **Practitioner leg [P]** (vatvalidate.eu): "A valid VAT result and a blank company name answer different
  questions … A blank name or address does not turn a valid result into an invalid one; **it also does not confirm
  that the VAT number belongs to the business named on your invoice.** … **Compare any returned name and address
  with your customer or supplier records. If details are missing or do not match, ask the business to confirm its
  VAT number and registered details.** Do not treat an empty field alone as proof of fraud. … If you still need
  confirmation, contact the relevant national tax authority. Your Europe explains that you can ask whether a
  specific name and address are associated with a VAT number. … **Keep a dated record of the check and the follow-up
  information.**" The same page distinguishes blank, unavailable and invalid results ("An unavailable result means
  the check did not obtain a validation answer. Keep that check unresolved and retry later; do not record it as
  invalid").
- Stripe (30 Oct memo, S16 of angle 2): the platform "only verifies the validity of the tax ID, and not whether
  the customer's name and address match what's on the customers page" — i.e. the market leaves the match to the
  merchant, which confirms the comparison step is a real, merchant-side duty rather than vendor boilerplate.

## 2.3 "Information to the contrary" — what counts, and what a mismatch is

**The chapeau is the operative condition.** Art 18(1) opens "Unless he has information to the contrary" — the
"may regard … as a taxable person" is a **presumption**, not a safe harbour. Art 19 shows the drafting pattern:
"Unless he has information to the contrary, **such as information on the nature of the services provided**, the
supplier may consider that the services are for the customer's business use …" — the drafters' example of contrary
information is an objective fact that contradicts the presumption's basis.

**Is a name/address mismatch "information to the contrary"?** Yes, on the text and structure:
1. The presumption's basis is that the communicated number identifies **the customer** as a taxable person. The
   Art 31 confirmation product is precisely the association of the number with **a name and address** (Reg 904
   Art 31(1)–(2); Your Europe). Returned register data naming a **different entity or a materially different
   address** is positive information that the number does not identify the declared customer — it contradicts the
   factual basis of the presumption, which is all "information to the contrary" requires (contrast Art 19's
   "such as" formulation).
2. A **blank** name/address (member state does not publish) is **not** contrary information — there is no
   information contradicting anything (FAQ Q17; vatvalidate.eu). Distinguish three states: match / mismatch /
   unavailable-data. Only mismatch (and invalid/outage) is contrary or absent evidence.
3. The Art 18(2) second subparagraph's "irrespective of information to the contrary" does **not** help where a
   number was communicated — its proviso is "as long as that customer has not communicated his individual VAT
   identification number" (angle-2 memo C4). A mismatched number is a communicated number; the ordinary
   defeasible presumption applies.

**What must the supplier do on receiving contrary information?** The presumption lapses; the supplier falls back
to the substantive question (is the customer a taxable person? Art 17; Reg 282 Arts 17, 20) and must establish it
by reasonable means, or treat the customer as non-taxable and charge VAT. The verification standard is the general
one: good faith and "every step which could reasonably be asked" (Mecsek ¶48; VSTR ¶52 — "acting in good faith
and having taken all the measures which can reasonably be required of him"), plus "normal commercial security
measures such as those relating to identity or payment checks" where Art 18(1)(b)/Art 20 logic applies. The EC
e-commerce explanatory notes (July 2026 revision) describe the same standard for due commercial care: "the CJEU
stressed that a trader should act in good faith and take every step which could reasonably be asked of him to
ensure that the transaction which he is carrying out does not result in tax evasion … the responsibility of the
taxable person is limited to what is a normal trader's due diligence (or due commercial care) in the course of his
business" (citing Santogal C-26/16 ¶71–72, Mecsek C-273/11 ¶48, LVK-56 C-643/11 ¶63, Netto Supermarkt C-271/06
¶24–27, Tóth C-324/11 ¶45).

**CJEU, precisely:**
- **C-273/11 Mecsek-Gabona (6 Sept 2012) — scope.** Operative part 1: exemption may be refused "provided that it
  has been established, on the basis of objective evidence, **that the vendor has failed to fulfil its obligations
  as regards evidence**, or that it knew or should have known that the transaction … was part of a tax fraud … and
  that it had not taken every reasonable step within its power to prevent its own participation in that fraud."
  Operative part 2: a vendor "may not be refused the VAT exemption … **solely on the ground that the tax authority
  of another Member State has removed the purchaser's VAT identification number from the register, with retroactive
  effect** from a date prior to the sale … even though the number was removed after the goods had been supplied."
  ¶48: "it is not contrary to European Union law to require an operator to act in good faith and to take every step
  which could reasonably be asked of it …". **Scope:** reliance protection runs to a supplier who **did** meet its
  evidence obligations and whose register evidence later turned out wrong (retroactive cancellation). It does not
  protect a supplier who ignored contrary information or never obtained the confirmation — that is the
  "failed to fulfil its obligations as regards evidence" limb of operative part 1. A name/address mismatch
  ignored at the time of the tax point falls on the wrong side of that line.
- **C-664/16 Vădan (21 Nov 2018)** — the case the brief means by "C-414/17 Vădan" (conflict A4). Operative part:
  "a taxable person who is unable to provide evidence of the amount of input VAT he has paid, by producing invoices
  or any other document, cannot benefit from a right to deduct VAT solely on the basis of an assessment resulting
  from an expert report commissioned by a national court." Relevance here: evidence discipline — documentary proof
  at the level of the specific transaction, burden on the taxable person; estimates and reconstructions do not
  replace the record.
- **C-414/17 is AREX CZ (19 Dec 2018)** — chain transactions with a single transport of excise goods; ¶77: "the
  chargeable event for VAT … is the supply or import of the goods, not the levying of excise duty". It says
  nothing about VAT-number reliance; do not cite it for this topic.
- Good-faith reliance generally: VSTR C-587/10 ¶52 (quoted in the angle-2 memo) remains the standard formula.

## 2.4 Consequences of reverse-charging on stale/mismatched evidence

**Who bears the tax.**
1. **If the customer is a taxable person in its member state** (number valid or not — validity is formal, VSTR
   ¶49–51): the supply is a B2B service taxable at the customer's establishment (Art 44) and **the customer owes
   the VAT under Art 196** in its own member state at its own tax point. The supplier's exposure is documentary
   and procedural: an Art 226(4)/(11a) invoice and a VD (recapitulative) entry with a number that may be rejected
   (Arts 262–264), and loss of the Art 18 presumption's comfort if the mismatch was ignored.
2. **If the customer is not a taxable person** (bogus number, consumer, fraud): Art 44 does not apply; for TBE
   services the supply is taxed at the customer's location (Art 58) and **the supplier owes the destination VAT**
   — for ApexMail through the **OSS Union scheme** (Arts 369a–369k; KMS § 43 special scheme). The mistaken 0 %
   is then an under-declaration of OSS VAT. The member state of identification (Estonia) administers and collects
   the OSS debt (Arts 369i–369j) — so the Estonian penalty regime is the operative one.
3. **If the supplier charges VAT that should not have been charged**, it owes that VAT anyway: KMS § 38(1) 2nd
   sentence — "Samas korras peab ta tasuma käibemaksusumma, mille ta on väljastatud arvele või muule
   müügidokumendile märkinud seaduses sätestatut eirates" (the Estonian Art 203 twin: VAT shown on an invoice
   contrary to law must be paid) — corrected only by credit note with specific reference (Art 219; KMS § 37(4)).

**Estonian penalty exposure [L][G].**
- **Interest on arrears:** the Taxation Act (maksukorralduse seadus, MKS) § 117(1): "Käesoleva seaduse §-des 115 ja
  116 sätestatud intressi määr on **0,06 protsenti päevas**" — 0.06 % per day (~21.9 % p.a.). EMTA confirms:
  "Until full payment of tax arrears, the arrears are subject to a daily interest rate of 0.06 per cent (i.e. 21.9%
  per year)" (interest from the day after the statutory due date; §§ 97, 118, 119 MKS for rounding and
  suspension).
- **Misdemeanour for understated tax on a return:** MKS § 153¹ "Maksukohustuse varjamine ja tagastusnõude alusetu
  suurendamine": "(1) Maksuhaldurile tahtlikult andmete esitamata jätmise või valeandmete esitamise eest, kui
  sellega vähendatakse maksu- või kinnipidamiskohustust või suurendatakse tagastusnõuet – karistatakse
  rahatrahviga kuni 300 trahviühikut. (2) Sama teo eest, kui selle on toime pannud juriidiline isik – karistatakse
  rahatrahviga **kuni 32 000 eurot**." — intentionally withholding or submitting false data reducing the tax
  liability: up to 300 fine units; for a **legal person up to EUR 32,000**. (Fine-unit EUR value set by the Penal
  Code — **UNVERIFIED** here; the legal-person figure is express and is the one that matters to ApexMail.)
- **Procedural misdemeanours:** MKS § 154: failure to submit a return/document by the deadline, breach of
  record-keeping requirements, failure to register etc.: up to 300 fine units / **up to EUR 3,200 for a legal
  person**. Limitation for §§ 153¹, 154, 154¹, 155¹–155³ misdemeanours: **3 years** (MKS).
- **Mirror-image recipient liability (for the accountant's file):** an Estonian-registered recipient owes VAT on
  services received from an unregistered foreign person where the place of supply is Estonia — KMS § 3(4) 2)
  ("teenustelt, mis on saadud ettevõtlusega tegelevalt välisriigi isikult, kes ei ole Eestis registreeritud
  maksukohustuslasena …") with the self-assessed amount deductible per the input-VAT rules (KMS § 29(1) 3));
  § 37(8) 2) then requires the "pöördmaksustamine" note. Failure to self-assess is the classic "incorrect reverse
  charge" exposure under §§ 153¹/154 + interest.
- **Due-diligence standard [G]:** the EC e-commerce notes (July 2026): the taxable person's responsibility "is
  limited to what is a normal trader's due diligence (or due commercial care) in the course of his business",
  with examples scaled to size and transaction volume (a documented, proportionate verification process is the
  benchmark).

## 2.5 Recommended policy

**What the law constrains.** (i) The presumption is available only with obtained confirmation of validity **and**
the associated name/address (Art 18(1)(a); Reg 904 Art 31); (ii) it is defeasible by information to the contrary
(the chapeau); (iii) status is judged at each chargeable event (Art 25); (iv) where the presumption fails and
taxable status cannot be established otherwise, destination VAT must be charged (FAQ Q3/Q20 logic; Art 58);
(v) records must evidence all of it (Arts 242/244/369k; KMS § 36). **What the law leaves open:** the exact
comparison tolerance (trading name vs legal name; address normalisation), whether to accept other proof of status
instead of failing closed, and the query cadence beyond "at the chargeable event".

**Concrete mismatch policy (recommended):**

| VIES result | Name/address | Action at the tax point |
|---|---|---|
| Valid | returned, **matches** declared | Reverse charge allowed; snapshot the response (raw + hash + timestamp + request id) and the comparison result |
| Valid | returned, **mismatches** declared | **Treat as "information to the contrary". Do not auto-apply reverse charge.** Contact the customer to reconcile the legal name/address or the number; re-check VIES after correction. If unresolved at the tax point, **charge destination VAT** (fail closed) — or, as an explicit documented override, accept a customer attestation + registry extract and keep it on file as the Art 18(1)(b)-style "other proof". Never silently ignore. |
| Valid | **not published** (MS policy, FAQ Q17) | Not contrary information by itself. Proceed, but record "association not published by MS" and, for high-value/high-risk customers, take the Your Europe national-authority association check ("is this name and address associated with this number?") |
| Invalid | — | No presumption; charge VAT unless other proof of taxable status exists (Art 17/18(1)(b) logic; VSTR ¶52) |
| Outage / unavailable | — | No confirmation obtained; retry; treat like invalid for the decision, but record it as "unresolved outage", not "invalid" (vatvalidate.eu; FAQ Q14/Q20) |

**Cadence.** Re-validate at **each renewal / before each zero-rated invoice** (per § 1.5: Art 25 evidential result;
vatnode practice). Optionally add a periodic sweep (monthly/quarterly) to catch drift between renewals. Re-check
immediately whenever the customer's declared name/address or number changes.

**Documentation standard.** Per customer and per tax point: the customer declaration (name, address, number,
business status, terms version, timestamp); the raw VIES response (name/address as returned, valid/invalid,
request reference, response hash, consultation timestamp); the comparison result (match/mismatch/unavailable);
any contrary information and its resolution; the tax point the evidence supports; and the decision taken. Retain
per Art 242/244 + KMS § 36(1) 1) (7 years) and Art 369k(2) (10 years for OSS transactions) — 10 years in
practice. Your Europe: "It is recommended that you keep track of your validation in case of tax control."

## 2.6 Propositions with three confirmations

**II1. Art 18(1)(a) requires confirmation of validity AND of the associated name and address via the Reg 904
Art 31 service; the name/address limb is a real limb of the presumption.**
- [L] Reg 282 Art 18(1)(a); Reg 904 Art 31(1)–(2) ("as well as the associated name and address … shall correspond
  to the data referred to in Article 17"; member states "shall provide confirmation … of the name and address").
- [G] VIES FAQ Q2/Q17 (name/address returned where national data-protection rules permit); Your Europe ("confirm
  … if the VAT number is 'associated with' a certain name and address").
- [P] vatvalidate.eu ("it also does not confirm that the VAT number belongs to the business named on your
  invoice"); Stripe (platform does not match name/address — merchant must).

**II2. A name/address returned by VIES that disagrees with the declared one is "information to the contrary" and
defeats the Art 18(1)(a) presumption until resolved; a blank name/address is not.**
- [L] Art 18 chapeau; Art 19 ("such as information on the nature of the services provided"); Reg 904 Art 31(1)
  (the confirmation product is the association).
- [G] Your Europe (association confirmation; national authorities "will only confirm if there is a certain name and
  address associated with a specific VAT number or not"); FAQ Q17 (blank = member state does not display).
- [P] vatvalidate.eu ("Compare any returned name and address with your customer or supplier records. If details
  are missing or do not match, ask the business to confirm its VAT number and registered details. Do not treat an
  empty field alone as proof of fraud.").

**II3. On contrary information the supplier must verify or charge VAT; the due-diligence standard is good faith
plus every step reasonably asked, proportionate to the business.**
- [L] Art 18 chapeau + Art 17/20; Mecsek ¶48 and operative part 1 ("failed to fulfil its obligations as regards
  evidence"); VSTR ¶52.
- [G] EC e-commerce explanatory notes (July 2026) on due commercial care (quote in § 2.3); VIES FAQ Q3/Q20.
- [P] vatvalidate.eu (steps 2–4: compare → ask the business → national authority → keep dated records).

**II4. Mecsek protects reliance on register evidence that was valid when obtained and later cancelled
retroactively; it does not protect ignoring contrary information or never checking.**
- [L] C-273/11 operative parts 1–2 (quoted in § 2.3).
- [G] EC e-commerce notes cite Mecsek ¶48 as the due-diligence standard.
- [P] vatnode.dev ("A VAT validation is a snapshot … It is not a standing certificate, and it does not renew
  itself") — the practitioner framing of the same limit.

**II5. Where the supplier reverse-charges on bad evidence and the customer is not a taxable person, the supplier
bears the destination VAT through the OSS return, collected by Estonia as member state of identification.**
- [L] Arts 58, 196, 369d/369i–369j; KMS § 43 (special scheme); KMS § 38(1) (VAT wrongly shown must be paid).
- [G] EC OSS guidance via the OSS portal's Explanatory Notes/Guidelines (July 2026 revisions, on file from
  vat-one-stop-shop.ec.europa.eu); EMTA OSS handbook chapter.
- [P] **UNVERIFIED** at practitioner level on the specific OSS-assessment path; two classes satisfied.

**II6. Estonian exposure on an understated return: interest at 0.06 %/day plus a misdemeanour fine of up to EUR
32,000 (legal person) for false/incomplete data reducing tax, and up to EUR 3,200 for late/missing returns.**
- [L] MKS §§ 115–117 (interest 0.06 %/day), § 153¹ (up to EUR 32,000), § 154 (up to EUR 3,200); KMS § 38(1).
- [G] EMTA *Payment of interests* ("the arrears are subject to a daily interest rate of 0.06 per cent (i.e. 21.9%
  per year)").
- [P] **UNVERIFIED** (Big-4 commentary not retrieved on the specific figures); two classes satisfied.

**II7. Records: keep the association evidence itself — returned name/address, comparison result, consultation
provenance — not just "valid: true".**
- [L] Arts 242/244/369k(2); KMS § 36(1) 1); Art 18(1)(a) (the thing to evidence is the confirmation of validity
  **and** association).
- [G] Your Europe ("keep track of your validation in case of tax control").
- [P] vatvalidate.eu ("Keep a dated record of the check and the follow-up information").

**II8. Re-validation cadence for the mismatch control: per tax point (each renewal), with the comparison re-run
whenever the declaration changes.** (Sources as I8.)

---

# CONFLICT LIST (primary text quoted where sources disagree)

**A1. "Art 64(2) period expiry" is the wrong citation for monthly renewals.**
The 30 Oct memo floats Art 64(2) as the alternative reading. Primary text: Art 64(1) is the successive-statements
rule ("the supply of services shall be regarded as being completed on expiry of the periods to which such
statements of account or payments relate"); Art 64(2) 2nd subpara is the >1-year-continuous-unbilled Art 196 case
("on expiry of each calendar year"); Art 64(2) 3rd subpara is the member-state annual-interval option. **Resolution:
cite Art 64(1) (+ KMS § 11(4)) for monthly renewals; cite Art 64(2) 2nd subpara only for >1-year unbilled
reverse-charge supplies.** The code/PDF comment "the deemed supply date for the continuous period (Art. 64(2)/226(7))"
should read Art 64(1).

**A2. "Charge date = the invoice moment" conflates three dates.**
Primary text: the invoice moment is not a tax point (EMTA example 7: "No supply is created from issuing an invoice
alone"); Art 66's invoice-date option "shall not … apply to supplies of services in respect of which VAT is payable
by the customer pursuant to Article 196"; the tax point is payment receipt (Art 65; § 11(1) 2)) or period completion
(Art 64(1); § 11(4)). **Resolution: tax point = payment-settlement date when received before period end, else
period end; the invoice date is only the issue date (Art 226(1)), and the tax point must be printed when it
differs (Art 226(7); § 37(7) 7)).**

**A3. The brief's "Art 69/70 (tax point where payments precede the invoice)" is a mis-citation.**
Primary text: Arts 68–69 are the intra-Community-acquisition-of-goods chapter ("VAT shall become chargeable on
issue of the invoice" for **IC acquisitions of goods**); Art 70 is importation. The services advance-payment
provision is **Art 65** with Arts 220(1)(4)–(5) and 226(7). **Resolution: cite Art 65.**

**A4. "C-414/17 Vădan" merges two different cases.**
C-414/17 is **AREX CZ a.s. v Odvolací finanční ředitelství** (19 Dec 2018 — chain transactions, single transport,
excise goods). **Vădan is C-664/16** (Lucreţiu Hadrian Vădan v ANAF, 21 Nov 2018 — evidence of input VAT; expert
report insufficient). **Resolution: cite C-664/16 Vădan for the evidence-burden proposition; drop C-414/17 from
this topic.**

**A5. "Art 64a (goods on approval)" does not exist in the current consolidated VAT Directive.**
Checked both the 01.01.2025 and 14.04.2025 consolidations: the chapter runs Arts 62, 63, 64, 65, 66, **66a**, 67,
68, 69, 70, 71. The nearest insertion, Art 66a (▼M24), is the deemed-supplier goods rule (Art 14a chains) and is
irrelevant to SaaS. **Resolution: drop "Art 64a"; irrelevance confirmed regardless.**

**A6. "Working Paper 860" could not be verified.**
Exact-phrase searches ("working paper 860" + VAT/VAT Committee/Reg 282/2011) via Bing, Google and DuckDuckGo
plus EUR-Lex browsing on 31 Oct 2026 surfaced no VAT Committee document with that number. **UNVERIFIED — treat
the number as unconfirmed and do not cite it.** What the "2013 guidance" line probably refers to is the DG TAXUD
"Explanatory Notes — VAT invoicing rules (Council Directive 2010/45/EU)" (created/last edited 05/10/2011,
published on the Commission's taxation website in 2013; retrieved here as `explanatory_notes_en.pdf`) — but those
notes cover sequential numbering, "Cash accounting" (Art 226(7a)), the exemption reference (226(11)) and currency,
and **do not address Art 18**. The Art 18-adjacent official guidance verified for this memo is the VIES FAQ, the
"Your Europe" VIES page, and the e-commerce explanatory notes.

**A7. Vendor software default "rate = rate in force on the invoice date" (tttarkvara.ee transition PDF) conflicts
with Art 93.**
Primary text: the rate is the one in force at the chargeable event, or — in Art 65/66 cases — "when VAT becomes
chargeable" (Art 93). EMTA: "The correct tax rate must be chosen on the basis of the time of supply"; example 7
("the VAT rate indicated on the invoice must also be" the tax-point rate). The vendor default coincides with the
law only where invoice date = tax point. minuari.ee states the correct rule ("Otsustav on käibe tekkimise
kuupäev, mitte arve väljastamise kuupäev"). **Resolution: rate lookup at the resolved tax point; invoice-date
heuristics are not law.**

**A8. EN translations of the KMS are stale (the brief's "20 %" note).**
Redaction 511072022006 (1 July 2022) shows 20 %; redaction 503012024001 (2024) shows 22 %; the current Estonian
original (130062026129, in force 2026-10-01) shows 24 % (§ 15(1)). Also, EN § 37(8) 2) says "place of supply of
**goods** is not Estonia" where the Estonian original says "käibe tekkimise koht ei ole Eesti" (place of supply is
not Estonia) with no goods limitation — closing angle-2 conflict C7. **Resolution: cite the Estonian original for
rates and the reverse-charge note; use the EN text only for orientation.**

**A9. The 2021 e-commerce explanatory notes have been revised.**
The brief's "2021 EC e-commerce guidance" is now published as "Explanatory Notes on VAT e-commerce rules", DG
TAXUD, **published July 2026**, covering Directive (EU) 2025/516 (ViDA) changes as from entry into force and on
1/1/2027 (the 2020 draft is on file as `vatecommerceexplanatory_notes_28102020`). Its "information to the
contrary" passages concern the Art 5d deemed-supplier presumption, not Art 18(1)(a); its due-diligence standard
(Mecsek ¶48 line) is general. **Resolution: cite the current revision; do not attribute an Art 18 name/address
rule to it.**

**A10. The angle-2 memo's open item "whether Estonia exercised Art 95" is now answered.**
Estonia used selective, time-limited transitional measures (KMS § 46(25) grandfathering of pre-1-May-2023 written
long-term contracts at a fixed 20 %; transitional rules for cash-accounting users), but no general Art 65
adjustment: advance payments keep the payment-date rate (EMTA examples 1–2, 4–5). **Resolution: close the item as
"exercised selectively; ordinary prepayments unadjusted".**

**A11. Stripe's format-only reverse-charge posture (angle-2 C9) remains non-conformant with Art 18(1)(a) and is
reinforced by the name/address analysis.** Format checks neither confirm validity nor association. Keep the
repo's evidence-based gate; add the comparison step per § 2.5.

**A12. The angle-2 memo's practitioner legs for tax points and re-validation were UNVERIFIED; they are now
filled** by minuari.ee (tax point/rate change for prepayments and continuous services) and vatnode.dev (renewal
re-validation cadence). The remaining UNVERIFIED practitioner legs are the SEPA-refund tax-point interaction
(II/§1.4) and Big-4 commentary on the Estonian fine figures (II6).

---

# CODE-READY ANSWERS

## Item 1 — the renewal tax point

**The single defensible answer:** For a monthly SaaS renewal the tax point is **the date the payment is received
when payment is received before the end of the covered period, and otherwise the last day of that period**. The
invoice date is never the tax point. The VAT rate (B2C/OSS and domestic) is the rate in force **at that tax point**
— for advance payments Art 93(2)(a) makes the payment-receipt date the rate date. The invoice must show that
tax-point date whenever it is determinable and differs from the issue date (Art 226(7); KMS § 37(7) 7)).

Sentences for code comments / the policy doc:

> `// TAX POINT (Directive 2006/112/EC Arts 63, 64(1), 65; KMS § 11(1),(3),(4)):`
> `// the chargeable event for a monthly renewal is the earlier of (a) receipt of the`
> `// payment (card settlement / SEPA Direct Debit settlement = date funds are received) and`
> `// (b) completion of the covered period (its last day). If no payment is received by`
> `// period end, the tax point is the period-end date. The invoice ISSUE DATE is not a`
> `// tax point (EMTA: "No supply is created from issuing an invoice alone"; Art 66's`
> `// invoice-date option does not apply to Art 196 services).`
>
> `// RATE (Art 93; Art 93(2)(a) for Art 65 advance payments; KMS § 15): look up the dated`
> `// rate table at the resolved TAX POINT, not at invoice generation. A rate change mid-`
> `// period re-rates only tax points on/after the change: prepayments before the change`
> `// keep the old rate for the amount paid; unpaid periods take the period-end rate.`
>
> `// INVOICE (Art 226(7) / Art 220(1)(5); KMS § 37(7) 7): print the tax-point date — the`
> `// payment-settlement date where Art 65 applies, else the supply-completion date — when`
> `// it is determinable and differs from the issue date. Period-expiry citations for`
> `// monthly billing are Art 64(1) + KMS § 11(4) (Art 64(2) is the >1-year unbilled case).`

**Where the law leaves a policy choice:** the treatment of late settlement straddling a rate change (correct the
document vs record-only) and whether to issue after settlement (KMS § 37(2) 7-day window) or before. Recommend:
resolve the tax point at settlement time and correct any invoice whose printed rate/date contradicts it (credit
note + re-invoice, Art 219 / KMS § 37(4)); for SEPA Direct Debit prefer issuing within the § 37(2) window after
settlement so the invoice face shows the true tax point.

## Item 1.4 — re-validation cadence

> `// EVIDENCE AT EACH TAX POINT (Reg 282/2011 Art 25: "only the circumstances existing at`
> `// the time of the chargeable event"): each renewal is its own chargeable event. The law`
> `// sets an evidential result, not a query schedule (Mecsek C-273/11 ¶48; Tóth C-324/11).`
> `// Policy: re-validate the VIES number (and the name/address comparison) at every`
> `// renewal, immediately before each zero-rated invoice. The 90-day freshness bound stays`
> `// as an internal control, never as the legal test.`

## Item 2 — the VIES name/address mismatch

**The single defensible answer:** Art 18(1)(a) requires confirmation of the validity of the number **and of the
associated name and address**. Where the VIES/national response returns a name or address that disagrees with the
declared one, the supplier has **not** obtained confirmation of the association and additionally holds
**"information to the contrary"** within the Art 18 chapeau: the presumption to treat the customer as a taxable
person is defeated until the discrepancy is resolved. A blank name/address (member state does not publish) is not
contrary information. If the discrepancy is unresolved at the tax point and taxable status cannot be established
otherwise, charge destination VAT.

Sentences for code comments / the policy doc:

> `// ART 18(1)(a) VIES EVIDENCE: valid-number AND associated-name/address confirmation.
> `// COMPARE the returned name/address with the customer's declared name/address and
> `// store the result (match / mismatch / not-returned). A MISMATCH is "information to
> `// the contrary" (Art 18 chapeau; Reg 904/2010 Art 31 confirms the number↔name/address
> `// association): do NOT auto-apply reverse charge; reconcile with the customer and
> `// re-check; if unresolved at the tax point, charge VAT (or hold a documented,
> `// reviewed override as "other proof" of status). A BLANK return (member state does not
> `// publish — VIES FAQ Q17) is not contrary information: proceed and log the limitation.
> `// Keep per tax point: raw response + hash + timestamp + request ref, the compared
> `// declared identity, the match result, any contrary information and its resolution
> `// (Arts 242/244/369k; KMS § 36; "keep track of your validation in case of tax control").`

**Consequences sentence (for the policy doc):**

> If the supplier reverse-charges on stale or mismatched evidence and the customer is not a taxable person, the
> destination VAT is owed by the supplier through the OSS return and is collected by Estonia as member state of
> identification: unpaid OSS VAT draws interest at 0.06 %/day (MKS § 117) and false or incomplete return data
> reducing tax is a misdemeanour punishable by a fine of up to EUR 32,000 for a legal person (MKS § 153¹; up to
> EUR 3,200 for late or missing returns under § 154). VAT wrongly shown on an invoice must be paid regardless
> (KMS § 38(1)).

**Where the law leaves a policy choice:** comparison tolerance (legal name vs trading name; address
normalisation), whether to accept customer attestations/registry extracts as "other proof" instead of failing
closed, and the cadence beyond "at each chargeable event". Recommend: normalise + exact-legal-name match as the
default (warn on trading-name-only differences), fail closed on entity-level mismatches with a documented
override path owned by the accountant, and per-renewal revalidation as the cadence.

---

# SOURCES

| ID | Source | URL / locator | Retrieved |
|---|---|---|---|
| S1 | Council Directive 2006/112/EC, consolidated 14.04.2025 (CELEX 02006L0112-20250414) — Arts 62–71, 93–95, 220, 226 (diffed against 01.01.2025 consolidation: identical) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02006L0112-20250414 (via r.jina.ai) | 31 Oct 2026 |
| S2 | Estonian VAT Act (KMS), current Estonian consolidated original, version 130062026129, in force 2026-10-01 – 2026-12-31 — §§ 3(4), 11, 15, 29(1), 36–38, 41¹, 43 | https://www.riigiteataja.ee/public-api/api/v1/akt/130062026129/xml | 31 Oct 2026 |
| S3 | KMS English translation, redaction 503012024001 (in force 2024-01-01 – 2024-12-31) — staleness check (shows 22 %) | https://www.riigiteataja.ee/public-api/api/v1/en/akt/503012024001/xml | 31 Oct 2026 |
| S4 | KMS English translation, redaction 511072022006 (1 July 2022) — "20 %" staleness cited in the brief (angle-1 memo, /tmp/vat-law-a.md) | https://www.riigiteataja.ee/en/eli/ee/511072022006/consolide/current | as cited (30 Oct 2026 memo) |
| S5 | EMTA (Estonian Tax and Customs Board): *Standard VAT rate* + *Examples of taxation related to the VAT rate change from 1 July 2025*; *Issuance of invoices*; *Payment of interests* | https://www.emta.ee/en/business-client/taxes-and-payment/value-added-tax (+ /vat-rates-and-supply-exempt-tax/standard-vat-rate; /vat-accounting-and-invoices/issuance-invoices; /payment-arrears/payment-interests) | 31 Oct 2026 |
| S6 | European Commission, VIES FAQ (Q2, Q3, Q6, Q7, Q14, Q17, Q20, Q22) | https://ec.europa.eu/taxation_customs/vies/faq.html (via r.jina.ai) | 31 Oct 2026 |
| S7 | European Commission, Your Europe: *Check a VAT number (VIES)* ("associated with a certain name and address"; "keep track of your validation") | https://europa.eu/youreurope/business/finance-and-tax/vat/check-vat-number-vies/index_en.htm | 31 Oct 2026 |
| S8 | Implementing Regulation (EU) No 282/2011, consolidated 01.07.2022 — Arts 18, 19, 20, 24f, 25 | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02011R0282-20220701 (via r.jina.ai) | 31 Oct 2026 |
| S9 | Council Regulation (EU) No 904/2010 (original OJ text) — Art 31(1)–(2), Art 17(1) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32010R0904 (via r.jina.ai) | 31 Oct 2026 |
| S10 | CJEU C-273/11 Mecsek-Gabona (6 Sept 2012) — ¶48, operative parts 1–2 | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62011CJ0273 | 31 Oct 2026 |
| S11 | CJEU C-664/16 Vădan (21 Nov 2018) — operative part | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62016CJ0664 | 31 Oct 2026 |
| S12 | CJEU C-414/17 AREX CZ (19 Dec 2018) — mis-citation check (¶77) | https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62017CJ0414 | 31 Oct 2026 |
| S13 | DG TAXUD, *Explanatory Notes — VAT invoicing rules (Council Directive 2010/45/EU)* (the "2013 guidance") | https://taxation-customs.ec.europa.eu/document/download/12dc566c-9f43-49d9-a306-b706879104ba_en?filename=explanatory_notes_en.pdf | 31 Oct 2026 |
| S14 | DG TAXUD, *Explanatory Notes on VAT e-commerce rules*, published July 2026 (incl. ViDA changes; the revision of the 2021 notes) + OSS Guidelines (1 Jan 2027 revisions) | https://vat-one-stop-shop.ec.europa.eu/document/download/774b31ca-03c6-4fb1-8209-9e447aeeb1e9_en (and /55f4ec9d-… OSS Guidelines) | 31 Oct 2026 |
| S15 | Estonian Taxation Act (MKS), current version 116102026010 — §§ 115–117 (interest 0.06 %/day), 153¹, 154 | https://www.riigiteataja.ee/public-api/api/v1/akt/116102026010/xml | 31 Oct 2026 |
| S16 | minuari.ee, *Käibemaksu tõus 2025: 22% → 24% — mida ettevõtja peab teadma* (Estonian practitioner advisory) | https://minuari.ee/kalkulaatorid/kaibemaks-2025 | 31 Oct 2026 |
| S17 | vatnode.dev, *Validate VAT Numbers on Subscription Renewal, Not Purchase* (16 Sep 2026); *When to Validate a Customer's VAT Number* (17 Aug 2026) | https://vatnode.dev/blog/vat-validation-subscription-renewals ; /blog/when-to-validate-customer-vat-numbers | 31 Oct 2026 |
| S18 | vatvalidate.eu, *VIES name and address missing: what does a valid VAT result mean?* | https://vatvalidate.eu/vies-name-address | 31 Oct 2026 |
| S19 | tttarkvara.ee, *Uuele käibemaksumäärale üleminek 1. juuli 2025* (accounting-software transition guide; invoice-date rate default) | https://www.tttarkvara.ee/RP/juhendid/Uuele_kaibemaksumaarale_uleminek_2025.pdf | 31 Oct 2026 |
| S20 | PwC Worldwide Tax Summaries, Estonia (24 % standard rate) — via the 30 Oct 2026 memo | https://taxsummaries.pwc.com/estonia/corporate/other-taxes | as cited (29 May 2026 review) |
| S21 | Stripe Tax documentation (tax-ID handling; no name/address match) — via the 30 Oct 2026 memo | https://docs.stripe.com/tax/tax-ids | as cited (30 Oct 2026) |

**Search coverage for UNVERIFIED items:** "Working Paper 860" — exact-phrase searches on Bing, Google and
DuckDuckGo (plus EUR-Lex browsing), 31 Oct 2026, no hit; treat as unconfirmed. Estonian fine-unit EUR value —
not retrieved (the legal-person fines are express EUR amounts). SEPA Direct Debit refund-window/VAT interaction —
no practitioner source retrieved; the legal rule (receipt = settlement) is from S1/S2.

*End of memo. No repository changes were made.*
