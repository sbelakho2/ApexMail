# VATDEEP-B — e-arve 1.2 elements for the reverse-charge reference, supply date/period and per-rate VAT summary; customer fixed establishments (Art 44 second limb)

Research memo for the two remaining accountant-open items of the 30 Oct 2026 triple-law verification
(`docs/research/eu-vat-legal-verification-2026-10-30.md`). Companion to
`docs/research/eu-vat-law-evidence-and-invoicing.md` (which recorded the F2 gap: the e-arve XML carries
no reverse-charge note and no supply date; and the FE open item). NO repository changes were made.

**All retrievals in this memo: 2026-10-31.** Three-source discipline per proposition: primary text +
official guidance + practitioner, with quotes of operative sentences. UNVERIFIED marks where a source
could not be obtained.

---

# ITEM 3 — The Estonian e-arve 1.2 schema: where the statutory reference, supply date and per-rate VAT summary belong

## 3.1 The actual schema was found (the chain of custody)

The e-arve standard is **owned by the Estonian IT and Telecommunications Association (ITL)** since 2019
(after the Estonian Banking Association / Pangaliit handed it over); Pangaliit's own page links to ITL.

| Source class | What was retrieved (2026-10-31) | Where |
|---|---|---|
| Official | Pangaliit e-arve page: "Täpsem teave e-arve standardi kohta on leitav Eesti Infotehnoloogia ja Telekommunikatsiooni Liidu (ITL) koduleheküljelt" ("More detailed information about the e-arve standard can be found on the ITL website") + bank-sending guides (Ver 1.05 / 1.0, EST + ENG) | https://www.pangaliit.ee/arveldused/e-arve |
| Official (custodian) | ITL "Eesti e-arve" page: standard description **Ver 1.2** and **Ver 1.1** + `EE_einvoice_1.2.zip`; English description "Description of Estonian e-invoice, Version 1.2, 01.12.2013"; and the IoB-project **v1.2.EN** package (description + `e-invoice_ver1.2.EN.xsd` + EN/CII/PEPPOL syntax bindings) | https://www.itl.ee/e-arve-kirjeldus/ ; downloads on https://wp.itl.ee/files/… |
| Official (file set) | `EE_einvoice_1.2.zip` contains `e-invoice_ver1.2.xsd` (header comment: "Schema version: 1.2, Schema date: 01.12.2013, License rules: no"), plus official sample instances `EARVE_1.2_all_fields.xml` and `EARVE_1.2_mandatory_fields.xml`. The 52-page description lists the working group: **Ministry of Finance, Ministry of Economic Affairs, Bank of Estonia, Maksu- ja Tolliamet (EMTA), Estonian Banking Association, RIA** + banks Swedbank/SEB/Nordea + operators Telema, Eesti Post, Krediidiinfo, OpusCapita. | downloaded to /tmp/vatresearch/itl/ |
| Corroboration (independent copies) | `internetee/e_invoice` Ruby gem ("Implements Estonian e-invoice standard v1.2"; README resource link = pangaliit.ee/arveldused/e-arve) ships `test/xml_schemas/v1.2.xsd` — **byte-identical** (modulo line endings) to the official ITL XSD. `thorgate/estonian_e_invoice` (Python) validation schema lists the same elements (DocumentName required, PayDueDate, VATRate/VATSum/SumBeforeVAT, TotalToPay/TotalVATSum). `sp19hub/freeEarve` (C#), `itsbalamurali/balticum` (Rust), `Fitek-Global/fitek_ai` model docs also implement InvoiceSumGroup/VATRecord. | github.com (GitHub code search) |
| Official (statutory mark) | EMTA handbook "Käibemaksuarvestus ja arved" chapters "Arvele märgitavad andmed" / "Arvele märgitavad viited" / "Muud viited ja märkused" (page last updated 19.08.2026) | https://emta.ee/ariklient/maksud-ja-tasumine/kaibemaks/kaibemaksuarvestus-ja-arved/… |

Retrieval note: web.archive.org was **offline on 2026-10-31** ("Internet Archive services are temporarily
offline"), so the Wayback fallback could not be exercised. Not needed: the live ITL custodian page carries
the full version history and the original 2013 description PDF/XSD. **UNVERIFIED (retrieval limitation):
archived pangaliit.ee pre-2019 pages.**

## 3.2 Does 1.3 exist? What changed? What to target?

**No e-arve 1.3 exists.** Version history of the official description (title page + history table):

| Date | Version | Note |
|---|---|---|
| 01/12/2009 | 1.1 | "Update of Estonian e-invoice description" (Andres Lilleste) |
| 01/12/2013 | 1.2 | "Update of Estonian e-invoice description" — **current local norm** |
| 28/08/2018 | 1.2.EN | "Update based on EVS-EN 16931-1:2017 (EU invoice standard)" — **document status: draft**; an EN extension carried *inside* the 1.2 structure via `ExtensionRecord/CustomContent` (IoB project 2018) |

The "e-invoice_ver1.11.xsd" inside `EE_einvoice_1.11_and_bank_files.zip` is **not** a successor: its header
says "Estonian e-invoice description with attributes for AATT service … New attributes: present and
invoiceGlobUniqId; Schema version: 1.11; Schema date: 01.11.2012" — a bank-transport variant of 1.1 for
the AATT service, predating 1.2. ITL's page (custodian since 2019) lists only Ver 1.1, Ver 1.2 and the
v1.2.EN mapping. Bing/DuckDuckGo/Google searches for "e-arve 1.3" returned nothing. **Conclusion: the
brief's "1.3 if it exists" — it does not; there is nothing newer than 1.2 for the local format.**

What to target for a new export:

- **Target e-arve 1.2** for the bank/operator channel (Omniva etc.) — that is what the e-invoice standard
  prescribes and what receiving banks present.
- The forward path is **EN 16931**: ITL quotes the Accounting Act (RPS) § 7¹(7): "eeldatakse, et Eestis on
  e-arve vormistatud nõuetekohaselt, kui see vastab e-arveldamise Euroopa standardile EN 16931-1. Samas
  võivad pooled kokku leppida ka muu asjakohase standardi kasutamises." (an Estonian e-invoice is presumed
  properly issued if it conforms to EN 16931-1; parties may agree another suitable standard — the most
  common being the Estonian local e-invoice norm). The **v1.2.EN** variant (with mapping docs to the EN
  semantic model, UN/CEFACT CII and PEPPOL BIS3 UBL) is the bridge. A pragmatic exporter emits **1.2
  base + the EN extension blocks in `CustomContent`** (see snippets), which is exactly how ITL designed it.

## 3.3 The exact elements (from the official XSD + the official description, quotable)

All element order below is the XSD `xs:sequence` order. Types: `NormalTextType` = max 100 chars,
`ShortTextType` = max 20, `LongTextSingleType` = 1–500 (Description), `LongTextType` = max 500
(InformationContent), `PaymentDescriptionType` = max 210, `DateType` = xs:date.

### (a) Invoice-level free-text note (the reverse-charge reference)

There is **no dedicated reverse-charge element** in e-arve 1.2 (no flag, no "VATReverseCharge", no
"märkus" field). The designed carriers, in order of fit:

1. **`Invoice/AdditionalInformation`** (type `ExtensionRecord`, 0..unbounded) — the description (§ 2.9)
   says: *"AdditionalInformation element describes additional information on the invoice. For example
   information related to marketing messages and service terms"* and the tag table: *"Additional
   information which is shown on the invoice."* Structure: optional `InformationName` (NormalTextType),
   **mandatory `InformationContent`** (LongTextType, 500 chars), optional `CustomContent` (contains
   `xs:any` — the formal extension point), attribute `extensionId` (ShortTextType, optional).
2. `InvoiceInformation/InvoiceContentText` (NormalTextType, optional) — "Description about the invoice
   content" (100 chars).
3. `InvoiceInformation/DocumentName` — **mandatory** in 1.2 ("Name of the document (ex: invoice, credit
   invoice, waybill etc)"); the repo's XML currently omits it entirely (see conflicts).
4. `PaymentInfo/PaymentDescription` (210 chars) — but its purpose is the payment ("Invoice 2026-000042"),
   not invoice content; the choice group requires PaymentDescription or PaymentRefId.
5. `ItemEntry/Description` (per line, 500 chars) — a per-line free text, visible in bank presentation;
   the docs do **not** instruct exporters to use it as the invoice note (so "extend the item description"
   is *not* the documented answer — `AdditionalInformation` is).

Official samples use `extensionId="ShortText"` on AdditionalInformation. (The description PDF's § 2.9
example shows `id="Note"` — an attribute name inconsistent with its own XSD; the XSD and the official
samples use `extensionId`. See conflict C8.)

### (b) Supply date / service period

There is **no "ServiceDate", "SupplyDate" or "DateOfSupply" element** in e-arve 1.2 (verified against the
full XSD element list). The designed carrier:

- **`InvoiceInformation/Period`** (optional): `PeriodName` (NormalTextType, opt.), `StartDate`
  (DateType, opt.), `EndDate` (DateType, opt.). Description § 2.6: *"If invoice concerns some kind of
  period-related service – for example energy consumption on given period, then the period can be
  specified."* Example in the official description: `<Period><PeriodName>Teenuse osutamise periood</PeriodName><StartDate>2009-11-01</StartDate><EndDate>2009-11-30</EndDate></Period>`.
- For the Art 226(7) statement ("date of supply … if it differs from the date of issue") there is no
  dedicated slot; the practical encoding is `Period` (for continuous services the Art 64(2) deemed date is
  the period's last day = `EndDate`) plus an explicit sentence in `AdditionalInformation` /
  `InvoiceContentText`. **"Date of supply" is genuinely NOT representable as its own element in e-arve 1.2.**
- Per-line periods do not exist in plain 1.2 `ItemEntry` either (only `Description` free text).
- The **v1.2.EN** extension adds exactly these missing semantics inside `CustomContent`:
  - `InvoiceInformationEN/VATPointDate` (`VATPointDate` + `VATPointDateCode` (UNTDID 2005; mutually
    exclusive)) — description: *"The date when the VAT becomes accountable for the Seller and for the
    Buyer in so far as that date can be determined and differs from the date of issue of the invoice,
    according to the VAT directive"* — i.e. the Art 226(7) tax-point date;
  - `InvoiceInformationEN/ActualDeliveryDate` (EN 16931 BT-72-style actual supply date);
  - `ItemEntryEN/Period` (per-line period).

### (c) Per-rate VAT summary

**`InvoiceSumGroup/VAT`** (type `VATRecord`, **0..unbounded**) — the official description § 2.7 states
verbatim: *"VAT … Describes value-added tax. See VATRecord for details. **Invoice must have as many VAT
blocks as there are different VATRate values.** Value is equal to InvoiceItemGroup/ItemEntry/VAT amounts
based on VAT rates."* VATRecord structure (order fixed):

- `SumBeforeVAT` (Decimal4FractionDigitsType, opt.) — "Amount from which the VAT is calculated"
- `VATRate` (**mandatory**, Decimal2FractionDigitsType) — "VAT rate"
- `VATSum` (**mandatory**, Decimal4FractionDigitsType) — "VAT amount"
- `Currency` (opt.), `SumAfterVAT` (opt.) — "Amount with VAT amount"
- `Reference` (ExtensionRecord, opt.) — the v1.2.EN variant hangs `VATEN` here
- attribute `vatId` (optional): `NOTTAX` – not taxable; `TAXEX` – tax exemption; `TAX` – taxable

Then `TotalVATSum` ("Total of all VAT sums", opt.), `TotalSum` (**mandatory**), `TotalToPay` ("Amount to
be paid. Credit invoice must have 0.00 – negative amount does not correspond to the Estonian
legislation", opt.), `Currency`, `Accounting`, `Extension`.

`InvoiceSumGroup` itself has `maxOccurs="2"`; per-line `ItemEntry` carries a single `VAT` (VATRecord).

### (d) Confirmed parent structures (order-critical)

- Root `E_Invoice`: `Header`, `Invoice` (1..n), **`Footer`** (`TotalNumberInvoices`, `TotalAmount`) — the
  Footer is **mandatory**; the repo's XML omits it.
- `Invoice` mandatory attributes: **`invoiceId`, `regNumber`, `sellerRegnumber`** (plus optional
  `serviceId`, `channelId`, `channelAddress`, `factoring`, `templateId`, `languageId`, `presentment`,
  `invoiceGlobUniqId`, `sellerContractId`). The repo's XML has no attributes at all.
- `Invoice`: `InvoiceParties`, `InvoiceInformation`, `InvoiceSumGroup` (max 2), `InvoiceItem`,
  `AdditionalInformation`* (0..n), `AttachmentFile`?, `PaymentInfo`.
- `InvoiceInformation`: `Type` (attribute name is lowercase **`type`**, values `DEB`/`CRE`; optional
  `SourceInvoice` child), `FactorContractNumber`?, `ContractNumber`?, **`DocumentName` (mandatory)**,
  `InvoiceNumber` (mandatory), `InvoiceContentCode`?, `InvoiceContentText`?, `PaymentReferenceNumber`?,
  `PaymentMethod`?, `InvoiceDate` (mandatory), `DueDate`?, `PaymentTerm`?, `FineRatePerDay`?, `Period`?,
  `InvoiceDeliverer`?, `Extension`*.
- `InvoiceItem`: `InvoiceTotalGroup`? / **`InvoiceItemGroup` (1..n, each holding `ItemEntry`+)** /
  `InvoiceItemTotalGroup`?. `ItemEntry` order: `RowNo`?, `SerialNumber`?, …, `Description` (**mandatory**),
  …, `ItemDetailInfo`* (`ItemUnit`?/`ItemAmount`?/`ItemPrice`?), `ItemSum`? (a **decimal**, not a complex
  type), `Addition`*, `VAT`?, `ItemTotal`?.
- `PaymentInfo`: `Currency`, then the choice (`PaymentDescription` | `PaymentRefId` + `PaymentDescription`),
  `Payable`, **`PayDueDate`** (not "DueDate"!), `PaymentTotalSum`, `PayerName`, `PaymentId`,
  `PayToAccount`, `PayToName`, `PayToBIC`?, …

### (e) The statutory mark itself (what the note must say)

- Primary: Directive Art 226(11a): *"where the customer is liable for the payment of the VAT, the mention
  'Reverse charge'"*.
- National: KMS § 37(8)2) (English consolidated text, quoted in the companion memo): the reference
  "reverse charge" where the recipient is liable.
- Official guidance (EMTA, "Muud viited ja märkused", updated 19.08.2026, retrieved 2026-10-31): *"Kui
  käive kuulub pöördmaksustamisele, siis märgitakse arvele „pöördmaksustamine“ sõltumata sellest, kas
  tegemist on maksuvaba käibega või maksustatakse käivet 0% määraga"* — if the supply is subject to reverse
  charge, the invoice is marked **„pöördmaksustamine"** regardless of whether it is exempt or 0%-rated.
  And: for exemptions/0% (except where „pöördmaksustamine" is required) the KMS/Directive reference may be
  replaced by "another clear and unambiguous marking" — for reverse charge the mark is mandatory and fixed.
  EMTA's services table maps KMS § 10(4)9) B2B-to-another-MS services to "Pöördmaksustamine, ingl reverse
  charge".
- So the note text to render: **"Pöördmaksustamine / Reverse charge — käibemaksu tasub saaja (KMS § 37 lg 8
  p 2; direktiivi 2006/112/EÜ art 226 lg 11a)"**. The KMS § 37(7) data list (EMTA "Arvele märgitavad
  andmed", updated 20.05.2026) also confirms the two other items this memo covers: *"kauba väljastamise
  või teenuse osutamise kuupäev … kui see on kindlaksmääratav ja erineb arve väljastamise kuupäevast"*
  (supply date if determinable and different from issue date) and *"maksustatav summa käibemaksumäärade
  kaupa koos kohaldatavate käibemaksumääradega"* (taxable amount **per VAT rate** with the rates applied).

## 3.4 EXACT XML SNIPPETS (conformant to `e-invoice_ver1.2.xsd`, order-correct)

**Namespace finding (important).** The official XSD declares **no `targetNamespace`** and the official
sample instances root as `<E_Invoice xsi:noNamespaceSchemaLocation="e-invoice_ver1.2.xsd"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` — the format is **no-namespace**. The
`internetee/e_invoice` generator emits the same root. The repo's `<E_Invoice xmlns="http://www.pangaliit.ee/e-arve/e-arve">`
therefore **cannot be validated against the official `e-invoice_ver1.2.xsd`** (demonstrated: xmllint reports
"No matching global declaration available for the validation root"). Whether specific banks' importers also
accept the namespaced dialect is **UNVERIFIED**; the snippets below use the official form.

Both snippets below were **validated with `xmllint --schema e-invoice_ver1.2.xsd` against the official ITL
XSD on 2026-10-31: VALID.** (Order rules caught in validation: in `ContactDataRecord`, `E-mailAddress`
comes **before** `LegalAddress` — the repo's current renderer has them the other way round.)

### Snippet A — reverse-charge B2B invoice (note + period), Estonian supplier → EU business customer

```xml
<?xml version="1.0" encoding="UTF-8"?>
<E_Invoice xsi:noNamespaceSchemaLocation="e-invoice_ver1.2.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Header>
    <Date>2026-10-31</Date>
    <FileId>INV-2026-000042</FileId>
    <Version>1.2</Version>
  </Header>
  <!-- invoiceId / regNumber / sellerRegnumber are REQUIRED attributes -->
  <Invoice invoiceId="INV-2026-000042" regNumber="12345678" sellerRegnumber="12345678">
    <InvoiceParties>
      <!-- SellerParty / BuyerParty as today (BuyerParty/VATRegNumber = the number
           under which the service is received, Art 226(4)). ContactData order:
           PhoneNumber?, FaxNumber?, URL?, E-mailAddress?, THEN LegalAddress?, MailAddress? -->
    </InvoiceParties>
    <InvoiceInformation>
      <Type type="DEB"/>                                  <!-- attribute is lowercase "type" -->
      <DocumentName>Arve</DocumentName>                   <!-- MANDATORY in 1.2 -->
      <InvoiceNumber>2026-000042</InvoiceNumber>
      <InvoiceContentCode>SERVICES</InvoiceContentCode>
      <InvoiceContentText>Pöördmaksustamine — käibemaksu tasub saaja</InvoiceContentText>
      <InvoiceDate>2026-10-31</InvoiceDate>
      <DueDate>2026-11-14</DueDate>
      <Period>
        <PeriodName>Teenuse osutamise periood</PeriodName>
        <StartDate>2026-10-01</StartDate>
        <EndDate>2026-10-31</EndDate>
      </Period>
      <!-- "Date of supply" has NO dedicated element in 1.2; state it explicitly
           (Art 226(7); KMS § 37 lg 7): -->
      <Extension extensionId="SupplyDate">
        <InformationName>Teenuse osutamise kuupäev</InformationName>
        <InformationContent>2026-10-31 (perioodi viimane päev, direktiivi 2006/112/EÜ art 64 lg 2)</InformationContent>
      </Extension>
    </InvoiceInformation>
    <InvoiceSumGroup>
      <InvoiceSum>100.00</InvoiceSum>
      <!-- ONE VAT block per distinct VATRate (spec § 2.7) -->
      <VAT vatId="TAX">
        <SumBeforeVAT>100.00</SumBeforeVAT>
        <VATRate>0.00</VATRate>
        <VATSum>0.00</VATSum>
        <Currency>EUR</Currency>
        <SumAfterVAT>100.00</SumAfterVAT>
      </VAT>
      <TotalVATSum>0.00</TotalVATSum>
      <TotalSum>100.00</TotalSum>
      <TotalToPay>100.00</TotalToPay>
      <Currency>EUR</Currency>
    </InvoiceSumGroup>
    <InvoiceItem>
      <InvoiceItemGroup>                                  <!-- ItemEntry must be wrapped -->
        <ItemEntry>
          <RowNo>1</RowNo>
          <Description>ApexMail SaaS subscription 2026-10</Description>
          <ItemDetailInfo>
            <ItemUnit>MON</ItemUnit>
            <ItemAmount>1.0000</ItemAmount>
            <ItemPrice>100.0000</ItemPrice>
          </ItemDetailInfo>
          <ItemSum>100.0000</ItemSum>                     <!-- ItemSum is a DECIMAL -->
          <VAT vatId="TAX">
            <SumBeforeVAT>100.0000</SumBeforeVAT>
            <VATRate>0.00</VATRate>
            <VATSum>0.0000</VATSum>
            <Currency>EUR</Currency>
            <SumAfterVAT>100.0000</SumAfterVAT>
          </VAT>
          <ItemTotal>100.0000</ItemTotal>
        </ItemEntry>
      </InvoiceItemGroup>
    </InvoiceItem>
    <!-- The Art 226(11a) / KMS § 37 lg 8 mark lives here: -->
    <AdditionalInformation extensionId="ReverseCharge">
      <InformationName>Pöördmaksustamine</InformationName>
      <InformationContent>Reverse charge — VAT is payable by the recipient. Käibemaksu tasub saaja (KMS § 37 lg 8 p 2; direktiivi 2006/112/EÜ art 226 lg 11a).</InformationContent>
    </AdditionalInformation>
    <PaymentInfo>
      <Currency>EUR</Currency>
      <PaymentDescription>Invoice 2026-000042</PaymentDescription>
      <Payable>YES</Payable>
      <PayDueDate>2026-11-14</PayDueDate>                 <!-- PayDueDate, not DueDate -->
      <PaymentTotalSum>100.00</PaymentTotalSum>
      <PayerName>Customer GmbH</PayerName>
      <PaymentId>2026-000042</PaymentId>
      <PayToAccount>EE381010220123456789</PayToAccount>
      <PayToName>ApexMail OÜ</PayToName>
    </PaymentInfo>
  </Invoice>
  <Footer>
    <TotalNumberInvoices>1</TotalNumberInvoices>
    <TotalAmount>100.00</TotalAmount>
  </Footer>
</E_Invoice>
```

Notes on conventions the schema leaves open (marked, not invented):
- `vatId` for the reverse-charge line: `TAX` + `VATRate 0.00` is the accurate encoding (KMS § 15(4)(1)
  applies a **0 % rate to a taxable** out-of-scope-of-EE-tax supply; it is not an exemption). Some
  exporters use `NOTTAX`; the spec does not prescribe either for reverse charge. **Convention — decide and
  document.** The mandatory, non-optional part is the `AdditionalInformation` mark (EMTA).
- If maximum visibility in bank presentation matters, repeat the mark in `InvoiceContentText` (shown
  above) and/or the first `ItemEntry/Description`; which receiving banks render `AdditionalInformation`
  blocks is **UNVERIFIED** (per-bank presentation).

### Snippet B — consumer VAT-inclusive invoice: per-rate VAT summary (Art 226(8); KMS § 37 lg 7)

```xml
    <InvoiceSumGroup>
      <InvoiceSum>110.00</InvoiceSum>
      <!-- as many VAT blocks as there are different VATRate values (spec § 2.7) -->
      <VAT vatId="TAX">
        <SumBeforeVAT>100.00</SumBeforeVAT>
        <VATRate>24.00</VATRate>
        <VATSum>24.00</VATSum>
        <Currency>EUR</Currency>
        <SumAfterVAT>124.00</SumAfterVAT>
      </VAT>
      <VAT vatId="TAX">
        <SumBeforeVAT>10.00</SumBeforeVAT>
        <VATRate>9.00</VATRate>
        <VATSum>0.90</VATSum>
        <Currency>EUR</Currency>
        <SumAfterVAT>10.90</SumAfterVAT>
      </VAT>
      <TotalVATSum>24.90</TotalVATSum>
      <TotalSum>134.90</TotalSum>
      <TotalToPay>134.90</TotalToPay>
      <Currency>EUR</Currency>
    </InvoiceSumGroup>
```

(For a single-rate EE consumer invoice there is exactly one VAT block, 24.00.)

### Snippet C — the v1.2.EN extension (only if the receiver is EN-aware; goes inside the 1.2 structure)

```xml
    <!-- inside InvoiceInformation, after Period: -->
    <Extension extensionId="InvoiceInformationEN">
      <InformationContent>EN 16931 extension block</InformationContent>
      <CustomContent>
        <InvoiceInformationEN>
          <InvoiceTypeCode>380</InvoiceTypeCode>
          <VATPointDate>
            <VATPointDate>2026-10-31</VATPointDate>
            <!-- or, if the date is unknown at issue:
            <VATPointDateCode>13</VATPointDateCode>   (UNTDID 2005 codes; use is mutually exclusive) -->
          </VATPointDate>
          <ActualDeliveryDate>2026-10-31</ActualDeliveryDate>
          <InvoiceNote>
            <Note>Pöördmaksustamine / Reverse charge — käibemaksu tasub saaja (Art 226(11a))</Note>
          </InvoiceNote>
        </InvoiceInformationEN>
      </CustomContent>
    </Extension>

    <!-- inside each InvoiceSumGroup VAT block, in VAT/Reference: -->
    <VAT vatId="TAX">
      <SumBeforeVAT>100.00</SumBeforeVAT>
      <VATRate>0.00</VATRate>
      <VATSum>0.00</VATSum>
      <Currency>EUR</Currency>
      <SumAfterVAT>100.00</SumAfterVAT>
      <Reference extensionId="VATEN">
        <InformationContent>EN VAT category extension</InformationContent>
        <CustomContent>
          <VATEN>
            <CategoryCode>AE</CategoryCode>
            <ExemptionReasonText>Reverse charge — VAT payable by the recipient (Directive 2006/112/EC Art 226(11a))</ExemptionReasonText>
          </VATEN>
        </CustomContent>
      </Reference>
    </VAT>
```

The v1.2.EN description ties `ExemptionReasonText` to the statute explicitly: *"A textual statement of the
reason why the amount is exempted from VAT or why no VAT is being charged. **Articles 226 items 11 to 15
Directive 2006/112/EN** [sic — EC]."* — the range that contains Art 226(11a). `CategoryCode` values come
from UNTDID 5305 ("AE" = VAT reverse charge per EN 16931 practice; **UNVERIFIED as to the code list
itself** — the e-arve EN description only says "Entries from UNTDID 5305 should be used").

## 3.5 Where the schema genuinely lacks an element — and what to do

| Statutory item | e-arve 1.2 status | What exporters do / what we should do |
|---|---|---|
| Art 226(11a) "Reverse charge" mention | **No dedicated element.** Free-text only | `AdditionalInformation` (spec-sanctioned: "additional information which is shown on the invoice") + mirror in `InvoiceContentText`. Do NOT invent a custom element outside `CustomContent`. In v1.2.EN: `VATEN/ExemptionReasonText` (+ `InvoiceNote`). |
| Art 226(7) date of supply (when ≠ issue date) | **Not representable as a dedicated element.** | `InvoiceInformation/Period` (StartDate/EndDate; EndDate = Art 64(2) deemed date for continuous supply) + explicit sentence in `AdditionalInformation`. In v1.2.EN: `VATPointDate` / `ActualDeliveryDate`. Per line: only `ItemEntry/Description` free text (plain 1.2) or `ItemEntryEN/Period` (EN). |
| Art 226(8) taxable amount + VAT per rate | **Representable natively**: `InvoiceSumGroup/VAT` × n + `TotalVATSum`/`TotalSum`/`TotalToPay` (spec: "Invoice must have as many VAT blocks as there are different VATRate values") | Use the VAT blocks. Nothing to invent. |
| A machine-readable "reverse charge" flag | Absent | vatId=`TAX` + VATRate 0 + note (convention); or `CustomContent` extension agreed with the operator. |

---

# ITEM 4 — Customer fixed establishments (VAT Directive Art 44 second limb)

## 4.1 The correct articles (the brief's citations need correction)

**Confirmed by retrieval on 2026-10-31 (EUR-Lex consolidated texts):**

- **The VAT Directive does NOT define "fixed establishment".** Directive Art 11 is **VAT grouping**
  ("each Member State may regard as a single taxable person any persons … closely bound to one another by
  financial, economic and organisational links") — not the FE definition. Directive Art 28a (inserted by
  ViDA Directive (EU) 2025/516, applies 1 July 2028 at the earliest) is the **platform deemed-supplier**
  rule for short-term accommodation/passenger transport — irrelevant to FE and to ApexMail. The FE
  definition lives in **Reg 282/2011 Arts 10–11** (case law dates back to Berkholz/ARO Lease/DFDS/Planzer).
- **Reg 282/2011 Art 10** (business establishment for Arts 44/45): *"the place where the functions of the
  business's central administration are carried out"*; criteria: essential decisions / registered office /
  management meetings; *"The mere presence of a postal address may not be taken to be the place of
  establishment of a business."*
- **Reg 282/2011 Art 11(1)** — the operative customer-side FE test for Art 44 (verbatim):
  > *"For the application of Article 44 of Directive 2006/112/EC, a 'fixed establishment' shall be any
  > establishment, other than the place of establishment of a business referred to in Article 10 of this
  > Regulation, characterised by a sufficient degree of permanence and a suitable structure in terms of
  > human and technical resources to enable it to receive and use the services supplied to it for its own
  > needs."*
- **Art 11(2)**: supplier-side FE (for Arts 45, 56(2), 192a): *"… to enable it to provide the services
  which it supplies"*. **Art 11(3)**: *"The fact of having a VAT identification number shall not in itself
  be sufficient to consider that a taxable person has a fixed establishment."*
- **Art 22(1)** — the supplier's identification procedure (verbatim):
  > *"In order to identify the customer's fixed establishment to which the service is provided, the
  > supplier shall examine the nature and use of the service provided. Where the nature and use of the
  > service provided do not enable him to identify the fixed establishment to which the service is
  > provided, the supplier, in identifying that fixed establishment, shall pay particular attention to
  > whether the contract, the order form and the VAT identification number attributed by the Member State
  > of the customer and communicated to him by the customer identify the fixed establishment as the
  > customer of the service and whether the fixed establishment is the entity paying for the service.
  > Where the customer's fixed establishment to which the service is provided cannot be determined in
  > accordance with the first and second subparagraphs … or where services covered by Article 44 … are
  > supplied to a taxable person under a contract covering one or more services used in an unidentifiable
  > and non-quantifiable manner, the supplier may legitimately consider that the services have been
  > supplied at the place where the customer has established his business."*
  > Art 22(2): *"The application of this Article shall be without prejudice to the customer's obligations."*
- **Directive Art 44** (second limb, verbatim): *"However, if those services are provided to a fixed
  establishment of the taxable person located in a place other than the place where he has established his
  business, the place of supply of those services shall be the place where that fixed establishment is
  located."* **Art 196**: *"VAT shall be payable by any taxable person … to whom the services referred to
  in Article 44 are supplied, if the services are supplied by a taxable person not established within the
  territory of the Member State."* **Art 192a**: a taxable person with an FE in the Member State where tax
  is due is treated as **not established** there (so the reverse charge survives) only if his establishment
  there does not intervene in the supply.
- **"The 2017 amendments" to Arts 10–13 do not exist.** Verified by comparing the original OJ text
  (CELEX 32011R0282) with the current consolidated text (CELEX 02011R0282-20250414): Articles 10–13 are
  **textually identical**; no amendment markers touch them (the next marker is ▼M2 at Art 13a). Council
  Implementing Regulation (EU) **2017/2459** — the only "2017 amendment" of 282/2011 — replaces **Art 24b**
  (one-item evidence for B2C location, applies from 1 January 2019); it does not touch FE. The brief's
  "(the 2017 amendments)" most likely refers to a **never-adopted 2017 Commission draft amending
  regulation on the identification of fixed establishments** (**UNVERIFIED** as to its exact COM number and
  current status — no trace in the consolidated texts). What did emerge from that process: the Commission's
  VAT Expert Group opinion and the ViDA work (below).

## 4.2 CJEU — which establishment is the customer's for B2B services

Operative parts, retrieved 2026-10-31 from EUR-Lex (CELEX 6…):

- **C-605/12 Welmory (16 Oct 2014)** — the customer-side FE test for Art 44 (verbatim operative part):
  > *"A first taxable person who has established his business in one Member State, and receives services
  > supplied by a second taxable person established in another Member State, must be regarded as having a
  > 'fixed establishment' … in that other Member State, for the purpose of determining the place of
  > taxation of those services, if that establishment is characterised by a sufficient degree of permanence
  > and a suitable structure in terms of human and technical resources to enable it to receive the services
  > supplied to it and use them for its business, which is for the referring court to ascertain."*

- **C-547/18 Dong Yang Electronics (7 May 2020)** — **this is a SERVICES case, not goods** (the underlying
  supply was PCB-assembly services by a Polish company to a Korean customer; the Polish FA claimed Polish
  VAT from the supplier on the theory that the customer's Polish subsidiary was its FE). Operative part:
  > *"Article 44 … and Article 11(1) and Article 22(1) of [Reg 282/2011] must be interpreted as meaning
  > that the existence, in the territory of a Member State, of a fixed establishment of a company
  > established in a non-Member State may not be inferred by a supplier of services from the mere fact
  > that that company has a subsidiary there, and that supplier is not required to inquire, for the
  > purposes of such an assessment, into contractual relationships between the two entities."*
  Facts that matter for us: the customer *assured* the supplier it had no Polish FE ("LG Korea assured
  Dong Yang that it did not have a fixed establishment in Poland and that it did not employ staff, own
  immovable property or have technical resources there") and the Court still protects the supplier who
  relies on the customer's information.

- **C-931/19 Titanium (3 June 2020)** — the establishment test. Operative part: *"A property which is let
  in a Member State, in the circumstance where the owner of that property does not have his or her own
  staff to perform services relating to the letting does not constitute a fixed establishment…"*.
  Reasoning (para 42): *"The concept of 'fixed establishment' … implies a minimum degree of stability
  derived from the permanent presence of both the human and technical resources necessary for the
  provision of given services. It thus requires a sufficient degree of permanence and a structure adequate,
  in terms of human and technical resources, to supply the services in question on an independent basis
  (… Planzer Luxembourg, C-73/06 …). In particular, a structure without its own staff cannot fall within
  the scope of the concept of a 'fixed establishment' (… ARO Lease, C-190/95 …)."*

- **C-333/20 Berlin Chemie (7 Apr 2022)** — services; subsidiary as putative FE. Operative part:
  > *"Article 44 … and Article 11(1) of [Reg 282/2011] must be interpreted as meaning that a company which
  > has its registered office in one Member State does not have a fixed establishment in another Member
  > State on the ground that that company owns a subsidiary there that makes available to it human and
  > technical resources under contracts by means of which that subsidiary provides, exclusively to it,
  > marketing, regulatory, advertising and representation services that are capable of having a direct
  > influence on the volume of its sales."*
  Key reasoning: para 41 — ownership is not required, *"it is however necessary for that taxable person to
  have the right to dispose of those human and technical resources in the same way as if they were its
  own, on the basis, for example, of employment and leasing contracts which make those resources available
  to the taxable person and cannot be terminated at short notice"*; para 54 — *"the same means cannot be
  used both to provide and receive the same services."* Facts: the German parent had a **tax representative
  in Romania and was VAT-registered there** (para 7) — and still no FE; consistent with Reg 282/2011
  Art 11(3).

Practitioner/expert (the third source): **VAT Expert Group opinion No 108, "Fixed Establishments"
(taxud.c.1(2022)4464651, June 2022)** — the European Commission's expert group (retrieved 2026-10-31 from
vatupdate.com mirror):
> *"It is the business recipient who, based on the contractual arrangements, needs to provide the supplier
> with the relevant information regarding his location by sharing comprehensive details as to his place of
> establishment and relevant VAT Id-No with the supplier, so that the latter can determine the proper place
> of taxation … The supplier has to rely on the information received from the business customer – the
> supplier cannot look into the 'customer's kitchen'."*
> *"This decision must be taken at the time when the supply takes place. A wrong decision may expose the
> parties to sanctions, penalties and even difficulties with achieving a full input VAT deduction (or VAT
> recovery) by the customer."*

Market practice (vendor implementation): **Stripe Tax** (docs.stripe.com/tax, retrieved 2026-10-31):
"Stripe Tax uses a single address as your customer's location when calculating tax" (address hierarchy:
shipping → billing → payment-method billing → IP); *"Stripe Tax automatically applies the reverse charge
based on the presence of a tax ID and the jurisdictions involved in the transaction. You can also set a
customer's tax status to reverse charge using the API or the Dashboard."* There is **no fixed-establishment
field anywhere** in Stripe Tax: the market-standard engine keys on (customer status + VAT number +
address) and offers a manual override. i.e. vendors **ignore FE unless the customer declares it or the
merchant knows** — exactly the Art 22 default (business establishment) plus an override.

## 4.3 What a SaaS seller must ask/document

The law imposes no questionnaire. The duty stack is:

1. **Examine the nature and use of the service** (Reg 282/2011 Art 22(1) subpara 1). For SaaS: who are the
   seats/admins, which entity consumes the service, who is invoiced and who pays.
2. **Then look at contract, order form, the customer's VAT number and the payer** (Art 22(1) subpara 2).
3. **Default rule:** where the FE cannot be determined that way — or where a single contract covers
   services "used in an unidentifiable and non-quantifiable manner" — *"the supplier may legitimately
   consider that the services have been supplied at the place where the customer has established his
   business"* (Art 22(1) subpara 3). For a centrally-bought SaaS subscription available to group staff in
   several countries, this is the standard and defensible position: invoice the HQ.
4. **No duty to audit the customer's group structure** (Dong Yang: not "required to inquire … into
   contractual relationships between the two entities"; Berlin Chemie: subsidiary resources ≠ parent's FE
   unless the parent can dispose of them "as if they were its own"). A customer declaration is sufficient
   evidence; company-register extracts or org charts are NOT expected of the supplier (VEG 108: the
   supplier "cannot look into the customer's kitchen").
5. **But the default is defeasible by knowledge:** Art 22 is "without prejudice to the customer's
   obligations", and a supplier who is told (or plainly sees) that the service is *for* a fixed
   establishment cannot keep invoicing the HQ. Evidence to keep: the customer's declaration (who/when/
   terms version), the contract/order, the VAT number validated in VIES, the payer identity — the same
   evidence-row pattern the repo already uses for Art 18 (vat_validation_evidence).

## 4.4 Risk analysis — worked explicitly: DE-HQ / EE-FE mis-invoicing

**Scenario.** ApexMail OÜ (EE-established SaaS seller; no FE abroad) sells a subscription to
"Customer GmbH", VAT-registered in Germany (DE VAT number, Berlin billing address). The service is in
fact received and used by the customer's **fixed establishment in Estonia** (EE office with staff using
the product "for its own needs" — Welmory test met). ApexMail invoiced the DE HQ: 0 %, "Reverse charge",
DE VAT number. Facts assumed verified after the event (e.g. customer told us, or the workspace usage and
an EE billing/payment trail show it).

**Step 1 — Place of supply.** Art 44 second limb: the service is "provided to a fixed establishment …
located in a place other than the place where he has established his business" → place of supply =
**Estonia**. (Reg 282/2011 Art 11(1) FE test met; Art 22 nature/use of a SaaS seat-consuming EE office
points to the EE FE; the customer even pays from an EE account → Art 22(1) subpara 2 indicators.)

**Step 2 — Who owes the tax.** Art 196 shifts liability to the customer only "if the services are supplied
by a taxable person **not established** within the territory of the Member State" where the VAT is due.
ApexMail **is** established in Estonia (its place of business; Art 10/Art 192a do not rescue it — its own
establishment is the one making the supply). So Art 196 is excluded and the supply is an **Estonian
domestic taxable supply: 24 % EE VAT, charged by ApexMail** (KMS § 10(1); § 33). The German reverse-charge
self-assessment is the wrong tax in the wrong Member State and does not discharge the EE VAT.

**Step 3 — What the error costs, and who pays.**

| Item | Consequence | Who bears it |
|---|---|---|
| Unpaid EE VAT on the domestic supply | 24 % of the net price, assessable against the supplier (the supplier is the person liable for tax on its own taxable supply; parallel to Art 193) | **ApexMail** — this is the case where the supplier's error costs the supplier real money |
| Interest on late VAT (KMS intress) | Accrues from the due date of the return | **ApexMail** |
| Penalties / misdemeanour liability for unsubmitted or incorrect VAT declarations | KMS sanction provisions (exact fine scale **UNVERIFIED** — accountant to confirm current §§ 102–106 KMS) | **ApexMail** |
| Wrong invoice ("Reverse charge" note + 0 % on a 24 % domestic supply) | Invoice must be corrected (credit note + corrected invoice referencing the original, Art 219; KMS § 37(4)); if any VAT had been *entered* on an invoice, Art 203 would make that VAT payable to the treasury anyway | **ApexMail** (correction workload; Art 203 trap on "fixing" it by adding VAT later without credit-noting) |
| Customer's German RC deduction | German FA may deny the DE input VAT self-assessment (wrong place of supply); if the customer is EE-VAT-registered through the FE, the corrected EE invoice is normally deductible there — the ultimate economic burden then lands back on the customer's VAT account, but the supplier still fronts the cash and the penalties | Shared, but the collection risk is ApexMail's |
| Recapitulative-statement/VD and KMD fields | Corrections in the EE return (0 %-rated § 10(4)9 line was wrong; the sale belongs in domestic boxes) | **ApexMail** |

Numerically: a €1,000 net annual plan mis-invoiced as reverse charge → **€240 EE VAT + interest + penalty
exposure** out of the supplier's pocket per invoice; with N affected customers the exposure scales linearly.
This is the worst-case direction of the FE error.

**Step 4 — The benign direction (for contrast).** If instead the FE had been in **France** and ApexMail
invoiced DE HQ reverse charge: place of supply = France; ApexMail is not established in France → **Art 196:
the customer owes French VAT**. The tax cost falls on the customer, not the supplier. The supplier's
exposure is narrower but non-zero: an incorrect invoice (wrong "number under which the services are
supplied", Art 226(4); wrong place statement), national invoicing penalties possible, mandatory credit
note + re-invoice, ESL/VD corrections, customer claims (the customer self-assessed in the wrong MS and may
be denied deduction / hit with FR VAT + penalties — a contractual-indemnity and reputation risk). And a
repeated pattern of wrong place-of-supply statements is exactly what an audit turns into negligence claims.

**Step 5 — Why "reverse charge anyway" is not a complete comfort.** For a customer whose FE is in **any
Member State other than the supplier's**, the Art 196 mechanism keeps the tax with the customer, so the
supplier's downside is documentation/penalty/commercial risk (lower, as the brief suspects). The exception
— and it is the one that burns — is **the FE located in Estonia (the supplier's own Member State)**:
domestic supply, supplier charges EE VAT, supplier's own money at stake. A second exception: if ApexMail
ever had its own FE in the customer's country (Art 11(2)/192a), the reverse charge would drop out there
too.

## 4.5 Minimal viable policy (single-tenant SaaS seller)

1. **One declaration at checkout/account creation for business accounts** (checkbox + optional country
   field): "The services are received at the business establishment identified above. If they are received
   at a fixed establishment in another country, please state it: [country / none]." Contract clause: the
   customer must notify changes; the supplier is entitled to rely on the declaration, contract, VAT number
   and payer identity (Art 22; Dong Yang; VEG 108).
2. **Persist it** like the VIES evidence row: who declared, when, terms version, the FE country (nullable).
3. **Decision rule** (code-shaped):
   - `fe_country` set and ≠ `vat_country` → place of supply = `fe_country`;
     - `fe_country == "EE"` → **charge 24 % EE VAT** (domestic supply; the supplier is established here);
     - otherwise → reverse charge (0 %, "Pöördmaksustamine" note), and use the customer's VAT number of
       that FE country as the Art 226(4) number if they have one (ask for it).
   - `fe_country` empty → place of supply = business establishment (VAT-number country / billing country),
     with the Art 22(3) fallback expressly documented ("services used in an unidentifiable and
     non-quantifiable manner → business establishment is legitimate").
4. **Red-flag triggers** (queue for human review, don't auto-reverse): billing address country ≠ VAT
   country; payment from a third country; a declared business address that is a mailbox/registered-agent
   address; the customer asking for invoices "for our Tallinn office". SaaS usage signals (admin/user
   concentration) are legitimate "nature and use" observations under Art 22(1) — use them as a prompt to
   ask, never as silent auto-classification.
5. **Do not** investigate group structures, employment contracts or resource ownership (Dong Yang;
   Berlin Chemie paras 41–45: what matters is the customer's right to dispose of resources "as if its
   own", which the supplier cannot see). If the customer declares "no FE", that plus the Art 22 checklist
   is a complete defence file.
6. **Correction path:** credit note referencing the original (Art 219/KMS § 37(4)) + corrected invoice;
   never amend by adding VAT to an already-issued invoice (Art 203).

---

# CONFLICT LIST (with the brief, the companion memo, and the repo)

| # | Conflict | Resolution |
|---|---|---|
| C1 | Brief: "e-arve 1.2 (and 1.3 if it exists)". | **1.3 does not exist.** Current local norm: **1.2 (01.12.2013)**; 1.2.EN (28.08.2018, draft) is an EN 16931 extension inside 1.2. "1.11" is a 2012 AATT bank-transport variant of 1.1, not a successor. (ITL custodian page + version histories; Wayback offline 2026-10-31.) |
| C2 | Brief: "Reg 282/2011 Arts. 10-13 (FE definition for services; **the 2017 amendments**)". | Arts 10–13 are **unchanged since 2011** (verified original vs consolidated 2025-04-14). Reg 2017/2459 amends **Art 24b** (B2C evidence), not FE. The "2017 amendments" are likely the never-adopted draft FE-identification regulation (**UNVERIFIED**). |
| C3 | Brief: "the definition of fixed establishment (**Art 11 + 28a?** confirm the correct articles)". | Directive **Art 11 = VAT grouping**; Directive **Art 28a = ViDA platform deemed supplier** (2028). The FE definition is **Reg 282/2011 Art 11(1)** (customer side, Art 44) / Art 11(2) (supplier side) with Art 10 and Art 22; supported by Directive Arts 44, 192a, 196. |
| C4 | Brief: "C-547/18 Dong Yang Electronics (**goods?** — check whether it applies)". | Dong Yang is a **services** case (PCB assembly services; Art 44 + Reg 282 Arts 11(1)/22(1)) and is directly applicable to B2B services. |
| C5 | Repo `render_invoice_xml` claims "Version 1.2" conformance. | The emitted XML **does not validate** against the official `e-invoice_ver1.2.xsd`: missing `Footer` (mandatory), missing mandatory Invoice attributes (`invoiceId`/`regNumber`/`sellerRegnumber`), missing mandatory `DocumentName`, `<Type Type="DEB"/>` should be `<Type type="DEB"/>`, `InvoiceSumGroup/PaidAmount`+`PayableAmount` are **not schema elements** (use `TotalToPay`/`Balance`), `ItemEntry` must be wrapped in `InvoiceItemGroup`, `ItemSum` is a decimal (not the complex type currently emitted with `Amount`/`TotalSum`), `PaymentInfo/DueDate` should be `PayDueDate`, `PaymentId`/`PayToAccount`/`PayToName` are mandatory in PaymentInfo, and in `ContactDataRecord` `E-mailAddress` must precede `LegalAddress` (repo emits it after). The snippets in § 3.4 are conformant (xmllint-validated). |
| C10 | Repo emits `<E_Invoice xmlns="http://www.pangaliit.ee/e-arve/e-arve">`. | The official package is **no-namespace**: `e-invoice_ver1.2.xsd` has no `targetNamespace`; official samples and the internetee gem root with `xsi:noNamespaceSchemaLocation="e-invoice_ver1.2.xsd"`. The official XSD rejects the namespaced root (xmllint: "No matching global declaration available for the validation root"). Adopt the official no-namespace root; keep the namespaced variant only if a specific receiving bank demonstrably requires it (**UNVERIFIED**). |
| C6 | Companion memo C7: KMS § 37(8)2) English says "goods"; translation artefact suspected. | EMTA guidance (retrieved 2026-10-31, page updated 19.08.2026) resolves it: the mark „pöördmaksustamine" is required for reverse-charge supplies **including services** (KMS § 10(4)9) table entry). Directive Art 226(11a) is goods-and-services neutral. |
| C7 | Note wording: "Reverse charge" (Directive) vs „pöördmaksustamine" (EMTA). | Print both: "Pöördmaksustamine / Reverse charge — käibemaksu tasub saaja …". EMTA: for reverse charge the mark is fixed and may not be replaced by a generic wording (unlike exemptions/0 %). |
| C8 | Official description § 2.9 example uses `id="Note"` on AdditionalInformation. | The XSD attribute is **`extensionId`** and the official sample files use `extensionId`. Follow the XSD; treat the PDF example as a documentation typo. |
| C9 | Brief: "what exporters do instead (e.g. extend InvoiceItem description? a note in PaymentDescription? the docs say which?)". | The **docs say which**: `AdditionalInformation` ("additional information which is shown on the invoice") + `InvoiceContentText`. ItemEntry-description stuffing and PaymentDescription are not the documented mechanism (PaymentDescription is for the payment). Which receiving banks render AdditionalInformation visually is **UNVERIFIED**. |

---

# CODE-READY ANSWERS

## A. e-invoice XML export (drop-in answers for `render_invoice_xml`, `services/mail-server/crates/api-server/src/routes/billing.rs`)

1. **Reverse-charge reference (Art 226(11a)):** emit
   `<AdditionalInformation extensionId="ReverseCharge"><InformationName>Pöördmaksustamine</InformationName><InformationContent>Reverse charge — VAT is payable by the recipient. Käibemaksu tasub saaja (KMS § 37 lg 8 p 2; direktiivi 2006/112/EÜ art 226 lg 11a).</InformationContent></AdditionalInformation>`
   as a direct child of `<Invoice>` (after `InvoiceItem`, before `PaymentInfo`), **gated on the same
   evidence-backed reverse_charge flag as the PDF renderer** (never the structural VAT-number check),
   plus mirror text in `InvoiceContentText`. There is no dedicated element — this is the schema's designed
   free-text slot ("shown on the invoice"), 500 chars.
2. **Supply date / period (Art 226(7); Art 64(2)):** emit
   `<Period><PeriodName>Teenuse osutamise periood</PeriodName><StartDate>{period_start}</StartDate><EndDate>{period_end}</EndDate></Period>`
   inside `InvoiceInformation` (after `DueDate`), and state the date of supply explicitly in an
   `Extension`/`AdditionalInformation` sentence ("Teenuse osutamise kuupäev {date} (perioodi viimane päev,
   direktiivi art 64 lg 2)") — **a dedicated supply-date element does not exist in e-arve 1.2** ("not
   representable" beyond Period + free text; the only structured carriers are the v1.2.EN `VATPointDate`/
   `ActualDeliveryDate` inside `CustomContent`).
3. **Per-rate VAT summary (Art 226(8)):** one `<VAT vatId="TAX">` block per distinct rate in
   `InvoiceSumGroup` (`SumBeforeVAT`, `VATRate`, `VATSum`, `Currency`, `SumAfterVAT`), then `TotalVATSum`,
   `TotalSum`, `TotalToPay`, `Currency` — schema-mandated shape ("Invoice must have as many VAT blocks as
   there are different VATRate values"). Reverse charge = one block, `VATRate 0.00`, `vatId="TAX"`
   (0 % taxable supply per KMS § 15(4)(1); document this convention).
4. **Conformance fixes required for the export to be a real e-arve 1.2** (conflicts C5/C10): root element
   in **no-namespace** form `<E_Invoice xsi:noNamespaceSchemaLocation="e-invoice_ver1.2.xsd"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` (drop the `xmlns="…pangaliit.ee…"` namespace —
   the official XSD has no targetNamespace and rejects it); add mandatory `Footer`
   (`TotalNumberInvoices`, `TotalAmount`); add Invoice attributes `invoiceId`/`regNumber`/
   `sellerRegnumber`; add mandatory `DocumentName` ("Arve"); `<Type type="DEB"/>` (lowercase attribute);
   replace `PaidAmount`/`PayableAmount` with `TotalToPay` (and `Balance` if partial settlement must be
   shown); wrap `ItemEntry` in `InvoiceItemGroup`; make `ItemSum` a decimal and move VAT to the
   `ItemEntry/VAT` (VATRecord) slot; `PayDueDate` instead of `DueDate` in `PaymentInfo`; in `ContactData`
   put `E-mailAddress` **before** `LegalAddress`. (Snippets in § 3.4 were xmllint-validated against the
   official XSD on 2026-10-31.)
5. **Version to target:** e-arve **1.2** (there is no 1.3). Optional forward-compatible extras: the
   v1.2.EN `CustomContent` blocks (`InvoiceInformationEN` with `VATPointDate`/`ActualDeliveryDate`/
   `InvoiceNote`; `VATEN` with `CategoryCode` + `ExemptionReasonText` on each `VAT/Reference`) — that is
   also the EN 16931 route the Accounting Act § 7¹(7) presumes compliant.

## B. Customer fixed-establishment policy (Art 44 second limb)

1. **Ask once, in writing, at business signup/checkout:** "Services are received at the business
   establishment above; if received at a fixed establishment in another country, state it: [country/none]."
   Store the declaration (who/when/terms version/FE country) beside the existing VIES evidence row.
2. **Decision rule:** declared FE in another MS → place of supply is that MS. If the FE is in **Estonia**
   → domestic supply, **charge 24 % EE VAT** (Art 196 does not apply — supplier is established where the
   tax is due). If the FE is elsewhere → reverse charge with the "Pöördmaksustamine" note and the FE
   country's VAT number on the invoice (Art 226(4)). No declaration → business establishment (Art 22(3)
   fallback is legitimate, especially for subscriptions "used in an unidentifiable and non-quantifiable
   manner").
3. **Risk of ignoring FE:** where the FE is in the supplier's own country (the DE-HQ/EE-FE scenario,
   § 4.4) the supplier owes the domestic VAT out of its own pocket (24 % + interest + penalties + credit
   notes). Where the FE is in another MS, Art 196 leaves the tax with the customer, and the supplier's
   exposure is wrong-invoice corrections, invoicing penalties and customer claims — lower, but real.
4. **Do not** audit the customer's subsidiaries or contracts (Dong Yang); rely on the declaration +
   contract + VAT number + payer (Reg 282/2011 Art 22; VEG 108). Red flags (billing/VAT country mismatch,
   payment from a third country, "invoice our Tallinn office") trigger a question, not an automatic
   reclassification.
5. **Minimal viable implementation:** one nullable `fixed_establishment_country` + a timestamped
   declaration on the customer/billing record; a branch in the quoting function as in (2); a review queue
   for red flags; a documented policy statement ("we treat the supply as made to the business
   establishment unless the customer declares a fixed establishment") — which is exactly what the market
   (Stripe Tax single-address sourcing + VAT-ID reverse charge + manual override) implements.

---

## Source index (all retrieved 2026-10-31)

- e-arve 1.2: pangaliit.ee/arveldused/e-arve; itl.ee/e-arve-kirjeldus (+ wp.itl.ee/files: EE_einvoice_1.2.zip
  = `e-invoice_ver1.2.xsd` + `EARVE_1.2_all_fields.xml` + `EARVE_1.2_mandatory_fields.xml`;
  Estonian_e-invoice_description_ver1.2_eng.pdf (52 pp, 01.12.2013); Estonian_e-invoice_description_ver1.1_eng.pdf;
  EE_einvoice_1.11_and_bank_files.zip; IoB v1.2.EN description (28.08.2018) + `e-invoice_ver1.2.EN.xsd` +
  syntax-binding PDFs). Independent copies: github.com/internetee/e_invoice (v1.2.xsd byte-identical),
  github.com/thorgate/estonian_e_invoice, sp19hub/freeEarve, itsbalamurali/balticum, Fitek-Global/fitek_ai.
- Statutory marks & invoice content: EMTA handbook "Käibemaksuarvestus ja arved" —
  emta.ee/ariklient/maksud-ja-tasumine/kaibemaks/kaibemaksuarvestus-ja-arved/{arvele-margitavad-andmed,
  arvele-margitavad-viited,muud-viited-ja-markused,teenuse-kaibe-tekkimise-koht-ei-ole-eesti};
  Directive 2006/112/EC Arts 44, 196 (CELEX 02006L0112-20250414); KMS § 37 English consolidated (via
  docs/research/eu-vat-law-evidence-and-invoicing.md § 4.3).
- FE law: Reg 282/2011 CELEX 32011R0282 (original) and CELEX 02011R0282-20250414 (consolidated) Arts 10–13,
  22, 13a; Reg (EU) 2017/2459 (Art 24b; applies 1 Jan 2019); Directive Arts 44, 192a, 196, 11 (VAT
  grouping), 28a (correlation table to ViDA (EU) 2025/516).
- CJEU (EUR-Lex): C-605/12 Welmory (62012CJ0605); C-547/18 Dong Yang (62018CJ0547); C-931/19 Titanium
  (62019CJ0931, incl. paras 42–43); C-333/20 Berlin Chemie (62020CJ0333, incl. paras 39–55).
- Practitioner: VAT Expert Group opinion No 108 "Fixed Establishments" (taxud.c.1(2022)4464651, via
  vatupdate.com mirror); Stripe Tax docs (docs.stripe.com/tax/{calculating,customer-locations,zero-tax}).
- Limitation: web.archive.org offline on 2026-10-31 (no Wayback cross-check of pre-2019 pangaliit pages);
  UNTDID 5305 code values (e.g. "AE") and per-bank rendering of AdditionalInformation marked UNVERIFIED.
