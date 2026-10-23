+++
title = "Anforderung eines Sicherheitsfragebogens"
description = "Fordern Sie ApexMail-Sicherheitsdokumentation, SIG/CAIQ-Antworten, Penetrationstest-Zusammenfassungen an oder vereinbaren Sie ein Sicherheitsarchitektur-Review."
template = "prose.html"

[extra]
form_id = "security-contact"
+++

## Anforderung eines Sicherheitsfragebogens

ApexMail stellt qualifizierten Enterprise-Interessenten und Kunden Sicherheitsdokumentation bereit, wo erforderlich unter NDA. Nutzen Sie dieses Formular, um SIG-, CAIQ-, HECVAT- oder individuelle Sicherheitsfragebögen anzufordern oder ein Sicherheitsarchitektur-Review zu vereinbaren.

## Was wir bereitstellen

- **SIG / CAIQ / HECVAT** — Standardisierte Antworten für Sicherheitsbewertungen für qualifizierte Enterprise-Kunden.
- **Penetrationstest-Zusammenfassung** — Eine Zusammenfassung der Befunde und Behebungsmaßnahmen wird verfügbar sein, sobald der erste externe Penetrationstest der Anwendung abgeschlossen ist.
- **Sicherheitsarchitektur-Review** — Ein gemeinsamer Durchgang durch die Sicherheitskontrollen, die Verschlüsselungsarchitektur, die Audit-Protokollierung und die Bereitstellungs-Isolationsmodelle von ApexMail.
- **Datenflussdiagramme** — Visuelle Dokumentation der Datenverarbeitung, der Speicherorte und der Unterauftragsverarbeiter-Beziehungen.

## Formular zur Anforderung eines Sicherheitsfragebogens

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Übermittelt</b>
  <p>Vielen Dank — Ihre Eingabe wurde übermittelt. Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Nicht angenommen</b>
  <p>Ihre Eingabe konnte nicht entgegengenommen werden. Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="de" />
  <div class="apex-field">
    <label for="work-email-sec" class="apex-label">Geschäftliche E-Mail <span class="">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="apex-field">
    <label for="company-sec" class="apex-label">Unternehmen <span class="">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="apex-input"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div class="apex-field">
    <label for="document-type" class="apex-label">Angeforderte Dokumentation <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="document-type" name="document_type" required>
      <option value="" disabled selected>Benötigte Dokumente auswählen</option>
      <option value="sig">SIG-Fragebogen</option>
      <option value="caiq">CAIQ-Fragebogen</option>
      <option value="hecvat">HECVAT-Fragebogen</option>
      <option value="custom">Individueller Sicherheitsfragebogen</option>
      <option value="pentest">Penetrationstest-Zusammenfassung</option>
      <option value="architecture_review">Sicherheitsarchitektur-Review</option>
      <option value="data_flow">Datenflussdiagramme</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="nda-status" class="apex-label">NDA-Status</label>
    <div class="apex-select-wrap">
      <select id="nda-status" name="nda_status">
      <option value="not_signed" selected>NDA noch nicht unterzeichnet</option>
      <option value="signed">NDA bereits vorhanden</option>
      <option value="willing">Bereit, eine NDA zu unterzeichnen</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="context" class="apex-label">Zusätzlicher Kontext</label>
    <textarea id="context" name="context" rows="4"
      placeholder="Konkrete Compliance-Frameworks, regulatorische Anforderungen oder Zeitplanvorgaben, die wir kennen sollten."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Anfrage senden
    </button>
  </div>
  <p class="apex-footnote">Mit dem Absenden dieses Formulars akzeptieren Sie unsere <a href="/de/privacy/">Datenschutzerklärung</a>. Wir verwenden Ihre Angaben ausschließlich zur Beantwortung Ihrer Anfrage (DSGVO Art. 13).</p>
</form>

## Direkter Kontakt

Sie können Ihre Anfrage für Sicherheitsdokumentation auch per E-Mail an [support@apexmail.ee](mailto:support@apexmail.ee). Nennen Sie Ihren Firmennamen, die konkreten Dokumente oder Fragebögen, die Sie benötigen, und ob eine NDA bereits besteht oder erforderlich ist.
