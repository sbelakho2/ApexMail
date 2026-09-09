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

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status">
  <p><strong>Vielen Dank — Ihre Eingabe wurde übermittelt.</strong> Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert">
  <p><strong>Ihre Eingabe konnte nicht entgegengenommen werden.</strong> Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="de" />
  <div>
    <label for="work-email-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Geschäftliche E-Mail <span class="text-red-500">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div>
    <label for="company-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Unternehmen <span class="text-red-500">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div>
    <label for="document-type" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Angeforderte Dokumentation <span class="text-red-500">*</span></label>
    <select id="document-type" name="document_type" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
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

  <div>
    <label for="nda-status" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">NDA-Status</label>
    <select id="nda-status" name="nda_status"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="not_signed" selected>NDA noch nicht unterzeichnet</option>
      <option value="signed">NDA bereits vorhanden</option>
      <option value="willing">Bereit, eine NDA zu unterzeichnen</option>
    </select>
  </div>

  <div>
    <label for="context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Zusätzlicher Kontext</label>
    <textarea id="context" name="context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Konkrete Compliance-Frameworks, regulatorische Anforderungen oder Zeitplanvorgaben, die wir kennen sollten."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Anfrage senden
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
  <p class="form-privacy-note">Mit dem Absenden dieses Formulars akzeptieren Sie unsere <a href="/de/privacy/">Datenschutzerklärung</a>. Wir verwenden Ihre Angaben ausschließlich zur Beantwortung Ihrer Anfrage (DSGVO Art. 13).</p>
</form>

## Direkter Kontakt

Lieber per E-Mail? Senden Sie Ihre Anfrage für Sicherheitsdokumentation an [support@apexmail.ee](mailto:support@apexmail.ee). Nennen Sie Ihren Firmennamen, die konkreten Dokumente oder Fragebögen, die Sie benötigen, und ob eine NDA bereits besteht oder erforderlich ist.
