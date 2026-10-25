+++
title = "Enterprise-Kontakt"
description = "Fordern Sie eine Prüfung einer Enterprise-Bereitstellung, eine Preisdiskussion oder eine Private-Cloud-Bewertung mit dem ApexMail-Team an."
template = "prose.html"

[extra]
form_id = "enterprise-contact"
+++

## Enterprise-Kontakt

Organisationen, die ApexMail Enterprise Shared, Dedicated Tenant oder BYOC-Bereitstellungen evaluieren, nutzen dieses Formular oder schreiben direkt an [support@apexmail.ee](mailto:support@apexmail.ee).

## Was Sie erwarten können

Nach dem Absenden des Formulars prüft unser Enterprise-Team Ihre Anforderungen und antwortet innerhalb von 2 Werktagen mit einem empfohlenen Bereitstellungsmodell, indikativen Preisen und den nächsten Schritten für ein strukturiertes Architektur-Review.

## Enterprise-Anfrageformular

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Übermittelt</b>
  <p>Vielen Dank, Ihre Eingabe wurde übermittelt. Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Nicht angenommen</b>
  <p>Ihre Eingabe konnte nicht entgegengenommen werden. Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="de" />
  <div class="apex-field">
    <label for="work-email" class="apex-label">Geschäftliche E-Mail <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="apex-field">
    <label for="company" class="apex-label">Unternehmen <span class="">*</span></label>
    <input type="text" id="company" name="company" required
      class="apex-input"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div class="apex-field">
    <label for="monthly-volume" class="apex-label">Ungefähres monatliches E-Mail-Volumen <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
      <option value="" disabled selected>Volumenbereich auswählen</option>
      <option value="lt_100k">Unter 100.000</option>
      <option value="100k_500k">100.000 – 500.000</option>
      <option value="500k_1m">500.000 – 1 Million</option>
      <option value="1m_5m">1 Million – 5 Millionen</option>
      <option value="5m_10m">5 Millionen – 10 Millionen</option>
      <option value="10m_50m">10 Millionen – 50 Millionen</option>
      <option value="50m_plus">50 Millionen+</option>
    </select>
    </div>
  </div>

  <fieldset class="border p-4">
    <legend class="px-2">Bereitstellungsmodell</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="shared" checked />
        <span><strong>Shared Cloud</strong>, Multi-Tenant-EU-Infrastruktur</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="dedicated" />
        <span><strong>Dedicated Tenant</strong>, isolierte Single-Tenant-Infrastruktur, vorbehaltlich Architektur- und Vertragsprüfung</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="byoc" />
        <span><strong>BYOC / Private Bereitstellung</strong>, verwaltete Bereitstellung in Ihrem Cloud-Konto, vorbehaltlich Architektur- und Vertragsprüfung</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="requirements" class="apex-label">Anforderungen & Kontext</label>
    <textarea id="requirements" name="requirements" rows="5"
      placeholder="Compliance-Anforderungen, Datenresidenz-Bedarf, aktueller Anbieter, Migrationszeitplan, benötigte Funktionen oder sonstiger Kontext, der uns hilft, die richtige Empfehlung vorzubereiten."></textarea>
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

Sie erreichen das Enterprise-Team auch per E-Mail unter [support@apexmail.ee](mailto:support@apexmail.ee). Nennen Sie Ihr monatliches Volumen, Ihre Präferenz beim Bereitstellungsmodell und etwaige Compliance-Anforderungen, damit wir uns auf das erste Gespräch vorbereiten können.
