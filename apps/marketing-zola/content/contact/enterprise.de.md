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

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status">
  <p><strong>Vielen Dank — Ihre Eingabe wurde übermittelt.</strong> Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert">
  <p><strong>Ihre Eingabe konnte nicht entgegengenommen werden.</strong> Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="de" />
  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Geschäftliche E-Mail <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Unternehmen <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div>
    <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Ungefähres monatliches E-Mail-Volumen <span class="text-red-500">*</span></label>
    <select id="monthly-volume" name="monthly_volume" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
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

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Bereitstellungsmodell</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="shared" checked class="accent-brand-500" />
        <span><strong>Shared Cloud</strong> — Multi-Tenant-EU-Infrastruktur</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="dedicated" class="accent-brand-500" />
        <span><strong>Dedicated Tenant</strong> — isolierte Single-Tenant-Infrastruktur, vorbehaltlich Architektur- und Vertragsprüfung</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Private Bereitstellung</strong> — verwaltete Bereitstellung in Ihrem Cloud-Konto, vorbehaltlich Architektur- und Vertragsprüfung</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="requirements" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Anforderungen & Kontext</label>
    <textarea id="requirements" name="requirements" rows="5"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Compliance-Anforderungen, Datenresidenz-Bedarf, aktueller Anbieter, Migrationszeitplan, benötigte Funktionen oder sonstiger Kontext, der uns hilft, die richtige Empfehlung vorzubereiten."></textarea>
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

Lieber per E-Mail? Erreichen Sie das Enterprise-Team unter [support@apexmail.ee](mailto:support@apexmail.ee). Nennen Sie Ihr monatliches Volumen, Ihre Präferenz beim Bereitstellungsmodell und etwaige Compliance-Anforderungen, damit wir uns auf das erste Gespräch vorbereiten können.
