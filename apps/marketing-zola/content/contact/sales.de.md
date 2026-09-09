+++
title = "Mit dem Vertrieb sprechen"
description = "Besprechen Sie Enterprise-Rollout-Pläne, Compliance-Anforderungen und Private-Cloud-Bereitstellungsoptionen mit ApexMail."
template = "prose.html"

[extra]
form_id = "sales-contact"
+++

## Mit dem Vertrieb sprechen

Für Enterprise-Beschaffung, Sicherheitsprüfung oder Private-Cloud-Planung füllen Sie das untenstehende Formular aus. Unser Team prüft Ihre Anfrage und antwortet innerhalb von 2 Werktagen.

## Vertriebsanfrage-Formular

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status" hidden>
  <p><strong>Vielen Dank — Ihre Eingabe wurde übermittelt.</strong> Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert" hidden>
  <p><strong>Ihre Eingabe konnte nicht entgegengenommen werden.</strong> Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="de" />
  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Unternehmen <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Geschäftliche E-Mail <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div>
      <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Monatliches E-Mail-Volumen <span class="text-red-500">*</span></label>
      <select id="monthly-volume" name="monthly_volume" required
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
        <option value="" disabled selected>Volumenbereich auswählen</option>
        <option value="lt_50k">Unter 50.000</option>
        <option value="50k_150k">50.000 – 150.000</option>
        <option value="150k_500k">150.000 – 500.000</option>
        <option value="500k_2m">500.000 – 2 Millionen</option>
        <option value="2m_5m">2 Millionen – 5 Millionen</option>
        <option value="5m_10m">5 Millionen – 10 Millionen</option>
        <option value="10m_plus">10 Millionen+</option>
      </select>
    </div>

    <div>
      <label for="peak-hourly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Spitzenvolumen pro Stunde</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume"
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
        placeholder="z. B. 50,000 pro Stunde" />
    </div>
  </div>

  <div>
    <label for="current-provider" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Aktueller Anbieter</label>
    <select id="current-provider" name="current_provider"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Aktuellen Anbieter auswählen (falls vorhanden)</option>
      <option value="sendgrid">SendGrid (Twilio)</option>
      <option value="postmark">Postmark (ActiveCampaign)</option>
      <option value="mailgun">Mailgun (Sinch)</option>
      <option value="ses">Amazon SES</option>
      <option value="resend">Resend</option>
      <option value="mailchimp">Mailchimp / Mandrill</option>
      <option value="brevo">Brevo (Sendinblue)</option>
      <option value="other">Anderer Anbieter</option>
      <option value="none">Kein aktueller Anbieter</option>
      <option value="multiple">Mehrere Anbieter</option>
    </select>
  </div>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Bevorzugte Bereitstellung</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="shared" checked class="accent-brand-500" />
        <span><strong>Shared Cloud</strong> — Multi-Tenant-EU-Infrastruktur</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="dedicated" class="accent-brand-500" />
        <span><strong>Dedicated Tenant</strong> — isolierte Single-Tenant-Infrastruktur</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Private Bereitstellung</strong> — verwaltete Bereitstellung in Ihrem Cloud-Konto</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="not_sure" class="accent-brand-500" />
        <span><strong>Noch unsicher</strong> — Beratung zum passenden Modell gewünscht</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Compliance-Anforderungen <span class="text-xs font-normal text-surface-400 normal-case tracking-normal">(alle zutreffenden auswählen)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="gdpr" class="accent-brand-500" />
        <span>DSGVO-/Datenresidenz-Bereitstellungsprüfung</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="hipaa" class="accent-brand-500" />
        <span>HIPAA-Anwendungsfall (derzeit nicht angeboten; Alternativen besprechen)</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="ccpa" class="accent-brand-500" />
        <span>CCPA / Datenschutzgesetze der US-Bundesstaaten</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="fedramp" class="accent-brand-500" />
        <span>FedRAMP / Behörden</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="regional_residency" class="accent-brand-500" />
        <span>Spezifische regionale Datenresidenzanforderung</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="dpf" class="accent-brand-500" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="target-timeline" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Gewünschter Zeitraum</label>
    <select id="target-timeline" name="target_timeline"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Zeitraum auswählen</option>
      <option value="immediate">Sofort (innerhalb von 2 Wochen)</option>
      <option value="30_days">Innerhalb von 30 Tagen</option>
      <option value="90_days">Innerhalb von 90 Tagen</option>
      <option value="6_months">Innerhalb von 6 Monaten</option>
      <option value="exploring">Optionen sichten — kein fester Zeitplan</option>
    </select>
  </div>

  <div>
    <label for="security-review" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Anforderungen an die Sicherheitsprüfung</label>
    <select id="security-review" name="security_review_needs"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Prüfungstiefe auswählen</option>
      <option value="standard">Standard — Sicherheitsfragebogen wird anhand aktueller Prüfunterlagen fallweise beantwortet (kein standardisiertes SIG/CAIQ/HECVAT-Paket ist Teil des Produktumfangs)</option>
      <option value="detailed">Detailliert — individueller Sicherheitsfragebogen erforderlich</option>
      <option value="pen_test">Penetrationstest-Bericht erforderlich</option>
      <option value="on_site">Vor-Ort-Audit oder Architektur-Review erforderlich</option>
      <option value="none">In dieser Phase keine Sicherheitsprüfung erforderlich</option>
    </select>
  </div>

  <div>
    <label for="additional-context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Zusätzlicher Kontext</label>
    <textarea id="additional-context" name="additional_context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Konkrete Integrationsanforderungen, Migrationspläne, Sicherheitsarchitektur-Bedarf oder sonstiger Kontext, der uns hilft, die richtige Empfehlung vorzubereiten."></textarea>
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

## Wie es weitergeht

Nach dem Absenden prüft unser Enterprise-Team Ihre Anforderungen und antwortet innerhalb von 2 Werktagen mit einem empfohlenen Bereitstellungsmodell, indikativen Preisen und den nächsten Schritten für ein strukturiertes Architektur-Review.

Für zeitkritische Beschaffungsgespräche senden Sie eine E-Mail an [support@apexmail.ee](mailto:support@apexmail.ee) mit dem Betreff "Urgent: Sales Enquiry" und geben Sie Ihr monatliches Volumen sowie Ihre bevorzugte Bereitstellung an.
