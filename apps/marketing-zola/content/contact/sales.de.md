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

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status" hidden>
  <b>Übermittelt</b>
  <p>Vielen Dank, Ihre Eingabe wurde übermittelt. Unser Team prüft die Anfrage und antwortet innerhalb von 2 Werktagen.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert" hidden>
  <b>Nicht angenommen</b>
  <p>Ihre Eingabe konnte nicht entgegengenommen werden. Bitte prüfen Sie die Pflichtfelder (eine gültige geschäftliche E-Mail-Adresse ist erforderlich) und versuchen Sie es erneut.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="de" />
  <div class="apex-field">
    <label for="company" class="apex-label">Unternehmen <span class="">*</span></label>
    <input type="text" id="company" name="company" required maxlength="200"
      class="apex-input"
      placeholder="Name Ihrer Organisation" />
  </div>

  <div class="apex-field">
    <label for="work-email" class="apex-label">Geschäftliche E-Mail <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div class="apex-field">
      <label for="monthly-volume" class="apex-label">Monatliches E-Mail-Volumen <span class="">*</span></label>
      <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
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
    </div>

    <div class="apex-field">
      <label for="peak-hourly-volume" class="apex-label">Spitzenvolumen pro Stunde</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume" maxlength="200"
        class="apex-input"
        placeholder="z. B. 50,000 pro Stunde" />
    </div>
  </div>

  <div class="apex-field">
    <label for="current-provider" class="apex-label">Aktueller Anbieter</label>
    <div class="apex-select-wrap">
      <select id="current-provider" name="current_provider">
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
  </div>

  <fieldset class="border p-4">
    <legend class="px-2">Bevorzugte Bereitstellung</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="shared" checked />
        <span><strong>Shared Cloud</strong>, Multi-Tenant-EU-Infrastruktur</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="dedicated" />
        <span><strong>Dedicated Tenant</strong>, isolierte Single-Tenant-Infrastruktur</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="byoc" />
        <span><strong>BYOC / Private Bereitstellung</strong>, verwaltete Bereitstellung in Ihrem Cloud-Konto</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="not_sure" />
        <span><strong>Noch unsicher</strong>, Beratung zum passenden Modell gewünscht</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border p-4">
    <legend class="px-2">Compliance-Anforderungen <span class="">(alle zutreffenden auswählen)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="gdpr" />
        <span>DSGVO-/Datenresidenz-Bereitstellungsprüfung</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="hipaa" />
        <span>HIPAA-Anwendungsfall (derzeit nicht angeboten; Alternativen besprechen)</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="ccpa" />
        <span>CCPA / Datenschutzgesetze der US-Bundesstaaten</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="fedramp" />
        <span>FedRAMP / Behörden</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="regional_residency" />
        <span>Spezifische regionale Datenresidenzanforderung</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="dpf" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="target-timeline" class="apex-label">Gewünschter Zeitraum</label>
    <div class="apex-select-wrap">
      <select id="target-timeline" name="target_timeline">
      <option value="" selected>Zeitraum auswählen</option>
      <option value="immediate">Sofort (innerhalb von 2 Wochen)</option>
      <option value="30_days">Innerhalb von 30 Tagen</option>
      <option value="90_days">Innerhalb von 90 Tagen</option>
      <option value="6_months">Innerhalb von 6 Monaten</option>
      <option value="exploring">Optionen sichten, kein fester Zeitplan</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="security-review" class="apex-label">Anforderungen an die Sicherheitsprüfung</label>
    <div class="apex-select-wrap">
      <select id="security-review" name="security_review_needs">
      <option value="" selected>Prüfungstiefe auswählen</option>
      <option value="standard">Standard, Sicherheitsfragebogen wird anhand aktueller Prüfunterlagen fallweise beantwortet (kein standardisiertes SIG/CAIQ/HECVAT-Paket ist Teil des Produktumfangs)</option>
      <option value="detailed">Detailliert, individueller Sicherheitsfragebogen erforderlich</option>
      <option value="pen_test">Penetrationstest-Bericht erforderlich</option>
      <option value="on_site">Vor-Ort-Audit oder Architektur-Review erforderlich</option>
      <option value="none">In dieser Phase keine Sicherheitsprüfung erforderlich</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="additional-context" class="apex-label">Zusätzlicher Kontext</label>
    <textarea id="additional-context" name="additional_context" rows="4" maxlength="2000"
      placeholder="Konkrete Integrationsanforderungen, Migrationspläne, Sicherheitsarchitektur-Bedarf oder sonstiger Kontext, der uns hilft, die richtige Empfehlung vorzubereiten."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Anfrage senden
    </button>
  </div>
  <p class="apex-footnote">Mit dem Absenden dieses Formulars akzeptieren Sie unsere <a href="/de/privacy/">Datenschutzerklärung</a>. Wir verwenden Ihre Angaben ausschließlich zur Beantwortung Ihrer Anfrage (DSGVO Art. 13).</p>
</form>

## Wie es weitergeht

Nach dem Absenden prüft unser Enterprise-Team Ihre Anforderungen und antwortet innerhalb von 2 Werktagen mit einem empfohlenen Bereitstellungsmodell, indikativen Preisen und den nächsten Schritten für ein strukturiertes Architektur-Review.

Für zeitkritische Beschaffungsgespräche senden Sie eine E-Mail an [support@apexmail.ee](mailto:support@apexmail.ee) mit dem Betreff "Urgent: Sales Enquiry" und geben Sie Ihr monatliches Volumen sowie Ihre bevorzugte Bereitstellung an.
