+++
title = "Talk to Sales"
description = "Discuss enterprise rollout plans, compliance requirements, and private cloud deployment options with ApexMail."
template = "prose.html"

[extra]
form_id = "sales-contact"
+++

## Talk to Sales

For enterprise buying, security review, or private-cloud planning, complete the form below. Our team reviews submissions and responds within 2 business days.

## Sales Enquiry Form

<!-- Status banners: hidden by default. The api-server PRG flow unhides the
     matching one via a signed single-minute flash cookie after the redirect;
     before that flow runs they must not render as if a submission happened. -->
<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status" hidden>
  <b>Received</b>
  <p>Thank you — your submission was received. Our team reviews submissions and responds within 2 business days.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert" hidden>
  <b>Not accepted</b>
  <p>We could not accept your submission. Please check the required fields (a valid work email is required) and try again.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="en" />
  <div class="apex-field">
    <label for="company" class="apex-label">Company <span class="">*</span></label>
    <input type="text" id="company" name="company" required maxlength="200"
      class="apex-input"
      placeholder="Your organisation name" />
  </div>

  <div class="apex-field">
    <label for="work-email" class="apex-label">Work Email <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div class="apex-field">
      <label for="monthly-volume" class="apex-label">Monthly Email Volume <span class="">*</span></label>
      <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
        <option value="" disabled selected>Select volume range</option>
        <option value="lt_50k">Under 50,000</option>
        <option value="50k_150k">50,000 – 150,000</option>
        <option value="150k_500k">150,000 – 500,000</option>
        <option value="500k_2m">500,000 – 2 million</option>
        <option value="2m_5m">2 million – 5 million</option>
        <option value="5m_10m">5 million – 10 million</option>
        <option value="10m_plus">10 million+</option>
      </select>
    </div>
    </div>

    <div class="apex-field">
      <label for="peak-hourly-volume" class="apex-label">Peak Hourly Volume</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume" maxlength="200"
        class="apex-input"
        placeholder="e.g. 50,000 per hour" />
    </div>
  </div>

  <div class="apex-field">
    <label for="current-provider" class="apex-label">Current Provider</label>
    <div class="apex-select-wrap">
      <select id="current-provider" name="current_provider">
      <option value="" selected>Select current provider (if any)</option>
      <option value="sendgrid">SendGrid (Twilio)</option>
      <option value="postmark">Postmark (ActiveCampaign)</option>
      <option value="mailgun">Mailgun (Sinch)</option>
      <option value="ses">Amazon SES</option>
      <option value="resend">Resend</option>
      <option value="mailchimp">Mailchimp / Mandrill</option>
      <option value="brevo">Brevo (Sendinblue)</option>
      <option value="other">Other provider</option>
      <option value="none">No current provider</option>
      <option value="multiple">Multiple providers</option>
    </select>
    </div>
  </div>

  <fieldset class="border p-4">
    <legend class="px-2">Deployment Preference</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" name="deployment_preference" value="shared" checked />
        <span><strong>Shared Cloud</strong> — Multi-tenant EU infrastructure</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_preference" value="dedicated" />
        <span><strong>Dedicated Tenant</strong> — Single-tenant isolated infrastructure</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_preference" value="byoc" />
        <span><strong>BYOC / Private Deployment</strong> — Managed deployment in your cloud account</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_preference" value="not_sure" />
        <span><strong>Not sure yet</strong> — Need guidance on the best model</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border p-4">
    <legend class="px-2">Compliance Requirements <span class="">(select all that apply)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="gdpr" />
        <span>GDPR / data-residency deployment review</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="hipaa" />
        <span>HIPAA use case (not currently offered; discuss alternatives)</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="ccpa" />
        <span>CCPA / US state privacy laws</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="fedramp" />
        <span>FedRAMP / Government</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="regional_residency" />
        <span>Specific regional data residency requirement</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="dpf" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="target-timeline" class="apex-label">Target Timeline</label>
    <div class="apex-select-wrap">
      <select id="target-timeline" name="target_timeline">
      <option value="" selected>Select timeline</option>
      <option value="immediate">Immediate (within 2 weeks)</option>
      <option value="30_days">Within 30 days</option>
      <option value="90_days">Within 90 days</option>
      <option value="6_months">Within 6 months</option>
      <option value="exploring">Exploring options — no fixed timeline</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="security-review" class="apex-label">Security Review Needs</label>
    <div class="apex-select-wrap">
      <select id="security-review" name="security_review_needs">
      <option value="" selected>Select review level</option>
        <option value="standard">Standard — security questionnaire answered case by case from current review material (no standardized SIG/CAIQ/HECVAT pack is a product entitlement)</option>
      <option value="detailed">Detailed — Custom security questionnaire required</option>
      <option value="pen_test">Penetration test report required</option>
      <option value="on_site">On-site audit or architecture review required</option>
      <option value="none">No security review required at this stage</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="additional-context" class="apex-label">Additional Context</label>
    <textarea id="additional-context" name="additional_context" rows="4" maxlength="2000"
      placeholder="Specific integration requirements, migration plans, security architecture needs, or any other context that helps us prepare the right recommendation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Submit Enquiry
    </button>
  </div>
  <p class="apex-footnote">By submitting this form you agree to our <a href="/privacy/">Privacy Policy</a>. We use the details you provide solely to respond to your enquiry, as set out in our GDPR Art. 13 notice at the point of collection.</p>
</form>

## What Happens Next

After submission, our enterprise team reviews your requirements and responds within 2 business days with a recommended deployment model, indicative pricing, and next steps for a structured architecture review.

For time-sensitive procurement discussions, email [support@apexmail.ee](mailto:support@apexmail.ee) with the subject line "Urgent: Sales Enquiry" and include your monthly volume and deployment preference.
