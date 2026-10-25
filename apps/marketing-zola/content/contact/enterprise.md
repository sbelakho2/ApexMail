+++
title = "Enterprise Contact"
description = "Request an enterprise deployment review, pricing discussion, or private cloud assessment with the ApexMail team."
template = "prose.html"

[extra]
form_id = "enterprise-contact"
+++

## Enterprise Contact

For organisations evaluating ApexMail Enterprise Shared, Dedicated Tenant, or BYOC deployments, use this form or email [support@apexmail.ee](mailto:support@apexmail.ee) directly.

## What to Expect

After you submit the form, our enterprise team reviews your requirements and responds within 2 business days with a recommended deployment model, indicative pricing, and next steps for a structured architecture review.

## Enterprise Enquiry Form

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Received</b>
  <p>Thank you, your submission was received. Our team reviews submissions and responds within 2 business days.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Not accepted</b>
  <p>We could not accept your submission. Please check the required fields (a valid work email is required) and try again.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="en" />
  <div class="apex-field">
    <label for="work-email" class="apex-label">Work Email <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="apex-field">
    <label for="company" class="apex-label">Company <span class="">*</span></label>
    <input type="text" id="company" name="company" required
      class="apex-input"
      placeholder="Your organisation name" />
  </div>

  <div class="apex-field">
    <label for="monthly-volume" class="apex-label">Approximate Monthly Email Volume <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
      <option value="" disabled selected>Select volume range</option>
      <option value="lt_100k">Under 100,000</option>
      <option value="100k_500k">100,000 – 500,000</option>
      <option value="500k_1m">500,000 – 1 million</option>
      <option value="1m_5m">1 million – 5 million</option>
      <option value="5m_10m">5 million – 10 million</option>
      <option value="10m_50m">10 million – 50 million</option>
      <option value="50m_plus">50 million+</option>
    </select>
    </div>
  </div>

  <fieldset class="apex-block apex-block--tight">
    <legend class="px-2">Deployment Model</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="shared" checked />
        <span><strong>Shared Cloud</strong>, Multi-tenant EU infrastructure</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="dedicated" />
        <span><strong>Dedicated Tenant</strong>, Single-tenant isolated infrastructure, subject to architecture and contract review</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="byoc" />
        <span><strong>BYOC / Private Deployment</strong>, Managed deployment in your cloud account, subject to architecture and contract review</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="requirements" class="apex-label">Requirements & Context</label>
    <textarea id="requirements" name="requirements" rows="5"
      placeholder="Compliance requirements, data residency needs, current provider, migration timeline, specific features needed, or any other context that helps us prepare the right recommendation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Submit Enquiry
    </button>
  </div>
  <p class="apex-footnote">By submitting this form you agree to our <a href="/privacy/">Privacy Policy</a>. We use the details you provide solely to respond to your enquiry, as set out in our GDPR Art. 13 notice at the point of collection.</p>
</form>

## Direct Contact

You can also reach the enterprise team by email at [support@apexmail.ee](mailto:support@apexmail.ee). Include your monthly volume, deployment model preference, and any compliance requirements to help us prepare before the first call.
