+++
title = "Security Questionnaire Request"
description = "Request ApexMail security documentation, SIG/CAIQ responses, penetration test summaries, or schedule a security architecture review."
template = "prose.html"

[extra]
form_id = "security-contact"
+++

## Security Questionnaire Request

ApexMail provides security documentation to qualified Enterprise prospects and customers under NDA where required. Use this form to request SIG, CAIQ, HECVAT, or custom security questionnaires, or to schedule a security architecture review.

## What We Provide

- **SIG / CAIQ / HECVAT** — Standardised security assessment responses for qualified Enterprise customers.
- **Penetration test summary** — A summary of findings and remediation will be available after the first external application penetration test is completed.
- **Security architecture review** — A walkthrough of ApexMail's security controls, encryption architecture, audit logging, and deployment isolation models.
- **Data flow diagrams** — Visual documentation of data processing, storage locations, and subprocessor relationships.

## Security Questionnaire Request Form

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Received</b>
  <p>Thank you — your submission was received. Our team reviews submissions and responds within 2 business days.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Not accepted</b>
  <p>We could not accept your submission. Please check the required fields (a valid work email is required) and try again.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="en" />
  <div class="apex-field">
    <label for="work-email-sec" class="apex-label">Work Email <span class="">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="you@company.com" />
  </div>

  <div class="apex-field">
    <label for="company-sec" class="apex-label">Company <span class="">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="apex-input"
      placeholder="Your organisation name" />
  </div>

  <div class="apex-field">
    <label for="document-type" class="apex-label">Documentation Requested <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="document-type" name="document_type" required>
      <option value="" disabled selected>Select what you need</option>
      <option value="sig">SIG Questionnaire</option>
      <option value="caiq">CAIQ Questionnaire</option>
      <option value="hecvat">HECVAT Questionnaire</option>
      <option value="custom">Custom Security Questionnaire</option>
      <option value="pentest">Penetration Test Summary</option>
      <option value="architecture_review">Security Architecture Review</option>
      <option value="data_flow">Data Flow Diagrams</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="nda-status" class="apex-label">NDA Status</label>
    <div class="apex-select-wrap">
      <select id="nda-status" name="nda_status">
      <option value="not_signed" selected>NDA not yet signed</option>
      <option value="signed">NDA already in place</option>
      <option value="willing">Willing to sign NDA</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="context" class="apex-label">Additional Context</label>
    <textarea id="context" name="context" rows="4"
      placeholder="Any specific compliance framework, regulatory requirements, or timeline constraints we should know about."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Submit Request
    </button>
  </div>
  <p class="apex-footnote">By submitting this form you agree to our <a href="/privacy/">Privacy Policy</a>. We use the details you provide solely to respond to your enquiry, as set out in our GDPR Art. 13 notice at the point of collection.</p>
</form>

## Direct Contact

You can also send your security documentation request by email to [support@apexmail.ee](mailto:support@apexmail.ee). Include your company name, the specific documents or questionnaires you need, and whether an NDA is already in place or needed.
