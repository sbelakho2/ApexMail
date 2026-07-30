+++
title = "Security Questionnaire Request"
description = "Request ApexMail security documentation, SIG/CAIQ responses, penetration test summaries, or schedule a security architecture review."
template = "page.html"

[extra]
form_id = "security-contact"
+++

# Security Questionnaire Request

ApexMail provides security documentation to qualified Enterprise prospects and customers under NDA where required. Use this form to request SIG, CAIQ, HECVAT, or custom security questionnaires, or to schedule a security architecture review.

## What We Provide

- **SIG / CAIQ / HECVAT** — Standardised security assessment responses for qualified Enterprise customers.
- **Penetration test summary** — A summary of findings and remediation will be available after the first external application penetration test is completed.
- **SOC 2 control mapping** — SOC 2 Trust Services Criteria control mapping and readiness assessment documentation (note: ApexMail is not currently SOC 2 certified).
- **Security architecture review** — A walkthrough of ApexMail's security controls, encryption architecture, audit logging, and deployment isolation models.
- **Data flow diagrams** — Visual documentation of data processing, storage locations, and subprocessor relationships.

## Security Questionnaire Request Form

<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <div>
    <label for="work-email-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Work Email <span class="text-red-500">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div>
    <label for="company-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Company <span class="text-red-500">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Your organisation name" />
  </div>

  <div>
    <label for="document-type" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Documentation Requested <span class="text-red-500">*</span></label>
    <select id="document-type" name="document_type" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" disabled selected>Select what you need</option>
      <option value="sig">SIG Questionnaire</option>
      <option value="caiq">CAIQ Questionnaire</option>
      <option value="hecvat">HECVAT Questionnaire</option>
      <option value="custom">Custom Security Questionnaire</option>
      <option value="pentest">Penetration Test Summary</option>
      <option value="soc2">SOC 2 Control Mapping</option>
      <option value="architecture_review">Security Architecture Review</option>
      <option value="data_flow">Data Flow Diagrams</option>
    </select>
  </div>

  <div>
    <label for="nda-status" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">NDA Status</label>
    <select id="nda-status" name="nda_status"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="not_signed" selected>NDA not yet signed</option>
      <option value="signed">NDA already in place</option>
      <option value="willing">Willing to sign NDA</option>
    </select>
  </div>

  <div>
    <label for="context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Additional Context</label>
    <textarea id="context" name="context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Any specific compliance framework, regulatory requirements, or timeline constraints we should know about."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Submit Request
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
</form>

## Direct Contact

Prefer email? Send your security documentation request to [support@apexmail.ee](mailto:support@apexmail.ee). Include your company name, the specific documents or questionnaires you need, and whether an NDA is already in place or needed.
