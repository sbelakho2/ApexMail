+++
title = "Enterprise Contact"
description = "Request an enterprise deployment review, pricing discussion, or private cloud assessment with the ApexMail team."
template = "page.html"

[extra]
form_id = "enterprise-contact"
+++

# Enterprise Contact

For organisations evaluating ApexMail Enterprise Shared, Dedicated Tenant, or BYOC deployments, use this form or email [support@apexmail.ee](mailto:support@apexmail.ee) directly.

## What to Expect

After you submit the form, our enterprise team reviews your requirements and responds within 2 business days with a recommended deployment model, indicative pricing, and next steps for a structured architecture review.

## Enterprise Enquiry Form

<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Work Email <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Company <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Your organisation name" />
  </div>

  <div>
    <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Approximate Monthly Email Volume <span class="text-red-500">*</span></label>
    <select id="monthly-volume" name="monthly_volume" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
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

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Deployment Model</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="shared" checked class="accent-brand-500" />
        <span><strong>Shared Cloud</strong> — Multi-tenant EU infrastructure</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="dedicated" class="accent-brand-500" />
        <span><strong>Dedicated Tenant</strong> — Single-tenant isolated infrastructure (from €4,000/mo)</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Private Deployment</strong> — Managed deployment in your cloud account (from €6,500/mo)</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="requirements" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Requirements & Context</label>
    <textarea id="requirements" name="requirements" rows="5"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Compliance requirements, data residency needs, current provider, migration timeline, specific features needed, or any other context that helps us prepare the right recommendation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Submit Enquiry
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
</form>

## Direct Contact

Prefer email? Reach the enterprise team at [support@apexmail.ee](mailto:support@apexmail.ee). Include your monthly volume, deployment model preference, and any compliance requirements to help us prepare before the first call.
