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

<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Company <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Your organisation name" />
  </div>

  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Work Email <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="you@company.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div>
      <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Monthly Email Volume <span class="text-red-500">*</span></label>
      <select id="monthly-volume" name="monthly_volume" required
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
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

    <div>
      <label for="peak-hourly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Peak Hourly Volume</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume"
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
        placeholder="e.g. 50,000 per hour" />
    </div>
  </div>

  <div>
    <label for="current-provider" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Current Provider</label>
    <select id="current-provider" name="current_provider"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
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

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Deployment Preference</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="shared" checked class="accent-brand-500" />
        <span><strong>Shared Cloud</strong> — Multi-tenant EU infrastructure</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="dedicated" class="accent-brand-500" />
        <span><strong>Dedicated Tenant</strong> — Single-tenant isolated infrastructure</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Private Deployment</strong> — Managed deployment in your cloud account</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="not_sure" class="accent-brand-500" />
        <span><strong>Not sure yet</strong> — Need guidance on the best model</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Compliance Requirements <span class="text-xs font-normal text-surface-400 normal-case tracking-normal">(select all that apply)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="gdpr" class="accent-brand-500" />
        <span>GDPR / data-residency deployment review</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="hipaa" class="accent-brand-500" />
        <span>HIPAA use case (not currently offered; discuss alternatives)</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="soc2" class="accent-brand-500" />
        <span>SOC 2 / ISO 27001 evidence</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="ccpa" class="accent-brand-500" />
        <span>CCPA / US state privacy laws</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="fedramp" class="accent-brand-500" />
        <span>FedRAMP / Government</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="regional_residency" class="accent-brand-500" />
        <span>Specific regional data residency requirement</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="dpf" class="accent-brand-500" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="target-timeline" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Target Timeline</label>
    <select id="target-timeline" name="target_timeline"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Select timeline</option>
      <option value="immediate">Immediate (within 2 weeks)</option>
      <option value="30_days">Within 30 days</option>
      <option value="90_days">Within 90 days</option>
      <option value="6_months">Within 6 months</option>
      <option value="exploring">Exploring options — no fixed timeline</option>
    </select>
  </div>

  <div>
    <label for="security-review" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Security Review Needs</label>
    <select id="security-review" name="security_review_needs"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Select review level</option>
      <option value="standard">Standard — SIG/CAIQ/HECVAT packs sufficient</option>
      <option value="detailed">Detailed — Custom security questionnaire required</option>
      <option value="pen_test">Penetration test report required</option>
      <option value="on_site">On-site audit or architecture review required</option>
      <option value="none">No security review required at this stage</option>
    </select>
  </div>

  <div>
    <label for="additional-context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Additional Context</label>
    <textarea id="additional-context" name="additional_context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Specific integration requirements, migration plans, security architecture needs, or any other context that helps us prepare the right recommendation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Submit Enquiry
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
</form>

## What Happens Next

After submission, our enterprise team reviews your requirements and responds within 2 business days with a recommended deployment model, indicative pricing, and next steps for a structured architecture review.

For time-sensitive procurement discussions, email [support@apexmail.ee](mailto:support@apexmail.ee) with the subject line "Urgent: Sales Enquiry" and include your monthly volume and deployment preference.
