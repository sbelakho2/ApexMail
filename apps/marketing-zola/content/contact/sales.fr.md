+++
title = "Contacter l'équipe commerciale"
description = "Discutez des plans de déploiement Enterprise, des exigences de conformité et des options de cloud privé avec ApexMail."
template = "prose.html"

[extra]
form_id = "sales-contact"
+++

## Contacter l'équipe commerciale

Pour un achat Enterprise, une revue de sécurité ou la planification d'un cloud privé, remplissez le formulaire ci-dessous. Notre équipe examine les demandes et répond sous 2 jours ouvrés.

## Formulaire de demande commerciale

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status" hidden>
  <p><strong>Merci — votre demande a bien été reçue.</strong> Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert" hidden>
  <p><strong>Votre demande n'a pas pu être acceptée.</strong> Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="fr" />
  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Entreprise <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nom de votre organisation" />
  </div>

  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email professionnel <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="vous@entreprise.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div>
      <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Volume d'emails mensuel <span class="text-red-500">*</span></label>
      <select id="monthly-volume" name="monthly_volume" required
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
        <option value="" disabled selected>Sélectionnez une tranche de volume</option>
        <option value="lt_50k">Moins de 50 000</option>
        <option value="50k_150k">50 000 – 150 000</option>
        <option value="150k_500k">150 000 – 500 000</option>
        <option value="500k_2m">500 000 – 1 million</option>
        <option value="2m_5m">1 million – 5 millions</option>
        <option value="5m_10m">5 millions – 10 millions</option>
        <option value="10m_plus">Plus de 10 millions</option>
      </select>
    </div>

    <div>
      <label for="peak-hourly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Pic de volume horaire</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume"
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
        placeholder="ex. 50 000 par heure" />
    </div>
  </div>

  <div>
    <label for="current-provider" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Fournisseur actuel</label>
    <select id="current-provider" name="current_provider"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Sélectionnez le fournisseur actuel (le cas échéant)</option>
      <option value="sendgrid">SendGrid (Twilio)</option>
      <option value="postmark">Postmark (ActiveCampaign)</option>
      <option value="mailgun">Mailgun (Sinch)</option>
      <option value="ses">Amazon SES</option>
      <option value="resend">Resend</option>
      <option value="mailchimp">Mailchimp / Mandrill</option>
      <option value="brevo">Brevo (Sendinblue)</option>
      <option value="other">Autre fournisseur</option>
      <option value="none">Aucun fournisseur actuel</option>
      <option value="multiple">Plusieurs fournisseurs</option>
    </select>
  </div>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Préférence de déploiement</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="shared" checked class="accent-brand-500" />
        <span><strong>Cloud mutualisé</strong> — Infrastructure UE multi-tenant</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="dedicated" class="accent-brand-500" />
        <span><strong>Tenance dédiée</strong> — Infrastructure isolée mono-tenant</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Déploiement privé</strong> — Déploiement géré dans votre compte cloud</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="not_sure" class="accent-brand-500" />
        <span><strong>Pas encore décidé</strong> — Besoin d'aide pour choisir le bon modèle</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Exigences de conformité <span class="text-xs font-normal text-surface-400 normal-case tracking-normal">(cochez tout ce qui s'applique)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="gdpr" class="accent-brand-500" />
        <span>RGPD / revue de déploiement pour la résidence des données</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="hipaa" class="accent-brand-500" />
        <span>Cas d'usage HIPAA (non proposé actuellement ; discuter des alternatives)</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="soc2" class="accent-brand-500" />
        <span>Justificatifs SOC 2 / ISO 27001</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="ccpa" class="accent-brand-500" />
        <span>CCPA / lois américaines sur la vie privée des États</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="fedramp" class="accent-brand-500" />
        <span>FedRAMP / Secteur public</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="regional_residency" class="accent-brand-500" />
        <span>Exigence spécifique de résidence régionale des données</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="dpf" class="accent-brand-500" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="target-timeline" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Calendrier visé</label>
    <select id="target-timeline" name="target_timeline"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Sélectionnez un calendrier</option>
      <option value="immediate">Immédiat (sous 2 semaines)</option>
      <option value="30_days">Sous 30 jours</option>
      <option value="90_days">Sous 90 jours</option>
      <option value="6_months">Sous 6 mois</option>
      <option value="exploring">En exploration — pas de calendrier fixe</option>
    </select>
  </div>

  <div>
    <label for="security-review" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Besoins de revue de sécurité</label>
    <select id="security-review" name="security_review_needs"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Sélectionnez le niveau de revue</option>
      <option value="standard">Standard — questionnaire de sécurité traité au cas par cas à partir du matériel de revue actuel (aucun pack SIG/CAIQ/HECVAT standardisé n'est inclus dans l'offre)</option>
      <option value="detailed">Détaillé — questionnaire de sécurité personnalisé requis</option>
      <option value="pen_test">Rapport de test d'intrusion requis</option>
      <option value="on_site">Audit sur site ou revue d'architecture requis</option>
      <option value="none">Aucune revue de sécurité requise à ce stade</option>
    </select>
  </div>

  <div>
    <label for="additional-context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Contexte complémentaire</label>
    <textarea id="additional-context" name="additional_context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Exigences d'intégration spécifiques, plans de migration, besoins d'architecture de sécurité ou tout autre contexte nous aidant à préparer la bonne recommandation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Envoyer la demande
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
  <p class="form-privacy-note">En envoyant ce formulaire, vous acceptez notre <a href="/fr/privacy/">politique de confidentialité</a>. Nous utilisons ces informations uniquement pour répondre à votre demande (RGPD art. 13).</p>
</form>

## Les étapes suivantes

Après l'envoi, notre équipe Enterprise examine vos exigences et répond sous 2 jours ouvrés avec un modèle de déploiement recommandé, une tarification indicative et les prochaines étapes d'une revue d'architecture structurée.

Pour les discussions d'achat urgentes, écrivez à [support@apexmail.ee](mailto:support@apexmail.ee) avec l'objet « Urgent: Sales Enquiry » en précisant votre volume mensuel et votre préférence de déploiement.
