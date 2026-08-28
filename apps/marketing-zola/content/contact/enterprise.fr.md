+++
title = "Contact Enterprise"
description = "Demandez une revue de déploiement Enterprise, une discussion tarifaire ou une évaluation de cloud privé avec l'équipe ApexMail."
template = "prose.html"

[extra]
form_id = "enterprise-contact"
+++

## Contact Enterprise

Pour les organisations qui évaluent les déploiements ApexMail Enterprise Shared, Dedicated Tenant ou BYOC, utilisez ce formulaire ou écrivez directement à [support@apexmail.ee](mailto:support@apexmail.ee).

## Ce à quoi vous attendre

Après l'envoi du formulaire, notre équipe Enterprise examine vos exigences et répond sous 2 jours ouvrés avec un modèle de déploiement recommandé, une tarification indicative et les prochaines étapes d'une revue d'architecture structurée.

## Formulaire de demande Enterprise

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status">
  <p><strong>Merci — votre demande a bien été reçue.</strong> Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert">
  <p><strong>Votre demande n'a pas pu être acceptée.</strong> Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="fr" />
  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email professionnel <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="vous@entreprise.com" />
  </div>

  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Entreprise <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nom de votre organisation" />
  </div>

  <div>
    <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Volume d'emails mensuel approximatif <span class="text-red-500">*</span></label>
    <select id="monthly-volume" name="monthly_volume" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" disabled selected>Sélectionnez une tranche de volume</option>
      <option value="lt_100k">Moins de 100 000</option>
      <option value="100k_500k">100 000 – 500 000</option>
      <option value="500k_1m">500 000 – 1 million</option>
      <option value="1m_5m">1 million – 5 millions</option>
      <option value="5m_10m">5 millions – 10 millions</option>
      <option value="10m_50m">10 millions – 50 millions</option>
      <option value="50m_plus">Plus de 50 millions</option>
    </select>
  </div>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Modèle de déploiement</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="shared" checked class="accent-brand-500" />
        <span><strong>Cloud mutualisé</strong> — Infrastructure UE multi-tenant</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="dedicated" class="accent-brand-500" />
        <span><strong>Tenance dédiée</strong> — Infrastructure isolée mono-tenant, soumise à revue d'architecture et de contrat</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Déploiement privé</strong> — Déploiement géré dans votre compte cloud, soumis à revue d'architecture et de contrat</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="requirements" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Exigences et contexte</label>
    <textarea id="requirements" name="requirements" rows="5"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Exigences de conformité, besoins de résidence des données, fournisseur actuel, calendrier de migration, fonctionnalités spécifiques nécessaires, ou tout autre contexte nous aidant à préparer la bonne recommandation."></textarea>
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

## Contact direct

Vous préférez l'email ? Contactez l'équipe Enterprise à [support@apexmail.ee](mailto:support@apexmail.ee). Précisez votre volume mensuel, votre modèle de déploiement préféré et vos éventuelles exigences de conformité pour nous aider à préparer le premier échange.
