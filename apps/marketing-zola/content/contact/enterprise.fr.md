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

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Reçue</b>
  <p>Merci, votre demande a bien été reçue. Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Non acceptée</b>
  <p>Votre demande n'a pas pu être acceptée. Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="fr" />
  <div class="apex-field">
    <label for="work-email" class="apex-label">Email professionnel <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="vous@entreprise.com" />
  </div>

  <div class="apex-field">
    <label for="company" class="apex-label">Entreprise <span class="">*</span></label>
    <input type="text" id="company" name="company" required
      class="apex-input"
      placeholder="Nom de votre organisation" />
  </div>

  <div class="apex-field">
    <label for="monthly-volume" class="apex-label">Volume d'emails mensuel approximatif <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
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
  </div>

  <fieldset class="border p-4">
    <legend class="px-2">Modèle de déploiement</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="shared" checked />
        <span><strong>Cloud mutualisé</strong>, Infrastructure UE multi-tenant</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="dedicated" />
        <span><strong>Tenance dédiée</strong>, Infrastructure isolée mono-tenant, soumise à revue d'architecture et de contrat</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="byoc" />
        <span><strong>BYOC / Déploiement privé</strong>, Déploiement géré dans votre compte cloud, soumis à revue d'architecture et de contrat</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="requirements" class="apex-label">Exigences et contexte</label>
    <textarea id="requirements" name="requirements" rows="5"
      placeholder="Exigences de conformité, besoins de résidence des données, fournisseur actuel, calendrier de migration, fonctionnalités spécifiques nécessaires, ou tout autre contexte nous aidant à préparer la bonne recommandation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Envoyer la demande
    </button>
  </div>
  <p class="apex-footnote">En envoyant ce formulaire, vous acceptez notre <a href="/fr/privacy/">politique de confidentialité</a>. Nous utilisons ces informations uniquement pour répondre à votre demande (RGPD art. 13).</p>
</form>

## Contact direct

Vous pouvez également contacter l'équipe Enterprise par e-mail à [support@apexmail.ee](mailto:support@apexmail.ee). Précisez votre volume mensuel, votre modèle de déploiement préféré et vos éventuelles exigences de conformité pour nous aider à préparer le premier échange.
