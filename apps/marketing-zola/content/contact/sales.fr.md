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

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status" hidden>
  <b>Reçue</b>
  <p>Merci — votre demande a bien été reçue. Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert" hidden>
  <b>Non acceptée</b>
  <p>Votre demande n'a pas pu être acceptée. Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="fr" />
  <div class="apex-field">
    <label for="company" class="apex-label">Entreprise <span class="">*</span></label>
    <input type="text" id="company" name="company" required maxlength="200"
      class="apex-input"
      placeholder="Nom de votre organisation" />
  </div>

  <div class="apex-field">
    <label for="work-email" class="apex-label">Email professionnel <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="vous@entreprise.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div class="apex-field">
      <label for="monthly-volume" class="apex-label">Volume d'emails mensuel <span class="">*</span></label>
      <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
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
    </div>

    <div class="apex-field">
      <label for="peak-hourly-volume" class="apex-label">Pic de volume horaire</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume" maxlength="200"
        class="apex-input"
        placeholder="ex. 50 000 par heure" />
    </div>
  </div>

  <div class="apex-field">
    <label for="current-provider" class="apex-label">Fournisseur actuel</label>
    <div class="apex-select-wrap">
      <select id="current-provider" name="current_provider">
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
  </div>

  <fieldset class="border p-4">
    <legend class="px-2">Préférence de déploiement</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="shared" checked />
        <span><strong>Cloud mutualisé</strong> — Infrastructure UE multi-tenant</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="dedicated" />
        <span><strong>Tenance dédiée</strong> — Infrastructure isolée mono-tenant</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="byoc" />
        <span><strong>BYOC / Déploiement privé</strong> — Déploiement géré dans votre compte cloud</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="not_sure" />
        <span><strong>Pas encore décidé</strong> — Besoin d'aide pour choisir le bon modèle</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border p-4">
    <legend class="px-2">Exigences de conformité <span class="">(cochez tout ce qui s'applique)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="gdpr" />
        <span>RGPD / revue de déploiement pour la résidence des données</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="hipaa" />
        <span>Cas d'usage HIPAA (non proposé actuellement ; discuter des alternatives)</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="ccpa" />
        <span>CCPA / lois américaines sur la vie privée des États</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="fedramp" />
        <span>FedRAMP / Secteur public</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="regional_residency" />
        <span>Exigence spécifique de résidence régionale des données</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="dpf" />
        <span>EU-US Data Privacy Framework</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="target-timeline" class="apex-label">Calendrier visé</label>
    <div class="apex-select-wrap">
      <select id="target-timeline" name="target_timeline">
      <option value="" selected>Sélectionnez un calendrier</option>
      <option value="immediate">Immédiat (sous 2 semaines)</option>
      <option value="30_days">Sous 30 jours</option>
      <option value="90_days">Sous 90 jours</option>
      <option value="6_months">Sous 6 mois</option>
      <option value="exploring">En exploration — pas de calendrier fixe</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="security-review" class="apex-label">Besoins de revue de sécurité</label>
    <div class="apex-select-wrap">
      <select id="security-review" name="security_review_needs">
      <option value="" selected>Sélectionnez le niveau de revue</option>
      <option value="standard">Standard — questionnaire de sécurité traité au cas par cas à partir du matériel de revue actuel (aucun pack SIG/CAIQ/HECVAT standardisé n'est inclus dans l'offre)</option>
      <option value="detailed">Détaillé — questionnaire de sécurité personnalisé requis</option>
      <option value="pen_test">Rapport de test d'intrusion requis</option>
      <option value="on_site">Audit sur site ou revue d'architecture requis</option>
      <option value="none">Aucune revue de sécurité requise à ce stade</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="additional-context" class="apex-label">Contexte complémentaire</label>
    <textarea id="additional-context" name="additional_context" rows="4" maxlength="2000"
      placeholder="Exigences d'intégration spécifiques, plans de migration, besoins d'architecture de sécurité ou tout autre contexte nous aidant à préparer la bonne recommandation."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Envoyer la demande
    </button>
  </div>
  <p class="apex-footnote">En envoyant ce formulaire, vous acceptez notre <a href="/fr/privacy/">politique de confidentialité</a>. Nous utilisons ces informations uniquement pour répondre à votre demande (RGPD art. 13).</p>
</form>

## Les étapes suivantes

Après l'envoi, notre équipe Enterprise examine vos exigences et répond sous 2 jours ouvrés avec un modèle de déploiement recommandé, une tarification indicative et les prochaines étapes d'une revue d'architecture structurée.

Pour les discussions d'achat urgentes, écrivez à [support@apexmail.ee](mailto:support@apexmail.ee) avec l'objet « Urgent: Sales Enquiry » en précisant votre volume mensuel et votre préférence de déploiement.
