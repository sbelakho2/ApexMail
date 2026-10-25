+++
title = "Demande de questionnaire de sécurité"
description = "Demandez la documentation de sécurité ApexMail, les réponses SIG/CAIQ, les résumés de tests d'intrusion ou planifiez une revue d'architecture de sécurité."
template = "prose.html"

[extra]
form_id = "security-contact"
+++

## Demande de questionnaire de sécurité

ApexMail fournit de la documentation de sécurité aux prospects et clients Enterprise qualifiés, sous NDA lorsque nécessaire. Utilisez ce formulaire pour demander les questionnaires SIG, CAIQ, HECVAT ou personnalisés, ou pour planifier une revue d'architecture de sécurité.

## Ce que nous fournissons

- **SIG / CAIQ / HECVAT**, Réponses standardisées d'évaluation de sécurité pour les clients Enterprise qualifiés.
- **Résumé de test d'intrusion**, Un résumé des constats et des mesures de correction sera disponible après la réalisation du premier test d'intrusion externe de l'application.
- **Revue d'architecture de sécurité**, Présentation détaillée des contrôles de sécurité d'ApexMail, de l'architecture de chiffrement, de la journalisation d'audit et des modèles d'isolation de déploiement.
- **Diagrammes de flux de données**, Documentation visuelle du traitement des données, des lieux de stockage et des relations entre sous-traitants.

## Formulaire de demande de questionnaire de sécurité

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Reçue</b>
  <p>Merci, votre demande a bien été reçue. Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>Non acceptée</b>
  <p>Votre demande n'a pas pu être acceptée. Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="fr" />
  <div class="apex-field">
    <label for="work-email-sec" class="apex-label">Email professionnel <span class="">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="vous@entreprise.com" />
  </div>

  <div class="apex-field">
    <label for="company-sec" class="apex-label">Entreprise <span class="">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="apex-input"
      placeholder="Nom de votre organisation" />
  </div>

  <div class="apex-field">
    <label for="document-type" class="apex-label">Documentation demandée <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="document-type" name="document_type" required>
      <option value="" disabled selected>Sélectionnez ce dont vous avez besoin</option>
      <option value="sig">Questionnaire SIG</option>
      <option value="caiq">Questionnaire CAIQ</option>
      <option value="hecvat">Questionnaire HECVAT</option>
      <option value="custom">Questionnaire de sécurité personnalisé</option>
      <option value="pentest">Résumé de test d'intrusion</option>
      <option value="architecture_review">Revue d'architecture de sécurité</option>
      <option value="data_flow">Diagrammes de flux de données</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="nda-status" class="apex-label">Statut du NDA</label>
    <div class="apex-select-wrap">
      <select id="nda-status" name="nda_status">
      <option value="not_signed" selected>NDA non encore signé</option>
      <option value="signed">NDA déjà en place</option>
      <option value="willing">Prêt à signer un NDA</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="context" class="apex-label">Contexte complémentaire</label>
    <textarea id="context" name="context" rows="4"
      placeholder="Tout cadre de conformité spécifique, exigence réglementaire ou contrainte de calendrier que nous devrions connaître."></textarea>
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

Vous pouvez également envoyer votre demande de documentation de sécurité par e-mail à [support@apexmail.ee](mailto:support@apexmail.ee). Précisez le nom de votre entreprise, les documents ou questionnaires spécifiques dont vous avez besoin, et si un NDA est déjà en place ou nécessaire.
