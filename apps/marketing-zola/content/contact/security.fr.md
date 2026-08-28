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

- **SIG / CAIQ / HECVAT** — Réponses standardisées d'évaluation de sécurité pour les clients Enterprise qualifiés.
- **Résumé de test d'intrusion** — Un résumé des constats et des mesures de correction sera disponible après la réalisation du premier test d'intrusion externe de l'application.
- **Mappage des contrôles SOC 2** — Documentation de mappage des critères SOC 2 Trust Services Criteria et d'évaluation de préparation (note : ApexMail n'est pas actuellement certifié SOC 2).
- **Revue d'architecture de sécurité** — Présentation détaillée des contrôles de sécurité d'ApexMail, de l'architecture de chiffrement, de la journalisation d'audit et des modèles d'isolation de déploiement.
- **Diagrammes de flux de données** — Documentation visuelle du traitement des données, des lieux de stockage et des relations entre sous-traitants.

## Formulaire de demande de questionnaire de sécurité

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status">
  <p><strong>Merci — votre demande a bien été reçue.</strong> Notre équipe l'examine et répond sous 2 jours ouvrés.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert">
  <p><strong>Votre demande n'a pas pu être acceptée.</strong> Vérifiez les champs obligatoires (une adresse e-mail professionnelle valide est requise) puis réessayez.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="fr" />
  <div>
    <label for="work-email-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email professionnel <span class="text-red-500">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="vous@entreprise.com" />
  </div>

  <div>
    <label for="company-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Entreprise <span class="text-red-500">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nom de votre organisation" />
  </div>

  <div>
    <label for="document-type" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Documentation demandée <span class="text-red-500">*</span></label>
    <select id="document-type" name="document_type" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" disabled selected>Sélectionnez ce dont vous avez besoin</option>
      <option value="sig">Questionnaire SIG</option>
      <option value="caiq">Questionnaire CAIQ</option>
      <option value="hecvat">Questionnaire HECVAT</option>
      <option value="custom">Questionnaire de sécurité personnalisé</option>
      <option value="pentest">Résumé de test d'intrusion</option>
      <option value="soc2">Mappage des contrôles SOC 2</option>
      <option value="architecture_review">Revue d'architecture de sécurité</option>
      <option value="data_flow">Diagrammes de flux de données</option>
    </select>
  </div>

  <div>
    <label for="nda-status" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Statut du NDA</label>
    <select id="nda-status" name="nda_status"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="not_signed" selected>NDA non encore signé</option>
      <option value="signed">NDA déjà en place</option>
      <option value="willing">Prêt à signer un NDA</option>
    </select>
  </div>

  <div>
    <label for="context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Contexte complémentaire</label>
    <textarea id="context" name="context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Tout cadre de conformité spécifique, exigence réglementaire ou contrainte de calendrier que nous devrions connaître."></textarea>
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

Vous préférez l'email ? Envoyez votre demande de documentation de sécurité à [support@apexmail.ee](mailto:support@apexmail.ee). Précisez le nom de votre entreprise, les documents ou questionnaires spécifiques dont vous avez besoin, et si un NDA est déjà en place ou nécessaire.
