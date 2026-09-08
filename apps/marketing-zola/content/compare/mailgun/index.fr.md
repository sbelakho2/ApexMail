+++
title = "ApexMail vs Mailgun | Comparatif des capacités"
description = "Comparaison factuelle des capacités d'email transactionnel : ApexMail vs Mailgun. Hébergement UE, API, délivrabilité, conformité et modèles de déploiement."
template = "compare.html"

[extra]
noindex = true
competitor = "Mailgun"
competitor_slug = "mailgun"
competitor_name = "Mailgun"
competitor_description = "Mailgun de Sinch est une plateforme de livraison d’emails proposant des API pour envoyer, recevoir et suivre les emails."
last_verified = "2026-07-29"
methodology = "Documentation publique de Mailgun sur mailgun.com/docs, consultée à la date de vérification. Tarifs comparés sur le forfait Foundation 100K. Facturation mensuelle. Les fonctionnalités, limites et tarifs peuvent changer."
volume_assumption = "100 000 emails/mois"
billing_period = "mensuelle"
currency_note = "Les prix sont indiqués en EUR. Lorsqu’un fournisseur publie uniquement en USD, le montant en EUR est converti à 1 USD = €0.92 (taux de référence, 2026-08-19) et le prix USD publié par le fournisseur est affiché entre parenthèses. Hors taxes applicables."
# Feature comparison counts — update when capabilities change
verdict_title = "Ce qui distingue ApexMail de Mailgun"
verdict_points = ["Configuration de déploiement orientée UE/EEE", "Catalogue public actuel (Mailgun publie en USD ; EUR affiché au taux de référence)", "Contrôles d’accès Business et Enterprise", "Journaux d’audit dès le forfait Growth", "Revue d’architecture et de contrat pour les déploiements non standards"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-mgN"> citations. Winner is one
# of: apexmail | competitor | tie | none.
comparison_sections = [
  { title = "TRAITEMENT DES DONNÉES DANS L’EEE", rows = [
    { feature = "Région d’hébergement principale", apex = 'Centres de données UE (Allemagne en primaire, Finlande en sauvegarde) — aucun traitement aux États-Unis pour les données principales', comp = 'États-Unis (région UE disponible sur les forfaits Foundation 50K+ et supérieurs)<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "Traitement des données dans l’EEE par défaut", apex = 'Configuration par défaut orientée UE/EEE ; les lieux actifs sont propres à chaque accord', comp = 'Non — basé aux États-Unis par défaut ; région UE configurée par domaine d’envoi<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "Disponibilité de la DPA", apex = 'Disponible dans le cadre de l’accord ApexMail applicable', comp = 'Disponible — la DPA de Sinch couvre les services Mailgun<sup><a href="#src-mg2">2</a></sup>', winner = "none" }
  ]},
  { title = "CAPACITÉS D’ENVOI", rows = [
    { feature = "API REST", apex = 'Oui — <code>POST /v1/messages</code>', comp = 'Oui — <code>POST /v3/{domain}/messages</code><sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Relais SMTP", apex = 'Oui — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Oui — smtp.mailgun.org:587 (STARTTLS)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Envoi par lots", apex = 'Disponible lorsque cette option est activée pour le forfait souscrit', comp = 'Oui — envoi par lots via <code>recipient-variables</code> avec jusqu’à 1 000 destinataires<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Clés d’idempotence", apex = 'Oui (tous les forfaits) — en-tête <code>Idempotency-Key</code>', comp = 'Non pris en charge — les applications doivent implémenter leur propre logique de déduplication<sup><a href="#src-mg3">3</a></sup>', winner = "apexmail" },
    { feature = "Envoi programmé", apex = 'Disponible lorsque cette option est activée pour le forfait souscrit', comp = 'Oui — paramètre <code>o:deliverytime</code> (format RFC 2822, jusqu’à 3 jours)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Email entrant", apex = 'Forfaits Business et Enterprise', comp = 'Oui — routes entrantes avec transfert, stockage et actions webhook<sup><a href="#src-mg4">4</a></sup>', winner = "none" }
  ]},
  { title = "MODÈLES DE DÉPLOIEMENT", rows = [
    { feature = "Cloud mutualisé", apex = 'Oui (tous les forfaits) — multi-tenant, hébergé dans l’UE', comp = 'Oui (tous les forfaits)<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "IP dédiée", apex = 'Option additionnelle approuvée sur Pro ; 1 incluse sur Growth, 3 sur Scale', comp = 'Disponible en option additionnelle sur le forfait Foundation et au-delà<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Tenance dédiée", apex = 'Soumis à revue d’architecture et de contrat', comp = 'Voir la documentation du fournisseur<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "BYOC / déploiement privé", apex = 'Soumis à revue d’architecture et de contrat', comp = 'Voir la documentation du fournisseur<sup><a href="#src-mg5">5</a></sup>', winner = "none" }
  ]},
  { title = "CONTRÔLES ENTERPRISE", rows = [
    { feature = "SAML SSO", apex = 'Forfaits Business et Enterprise', comp = 'Forfaits Foundation 100K et supérieurs<sup><a href="#src-mg6">6</a></sup>', winner = "none" },
    { feature = "SCIM", apex = 'Forfait Enterprise', comp = 'Non documenté à la date de vérification — provisioning des utilisateurs via l’API Mailgun<sup><a href="#src-mg6">6</a></sup>', winner = "apexmail" },
    { feature = "Journaux d’audit", apex = 'Forfait Growth et supérieurs — activité du compte, usage des clés API, changements de configuration ; consultables, exportables', comp = 'Journaux d’événements accessibles via l’API Events ; rétention variable selon le forfait ; pas de piste d’audit consolidée au niveau du compte<sup><a href="#src-mg7">7</a></sup>', winner = "apexmail" }
  ]},
  { title = "TARIFS À 100K/MOIS (vérifiés le 2026-07-29)", rows = [
    { feature = "Forfait comparé", apex = 'Pro : €65/mois (150 000 emails inclus)', comp = 'Scale : €82.80 (US$90)/mois (100 000 emails inclus)<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Conditions d’usage", apex = 'Voir le catalogue public actuel et le paiement pour les conditions d’usage applicables', comp = 'à partir de €1.20 (US$1.30)/1 000 en dépassement sur Foundation ; tarifs progressifs sur Scale<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Offre gratuite", apex = '30 000 emails/mois', comp = '100 emails/jour (essai Flex — sans carte bancaire)<sup><a href="#src-mg8">8</a></sup>', winner = "apexmail" }
  ]},
  { title = "DOMAINES OÙ MAILGUN EST PLUS FORT", rows = [
    { feature = "Validation d’emails", apex = 'API Email Grader (DNS/SPF/DKIM/DMARC/contenu/réputation)', comp = 'API de validation d’emails dédiée avec validation en temps réel et en masse<sup><a href="#src-mg9">9</a></sup>', winner = "competitor" },
    { feature = "Traitement des emails entrants", apex = 'Emails entrants sur les forfaits Business et Enterprise', comp = 'Routage entrant avec actions de transfert, webhook HTTP et stockage ; inclus sur tous les forfaits<sup><a href="#src-mg4">4</a></sup>', winner = "competitor" },
    { feature = "Sandbox de test d’emails", apex = 'Environnement sandbox avec domaines sandbox et limites de débit', comp = 'Domaine sandbox de test sur tous les forfaits avec identifiants de test distincts<sup><a href="#src-mg3">3</a></sup>', winner = "none" }
  ]}
]

# Sources block (rendered by macros::sources_block via partials/compare/table.html).
# Each entry: { ref = anchor suffix (e.g. "mg1"), n = display number, label, url }.
sources = [
  { ref = "mg1", n = 1, label = "Documentation du centre de données UE de Mailgun", url = "https://www.mailgun.com/eu-data-center/" },
  { ref = "mg2", n = 2, label = "Accord de traitement des données de Mailgun", url = "https://www.mailgun.com/legal/dpa/" },
  { ref = "mg3", n = 3, label = "Référence de l’API d’envoi de Mailgun", url = "https://documentation.mailgun.com/en/latest/api-sending.html" },
  { ref = "mg4", n = 4, label = "Documentation de Mailgun sur les emails entrants", url = "https://documentation.mailgun.com/en/latest/user_manual.html#receiving-forwarding-and-storing-messages" },
  { ref = "mg5", n = 5, label = "Page produits de Mailgun", url = "https://www.mailgun.com/products/" },
  { ref = "mg6", n = 6, label = "Documentation SSO de Mailgun", url = "https://www.mailgun.com/products/sso/" },
  { ref = "mg7", n = 7, label = "Référence de l’API Events de Mailgun", url = "https://documentation.mailgun.com/en/latest/api-events.html" },
  { ref = "mg8", n = 8, label = "Page tarifs de Mailgun", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg9", n = 9, label = "Validation d’emails Mailgun", url = "https://www.mailgun.com/email-validation/" }
]
sources_disclaimer = "Dernière vérification : 2026-08-19. Hypothèse de volume : 100 000 emails/mois, facturation mensuelle. Les prix sont indiqués en EUR. Lorsqu’un fournisseur publie uniquement en USD, le montant en EUR est converti à 1 USD = €0.92 (taux de référence, 2026-08-19) et le prix USD publié par le fournisseur est affiché entre parenthèses. Hors taxes applicables. Révisé par : l’ingénierie marketing d’ApexMail."
+++

<!-- Comparison rows and sources block are rendered from the
     [extra].comparison_sections and [extra].sources arrays by
     partials/compare/table.html. This body is intentionally empty. -->
