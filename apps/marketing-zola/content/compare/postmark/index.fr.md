+++
title = "ApexMail vs Postmark | Comparatif des fonctionnalités"
description = "Découvrez comment ApexMail se positionne face à Postmark sur la délivrabilité, la conformité, les tarifs et l’expérience développeur."
template = "compare.html"

[extra]
competitor = "Postmark"
competitor_slug = "postmark"
competitor_name = "Postmark"
competitor_description = "Postmark d’ActiveCampaign se concentre sur la livraison d’emails transactionnels rapide et fiable."
pricing_as_of = "2026-08-19"
currency_note = "Les prix sont indiqués en EUR. Lorsqu’un fournisseur publie uniquement en USD, le montant en EUR est converti à 1 USD = €0.92 (taux de référence, 2026-08-19) et le prix USD publié par le fournisseur est affiché entre parenthèses. Hors taxes applicables."
og_image = "/images/og-image.png"
apexmail_wins = 0
competitor_wins = 0

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans and any inline markup. Winner is one of: apexmail | competitor | tie | none.
# Postmark never declares a winner — every row uses winner = "none".
comparison_sections = [
  { title = "DÉLIVRABILITÉ", rows = [
    { feature = "Taux de livraison", apex = '<span class="text-brand-600 font-semibold">Élevé</span>', comp = '<span class="text-surface-600">Élevé</span>', winner = "none" },
    { feature = "Acceptation P95 jusqu’à la première tentative", apex = '<span class="text-brand-600 font-semibold">&le;30s (P95)</span>', comp = '<span class="text-surface-600">Non documenté publiquement</span>', winner = "none" },
    { feature = "IP dédiée", apex = '<span class="text-brand-600 font-semibold">Option additionnelle approuvée sur Pro ; 1 incluse sur Growth, 3 sur Scale</span>', comp = '<span class="text-surface-600">Voir les tarifs du fournisseur</span>', winner = "none" },
    { feature = "Réchauffement IP automatique", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-600">Automatique (géré par Postmark)</span>', winner = "none" },
    { feature = "Support BIMI", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "Support MTA-STS", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" }
  ]},
  { title = "CONFORMITÉ", rows = [
    { feature = "Automatisation RGPD", apex = '<span class="text-brand-600 font-semibold">Traitement complet des DSR</span>', comp = '<span class="text-surface-600">Gestion autonome</span>', winner = "none" },
    { feature = "Disponibilité HIPAA", apex = '<span class="text-surface-600 font-semibold">Non proposée actuellement</span>', comp = '<span class="text-surface-600">Voir la documentation du fournisseur</span>', winner = "none" },
    { feature = "Certification SOC 2", apex = '<span class="text-surface-600 font-semibold">Non proposée actuellement</span>', comp = '<span class="text-surface-600">Voir la documentation du fournisseur</span>', winner = "none" },
    { feature = "Journaux d’audit", apex = '<span class="text-brand-600 font-semibold">Forfait Growth et supérieurs</span>', comp = '<span class="text-surface-600">Journaux d’événements uniquement</span>', winner = "none" },
    { feature = "Gestion du consentement", apex = '<span class="text-brand-600 font-semibold">Intégrée</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "FONCTIONNALITÉS", rows = [
    { feature = "Email transactionnel", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" },
    { feature = "Email marketing", apex = '<span class="text-brand-600 font-semibold">Oui (API unifiée)</span>', comp = '<span class="text-surface-600">Produit distinct</span>', winner = "none" },
    { feature = "Traitement entrant", apex = '<span class="text-brand-600 font-semibold">Forfaits Scale et Enterprise</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" },
    { feature = "Modèles", apex = '<span class="text-brand-600 font-semibold">Modèles stockés</span>', comp = '<span class="text-surface-600">Propriétaires</span>', winner = "none" },
    { feature = "Envoi programmé", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "ENTERPRISE", rows = [
    { feature = "SSO/SAML", apex = '<span class="text-brand-600 font-semibold">Scale et Enterprise</span>', comp = '<span class="text-surface-600">Disponible sur demande</span>', winner = "none" },
    { feature = "Revue de déploiement personnalisé", apex = '<span class="text-brand-600 font-semibold">Revue Enterprise</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "Options de déploiement dédié", apex = '<span class="text-brand-600 font-semibold">Revue personnalisée</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "TARIFS", rows = [
    { feature = "Offre gratuite", apex = '<span class="text-brand-600 font-semibold">30 000/mois</span>', comp = '<span class="text-surface-600">100/mois</span>', winner = "none" },
    { feature = "100K emails/mois", apex = '<span class="text-brand-600 font-semibold">€65 (Pro : 150K)</span>', comp = '<span class="text-surface-600">€122.82 (US$133.50) — Pro : €15.18 (US$16.50)/mois + 90K en dépassement à €1.20 (US$1.30)/1K</span>', winner = "none" },
    { feature = "Membres d’équipe illimités", apex = '<span class="text-brand-600 font-semibold">Forfait Enterprise</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "Conditions Enterprise personnalisées", apex = '<span class="text-brand-600 font-semibold">Contrats annuels</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]}
]

# Trailing methodology paragraph (rendered via macros::methodology_note).
# Raw HTML — the inner <p> content with the methodology link. Uses a TOML
# multi-line basic string (""" """) because the text contains both a single
# quote ("provider's") and double-quoted HTML attributes; the leading \ trims
# the opening newline and literal newlines collapse to spaces per TOML spec.
methodology_note = """\
<strong>Méthodologie :</strong> Les comparaisons de fonctionnalités reposent sur la documentation publiquement disponible, les pages tarifs et les sources officielles. Forfaits comparés : paliers self-service d’ApexMail et forfaits standard de Postmark. Date du relevé tarifaire : 2026-05-09. Dernière vérification : 2026-07-30. Les données peuvent changer ; vérifiez auprès de la documentation actuelle de chaque fournisseur. Consultez notre <a href="/fr/compare/methodology/" class="text-brand-600 hover:text-brand-700 underline">méthodologie de comparaison</a> pour le détail des sources."""
+++

<!-- Comparison rows are rendered from the [extra].comparison_sections array
     by partials/compare/table.html. This body is intentionally empty. -->
