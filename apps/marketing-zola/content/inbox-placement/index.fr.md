+++
title = "Placement en boîte de réception, mesuré"
template = "prose.html"
description = "ApexMail interroge Google Postmaster Tools et Microsoft SNDS toutes les six heures, note la réputation de vos domaines d'envoi et bride automatiquement les envois sortants quand les données disent de ralentir."

[extra]
og_image = "/images/og-image.svg"
+++

## Un placement en boîte de réception adossé aux fournisseurs de messagerie eux-mêmes

La plupart des « tableaux de bord de délivrabilité » relèvent du théâtre des listes témoins. ApexMail lit le
signal **réel** que Gmail et Outlook publient sur votre domaine — et agit
en conséquence.

## Ce que nous mesurons

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-10">
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Google Postmaster Tools</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Réputation du domaine : HIGH / MEDIUM / LOW / BAD</li>
      <li>Réputation IP par IP d'envoi</li>
      <li>Taux de réussite SPF, DKIM, DMARC</li>
      <li>Taux de signalement spam par les utilisateurs</li>
      <li>Taux TLS entrant et sortant</li>
      <li>Répartition des erreurs de livraison</li>
    </ul>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Microsoft SNDS</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Résultat du filtre : GREEN / YELLOW / RED</li>
      <li>Taux de plainte par IP</li>
      <li>Atteintes aux pièges à spam</li>
      <li>Taux d'acceptation par les destinataires</li>
      <li>Retours du Junk Mail Reporting Program (JMRP)</li>
    </ul>
  </div>
</div>

## Comment nous agissons

Toutes les six heures, le planificateur de réputation d'ApexMail :

1. **Récupère** les dernières statistiques pour chaque domaine et chaque IP depuis lesquels vous envoyez.
2. **Note** chacun sur une échelle transparente de 0 à 100 (l'algorithme est dans notre documentation).
3. **Classe** le score : Vert (≥70), Ambre (40–69), Rouge (<40).
4. **Bride** automatiquement les envois sortants vers ce fournisseur :
   - Vert → bridage de 0 % (vitesse maximale)
   - Ambre → bridage de 50 % (report probabiliste)
   - Rouge → bridage de 90 % (quasi-arrêt, alerte envoyée)
5. **Alerte** les bonnes personnes — webhook, email ou Slack — lorsqu'un palier se dégrade.

Quand votre réputation remonte, le bridage se relâche sans intervention humaine.

## Pourquoi cela compte pour vos $100k de MRR

Un seul mauvais envoi massif peut placer un domaine émetteur sur la liste BAD de Gmail pendant 30 jours ou plus.
La plupart des ESP vous annoncent la mauvaise nouvelle au prochain bilan trimestriel.
ApexMail limite le rayon d'impact **au quart de tour** — vos tenants à fort volume
continuent de livrer via des voies propres pendant que le domaine touché refroidit.

## Dérogations de bridage par fournisseur

Les opérateurs peuvent épingler un niveau de bridage (par ex. 100 % pendant deux heures lors d'un incident
connu) sans modification de code. Chaque décision est journalisée avec score, palier et source, à des
fins d'audit et de transparence vis-à-vis des clients.

## Obtenez un instantané de réputation

Nous pouvons auditer votre domaine existant en moins d'une heure — en utilisant les mêmes flux de données
Google et Microsoft que ceux que nous exploitons en production. [Réservez une revue de délivrabilité](/fr/contact/).
