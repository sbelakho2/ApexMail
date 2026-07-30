+++
title = "Divulgation responsable"
description = "Politique de divulgation responsable d'ApexMail — comment signaler les vulnérabilités de sécurité."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 1. Politique

ApexMail prend au sérieux la sécurité de nos systèmes et des données de nos clients. Nous accueillons favorablement les signalements de chercheurs en sécurité et du public concernant des vulnérabilités potentielles. Cette politique décrit comment signaler les problèmes de sécurité et ce que vous pouvez attendre de nous.

## 2. Champ d'application

Cette politique s'applique à :

- `apexmail.ee` et tous les sous-domaines
- `api.apexmail.ee`
- `smtp.apexmail.ee`
- `app.apexmail.ee`
- `cdn.apexmail.ee`
- L'API ApexMail et l'application web

Les services non exploités par ApexMail (par exemple, les intégrations tierces) sont hors champ, sauf si la vulnérabilité concerne notre intégration avec ce service.

## 3. Comment signaler

Envoyez les rapports de vulnérabilité à **[security@apexmail.ee](mailto:security@apexmail.ee)** .

Veuillez inclure :

- Une description détaillée de la vulnérabilité.
- Les étapes pour la reproduire, y compris tout code de preuve de concept.
- Le domaine, le point de terminaison ou le composant concerné.
- Votre évaluation de l'impact potentiel.
- Toute suggestion de correction.

Chiffrez les rapports sensibles à l'aide de notre [clé PGP](/pgp-key.txt).

## 4. Ce que nous promettons

- Accuser réception dans les **48 heures**.
- Fournir une évaluation initiale dans les **5 jours ouvrés**.
- Vous tenir informé de l'avancement vers la résolution.
- Ne pas engager de poursuites judiciaires contre les chercheurs qui respectent cette politique.
- Créditer les chercheurs qui signalent des vulnérabilités valides (sauf si vous préférez rester anonyme).

## 5. Ce que nous demandons

- Ne pas accéder, modifier ou supprimer des données qui ne vous appartiennent pas.
- Ne pas dégrader le service ni perturber les autres utilisateurs.
- Ne pas divulguer publiquement la vulnérabilité avant que nous ayons eu un délai raisonnable pour la traiter (objectif : 90 jours).
- Ne pas tester la sécurité physique, l'ingénierie sociale ou le déni de service.

## 6. Reconnaissance

Nous reconnaissons et remercions les chercheurs en sécurité qui nous aident à nous améliorer. Les signalements de vulnérabilités valides sont reconnus sur cette page (avec le consentement du rapporteur).

## 7. Hors champ

Les éléments suivants sont généralement considérés comme hors champ mais seront examinés :

- Problèmes sans impact de sécurité clair.
- En-têtes de sécurité HTTP manquants qui ne présentent pas de risque direct.
- Self-XSS ou attaques nécessitant un accès physique à l'appareil d'une victime.
- Vulnérabilités théoriques sans preuve de concept.
