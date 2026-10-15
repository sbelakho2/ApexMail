+++
title = "Guides de migration par fournisseur"
sort_by = "title"
template = "section.html"
transparent = true
description = "Guides de migration par fournisseur pour SendGrid, Mailgun, Postmark et Resend : point d'accès de compatibilité, bascule de l'authentification, correspondance des champs, refus nommés, liste de contrôle DNS, noms d'événements webhook et plan de bascule 10/50/100."
+++

Migrer une intégration d'envoi est, chez ApexMail, un changement d'URL de base. Chaque fournisseur ci-dessous dispose d'une surface de compatibilité qui accepte la forme de requête du fournisseur et la clé API ApexMail dans l'en-tête d'identifiant du fournisseur, puis exécute le chemin d'envoi canonique : vérification du domaine expéditeur, filtres de suppression et de consentement, droits du forfait, registre d'idempotence durable et insertion dans la file.

Chaque guide indique la correspondance des points d'accès, les champs exacts que la surface refuse nommément, ce qui n'est pas relayé, les enregistrements DNS qui changent et qui restent, les noms d'événements webhook à réabonner, et un plan de bascule en six étapes dont le retour arrière est le même changement d'URL de base en sens inverse.
