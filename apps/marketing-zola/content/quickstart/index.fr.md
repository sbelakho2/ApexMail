+++
title = "Démarrage rapide | Guide développeur ApexMail"
description = "Envoyez votre premier email avec l'API ApexMail en moins de 10 minutes. Guide étape par étape avec exemples de code pour cURL et les SDK officiels."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
og_image = "/images/og-image.png"
+++

Ce guide vous mène de zéro à un domaine d'envoi vérifié et à votre premier email livré. Chaque étape inclut le chemin exact de l'interface, des exemples de code, les résultats attendus et les cas d'erreur courants.

**Temps total estimé :** 8–10 minutes pour un développeur familier avec DNS et les API REST.

**Note linguistique :** la documentation développeur (`/docs/`) et l'API Explorer liés dans ce guide ne sont disponibles qu'en anglais pour le moment.

---

## Étape 1 : Créer un compte

**Temps :** ~30 secondes

Accédez à [app.apexmail.ee/signup](https://app.apexmail.ee/signup).

**Ce dont vous avez besoin :** Une adresse email et un mot de passe (minimum 12 caractères). Aucune carte bancaire requise.

**Bouton :** Cliquez sur **Create Free Account**.

**Ce qui se passe :** Vous recevez un email de vérification à l'adresse fournie.

**Résultat attendu :** Redirection vers le tableau de bord avec une bannière invitant à vérifier l'email.

**Cas d'erreur :**
- **`Email already registered`** : Utilisez le flux de réinitialisation de mot de passe sur [app.apexmail.ee/reset-password](https://app.apexmail.ee/reset-password).
- **`Password too weak`** : Utilisez 15+ caractères (les phrases de passe plus longues conviennent — aucun mélange de symboles ou de chiffres n'est requis). Évitez les mots de passe courants et les motifs simples de répétition/séquence.

---

## Étape 2 : Vérifier l'email du compte

**Temps :** ~30 secondes

Ouvrez l'email de vérification envoyé à votre adresse enregistrée.

**Objet :** `Verify your ApexMail account`

**Bouton :** Cliquez sur **Verify Email Address**.

**Ce qui se passe :** Votre compte est activé. La bannière du tableau de bord disparaît.

**Résultat attendu :** Les sections **API Keys** et **Domains** deviennent accessibles dans la barre latérale du tableau de bord.

**Dépannage :**
- Vérifiez le dossier spam/indésirables.
- Si aucun email n'arrive dans les 2 minutes, cliquez sur **Resend Verification** dans la bannière du tableau de bord.
- Ajoutez `noreply@apexmail.ee` à vos contacts pour éviter les problèmes de livraison futurs.

---

## Étape 3 : Créer une clé API

**Temps :** ~30 secondes

Dans la barre latérale du tableau de bord, accédez à **Settings → API Keys**.

**Chemin :** Barre latérale du tableau de bord → `Settings` → `API Keys`

**Bouton :** Cliquez sur **Create API Key**.

**Champs à remplir :**
- **Nom de la clé :** p. ex. `Quickstart Key`
- **Scopes :** Sélectionnez au minimum `messages:write` et `messages:read`
- **Expiration :** Laissez `Never` pour le développement

**Ce qui se passe :** Une nouvelle clé API est générée et affichée une seule fois.

**Avertissement de sécurité :** Copiez la clé immédiatement. Elle ne sera plus affichée. Stockez-la dans un gestionnaire de mots de passe ou une variable d'environnement — ne la commitez jamais dans le contrôle de version.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Résultat attendu :** La clé apparaît dans votre liste de clés API avec le statut `Active`.

---

## Étape 4 : Ajouter un domaine d'envoi

**Temps :** ~1 minute

Accédez à **Settings → Domains** dans la barre latérale du tableau de bord.

**Chemin :** Barre latérale du tableau de bord → `Settings` → `Domains`

**Bouton :** Cliquez sur **Add Domain**.

**Champ :** Saisissez votre domaine d'envoi (p. ex. `mail.example.com` ou `example.com`).

**Ce qui se passe :** ApexMail génère des enregistrements DNS de vérification et les affiche à l'écran.

**Résultat attendu :** Le domaine apparaît dans votre liste de domaines avec le statut `Pending Verification` et les enregistrements DNS sont affichés.

**Note de sécurité :** Utilisez un sous-domaine (p. ex. `mail.example.com`) pour l'email transactionnel afin d'isoler la réputation d'envoi de votre domaine principal.

---

## Étape 5 : Ajouter des enregistrements MAIL FROM personnalisés

**Temps :** ~2 minutes (la propagation DNS peut prendre jusqu'à 48 heures, mais généralement 5–30 minutes)

Connectez-vous à la console de gestion de votre fournisseur DNS et copiez les deux enregistrements `bounce` affichés dans les paramètres de domaine (ou renvoyés par l'API d'enregistrements DNS) : un enregistrement TXT SPF contenant `include:amazonses.com` et un enregistrement MX avec la priorité `10` pointant vers `feedback-smtp.<aws-region>.amazonses.com`.

**Ce que cela fait :** Configure le domaine MAIL FROM personnalisé utilisé pour l'alignement SPF et la gestion des rebonds.

**Résultat attendu :** Après la propagation DNS, les vérifications SPF et return-path dans le panneau d'état du domaine affichent `verified`.

---

## Étape 6 : Ajouter des enregistrements DKIM

**Temps :** ~2 minutes

Copiez l'enregistrement DKIM **TXT** généré affiché dans les paramètres de domaine. Le nom d'hôte est `<selector>._domainkey.<your-domain>` et la valeur commence par `v=DKIM1; k=rsa; p=`. Le sélecteur et la clé publique sont spécifiques au domaine ; l'enregistrement généré dans le tableau de bord est la seule source prise en charge.

**Ce que cela fait :** Permet à ApexMail de signer cryptographiquement les messages sortants, permettant aux serveurs récepteurs de vérifier l'intégrité du message et l'authenticité de l'expéditeur.

**Résultat attendu :** Après la propagation DNS, la vérification DKIM dans le panneau d'état du domaine affiche `verified`.

**Dépannage :**
- Assurez-vous d'ajouter les enregistrements dans la bonne zone DNS (le domaine ajouté à l'étape 4).
- DKIM est un enregistrement TXT, pas un CNAME. N'ajoutez pas de CNAME Easy-DKIM ou d'hôte de service ApexMail.
- Utilisez le sélecteur exact affiché dans les paramètres de domaine lors de la vérification DNS avec `dig`.

---

## Étape 7 : Vérifier le domaine

**Temps :** ~1 minute (après la propagation DNS)

Revenez à la page **Settings → Domains** dans le tableau de bord.

**Bouton :** Cliquez sur **Verify** à côté de votre domaine.

**Ce qui se passe :** ApexMail vérifie les enregistrements SPF/MX du MAIL FROM personnalisé, la clé publique DKIM exacte et DMARC. En mode SES, il attend également que SES signale que l'identité BYODKIM et le domaine MAIL FROM personnalisé sont prêts.

**Résultat attendu :** L'état du domaine affiche `Verified` avec des coches vertes pour SPF, DKIM, DMARC et return path. La vérification SES peut rester en attente pendant qu'AWS détecte les enregistrements DNS nouvellement publiés.

**Cas d'erreur :**
- **`SPF record not found`** : Vérifiez que l'hôte est `bounce.<yourdomain>`, pas l'apex du domaine.
- **`DKIM selector not found`** : Vérifiez que le nom d'hôte TXT généré et la clé publique `p=` complète sont exacts.
- **`Verification timeout`** : Le DNS est peut-être encore en cours de propagation. Attendez 5 minutes et réessayez.

---

## Étape 8 : Installer le SDK ou préparer cURL

**Temps :** ~1 minute

Choisissez votre méthode d'intégration :

### Option A : SDK (compiler depuis les sources)

> **Pas encore sur les registres publics.** Les SDK ApexMail **ne sont pas encore publiés sur PyPI, pkg.go.dev, Packagist, RubyGems ni Maven Central** — `pip install apexmail`, `go get github.com/apexmail/apexmail-go` et `composer require apexmail/apexmail-php` échoueront jusqu'à la première version stable. D'ici là, installez depuis les sources du monorepo et épinglez un commit spécifique, et **vérifiez la source que vous intégrez** avant de livrer. Voir [SDKs](/docs/sdks/) pour l'état par langage.

Le code source du SDK est actuellement privé et disponible pour les clients d'aperçu approuvés pendant que les paquets sont préparés pour leur première publication sur un registre public — écrivez à [support@apexmail.ee](mailto:support@apexmail.ee) (ou à votre responsable de compte) et vous recevrez le dépôt de code source épinglé pour votre langage, avec une somme de contrôle, sous la licence du SDK. Chaque répertoire de SDK contient ses propres instructions de compilation et de test.

**Python** (`packages/sdk-python` — installez depuis le chemin local, ou intégrez le répertoire) :

```bash
pip install ./packages/sdk-python
```

**Go** (`packages/sdk-go` — épinglez le module aux sources intégrées avec une directive `replace`) :

```bash
go mod edit -replace github.com/apexmail/apexmail-go=./packages/sdk-go
go mod tidy
```

**PHP** (`packages/sdk-php` — pointez Composer vers le répertoire local) :

```bash
composer config repositories.apexmail path ./packages/sdk-php
composer require apexmail/apexmail-php:@dev
```

**Ruby** (`packages/sdk-ruby`) et **Java** (`packages/sdk-java`) : compilez depuis le répertoire du monorepo ; le README de chaque paquet contient ses instructions de compilation et de test.

### Option B : cURL (test rapide)

Aucune installation requise — utilisez le terminal :

```bash
# Verify your key works
curl -s https://api.apexmail.ee/v1/account \
  -H "X-API-Key: $APEXMAIL_API_KEY" | head -c 200
```

**Résultat attendu :** Une réponse JSON contenant les informations de votre compte et les détails du forfait.

---

## Étape 9 : Envoyer votre premier email de test

**Temps :** ~30 secondes

Avec votre domaine vérifié et votre clé API :

**cURL :**
```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: test-$(date +%s)" \
  -d '{
    "from": "hello@yourdomain.com",
    "to": ["your-email@example.com"],
    "subject": "Hello from ApexMail Quickstart",
    "text": "Your first transactional email via ApexMail!",
    "html": "<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
    "type": "transactional"
  }'
```

**SDK Python :**
```python
import os
from apexmail import ApexMail

client = ApexMail(api_key=os.environ["APEXMAIL_API_KEY"])

response = client.emails.send(
    from_="hello@yourdomain.com",
    to="your-email@example.com",
    subject="Hello from ApexMail Quickstart",
    text="Your first transactional email via ApexMail!",
    html="<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
)

print(f"Email queued! ID: {response.id}")
```

**Réponse attendue :**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "queued",
  "created_at": "2026-07-29T19:00:00Z"
}
```

**Ce qui se passe :** Le message est accepté dans la file de livraison. Le statut passe de `queued` → `processed` → `sent` → `delivered`.

**Cas d'erreur :**
- **`401 Unauthorized`** : La clé API est manquante ou incorrecte. Vérifiez que `$APEXMAIL_API_KEY` est définie.
- **`403 Forbidden`** : La clé API n'a pas le scope `messages:write`. Recréez la clé avec le bon scope.
- **`400 domain_not_verified`** : Votre domaine d'envoi n'est pas encore vérifié. Revenez à l'étape 7.
- **`429 Too Many Requests`** : Limite de débit dépassée. Forfait Free : 3 000 emails/mois récurrents (plus une allocation de lancement unique de 30 000 emails). Patientez et réessayez.

---

## Étape 10 : Voir l'événement du message

**Temps :** ~30 secondes

Récupérez le statut du message et les événements de livraison :

**cURL :**
```bash
curl https://api.apexmail.ee/v1/messages/msg_01JXXXXXXXXXXXXXXX \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

**Réponse attendue :**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "delivered",
  "from": "hello@yourdomain.com",
  "to": ["your-email@example.com"],
  "subject": "Hello from ApexMail Quickstart",
  "events": [
    { "type": "queued",      "timestamp": "2026-07-29T19:00:00.100Z" },
    { "type": "processed",   "timestamp": "2026-07-29T19:00:00.200Z" },
    { "type": "sent",        "timestamp": "2026-07-29T19:00:00.450Z" },
    { "type": "delivered",   "timestamp": "2026-07-29T19:00:01.800Z" }
  ]
}
```

**Alternative :** Consultez la chronologie du message dans le tableau de bord sous **Activity → Messages**.

---

## Étape 11 : Configurer un webhook

**Temps :** ~2 minutes

Accédez à **Settings → Webhooks** dans le tableau de bord.

**Chemin :** Barre latérale du tableau de bord → `Settings` → `Webhooks`

**Bouton :** Cliquez sur **Add Webhook Endpoint**.

**Champs :**
- **URL :** L'URL réceptrice de votre webhook (p. ex. `https://your-app.example.com/webhooks/apexmail`)
- **Events :** Sélectionnez au minimum `message.delivered`, `message.bounced`, `message.complained`
- **Secret :** Générez un secret de signature — stockez-le de manière sécurisée

**Ce qui se passe :** ApexMail commence à livrer les événements correspondants à votre URL avec des signatures HMAC-SHA256.

**Exemple de vérification (Python) :**
```python
import hmac
import hashlib
import time

def verify_webhook(body: bytes, signature: str, timestamp: str, secret: str) -> bool:
    # Verify timestamp is within 5 minutes
    now = int(time.time())
    if abs(now - int(timestamp)) > 300:
        return False

    # Compute expected signature
    payload = f"{timestamp}.{body.decode()}".encode()
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, signature)
```

**En-têtes requis sur les requêtes webhook entrantes :**
- `X-ApexMail-Signature` : empreinte hexadécimale HMAC-SHA256
- `X-ApexMail-Timestamp` : secondes d'époque Unix
- `Content-Type` : `application/json`

---

## Étape 12 : Passer en production

**Temps :** Variable (dépend de vos exigences)

Avant de passer en production :

1. **Passez du forfait Free** si vous dépassez 3 000 emails/mois récurrents (ou votre allocation de lancement unique de 30 000 emails). Voir [Tarifs](/fr/pricing/).
3. **Configurez DMARC** pour votre domaine d'envoi avec une politique d'au moins `p=none` initialement, puis `p=quarantine` ou `p=reject`.
4. **Configurez l'alignement SPF** en vous assurant que votre domaine `Return-Path` correspond à votre domaine `From`.
5. **Faites tourner les clés API** — créez des clés spécifiques à la production avec des scopes minimaux et des dates d'expiration.
6. **Mettez en place le monitoring** — configurez des alertes pour les taux de rebond supérieurs à 2 % et les taux de plainte supérieurs à 0,1 %.
7. **Testez l'idempotence du webhook** — vérifiez que votre gestionnaire déduplique correctement les événements via le champ `event_id`.
8. **Consultez la [Référence API](/docs/api/)** pour l'envoi par lots, les modèles et les fonctions avancées.

### Liste de contrôle de préparation à la production

| Vérification | Exigence |
|-------|-------------|
| Domaine vérifié | SPF + DKIM vérifiés pour tous les domaines d'envoi |
| DMARC configuré | Politique publiée, rapports activés |
| Clé API scopée | Scopes minimaux requis ; clé de production distincte de la clé de développement |
| Webhook vérifié | Vérification de signature implémentée avec tolérance d'horodatage |
| Gestion des erreurs | Nouvelles tentatives avec backoff exponentiel pour les réponses 5xx |
| Idempotence | Utilisation de l'en-tête `Idempotency-Key` pour toutes les requêtes modifiant l'état |
| Monitoring | Taux de rebond < 2 %, taux de plainte < 0,1 %, taux de livraison > 98 % |

---

## Prochaines étapes

- [Référence API](/docs/api/) — documentation complète des points de terminaison avec schémas requête/réponse
- [Webhooks](/docs/webhooks/) — catalogue complet des événements, sécurité et documentation de livraison
- [SDKs](/docs/sdks/) — installation du SDK, authentification et exemples d'utilisation
- [Analytics](/docs/analytics/) — métriques de livraison, classification des rebonds et rapports
- [API Explorer](/api-explorer/) — exécutez de vraies requêtes contre le bac à sable live isolé
