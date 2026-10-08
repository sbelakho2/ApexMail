+++
title = "Schnellstart | ApexMail-Entwickleranleitung"
description = "Senden Sie Ihre erste E-Mail mit der ApexMail-API in weniger als 10 Minuten. Schritt-für-Schritt-Anleitung mit Codebeispielen für cURL und offizielle SDKs."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
og_image = "/images/og-image.png"
+++

Diese Anleitung führt Sie von null bis zu einer verifizierten Absenderdomain und der ersten zugestellten E-Mail. Jeder Schritt enthält den genauen UI-Pfad, Codebeispiele, erwartete Ergebnisse und häufige Fehlerfälle.

**Geschätzte Gesamtzeit:** 8–10 Minuten für Entwickler, die mit DNS und REST-APIs vertraut sind.

---

## Schritt 1: Konto erstellen

**Zeit:** ~30 Sekunden

Navigieren Sie zu [app.apexmail.ee/signup](https://app.apexmail.ee/signup).

**Was Sie benötigen:** Eine E-Mail-Adresse und ein Passwort (mindestens 12 Zeichen). Keine Kreditkarte erforderlich.

**Schaltfläche:** Klicken Sie auf **Create Free Account**.

**Was passiert:** Sie erhalten eine Bestätigungs-E-Mail an die angegebene Adresse.

**Erwartetes Ergebnis:** Weiterleitung zum Dashboard mit einem Banner zur E-Mail-Bestätigung.

**Fehlerfälle:**
- **`Email already registered`**: Verwenden Sie den Passwort-Reset unter [app.apexmail.ee/reset-password](https://app.apexmail.ee/reset-password).
- **`Password too weak`**: Verwenden Sie 15+ Zeichen (längere Passphrasen sind in Ordnung — keine Symbol- oder Ziffernmischung erforderlich). Vermeiden Sie häufige Passwörter und einfache Wiederholungs-/Sequenzmuster.

---

## Schritt 2: Konto-E-Mail bestätigen

**Zeit:** ~30 Sekunden

Öffnen Sie die Bestätigungs-E-Mail an Ihre registrierte Adresse.

**Betreff:** `Verify your ApexMail account`

**Schaltfläche:** Klicken Sie auf **Verify Email Address**.

**Was passiert:** Ihr Konto wird aktiviert. Das Dashboard-Banner verschwindet.

**Erwartetes Ergebnis:** Die Abschnitte **API Keys** und **Domains** sind in der Dashboard-Seitenleiste zugänglich.

**Fehlerbehebung:**
- Prüfen Sie den Spam-/Junk-Ordner.
- Wenn innerhalb von 2 Minuten keine E-Mail ankommt, klicken Sie im Dashboard-Banner auf **Resend Verification**.
- Fügen Sie `noreply@apexmail.ee` zu Ihren Kontakten hinzu, um Zustellprobleme in Zukunft zu vermeiden.

---

## Schritt 3: API-Schlüssel erstellen

**Zeit:** ~30 Sekunden

Navigieren Sie in der Dashboard-Seitenleiste zu **Settings → API Keys**.

**Pfad:** Dashboard-Seitenleiste → `Settings` → `API Keys`

**Schaltfläche:** Klicken Sie auf **Create API Key**.

**Felder:**
- **Schlüsselname:** z. B. `Quickstart Key`
- **Scopes:** Wählen Sie mindestens `messages:write` und `messages:read`
- **Ablauf:** Für die Entwicklung auf `Never` belassen

**Was passiert:** Ein neuer API-Schlüssel wird generiert und einmalig angezeigt.

**Sicherheitshinweis:** Kopieren Sie den Schlüssel sofort. Er wird nicht erneut angezeigt. Speichern Sie ihn in einem Passwort-Manager oder einer Umgebungsvariable — niemals im Quellcode.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Erwartetes Ergebnis:** Der Schlüssel erscheint in Ihrer API-Keys-Liste mit Status `Active`.

---

## Schritt 4: Absenderdomain hinzufügen

**Zeit:** ~1 Minute

Navigieren Sie in der Dashboard-Seitenleiste zu **Settings → Domains**.

**Pfad:** Dashboard-Seitenleiste → `Settings` → `Domains`

**Schaltfläche:** Klicken Sie auf **Add Domain**.

**Feld:** Geben Sie Ihre Absenderdomain ein (z. B. `mail.example.com` oder `example.com`).

**Was passiert:** ApexMail generiert DNS-Verifizierungsdatensätze und zeigt sie an.

**Erwartetes Ergebnis:** Die Domain erscheint in Ihrer Domains-Liste mit Status `Pending Verification`, und die DNS-Datensätze werden angezeigt.

**Sicherheitshinweis:** Verwenden Sie für transaktionale E-Mails eine Subdomain (z. B. `mail.example.com`), um den Versand-Ruf von Ihrer Hauptdomain zu isolieren.

---

## Schritt 5: Eigene MAIL-FROM-Datensätze hinzufügen

**Zeit:** ~2 Minuten (DNS-Propagation kann bis zu 48 Stunden dauern, typisch jedoch 5–30 Minuten)

Melden Sie sich in der Verwaltungskonsole Ihres DNS-Anbieters an und kopieren Sie beide `bounce`-Datensätze aus den Domain-Einstellungen (oder aus der DNS-Records-API): einen TXT-SPF-Datensatz mit `include:amazonses.com` und einen MX-Datensatz mit Priorität `10`, der auf `feedback-smtp.<aws-region>.amazonses.com` zeigt.

**Wirkung:** Konfiguriert die eigene MAIL-FROM-Domain für SPF-Ausrichtung und Bounce-Verarbeitung.

**Erwartetes Ergebnis:** Nach der DNS-Propagation zeigen die SPF- und Return-Path-Prüfungen im Domain-Statuspanel `verified`.

---

## Schritt 6: DKIM-Datensätze hinzufügen

**Zeit:** ~2 Minuten

Kopieren Sie den generierten DKIM-**TXT**-Datensatz aus den Domain-Einstellungen. Der Hostname ist `<selector>._domainkey.<your-domain>` und der Wert beginnt mit `v=DKIM1; k=rsa; p=`. Selector und öffentlicher Schlüssel sind domainspezifisch — der im Dashboard generierte Datensatz ist die einzige unterstützte Quelle.

**Wirkung:** Ermöglicht ApexMail, ausgehende Nachrichten kryptografisch zu signieren, damit empfangende Server die Nachrichtenintegrität und Absenderauthentizität prüfen können.

**Erwartetes Ergebnis:** Nach der DNS-Propagation zeigt die DKIM-Prüfung im Domain-Statuspanel `verified`.

**Fehlerbehebung:**
- Stellen Sie sicher, dass Sie die Datensätze zur richtigen DNS-Zone hinzufügen (die Domain aus Schritt 4).
- DKIM ist ein TXT-Datensatz, kein CNAME. Fügen Sie keinen Easy-DKIM- oder ApexMail-Service-Host-CNAME hinzu.
- Verwenden Sie den exakt in den Domain-Einstellungen angezeigten Selector beim Prüfen der DNS mit `dig`.

---

## Schritt 7: Domain verifizieren

**Zeit:** ~1 Minute (nach DNS-Propagation)

Kehren Sie zur Seite **Settings → Domains** im Dashboard zurück.

**Schaltfläche:** Klicken Sie neben Ihrer Domain auf **Verify**.

**Was passiert:** ApexMail prüft die eigenen MAIL-FROM-SPF/MX-Datensätze, den exakten DKIM-öffentlichen Schlüssel und DMARC. Im SES-Modus wird zusätzlich gewartet, bis SES die BYODKIM-Identität und die eigene MAIL-FROM-Domain als bereit meldet.

**Erwartetes Ergebnis:** Der Domain-Status zeigt `Verified` mit grünen Häkchen für SPF, DKIM, DMARC und Return-Path. Die SES-Verifizierung kann ausstehen, während AWS neu veröffentlichte DNS-Datensätze erkennt.

**Fehlerfälle:**
- **`SPF record not found`**: Prüfen Sie, dass der Host `bounce.<your-domain>` ist, nicht die Domain-Apex.
- **`DKIM selector not found`**: Prüfen Sie, dass der generierte TXT-Hostname und der vollständige `p=`-öffentliche Schlüssel exakt sind.
- **`Verification timeout`**: Die DNS-Propagation läuft möglicherweise noch. Warten Sie 5 Minuten und versuchen Sie es erneut.

---

## Schritt 8: SDK installieren oder cURL vorbereiten

**Zeit:** ~1 Minute

Wählen Sie Ihre Integrationsmethode:

### Option A: SDK (aus Quellcode bauen)

> **Noch nicht auf öffentlichen Registries.** Die ApexMail-SDKs sind **noch nicht auf PyPI, pkg.go.dev, Packagist, RubyGems oder Maven Central veröffentlicht** — `pip install apexmail`, `go get github.com/apexmail/apexmail-go` und `composer require apexmail/apexmail-php` schlagen fehl, bis die erste stabile Version erscheint. Installieren Sie bis dahin aus dem Monorepo-Quellcode und pinnen Sie auf einen bestimmten Commit. **Verifizieren Sie die Quelle, die Sie mitliefern**, bevor Sie ausliefern. Siehe [SDKs](/docs/sdks/) für den standortspezifischen Status pro Sprache.

SDK-Quellcode ist derzeit privat und für genehmigte Preview-Kunden verfügbar, während die Pakete für ihre erste öffentliche Registry-Veröffentlichung vorbereitet werden — schreiben Sie an [support@apexmail.ee](mailto:support@apexmail.ee) (oder Ihren Account-Manager), und Sie erhalten den gepinnten Quellcode-Drop für Ihre Sprache, mit Prüfsumme, unter der SDK-Lizenz. Jedes SDK-Verzeichnis enthält eigene Build- und Testanweisungen.

**Python** (`packages/sdk-python` — vom lokalen Pfad installieren oder das Verzeichnis mitliefern):

```bash
pip install ./packages/sdk-python
```

**Go** (`packages/sdk-go` — das Modul mit einer `replace`-Direktive auf den mitgelieferten Quellcode pinnen):

```bash
go mod edit -replace github.com/apexmail/apexmail-go=./packages/sdk-go
go mod tidy
```

**PHP** (`packages/sdk-php` — Composer auf das lokale Verzeichnis verweisen):

```bash
composer config repositories.apexmail path ./packages/sdk-php
composer require apexmail/apexmail-php:@dev
```

**Ruby** (`packages/sdk-ruby`) und **Java** (`packages/sdk-java`): aus dem Monorepo-Verzeichnis bauen; die README jedes Pakets enthält Build- und Testanweisungen.

### Option B: cURL (Schnelltest)

Keine Installation erforderlich — verwenden Sie das Terminal:

```bash
# Verify your key works
curl -s https://api.apexmail.ee/v1/account \
  -H "X-API-Key: $APEXMAIL_API_KEY" | head -c 200
```

**Erwartetes Ergebnis:** Eine JSON-Antwort mit Ihren Kontoinformationen und Tarifdetails.

---

## Schritt 9: Erste Test-E-Mail senden

**Zeit:** ~30 Sekunden

Mit Ihrer verifizierten Domain und dem API-Schlüssel:

**cURL:**
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

**Python-SDK:**
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

**Erwartete Antwort:**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "queued",
  "created_at": "2026-07-29T19:00:00Z"
}
```

**Was passiert:** Die Nachricht wird in die Zustellwarteschlange aufgenommen. Der Status wechselt von `queued` → `processed` → `sent` → `delivered`.

**Fehlerfälle:**
- **`401 Unauthorized`**: API-Schlüssel fehlt oder ist falsch. Prüfen Sie, ob `$APEXMAIL_API_KEY` gesetzt ist.
- **`403 Forbidden`**: Dem API-Schlüssel fehlt der Scope `messages:write`. Erstellen Sie den Schlüssel mit dem korrekten Scope neu.
- **`400 domain_not_verified`**: Ihre Absenderdomain ist noch nicht verifiziert. Kehren Sie zu Schritt 7 zurück.
- **`429 Too Many Requests`**: Ratenlimit überschritten. Free-Tarif: 3.000 E-Mails/Monat dauerhaft (plus einmaliges Startguthaben von 30.000 E-Mails). Warten Sie und versuchen Sie es erneut.

---

## Schritt 10: Nachrichtenereignis anzeigen

**Zeit:** ~30 Sekunden

Rufen Sie den Nachrichtenstatus und die Zustellereignisse ab:

**cURL:**
```bash
curl https://api.apexmail.ee/v1/messages/msg_01JXXXXXXXXXXXXXXX \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

**Erwartete Antwort:**
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

**Alternative:** Sehen Sie sich die Nachrichtenzeitleiste im Dashboard unter **Activity → Messages** an.

---

## Schritt 11: Webhook konfigurieren

**Zeit:** ~2 Minuten

Navigieren Sie im Dashboard zu **Settings → Webhooks**.

**Pfad:** Dashboard-Seitenleiste → `Settings` → `Webhooks`

**Schaltfläche:** Klicken Sie auf **Add Webhook Endpoint**.

**Felder:**
- **URL:** Ihre Webhook-Empfänger-URL (z. B. `https://your-app.example.com/webhooks/apexmail`)
- **Events:** Wählen Sie mindestens `message.delivered`, `message.bounced`, `message.complained`
- **Secret:** Generieren Sie ein Signatur-Secret — speichern Sie es sicher

**Was passiert:** ApexMail liefert passende Ereignisse an Ihre URL mit HMAC-SHA256-Signaturen.

**Verifikationsbeispiel (Python):**
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

**Erforderliche Header bei eingehenden Webhook-Anfragen:**
- `X-ApexMail-Signature`: HMAC-SHA256-Hex-Digest
- `X-ApexMail-Timestamp`: Unix-Epoch-Sekunden
- `Content-Type`: `application/json`

---

## Schritt 12: In Produktion gehen

**Zeit:** Variabel (hängt von Ihren Anforderungen ab)

Bevor Sie in Produktion gehen:

1. **Upgrade vom Free-Tarif**, wenn Sie 3.000 E-Mails/Monat dauerhaft (oder Ihr einmaliges Startguthaben von 30.000 E-Mails) überschreiten. Siehe [Preise](/pricing/).
3. **DMARC konfigurieren** für Ihre Absenderdomain mit einer Policy von mindestens `p=none` zunächst, später `p=quarantine` oder `p=reject`.
4. **SPF-Ausrichtung einrichten**, indem Ihre `Return-Path`-Domain mit Ihrer `From`-Domain übereinstimmt.
5. **API-Schlüssel rotieren** — erstellen Sie produktions-spezifische Schlüssel mit minimalen Scopes und Ablaufdaten.
6. **Monitoring einrichten** — konfigurieren Sie Alarme für Bounce-Raten über 2 % und Beschwerde-Raten über 0,1 %.
7. **Webhook-Idempotenz testen** — prüfen Sie, dass Ihr Handler Ereignisse über das Feld `event_id` korrekt dedupliziert.
8. **[API-Referenz](/docs/api/) prüfen** für Batch-Sending, Templates und erweiterte Funktionen.

### Production-Readiness-Checkliste

| Prüfung | Anforderung |
|-------|-------------|
| Domain verifiziert | SPF + DKIM für alle Absenderdomains verifiziert |
| DMARC konfiguriert | Policy veröffentlicht, Reporting aktiviert |
| API-Schlüssel eingeschränkt | Mindest-Scopes; Produktionsschlüssel getrennt vom Entwicklungsschlüssel |
| Webhook verifiziert | Signaturverifikation mit Zeitstempel-Toleranz implementiert |
| Fehlerbehandlung | Retries mit exponentiellem Backoff für 5xx-Antworten |
| Idempotenz | `Idempotency-Key`-Header für alle zustandsändernden Anfragen |
| Monitoring | Bounce-Rate < 2 %, Beschwerde-Rate < 0,1 %, Zustellrate > 98 % |

---

## Nächste Schritte

- [API-Referenz](/docs/api/) — vollständige Endpunkt-Dokumentation mit Anfrage-/Antwort-Schemas
- [Webhooks](/docs/webhooks/) — vollständiger Ereigniskatalog, Sicherheit und Zustelldokumentation
- [SDKs](/docs/sdks/) — SDK-Installation, Authentifizierung und Nutzungsbeispiele
- [Analytics](/docs/analytics/) — Zustellmetriken, Bounce-Klassifizierung und Berichte
- [API Explorer](/api-explorer/) — echte Anfragen gegen die isolierte Live-Sandbox ausführen
