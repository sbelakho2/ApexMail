+++
title = "E-Mail-Lösung für SaaS-Plattformen"
description = "Multi-Tenant-E-Mail-Infrastruktur für B2B- und B2C-SaaS. Subaccounts, Domain-Isolation, RBAC, SSO und White-Label-Zustellung."
template = "prose.html"
+++

## SaaS-Plattformen

Stellen Sie Ihren Kunden zuverlässige, isolierte E-Mail-Infrastruktur bereit, ohne eine eigene E-Mail-Schicht zu bauen und zu betreiben. Das Subaccount-Modell von ApexMail gibt jedem Ihrer Tenants unabhängige Domains, API-Keys, Suppressionslisten und Ereignisströme.

## Zielgruppe

SaaS-Plattformen, die E-Mails im Namen ihrer Kunden senden: CRM-Systeme mit Kampagnen-E-Mails, E-Commerce-Plattformen mit Bestellbestätigungen, Analyse-Tools mit Berichten, Sicherheitsplattformen mit Warnmeldungen.

## Geschäftskontext

Plattformen, die für Kunden E-Mails senden, erben das Reputationsrisiko jedes einzelnen Kunden. Eine einzige Spam-Beschwerde auf einer gemeinsam genutzten IP kann die Zustellung für alle Tenants verschlechtern. Ohne Isolation können Plattformen Zustellprobleme nicht einzelnen Kunden zuordnen oder Compliance-Kontrollen je Tenant anbieten.

## Kernproblem

- Reputationsrisiko gemeinsam genutzter IPs über alle Plattform-Tenants hinweg.
- Abrechnung, Nutzungskontingente und Zustell-Analytik lassen sich nicht pro Kunde isolieren.
- Compliance-Anforderungen unterscheiden sich je Kunde (der eine benötigt HIPAA, der andere nur DSGVO).
- Kunden verlangen sichtbare Zustellbarkeitsmetriken und Authentifizierungsstatus auf Domain-Ebene.

## Die ApexMail-Lösung

- **Subaccounts** — Jeder Tenant erhält einen unabhängigen Subaccount mit eigenen API-Keys, Domains, Webhooks, Suppressionslisten, dedizierten IPs und Ereignisströmen.
- **Domain-Isolation** — Domain-Verifizierung und -Authentifizierung (SPF, DKIM, DMARC) pro Subaccount verhindert Reputations-Kreuzkontamination.
- **Benutzerdefiniertes RBAC** — Admin-Rollen auf Plattform- und Tenant-Ebene sowie Nur-Lese-Rollen. SCIM-Provisioning ab Enterprise.
- **SSO** — SAML 2.0 für Plattform-Betreiber und Tenant-Administratoren.
- **Nutzungskontingente** — Harte und weiche Limits pro Subaccount für Volumen, Rate und Parallelität.
- **White-Label** — Entfernen Sie das ApexMail-Branding aus Dashboards, E-Mail-Fußzeilen und Benachrichtigungsvorlagen.

## Technische Umsetzung

1. Erstellen Sie ein Master-Konto für Ihre Plattform.
2. Stellen Sie Subaccounts über die API oder das Dashboard für jeden Kunden-Tenant bereit.
3. Jeder Tenant verifiziert seine Sende-Domains unabhängig.
4. Weisen Sie Tenants, die Reputationsisolation benötigen, dedizierte IPs zu.
5. Konfigurieren Sie Webhook-Endpunkte je Tenant für Zustellereignisse.
6. Überwachen Sie die Zustellgesundheit der gesamten Plattform über aggregierte Analytik.

## Relevante API-Endpunkte

| Endpunkt | Beschreibung |
|---|---|
| `POST /v1/subaccounts` | Subaccount erstellen |
| `GET /v1/subaccounts` | Subaccounts auflisten |
| `GET /v1/subaccounts/:id` | Subaccount-Details abrufen |
| `PATCH /v1/subaccounts/:id` | Subaccount-Einstellungen aktualisieren |
| `DELETE /v1/subaccounts/:id` | Subaccount deaktivieren |
| `POST /v1/subaccounts/:id/api-keys` | Subaccount-API-Key erstellen |

## Erforderlicher Tarif

Subaccounts sind in Scale (bis zu 10) und Enterprise (bis zu 100) verfügbar. Jede nicht standardisierte Bereitstellungsregelung erfordert eine separate Architektur- und Vertragsprüfung.

## Sicherheitshinweise

- Plattform-Betreiber können E-Mail-Inhalte von Tenants standardmäßig nicht lesen. Inhaltszugriff erfordert eine ausdrückliche Autorisierung durch den Tenant.
- Subaccount-API-Keys sind ausschließlich auf ihren Subaccount beschränkt. Tenant-übergreifender Zugriff wird auf der Autorisierungsebene verhindert.
- Webhook-Endpunkte werden pro Subaccount konfiguriert. HMAC-Signaturen nutzen je Subaccount ein eigenes Geheimnis.
- Audit-Logs erfassen alle Erstellungen, Löschungen und Berechtigungsänderungen von Subaccounts.

## Compliance-Hinweise

- Jeder Subaccount führt unabhängige Suppressionslisten, Domain-Authentifizierung und Ereignisaufbewahrung.
- Die AVV-Abdeckung für Subaccounts erfordert die AVV der Plattform mit ApexMail. Die vertragliche Weitergabe an Tenants liegt in der Verantwortung der Plattform.
- Datenstandortanforderungen gelten auf Plattform-Ebene und müssen für die aktive Bereitstellung und die anwendbare Vereinbarung bestätigt werden.
- Plattform-Betreiber sind für die Einhaltung der Nutzungsbedingungen durch ihre Tenants verantwortlich.

## Bekannte Einschränkungen

- Die Subaccount-Isolation ist in Shared-Cloud-Tarifen logisch. Eine separat vertraglich vereinbarte Bereitstellung kann zusätzliche Isolationsanforderungen definieren — sie ist jedoch keine Berechtigung öffentlicher Tarife.
- Subaccount-übergreifende Analytik erfordert, dass die Plattform die Ereignisdaten der Subaccounts extern aggregiert.
- White-Label-Branding ist im Enterprise-Tarif verfügbar.

## Empfohlener nächster Schritt

[Kontaktieren Sie den Vertrieb](/de/contact/sales/) für ein Subaccount-Architektur-Review und Volumenpreise für Multi-Tenant-Bereitstellungen.
