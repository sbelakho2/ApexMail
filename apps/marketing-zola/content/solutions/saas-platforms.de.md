+++
title = "E-Mail-Lösung für SaaS-Plattformen"
description = "Multi-Tenant-E-Mail-Infrastruktur für B2B- und B2C-SaaS. Tenant-Isolation, Domain-Isolation, RBAC, SSO und White-Label-Zustellung."
template = "prose.html"
+++

## SaaS-Plattformen

Stellen Sie Ihren Kunden zuverlässige, isolierte E-Mail-Infrastruktur bereit, ohne eine eigene E-Mail-Schicht zu bauen und zu betreiben. ApexMail gibt jedem Ihrer Tenants eigene Domains, API-Keys, Webhook-Endpunkte mit HMAC-Geheimnissen je Tenant, Suppressionslisten, dedizierte IPs und Ereignisströme.

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

- **Tenant-Isolation** — Jeder Tenant erhält eigene Domains, API-Keys, Webhook-Endpunkte mit HMAC-Geheimnissen je Tenant, Suppressionslisten, dedizierte IPs und Ereignisströme.
- **Domain-Isolation** — Domain-Verifizierung und -Authentifizierung (SPF, DKIM, DMARC) pro Tenant verhindert Reputations-Kreuzkontamination.
- **Benutzerdefiniertes RBAC** — Admin-Rollen auf Plattform- und Tenant-Ebene sowie Nur-Lese-Rollen. SCIM-Provisioning ab Enterprise.
- **SSO** — SAML 2.0 für Plattform-Betreiber und Tenant-Administratoren.
- **Nutzungskontingente** — Harte und weiche Limits pro Tenant für Volumen, Rate und Parallelität.
- **White-Label** — Entfernen Sie das ApexMail-Branding aus Dashboards, E-Mail-Fußzeilen und Benachrichtigungsvorlagen.

## Technische Umsetzung

1. Erstellen Sie ein Konto für Ihre Plattform.
2. Richten Sie für jeden Kunden einen eigenen Tenant ein.
3. Jeder Tenant verifiziert seine Sende-Domains unabhängig.
4. Weisen Sie Tenants, die Reputationsisolation benötigen, dedizierte IPs zu.
5. Konfigurieren Sie Webhook-Endpunkte je Tenant für Zustellereignisse.
6. Überwachen Sie die Zustellgesundheit der gesamten Plattform über aggregierte Analytik.

## Erforderlicher Tarif

Jede nicht standardisierte Bereitstellungsregelung erfordert eine separate Architektur- und Vertragsprüfung.

## Sicherheitshinweise

- Plattform-Betreiber können E-Mail-Inhalte von Tenants standardmäßig nicht lesen. Inhaltszugriff erfordert eine ausdrückliche Autorisierung durch den Tenant.
- API-Keys sind ausschließlich auf ihren Tenant beschränkt. Tenant-übergreifender Zugriff wird auf der Autorisierungsebene verhindert.
- Webhook-Endpunkte werden pro Tenant konfiguriert. HMAC-Signaturen nutzen je Tenant ein eigenes Geheimnis.
- Audit-Logs erfassen alle Erstellungen, Löschungen und Berechtigungsänderungen von Tenants.

## Compliance-Hinweise

- Jeder Tenant führt unabhängige Suppressionslisten, Domain-Authentifizierung und Ereignisaufbewahrung.
- Die AVV-Abdeckung für Tenants erfordert die AVV der Plattform mit ApexMail. Die vertragliche Weitergabe an Tenants liegt in der Verantwortung der Plattform.
- Datenstandortanforderungen gelten auf Plattform-Ebene und müssen für die aktive Bereitstellung und die anwendbare Vereinbarung bestätigt werden.
- Plattform-Betreiber sind für die Einhaltung der Nutzungsbedingungen durch ihre Tenants verantwortlich.

## Bekannte Einschränkungen

- Die Tenant-Isolation ist in Shared-Cloud-Tarifen logisch. Eine separat vertraglich vereinbarte Bereitstellung kann zusätzliche Isolationsanforderungen definieren — sie ist jedoch keine Berechtigung öffentlicher Tarife.
- Tenant-übergreifende Analytik erfordert, dass die Plattform die Ereignisdaten der Tenants extern aggregiert.
- White-Label-Branding ist im Enterprise-Tarif verfügbar.

## Empfohlener nächster Schritt

[Kontaktieren Sie den Vertrieb](/de/contact/sales/) für ein Multi-Tenant-Architektur-Review und Volumenpreise für Ihre Bereitstellung.
