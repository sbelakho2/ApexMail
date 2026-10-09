+++
title = "Subprocesadores"
description = "Registro de subprocesadores de ApexMail — la lista de proveedores autorizados que procesan datos en nuestro nombre."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++
## Registro de subprocesadores

Esta página enumera los proveedores externos contratados por Bel Consulting OÜ (que opera como ApexMail) que pueden tratar datos personales de clientes en el curso de la prestación del servicio ApexMail. Este registro se mantiene de conformidad con el artículo 28 del RGPD y la sección 5 del Acuerdo de Tratamiento de Datos de ApexMail.

### Subprocesadores de infraestructura

Las siguientes entidades externas tratan datos personales de clientes por cuenta de ApexMail.

| Entidad legal | Marca | Servicio | Finalidad | Categorías de datos | País de tratamiento | País de almacenamiento | País corporativo | Mecanismo de transferencia | Obligatorio |
|---|---|---|---|---|---|---|---|---|---|
| Hetzner Online GmbH | Hetzner | Alojamiento en la nube | Cómputo, almacenamiento, red | Datos del servicio principal en la implementación compartida predeterminada | Región UE/EEE configurada | Región UE/EEE configurada | Alemania | Tratamiento intra-EEE; las normas de transferencia del capítulo V del RGPD no se aplican | Sí |
| Amazon Web Services, Inc. | AWS S3 | Almacenamiento de objetos de telemetría | Almacenamiento de telemetría cuando está activado | Los registros de Loki y las trazas de Tempo pueden contener metadatos operativos | Región de S3 configurada (predeterminada: `eu-central-1`) | Región de S3 configurada (predeterminada: `eu-central-1`) | EE. UU. | Cláusulas Contractuales Tipo de la UE (DPA de AWS) | No — solo cuando la implementación activa usa almacenamiento S3 |
| Amazon Web Services, Inc. | AWS SES | Transporte de entrega de email | Entrega de email cuando está activada | Contenido de los emails y direcciones de los destinatarios | Región de SES configurada | Región de SES configurada | EE. UU. | Cláusulas Contractuales Tipo de la UE (DPA de AWS) | No — solo cuando la implementación activa usa SES |
| Google LLC | Google | Autenticación OAuth | Inicio de sesión mediante Google OAuth | Tokens OAuth, dirección de email, nombre | Global (datos de la UE) | Usuarios con sede en el EEE: EEE | EE. UU. | Cláusulas Contractuales Tipo (SCC) | No — solo si el cliente activa Google OAuth |
| GitHub, Inc. | GitHub | Autenticación OAuth | Inicio de sesión mediante GitHub OAuth | Tokens OAuth, nombre de usuario, dirección de email | Global (datos de la UE) | Usuarios con sede en el EEE: EEE | EE. UU. | Cláusulas Contractuales Tipo (SCC) | No — solo si el cliente activa GitHub OAuth |
| Stripe, Inc. | Stripe | Procesamiento de pagos | Facturación por suscripción, facturación, almacenamiento de métodos de pago | Tokens de métodos de pago, metadatos de transacciones, datos de facturas | EE. UU. (principal); India (soporte) | EE. UU. | EE. UU. | Cláusulas Contractuales Tipo (SCC) según el DPA de Stripe | Sí — necesario para los planes de pago |

### Infraestructura autoalojada (no son subprocesadores externos)

El siguiente software lo despliega y gestiona ApexMail sobre infraestructura de Hetzner. Los editores del software no tratan datos de clientes.

| Software | Finalidad | Categorías de datos | País de tratamiento | País de almacenamiento | Notas |
|---|---|---|---|---|---|
| ClickHouse (código abierto) | Base de datos de analítica | Eventos de entrega, eventos de apertura y clic, datos de rebotes y quejas | Región de implementación configurada | Región de implementación configurada | Autoalojado por ApexMail. ClickHouse, Inc. no trata datos de clientes. |
| Redis (código abierto) | Caché en memoria | Tokens de sesión, contadores de límite de tasa | Región de implementación configurada | Región de implementación configurada | Autoalojado por ApexMail. Redis Ltd. no trata datos de clientes. |

### Notificación

Los clientes reciben notificación con al menos **30 días** de antelación antes de contratar a un nuevo subprocesador. Para recibir notificaciones, suscríbase en [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) o supervise esta página.

### Oposición

Si se opone a un nuevo subprocesador por motivos razonables de protección de datos, escriba a [privacy@apexmail.ee](mailto:privacy@apexmail.ee). Si no se alcanza una alternativa, puede rescindir los servicios afectados de conformidad con el DPA.

### Historial de cambios

| Fecha | Cambio | Descripción |
|---|---|---|
| 2026-07-29 | Publicación inicial | Registro de subprocesadores publicado con Hetzner (infraestructura), AWS (S3/SES, cuando están activados), Google (OAuth), GitHub (OAuth) y Stripe (pagos). ClickHouse y Redis son software autoalojado, no subprocesadores (véase arriba). |
