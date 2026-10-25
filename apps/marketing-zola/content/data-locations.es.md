+++
title = "Ubicaciones de datos"
description = "Matriz de ubicaciones de datos de ApexMail — dónde se almacena y procesa cada categoría de datos de clientes."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Matriz de ubicaciones de datos

Esta matriz describe la configuración de implementación proporcionada y orientada a la UE/EEE, no una garantía universal de ubicación. La configuración predeterminada de los datos principales de correo y la telemetría apunta a regiones del EEE; las ubicaciones activas, los proveedores habilitados y las garantías de transferencia deben confirmarse para el entorno implementado y el acuerdo aplicable.

Las entradas de Dedicated Tenant y BYOC que aparecen a continuación describen un modelo únicamente cuando un acuerdo escrito independiente lo aprueba. No forman parte de los planes públicos de autoservicio.

| # | Categoría de datos | Ubicación principal predeterminada | Copia de seguridad / Réplica predeterminada | Región de procesamiento predeterminada | Garantía de transferencia |
|---|---|---|---|---|---|
| 1 | Datos de cuenta (nombre, email, empresa, dirección) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 2 | Claves API (hash) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 3 | Direcciones de remitente y destinatario | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 4 | Contenido del mensaje (asunto, cuerpo, cabeceras) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 5 | Archivos adjuntos | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 6 | Eventos y registros (entrega, apertura, clic, rebote) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 7 | Autenticación (tokens OAuth, secretos MFA) | Centro de datos de la UE — Finlandia; Google LLC / GitHub, Inc. (OAuth) | Gestionado por el proveedor | EEE (principal); EE. UU. para proveedores OAuth | CCT (proveedores OAuth) |
| 8 | Facturación (facturas, transacciones, tokens de pago) | Centro de datos de la UE — Finlandia; Mollie B.V. (Países Bajos, UE) | Gestionado por el proveedor dentro de la UE | EEE (ApexMail y Mollie); redes de tarjetas según el DPA de Mollie | Tratamiento intra-EEE (Mollie B.V., Ámsterdam) |
| 9 | Tickets de soporte | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 10 | Analítica (métricas de entrega agregadas, interacción) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 11 | Registros de seguridad (pistas de auditoría, registros de acceso) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (sitio secundario) | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 12 | Copias de seguridad (base de datos, instantáneas de almacenamiento de archivos) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Finlandia (almacenamiento en frío cifrado) | EEE predeterminado | Tratamiento intra-EEE |

## Ubicaciones de subprocesadores

| Subprocesador | Finalidad | Ubicación | Garantía de transferencia |
|---|---|---|---|
| Hetzner Online GmbH | Infraestructura principal (computación, almacenamiento, red) | Finlandia (UE) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| Amazon Web Services, Inc. (AWS S3) | Almacenamiento de objetos de telemetría cuando está habilitado | Región S3 configurada (predeterminada: `eu-central-1`) | Tratamiento intra-EEE y la garantía de transferencia aplicable |
| Amazon Web Services, Inc. (AWS SES) | Transporte de entrega de correo cuando está habilitado | Región SES configurada | Tratamiento intra-EEE y la garantía de transferencia aplicable |
| Mollie B.V. | Procesamiento de pagos | Países Bajos (UE); las redes de tarjetas procesan globalmente según el DPA de Mollie | Tratamiento intra-UE (Mollie B.V., Ámsterdam) |
| Google LLC | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |
| GitHub, Inc. | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |

### Procesador de pagos

Mollie B.V. es una entidad de pago supervisada por De Nederlandsche Bank (DNB), con domicilio social en Keizersgracht 126, 1015 CW Ámsterdam, Países Bajos. Los datos de pago se procesan en los Países Bajos (UE); las redes de tarjetas pueden procesarlos globalmente conforme al Acuerdo de Tratamiento de Datos de Mollie.

## Modelos de implementación

| Modelo | Región principal | Control del cliente |
|---|---|---|
| Shared EU Cloud | Configuración predeterminada orientada a la UE/EEE; confirmar regiones activas | Gestionado por ApexMail |
| Dedicated Tenant | Región acordada con el cliente | Single-tenant, gestionado por ApexMail |
| BYOC (Bring Your Own Cloud) | Proveedor y región elegidos por el cliente | Infraestructura gestionada por el cliente, capa de aplicación gestionada por ApexMail |

## Enrutamiento EU-only

La matriz anterior cubre el almacenamiento. El transporte de entrega se rige por el modo de enrutamiento del inquilino: con enrutamiento EU-only (`eu_only`), cada envío sale por los MTA europeos propios de ApexMail y el transporte compartido de terceros (AWS SES en su región de la UE) queda prohibido — una ruta MTA propia no disponible retiene el mensaje en lugar de desviarlo. El argumento completo del transporte, cada punto enlazado con su evidencia, está en la [página de soberanía de la UE](/es/eu-sovereign/).

## Contacto

Para consultas sobre la ubicación de datos: **privacy@apexmail.ee**
