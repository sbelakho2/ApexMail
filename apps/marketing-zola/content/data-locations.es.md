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
| 1 | Datos de cuenta (nombre, email, empresa, dirección) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 2 | Claves API (hash) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 3 | Direcciones de remitente y destinatario | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 4 | Contenido del mensaje (asunto, cuerpo, cabeceras) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 5 | Archivos adjuntos | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 6 | Eventos y registros (entrega, apertura, clic, rebote) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 7 | Autenticación (tokens OAuth, secretos MFA) | Centro de datos de la UE — Alemania; Google LLC / GitHub, Inc. (OAuth) | Gestionado por el proveedor | EEE (principal); EE. UU. para proveedores OAuth | CCT (proveedores OAuth) |
| 8 | Facturación (facturas, transacciones, tokens de pago) | Centro de datos de la UE — Alemania; Stripe, Inc. (EE. UU.) | Gestionado por el proveedor (India para soporte de Stripe) | EEE (ApexMail); EE. UU./India (Stripe) | CCT (Stripe) |
| 9 | Tickets de soporte | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 10 | Analítica (métricas de entrega agregadas, interacción) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 11 | Registros de seguridad (pistas de auditoría, registros de acceso) | Centro de datos de la UE — Alemania | Centro de datos de la UE — Finlandia | EEE (sin transferencia a terceros países) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| 12 | Copias de seguridad (base de datos, instantáneas de almacenamiento de archivos) | Centro de datos de la UE — Finlandia | Centro de datos de la UE — Alemania (Núremberg, almacenamiento en frío) | EEE predeterminado | Tratamiento intra-EEE |

## Ubicaciones de subprocesadores

| Subprocesador | Finalidad | Ubicación | Garantía de transferencia |
|---|---|---|---|
| Hetzner Online GmbH | Infraestructura principal (computación, almacenamiento, red) | Alemania y Finlandia (UE) | Tratamiento intra-EEE; no se aplican las reglas de transferencia del capítulo V del RGPD |
| Amazon Web Services, Inc. (AWS S3) | Almacenamiento de objetos de telemetría cuando está habilitado | Región S3 configurada (predeterminada: `eu-central-1`) | Tratamiento intra-EEE y la garantía de transferencia aplicable |
| Amazon Web Services, Inc. (AWS SES) | Transporte de entrega de correo cuando está habilitado | Región SES configurada | Tratamiento intra-EEE y la garantía de transferencia aplicable |
| Stripe, Inc. | Procesamiento de pagos | EE. UU. (principal), India (soporte) | Cláusulas Contractuales Tipo de la UE |
| Google LLC | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |
| GitHub, Inc. | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |

## Modelos de implementación

| Modelo | Región principal | Control del cliente |
|---|---|---|
| Shared EU Cloud | Configuración predeterminada orientada a la UE/EEE; confirmar regiones activas | Gestionado por ApexMail |
| Dedicated Tenant | Región acordada con el cliente | Single-tenant, gestionado por ApexMail |
| BYOC (Bring Your Own Cloud) | Proveedor y región elegidos por el cliente | Infraestructura gestionada por el cliente, capa de aplicación gestionada por ApexMail |

## Contacto

Para consultas sobre la ubicación de datos: **privacy@apexmail.ee**
