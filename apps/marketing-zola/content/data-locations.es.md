+++
title = "Ubicaciones de datos"
description = "Matriz de ubicaciones de datos de ApexMail — dónde se almacena y procesa cada categoría de datos de clientes."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Matriz de ubicaciones de datos

Todos los datos de clientes se almacenan y procesan en centros de datos Hetzner en Alemania y Finlandia, a menos que se indique lo contrario a continuación. Las transferencias fuera del EEE se basan en las Cláusulas Contractuales Tipo de la UE (CCT) o una decisión de adecuación en virtud del Artículo 45 del RGPD.

| # | Categoría de datos | Ubicación principal | Copia de seguridad / Réplica | Región de procesamiento | Garantía de transferencia |
|---|---|---|---|---|---|
| 1 | Datos de cuenta (nombre, email, empresa, dirección) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 2 | Claves API (hash) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 3 | Direcciones de remitente y destinatario | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 4 | Contenido del mensaje (asunto, cuerpo, cabeceras) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 5 | Archivos adjuntos | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 6 | Eventos y registros (entrega, apertura, clic, rebote) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 7 | Autenticación (tokens OAuth, secretos MFA) | Hetzner, Alemania (Falkenstein/Núremberg); Google LLC / GitHub, Inc. (OAuth) | Gestionado por el proveedor | EEE (principal); EE. UU. para proveedores OAuth | CCT (proveedores OAuth) |
| 8 | Facturación (facturas, transacciones, tokens de pago) | Hetzner, Alemania; Stripe, Inc. (EE. UU.) | Gestionado por el proveedor (India para soporte de Stripe) | EEE (ApexMail); EE. UU./India (Stripe) | CCT (Stripe) |
| 9 | Tickets de soporte | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 10 | Analítica (métricas de entrega agregadas, interacción) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 11 | Registros de seguridad (pistas de auditoría, registros de acceso) | Hetzner, Alemania (Falkenstein/Núremberg) | Hetzner, Finlandia (Tuusula) | Solo EEE | No aplicable |
| 12 | Copias de seguridad (base de datos, instantáneas de almacenamiento de archivos) | Hetzner, Finlandia (Tuusula) | Hetzner, Alemania (Núremberg, almacenamiento en frío) | Solo EEE | No aplicable |

## Ubicaciones de subprocesadores

| Subprocesador | Finalidad | Ubicación | Garantía de transferencia |
|---|---|---|---|
| Hetzner Online GmbH | Infraestructura principal (computación, almacenamiento, red) | Alemania, Finlandia | No aplicable — EEE |
| Stripe, Inc. | Procesamiento de pagos | EE. UU. (principal), India (soporte) | Cláusulas Contractuales Tipo de la UE |
| Google LLC | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |
| GitHub, Inc. | Autenticación OAuth opcional | EE. UU. | Cláusulas Contractuales Tipo de la UE |

## Modelos de implementación

| Modelo | Región principal | Control del cliente |
|---|---|---|
| Shared EU Cloud | Alemania, Finlandia (Hetzner) | Gestionado por ApexMail |
| Dedicated Tenant | Región UE acordada con el cliente (predeterminada: Finlandia o Alemania) | Single-tenant, gestionado por ApexMail |
| BYOC (Bring Your Own Cloud) | Proveedor y región elegidos por el cliente | Infraestructura gestionada por el cliente, capa de aplicación gestionada por ApexMail |

## Contacto

Para consultas sobre la ubicación de datos: **privacy@apexmail.ee**
