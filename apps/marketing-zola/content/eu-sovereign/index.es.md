+++
title = "Soberanía UE | Creada en Europa, operada bajo derecho de la UE"
description = "Cómo funciona realmente la posición de soberanía europea de ApexMail: una empresa estonia bajo derecho de la UE, centros de datos de la UE, el modo de enrutamiento EU-only fail-closed, recibos de enrutamiento firmados con Ed25519 y la cadena de subencargados que EU-only elimina — cada afirmación enlazada con su evidencia."
template = "prose.html"

[extra]
last_updated = "2026-10-16"
og_image = "/images/og-image.png"
+++

## La promesa y el límite honesto

ApexMail es una empresa de la UE (Bel Consulting OÜ, Tallin, Estonia). La nube compartida funciona en centros de datos de la UE en Finlandia. El enrutamiento EU-only es un modo real que se activa con un solo ajuste: cada envío sale únicamente por los MTA europeos de ApexMail, un envío sin ruta MTA propia se retiene en lugar de redirigirse, y cada mensaje aceptado lleva un recibo de enrutamiento firmado con Ed25519 que cualquier tercero puede verificar con la clave pública publicada.

El límite honesto pertenece a la misma pantalla: el enrutamiento **predeterminado** de ApexMail es Global, y los envíos Global se entregan a través de SES de Amazon Web Services en su región de la UE configurada — una región de la UE de una empresa estadounidense, cubierta por el contrato de encargo de tratamiento de AWS y, cuando corresponde, por las cláusulas contractuales tipo de la UE. La frase «tu correo nunca toca un proveedor controlado por EE. UU.» es cierta **con enrutamiento EU-only**; no lo es para una cuenta Global, y este sitio no la afirma para toda la plataforma. La [matriz de ubicaciones de datos](/es/data-locations/) declara para el almacenamiento el mismo alcance que esta página declara para el transporte.

## Una empresa de la UE bajo derecho de la UE

La parte contratante es Bel Consulting OÜ (nombre comercial ApexMail), registrada en Estonia: código de registro 16588745, IVA EE102951727, Sakala tn 7-2, 10141 Tallin. El derecho aplicable a los contratos de ApexMail es el derecho estonio, y la jurisdicción judicial acordada es el Harju County Court, Tallin, Estonia. Esa identidad jurídica se renderiza desde un único registro canónico en cada página de este sitio.

Evidencia: los [Términos](/es/terms/) nombran a la parte contratante y el derecho aplicable; el [DPA](/es/dpa/) es el acuerdo de tratamiento del artículo 28; la [política de privacidad](/es/privacy/) indica los roles de responsable y encargado; la página [Acerca de](/es/about/) lleva los datos de registro de la empresa.

## Centros de datos de la UE

El despliegue compartido predeterminado funciona sobre infraestructura de Hetzner Online GmbH en Finlandia. Los datos esenciales del servicio — datos de cuenta, claves de API con hash, direcciones de remitente y destinatario, contenido de los mensajes, adjuntos, eventos y registros de entrega, tickets de soporte, analítica y copias de seguridad — se procesan y replican dentro del EEE, sin transferencia a terceros países para esas categorías. Las excepciones reales se nombran en lugar de ocultarse: el inicio de sesión OAuth opcional (Google, GitHub) y el procesamiento de pagos (Mollie B.V.) se detallan por separado en la matriz con sus propias garantías de transferencia.

Evidencia: la [matriz de ubicaciones de datos](/es/data-locations/) enumera para cada categoría de datos la ubicación principal, la copia de seguridad y la región de procesamiento; el [registro de subencargados](/es/subprocessors/) nombra las entidades y sus países de procesamiento y almacenamiento.

### Procesador de pagos

Mollie B.V. es una entidad de pago supervisada por De Nederlandsche Bank (DNB), con domicilio social en Keizersgracht 126, 1015 CW Ámsterdam, Países Bajos. Los datos de pago se procesan en los Países Bajos (UE); las redes de tarjetas pueden procesarlos globalmente conforme al Acuerdo de Tratamiento de Datos de Mollie.

## Enrutamiento EU-only: un solo ajuste, fail-closed

El enrutamiento EU-only es el modo de enrutamiento del inquilino (`routingMode`, almacenado como `global` o `eu_only`). Con `eu_only`, cada envío debe salir por los **MTA de retransmisión propios** de ApexMail; el transporte compartido de terceros (AWS SES) queda prohibido para ese inquilino, y el código no contiene ninguna entrada que produzca una ruta de terceros en modo EU-only.

Lo que ocurre cuando la ruta MTA propia no está disponible es lo que convierte el modo en una promesa y no en una preferencia: **el mensaje se retiene** — diferido en cola con un motivo nombrado, visible y liberable — nunca se desvía al transporte de terceros. La misma disciplina se aplica cuando la configuración de la fila no es legible: un valor de enrutamiento almacenado que no puede leerse como `global` se lee como `eu_only`, porque un mensaje retenido es recuperable y uno mal enrutado no lo es.

Lo que cambia frente a Global, dicho con claridad:

| | Global (predeterminado) | EU-only |
|---|---|---|
| Envíos por IP dedicada | MTA de retransmisión propios de ApexMail | MTA de retransmisión propios de ApexMail |
| Todo lo demás | Pool compartido — AWS SES en su región de la UE configurada | MTA europeos propios de ApexMail |
| Ruta no disponible | Conmutación al proveedor | **Retención con motivo nombrado** — sin respaldo de terceros |

Disponibilidad y precio: incluido en [Enterprise](/es/enterprise/) Cloud y en la línea contractual Compliance; en los planes de autoservicio es el complemento **EU-only routing** a **149 €/mes (165 US$/mes)** desde Pro — la cifra exacta del catálogo.

Evidencia: la [página de precios](/es/pricing/) muestra el complemento y la línea Compliance desde el catálogo de facturación; la [página de cumplimiento](/es/compliance/) documenta la parte de flujos de trabajo; la [página de arquitectura](/architecture) describe la ruta de entrega.

## Recibos de enrutamiento firmados: verificar, no confiar

Cada mensaje aceptado genera un recibo de enrutamiento firmado con Ed25519 (RFC 8032, firma de 64 bytes). La firma cubre bytes exactos y recalculables: una carga útil separada por LF, sin relleno:

```text
apexmail-routing-receipt/v1
message_id=<identificador de mensaje de la plataforma>
tenant_id=<número de inquilino>
transport=<etiqueta del transporte>
accepted_at=<RFC 3339 UTC>
actual_source_ip=<ip>          ← presente solo cuando el transporte informó una
```

Cualquier biblioteca Ed25519 puede recalcular esos bytes a partir de los campos publicados del recibo y comprobar la firma, sin confiar en la base de datos, la superficie de API ni la pila TLS de ApexMail. La clave de verificación se sirve sin autenticación:

- `GET https://api.apexmail.ee/v1/routing/receipts/public-key` — la clave pública Ed25519, la etiqueta del esquema y un id de clave (`hex(sha256(public_key))[0:16]`) registrado junto a cada firma, de modo que una rotación de clave sea auditable.
- `POST https://api.apexmail.ee/v1/routing/receipts/verify` — `{payload, signature}`; responde con el veredicto de verificación.

El esquema es fail-closed en ambos sentidos: una escritura de recibo sin clave de firma configurada se rechaza (la fila de aceptación no se marca como aceptada), y los servicios que poseen la ruta de aceptación se niegan a arrancar en producción sin clave. Un recibo sin firmar no puede existir en silencio.

Evidencia: ambos endpoints son superficies públicas, vivas y sin autenticación de la API; la [documentación de la API](/docs/api/) cubre el contrato circundante; la [línea contractual Compliance](/es/pricing/) lista los recibos de enrutamiento firmados como entregable incluido.

## Lo que EU-only elimina de la cadena de subencargados

El [registro de subencargados](/es/subprocessors/) se genera desde la configuración del propio despliegue, así que el conjunto listado no puede desviarse de lo que realmente se ejecuta. Con enrutamiento EU-only, la entrada de Amazon Web Services SES no transporta el correo de un inquilino: el mensaje sale exclusivamente por los MTA propios de ApexMail, operados sobre infraestructura de Hetzner (Hetzner Online GmbH, Finlandia). Las entradas restantes son pagos (Mollie B.V., Ámsterdam) e inicio de sesión OAuth opcional (Google, GitHub), cada una con su país de procesamiento y su mecanismo de transferencia indicados en el registro.

Dicho de otro modo: con EU-only, ningún tercero controlado por EE. UU. transporta el correo. Con Global, AWS SES sí lo hace — en una región de la UE, bajo el DPA y las CCT de AWS, y el registro dice exactamente eso.

Evidencia: el [registro de subencargados](/es/subprocessors/) (generado y protegido contra desviaciones), la sección 5 del [DPA](/es/dpa/) y la [matriz de ubicaciones de datos](/es/data-locations/).

## Aislamiento del envío comercial

El correo que envía el autopiloto comercial de ApexMail se clasifica por procedencia y se enruta por una ranura de transporte comercial dedicada. Nunca se despacha por el transporte SES o de retransmisión de un cliente, y cuando esa ranura no está configurada, el correo comercial se **retiene** — no se llama al transporte del cliente como respaldo. Los rebotes y quejas comerciales van al conjunto de supresión del inquilino comercial, no a la reputación de envío de los clientes.

Evidencia: el aislamiento es una propiedad de la decisión de enrutamiento del worker de entrega, descrita en la [página de arquitectura](/architecture); el efecto visible para el cliente (dominios de reputación separados) coincide con el modelo de envío documentado en las [funciones de entregabilidad](/es/features/).

## El paquete de evidencia para revisiones

Para compradores que necesitan el argumento en forma verificable en lugar de prosa:

- **Línea contractual Compliance** — 1 M de emails, enrutamiento EU-only incluido, IP dedicada, **paquete de evidencia DORA/NIS2**, paquete de encargado del RGPD, recibos de enrutamiento firmados, registro de auditoría de 1 año, SSO. Mostrada con su precio exacto en la [página de precios](/es/pricing/).
- **Material RGPD/DPA** — el [DPA](/es/dpa/), la [política de privacidad](/es/privacy/) y la [página de flujos de cumplimiento](/es/compliance/); la documentación de tratamiento está disponible para revisión.
- **Límites honestos, declarados como límites** — HIPAA no se ofrece actualmente, la certificación ISO 27001 no se ofrece actualmente, y ningún paquete estandarizado SIG/CAIQ/HECVAT es un derecho del producto; los cuestionarios de seguridad se atienden caso por caso con material de revisión actual. Estas declaraciones provienen del mismo registro canónico de afirmaciones que encuadra los textos de este sitio.

Evidencia: la [página de cumplimiento](/es/compliance/) enlaza su documentación; para el proceso de revisión, [contacta con ventas](/es/contact/sales/).

## Idiomas y soporte

Este sitio y las superficies de cliente del producto se publican en inglés, alemán, francés y español. El soporte funciona por email (`support@apexmail.ee`) con condiciones según el plan; Business y Enterprise asumen los compromisos de disponibilidad y rendimiento del [SLA](/es/sla/), medidos con sondas externas y compensados según la matriz del plan.

Evidencia: las cuatro ediciones lingüísticas de cada página (selector de idioma en la cabecera), el [SLA](/es/sla/) y la [página de contacto](/es/contact/).

## Por dónde seguir

- [Matriz de ubicaciones de datos](/es/data-locations/) — dónde vive cada categoría de datos.
- [Registro de subencargados](/es/subprocessors/) — la lista generada de proveedores.
- [Flujos de cumplimiento](/es/compliance/) y el [DPA](/es/dpa/) — la capa contractual.
- [Precios](/es/pricing/) — el complemento EU-only (149 €/mes, desde Pro) y la línea Compliance.
- [Enterprise](/es/enterprise/) — Enterprise Cloud, donde el enrutamiento EU-only está incluido.
- [ApexMail vs Amazon SES](/es/compare/amazon-ses/) — la comparación honesta con el transporte que EU-only elimina.
- [Arquitectura](/architecture) — la ruta de entrega con detalle técnico.
