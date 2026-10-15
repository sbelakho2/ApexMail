+++
title = "Migrar de Mailgun a ApexMail"
description = "Migre una integración de Mailgun a ApexMail cambiando la URL base: POST /v3/{domain}/messages acepta su clave API de ApexMail en la ranura de autenticación básica de Mailgun, con la correspondencia exacta de campos, los rechazos nombrados, la respuesta de messages.mime, la lista DNS y un plan de corte 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sirve `POST /v3/{domain}/messages` en una superficie de compatibilidad de Mailgun. La ruta traduce los campos de formulario a la solicitud de envío canónica y luego llama al mismo manejador que usa `POST /v1/messages`: la verificación del dominio remitente, los filtros de supresión y consentimiento, los derechos del plan, el registro de idempotencia y la inserción en la cola se ejecutan en un solo lugar. Su integración conserva sus campos de formulario y la forma de su punto de acceso; el cambio es el host y la clave.

## Correspondencia de puntos de acceso

| Punto de acceso de Mailgun | Superficie de compatibilidad de ApexMail | Punto de acceso nativo de ApexMail |
|---|---|---|
| `POST https://api.mailgun.net/v3/{domain}/messages` (UE: `api.eu.mailgun.net`) | `POST https://api.apexmail.ee/v3/{domain}/messages` | `POST https://api.apexmail.ee/v1/messages` |
| `POST /v3/{domain}/messages.mime` (MIME bruto) | Conectado y respondido `501` tras la autenticación, con el motivo | `POST /v1/messages` con campos estructurados, o un relé MTA por SMTP |
| Sin punto de acceso por lotes en esta superficie | Una solicitud por mensaje | `POST /v1/messages/batch`, hasta 100 mensajes por llamada |

El segmento de ruta `{domain}` es el dominio de envío de Mailgun y debe coincidir con el dominio de la dirección `from`. La ruta de envío canónica deriva la identidad DKIM del dominio remitente, de modo que una discrepancia se rechaza por nombre en lugar de firmarse con otra autoridad.

Un envío correcto responde `200` con `{"id": "<identificador canónico del mensaje>@{domain}", "message": "Queued. Thank you."}`. El identificador entre corchetes es el identificador canónico del mensaje, el mismo que devuelve `GET /v1/messages/{id}` y el mismo que los eventos webhook llevan en `data.messageId`.

`messages.mime` responde un `501` nombrado: `POST /v3/{domain}/messages.mime is not implemented by the ApexMail compatibility surface: raw MIME passthrough would require a second MIME parser in the request path. Use /v3/{domain}/messages with structured fields (from/to/subject/html/text/attachment), or the canonical POST /v1/messages API.`

## Cambio de autenticación

Su ranura de credencial se mantiene. Mailgun envía `Authorization: Basic base64("api:<key>")`; sustituya la clave por la clave API de ApexMail (`am_live_…` o `am_test_…`) y dele el alcance `messages:send`. El nombre de usuario no tiene autoridad y se acepta tal como llega.

| Elemento | Mailgun hoy | Superficie de compatibilidad de ApexMail |
|---|---|---|
| Encabezado de credencial | `Authorization: Basic base64("api:<key>")` | `Authorization: Basic base64("api:am_live_…")` |
| Tipo de cuerpo | `application/x-www-form-urlencoded` o `multipart/form-data` | Los mismos dos tipos de cuerpo |
| Alcance | Permisos de la clave, opcionalmente por dominio | `messages:send` |
| Idempotencia | No ofrecida | `Idempotency-Key: <uuid>` en la misma ruta; la misma clave dentro de 24 horas reproduce la respuesta original, incluido el mismo identificador de mensaje |
| Clase de asunto | No es un concepto del proveedor | `X-ApexMail-Category: transactional` (o `service`) exime el envío del filtro de preferencias de marketing; sin el encabezado, el envío cuenta como clase `marketing` predeterminada y se aplica el filtro de consentimiento |

## Correspondencia de campos

Los nombres canónicos son los del contrato `POST /v1/messages`, de modo que la misma comprensión de la carga útil se aplica si después pasa a la API nativa.

| Campo de Mailgun | Campo canónico | Notas |
|---|---|---|
| `from` | `from` | Obligatorio; su dominio debe coincidir con el segmento de ruta `{domain}` |
| `to` | `to` | Repetible o separado por comas; los nombres para mostrar entre comillas conservan sus comas |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `attachment` (parte de archivo multipart) | `attachments[]` | Contenido en base64, nombre de archivo y Content-Type de la parte; este último toma `application/octet-stream` por defecto |
| `o:tag` | `tags` | Duplicados eliminados |
| `o:deliverytime` | `scheduled_at` | Marca de tiempo RFC 2822, por ejemplo `Fri, 15 Oct 2026 12:00:00 -0000` |
| `h:X-Foo` | `headers` | Cualquier nombre de encabezado; `h:Reply-To` pasa al campo dedicado `reply_to` |
| `v:my-var` | `metadata` | |
| Encabezado `X-ApexMail-Category` | `category` | Validado por el normalizador canónico |
| `o:tracking=yes`, `o:tracking-clicks=yes`, `o:tracking-opens=yes`, `o:dkim=yes` | Sin efecto, aceptado | Coinciden con los valores predeterminados de la plataforma |
| `o:testmode=no` | Sin efecto, aceptado | El modo de prueba está apagado, que es el comportamiento de la plataforma |

## Campos que la superficie rechaza por nombre

Cada uno de estos elementos se rechaza con la forma de error propia de Mailgun `{"message": "…"}` con estado `400`, nunca se descarta en silencio. Varios problemas en una solicitud se unen en el único mensaje.

| Elemento de Mailgun | Rechazo |
|---|---|
| Parte de archivo `inline` | La ruta de envío canónica no tiene concepto de parte en línea; adjunte el archivo en lugar de incrustarlo |
| `attachment` enviado como valor de formulario | Los adjuntos deben enviarse como partes de archivo multipart (`-F attachment=@file`), no como valores de formulario |
| `template` (plantillas almacenadas) | Campo sin equivalente canónico |
| `o:campaign` | Campo sin equivalente canónico |
| `o:require-tls` | Campo sin equivalente canónico |
| `o:skip-verification` | Campo sin equivalente canónico |
| `o:tracking=no`, `o:tracking-clicks=no`, `o:tracking-opens=no`, `o:dkim=no` | Esta superficie no puede desactivar el comportamiento correspondiente; el seguimiento y la firma DKIM son ajustes de despliegue |
| `o:testmode=yes` | La ruta de envío canónica no tiene modo de entrega suprimida por mensaje; use la superficie de modo de prueba de la plataforma en lugar de enviar en silencio |
| Cualquier otro campo `o:*` y cualquier campo de formulario desconocido | Sin equivalente canónico en la superficie de compatibilidad de Mailgun |
| `{domain}` distinto del dominio de la dirección `from` | El segmento de ruta debe ser el dominio de la dirección `from`, porque la ruta de envío canónica firma con el dominio remitente |
| Un nombre de encabezado enviado dos veces, o dos valores `Reply-To` distintos | El duplicado se rechaza en lugar de resolverse eligiendo un valor |

## Lo que aún no se reenvía

La superficie de compatibilidad solo sirve la ruta de envío. Las API de Mailgun siguientes no tienen ruta de compatibilidad; use la API nativa de ApexMail o el panel.

- Envíos MIME brutos (`messages.mime`) y el campo `template` para plantillas almacenadas en Mailgun.
- Controles de entrega por mensaje: `o:require-tls`, `o:skip-verification`, `o:dkim=no`, `o:tracking*=no`, `o:testmode=yes`.
- Campañas (`o:campaign`), listas de correo y API de eventos y estadísticas.
- API de rutas, dominios, webhooks y supresiones: las supresiones viven en la lista de supresión de ApexMail; las suscripciones webhook usan `POST /v1/webhooks`.
- Enrutado entrante (Mailgun Routes) y recuperación de mensajes almacenados.
- Punto de acceso por lotes en la superficie de compatibilidad; el envío por lotes va por la API nativa (hasta 100 por llamada).

## DNS: qué cambia y qué se mantiene

Su dominio de envío sigue siendo suyo, y ApexMail firma DKIM con un selector generado por dominio en ese mismo dominio. Añada los cuatro registros de `GET /v1/domains/:id/dns-records` junto a los registros de Mailgun; retire los de Mailgun solo después del corte y de la ventana de retención.

| Registro de Mailgun | Equivalente en ApexMail |
|---|---|
| Registro DKIM bajo `mx._domainkey` o el host DKIM del proveedor | Registro TXT directo en `<selector>._domainkey.<domain>` con la clave pública DKIM. Un TXT directo, no un CNAME |
| Registros de ruta de retorno de Mailgun (mecanismo SPF `include:mailgun.org`, MX en el subdominio de rebote) | Registro TXT en `bounce.<domain>` con el valor SPF del MAIL FROM personalizado, y registro MX en `bounce.<domain>`, prioridad 10, hacia el host de retroalimentación de la región |
| CNAME de seguimiento de enlaces de marca | No se requiere CNAME de marca. ApexMail reescribe los enlaces a sus propias rutas de seguimiento; un dominio de seguimiento personalizado (CNAME en un subdominio de un dominio verificado) está disponible desde Pro |
| Autenticación de dominio | Registro TXT en `_dmarc.<domain>` con su política DMARC |

Lista de comprobación:

1. Añada el dominio de envío en el panel y obtenga sus registros DNS.
2. Publique los cuatro registros de ApexMail; deje los de Mailgun en su sitio.
3. Mantenga los registros de ruta de retorno de Mailgun mientras Mailgun envíe, porque el dominio MAIL FROM de Mailgun es un subdominio propio.
4. Ejecute la verificación del dominio y confirme que el selector DKIM resuelve.
5. Mantenga activados los informes DMARC (rua) durante la transición.
6. Tras el corte y la ventana de retención, retire los registros de Mailgun y revoque la clave antigua.

## Plantillas

Las plantillas almacenadas en Mailgun (`template` más `t:variables`) no se reenvían, y el campo se rechaza por nombre. Dos vías de conversión:

- Renderice el cuerpo en su aplicación y envíe `html` y `text` por la misma ruta de compatibilidad. Sin trabajo de migración de plantillas, y el envío conserva sus campos de formulario.
- Cree una plantilla con `POST /v1/templates` y envíela con `template_id` más `template_data` en el `POST /v1/messages` nativo. Los marcadores se escriben `{{variable}}`; un marcador sin resolver se renderiza tal cual en lugar de vaciarse, de modo que una variable ausente se ve en la vista previa.

Las variables de plantilla de Mailgun viajan como campos de formulario `t:name=value`; en la ruta de compatibilidad use metadatos `v:` o renderice los valores en el cuerpo, y mueva las variables a `template_data` cuando adopte la API de plantillas nativa.

## Webhooks

Los webhooks de Mailgun envían JSON a su extremo (tipo `http-post`). Apunte el extremo a ApexMail, suscriba los eventos que consume y verifique la firma de ApexMail: `X-ApexMail-Signature: sha256=<hex>` sobre el cuerpo bruto de la solicitud junto con `X-ApexMail-Timestamp`. La entrega es al menos una vez, así que deduplique por el campo `id` del evento.

| Evento de Mailgun | Evento de ApexMail | Notas |
|---|---|---|
| `accepted` | `message.accepted` | Aceptado para entrega |
| `stored` | `message.queued` | El mensaje entró en la cola de salida |
| `delivered` | `message.delivered` | El servidor destinatario aceptó el mensaje |
| `failed` de gravedad permanente | `message.bounced` | Rebote duro |
| `failed` de gravedad temporal | `message.deferred` | Aplazamiento 4xx; hay un reintento programado |
| `rejected` | `message.suppressed` | Rechazo por lista de supresión o política |
| `opened` | `message.opened` | |
| `clicked` | `message.clicked` | |
| `complained` | `message.complained` | |
| `unsubscribed` | `recipient.unsubscribed` | |

La forma de la carga útil cambia con el proveedor: los eventos de ApexMail usan el sobre `{id, event, timestamp, data}`, con `data.messageId` en los eventos de mensaje y `data.email` en los de supresión.

## Plan de corte

El corte es un cambio de host por ruta o por entorno, así que la reversión es el mismo cambio a la inversa. No hay campos de formulario ni plantillas que deshacer.

| Paso | Acción | Criterios de salida | Reversión |
|---|---|---|---|
| 1. Preparar | Cree la cuenta, añada y verifique el dominio de envío, cree una clave API con `messages:send`, suscriba los eventos webhook | La verificación pasa; un mensaje de prueba sale desde un entorno de preproducción | Aún no hay tráfico de producción |
| 2. Validar en paralelo | Envíe las mismas cargas de formulario a `https://api.apexmail.ee/v3/{domain}/messages` con la clave de ApexMail en la ranura básica; compare respuestas, identificadores y eventos webhook | `200` con el cuerpo `Queued. Thank you.` en cada prueba; los eventos llegan con firmas válidas | Devuelva la ruta de prueba a Mailgun |
| 3. Desplazar el 10 % | Dirija el 10 % de los envíos de producción por la ruta de compatibilidad; vigile las tasas de rebote y queja frente a los umbrales de la AUP (2 % de rebotes, 0,1 % de quejas) | Las métricas de entrega igualan a Mailgun dentro de la tolerancia acordada durante la ventana de observación | Devuelva la ruta; Mailgun conserva el otro 90 % |
| 4. Desplazar el 50 % | Suba al 50 % cuando la ventana cierre limpia; ambos proveedores envían desde el mismo dominio | Paridad sostenida en la cuota superior | Vuelva al 100 % en Mailgun |
| 5. Cortar al 100 % | Dirija todos los envíos por `POST /v3/{domain}/messages` en ApexMail | Volumen completo en ApexMail con métricas limpias | Vuelva atrás; las claves siguen activas durante la ventana de retención |
| 6. Retirar la ruta antigua | Retire los registros DNS de Mailgun, revoque su clave, retire la configuración de plantillas almacenadas | Los registros resuelven solo hacia ApexMail | Restaure los registros desde su registro de cambios |

## Siguientes pasos

- Compare ambas plataformas característica por característica en la [comparación ApexMail vs. Mailgun](/es/compare/mailgun/).
- Lea la [visión general de la API](/docs/api/) y la [especificación OpenAPI](/docs/api/openapi/) para el contrato nativo, incluidos envíos por lotes y plantillas.
- Lea [Webhooks](/docs/webhooks/) para los esquemas de carga útil y la verificación de firmas.
- [Contacte con ventas](/es/contact/sales/) para una evaluación de migración si una ruta MIME bruta o plantillas almacenadas forman parte de su tráfico de producción.
