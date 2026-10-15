+++
title = "Migrar de Postmark a ApexMail"
description = "Migre una integración de Postmark a ApexMail cambiando la URL base: POST /email y POST /email/batch aceptan su clave API de ApexMail en el encabezado X-Postmark-Server-Token, con la correspondencia de MessageStream, los rechazos nombrados, la lista DNS y un plan de corte 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sirve `POST /email` y `POST /email/batch` en una superficie de compatibilidad de Postmark. Las rutas traducen las cargas útiles JSON a la solicitud de envío canónica y luego llaman a los mismos manejadores que usan `POST /v1/messages` y `POST /v1/messages/batch`: la verificación del dominio remitente, los filtros de supresión y consentimiento, los derechos del plan, el registro de idempotencia y la inserción en la cola se ejecutan en un solo lugar. Su integración conserva la forma de su carga útil y su encabezado; el cambio es el host y el token.

## Correspondencia de puntos de acceso

| Punto de acceso de Postmark | Superficie de compatibilidad de ApexMail | Punto de acceso nativo de ApexMail |
|---|---|---|
| `POST https://api.postmarkapp.com/email` | `POST https://api.apexmail.ee/email` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.postmarkapp.com/email/batch` | `POST https://api.apexmail.ee/email/batch`, hasta 500 mensajes | `POST https://api.apexmail.ee/v1/messages/batch`, hasta 100 mensajes por llamada |
| `POST /email/bulk` (envío masivo por plantilla) | No servido | `POST /v1/messages/batch` con cuerpos explícitos, o un identificador de plantilla por mensaje |

Un envío correcto responde `200` con `{"ErrorCode": 0, "Message": "OK", "MessageID": "<identificador canónico del mensaje>"}`. La ruta por lotes responde un array ordenado con un objeto de resultado por mensaje solicitado: `ErrorCode` 0 con el `MessageID`, o un `ErrorCode` distinto de cero con el texto del rechazo en esa posición, de modo que un lote parcial nunca se presenta como un éxito completo. El identificador es el canónico, el mismo que devuelve `GET /v1/messages/{id}` y el mismo que los eventos webhook llevan en `data.messageId`.

## Cambio de autenticación

Su ranura de credencial se mantiene. Postmark envía `X-Postmark-Server-Token`; sustituya el valor por la clave API de ApexMail (`am_live_…` o `am_test_…`) y dele el alcance `messages:send`.

| Elemento | Postmark hoy | Superficie de compatibilidad de ApexMail |
|---|---|---|
| Encabezado de credencial | `X-Postmark-Server-Token: <server token>` | `X-Postmark-Server-Token: am_live_…` |
| Alcance | Token a nivel de servidor | `messages:send` |
| Idempotencia | No ofrecida | `Idempotency-Key: <uuid>` en la misma ruta; la misma clave dentro de 24 horas reproduce la respuesta original, incluido el mismo `MessageID` |
| Clase de asunto | `MessageStream` selecciona el flujo | `MessageStream` `outbound` pasa a `transactional` y `broadcast` a `marketing`; el encabezado `X-ApexMail-Category` también funciona y acepta `transactional`, `service` o `marketing` |

## Correspondencia de campos

Los nombres canónicos son los del contrato `POST /v1/messages`, de modo que la misma comprensión de la carga útil se aplica si después pasa a la API nativa.

| Campo de Postmark | Campo canónico | Notas |
|---|---|---|
| `From` | `from` | Obligatorio |
| `To` | `to` | Cadena separada por comas o array; los nombres para mostrar entre comillas conservan sus comas |
| `Cc` / `Bcc` | `cc` / `bcc` | |
| `Subject` | `subject` | |
| `HtmlBody` / `TextBody` | `html` / `text` | |
| `ReplyTo` | `reply_to` | |
| `Headers[].Name` / `.Value` | `headers` | `Reply-To` pasa al campo dedicado `reply_to` |
| `Attachments[].Name` / `.Content` / `.ContentType` | `attachments[]` (`filename`, `content`, `contentType`) | `ContentType` toma `application/octet-stream` por defecto |
| `Tag` | `tags` (una etiqueta) | |
| `Metadata` (valores de cadena) | `metadata` | Los valores que no son cadenas se rechazan por nombre |
| `MessageStream` `outbound` / `broadcast` | `category` `transactional` / `marketing` | |
| `TrackOpens` / `TrackLinks` `true` | Sin efecto, aceptado | La plataforma registra aperturas y clics en cada envío |
| Encabezado `X-ApexMail-Category` | `category` | Validado por el normalizador canónico |

El envío programado no forma parte de esta superficie: la carga útil de Postmark no tiene campo de programación, así que la ruta de compatibilidad tampoco. Use `scheduled_at` (ISO 8601) en el `POST /v1/messages` nativo.

## Campos que la superficie rechaza por nombre

Cada uno de estos elementos se rechaza con la forma de error propia de Postmark `{"ErrorCode": <code>, "Message": "…"}`. Los rechazos de validación responden `422`; un token ausente o inválido responde `401` con `ErrorCode` 10.

| Elemento de Postmark | Rechazo |
|---|---|
| `TemplateId`, `TemplateAlias` | Un identificador de plantilla de Postmark no es un identificador de plantilla de ApexMail; renderice el cuerpo en el cliente o envíe un `template_id` de ApexMail por la API nativa |
| `TemplateModel` | La ruta de envío canónica no tiene equivalente para este campo |
| `InlineImages`, `Attachments[].ContentID` | La ruta de envío canónica no tiene concepto de parte en línea; adjunte el archivo en lugar de incrustarlo |
| `TrackOpens: false`, `TrackLinks: false` | La plataforma registra aperturas y clics en cada envío; el seguimiento por mensaje no puede desactivarse en esta superficie |
| Cualquier otro valor de `MessageStream` | Solo `outbound` (transaccional) y `broadcast` (marketing) corresponden a la categoría canónica |
| Un array por lotes de más de 500 mensajes | Un lote de Postmark lleva como máximo 500 mensajes |
| Cualquier otro campo de nivel superior | Sin equivalente canónico |
| Un valor no de cadena en `Metadata` | Los valores de Metadata deben ser cadenas |
| Un `Headers[].Name` enviado dos veces | El encabezado duplicado se rechaza en lugar de resolverse eligiendo un valor |

## Lo que aún no se reenvía

La superficie de compatibilidad solo sirve las dos rutas de envío. Las API de Postmark siguientes no tienen ruta de compatibilidad; use la API nativa de ApexMail o el panel.

- Plantillas y diseños (`/templates`, renderizado de `TemplateModel`).
- Administración de flujos de mensajes y configuración por servidor.
- Búsqueda de mensajes salientes, estadísticas y puntos de acceso de rebote; los datos de rebote llegan mediante eventos `message.bounced`.
- El punto de acceso `/email/bulk` (envío masivo por plantilla).
- Configuración de webhooks entrantes. La canalización entrante de ApexMail emite el evento `inbound`, y el correo entrante está disponible en Business y Enterprise Cloud.
- Gestión de supresiones mediante la API de Postmark; las supresiones viven en la lista de supresión de ApexMail.

## DNS: qué cambia y qué se mantiene

Su dominio de envío sigue siendo suyo, y ApexMail firma DKIM con un selector generado por dominio en ese mismo dominio. Añada los cuatro registros de `GET /v1/domains/:id/dns-records` junto a los registros de Postmark; retire los de Postmark solo después del corte y de la ventana de retención.

| Registro de Postmark | Equivalente en ApexMail |
|---|---|
| Registro DKIM (el par TXT o CNAME que el proveedor emite por servidor) | Registro TXT directo en `<selector>._domainkey.<domain>` con la clave pública DKIM. Un TXT directo, no un CNAME |
| CNAME de ruta de retorno (el dominio de rebote del proveedor) | Registro MX en `bounce.<domain>`, prioridad 10, hacia el host de retroalimentación de la región, más un registro TXT en `bounce.<domain>` con el valor SPF del MAIL FROM personalizado |
| CNAME de seguimiento de enlaces de marca (cuando el seguimiento usa su dominio) | No se requiere CNAME de marca. ApexMail reescribe los enlaces a sus propias rutas de seguimiento; un dominio de seguimiento personalizado (CNAME en un subdominio de un dominio verificado) está disponible desde Pro |
| Autenticación de dominio | Registro TXT en `_dmarc.<domain>` con su política DMARC |

Lista de comprobación:

1. Añada el dominio de envío en el panel y obtenga sus registros DNS.
2. Publique los cuatro registros de ApexMail; deje los de Postmark en su sitio.
3. Mantenga los registros de Postmark mientras Postmark envíe. El dominio MAIL FROM de Postmark es propio del proveedor, así que sus registros son independientes de los de ApexMail en `bounce.<domain>`.
4. Ejecute la verificación del dominio y confirme que el selector DKIM resuelve.
5. Mantenga activados los informes DMARC (rua) durante la transición.
6. Tras el corte y la ventana de retención, retire los registros de Postmark y revoque el token de servidor antiguo.

## Plantillas

Las plantillas, diseños y alias de Postmark no se reenvían, y `TemplateId`, `TemplateAlias` y `TemplateModel` se rechazan por nombre. Dos vías de conversión:

- Renderice el cuerpo en su aplicación y envíe `HtmlBody` y `TextBody` por la misma ruta de compatibilidad. Sin trabajo de migración de plantillas, y el envío conserva la forma de su carga útil.
- Cree una plantilla con `POST /v1/templates` y envíela con `template_id` más `template_data` en el `POST /v1/messages` nativo. Los marcadores se escriben `{{variable}}`; un marcador sin resolver se renderiza tal cual en lugar de vaciarse, de modo que una variable ausente se ve en la vista previa.

Los diseños de Postmark (una envoltura común alrededor de las plantillas de mensaje) corresponden al propio cuerpo de la plantilla: integre el HTML del diseño en cada plantilla de ApexMail, o siga renderizando en su aplicación. Los condicionales y bucles de Mustachio no tienen equivalente directo en el motor de marcadores; convierta esas plantillas a HTML renderizado en su aplicación o divídalas en plantillas por caso.

## Webhooks

Los webhooks de Postmark envían JSON por flujo de mensajes a su extremo. Apunte el extremo a ApexMail, suscriba los eventos que consume y verifique la firma de ApexMail: `X-ApexMail-Signature: sha256=<hex>` sobre el cuerpo bruto de la solicitud junto con `X-ApexMail-Timestamp`. La entrega es al menos una vez, así que deduplique por el campo `id` del evento.

| Webhook de Postmark | Evento de ApexMail | Notas |
|---|---|---|
| `Delivery` | `message.delivered` | El servidor destinatario aceptó el mensaje |
| `Bounce` con `Type: HardBounce` | `message.bounced` | Rebote duro |
| `Bounce` con `Type: Transient` | `message.deferred` | Aplazamiento 4xx; hay un reintento programado |
| `SpamComplaint` | `message.complained` | |
| `Open` | `message.opened` | |
| `Click` | `message.clicked` | |
| `SubscriptionChange` | `recipient.unsubscribed` | ApexMail emite la dirección de baja; las resubscripciones quedan anotadas en el registro de preferencias |
| `Inbound` | `inbound` | El correo entrante está disponible en Business y Enterprise Cloud |
| `SMTPAPIError` | Sin evento equivalente | Los rechazos en la aceptación vuelven en la respuesta de la API |

La forma de la carga útil cambia con el proveedor: los eventos de ApexMail usan el sobre `{id, event, timestamp, data}`, con `data.messageId` en los eventos de mensaje y `data.email` en los de supresión.

## Plan de corte

El corte es un cambio de host por ruta o por entorno, así que la reversión es el mismo cambio a la inversa. No hay carga útil ni plantillas que deshacer.

| Paso | Acción | Criterios de salida | Reversión |
|---|---|---|---|
| 1. Preparar | Cree la cuenta, añada y verifique el dominio de envío, cree una clave API con `messages:send`, suscriba los eventos webhook | La verificación pasa; un mensaje de prueba sale desde un entorno de preproducción | Aún no hay tráfico de producción |
| 2. Validar en paralelo | Envíe las mismas cargas útiles a `https://api.apexmail.ee/email` con la clave de ApexMail en `X-Postmark-Server-Token`; compare respuestas, valores `MessageID` y eventos webhook | `ErrorCode` 0 en cada prueba; los eventos llegan con firmas válidas | Devuelva la ruta de prueba a Postmark |
| 3. Desplazar el 10 % | Dirija el 10 % de los envíos de producción por la ruta de compatibilidad; vigile las tasas de rebote y queja frente a los umbrales de la AUP (2 % de rebotes, 0,1 % de quejas) | Las métricas de entrega igualan a Postmark dentro de la tolerancia acordada durante la ventana de observación | Devuelva la ruta; Postmark conserva el otro 90 % |
| 4. Desplazar el 50 % | Suba al 50 % cuando la ventana cierre limpia; ambos proveedores envían desde el mismo dominio | Paridad sostenida en la cuota superior | Vuelva al 100 % en Postmark |
| 5. Cortar al 100 % | Dirija todos los envíos por `POST /email` (y `/email/batch`) en ApexMail | Volumen completo en ApexMail con métricas limpias | Vuelva atrás; los tokens siguen activos durante la ventana de retención |
| 6. Retirar la ruta antigua | Retire los registros DNS de Postmark, revoque el token de servidor, retire la configuración de plantillas y flujos | Los registros resuelven solo hacia ApexMail | Restaure los registros desde su registro de cambios |

## Siguientes pasos

- Compare ambas plataformas característica por característica en la [comparación ApexMail vs. Postmark](/es/compare/postmark/).
- Lea la [visión general de la API](/docs/api/) y la [especificación OpenAPI](/docs/api/openapi/) para el contrato nativo, incluidos envíos por lotes y plantillas.
- Lea [Webhooks](/docs/webhooks/) para los esquemas de carga útil y la verificación de firmas.
- [Contacte con ventas](/es/contact/sales/) para una evaluación de migración si las plantillas de Postmark o los webhooks entrantes forman parte de su tráfico de producción.
