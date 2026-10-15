+++
title = "Migrar de Resend a ApexMail"
description = "Migre una integración de Resend a ApexMail cambiando la URL base: POST /emails y POST /emails/batch aceptan su clave API de ApexMail en la ranura bearer de Authorization que ya envía, con la correspondencia exacta de campos, los rechazos nombrados, la lista DNS y un plan de corte 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sirve `POST /emails` y `POST /emails/batch` en una superficie de compatibilidad de Resend. Las rutas traducen las cargas útiles JSON a la solicitud de envío canónica y luego llaman a los mismos manejadores que usan `POST /v1/messages` y `POST /v1/messages/batch`: la verificación del dominio remitente, los filtros de supresión y consentimiento, los derechos del plan, el registro de idempotencia duradero y la inserción en la cola se ejecutan en un solo lugar. Su integración conserva la forma de su carga útil y su encabezado bearer; el cambio es el host y la clave.

## Correspondencia de puntos de acceso

| Punto de acceso de Resend | Superficie de compatibilidad de ApexMail | Punto de acceso nativo de ApexMail |
|---|---|---|
| `POST https://api.resend.com/emails` | `POST https://api.apexmail.ee/emails` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.resend.com/emails/batch` | `POST https://api.apexmail.ee/emails/batch`, hasta 100 correos | `POST https://api.apexmail.ee/v1/messages/batch`, hasta 100 mensajes por llamada |
| `GET /emails/:id` (consulta) | No servido | `GET /v1/messages/{id}` |

Un envío correcto responde `200` con `{"id": "<identificador canónico del mensaje>"}`. La ruta por lotes responde `{"data": […]}` en el orden de la solicitud: cada posición lleva `{"id": …}` o un objeto `error` con el rechazo, de modo que un lote parcial nunca se presenta como un éxito completo. El identificador es el canónico, el mismo que devuelve `GET /v1/messages/{id}` y el mismo que los eventos webhook llevan en `data.messageId`.

## Cambio de autenticación

Su ranura de credencial se mantiene. Resend envía `Authorization: Bearer`; sustituya la clave por la clave API de ApexMail (`am_live_…` o `am_test_…`) y dele el alcance `messages:send`.

| Elemento | Resend hoy | Superficie de compatibilidad de ApexMail |
|---|---|---|
| Encabezado de credencial | `Authorization: Bearer re_…` | `Authorization: Bearer am_live_…` |
| Alcance | Acceso completo o clave solo de envío | `messages:send` |
| Idempotencia | Encabezado `Idempotency-Key` | El mismo encabezado, contra el registro duradero de ApexMail; la misma clave dentro de 24 horas reproduce la respuesta original, incluido el mismo identificador |
| Clase de asunto | No es un concepto del proveedor | `X-ApexMail-Category: transactional` (o `service`) exime el envío del filtro de preferencias de marketing; sin el encabezado, el envío cuenta como clase `marketing` predeterminada y se aplica el filtro de consentimiento |

## Correspondencia de campos

Los nombres canónicos son los del contrato `POST /v1/messages`, de modo que la misma comprensión de la carga útil se aplica si después pasa a la API nativa.

| Campo de Resend | Campo canónico | Notas |
|---|---|---|
| `from` | `from` | Obligatorio |
| `to` | `to` | Una cadena única, un array u objetos `{email, name}` |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `reply_to` | `reply_to` | |
| `headers` (objeto) | `headers` | Valores de cadena |
| `attachments[].filename` / `.content` / `.content_type` | `attachments[]` (`filename`, `content`, `contentType`) | `content_type` toma `application/octet-stream` por defecto |
| `tags[].name` / `.value` | `tags` | Cada par pasa a `"name:value"` |
| `scheduled_at` (ISO 8601) | `scheduled_at` | Solo marcas de tiempo RFC 3339 |
| Encabezado `X-ApexMail-Category` | `category` | Validado por el normalizador canónico |

## Campos que la superficie rechaza por nombre

Cada uno de estos elementos se rechaza con la forma de error propia de Resend `{"statusCode": <code>, "name": "<name>", "message": "…"}`: `statusCode` 422 con `name` `validation_error` en los rechazos de validación, `401` `invalid_api_key` o `missing_api_key` en los rechazos de credencial, y `403` `restricted_api_key` en una clave sin el alcance `messages:send`.

| Elemento de Resend | Rechazo |
|---|---|
| `attachments[].path` | Las URL de adjuntos remotas no se descargan; envíe el archivo como `content` en base64 |
| `template` | Las plantillas no tienen equivalente canónico en esta superficie; use la API nativa de ApexMail para plantillas |
| `topic_id`, `audience_id`, `broadcast_id` | Audiencias, topics y broadcasts no tienen equivalente canónico en esta superficie; use la API nativa para listas |
| Un `scheduled_at` en lenguaje natural (`"in 1 min"`) | Se requiere una marca de tiempo ISO 8601 (RFC 3339); las programaciones en lenguaje natural no se admiten |
| Un array por lotes de más de 100 correos | Un lote de Resend lleva como máximo 100 correos |
| Cualquier otro campo de nivel superior | Sin equivalente canónico |

## Lo que aún no se reenvía

La superficie de compatibilidad solo sirve las dos rutas de envío. Las API de Resend siguientes no tienen ruta de compatibilidad; use la API nativa de ApexMail o el panel.

- Plantillas (`template`) y la ruta de renderizado de plantillas.
- Audiencias, contactos, topics y broadcasts; las campañas, listas y segmentos de ApexMail cubren estas necesidades mediante la API nativa.
- Gestión de dominios (`/domains`): los dominios se añaden y verifican en el panel de ApexMail o con `POST /v1/domains`.
- Gestión de claves API, CRUD de suscripciones webhook y registro de eventos; las suscripciones webhook usan `POST /v1/webhooks`.
- Adjuntos descargados desde una URL remota y programación en lenguaje natural.
- Recepción entrante (`email.received`). La canalización entrante de ApexMail emite el evento `inbound`, y el correo entrante está disponible en Business y Enterprise Cloud.

## DNS: qué cambia y qué se mantiene

Su dominio de envío sigue siendo suyo, y ApexMail firma DKIM con un selector generado por dominio en ese mismo dominio. Añada los cuatro registros de `GET /v1/domains/:id/dns-records` junto a los registros de Resend; retire los de Resend solo después del corte y de la ventana de retención.

| Registro de Resend | Equivalente en ApexMail |
|---|---|
| Registro DKIM (el registro TXT del proveedor para el dominio) | Registro TXT directo en `<selector>._domainkey.<domain>` con la clave pública DKIM. Un TXT directo, no un CNAME |
| Registros de ruta de retorno (los registros MX y TXT SPF del proveedor en su propio subdominio) | Registro MX en `bounce.<domain>`, prioridad 10, hacia el host de retroalimentación de la región, más un registro TXT en `bounce.<domain>` con el valor SPF del MAIL FROM personalizado |
| CNAME de seguimiento de clics (cuando el seguimiento usa su dominio) | No se requiere CNAME de marca. ApexMail reescribe los enlaces a sus propias rutas de seguimiento; un dominio de seguimiento personalizado (CNAME en un subdominio de un dominio verificado) está disponible desde Pro |
| Autenticación de dominio | Registro TXT en `_dmarc.<domain>` con su política DMARC |

Lista de comprobación:

1. Añada el dominio de envío en el panel y obtenga sus registros DNS.
2. Publique los cuatro registros de ApexMail; deje los de Resend en su sitio.
3. Mantenga los registros de Resend mientras Resend envíe; los registros de su subdominio de ruta de retorno son independientes de los de ApexMail en `bounce.<domain>`.
4. Ejecute la verificación del dominio y confirme que el selector DKIM resuelve.
5. Mantenga activados los informes DMARC (rua) durante la transición.
6. Tras el corte y la ventana de retención, retire los registros de Resend y revoque la clave antigua.

## Plantillas

Las plantillas de Resend no se reenvían, y `template` se rechaza por nombre. Dos vías de conversión:

- Renderice el cuerpo en su aplicación y envíe `html` y `text` por la misma ruta de compatibilidad. Sin trabajo de migración de plantillas, y el envío conserva la forma de su carga útil.
- Cree una plantilla con `POST /v1/templates` y envíela con `template_id` más `template_data` en el `POST /v1/messages` nativo. Los marcadores se escriben `{{variable}}`; un marcador sin resolver se renderiza tal cual en lugar de vaciarse, de modo que una variable ausente se ve en la vista previa.

La forma de triple llave `{{{variable}}}` de Resend y sus componentes de React Email se renderizan en su aplicación o en su paso de compilación; el motor de marcadores acepta la sustitución `{{variable}}`, así que convierta esos cuerpos a HTML antes de crear la plantilla de ApexMail.

## Webhooks

Apunte su extremo a ApexMail, suscriba los eventos que consume y verifique la firma de ApexMail: `X-ApexMail-Signature: sha256=<hex>` sobre el cuerpo bruto de la solicitud junto con `X-ApexMail-Timestamp`. La entrega es al menos una vez, así que deduplique por el campo `id` del evento.

| Evento de Resend | Evento de ApexMail | Notas |
|---|---|---|
| `email.sent` | `message.accepted` | Aceptado para entrega |
| `email.scheduled` | `message.accepted` | El envío programado se acepta al encolar |
| `email.delivered` | `message.delivered` | El servidor destinatario aceptó el mensaje |
| `email.delivery_delayed` | `message.deferred` | Aplazamiento 4xx; hay un reintento programado |
| `email.bounced` | `message.bounced` | Rebote duro |
| `email.complained` | `message.complained` | |
| `email.opened` | `message.opened` | |
| `email.clicked` | `message.clicked` | |
| `email.failed` (correspondencia más cercana) | `message.bounced` | Los rechazos en la aceptación vuelven en la respuesta de la API |
| `email.received` | `inbound` | El correo entrante está disponible en Business y Enterprise Cloud |

La forma de la carga útil cambia con el proveedor: los eventos de ApexMail usan el sobre `{id, event, timestamp, data}`, con `data.messageId` en los eventos de mensaje y `data.email` en los de supresión.

## Plan de corte

El corte es un cambio de host por ruta o por entorno, así que la reversión es el mismo cambio a la inversa. No hay carga útil ni plantillas que deshacer.

| Paso | Acción | Criterios de salida | Reversión |
|---|---|---|---|
| 1. Preparar | Cree la cuenta, añada y verifique el dominio de envío, cree una clave API con `messages:send`, suscriba los eventos webhook | La verificación pasa; un mensaje de prueba sale desde un entorno de preproducción | Aún no hay tráfico de producción |
| 2. Validar en paralelo | Envíe las mismas cargas útiles a `https://api.apexmail.ee/emails` con la clave de ApexMail en la ranura bearer; compare respuestas, identificadores y eventos webhook | `200` con un identificador en cada prueba; los eventos llegan con firmas válidas | Devuelva la ruta de prueba a Resend |
| 3. Desplazar el 10 % | Dirija el 10 % de los envíos de producción por la ruta de compatibilidad; vigile las tasas de rebote y queja frente a los umbrales de la AUP (2 % de rebotes, 0,1 % de quejas) | Las métricas de entrega igualan a Resend dentro de la tolerancia acordada durante la ventana de observación | Devuelva la ruta; Resend conserva el otro 90 % |
| 4. Desplazar el 50 % | Suba al 50 % cuando la ventana cierre limpia; ambos proveedores envían desde el mismo dominio | Paridad sostenida en la cuota superior | Vuelva al 100 % en Resend |
| 5. Cortar al 100 % | Dirija todos los envíos por `POST /emails` (y `/emails/batch`) en ApexMail | Volumen completo en ApexMail con métricas limpias | Vuelva atrás; las claves siguen activas durante la ventana de retención |
| 6. Retirar la ruta antigua | Retire los registros DNS de Resend, revoque su clave, retire la configuración de plantillas y audiencias | Los registros resuelven solo hacia ApexMail | Restaure los registros desde su registro de cambios |

## Siguientes pasos

- Compare ambas plataformas característica por característica en la [comparación ApexMail vs. Resend](/es/compare/resend/).
- Lea la [visión general de la API](/docs/api/) y la [especificación OpenAPI](/docs/api/openapi/) para el contrato nativo, incluidos envíos por lotes y plantillas.
- Lea [Webhooks](/docs/webhooks/) para los esquemas de carga útil y la verificación de firmas.
- [Contacte con ventas](/es/contact/sales/) para una evaluación de migración si las plantillas, audiencias o broadcasts de Resend forman parte de su tráfico de producción.
