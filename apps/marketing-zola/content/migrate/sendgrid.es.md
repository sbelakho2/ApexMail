+++
title = "Migrar de SendGrid a ApexMail"
description = "Migre una integración de SendGrid a ApexMail cambiando la URL base: la superficie de compatibilidad sirve POST /v3/mail/send con una clave API de ApexMail en el mismo encabezado Authorization, con la correspondencia de campos, los rechazos nombrados, la lista DNS, los nombres de eventos webhook y un plan de corte 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sirve `POST /v3/mail/send` en una superficie de compatibilidad de SendGrid. La ruta traduce la carga útil de SendGrid a la solicitud de envío canónica y luego llama al mismo manejador que usa `POST /v1/messages`: la verificación del dominio remitente, los filtros de supresión y consentimiento, los derechos del plan, el registro de idempotencia y la inserción en la cola se ejecutan en un solo lugar. Su integración conserva la forma de su solicitud; el cambio es la URL base y la clave.

## Correspondencia de puntos de acceso

| Punto de acceso de SendGrid | Superficie de compatibilidad de ApexMail | Punto de acceso nativo de ApexMail |
|---|---|---|
| `POST https://api.sendgrid.com/v3/mail/send` | `POST https://api.apexmail.ee/v3/mail/send` | `POST https://api.apexmail.ee/v1/messages` |
| Sin punto de acceso por lotes en esta superficie | Una solicitud por mensaje | `POST https://api.apexmail.ee/v1/messages/batch`, hasta 100 mensajes por llamada |

Un envío correcto responde `202 Accepted` con cuerpo vacío y el identificador canónico del mensaje en el encabezado `X-Message-Id`. Ese identificador es el mismo que devuelve `GET /v1/messages/{id}` y el mismo que los eventos webhook llevan en `data.messageId`.

Una entrada de `personalizations` por solicitud: la superficie procesa exactamente una. Una carga útil con varias personalizaciones se rechaza de forma nombrada en lugar de enviarse con asuntos o encabezados descartados.

## Cambio de autenticación

Su ranura de credencial se mantiene. Envíe la clave API de ApexMail (`am_live_…` o `am_test_…`) donde estaba la clave de SendGrid y dele el alcance `messages:send` que también exige `POST /v1/messages`.

| Elemento | SendGrid hoy | Superficie de compatibilidad de ApexMail |
|---|---|---|
| Encabezado de credencial | `Authorization: Bearer SG.…` | `Authorization: Bearer am_live_…` |
| Alcance | Permisos de la clave | `messages:send` |
| Idempotencia | No ofrecida | `Idempotency-Key: <uuid>` en la misma ruta; la misma clave dentro de 24 horas reproduce la respuesta original, incluido el mismo `X-Message-Id` |
| Clase de asunto | No es un concepto del proveedor | `X-ApexMail-Category: transactional` (o `service`) exime el envío del filtro de preferencias de marketing; sin el encabezado, el envío cuenta como clase `marketing` predeterminada y se aplica el filtro de consentimiento |

## Correspondencia de campos

Los nombres canónicos son los del contrato `POST /v1/messages`, de modo que la misma comprensión de la carga útil se aplica si después pasa a la API nativa.

| Campo de SendGrid | Campo canónico | Notas |
|---|---|---|
| `from` (`{email, name}` o cadena) | `from` | `"Name <addr>"` cuando hay un nombre |
| `personalizations[0].to[]` | `to` | Obligatorio; se aceptan cadenas de dirección, cadenas `"Name <addr>"` y objetos `{email, name}` |
| `personalizations[0].cc[]` / `.bcc[]` | `cc` / `bcc` | |
| `personalizations[0].subject` (si no, `subject` de nivel superior) | `subject` | Gana el valor de la personalización |
| `personalizations[0].headers`, fusionados bajo `headers` de nivel superior | `headers` | Un encabezado definido en ambos lugares con valores distintos se rechaza |
| `content[]` con `type` `text/plain` / `text/html` | `text` / `html` | Exactamente una parte de cada tipo |
| `attachments[].content`, `.filename`, `.type` | `attachments[]` (`filename`, `content`, `contentType`) | `type` toma `application/octet-stream` por defecto |
| `categories[]` y `X-SMTPAPI` `category`/`categories` | `tags` | Las etiquetas duplicadas se eliminan |
| `custom_args` y `X-SMTPAPI` `unique_args` | `metadata` | Solo valores de cadena; una clave definida en ambos lugares con valores distintos se rechaza |
| `reply_to` | `reply_to` | |
| `send_at` (segundos Unix) | `scheduled_at` | |
| Encabezado `X-ApexMail-Category` | `category` | Validado por el normalizador canónico |
| `mail_settings.sandbox_mode.enable = false` | Sin efecto, aceptado | El valor predeterminado documentado de los SDK |

## Campos que la superficie rechaza por nombre

Cada uno de estos elementos se rechaza con la forma de error propia de SendGrid `{"errors": [{"message", "field", "help"}]}`, nunca se descarta en silencio. El par canónico 400/422 se representa como `400` de SendGrid.

| Elemento de SendGrid | Rechazo |
|---|---|
| Más de una entrada de `personalizations` | `more than one 'personalizations' entry is not supported by the ApexMail compatibility surface: per-personalization subject/headers would be dropped — send one request per personalization` |
| `personalizations[].substitutions`, `.dynamic_template_data` | Campo sin equivalente canónico |
| `template_id`, `dynamic_template_data` | Los identificadores de plantilla de SendGrid no son identificadores de plantilla de ApexMail |
| `attachments[].content_id`, `disposition: "inline"` | La ruta de envío canónica no tiene concepto de parte en línea; adjunte el archivo en lugar de incrustarlo |
| `content[].type` distinto de `text/plain` y `text/html` | Solo esas dos partes tienen equivalente canónico |
| `asm`, `batch_id`, `ip_pool_name` | Sin equivalente canónico |
| `mail_settings.*` salvo el no-op de sandbox | Sin equivalente canónico |
| `mail_settings.sandbox_mode.enable = true` | Sin modo sandbox por mensaje; use la superficie de modo de prueba de la plataforma |
| `tracking_settings.*` | Sin equivalente canónico |
| Claves `X-SMTPAPI` distintas de `category`, `categories`, `unique_args` | Sin equivalente canónico |
| Cualquier otro campo de nivel superior | Sin equivalente canónico |

## Lo que aún no se reenvía

La superficie de compatibilidad solo sirve la ruta de envío. Las API de SendGrid siguientes no tienen ruta de compatibilidad; use la API nativa de ApexMail o el panel.

- Almacenamiento y renderizado de plantillas (`/v3/templates`, `dynamic_template_data` de Handlebars): consulte la sección de plantillas.
- Gestión de supresiones (`/v3/asm/*`, `bypass_list_management`): las supresiones viven en la lista de supresión de ApexMail, gestionada en el panel o mediante la API nativa.
- API de estadísticas, actividad de mensajes y validación de direcciones.
- API de contactos de marketing, listas y campañas de envío único.
- Inbound Parse.
- Modo sandbox por mensaje, interruptores de seguimiento por mensaje y varias personalizaciones.

## DNS: qué cambia y qué se mantiene

Su dominio de envío sigue siendo suyo, y ApexMail firma DKIM con un selector generado por dominio en ese mismo dominio. Añada los cuatro registros de `GET /v1/domains/:id/dns-records` junto a los registros de SendGrid; retire los de SendGrid solo después del corte y de la ventana de retención.

| Registro de SendGrid | Equivalente en ApexMail |
|---|---|
| Par CNAME de DKIM (`s1._domainkey`, `s2._domainkey`) | Registro TXT directo en `<selector>._domainkey.<domain>` con la clave pública DKIM. Un TXT directo, no un CNAME |
| CNAME de marca de enlaces (`url…`) | No se requiere CNAME de marca. ApexMail reescribe los enlaces a sus propias rutas de seguimiento; un dominio de seguimiento personalizado (CNAME en un subdominio de un dominio verificado) está disponible desde Pro |
| CNAME del dominio de rebote | Registro MX en `bounce.<domain>`, prioridad 10, hacia el host de retroalimentación de la región, más un registro TXT en `bounce.<domain>` con el valor SPF del MAIL FROM personalizado |
| Autenticación de dominio | Registro TXT en `_dmarc.<domain>` con su política DMARC |

Lista de comprobación:

1. Añada el dominio de envío en el panel y obtenga sus registros DNS.
2. Publique los cuatro registros de ApexMail; deje los de SendGrid en su sitio.
3. Mantenga el registro SPF del dominio raíz mientras SendGrid envíe. El valor SPF de ApexMail vive en el subdominio `bounce.<domain>` (el MAIL FROM personalizado), así que no necesita entrada en el registro raíz.
4. Ejecute la verificación del dominio y confirme que el selector DKIM resuelve.
5. Mantenga activados los informes DMARC (rua) durante la transición.
6. Tras el corte y la ventana de retención, retire los CNAME de SendGrid y cualquier mecanismo de SendGrid de sus registros.

## Plantillas

Los identificadores de plantilla de SendGrid no son identificadores de plantilla de ApexMail, y `template_id` con `dynamic_template_data` se rechaza por nombre en la ruta de compatibilidad. Dos vías de conversión:

- Renderice el cuerpo en su aplicación y envíelo como `content[]` por la misma ruta de compatibilidad. Sin trabajo de migración de plantillas, y el envío conserva la forma de su solicitud.
- Cree una plantilla con `POST /v1/templates` y envíela con `template_id` más `template_data` en el `POST /v1/messages` nativo. Los marcadores se escriben `{{variable}}`; un marcador sin resolver se renderiza tal cual en lugar de vaciarse, de modo que una variable ausente se ve en la vista previa.

Los ayudantes de Handlebars (condicionales, bucles, `{{#each}}`) no tienen equivalente directo en el motor de marcadores; convierta esas plantillas a HTML renderizado en su aplicación o divídalas en plantillas por caso.

## Webhooks

Apunte su extremo a ApexMail, suscriba los eventos que consume y verifique la firma de ApexMail: `X-ApexMail-Signature: sha256=<hex>` sobre el cuerpo bruto de la solicitud junto con `X-ApexMail-Timestamp`. La entrega es al menos una vez, así que deduplique por el campo `id` del evento.

| Evento de SendGrid | Evento de ApexMail | Notas |
|---|---|---|
| `processed` | `message.accepted` | Aceptado para entrega |
| `delivered` | `message.delivered` | El servidor destinatario aceptó el mensaje |
| `bounce` | `message.bounced` | Rebote duro |
| `deferred` | `message.deferred` | Aplazamiento 4xx; hay un reintento programado |
| `dropped` | `message.suppressed` | Destinatario en la lista de supresión |
| `open` | `message.opened` | |
| `click` | `message.clicked` | |
| `spamreport` | `message.complained` | |
| `unsubscribe`, `group_unsubscribe` | `recipient.unsubscribed` | |
| `group_resubscribe` | Sin evento equivalente | La resubscripción queda anotada en el registro de preferencias, no como evento |

## Plan de corte

El corte es un cambio de URL base por ruta o por entorno, así que la reversión es el mismo cambio a la inversa. No hay carga útil ni plantilla que deshacer.

| Paso | Acción | Criterios de salida | Reversión |
|---|---|---|---|
| 1. Preparar | Cree la cuenta, añada y verifique el dominio de envío, cree una clave API con `messages:send`, suscriba los eventos webhook | La verificación pasa; un mensaje de prueba sale desde un entorno de preproducción | Aún no hay tráfico de producción |
| 2. Validar en paralelo | Envíe las mismas cargas útiles a `https://api.apexmail.ee/v3/mail/send` con la clave de ApexMail; compare respuestas, identificadores y eventos webhook | `202` con `X-Message-Id` en cada prueba; los eventos llegan con firmas válidas | Devuelva la ruta de prueba a SendGrid |
| 3. Desplazar el 10 % | Dirija el 10 % de los envíos de producción por la ruta de compatibilidad; vigile las tasas de rebote y queja frente a los umbrales de la AUP (2 % de rebotes, 0,1 % de quejas) | Las métricas de entrega igualan a SendGrid dentro de la tolerancia acordada durante la ventana de observación | Devuelva la ruta; SendGrid conserva el otro 90 % |
| 4. Desplazar el 50 % | Suba al 50 % cuando la ventana cierre limpia; ambos proveedores envían desde el mismo dominio | Paridad sostenida en la cuota superior | Vuelva al 100 % en SendGrid |
| 5. Cortar al 100 % | Dirija todos los envíos por `POST /v3/mail/send` en ApexMail | Volumen completo en ApexMail con métricas limpias | Vuelva atrás; las claves siguen activas durante la ventana de retención |
| 6. Retirar la ruta antigua | Retire los CNAME de SendGrid y su mecanismo SPF, revoque su clave, elimine la configuración de plantillas restante | Los registros resuelven solo hacia ApexMail | Restaure los registros desde su registro de cambios |

## Siguientes pasos

- Compare ambas plataformas característica por característica en la [comparación ApexMail vs. SendGrid](/es/compare/sendgrid/).
- Lea la [visión general de la API](/docs/api/) y la [especificación OpenAPI](/docs/api/openapi/) para el contrato nativo, incluidos envíos por lotes y plantillas.
- Lea [Webhooks](/docs/webhooks/) para los esquemas de carga útil y la verificación de firmas.
- [Contacte con ventas](/es/contact/sales/) para una evaluación de migración si los elementos rechazados arriba forman parte de su tráfico de producción.
