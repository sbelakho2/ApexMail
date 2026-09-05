+++
title = "Solución de email transaccional"
description = "Email transaccional generado por la aplicación: restablecimientos de contraseña, recibos, notificaciones. API REST y relé SMTP con webhooks firmados y opciones de despliegue orientadas a la UE/EEE."
template = "prose.html"
+++

## Email transaccional

Envíe email generado por su aplicación a través de la API REST o el relé SMTP de ApexMail. Cada mensaje se rastrea desde la aceptación hasta la entrega con un historial de eventos por mensaje.

## Público destinatario

Equipos de ingeniería que construyen aplicaciones con envío de email automatizado: restablecimientos de contraseña, verificación de cuentas, recibos de compra, notificaciones de envío, alertas de seguridad y actualizaciones de estado del sistema.

## Contexto de negocio

El email transaccional es infraestructura de misión crítica. Los restablecimientos de contraseña retrasados bloquean a los usuarios. Los recibos que no llegan generan tickets de soporte. Las notificaciones perdidas dañan la confianza. La capa de email debe ser rápida, observable y fiable sin distraer a ingeniería del trabajo de producto.

## Problema principal

- La entregabilidad varía según el proveedor del destinatario, la reputación del dominio y la calidad de la autenticación.
- Las bibliotecas SMTP incrustadas añaden carga de mantenimiento y ocultan los fallos de entrega.
- Sin eventos de webhooks por mensaje, los equipos no pueden detectar fallos de entrega silenciosos.
- La acumulación en cola durante caídas del proveedor requiere lógica de reintentos y gestión de tiempos de espera.

## Solución de ApexMail

- **API REST** (`POST /v1/messages`) — Payloads JSON con claves de idempotencia. Envíe y olvídese.
- **Relé SMTP** (`smtp.apexmail.ee:587` con STARTTLS) — Sustitución directa para clientes SMTP existentes.
- **Configuración de envío aislada** — Las IP dedicadas, dominios personalizados y listas de supresión pueden delimitarse por tipo de email.
- **Webhooks firmados** — Eventos `delivered`, `bounced`, `complained`, `opened` y `clicked` en tiempo real, cada uno con un ID de evento único y firma HMAC.
- **Idempotencia** — Deduplique envíos con claves suministradas por el cliente. Reenvíe con seguridad tras errores de red.

## Implementación técnica

1. Cree una clave de API en **Panel → Configuración → Claves de API**.
2. Verifique su dominio de envío (SPF, DKIM, return-path personalizado).
3. Configure un dominio de envío dedicado (y, en planes elegibles, una IP dedicada) para su tipo de email.
4. Envíe mediante REST o SMTP.
5. Registre un endpoint de webhook para recibir los eventos de entrega.
6. Supervise las métricas de entrega en el panel o mediante la API de analítica.

## Endpoints de API relevantes

| Endpoint | Descripción |
|---|---|
| `POST /v1/messages` | Enviar un email |
| `GET /v1/messages/:id` | Obtener el estado y los eventos de un email |
| `POST /v1/messages/:id/cancel` | Cancelar un envío programado |
| `POST /v1/messages/batch` | Enviar hasta 100 mensajes en una sola solicitud |

## Eventos de webhooks relevantes

| Evento | Desencadenante |
|---|---|
| `message.sent` | Mensaje aceptado para entrega |
| `message.delivered` | El servidor receptor aceptó el mensaje |
| `message.bounced` | Rebote duro o blando |
| `message.complained` | El destinatario lo reportó como spam |
| `message.opened` | Apertura detectada (píxel de seguimiento) |
| `message.clicked` | Clic en un enlace detectado |

## Plan requerido

| Plan | Volumen mensual | Soporte |
|---|---|---|
| Free | 30.000 emails | Comunidad |
| Starter | 50.000 emails | Soporte por email |
| Pro | 150.000 emails | Soporte por email |
| Growth | 500.000 emails | Soporte por email |
| Scale | 2.000.000 de emails | Soporte prioritario |
| Enterprise | 5.000.000 de emails | Soporte dedicado |

## Consideraciones de seguridad

- Las claves de API tienen alcance por entorno (live/test). Las claves de prueba enrutan a buzones de prueba.
- Los webhooks están firmados con HMAC. Valide las firmas antes de procesar los eventos.
- Se requiere TLS 1.2+ para todas las conexiones de API y SMTP.
- Contenido del mensaje cifrado en reposo. Retención de contenido configurable según el plan.

## Consideraciones de cumplimiento

- Opciones de despliegue orientadas a la UE/EEE; confirme las ubicaciones de datos activas y las salvaguardas de transferencia del despliegue.
- La DPA está disponible en el acuerdo de ApexMail aplicable.
- La disponibilidad HIPAA y los BAA no se ofrecen actualmente.
- El cliente es responsable del consentimiento de los destinatarios y de la gestión de la baja.

## Limitaciones conocidas

- El historial de eventos se conserva 30 días por defecto (7 días en el plan Free); el contenido de los mensajes 7 días por defecto, según el plan hasta 730 días.
- El tamaño de los adjuntos está limitado a 25 MB por mensaje.
- El seguimiento de aperturas y clics requiere cuerpo HTML con píxel de seguimiento o enlaces.

## Siguiente paso recomendado

[Cree una cuenta gratuita](https://app.apexmail.ee/signup) y envíe su primer email mediante la API REST o el relé SMTP.
