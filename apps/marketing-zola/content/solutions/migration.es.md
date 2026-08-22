+++
title = "Solución de migración"
description = "Migre desde SendGrid, Postmark, Mailgun, SES o Resend a ApexMail. Calentamiento de IP, transición de dominios, migración de plantillas y validación con envío en paralelo."
template = "prose.html"
+++

## Migración

Traslade su infraestructura de email transaccional a ApexMail sin interrupciones. Esta solución cubre la transición de dominios, el calentamiento de IP, la migración de plantillas, la compatibilidad de webhooks y la validación con envío en paralelo.

## Público destinatario

Equipos de ingeniería que migran desde SendGrid, Postmark, Mailgun, Amazon SES o Resend. Equipos de operaciones que gestionan el corte. Equipos de cumplimiento que verifican los requisitos de residencia de datos.

## Contexto de negocio

La migración de proveedor de email es una operación de alto riesgo. Una caída de la entrega durante el corte supone ingresos perdidos. El calentamiento de IP sin automatización expone a la inclusión en listas negras. La reputación del dominio debe conservarse entre proveedores. Sin un plan de migración estructurado, los equipos se exponen a una degradación prolongada de la entrega.

## Problema principal

- La reputación de IP es específica de cada proveedor y no puede transferirse.
- Los registros de autenticación del dominio (SPF, DKIM, DMARC) requieren cambios de DNS coordinados.
- La sintaxis de plantillas difiere entre proveedores.
- Los payloads de webhooks y los tipos de eventos no están estandarizados.
- El envío en paralelo durante la validación requiere enrutado a dos proveedores.

## Solución de ApexMail

- **Calentamiento de IP gestionado** — Calendario automatizado de calentamiento para IP dedicadas, con limitación y supervisión de reputación.
- **Guía de transición de dominios** — Configuración de DNS paso a paso para SPF, DKIM, DMARC y return-path personalizado.
- **Importación de plantillas** — Mapeo de sus plantillas existentes al formato de ApexMail conservando variables y estructura.
- **Compatibilidad de webhooks** — Tipos de eventos estandarizados con documentación de mapeo de payloads.
- **Validación con envío en paralelo** — Enrute un porcentaje configurable del tráfico a través de ApexMail mientras mantiene su proveedor actual.

## Implementación técnica

1. Cree una cuenta de ApexMail y verifique su dominio de envío.
2. Copie el registro o registros DKIM específicos del dominio generados en la configuración de Dominios junto a los selectores de su proveedor actual.
3. Añada el mecanismo SPF generado por ApexMail al registro SPF existente; no elimine el proveedor anterior hasta validar la transición.
4. Fije la política DMARC en `p=none` durante la transición para recopilar informes sin aplicar la política.
5. Importe las plantillas mediante la API de plantillas.
6. Configure los endpoints de webhooks para la entrega de eventos.
7. Comience el envío en paralelo con un 10 % del volumen, incrementándolo gradualmente mientras supervisa las métricas de entrega.
8. Tras el periodo de validación, enrute el 100 % a través de ApexMail y elimine la configuración del proveedor heredado.

## Endpoints de API relevantes

| Endpoint | Descripción |
|---|---|
| `POST /v1/emails` | Enviar un email |
| `POST /v1/emails/batch` | Envío por lotes de hasta 1.000 emails |
| `POST /v1/templates` | Crear una plantilla |
| `GET /v1/templates` | Listar plantillas |
| `PUT /v1/templates/:id` | Actualizar una plantilla |

## Eventos de webhooks relevantes

| Evento | Desencadenante |
|---|---|
| `email.delivered` | El servidor receptor aceptó el mensaje |
| `email.bounced` | Rebote duro o blando |
| `email.delayed` | Mensaje aplazado por el servidor receptor |

## Plan requerido

| Plan | IP dedicada | Soporte |
|---|---|---|
| Growth | 1 IP dedicada incluida | Soporte por email |
| Scale | 3 IP dedicadas incluidas | Soporte prioritario |
| Enterprise | 10 IP dedicadas incluidas | Soporte dedicado |

## Consideraciones de seguridad

- Los cambios de DNS deben implementarse durante una ventana de mantenimiento.
- Supervise los informes agregados de DMARC (RUA) durante todo el periodo de transición.
- Mantenga activas las claves de API de ambos proveedores hasta completar la validación.

## Consideraciones de cumplimiento

- Confirme los requisitos de ubicación de datos y de DPA durante la revisión de la cuenta o Enterprise; un corte técnico no crea por sí solo un compromiso de residencia o cumplimiento.
- El cliente conserva la responsabilidad de la continuidad del consentimiento de los destinatarios durante la migración.

## Limitaciones conocidas

- El envío en paralelo puede generar eventos de entrega duplicados durante la ventana de validación.
- El calentamiento de IP requiere de 2 a 4 semanas para las IP dedicadas.
- La migración de plantillas requiere revisión manual para la lógica condicional compleja.

## Siguiente paso recomendado

[Contacte con ventas](/es/contact/sales/) para una evaluación de migración y la revisión de elegibilidad de IP dedicada.
