+++
title = "Solución de envío de alto volumen"
description = "Millones de emails transaccionales al mes. IP dedicadas gestionadas, calentamiento automatizado, priorización de colas, APIs por lotes y SLA contractuales."
template = "prose.html"
+++

## Envío de alto volumen

Envíe millones de emails transaccionales al mes con rendimiento predecible, reputación de IP dedicada, calentamiento automatizado y garantías de disponibilidad contractuales.

## Público destinatario

Grandes plataformas SaaS que envían más de 1M de emails/mes. Plataformas de comercio electrónico que envían confirmaciones de pedido a gran escala. Redes sociales que envían resúmenes de notificaciones. Plataformas IoT que envían alertas de dispositivos. Cualquier organización en la que el rendimiento del email afecte directamente a la experiencia del cliente y a los ingresos.

## Contexto de negocio

A alto volumen, los pequeños cambios de entregabilidad tienen un gran impacto en los ingresos. Una degradación del 1 % en la entrega con 10M de emails/mes supone 100.000 mensajes perdidos. La contrapresión de colas durante la limitación de los proveedores de destino no debe propagarse a la latencia de la aplicación. Sin automatización, la gestión de la reputación de IP se convierte en una dedicación a tiempo completo.

## Problema principal

- Los pools de IP compartidas acumulan riesgo de reputación de otros remitentes.
- La contrapresión de colas durante la limitación del proveedor afecta a todos los flujos si no se aísla.
- El calentamiento manual de IP es propenso a errores y lento.
- Los límites de velocidad de los planes estándar limitan el rendimiento por debajo de las necesidades del negocio.
- Sin infraestructura dedicada, el tráfico punta compite con el de otros clientes.

## Solución de ApexMail

- **IP dedicadas** — Complemento aprobado en Pro; 1 incluida en Growth, 3 en Scale y 10 en Enterprise. Las opciones de despliegue de ámbito contractual se revisan por separado.
- **Calentamiento automatizado** — Ramp gradual de volumen según calendarios específicos de cada proveedor. Supervisado por señales de reputación. Anulación manual disponible.
- **Priorización de colas** — Configuración de prioridad por flujo. Los flujos transaccionales se procesan antes que los masivos. Objetivos de tiempo hasta bandeja supervisados.
- **API por lotes** (`POST /v1/emails/batch`) — Envíe hasta 1.000 emails por solicitud. Menor sobrecoste por mensaje que las llamadas individuales a la API.
- **Límites de velocidad** — Los límites se aplican por clave de API y plan; consulte la documentación pública actual de la API para conocer los límites públicos.
- **SLA contractual** — Scale y Enterprise incluyen condiciones de SLA a nivel de plan; los despliegues no estándar requieren una revisión contractual separada.

## Implementación técnica

1. Solicite la revisión de elegibilidad de IP dedicada a soporte o ventas.
2. Una vez aprobado, las IP dedicadas se aprovisionan y se asignan a su cuenta.
3. Comienza el calentamiento automatizado. Supervise el progreso en el panel.
4. Asigne IP dedicadas a los flujos transaccionales para aislar la reputación.
5. Configure la prioridad de cola y los límites de concurrencia por flujo.
6. Use la API por lotes para escenarios de envío de alto rendimiento.
7. Supervise la latencia de entrega, la profundidad de cola y las tasas de aceptación por proveedor.

## Endpoints de API relevantes

| Endpoint | Descripción |
|---|---|
| `POST /v1/emails` | Enviar un email individual |
| `POST /v1/emails/batch` | Enviar hasta 1.000 emails en una sola solicitud |
| `GET /v1/dedicated-ips` | Listar IP dedicadas y estado de calentamiento |
| `GET /v1/streams/:id/stats` | Métricas de rendimiento y latencia por flujo |
| `GET /v1/analytics/delivery` | Métricas agregadas de entrega por proveedor |

## Plan requerido

| Plan | Volumen mensual | IP dedicadas | Límite de velocidad | Soporte |
|---|---|---|---|---|
| Growth | 500.000 emails | 1 incluida | Según plan | Soporte por email |
| Scale | 2.000.000 de emails | 3 incluidas | Según plan | Soporte prioritario |
| Enterprise | 5.000.000 de emails | 10 incluidas | Según contrato | Soporte dedicado |

## Consideraciones de seguridad

- La reputación de la IP dedicada se gestiona en exclusiva para su cuenta. Los cambios requieren la aprobación del titular de la cuenta.
- Las solicitudes a la API por lotes son atómicas: todos los mensajes de un lote se completan o fallan juntos (sin finalización parcial).
- La profundidad de cola y la latencia de procesamiento son visibles en tiempo real mediante el panel y la API.
- Cabeceras de límite de velocidad en cada respuesta. Vigile `X-RateLimit-Remaining` para evitar limitaciones.

## Limitaciones conocidas

- La elegibilidad para IP dedicada requiere una revisión del historial de envíos. Las cuentas nuevas comienzan en IP compartidas.
- El calentamiento de IP suele tardar de 2 a 4 semanas según el volumen objetivo y las políticas del proveedor.
- El tamaño máximo de lote es de 1.000 emails por solicitud. Los volúmenes mayores requieren varias llamadas por lotes.
- El rendimiento durante caídas del proveedor depende de la configuración de reintentos de cola y del tiempo de recuperación del proveedor.

## Siguiente paso recomendado

[Contacte con ventas](/es/contact/sales/) para una evaluación de volumen, una evaluación de IP dedicada y precios de inquilino dedicado.
