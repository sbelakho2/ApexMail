+++
title = "Acuerdo de Nivel de Servicio (SLA)"
description = "SLA de ApexMail — compromisos contractuales de disponibilidad para clientes de los planes Business y Enterprise."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 1. Ámbito

Este Acuerdo de Nivel de Servicio («SLA») se aplica a los clientes de los planes Business y Enterprise y define nuestros compromisos de disponibilidad y rendimiento.

## 2. Compromiso de disponibilidad

| Métrica | Objetivo |
|---|---|
| Disponibilidad de la API | 99,9 % mensual |
| Disponibilidad del relay SMTP | 99,9 % mensual |
| Disponibilidad del panel | 99,9 % mensual |

## 3. Objetivos de rendimiento

| Métrica | Objetivo |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| Aceptación de correo hasta primer intento de entrega | ≤30 segundos |
| Entrega de webhook (P95) | ≤5 segundos |

### Definiciones de métricas

**Production API P95 (Gateway):** Medido en la capa de gateway API para todas las solicitudes de producción `POST /v1/messages`. Marca de tiempo de inicio: entrada de solicitud en el gateway. Marca de tiempo de fin: salida de respuesta del gateway. Percentil: P95. Solicitudes cualificadas: respuestas HTTP 200-299 del endpoint de mensajes, excluyendo tráfico de clave API sandbox/test. Exclusiones: sondas de health-check, OPTIONS preflight, claves API sandbox. Periodo de muestra: ventana móvil de 30 días, cubos de agregación de 1 minuto.

## 4. Medición

La disponibilidad se mide mediante nuestro sistema de monitoreo externo (Blackbox exporter + Prometheus) desde múltiples ubicaciones geográficas. Las ventanas de mantenimiento programadas (anunciadas con 48 horas de antelación) se excluyen.

## 5. Créditos de servicio

Los planes elegibles tienen un compromiso de disponibilidad mensual del 99,9 %. Cuando la disponibilidad mensual medida cae por debajo de ese umbral, se aplica un crédito de servicio según la matriz específica del plan que aparece a continuación — el porcentaje de crédito corresponde al cargo recurrente mensual del inquilino por el mes afectado.

| Disponibilidad mensual medida | Business | Enterprise Cloud / contractual |
|---|---:|---:|
| ≥ 99,9 % | 0 % (compromiso cumplido) | 0 % (compromiso cumplido) |
| 99,0 % – 99,899 % | 10 % | 10 % |
| 95,0 % – 98,999 % | 20 % | 25 % |
| < 95,0 % | 30 % | 25 % |

**Notas del plan:**

- **Business** — porcentajes graduados como se indica; sin tope fijo por debajo de los tramos.
- **Enterprise Cloud y despliegues contractuales** — porcentajes como se indica, con un tope del 25 % (o la figura contractual cuando un formulario de pedido la especifica).

Los créditos se calculan a partir de la disponibilidad mensual medida por debajo del compromiso y se limitan según el plan del cliente.

## 6. Exclusiones

Los créditos no se aplican a: fuerza mayor, problemas causados por el cliente, mantenimiento programado ni funciones beta.

## 7. Solicitud de créditos

Envíe las solicitudes de crédito a support@apexmail.ee dentro de los 30 días siguientes al incidente. Los créditos se aplican al siguiente ciclo de facturación.
