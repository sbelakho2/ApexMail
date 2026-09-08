+++
title = "Acuerdo de Nivel de Servicio (SLA)"
description = "SLA de ApexMail — compromis contractuales de disponibilidad para clientes de los planes Business y Enterprise."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 3. Objetivos de rendimiento

| Métrica | Objetivo |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| Aceptación de correo hasta primer intento de entrega | ≤30 segundos |
| Entrega de webhook (P95) | ≤5 segundos |

### Definiciones de métricas

**Production API P95 (Gateway):** Medido en la capa de gateway API para todas las solicitudes de producción `POST /v1/messages`. Marca de tiempo de inicio: entrada de solicitud en el gateway. Marca de tiempo de fin: salida de respuesta del gateway. Percentil: P95. Solicitudes cualificadas: respuestas HTTP 200-299 del endpoint de mensajes, excluyendo tráfico de clave API sandbox/test. Exclusiones: sondas de health-check, OPTIONS preflight, claves API sandbox. Periodo de muestra: ventana móvil de 30 días, cubos de agregación de 1 minuto.
