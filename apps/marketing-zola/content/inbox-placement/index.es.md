+++
title = "Ubicación en bandeja de entrada, medida"
template = "prose.html"
description = "ApexMail consulta Google Postmaster Tools y Microsoft SNDS cada seis horas, puntúa su reputación de envío y limita automáticamente el tráfico saliente cuando los datos indican que conviene frenar."

[extra]
og_image = "/images/og-image.svg"
+++

## Ubicación en bandeja de entrada, respaldada por los propios proveedores de buzón

La mayoría de los "paneles de entregabilidad" son teatro de listas semilla. ApexMail lee la
señal **real** que Gmail y Outlook publican sobre su dominio — y
actúa en consecuencia.

## Qué medimos

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-10">
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Google Postmaster Tools</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Reputación del dominio: HIGH / MEDIUM / LOW / BAD</li>
      <li>Reputación de IP por IP de envío</li>
      <li>Ratios de aprobación de SPF, DKIM y DMARC</li>
      <li>Ratio de spam reportado por usuarios</li>
      <li>Tasas de TLS entrante y saliente</li>
      <li>Desglose de errores de entrega</li>
    </ul>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Microsoft SNDS</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Resultado del filtro: GREEN / YELLOW / RED</li>
      <li>Tasa de quejas por IP</li>
      <li>Impactos en trampas de spam</li>
      <li>Ratio de aceptación de destinatarios</li>
      <li>Feedback del Junk Mail Reporting Program (JMRP)</li>
    </ul>
  </div>
</div>

## Cómo actuamos en consecuencia

Cada seis horas, el planificador de reputación de ApexMail:

1. **Obtiene** las últimas estadísticas de cada dominio e IP desde los que envía.
2. **Puntúa** en una escala transparente de 0–100 (el algoritmo está en nuestra documentación).
3. **Clasifica** la puntuación en bandas: verde (≥70), ámbar (40–69), rojo (<40).
4. **Limita** automáticamente el tráfico saliente hacia ese proveedor:
   - Verde → 0 % de limitación (velocidad máxima)
   - Ámbar → 50 % de limitación (aplazamiento probabilístico)
   - Rojo → 90 % de limitación (casi parada, alerta enviada)
5. **Alerta** a las personas adecuadas — webhook, email o Slack — cuando una banda cae.

Cuando su reputación se recupera, la limitación se libera sin intervención humana.

## Por qué importa esto para su MRR de 100.000 $

Un solo lote defectuoso puede meter un dominio de envío en la lista BAD de Gmail
durante más de 30 días. La mayoría de los ESP le dan la mala noticia en su
siguiente revisión trimestral de negocio. ApexMail limita el radio de impacto
**en el mismo turno** — sus tenants de alto volumen siguen entregando por
carriles limpios mientras el dominio afectado se enfría.

## Anulaciones de limitación por proveedor

Los operadores pueden fijar una limitación (p. ej., el 100 % durante dos horas
en un incidente conocido) sin cambios de código. Cada decisión queda registrada
con puntuación, banda y fuente para auditoría y transparencia ante el cliente.

## Obtenga una instantánea de reputación

Podemos auditar su dominio existente en menos de una hora — usando los mismos
flujos de datos de Google y Microsoft que usamos en producción.
[Reserve una revisión de entregabilidad](/es/contact/).
