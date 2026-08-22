+++
title = "Metodología de comparación"
description = "Cómo elabora y mantiene ApexMail sus comparativas de mercado: estándares de evidencia, política de fuentes, frecuencia de actualización y proceso de corrección."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Finalidad

ApexMail publica comparativas objetivas y basadas en evidencias para ayudar a desarrolladores y equipos de contratación a evaluar proveedores de email transaccional. Cada afirmación de cada comparativa es rastreable hasta una fuente pública.

## Estándares de divulgación

Cada página de comparación revela:

| Campo | Descripción |
|-------|-------------|
| **Fecha de verificación** | Cuándo se comprobó por última vez la comparación con las fuentes publicadas |
| **Plan del competidor comparado** | Nombre exacto del plan y nivel referenciados |
| **Plan de ApexMail comparado** | Plan exacto de ApexMail utilizado para el mapeo función por función |
| **Supuesto de volumen mensual** | El volumen de email con el que se calculan los precios |
| **Periodo de facturación** | Facturación mensual o anual utilizada para la comparación de precios |
| **Moneda** | Todos los precios se muestran en EUR. Los precios de ApexMail se publican en EUR; cuando un competidor solo publica precios en USD, la cifra en EUR se convierte al tipo de referencia documentado (1 USD = €0.92, 2026-08-19) y se muestra entre paréntesis el precio en USD publicado por el proveedor |
| **Tratamiento fiscal** | Todos los precios excluyen el IVA salvo indicación en contrario |
| **Definiciones de funciones** | Cómo se define cada función comparada |
| **Política de fuentes** | Solo documentación oficial pública y páginas de precios |
| **Frecuencia de actualización** | Revisión dirigida cada 90 días; afirmaciones críticas revisadas mensualmente |
| **Proceso de corrección** | Correcciones aceptadas en security@apexmail.ee; verificadas en un plazo de 5 días laborables |

## Campos de evidencia por fila de comparación

Cada fila de una tabla comparativa está respaldada por:

| Campo de evidencia | Obligatorio |
|----------------|----------|
| Nombre de la función | Sí |
| Implementación de ApexMail | Sí |
| Implementación del competidor | Sí |
| Plan o nivel exacto | Sí |
| URL de la fuente oficial | Sí |
| Fecha de la fuente | Sí |
| Fecha de verificación | Sí |
| Revisor | Sí |
| Matiz (si existe) | Obligatorio si la afirmación está matizada |
| Captura o evidencia archivada | Conservada internamente |

## Reglas de comparación de precios

- Las comparaciones de precios utilizan **volúmenes mensuales equivalentes** en ambos lados.
- La facturación anual solo se compara cuando el catálogo público actual de cada proveedor la admite expresamente; no se aplica ningún descuento supuesto.
- Cuando los precios del competidor varían por tramo de volumen, se selecciona el tramo más cercano al supuesto de volumen indicado.
- Las monedas se muestran en su denominación original. Cuando el contexto de conversión resulta útil, se indica el tipo de referencia del BCE en la fecha de verificación.

## Reglas de comparación de funciones

- Las funciones se comparan según su **disponibilidad documentada públicamente** en el nivel de plan indicado.
- "Disponible en planes superiores" solo se indica cuando la función no está disponible en el plan comparado.
- "Disponible como complemento" incluye el precio del complemento cuando está publicado.
- Las funciones listadas como "planificadas" o "próximamente" se excluyen salvo que el proveedor publique una fecha firme de lanzamiento.
- Las funciones de ApexMail listadas como "disponibles" deben estar generalmente disponibles en producción en el momento de la verificación.

## Política de evaluación subjetiva

- Las etiquetas subjetivas ("mejor", "superior", "básico", "limitado") se sustituyen por **afirmaciones medibles**.
- Cuando una evaluación cualitativa es inevitable, se etiqueta explícitamente como **valoración editorial de ApexMail** con los criterios indicados.
- Las ventajas de los competidores se reconocen explícitamente y sin matizaciones.

## Proceso de corrección y disputas

- Los proveedores o lectores pueden enviar correcciones a security@apexmail.ee.
- Las correcciones se verifican contra fuentes oficiales en un plazo de 5 días laborables.
- Las correcciones verificadas se publican con su fecha de corrección.
- Una sección de fe de erratas que recoge la corrección aparece al final de la página afectada.

## Cadencia de revisión

| Tipo de comprobación | Frecuencia |
|------------|-----------|
| Exactitud de precios (todos los competidores) | Cada 90 días |
| Afirmaciones de funciones (filas críticas) | Cada 30 días |
| Afirmaciones de funciones (todas las filas) | Cada 90 días |
| Validez de las URL de las fuentes | Cada 90 días |
| Reverificación completa | Cada 180 días o ante un lanzamiento importante del proveedor |

## Limitaciones

- Las comparativas reflejan la información disponible públicamente en la fecha de verificación. Los proveedores pueden cambiar precios y funciones sin previo aviso.
- Los precios Enterprise (presupuestos personalizados, descuentos por volumen) no se comparan salvo que estén publicados.
- Las comparativas no constituyen asesoramiento legal, recomendaciones de compra ni ofertas contractuales.
- Los benchmarks de rendimiento (latencia, throughput) no se comparan salvo que ApexMail los haya medido de forma independiente en condiciones de prueba divulgadas.
