+++
title = "Guías de migración por proveedor"
sort_by = "title"
template = "section.html"
transparent = true
description = "Guías de migración por proveedor para SendGrid, Mailgun, Postmark y Resend: punto de acceso de compatibilidad, cambio de autenticación, correspondencia de campos, rechazos nombrados, lista de comprobación DNS, nombres de eventos webhook y plan de corte 10/50/100."
+++

Migrar una integración de envío es, en ApexMail, un cambio de URL base. Cada proveedor de abajo tiene su propia superficie de compatibilidad que acepta la forma de solicitud del proveedor y la clave API de ApexMail en el encabezado de credencial del proveedor, y luego ejecuta la ruta de envío canónica: verificación del dominio remitente, filtros de supresión y consentimiento, derechos del plan, registro de idempotencia duradero e inserción en la cola.

Cada guía indica la correspondencia de puntos de acceso, los campos exactos que la superficie rechaza por nombre, lo que no se reenvía, los registros DNS que cambian y que se mantienen, los nombres de eventos webhook que hay que volver a suscribir, y un plan de corte en seis pasos cuya reversión es el mismo cambio de URL base a la inversa.
