+++
title = "ApexMail vs Mailgun | Comparación de capacidades"
description = "Comparación objetiva de capacidades de email transaccional: ApexMail vs Mailgun. Alojamiento en la UE, API, entregabilidad, cumplimiento y modelos de despliegue."
template = "compare.html"

[extra]
noindex = true
competitor = "Mailgun"
competitor_slug = "mailgun"
competitor_name = "Mailgun"
competitor_description = "Mailgun de Sinch es una plataforma de entrega de email con APIs para enviar, recibir y rastrear emails."
last_verified = "2026-07-29"
methodology = "Documentación pública de Mailgun en mailgun.com/docs revisada en la fecha de verificación. Precios comparados en el plan Foundation 100K. Facturación mensual. Las funciones, los límites y los precios pueden cambiar."
volume_assumption = "100.000 emails/mes"
billing_period = "monthly"
currency_note = "Los precios se muestran en EUR. Cuando un proveedor solo publica precios en USD, la cifra en EUR se convierte a 1 USD = €0.92 (tipo de referencia, 2026-08-19) y se muestra entre paréntesis el precio en USD publicado por el proveedor. Impuestos no incluidos."
# Feature comparison counts — update when capabilities change
verdict_title = "En qué se diferencia ApexMail de Mailgun"
verdict_points = ["Configuración de despliegue orientada a la UE/EEE", "Catálogo público actual (Mailgun publica en USD; EUR mostrado al tipo de referencia)", "Controles de acceso en Business y Enterprise", "Registros de auditoría en Growth y superiores", "Revisión de arquitectura y contractual para despliegues no estándar"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-mgN"> citations. Winner is one
# of: apexmail | competitor | tie | none.
comparison_sections = [
  { title = "PROCESAMIENTO DE DATOS EN EL EEE", rows = [
    { feature = "Región principal de alojamiento", apex = 'Configuración orientada a la UE/EEE por defecto; confirmar el despliegue activo', comp = 'EE. UU. (región UE disponible en Foundation 50K+ y planes superiores)<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "Procesamiento de datos en el EEE por defecto", apex = 'Configuración orientada a la UE/EEE por defecto; las ubicaciones activas dependen del acuerdo', comp = 'No — en EE. UU. por defecto; región UE configurada por dominio de envío<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "Disponibilidad de la DPA", apex = 'Disponible en el acuerdo de ApexMail aplicable', comp = 'Disponible — la DPA de Sinch cubre los servicios de Mailgun<sup><a href="#src-mg2">2</a></sup>', winner = "none" }
  ]},
  { title = "CAPACIDADES DE ENVÍO", rows = [
    { feature = "API REST", apex = 'Sí — <code>POST /v1/messages</code>', comp = 'Sí — <code>POST /v3/{domain}/messages</code><sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Relé SMTP", apex = 'Sí — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Sí — smtp.mailgun.org:587 (STARTTLS)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Envío por lotes", apex = 'Disponible cuando esté habilitado para el plan contratado', comp = 'Sí — envío por lotes mediante <code>recipient-variables</code> con hasta 1.000 destinatarios<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Claves de idempotencia", apex = 'Sí (todos los planes) — cabecera <code>Idempotency-Key</code>', comp = 'No admitido — las aplicaciones deben implementar su propia lógica de deduplicación<sup><a href="#src-mg3">3</a></sup>', winner = "apexmail" },
    { feature = "Envío programado", apex = 'Disponible cuando esté habilitado para el plan contratado', comp = 'Sí — parámetro <code>o:deliverytime</code> (formato RFC 2822, hasta 3 días)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Email entrante", apex = 'Planes Business y Enterprise', comp = 'Sí — rutas entrantes con acciones de reenvío, almacenamiento y webhooks<sup><a href="#src-mg4">4</a></sup>', winner = "none" }
  ]},
  { title = "MODELOS DE DESPLIEGUE", rows = [
    { feature = "Nube compartida", apex = 'Sí (todos los planes) — multi-tenant, alojado en la UE', comp = 'Sí (todos los planes)<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "IP dedicada", apex = 'Complemento aprobado en Pro; 1 incluida en Growth, 3 en Scale', comp = 'Disponible como complemento en el plan Foundation y superiores<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Inquilino dedicado", apex = 'Sujeto a revisión de arquitectura y contractual', comp = 'Consulte la documentación del proveedor<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "BYOC / despliegue privado", apex = 'Sujeto a revisión de arquitectura y contractual', comp = 'Consulte la documentación del proveedor<sup><a href="#src-mg5">5</a></sup>', winner = "none" }
  ]},
  { title = "CONTROLES ENTERPRISE", rows = [
    { feature = "SAML SSO", apex = 'Planes Business y Enterprise', comp = 'Foundation 100K y planes superiores<sup><a href="#src-mg6">6</a></sup>', winner = "none" },
    { feature = "SCIM", apex = 'Plan Enterprise', comp = 'No documentado en la fecha de verificación — aprovisionamiento de usuarios mediante la API de Mailgun<sup><a href="#src-mg6">6</a></sup>', winner = "apexmail" },
    { feature = "Registros de auditoría", apex = 'Plan Growth y superiores — actividad de la cuenta, uso de claves de API y cambios de configuración; con búsqueda y exportación', comp = 'Registros de eventos accesibles mediante la Events API; la retención varía según el plan; sin pista de auditoría consolidada a nivel de cuenta<sup><a href="#src-mg7">7</a></sup>', winner = "apexmail" }
  ]},
  { title = "PRECIOS A 100K/MES (verificado 2026-07-29)", rows = [
    { feature = "Plan comparado", apex = 'Pro: €65/mes (150.000 emails incluidos)', comp = 'Scale: €82.80 (US$90)/mes (100.000 emails incluidos)<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Condiciones de uso", apex = 'Consulte el catálogo público actual y el proceso de contratación para las condiciones de uso aplicables', comp = 'desde €1.20 (US$1.30)/1.000 en el exceso de Foundation; tarifas escalonadas en Scale<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Nivel gratuito", apex = '30.000 emails/mes', comp = '100 emails/día (prueba Flex — sin tarjeta de crédito)<sup><a href="#src-mg8">8</a></sup>', winner = "apexmail" }
  ]},
  { title = "ÁREAS DONDE MAILGUN ES MÁS FUERTE", rows = [
    { feature = "Validación de email", apex = 'API Email Grader (DNS/SPF/DKIM/DMARC/contenido/reputación)', comp = 'API de validación de email dedicada con validación en tiempo real y masiva<sup><a href="#src-mg9">9</a></sup>', winner = "competitor" },
    { feature = "Procesamiento de email entrante", apex = 'Email entrante en los planes Business y Enterprise', comp = 'Enrutado entrante con acciones de reenvío, webhook HTTP y almacenamiento; incluido en todos los planes<sup><a href="#src-mg4">4</a></sup>', winner = "competitor" },
    { feature = "Sandbox de pruebas de email", apex = 'Entorno sandbox con dominios sandbox y límites de velocidad', comp = 'Dominio sandbox para pruebas en todos los planes con credenciales de prueba independientes<sup><a href="#src-mg3">3</a></sup>', winner = "none" }
  ]}
]

# Sources block (rendered by macros::sources_block via partials/compare/table.html).
# Each entry: { ref = anchor suffix (e.g. "mg1"), n = display number, label, url }.
sources = [
  { ref = "mg1", n = 1, label = "Precios de Mailgun (región UE según plan)", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg2", n = 2, label = "Acuerdo de procesamiento de datos de Mailgun", url = "https://www.mailgun.com/legal/dpa/" },
  { ref = "mg3", n = 3, label = "Referencia de la API de envío de Mailgun", url = "https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages" },
  { ref = "mg4", n = 4, label = "Documentación de email entrante de Mailgun", url = "https://documentation.mailgun.com/en/latest/user_manual.html#receiving-forwarding-and-storing-messages" },
  { ref = "mg5", n = 5, label = "Página de productos de Mailgun", url = "https://www.mailgun.com/products/" },
  { ref = "mg6", n = 6, label = "Precios de Mailgun (SSO según plan)", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg7", n = 7, label = "Referencia de la Events API de Mailgun", url = "https://documentation.mailgun.com/docs/mailgun/user-manual/events" },
  { ref = "mg8", n = 8, label = "Página de precios de Mailgun", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg9", n = 9, label = "Validación de email de Mailgun", url = "https://www.mailgun.com/email-validation/" }
]
sources_disclaimer = "Última verificación: 2026-08-19. Supuesto de volumen: 100.000 emails/mes, facturación mensual. Los precios se muestran en EUR. Cuando un proveedor solo publica precios en USD, la cifra en EUR se convierte a 1 USD = €0.92 (tipo de referencia, 2026-08-19) y se muestra entre paréntesis el precio en USD publicado por el proveedor. Impuestos no incluidos. Revisado por: ingeniería de marketing de ApexMail."
+++

<!-- Comparison rows and sources block are rendered from the
     [extra].comparison_sections and [extra].sources arrays by
     partials/compare/table.html. This body is intentionally empty. -->
