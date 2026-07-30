+++
title = "Política de uso aceptable"
description = "Política de uso aceptable de ApexMail — normas que rigen el uso del servicio de correo electrónico, organizadas por categoría de mensaje."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

Esta Política de uso aceptable («PUA») define los usos prohibidos y aceptables de la infraestructura de correo electrónico de ApexMail. Su violación puede dar lugar a la suspensión o rescisión. Esta PUA distingue entre correos electrónicos de marketing y promocionales y correos electrónicos transaccionales y de servicio — cada categoría conlleva obligaciones diferentes de consentimiento, cancelación de suscripción y envío, como se describe a continuación.

## Correo electrónico de marketing y promocional

El correo electrónico de marketing y promocional incluye boletines, anuncios de productos, ofertas, invitaciones a eventos y cualquier mensaje cuyo propósito principal sea la promoción comercial o la participación del cliente más allá del cumplimiento directo de un servicio.

**Requisitos para todo correo electrónico de marketing y promocional:**

- **Consentimiento de suscripción voluntaria.** Los remitentes deben obtener y conservar la prueba del consentimiento de suscripción voluntaria antes del envío. Cuando la jurisdicción del destinatario o las obligaciones regulatorias del remitente exijan el consentimiento expreso (p. ej., RGPD Artículo 7 para marketing directo a personas en el EEE, CAN-SPAM en Estados Unidos), el remitente debe obtener dicho consentimiento.
- **Base jurídica.** Los remitentes deben identificar, documentar y mantener la base jurídica para el tratamiento de los datos de los destinatarios según todas las leyes aplicables (p. ej., consentimiento según el RGPD Artículo 6(1)(a), interés legítimo cuando sea jurídicamente válido). El remitente asume la responsabilidad exclusiva de garantizar que exista una base jurídica válida para cada comunicación de marketing antes del envío.
- **Identificación del remitente.** Cada mensaje debe identificar claramente a la organización remitente y proporcionar encabezados `From`, `Reply-To` y dirección postal física precisos.
- **Mecanismo de cancelación de suscripción funcional.** Cada mensaje debe incluir un mecanismo de cancelación de suscripción en un solo clic que procese las solicitudes de eliminación de manera rápida y permanente. Los enlaces de cancelación deben permanecer funcionales durante al menos 30 días después del envío.
- **Prohibición de listas compradas, extraídas o recolectadas.** No se permiten listas adquiridas mediante compra, alquiler, extracción o recolección. Todas las direcciones de destinatarios deben ser recopiladas directamente por el remitente mediante un proceso de suscripción voluntaria.
- **Monitoreo de quejas.** Los remitentes deben monitorear las quejas de abuso y mantener la tasa de quejas por debajo del 0,1 % (calculada como quejas ÷ mensajes entregados por dominio de envío por día).
- **Cumplimiento de la lista de supresión.** Los remitentes deben suprimir a los destinatarios que se hayan dado de baja o presentado quejas. ApexMail mantiene una lista de supresión a nivel de plataforma; los clientes no deben volver a agregar direcciones suprimidas.

## Correo electrónico transaccional y de servicio

El correo electrónico transaccional y de servicio incluye mensajes necesarios para proporcionar un servicio que el destinatario ha solicitado o que el remitente está legalmente obligado a enviar. Estos mensajes no son principalmente promocionales.

**Ejemplos de correo electrónico transaccional y de servicio:**

- Restablecimientos de contraseña y enlaces de recuperación de cuenta
- Códigos de autenticación (contraseñas de un solo uso, tokens de dos factores)
- Alertas de seguridad (inicio de sesión no reconocido, cambio de dispositivo, aviso de suspensión de cuenta)
- Recibos de compra y confirmaciones de pedido
- Facturas, recibos de pago y avisos de facturación
- Notificaciones de estado de cuenta (vencimiento de prueba, cambio de plan, finalización de exportación de datos)
- Confirmaciones de servicio (verificación de dominio, validación de endpoint de webhook)
- Mensajes legalmente requeridos (actualizaciones de políticas de privacidad cuando la notificación es obligatoria, notificaciones de violación de datos)

**Requisitos para correo electrónico transaccional y de servicio:**

- **Debe ser necesario para el servicio.** El mensaje debe estar directamente relacionado con la cuenta, transacción u obligación legal del destinatario. El contenido promocional o de marketing no debe disfrazarse como mensaje transaccional.
- **No debe contener marketing encubierto.** Si un mensaje transaccional también contiene contenido promocional (por ejemplo, un restablecimiento de contraseña que también anuncia un nuevo producto), todo el mensaje se trata como marketing y debe cumplir con la sección «Correo electrónico de marketing y promocional».
- **Identidad precisa del remitente.** La identidad del remitente debe estar claramente indicada con información correcta de dominio y encabezado.
- **Responsabilidad del cliente en la clasificación.** El cliente es responsable de clasificar correctamente sus mensajes (transaccional vs. marketing) y de identificar la base legal adecuada. ApexMail proporciona etiquetas de categoría de mensaje en la API; el uso de una etiqueta transaccional para contenido de marketing viola esta PUA.
- **Retención adecuada.** Los remitentes deben conservar los datos de los mensajes transaccionales solo durante el tiempo necesario para cumplir con la finalidad del servicio o con las obligaciones legales aplicables. Los datos transaccionales rutinarios (p. ej., confirmaciones de entrega, registros de autenticación) no deben conservarse más allá de lo requerido para la integridad operativa y el cumplimiento legal.
- **Tratamiento jurídico según la finalidad del mensaje.** Cada categoría de mensaje transaccional se trata según su finalidad jurídica específica. Los códigos de autenticación son medidas de seguridad según el RGPD Artículo 32. Las facturas son registros financieros sujetos a requisitos de conservación. Las confirmaciones de servicio son comunicaciones de ejecución contractual. El remitente debe aplicar el marco jurídico correcto para cada categoría de mensaje. El uso de una categoría de mensaje inapropiada para eludir requisitos legales (p. ej., etiquetar contenido de marketing como transaccional) constituye una violación de esta PUA.

## Contenido prohibido (todas las categorías)

No puede usar ApexMail para enviar:

- **Spam:** Correo masivo no solicitado sin el consentimiento de suscripción voluntaria requerido descrito en la sección «Correo electrónico de marketing y promocional».
- **Phishing:** Correos electrónicos diseñados para obtener fraudulentamente información personal o financiera.
- **Malware:** Correos electrónicos que contengan virus, troyanos, ransomware o archivos adjuntos o enlaces maliciosos.
- **Contenido ilegal:** Contenido que viole las leyes aplicables en Estonia, la UE o la jurisdicción del destinatario.
- **Acoso:** Contenido amenazante, abusivo, difamatorio o discriminatorio.

## Requisitos generales de envío

Estos requisitos se aplican a todas las categorías de mensajes:

- La identidad del remitente debe estar claramente indicada (sin suplantación de dominio o encabezado).
- Las tasas de rebote deben permanecer por debajo del 2 % por dominio de envío por día.
- Las quejas deben permanecer por debajo del 0,1 % por dominio de envío por día.
- Los dominios de envío deben estar verificados con registros SPF, DKIM y DMARC válidos.

## Protección de la infraestructura

- No intente eludir los límites de velocidad, cuotas o topes de volumen de envío.
- No use el servicio para ataques DDoS, abuso de red o escaneo de puertos.
- No comparta claves API ni credenciales. Cada usuario debe tener su propia clave API con ámbito.
- No intente acceder o interferir con los datos, cuentas o configuraciones de envío de otros clientes.

## Aplicación

Monitoreamos los patrones de envío y:

1. Advertiremos por primeras violaciones menores (por ejemplo, tasa de rebote elevada).
2. Limitaremos el envío por problemas repetidos o violaciones sostenidas de la política.
3. Suspenderemos el envío (con aviso cuando sea posible) por violaciones graves, incluidas quejas de spam, phishing o intentos de elusión.
4. Rescindiremos cuentas por violaciones graves, repetidas o penales.

## Denuncia

Denuncie abusos o violaciones de la PUA a: **abuse@apexmail.ee**

Todas las denuncias se revisan en un plazo de 1 día hábil. Los denunciantes reciben un acuse de recibo y, cuando corresponda, un resumen de las medidas adoptadas.
