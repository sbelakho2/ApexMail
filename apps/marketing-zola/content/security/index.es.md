+++
title = "Resumen de seguridad"
description = "Controles de seguridad de ApexMail: cifrado, autenticación, defensa de red, respuesta a incidentes, gestión de vulnerabilidades y evidencia de cumplimiento."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Cifrado

### Datos en tránsito

- TLS 1.2+ requerido para todas las conexiones API y SMTP.
- TLS 1.3 preferido cuando sea compatible con el MTA receptor.
- Red privada y no pública para la comunicación entre servicios (redes de despliegue aisladas; sin tráfico servicio-a-servicio por internet público).

[roadmap] La publicación de política MTA-STS (`mode: enforce`) y la validación DANE (registros TLSA) de los servidores MX destinatarios son capacidades planificadas; no se aplican hoy en las rutas de correo de la nube gestionada.

### Datos en reposo

- Cifrado AES-256-GCM para contenido de mensajes y archivos adjuntos.
- Argon2id para hash de contraseñas (resistente a memoria, resistente a ataques GPU/ASIC).
- Volúmenes de base de datos cifrados (LUKS/dm-crypt).
- Copias de seguridad cifradas con gestión de claves separada.
- Los requisitos de claves de cifrado gestionadas por el cliente solo pueden evaluarse en una implementación con contrato independiente; no son un derecho de plan público.

## Autenticación y control de acceso

- Claves API con ámbito por entorno (live/test) con permisos configurables.
- Firmas HMAC de webhooks (SHA-256) para integridad de carga útil de eventos.
- SAML SSO en los planes Business y Enterprise; los compromisos de aprovisionamiento se confirman en el contrato aplicable.
- Control de acceso basado en roles (RBAC) con roles personalizados en plan Enterprise.
- Autenticación multifactor (TOTP) para acceso al panel.
- Gestión de sesiones con tiempo de espera configurable y vinculación IP.

## Seguridad de aplicaciones

### Inspección de solicitudes (firewall de aplicaciones web)

[roadmap] Un firewall de inspección de solicitudes (WAF) basado en reglas SQLi/XSS/traversal/inyección-de-comandos/SSRF evalúa hoy método, ruta, cadena de consulta y encabezados de las solicitudes públicas de la API en modo monitor: los veredictos se registran, no se bloquean. Habilitar el bloqueo por defecto y extender la inspección a los cuerpos de solicitud está en la hoja de ruta; la postura por defecto de la nube gestionada no incluye bloqueo WAF. La detección/prevención de intrusiones (IDS/IPS) existe como biblioteca que no inspecciona tráfico real y tampoco es un control activo.

- Validación y saneamiento de entrada en todos los endpoints de la API (a nivel de handler).
- Limitación de velocidad por endpoint y clave API.

### Protección DDoS y contra abusos

Defensas de capa de aplicación integradas en la ruta pública de solicitudes de la API:

1. Limitación de velocidad basada en coste con presupuestos por tenant.
2. Umbrales adaptativos por IP (detección estadística de anomalías z-score sobre patrones de solicitud).
3. Huella digital de solicitudes (fingerprints JA4/TLS y HTTP/2) para decisiones de reputación.
4. Middleware de load-shedding previa al trabajo de autenticación y limitación de velocidad.

### Autenticación API

- Todos los endpoints de la API requieren el encabezado `X-API-Key` con clave API con ámbito.
- Firmas de webhooks verificadas mediante HMAC-SHA256.
- OAuth 2.0 para integraciones de terceros (inicio de sesión con Google, GitHub).
- Autenticación basada en sesiones con cookies seguras HTTP-only para acceso al panel.

## Verificación de integridad del sistema

La integridad del sistema se verifica mediante controles automatizados y recurrentes en toda la pila de implementación y tiempo de ejecución:

| Control | Qué se verifica | Frecuencia | Evidencia |
|---|---|---|---|
| **Artefactos de implementación firmados** | Todos los binarios de aplicación e imágenes de contenedor se firman criptográficamente en el momento de compilación. Las implementaciones validan las firmas antes del despliegue. | Cada compilación | Registros de atestación de compilación (inmutables, solo anexar) |
| **Verificaciones de integridad de base de datos** | Validación de suma de verificación PostgreSQL en todas las páginas de datos; integridad de cadena hash en tablas de registro de auditoría mediante resúmenes SHA-256 encadenados. | Continuo (suma de verificación en lectura); escaneo completo nocturno | Alerta por corrupción; endpoint de verificación de cadena de registro de auditoría |
| **Registros de implementación inmutables** | Cada evento de implementación (quién, qué, cuándo, commit git, hash de artefacto) se registra en un registro de solo anexar. | Cada implementación | Endpoint de historial de implementación; registro a prueba de manipulaciones |
| **Monitoreo de integridad de archivos** | Los binarios del sistema, archivos de configuración y certificados TLS se monitorean para detectar modificaciones no autorizadas. | Continuo (basado en inotify) | Alerta por modificación fuera de ventanas de cambio aprobadas |
| **Restauraciones de respaldo verificadas** | Pruebas de restauración automatizadas validan la integridad y recuperabilidad de las copias de seguridad. | Semanal | Registro de éxito/fracaso de restauración; comparación de datos de muestra |
| **Integridad en tiempo de ejecución** | Los procesos de aplicación se monitorean para detectar cambios binarios inesperados o desviaciones de configuración respecto al estado declarado de infraestructura como código. | Continuo | Alerta de detección de desviación; informe de conciliación |

## Seguridad de infraestructura

- Hetzner Online GmbH para computación, almacenamiento y redes en la región de implementación configurada.
- Sistemas operativos Debian/Ubuntu reforzados con CIS.
- Parches de seguridad automatizados con implementación por etapas.
- Infraestructura inmutable mediante infraestructura como código.
- Segmentación de red entre planos de aplicación, datos y gestión.
- Aislamiento de red: servidores de aplicaciones, servidores de bases de datos e interfaces de gestión en VLAN separadas.
- Gestión de secretos mediante secretos sellados y aislamiento de entorno.

## Gestión de vulnerabilidades

- Escaneo automatizado de dependencias en el pipeline CI/CD.
- Escaneo automatizado de vulnerabilidades de infraestructura (frecuencia semanal).
- Prueba de penetración anual por terceros (planificada — actualmente en adquisición; los resultados se publicarán después de la primera prueba y remediación).
- Programa de divulgación responsable: [security@apexmail.ee](mailto:security@apexmail.ee)
- Objetivos de remediación de vulnerabilidades por gravedad:
  - **Crítica:** Mitigación inmediata requerida; corrección permanente en 7 días.
  - **Alta:** Objetivo dentro de 30 días.
  - **Media:** Objetivo dentro de 90 días.
  - **Baja:** Basada en riesgo — abordada en ciclos de mantenimiento regulares.
  - **Explotada activamente:** Proceso de emergencia independientemente de la gravedad.

## Respuesta a incidentes

- Plan documentado de respuesta a incidentes con ejercicios de mesa semestrales y simulación completa anual.
- Clasificación de gravedad de incidentes de seguridad: Crítico (SEV-1), Alto (SEV-2), Medio (SEV-3), Bajo (SEV-4).
- Página de estado actualizada dentro de los 15 minutos posteriores a un incidente SEV-1/SEV-2 confirmado. Notificación al cliente por correo electrónico dentro de 1 hora para incidentes críticos.
- Resumen post-incidente dentro de 1 día hábil para todos los incidentes. Calendario post-mortem:
  - Dentro de 5 días hábiles para incidentes mayores (todos los modelos de implementación).
  - El análisis final de causa raíz se publica cuando se completa la validación.
- Procedimientos de notificación de violaciones alineados con el RGPD Art. 33/34 (autoridad de control dentro de 72 horas).

## Evidencia de auditoría y cumplimiento

- Resumen de prueba de penetración: planificado para publicación después de completar la primera prueba de penetración externa de la aplicación y remediar los hallazgos altos/críticos. Actualmente no disponible.
- Las solicitudes de cuestionarios de seguridad se evalúan caso por caso usando los materiales de revisión actuales; los paquetes SIG, CAIQ o HECVAT estandarizados no son un derecho de producto.
- Los registros de auditoría están disponibles en Growth, Business y Enterprise; la retención depende del plan contratado.
- La facilitación de auditorías de clientes está sujeta a revisión contractual Enterprise.

## Seguridad operativa

- Verificación de antecedentes para personal con acceso a producción.
- Revisiones de acceso trimestrales.
- El acceso a producción requiere autenticación multifactor y aprobación.
- Gestión de cambios con revisión por pares y capacidad de reversión.
- Segregación de funciones entre desarrollo y operaciones.

## Relacionado

- [Centro de cumplimiento](/es/compliance)
- [Resumen de arquitectura](/architecture)
- [Política de privacidad](/es/privacy)
- [Acuerdo de procesamiento de datos](/es/dpa)
- [Política de uso aceptable](/es/acceptable-use)
- [Divulgación responsable](/es/responsible-disclosure)
