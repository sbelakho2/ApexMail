+++
title = "Solución de email para plataformas SaaS"
description = "Infraestructura de email multi-tenant para SaaS B2B y B2C. Subcuentas, aislamiento de dominios, RBAC, SSO y entrega con marca blanca."
template = "prose.html"
+++

## Plataformas SaaS

Ofrezca a sus clientes una infraestructura de email fiable y aislada sin construir ni mantener su propia capa de email. El modelo de subcuentas de ApexMail da a cada uno de sus tenants dominios, claves de API, listas de supresión y flujos de eventos independientes.

## Público destinatario

Plataformas SaaS que envían email en nombre de sus clientes: CRM que envían campañas, plataformas de comercio electrónico que envían recibos, herramientas de analítica que envían informes y plataformas de seguridad que envían alertas.

## Contexto de negocio

Las plataformas que envían email por sus clientes heredan el riesgo de reputación de cada cliente. Una sola queja de spam en una IP compartida puede degradar la entrega de todos los tenants. Sin aislamiento, las plataformas no pueden atribuir los problemas de entrega a clientes concretos ni ofrecer controles de cumplimiento por tenant.

## Problema principal

- Riesgo de reputación de IP compartida entre todos los tenants de la plataforma.
- Imposibilidad de aislar facturación, cuotas de uso y analítica de entrega por cliente.
- Requisitos de cumplimiento que varían por cliente (uno necesita HIPAA, otro solo RGPD).
- Clientes que exigen métricas de entregabilidad visibles y estado de autenticación a nivel de dominio.

## Solución de ApexMail

- **Subcuentas** — Cada tenant recibe una subcuenta independiente con sus propias claves de API, dominios, webhooks, listas de supresión, IP dedicadas y flujos de eventos.
- **Aislamiento de dominios** — La verificación y autenticación de dominios por subcuenta (SPF, DKIM, DMARC) evita la contaminación cruzada de reputación.
- **RBAC personalizado** — Administrador a nivel de plataforma, administrador a nivel de tenant y roles de solo lectura. Aprovisionamiento SCIM en Enterprise.
- **SSO** — SAML 2.0 para operadores de plataforma y administradores de tenants.
- **Cuotas de uso** — Límites duros y blandos por subcuenta para volumen, velocidad y concurrencia.
- **Marca blanca** — Elimine la marca de ApexMail de paneles, pies de email y plantillas de notificación.

## Implementación técnica

1. Cree una cuenta maestra para su plataforma.
2. Aprovisione subcuentas mediante la API o el panel para cada tenant de cliente.
3. Cada tenant verifica sus dominios de envío de forma independiente.
4. Asigne IP dedicadas a los tenants que necesiten aislamiento de reputación.
5. Configure endpoints de webhooks por tenant para los eventos de entrega.
6. Supervise la salud de entrega de toda la plataforma mediante analítica agregada.

## Endpoints de API relevantes

| Endpoint | Descripción |
|---|---|
| `POST /v1/subaccounts` | Crear una subcuenta |
| `GET /v1/subaccounts` | Listar subcuentas |
| `GET /v1/subaccounts/:id` | Obtener detalles de una subcuenta |
| `PATCH /v1/subaccounts/:id` | Actualizar la configuración de una subcuenta |
| `DELETE /v1/subaccounts/:id` | Desactivar una subcuenta |
| `POST /v1/subaccounts/:id/api-keys` | Crear una clave de API de subcuenta |

## Plan requerido

Las subcuentas están disponibles en Scale (hasta 10) y Enterprise (hasta 100). Cualquier disposición de despliegue no estándar requiere una revisión de arquitectura y contractual separada.

## Consideraciones de seguridad

- Los operadores de la plataforma no pueden leer el contenido de los emails de los tenants por defecto. El acceso al contenido requiere autorización explícita del tenant.
- Las claves de API de las subcuentas tienen alcance limitado a su subcuenta. El acceso entre tenants se bloquea en la capa de autorización.
- Los endpoints de webhooks se configuran por subcuenta. Las firmas HMAC usan un secreto por subcuenta.
- Los registros de auditoría recogen toda creación, eliminación y cambio de permisos de subcuentas.

## Consideraciones de cumplimiento

- Cada subcuenta mantiene listas de supresión, autenticación de dominios y retención de eventos independientes.
- La cobertura de la DPA para las subcuentas requiere la DPA de la plataforma con ApexMail. La extensión contractual a los tenants es responsabilidad de la plataforma.
- Los requisitos de ubicación de datos se aplican a nivel de plataforma y deben confirmarse para el despliegue activo y el acuerdo aplicable.
- Los operadores de la plataforma son responsables del cumplimiento del uso aceptable por parte de sus tenants.

## Limitaciones conocidas

- El aislamiento de subcuentas es lógico en los planes de Nube compartida. Un despliegue contratado por separado puede definir requisitos adicionales de aislamiento, pero no constituye un derecho de un plan público.
- La analítica entre subcuentas requiere que la plataforma agregue externamente los datos de eventos de las subcuentas.
- La marca blanca está disponible en el plan Enterprise.

## Siguiente paso recomendado

[Contacte con ventas](/es/contact/sales/) para una revisión de arquitectura de subcuentas y precios por volumen para despliegues multi-tenant.
