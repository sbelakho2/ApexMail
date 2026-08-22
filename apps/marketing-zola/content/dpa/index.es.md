+++
title = "Acuerdo de procesamiento de datos"
description = "DPA de ApexMail — condiciones de tratamiento de datos conforme al artículo 28 del RGPD."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## 1. Ámbito

El presente Acuerdo de procesamiento de datos («DPA») complementa las Condiciones de servicio y regula el tratamiento de datos personales por **Bel Consulting OÜ** (código de registro 16588745, IVA EE102951727, Sakala 7-2, 10141 Tallinn, Estonia), operando como ApexMail («**Encargado del tratamiento**») en nombre del Cliente («**Responsable del tratamiento**») en virtud del Artículo 28 del Reglamento (UE) 2016/679 (Reglamento General de Protección de Datos).

## 2. Definiciones

Los términos utilizados en este DPA tienen el significado establecido en el RGPD, salvo que se defina lo contrario.

## 3. Detalles del tratamiento

| Elemento | Descripción |
|---|---|
| **Objeto** | Envío de correo electrónico, seguimiento de entrega, analítica |
| **Duración** | Vigencia del contrato de servicio |
| **Naturaleza** | Tratamiento y transmisión automatizados de mensajes de correo electrónico |
| **Finalidad** | Prestación de servicios de infraestructura de correo electrónico |
| **Categorías de datos** | Direcciones de correo electrónico, contenido de mensajes, metadatos de entrega, direcciones IP |
| **Interesados** | Usuarios finales del cliente (destinatarios de correo electrónico) |

## 4. Obligaciones del encargado del tratamiento

El Encargado del tratamiento se compromete a:
- Tratar los datos únicamente según instrucciones documentadas del Responsable del tratamiento.
- Garantizar que el personal esté sujeto a confidencialidad.
- Implementar medidas técnicas y organizativas apropiadas (Artículo 32).
- Ayudar al Responsable del tratamiento a responder a las solicitudes de los interesados.
- Suprimir o devolver todos los datos personales al finalizar el acuerdo.
- Poner a disposición toda la información necesaria para demostrar el cumplimiento del Artículo 28.
- Permitir y contribuir a auditorías e inspecciones realizadas por el Responsable del tratamiento o un auditor autorizado.

## 5. Subencargados del tratamiento

### 5.1 Subencargados autorizados

La lista actual de subencargados autorizados se mantiene en el [Registro de subencargados de ApexMail](https://apexmail.ee/subprocessors/), incorporado a este DPA por referencia.

| Subencargado | Finalidad | Ubicación | Garantía de transferencia |
|---|---|---|---|
| Hetzner Online GmbH | Infraestructura principal (computación, almacenamiento) | Región UE/EEE configurada | Confirmar la implementación activa y la garantía de transferencia aplicable |
| Amazon Web Services, Inc. | Almacenamiento de objetos de telemetría cuando está habilitado | Región S3 configurada (predeterminada: `eu-central-1`) | Confirmar la implementación activa y la garantía de transferencia aplicable |
| Amazon Web Services, Inc. | Transporte de entrega de correo cuando está habilitado | Región SES configurada | Confirmar la implementación activa y la garantía de transferencia aplicable |
| Google LLC | Autenticación OAuth opcional | Global (entidad estadounidense, datos tratados según configuración OAuth) | Cláusulas Contractuales Tipo |
| GitHub, Inc. | Autenticación OAuth opcional | Global (entidad estadounidense) | Cláusulas Contractuales Tipo |
| Stripe, Inc. | Procesamiento de pagos | EE. UU. (principal), India (soporte) | Cláusulas Contractuales Tipo |

La infraestructura autogestionada (ClickHouse, Redis) se ejecuta en servidores Hetzner bajo el control operativo de ApexMail. Los editores upstream de código abierto no procesan datos de clientes.

### 5.2 Notificación de cambios

El Encargado del tratamiento notificará al Responsable del tratamiento con al menos **30 días** de antelación antes de añadir o reemplazar cualquier subencargado, dando al Responsable del tratamiento la oportunidad de oponerse. Si el Responsable del tratamiento se opone por motivos razonables de protección de datos y no se puede alcanzar una alternativa, el Responsable del tratamiento puede rescindir los servicios afectados.

## 6. Transferencias internacionales

La configuración proporcionada apunta a regiones de la UE/EEE para la infraestructura principal y el almacenamiento de objetos de telemetría. Los proveedores y ubicaciones activos dependen de la implementación; consulte la página [Ubicaciones de datos](/es/data-locations/) para una matriz completa categoría por categoría. No se transfieren datos personales fuera del EEE sin garantías adecuadas (Cláusulas Contractuales Tipo o una decisión de adecuación en virtud del Artículo 45).

## 7. Medidas de seguridad

- Cifrado AES-256-GCM en reposo
- TLS 1.2+ en tránsito (TLS 1.3 preferido)
- Hashing de contraseñas Argon2id
- Registro de auditoría con integridad de cadena hash
- Controles de seguridad alineados con SOC 2 (no certificado actualmente; mapeo de controles y evaluación de preparación en curso)
- Control de acceso con autenticación multifactor
- Escaneo continuo de vulnerabilidades; programa independiente de pruebas de penetración en establecimiento, primera prueba planificada
- Remediación según gravedad conforme a la política de gestión de vulnerabilidades de ApexMail

## 8. Notificación de violaciones de datos

El Encargado del tratamiento notificará al Responsable del tratamiento **sin dilación indebida** después de tener conocimiento de una violación de datos personales que afecte a los datos del Responsable del tratamiento. ApexMail se compromete contractualmente a realizar una notificación inicial en un plazo de 48 horas, basándose en la información razonablemente disponible en ese momento. La notificación incluirá:
- La naturaleza de la violación.
- Las categorías y el número aproximado de interesados y registros afectados.
- Los datos de contacto del Delegado de Protección de Datos.
- Las consecuencias probables y las medidas adoptadas o propuestas.

## 9. Devolución y supresión de datos

Al finalizar el acuerdo, el Encargado del tratamiento, a elección del Responsable del tratamiento, devolverá o suprimirá todos los datos personales tratados en nombre del Responsable del tratamiento, a menos que la legislación de la UE o de Estonia exija su conservación (por ejemplo, registros de facturación conservados durante 7 años según la Ley de Contabilidad de Estonia).

## 10. Derechos de auditoría

El Responsable del tratamiento puede solicitar una auditoría del cumplimiento del Encargado del tratamiento con este DPA a intervalos razonables. La auditoría se realizará a cargo del Responsable del tratamiento y estará sujeta a obligaciones de confidencialidad.

## 11. Legislación aplicable

El presente DPA se rige por las leyes de la República de Estonia y el RGPD. Cualquier litigio se resolverá en los tribunales de Tallin, Estonia.
