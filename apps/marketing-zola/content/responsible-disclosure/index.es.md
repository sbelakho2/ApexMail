+++
title = "Divulgación responsable"
description = "Política de divulgación responsable de ApexMail: cómo informar vulnerabilidades de seguridad."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 1. Política

ApexMail se toma en serio la seguridad de nuestros sistemas y los datos de nuestros clientes. Agradecemos los informes de investigadores de seguridad y del público sobre posibles vulnerabilidades. Esta política describe cómo informar problemas de seguridad y qué puede esperar de nosotros.

## 2. Alcance

Esta política se aplica a:

- `apexmail.ee` y todos los subdominios
- `api.apexmail.ee`
- `smtp.apexmail.ee`
- `app.apexmail.ee`
- `cdn.apexmail.ee`
- La API de ApexMail y la aplicación web

Los servicios no operados por ApexMail (por ejemplo, integraciones de terceros) están fuera del alcance, a menos que la vulnerabilidad esté en nuestra integración con ese servicio.

## 3. Cómo informar

Envíe informes de vulnerabilidad a **[security@apexmail.ee](mailto:security@apexmail.ee)** .

Por favor, incluya:

- Una descripción detallada de la vulnerabilidad.
- Pasos para reproducirla, incluyendo cualquier código de prueba de concepto.
- El dominio, endpoint o componente afectado.
- Su evaluación del impacto potencial.
- Cualquier sugerencia de remediación.

Cifre los informes confidenciales utilizando nuestra [clave PGP](/pgp-key.txt).

## 4. Lo que prometemos

- Acusar recibo en un plazo de **48 horas**.
- Proporcionar una evaluación inicial en un plazo de **5 días hábiles**.
- Mantenerle informado del progreso hacia la resolución.
- No emprender acciones legales contra los investigadores que sigan esta política.
- Reconocer a los investigadores que informen de vulnerabilidades válidas (a menos que prefieran permanecer en el anonimato).

## 5. Lo que pedimos

- No acceda, modifique ni elimine datos que no le pertenezcan.
- No degrade el servicio ni interrumpa a otros usuarios.
- No divulgue públicamente la vulnerabilidad hasta que hayamos tenido un tiempo razonable para abordarla (objetivo: 90 días).
- No pruebe la seguridad física, la ingeniería social ni la denegación de servicio.

## 6. Reconocimiento

Reconocemos y agradecemos a los investigadores de seguridad que nos ayudan a mejorar. Los informes de vulnerabilidad válidos se reconocen en esta página (con el consentimiento del informante).

## 7. Fuera de alcance

Generalmente se considera fuera de alcance lo siguiente, pero será revisado:

- Problemas sin un impacto de seguridad claro.
- Encabezados de seguridad HTTP faltantes que no presenten un riesgo directo.
- Self-XSS o ataques que requieran acceso físico al dispositivo de la víctima.
- Vulnerabilidades teóricas sin prueba de concepto.
