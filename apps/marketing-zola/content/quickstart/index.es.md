+++
title = "Inicio rápido | Guía para desarrolladores de ApexMail"
description = "Envíe su primer correo electrónico con la API de ApexMail en menos de 10 minutos. Guía paso a paso con ejemplos de código para cURL y SDKs oficiales."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
og_image = "/images/og-image.png"
+++

Esta guía lo lleva desde cero hasta un dominio de envío verificado y su primer correo entregado. Cada paso incluye la ruta exacta de la interfaz, ejemplos de código, resultados esperados y casos de error frecuentes.

**Tiempo total estimado:** 8–10 minutos para un desarrollador familiarizado con DNS y APIs REST.

---

## Paso 1: Crear una cuenta

**Tiempo:** ~30 segundos

Navegue a [app.apexmail.ee/signup](https://app.apexmail.ee/signup).

**Qué necesita:** Una dirección de email y una contraseña (mínimo 12 caracteres). No se requiere tarjeta de crédito.

**Botón:** Haga clic en **Create Free Account**.

**Qué sucede:** Recibe un email de verificación en la dirección proporcionada.

**Resultado esperado:** Redirección al panel con un banner que solicita la verificación del email.

**Casos de error:**
- **`Email already registered`**: Use el flujo de restablecimiento de contraseña en [app.apexmail.ee/reset-password](https://app.apexmail.ee/reset-password).
- **`Password too weak`**: Use 15+ caracteres (las frases de contraseña más largas están bien — no se requiere mezcla de símbolos o dígitos). Evite contraseñas comunes y patrones simples de repetición/secuencia.

---

## Paso 2: Verificar el email de la cuenta

**Tiempo:** ~30 segundos

Abra el email de verificación enviado a su dirección registrada.

**Asunto:** `Verify your ApexMail account`

**Botón:** Haga clic en **Verify Email Address**.

**Qué sucede:** Su cuenta se activa. El banner del panel desaparece.

**Resultado esperado:** Las secciones **API Keys** y **Domains** quedan accesibles en la barra lateral del panel.

**Solución de problemas:**
- Revise la carpeta de spam/correo no deseado.
- Si no llega un email en 2 minutos, haga clic en **Resend Verification** en el banner del panel.
- Agregue `noreply@apexmail.ee` a sus contactos para evitar problemas de entrega futuros.

---

## Paso 3: Crear una clave API

**Tiempo:** ~30 segundos

En la barra lateral del panel, navegue a **Settings → API Keys**.

**Ruta:** Barra lateral del panel → `Settings` → `API Keys`

**Botón:** Haga clic en **Create API Key**.

**Campos a completar:**
- **Nombre de la clave:** p. ej., `Quickstart Key`
- **Scopes:** Seleccione al menos `messages:write` y `messages:read`
- **Caducidad:** Déjelo en `Never` para desarrollo

**Qué sucede:** Se genera una nueva clave API y se muestra una sola vez.

**Advertencia de seguridad:** Copie la clave de inmediato. No se volverá a mostrar. Guárdela en un gestor de contraseñas o en una variable de entorno — nunca la suba al control de versiones.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Resultado esperado:** La clave aparece en su lista de API Keys con estado `Active`.

---

## Paso 4: Agregar un dominio de envío

**Tiempo:** ~1 minuto

Navegue a **Settings → Domains** en la barra lateral del panel.

**Ruta:** Barra lateral del panel → `Settings` → `Domains`

**Botón:** Haga clic en **Add Domain**.

**Campo:** Introduzca su dominio de envío (p. ej., `mail.example.com` o `example.com`).

**Qué sucede:** ApexMail genera registros DNS de verificación y los muestra en pantalla.

**Resultado esperado:** El dominio aparece en su lista de Dominios con estado `Pending Verification` y se muestran los registros DNS.

**Nota de seguridad:** Use un subdominio (p. ej., `mail.example.com`) para el email transaccional a fin de aislar la reputación de envío de su dominio principal.

---

## Paso 5: Agregar registros MAIL FROM personalizados

**Tiempo:** ~2 minutos (la propagación DNS puede tardar hasta 48 horas, aunque normalmente 5–30 minutos)

Inicie sesión en la consola de gestión de su proveedor DNS y copie ambos registros `bounce` que se muestran en la configuración de Dominios (o los devueltos por la API de registros DNS): un registro TXT SPF que contiene `include:amazonses.com` y un registro MX con prioridad `10` que apunta a `feedback-smtp.<aws-region>.amazonses.com`.

**Qué hace esto:** Configura el dominio MAIL FROM personalizado usado para la alineación SPF y el manejo de rebotes.

**Resultado esperado:** Tras la propagación DNS, las comprobaciones de SPF y return-path en el panel de estado del dominio muestran `verified`.

---

## Paso 6: Agregar registros DKIM

**Tiempo:** ~2 minutos

Copie el registro DKIM **TXT** generado que se muestra en la configuración de Dominios. El nombre de host es `<selector>._domainkey.<your-domain>` y el valor comienza con `v=DKIM1; k=rsa; p=`. El selector y la clave pública son específicos del dominio, por lo que el registro generado en el panel es la única fuente admitida.

**Qué hace esto:** Permite a ApexMail firmar criptográficamente los mensajes salientes, permitiendo a los servidores receptores verificar la integridad del mensaje y la autenticidad del remitente.

**Resultado esperado:** Tras la propagación DNS, la comprobación DKIM en el panel de estado del dominio muestra `verified`.

**Solución de problemas:**
- Asegúrese de agregar registros a la zona DNS correcta (el dominio que agregó en el Paso 4).
- DKIM es un registro TXT, no un CNAME. No agregue un CNAME Easy-DKIM ni de host de servicio de ApexMail.
- Use el selector exacto que se muestra en la configuración de Dominios al verificar el DNS con `dig`.

---

## Paso 7: Verificar el dominio

**Tiempo:** ~1 minuto (tras la propagación DNS)

Vuelva a la página **Settings → Domains** en el panel.

**Botón:** Haga clic en **Verify** junto a su dominio.

**Qué sucede:** ApexMail comprueba los registros SPF/MX del MAIL FROM personalizado, la clave pública DKIM exacta y DMARC. En modo SES también espera a que SES informe que la identidad BYODKIM y el dominio MAIL FROM personalizado están listos.

**Resultado esperado:** El estado del dominio muestra `Verified` con marcas verdes para SPF, DKIM, DMARC y return path. La verificación SES puede permanecer pendiente mientras AWS detecta los registros DNS recién publicados.

**Casos de error:**
- **`SPF record not found`**: Verifique que el host sea `bounce.<yourdomain>`, no el apex del dominio.
- **`DKIM selector not found`**: Verifique que el nombre de host TXT generado y la clave pública `p=` completa sean exactos.
- **`Verification timeout`**: El DNS puede seguir propagándose. Espere 5 minutos y reintente.

---

## Paso 8: Instalar el SDK o preparar cURL

**Tiempo:** ~1 minuto

Elija su método de integración:

### Opción A: SDK (compilar desde el código fuente)

> **Aún no en registros públicos.** Los SDK de ApexMail **aún no están publicados en PyPI, pkg.go.dev, Packagist, RubyGems ni Maven Central** — `pip install apexmail`, `go get github.com/apexmail/apexmail-go` y `composer require apexmail/apexmail-php` fallarán hasta la primera versión estable. Hasta entonces, instale desde el código fuente del monorepo y fije un commit específico, y **verifique el fuente que incorpora** antes de publicar. Vea [SDKs](/docs/sdks/) para el estado por lenguaje.

El código fuente del SDK es actualmente privado y está disponible para clientes de vista previa aprobados mientras se preparan los paquetes para su primera publicación en un registro público — escriba a [support@apexmail.ee](mailto:support@apexmail.ee) (o a su gestor de cuenta) y recibirá el paquete de código fuente fijado para su lenguaje, con suma de verificación, bajo la licencia del SDK. Cada directorio de SDK incluye sus propias instrucciones de compilación y prueba.

**Python** (`packages/sdk-python` — instale desde la ruta local, o incorpore el directorio):

```bash
pip install ./packages/sdk-python
```

**Go** (`packages/sdk-go` — fije el módulo al código fuente incorporado con una directiva `replace`):

```bash
go mod edit -replace github.com/apexmail/apexmail-go=./packages/sdk-go
go mod tidy
```

**PHP** (`packages/sdk-php` — apunte Composer al directorio local):

```bash
composer config repositories.apexmail path ./packages/sdk-php
composer require apexmail/apexmail-php:@dev
```

**Ruby** (`packages/sdk-ruby`) y **Java** (`packages/sdk-java`): compile desde el directorio del monorepo; el README de cada paquete tiene sus instrucciones de compilación y prueba.

### Opción B: cURL (prueba rápida)

No requiere instalación — use la terminal:

```bash
# Verify your key works
curl -s https://api.apexmail.ee/v1/account \
  -H "X-API-Key: $APEXMAIL_API_KEY" | head -c 200
```

**Resultado esperado:** Una respuesta JSON con la información de su cuenta y los detalles del plan.

---

## Paso 9: Enviar su primer email de prueba

**Tiempo:** ~30 segundos

Con su dominio verificado y su clave API:

**cURL:**
```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: test-$(date +%s)" \
  -d '{
    "from": "hello@yourdomain.com",
    "to": ["your-email@example.com"],
    "subject": "Hello from ApexMail Quickstart",
    "text": "Your first transactional email via ApexMail!",
    "html": "<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
    "type": "transactional"
  }'
```

**SDK de Python:**
```python
import os
from apexmail import ApexMail

client = ApexMail(api_key=os.environ["APEXMAIL_API_KEY"])

response = client.emails.send(
    from_="hello@yourdomain.com",
    to="your-email@example.com",
    subject="Hello from ApexMail Quickstart",
    text="Your first transactional email via ApexMail!",
    html="<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
)

print(f"Email queued! ID: {response.id}")
```

**Respuesta esperada:**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "queued",
  "created_at": "2026-07-29T19:00:00Z"
}
```

**Qué sucede:** El mensaje se acepta en la cola de entrega. El estado pasa de `queued` → `processed` → `sent` → `delivered`.

**Casos de error:**
- **`401 Unauthorized`**: Falta la clave API o es incorrecta. Verifique que `$APEXMAIL_API_KEY` esté definida.
- **`403 Forbidden`**: A la clave API le falta el scope `messages:write`. Recree la clave con el scope correcto.
- **`400 domain_not_verified`**: Su dominio de envío aún no está verificado. Vuelva al Paso 7.
- **`429 Too Many Requests`**: Se excedió el límite de tasa. Plan Free: 3.000 emails/mes recurrentes (más una asignación de lanzamiento única de 30.000 emails). Espere y reintente.

---

## Paso 10: Ver el evento del mensaje

**Tiempo:** ~30 segundos

Recupere el estado del mensaje y los eventos de entrega:

**cURL:**
```bash
curl https://api.apexmail.ee/v1/messages/msg_01JXXXXXXXXXXXXXXX \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

**Respuesta esperada:**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "delivered",
  "from": "hello@yourdomain.com",
  "to": ["your-email@example.com"],
  "subject": "Hello from ApexMail Quickstart",
  "events": [
    { "type": "queued",      "timestamp": "2026-07-29T19:00:00.100Z" },
    { "type": "processed",   "timestamp": "2026-07-29T19:00:00.200Z" },
    { "type": "sent",        "timestamp": "2026-07-29T19:00:00.450Z" },
    { "type": "delivered",   "timestamp": "2026-07-29T19:00:01.800Z" }
  ]
}
```

**Alternativa:** Vea la línea de tiempo del mensaje en el panel en **Activity → Messages**.

---

## Paso 11: Configurar un webhook

**Tiempo:** ~2 minutos

Navegue a **Settings → Webhooks** en el panel.

**Ruta:** Barra lateral del panel → `Settings` → `Webhooks`

**Botón:** Haga clic en **Add Webhook Endpoint**.

**Campos:**
- **URL:** La URL receptora de su webhook (p. ej., `https://your-app.example.com/webhooks/apexmail`)
- **Events:** Seleccione al menos `message.delivered`, `message.bounced`, `message.complained`
- **Secret:** Genere un secreto de firma — guárdelo de forma segura

**Qué sucede:** ApexMail comienza a entregar los eventos coincidentes a su URL con firmas HMAC-SHA256.

**Ejemplo de verificación (Python):**
```python
import hmac
import hashlib
import time

def verify_webhook(body: bytes, signature: str, timestamp: str, secret: str) -> bool:
    # Verify timestamp is within 5 minutes
    now = int(time.time())
    if abs(now - int(timestamp)) > 300:
        return False

    # Compute expected signature
    payload = f"{timestamp}.{body.decode()}".encode()
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, signature)
```

**Cabeceras requeridas en las solicitudes de webhook entrantes:**
- `X-ApexMail-Signature`: resumen hexadecimal HMAC-SHA256
- `X-ApexMail-Timestamp`: segundos de época Unix
- `Content-Type`: `application/json`

---

## Paso 12: Pasar a producción

**Tiempo:** Variable (depende de sus requisitos)

Antes de pasar a producción:

1. **Actualice desde el plan Free** si supera 3.000 emails/mes recurrentes (o su asignación de lanzamiento única de 30.000 emails). Vea [Precios](/pricing/).
3. **Configure DMARC** para su dominio de envío con una política de al menos `p=none` inicialmente, avanzando a `p=quarantine` o `p=reject`.
4. **Configure la alineación SPF** asegurando que su dominio `Return-Path` coincida con su dominio `From`.
5. **Rote las claves API** — cree claves específicas de producción con scopes mínimos y fechas de caducidad.
6. **Configure el monitoreo** — establezca alertas para tasas de rebote superiores al 2 % y tasas de queja superiores al 0,1 %.
7. **Pruebe la idempotencia del webhook** — verifique que su manejador deduplica correctamente los eventos usando el campo `event_id`.
8. **Revise la [Referencia de la API](/docs/api/)** para envío por lotes, plantillas y funciones avanzadas.

### Lista de verificación de preparación para producción

| Verificación | Requisito |
|-------|-------------|
| Dominio verificado | SPF + DKIM verificados para todos los dominios de envío |
| DMARC configurado | Política publicada, informes habilitados |
| Clave API con scopes | Scopes mínimos necesarios; clave de producción separada de la de desarrollo |
| Webhook verificado | Verificación de firma implementada con tolerancia de marca de tiempo |
| Manejo de errores | Reintentos con retroceso exponencial para respuestas 5xx |
| Idempotencia | Uso de la cabecera `Idempotency-Key` en todas las solicitudes que cambian estado |
| Monitoreo | Tasa de rebote < 2 %, tasa de queja < 0,1 %, tasa de entrega > 98 % |

---

## Siguientes pasos

- [Referencia de la API](/docs/api/) — documentación completa de endpoints con esquemas de solicitud/respuesta
- [Webhooks](/docs/webhooks/) — catálogo completo de eventos, seguridad y documentación de entrega
- [SDKs](/docs/sdks/) — instalación del SDK, autenticación y ejemplos de uso
- [Analytics](/docs/analytics/) — métricas de entrega, clasificación de rebotes e informes
- [API Explorer](/api-explorer/) — ejecute solicitudes reales contra el sandbox en vivo aislado
