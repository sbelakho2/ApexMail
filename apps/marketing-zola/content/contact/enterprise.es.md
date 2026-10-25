+++
title = "Contacto Enterprise"
description = "Solicite una revisión de despliegue Enterprise, una conversación sobre precios o una evaluación de nube privada con el equipo de ApexMail."
template = "prose.html"

[extra]
form_id = "enterprise-contact"
+++

## Contacto Enterprise

Para organizaciones que evalúan despliegues ApexMail Enterprise Shared, Dedicated Tenant o BYOC, utilice este formulario o escriba directamente a [support@apexmail.ee](mailto:support@apexmail.ee).

## Qué puede esperar

Tras enviar el formulario, nuestro equipo empresarial revisa sus requisitos y responde en un plazo de 2 días laborables con un modelo de despliegue recomendado, precios orientativos y los siguientes pasos para una revisión de arquitectura estructurada.

## Formulario de consulta Enterprise

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Recibida</b>
  <p>Gracias, su solicitud se ha recibido correctamente. Nuestro equipo la revisa y responde en un plazo de 2 días laborables.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>No aceptada</b>
  <p>No se ha podido aceptar su solicitud. Compruebe los campos obligatorios (se necesita un correo electrónico profesional válido) e inténtelo de nuevo.</p>
</div>
<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <input type="hidden" name="page_language" value="es" />
  <div class="apex-field">
    <label for="work-email" class="apex-label">Email profesional <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="usted@empresa.com" />
  </div>

  <div class="apex-field">
    <label for="company" class="apex-label">Empresa <span class="">*</span></label>
    <input type="text" id="company" name="company" required
      class="apex-input"
      placeholder="Nombre de su organización" />
  </div>

  <div class="apex-field">
    <label for="monthly-volume" class="apex-label">Volumen mensual aproximado de emails <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
      <option value="" disabled selected>Seleccione un rango de volumen</option>
      <option value="lt_100k">Menos de 100.000</option>
      <option value="100k_500k">100.000 – 500.000</option>
      <option value="500k_1m">500.000 – 1 millón</option>
      <option value="1m_5m">1 millón – 5 millones</option>
      <option value="5m_10m">5 millones – 10 millones</option>
      <option value="10m_50m">10 millones – 50 millones</option>
      <option value="50m_plus">Más de 50 millones</option>
    </select>
    </div>
  </div>

  <fieldset class="apex-block apex-block--tight">
    <legend class="px-2">Modelo de despliegue</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="shared" checked />
        <span><strong>Nube compartida</strong>, Infraestructura multi-tenant en la UE</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="dedicated" />
        <span><strong>Inquilino dedicado</strong>, Infraestructura aislada de inquilino único, sujeta a revisión de arquitectura y contractual</span>
      </label>
      <label class="apex-check">
        <input type="radio" name="deployment_model" value="byoc" />
        <span><strong>BYOC / Implementación privada</strong>, Despliegue gestionado en su propia cuenta cloud, sujeto a revisión de arquitectura y contractual</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="requirements" class="apex-label">Requisitos y contexto</label>
    <textarea id="requirements" name="requirements" rows="5"
      placeholder="Requisitos de cumplimiento, necesidades de residencia de datos, proveedor actual, calendario de migración, funcionalidades específicas necesarias o cualquier otro contexto que nos ayude a preparar la recomendación adecuada."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Enviar consulta
    </button>
  </div>
  <p class="apex-footnote">Al enviar este formulario, acepta nuestra <a href="/es/privacy/">política de privacidad</a>. Utilizamos estos datos únicamente para responder a su consulta (RGPD art. 13).</p>
</form>

## Contacto directo

También puede contactar con el equipo empresarial por correo electrónico en [support@apexmail.ee](mailto:support@apexmail.ee). Incluya su volumen mensual, su preferencia de modelo de despliegue y cualquier requisito de cumplimiento para que podamos prepararnos antes de la primera llamada.
