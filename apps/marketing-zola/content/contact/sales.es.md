+++
title = "Hable con ventas"
description = "Trate con ApexMail los planes de despliegue empresarial, los requisitos de cumplimiento y las opciones de nube privada."
template = "prose.html"

[extra]
form_id = "sales-contact"
+++

## Hable con ventas

Para compras empresariales, revisiones de seguridad o planificación de nube privada, complete el formulario siguiente. Nuestro equipo revisa las solicitudes y responde en un plazo de 2 días laborables.

## Formulario de consulta de ventas

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status" hidden>
  <b>Recibida</b>
  <p>Gracias, su solicitud se ha recibido correctamente. Nuestro equipo la revisa y responde en un plazo de 2 días laborables.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert" hidden>
  <b>No aceptada</b>
  <p>No se ha podido aceptar su solicitud. Compruebe los campos obligatorios (se necesita un correo electrónico profesional válido) e inténtelo de nuevo.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="es" />
  <div class="apex-field">
    <label for="company" class="apex-label">Empresa <span class="">*</span></label>
    <input type="text" id="company" name="company" required maxlength="200"
      class="apex-input"
      placeholder="Nombre de su organización" />
  </div>

  <div class="apex-field">
    <label for="work-email" class="apex-label">Email profesional <span class="">*</span></label>
    <input type="email" id="work-email" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="usted@empresa.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div class="apex-field">
      <label for="monthly-volume" class="apex-label">Volumen mensual de emails <span class="">*</span></label>
      <div class="apex-select-wrap">
      <select id="monthly-volume" name="monthly_volume" required>
        <option value="" disabled selected>Seleccione un rango de volumen</option>
        <option value="lt_50k">Menos de 50.000</option>
        <option value="50k_150k">50.000 – 150.000</option>
        <option value="150k_500k">150.000 – 500.000</option>
        <option value="500k_2m">500.000 – 2 millones</option>
        <option value="2m_5m">2 millones – 5 millones</option>
        <option value="5m_10m">5 millones – 10 millones</option>
        <option value="10m_plus">Más de 10 millones</option>
      </select>
    </div>
    </div>

    <div class="apex-field">
      <label for="peak-hourly-volume" class="apex-label">Volumen horario punta</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume" maxlength="200"
        class="apex-input"
        placeholder="p. ej., 50.000 por hora" />
    </div>
  </div>

  <div class="apex-field">
    <label for="current-provider" class="apex-label">Proveedor actual</label>
    <div class="apex-select-wrap">
      <select id="current-provider" name="current_provider">
      <option value="" selected>Seleccione su proveedor actual (si tiene)</option>
      <option value="sendgrid">SendGrid (Twilio)</option>
      <option value="postmark">Postmark (ActiveCampaign)</option>
      <option value="mailgun">Mailgun (Sinch)</option>
      <option value="ses">Amazon SES</option>
      <option value="resend">Resend</option>
      <option value="mailchimp">Mailchimp / Mandrill</option>
      <option value="brevo">Brevo (Sendinblue)</option>
      <option value="other">Otro proveedor</option>
      <option value="none">Sin proveedor actual</option>
      <option value="multiple">Varios proveedores</option>
    </select>
    </div>
  </div>

  <fieldset class="apex-block apex-block--tight">
    <legend class="px-2">Preferencia de despliegue</legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="shared" checked />
        <span><strong>Nube compartida</strong>, Infraestructura multi-tenant en la UE</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="dedicated" />
        <span><strong>Inquilino dedicado</strong>, Infraestructura aislada de inquilino único</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="byoc" />
        <span><strong>BYOC / Implementación privada</strong>, Despliegue gestionado en su propia cuenta cloud</span>
      </label>
      <label class="apex-check">
        <input type="radio" class="apex-checkbox apex-input" name="deployment_preference" value="not_sure" />
        <span><strong>Aún no lo tengo claro</strong>, Necesito orientación sobre el modelo más adecuado</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="apex-block apex-block--tight">
    <legend class="px-2">Requisitos de cumplimiento <span class="">(seleccione todos los que apliquen)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="gdpr" />
        <span>RGPD / revisión de despliegue con residencia de datos</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="hipaa" />
        <span>Caso de uso HIPAA (no disponible actualmente; consultar alternativas)</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="ccpa" />
        <span>CCPA / leyes de privacidad estatales de EE. UU.</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="fedramp" />
        <span>FedRAMP / sector público</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="regional_residency" />
        <span>Requisito específico de residencia regional de datos</span>
      </label>
      <label class="apex-check">
        <input type="checkbox" name="compliance_needs" value="dpf" />
        <span>Marco de Privacidad de Datos UE-EE. UU.</span>
      </label>
    </div>
  </fieldset>

  <div class="apex-field">
    <label for="target-timeline" class="apex-label">Plazo previsto</label>
    <div class="apex-select-wrap">
      <select id="target-timeline" name="target_timeline">
      <option value="" selected>Seleccione un plazo</option>
      <option value="immediate">Inmediato (en 2 semanas)</option>
      <option value="30_days">En 30 días</option>
      <option value="90_days">En 90 días</option>
      <option value="6_months">En 6 meses</option>
      <option value="exploring">Explorando opciones, sin plazo fijo</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="security-review" class="apex-label">Necesidades de revisión de seguridad</label>
    <div class="apex-select-wrap">
      <select id="security-review" name="security_review_needs">
      <option value="" selected>Seleccione el nivel de revisión</option>
      <option value="standard">Estándar, cuestionario de seguridad respondido caso por caso con material de revisión actual (ningún paquete SIG/CAIQ/HECVAT estandarizado forma parte del producto)</option>
      <option value="detailed">Detallada, Se requiere un cuestionario de seguridad personalizado</option>
      <option value="pen_test">Se requiere informe de test de intrusión</option>
      <option value="on_site">Se requiere auditoría presencial o revisión de arquitectura</option>
      <option value="none">No se requiere revisión de seguridad en esta fase</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="additional-context" class="apex-label">Contexto adicional</label>
    <textarea id="additional-context" name="additional_context" rows="4" maxlength="2000"
      placeholder="Requisitos específicos de integración, planes de migración, necesidades de arquitectura de seguridad o cualquier otro contexto que nos ayude a preparar la recomendación adecuada."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Enviar consulta
    </button>
  </div>
  <p class="apex-footnote">Al enviar este formulario, acepta nuestra <a href="/es/privacy/">política de privacidad</a>. Utilizamos estos datos únicamente para responder a su consulta (RGPD art. 13).</p>
</form>

## Qué sucede a continuación

Tras el envío, nuestro equipo empresarial revisa sus requisitos y responde en un plazo de 2 días laborables con un modelo de despliegue recomendado, precios orientativos y los siguientes pasos para una revisión de arquitectura estructurada.

Para contrataciones urgentes, envíe un email a [support@apexmail.ee](mailto:support@apexmail.ee) con el asunto "Urgent: Sales Enquiry" e incluya su volumen mensual y su preferencia de despliegue.
